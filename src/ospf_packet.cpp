/*
 * OSPF 报文线速编解码：ByteReader 只负责边界安全读取，公共头和 Hello
 * 的版本差异由上层函数显式分支处理。所有写入均按大端序输出。
 */
#include "ospf_gateway/ospf_packet.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace ospf_gateway {

namespace {

class ByteReader {
public:
    explicit ByteReader(const std::vector<std::uint8_t>& bytes)
        : bytes_(bytes) {}

    std::uint8_t read_u8() {
        // 单字节读取是更大字段读取的基础，require() 保证不会越界。
        require(1);
        return bytes_[offset_++];
    }

    std::uint16_t read_u16() {
        // 将两个线速字节拼成主机序整数，并推进共享偏移量。
        require(2);
        const std::uint16_t value =
            (static_cast<std::uint16_t>(bytes_[offset_]) << 8U) |
            static_cast<std::uint16_t>(bytes_[offset_ + 1]);
        offset_ += 2;
        return value;
    }

    std::uint32_t read_u32() {
        // Router ID、Area ID 等四字节字段都通过同一大端路径解析。
        require(4);
        const std::uint32_t value =
            (static_cast<std::uint32_t>(bytes_[offset_]) << 24U) |
            (static_cast<std::uint32_t>(bytes_[offset_ + 1]) << 16U) |
            (static_cast<std::uint32_t>(bytes_[offset_ + 2]) << 8U) |
            static_cast<std::uint32_t>(bytes_[offset_ + 3]);
        offset_ += 4;
        return value;
    }

    std::uint32_t read_u24() {
        // OSPFv3 options 只有 24 位，单独读取避免误把保留字节当成选项。
        require(3);
        const std::uint32_t value =
            (static_cast<std::uint32_t>(bytes_[offset_]) << 16U) |
            (static_cast<std::uint32_t>(bytes_[offset_ + 1]) << 8U) |
            static_cast<std::uint32_t>(bytes_[offset_ + 2]);
        offset_ += 3;
        return value;
    }

    std::size_t remaining() const noexcept {
        // 返回当前游标之后的字节数，Hello 邻居列表据此循环读取。
        return bytes_.size() - offset_;
    }

private:
    void require(std::size_t count) const {
        // 统一截断检查，让所有解析入口返回一致的异常类型。
        if (count > remaining()) {
            throw std::invalid_argument("truncated OSPF packet");
        }
    }

    const std::vector<std::uint8_t>& bytes_;
    std::size_t offset_ = 0;
};

void append_u8(std::vector<std::uint8_t>& bytes, std::uint8_t value) {
    // 追加一个原样传输的 8 位字段。
    bytes.push_back(value);
}

void append_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    // 以网络字节序追加 16 位字段。
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void append_u24(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    // OSPFv3 选项字段限定为 24 位，超范围必须拒绝而不是截断。
    if (value > 0x00ffffffU) {
        throw std::invalid_argument("OSPFv3 options exceed 24 bits");
    }
    bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    // 以高字节在前的顺序追加 32 位字段。
    bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void validate_packet_type(std::uint8_t raw_type) {
    // 当前编解码器只接受协议定义的五种报文类型。
    if (raw_type < static_cast<std::uint8_t>(OspfPacketType::Hello) ||
        raw_type > static_cast<std::uint8_t>(OspfPacketType::LinkStateAcknowledgment)) {
        throw std::invalid_argument("unknown OSPF packet type");
    }
}

std::vector<std::uint8_t> checksum_input_with_zeroed_field(
    const std::vector<std::uint8_t>& packet) {
    // 复制报文并清零公共头 checksum 字段，供 v2/v3 校验复用。
    if (packet.size() < 16) {
        throw std::invalid_argument("OSPF packet is shorter than its checksum field");
    }
    std::vector<std::uint8_t> copy = packet;
    copy[12] = 0;
    copy[13] = 0;
    return copy;
}

} // namespace

const char* to_string(OspfVersion version) noexcept {
    switch (version) {
    case OspfVersion::V2:
        return "ospfv2";
    case OspfVersion::V3:
        return "ospfv3";
    }
    return "unknown";
}

const char* to_string(OspfPacketType type) noexcept {
    switch (type) {
    case OspfPacketType::Hello:
        return "hello";
    case OspfPacketType::DatabaseDescription:
        return "database-description";
    case OspfPacketType::LinkStateRequest:
        return "link-state-request";
    case OspfPacketType::LinkStateUpdate:
        return "link-state-update";
    case OspfPacketType::LinkStateAcknowledgment:
        return "link-state-acknowledgment";
    }
    return "unknown";
}

std::size_t ospf_header_length(OspfVersion version) noexcept {
    // v2 额外包含 8 字节认证数据，因此头部比 v3 长 8 字节。
    return version == OspfVersion::V2 ? 24U : 16U;
}

OspfPacket parse_ospf_packet(const std::vector<std::uint8_t>& bytes) {
    // 解析流程先判版本和固定头长，再校验声明长度，最后拆出 payload。
    if (bytes.size() < 2) {
        throw std::invalid_argument("OSPF packet is too short");
    }

    const auto raw_version = bytes[0];
    OspfVersion version;
    if (raw_version == static_cast<std::uint8_t>(OspfVersion::V2)) {
        version = OspfVersion::V2;
    } else if (raw_version == static_cast<std::uint8_t>(OspfVersion::V3)) {
        version = OspfVersion::V3;
    } else {
        throw std::invalid_argument("unsupported OSPF version");
    }

    const std::size_t header_size = ospf_header_length(version);
    if (bytes.size() < header_size) {
        throw std::invalid_argument("OSPF packet is shorter than its header");
    }

    ByteReader reader(bytes);
    OspfHeader header;
    header.version = version;
    reader.read_u8();
    const std::uint8_t raw_type = reader.read_u8();
    validate_packet_type(raw_type);
    header.type = static_cast<OspfPacketType>(raw_type);
    header.packet_length = reader.read_u16();
    header.router_id = reader.read_u32();
    header.area_id = reader.read_u32();
    header.checksum = reader.read_u16();

    if (header.packet_length < header_size || header.packet_length != bytes.size()) {
        throw std::invalid_argument("OSPF packet length does not match input");
    }

    // 认证字段只属于 v2；v3 在对应位置保存实例号和保留字节。
    if (version == OspfVersion::V2) {
        header.authentication_type = reader.read_u16();
        for (std::uint8_t& byte : header.authentication) {
            byte = reader.read_u8();
        }
    } else {
        header.instance_id = reader.read_u8();
        reader.read_u8();
    }

    OspfPacket packet;
    packet.header = header;
    packet.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(header_size), bytes.end());
    return packet;
}

std::vector<std::uint8_t> serialize_ospf_packet(
    OspfHeader header,
    const std::vector<std::uint8_t>& payload) {
    // 先计算并写回 packet_length，再拼接版本相关字段和载荷。
    const std::size_t header_size = ospf_header_length(header.version);
    const std::size_t total_size = header_size + payload.size();
    if (total_size > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument("OSPF packet exceeds 65535 bytes");
    }

    header.packet_length = static_cast<std::uint16_t>(total_size);
    std::vector<std::uint8_t> bytes;
    bytes.reserve(total_size);
    append_u8(bytes, static_cast<std::uint8_t>(header.version));
    append_u8(bytes, static_cast<std::uint8_t>(header.type));
    append_u16(bytes, header.packet_length);
    append_u32(bytes, header.router_id);
    append_u32(bytes, header.area_id);
    append_u16(bytes, header.checksum);

    if (header.version == OspfVersion::V2) {
        append_u16(bytes, header.authentication_type);
        bytes.insert(bytes.end(), header.authentication.begin(), header.authentication.end());
    } else {
        append_u8(bytes, header.instance_id);
        append_u8(bytes, 0);
    }

    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

OspfHello parse_ospf_hello(const OspfPacket& packet) {
    // Hello 固定前 20 字节，剩余部分必须是 4 字节对齐的邻居 Router ID 列表。
    if (packet.header.type != OspfPacketType::Hello) {
        throw std::invalid_argument("packet is not an OSPF Hello packet");
    }
    if (packet.payload.size() < 20 || (packet.payload.size() - 20) % 4 != 0) {
        throw std::invalid_argument("invalid OSPF Hello payload length");
    }

    ByteReader reader(packet.payload);
    OspfHello hello;
    // v2/v3 的字段顺序不同，但都归一化为 OspfHello 供状态机使用。
    if (packet.header.version == OspfVersion::V2) {
        hello.network_mask = reader.read_u32();
        hello.hello_interval = reader.read_u16();
        hello.options = reader.read_u8();
        hello.router_priority = reader.read_u8();
        hello.dead_interval = reader.read_u32();
    } else {
        hello.interface_id = reader.read_u32();
        hello.router_priority = reader.read_u8();
        hello.options = reader.read_u24();
        hello.hello_interval = reader.read_u16();
        hello.dead_interval = reader.read_u16();
    }
    hello.designated_router = reader.read_u32();
    hello.backup_designated_router = reader.read_u32();

    while (reader.remaining() != 0) {
        hello.neighbors.push_back(reader.read_u32());
    }
    return hello;
}

std::vector<std::uint8_t> serialize_ospf_hello(
    OspfHeader header,
    const OspfHello& hello) {
    // 按头部版本选择 body 布局，并在写入前检查 v2/v3 的位宽限制。
    if (header.type != OspfPacketType::Hello) {
        throw std::invalid_argument("Hello body requires packet type Hello");
    }

    std::vector<std::uint8_t> payload;
    payload.reserve(20 + hello.neighbors.size() * 4);
    if (header.version == OspfVersion::V2) {
        if (hello.options > 0xffU) {
            throw std::invalid_argument("OSPFv2 options exceed 8 bits");
        }
        append_u32(payload, hello.network_mask);
        append_u16(payload, hello.hello_interval);
        append_u8(payload, static_cast<std::uint8_t>(hello.options));
        append_u8(payload, hello.router_priority);
        append_u32(payload, hello.dead_interval);
    } else {
        if (hello.dead_interval > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument("OSPFv3 dead interval exceeds 16 bits");
        }
        append_u32(payload, hello.interface_id);
        append_u8(payload, hello.router_priority);
        append_u24(payload, hello.options);
        append_u16(payload, hello.hello_interval);
        append_u16(payload, static_cast<std::uint16_t>(hello.dead_interval));
    }
    append_u32(payload, hello.designated_router);
    append_u32(payload, hello.backup_designated_router);
    for (const std::uint32_t neighbor : hello.neighbors) {
        append_u32(payload, neighbor);
    }
    return serialize_ospf_packet(header, payload);
}

std::uint16_t internet_checksum(const std::vector<std::uint8_t>& bytes) noexcept {
    // 按 16 位反码加法累加，奇数字节长度时末字节放在高八位。
    std::uint32_t sum = 0;
    std::size_t index = 0;
    while (index + 1 < bytes.size()) {
        sum += (static_cast<std::uint32_t>(bytes[index]) << 8U) | bytes[index + 1];
        index += 2;
    }
    if (index < bytes.size()) {
        sum += static_cast<std::uint32_t>(bytes[index]) << 8U;
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t compute_ospfv2_checksum(
    const std::vector<std::uint8_t>& serialized_packet) {
    // v2 校验排除认证 8 字节，只对公共头前 16 字节和 payload 求和。
    const OspfPacket packet = parse_ospf_packet(serialized_packet);
    if (packet.header.version != OspfVersion::V2) {
        throw std::invalid_argument("OSPFv2 checksum requires an OSPFv2 packet");
    }

    const std::vector<std::uint8_t> zeroed =
        checksum_input_with_zeroed_field(serialized_packet);
    std::vector<std::uint8_t> checksum_bytes;
    checksum_bytes.reserve(zeroed.size() - 8);
    checksum_bytes.insert(checksum_bytes.end(), zeroed.begin(), zeroed.begin() + 16);
    checksum_bytes.insert(checksum_bytes.end(), zeroed.begin() + 24, zeroed.end());
    return internet_checksum(checksum_bytes);
}

std::uint16_t compute_ospfv3_checksum(
    const std::vector<std::uint8_t>& serialized_packet,
    const std::array<std::uint8_t, 16>& source_address,
    const std::array<std::uint8_t, 16>& destination_address) {
    // v3 校验在 OSPF 载荷前加入 IPv6 伪首部，协议号固定为 89。
    const OspfPacket packet = parse_ospf_packet(serialized_packet);
    if (packet.header.version != OspfVersion::V3) {
        throw std::invalid_argument("OSPFv3 checksum requires an OSPFv3 packet");
    }

    const std::vector<std::uint8_t> zeroed =
        checksum_input_with_zeroed_field(serialized_packet);
    std::vector<std::uint8_t> pseudo_header;
    pseudo_header.reserve(40 + zeroed.size());
    pseudo_header.insert(pseudo_header.end(), source_address.begin(), source_address.end());
    pseudo_header.insert(pseudo_header.end(), destination_address.begin(), destination_address.end());
    append_u32(pseudo_header, static_cast<std::uint32_t>(zeroed.size()));
    pseudo_header.push_back(0);
    pseudo_header.push_back(0);
    pseudo_header.push_back(0);
    pseudo_header.push_back(89);
    pseudo_header.insert(pseudo_header.end(), zeroed.begin(), zeroed.end());
    return internet_checksum(pseudo_header);
}

} // namespace ospf_gateway
