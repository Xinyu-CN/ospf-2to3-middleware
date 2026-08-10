/*
 * LSA 编解码实现：使用显式的大端读写函数构造线速字节，避免依赖主机对齐和
 * 字节序。AS-External-LSA 的 body 根据协议域选择 IPv4 或 IPv6 前缀格式。
 */
#include "ospf_gateway/lsa.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>

namespace ospf_gateway {

namespace {

constexpr std::uint16_t kLsaHeaderLength = 20;
constexpr std::uint16_t kMaxAge = 3600;

void append_u8(std::vector<std::uint8_t>& bytes, std::uint8_t value) {
    // 逐字节追加，保持序列化游标与协议字段边界一致。
    bytes.push_back(value);
}

void append_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    // OSPF 线速字段统一采用网络字节序（高字节在前）。
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    // 32 位 Router ID、序列号和度量按同样的高位优先规则编码。
    bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 16U));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t& offset) {
    // 读取前检查剩余长度，所有截断输入都转换为可诊断的 invalid_argument。
    if (bytes.size() - offset < 2) {
        throw std::invalid_argument("truncated LSA field");
    }
    const std::uint16_t value =
        (static_cast<std::uint16_t>(bytes[offset]) << 8U) |
        static_cast<std::uint16_t>(bytes[offset + 1]);
    offset += 2;
    return value;
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& bytes, std::size_t& offset) {
    // offset 由调用者共享，成功后始终前进四字节。
    if (bytes.size() - offset < 4) {
        throw std::invalid_argument("truncated LSA field");
    }
    const std::uint32_t value =
        (static_cast<std::uint32_t>(bytes[offset]) << 24U) |
        (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U) |
        (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U) |
        static_cast<std::uint32_t>(bytes[offset + 3]);
    offset += 4;
    return value;
}

std::uint32_t prefix_id(const Prefix& prefix) {
    // LSA 的 Link State ID 需要稳定的 32 位值；FNV-1a 足以覆盖常见前缀。
    const std::string text = prefix.to_string();
    std::uint32_t hash = 2166136261U;
    for (const unsigned char byte : text) {
        hash ^= byte;
        hash *= 16777619U;
    }
    return hash;
}

struct PrefixBytes {
    AddressFamily family;
    std::uint8_t length;
    std::array<std::uint8_t, 16> bytes{};
};

PrefixBytes prefix_bytes(const Prefix& prefix) {
    // 从规范化 CIDR 文本恢复地址字节，并保留有效前缀长度。
    const std::string text = prefix.to_string();
    const std::size_t slash = text.find('/');
    const std::string address = text.substr(0, slash);
    const unsigned long length = std::stoul(text.substr(slash + 1));
    PrefixBytes result{prefix.family(), static_cast<std::uint8_t>(length), {}};
    const int family = prefix.is_ipv4() ? AF_INET : AF_INET6;
    if (inet_pton(family, address.c_str(), result.bytes.data()) != 1) {
        throw std::invalid_argument("failed to encode route prefix");
    }
    return result;
}

std::string prefix_text(AddressFamily family,
                        const std::array<std::uint8_t, 16>& bytes,
                        std::uint8_t length) {
    char address[INET6_ADDRSTRLEN] = {};
    const int address_family = family == AddressFamily::IPv4 ? AF_INET : AF_INET6;
    if (inet_ntop(address_family, bytes.data(), address, sizeof(address)) == nullptr) {
        throw std::runtime_error("failed to decode route prefix");
    }
    return std::string(address) + "/" + std::to_string(length);
}

void append_prefix(std::vector<std::uint8_t>& bytes, const PrefixBytes& prefix) {
    // LSA 前缀只发送覆盖有效位的字节，随后填充到 32 位边界。
    const std::size_t byte_count = (prefix.length + 7U) / 8U;
    bytes.insert(bytes.end(), prefix.bytes.begin(), prefix.bytes.begin() + byte_count);
    while (bytes.size() % 4U != 0) {
        bytes.push_back(0);
    }
}

std::uint32_t metric_field(const Route& route) {
    // AS-External-LSA 用最高位表示 E1/E2，其余 24 位保存外部度量。
    if (route.metric > 0x00ffffffU) {
        throw std::invalid_argument("external route metric exceeds 24 bits");
    }
    const std::uint32_t e_bit = route.route_type == RouteType::External2 ? 0x80000000U : 0;
    return e_bit | route.metric;
}

std::uint32_t ipv4_mask(std::uint8_t length) {
    // OSPFv2 外部 LSA 直接携带 32 位掩码，/0 需特殊处理避免移位 32 位。
    if (length > 32) {
        throw std::invalid_argument("IPv4 prefix length exceeds 32 bits");
    }
    if (length == 0) {
        return 0;
    }
    return 0xffffffffU << (32U - length);
}

void finalize_lsa(Lsa& lsa) {
    // 先写入最终长度，再以校验字段为零的完整序列计算 Fletcher 校验和。
    lsa.header.length = static_cast<std::uint16_t>(kLsaHeaderLength + lsa.body.size());
    if (lsa.header.length < kLsaHeaderLength) {
        throw std::invalid_argument("LSA is too large");
    }
    const std::vector<std::uint8_t> serialized = serialize_lsa(lsa);
    lsa.header.checksum = compute_lsa_checksum(serialized);
}

} // namespace

bool LsaKey::operator<(const LsaKey& other) const noexcept {
    // map 使用协议规定的身份三元组排序，使 LSDB 快照具有确定顺序。
    if (type != other.type) {
        return type < other.type;
    }
    if (link_state_id != other.link_state_id) {
        return link_state_id < other.link_state_id;
    }
    return advertising_router < other.advertising_router;
}

bool LsaKey::operator==(const LsaKey& other) const noexcept {
    // 序列号、年龄和校验和变化都不影响“同一 LSA 键”的判断。
    return type == other.type && link_state_id == other.link_state_id &&
           advertising_router == other.advertising_router;
}

LsaKey Lsa::key() const noexcept {
    // 只取三项身份字段，实例新旧由 LinkStateDatabase::install() 单独比较。
    return {header.type, header.link_state_id, header.advertising_router};
}

LsaInstallResult LinkStateDatabase::install(Lsa lsa) {
    // 以序列号为主、校验和为辅选择实例；年龄不会单独决定新旧。
    lsa.header.length = static_cast<std::uint16_t>(kLsaHeaderLength + lsa.body.size());
    const auto iterator = entries_.find(lsa.key());
    if (iterator == entries_.end()) {
        entries_.insert_or_assign(lsa.key(), std::move(lsa));
        return LsaInstallResult::Installed;
    }

    const Lsa& old = iterator->second;
    if (lsa.header.sequence_number < old.header.sequence_number ||
        (lsa.header.sequence_number == old.header.sequence_number &&
         lsa.header.checksum < old.header.checksum)) {
        return LsaInstallResult::OlderIgnored;
    }
    if (lsa.header.sequence_number == old.header.sequence_number &&
        lsa.header.checksum == old.header.checksum) {
        return LsaInstallResult::SameIgnored;
    }

    entries_.insert_or_assign(lsa.key(), std::move(lsa));
    return LsaInstallResult::Replaced;
}

bool LinkStateDatabase::remove(const LsaKey& key) {
    // erase 的返回值天然表达“是否真的存在并删除了条目”。
    return entries_.erase(key) != 0;
}

void LinkStateDatabase::clear() noexcept {
    // Speaker 停止或重置时清空全部 LSDB 状态。
    entries_.clear();
}

std::optional<Lsa> LinkStateDatabase::find(const LsaKey& key) const {
    // 返回副本，调用方不会持有内部 map 的可变引用。
    const auto iterator = entries_.find(key);
    if (iterator == entries_.end()) {
        return std::nullopt;
    }
    return iterator->second;
}

std::vector<Lsa> LinkStateDatabase::all() const {
    // 生成独立快照供泛洪或诊断使用，避免迭代器生命周期泄漏。
    std::vector<Lsa> result;
    result.reserve(entries_.size());
    for (const auto& entry : entries_) {
        result.push_back(entry.second);
    }
    return result;
}

void LinkStateDatabase::age(std::uint16_t seconds) noexcept {
    // 年龄按秒累加并在 MaxAge 截断，防止 16 位字段回绕。
    for (auto& entry : entries_) {
        const std::uint32_t aged = static_cast<std::uint32_t>(entry.second.header.age) + seconds;
        entry.second.header.age = static_cast<std::uint16_t>(
            std::min(aged, static_cast<std::uint32_t>(kMaxAge)));
    }
}

std::size_t LinkStateDatabase::size() const noexcept {
    return entries_.size();
}

Lsa parse_lsa(const std::vector<std::uint8_t>& bytes, std::size_t& offset) {
    // 先解析固定头，再按 length 截取 body；offset 最终指向下一条 LSA。
    if (bytes.size() - offset < kLsaHeaderLength) {
        throw std::invalid_argument("truncated LSA header");
    }
    Lsa lsa;
    lsa.header.age = read_u16(bytes, offset);
    lsa.header.type = read_u16(bytes, offset);
    lsa.header.link_state_id = read_u32(bytes, offset);
    lsa.header.advertising_router = read_u32(bytes, offset);
    lsa.header.sequence_number = read_u32(bytes, offset);
    lsa.header.checksum = read_u16(bytes, offset);
    lsa.header.length = read_u16(bytes, offset);
    if (lsa.header.length < kLsaHeaderLength ||
        lsa.header.length > bytes.size() - offset + kLsaHeaderLength) {
        throw std::invalid_argument("invalid LSA length");
    }
    const std::size_t body_size = lsa.header.length - kLsaHeaderLength;
    lsa.body.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                    bytes.begin() + static_cast<std::ptrdiff_t>(offset + body_size));
    offset += body_size;
    return lsa;
}

std::vector<std::uint8_t> serialize_lsa(Lsa lsa) {
    // 序列化前重新计算 length，允许调用者只修改 body 而不手工维护长度。
    if (lsa.body.size() > std::numeric_limits<std::uint16_t>::max() - kLsaHeaderLength) {
        throw std::invalid_argument("LSA body is too large");
    }
    lsa.header.length = static_cast<std::uint16_t>(kLsaHeaderLength + lsa.body.size());
    std::vector<std::uint8_t> bytes;
    bytes.reserve(lsa.header.length);
    append_u16(bytes, lsa.header.age);
    append_u16(bytes, lsa.header.type);
    append_u32(bytes, lsa.header.link_state_id);
    append_u32(bytes, lsa.header.advertising_router);
    append_u32(bytes, lsa.header.sequence_number);
    append_u16(bytes, lsa.header.checksum);
    append_u16(bytes, lsa.header.length);
    bytes.insert(bytes.end(), lsa.body.begin(), lsa.body.end());
    return bytes;
}

std::vector<Lsa> parse_link_state_update(const std::vector<std::uint8_t>& payload) {
    // LSU 前四字节是 LSA 数量，后续必须恰好解析出这么多条完整 LSA。
    if (payload.size() < 4) {
        throw std::invalid_argument("LSU payload is missing its LSA count");
    }
    std::size_t offset = 0;
    const std::uint32_t count = read_u32(payload, offset);
    if (count > payload.size() / kLsaHeaderLength) {
        throw std::invalid_argument("LSU LSA count is impossible for payload size");
    }
    std::vector<Lsa> lsas;
    lsas.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        lsas.push_back(parse_lsa(payload, offset));
    }
    if (offset != payload.size()) {
        throw std::invalid_argument("LSU contains trailing bytes");
    }
    return lsas;
}

std::vector<std::uint8_t> serialize_link_state_update(const std::vector<Lsa>& lsas) {
    // 计数器和 LSA 列表按 OSPF LSU 顺序写入，空列表仍保留计数器字段。
    std::vector<std::uint8_t> bytes;
    append_u32(bytes, static_cast<std::uint32_t>(lsas.size()));
    for (const Lsa& lsa : lsas) {
        const std::vector<std::uint8_t> encoded = serialize_lsa(lsa);
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    return bytes;
}

std::vector<LsaHeader> parse_link_state_acknowledgment(
    const std::vector<std::uint8_t>& payload) {
    // LSAck 只允许连续的 20 字节头，任何 body 或半截头都属于畸形报文。
    if (payload.size() % kLsaHeaderLength != 0) {
        throw std::invalid_argument("LSAck payload is not a sequence of LSA headers");
    }
    std::vector<LsaHeader> headers;
    std::size_t offset = 0;
    while (offset != payload.size()) {
        Lsa lsa = parse_lsa(payload, offset);
        if (!lsa.body.empty()) {
            throw std::invalid_argument("LSAck entry contains an LSA body");
        }
        headers.push_back(lsa.header);
    }
    return headers;
}

std::vector<std::uint8_t> serialize_link_state_acknowledgment(
    const std::vector<LsaHeader>& headers) {
    // 复用通用 LSA 序列化器，但传入空 body 以生成纯头部确认报文。
    std::vector<std::uint8_t> bytes;
    bytes.reserve(headers.size() * kLsaHeaderLength);
    for (const LsaHeader& header : headers) {
        Lsa lsa{header, {}};
        const std::vector<std::uint8_t> encoded = serialize_lsa(lsa);
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    return bytes;
}

std::uint16_t compute_lsa_checksum(const std::vector<std::uint8_t>& serialized_lsa) {
    // 按 RFC 的 Fletcher 规则跳过 Age 两字节，并将 checksum 字段视为零。
    if (serialized_lsa.size() < kLsaHeaderLength || serialized_lsa.size() > 0xffffU) {
        throw std::invalid_argument("invalid serialized LSA length");
    }
    std::vector<std::uint8_t> bytes = serialized_lsa;
    bytes[16] = 0;
    bytes[17] = 0;

    std::uint32_t c0 = 0;
    std::uint32_t c1 = 0;
    for (std::size_t index = 2; index < bytes.size(); ++index) {
        c0 = (c0 + bytes[index]) % 255U;
        c1 = (c1 + c0) % 255U;
    }

    const std::uint32_t length = static_cast<std::uint32_t>(bytes.size());
    const std::int64_t raw_x =
        (static_cast<std::int64_t>(length) - 15) * static_cast<std::int64_t>(c0) -
        static_cast<std::int64_t>(c1);
    const std::int64_t x = ((raw_x % 255) + 255) % 255;
    const std::int64_t y =
        ((510 - static_cast<std::int64_t>(c0) - x) % 255 + 255) % 255;
    return static_cast<std::uint16_t>((static_cast<std::uint32_t>(x) << 8U) |
                                      static_cast<std::uint32_t>(y));
}

Lsa make_external_lsa(const Route& route,
                      OspfVersion version,
                      std::uint32_t advertising_router,
                      std::uint32_t sequence_number) {
    // 先验证版本与地址族，再分别写入 v2 掩码格式或 v3 前缀长度格式。
    const PrefixBytes prefix = prefix_bytes(route.prefix);
    if (version == OspfVersion::V2 && !route.prefix.is_ipv4()) {
        throw std::invalid_argument("OSPFv2 external LSA requires an IPv4 route");
    }
    if (version == OspfVersion::V3 &&
        route.learned_from == ProtocolDomain::OspfV2 && !route.prefix.is_ipv4()) {
        throw std::invalid_argument("OSPFv3 IPv4 AF external LSA requires IPv4 route");
    }

    Lsa lsa;
    lsa.header.type = version == OspfVersion::V2 ? kAsExternalLsaTypeV2 : kAsExternalLsaTypeV3;
    lsa.header.link_state_id = route.prefix.is_ipv4() ?
                                   (static_cast<std::uint32_t>(prefix.bytes[0]) << 24U) |
                                   (static_cast<std::uint32_t>(prefix.bytes[1]) << 16U) |
                                   (static_cast<std::uint32_t>(prefix.bytes[2]) << 8U) |
                                   prefix.bytes[3]
                               : prefix_id(route.prefix);
    lsa.header.advertising_router = advertising_router;
    lsa.header.sequence_number = sequence_number;

    if (version == OspfVersion::V2) {
        append_u32(lsa.body, ipv4_mask(prefix.length));
        append_u32(lsa.body, metric_field(route));
        append_u32(lsa.body, 0);
        append_u32(lsa.body, route.tag);
    } else {
        append_u32(lsa.body, metric_field(route));
        append_u8(lsa.body, prefix.length);
        append_u8(lsa.body, 0);
        append_u16(lsa.body, 0);
        append_prefix(lsa.body, prefix);
        append_u32(lsa.body, route.tag);
    }
    finalize_lsa(lsa);
    return lsa;
}

std::optional<Route> decode_external_lsa(
    const Lsa& lsa,
    ProtocolDomain domain,
    const std::string& next_hop,
    std::uint32_t interface_index) {
    // 只解码目标域对应的 AS-External 类型；其他 LSA 留给拓扑组件处理。
    const bool v2 = domain == ProtocolDomain::OspfV2;
    const bool v3 = domain == ProtocolDomain::OspfV3IPv4 || domain == ProtocolDomain::OspfV3IPv6;
    if (!v2 && !v3) {
        return std::nullopt;
    }
    if ((v2 && lsa.header.type != kAsExternalLsaTypeV2) ||
        (v3 && lsa.header.type != kAsExternalLsaTypeV3)) {
        return std::nullopt;
    }

    std::size_t offset = 0;
    if (v2) {
        // v2 body 固定为掩码、度量、转发地址和标签四个 32 位字段。
        if (lsa.body.size() < 16) {
            return std::nullopt;
        }
        const std::uint32_t mask = read_u32(lsa.body, offset);
        const std::uint32_t metric = read_u32(lsa.body, offset);
        (void)read_u32(lsa.body, offset);
        const std::uint32_t tag = read_u32(lsa.body, offset);
        const std::string prefix =
            std::to_string((lsa.header.link_state_id >> 24U) & 0xffU) + "." +
            std::to_string((lsa.header.link_state_id >> 16U) & 0xffU) + "." +
            std::to_string((lsa.header.link_state_id >> 8U) & 0xffU) + "." +
            std::to_string(lsa.header.link_state_id & 0xffU) + "/" +
            std::to_string(__builtin_popcount(mask));
        const RouteType type = (metric & 0x80000000U) != 0 ?
                                   RouteType::External2 : RouteType::External1;
        return Route(Prefix::parse(prefix), domain, type, metric & 0x00ffffffU, tag,
                     "ospf-external", next_hop, interface_index);
    }

    if (lsa.body.size() < 8) {
        return std::nullopt;
    }
    // v3 body 先给出度量和前缀长度，再按 32 位边界填充并读取标签。
    const std::uint32_t metric = read_u32(lsa.body, offset);
    const std::uint8_t prefix_length = lsa.body[offset++];
    (void)lsa.body[offset++];
    offset += 2;
    if (prefix_length > (domain == ProtocolDomain::OspfV3IPv4 ? 32 : 128)) {
        return std::nullopt;
    }
    const std::size_t prefix_bytes_count = (prefix_length + 7U) / 8U;
    if (lsa.body.size() - offset < prefix_bytes_count) {
        return std::nullopt;
    }
    std::array<std::uint8_t, 16> address{};
    std::copy_n(lsa.body.begin() + static_cast<std::ptrdiff_t>(offset),
                prefix_bytes_count, address.begin());
    offset += prefix_bytes_count;
    while (offset % 4U != 0) {
        ++offset;
    }
    if (lsa.body.size() - offset < 4) {
        return std::nullopt;
    }
    const std::uint32_t tag = read_u32(lsa.body, offset);
    const AddressFamily family = domain == ProtocolDomain::OspfV3IPv4 ?
                                     AddressFamily::IPv4 : AddressFamily::IPv6;
    const RouteType type = (metric & 0x80000000U) != 0 ?
                               RouteType::External2 : RouteType::External1;
    return Route(Prefix::parse(prefix_text(family, address, prefix_length)), domain, type,
                 metric & 0x00ffffffU, tag, "ospf-external", next_hop, interface_index);
}

} // namespace ospf_gateway
