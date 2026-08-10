#pragma once

/*
 * OSPF 报文编解码层：统一处理 v2/v3 公共头部、Hello 载荷和校验和。
 * 结构体中的整数使用主机序，只有序列化/反序列化边界才转换为网络序，
 * 这样上层状态机不会混淆字节序。
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ospf_gateway {

/** OSPF wire protocol version carried in the common packet header. */
enum class OspfVersion : std::uint8_t {
    // OSPFv2 头部含认证字段，长度为 24 字节。
    V2 = 2,
    V3 = 3,
};

/** OSPF packet type values shared by OSPFv2 and OSPFv3. */
enum class OspfPacketType : std::uint8_t {
    // 报文类型值遵循 RFC 中的线速编码。
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAcknowledgment = 5,
};

/** Returns a stable printable name for an OSPF protocol version. */
const char* to_string(OspfVersion version) noexcept;

/** Returns a stable printable name for an OSPF packet type. */
const char* to_string(OspfPacketType type) noexcept;

/** Returns the common-header size for the selected OSPF version. */
// 中文：v2 返回 24，v3 返回 16，供解析器在读取 payload 前做边界校验。
std::size_t ospf_header_length(OspfVersion version) noexcept;

/**
 * Common OSPF packet header.
 *
 * Router ID and Area ID are represented as host-order integers in C++ and are
 * converted to network byte order only while encoding or decoding a packet.
 * OSPFv2 uses authentication_type/authentication; OSPFv3 uses instance_id.
 */
struct OspfHeader {
    // 中文：公共头字段按协议顺序编码；v2 的认证字段和 v3 的实例号互斥。
    OspfVersion version = OspfVersion::V2;       // 中文：线协议版本。
    OspfPacketType type = OspfPacketType::Hello; // 中文：报文类型。
    std::uint16_t packet_length = 0;             // 中文：头部和 payload 的总长度。
    std::uint32_t router_id = 0;                 // 中文：发送者 Router ID，主机序保存。
    std::uint32_t area_id = 0;                  // 中文：所属区域 ID，主机序保存。
    std::uint16_t checksum = 0;                // 中文：序列化后的协议校验和。
    std::uint16_t authentication_type = 0;     // 中文：仅 OSPFv2 使用的认证类型。
    std::array<std::uint8_t, 8> authentication{}; // 中文：仅 OSPFv2 使用的认证数据。
    std::uint8_t instance_id = 0;              // 中文：仅 OSPFv3 使用的接口实例号。
};

/** Parsed common header plus the payload bytes that follow it. */
struct OspfPacket {
    OspfHeader header;
    std::vector<std::uint8_t> payload;
};

/**
 * OSPF Hello body normalized across OSPFv2 and OSPFv3.
 *
 * For OSPFv2, network_mask and the 32-bit dead_interval are used. For OSPFv3,
 * interface_id and the 16-bit range of dead_interval are used. The options
 * field is 8 bits on OSPFv2 and 24 bits on OSPFv3.
 */
struct OspfHello {
    // 中文：该结构把两种版本的 Hello 共有语义归一化，未使用的字段保持默认值。
    std::uint32_t network_mask = 0;             // 中文：v2 网络掩码，v3 不使用。
    std::uint32_t interface_id = 0;             // 中文：v3 接口 ID，v2 不使用。
    std::uint8_t router_priority = 0;           // 中文：DR 选举优先级。
    std::uint32_t options = 0;                  // 中文：v2 为 8 位，v3 为 24 位能力位。
    std::uint16_t hello_interval = 0;           // 中文：Hello 周期（秒）。
    std::uint32_t dead_interval = 0;            // 中文：失效判定时间，v3 线速仅 16 位。
    std::uint32_t designated_router = 0;        // 中文：当前 DR 的 Router ID。
    std::uint32_t backup_designated_router = 0; // 中文：当前 BDR 的 Router ID。
    std::vector<std::uint32_t> neighbors;       // 中文：邻居 Router ID 列表。
};

/**
 * Parses one complete OSPF packet.
 *
 * The input must contain exactly one packet. The declared packet length must
 * be at least the version-specific header size and must match the input size;
 * trailing or truncated bytes are rejected with std::invalid_argument.
 */
OspfPacket parse_ospf_packet(const std::vector<std::uint8_t>& bytes);

/**
 * Encodes a complete OSPF packet from a header and payload.
 *
 * The function updates header.packet_length. It preserves the checksum field;
 * checksum calculation is intentionally separate because OSPFv3 requires the
 * IPv6 pseudo-header, which is unavailable from this function alone.
 */
std::vector<std::uint8_t> serialize_ospf_packet(
    OspfHeader header,
    const std::vector<std::uint8_t>& payload);

/** Parses and validates an OSPF Hello packet body. */
// 中文：函数要求公共头 type 为 Hello，并检查固定字段和邻居列表的 4 字节对齐。
OspfHello parse_ospf_hello(const OspfPacket& packet);

/** Encodes an OSPF Hello packet using the version in header.version. */
// 中文：会验证 v2 选项、v3 选项和 Dead Interval 的位宽限制。
std::vector<std::uint8_t> serialize_ospf_hello(
    OspfHeader header,
    const OspfHello& hello);

/** Computes the Internet checksum over an arbitrary byte sequence. */
// 中文：这是 v2 checksum 和 v3 伪首部 checksum 共用的 16 位反码加法核心。
std::uint16_t internet_checksum(const std::vector<std::uint8_t>& bytes) noexcept;

/**
 * Computes the OSPFv2 checksum for an already serialized packet.
 *
 * OSPFv2 authentication bytes are excluded from the checksum. The checksum
 * field is treated as zero while calculating the result.
 */
std::uint16_t compute_ospfv2_checksum(
    const std::vector<std::uint8_t>& serialized_packet);

/**
 * Computes the OSPFv3 checksum using IPv6 source and destination addresses.
 *
 * The IPv6 pseudo-header is included and the checksum field in the packet is
 * treated as zero. The addresses must be in network-byte-order byte arrays.
 */
std::uint16_t compute_ospfv3_checksum(
    const std::vector<std::uint8_t>& serialized_packet,
    const std::array<std::uint8_t, 16>& source_address,
    const std::array<std::uint8_t, 16>& destination_address);

} // namespace ospf_gateway
