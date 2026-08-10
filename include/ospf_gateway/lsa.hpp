#pragma once

/*
 * LSA/LSDB 层负责 20 字节 LSA 头、AS-External-LSA 的编码解码、Fletcher 校验
 * 以及按序列号和校验和选择新实例。它保存不透明 body，避免把尚未实现的拓扑
 * LSA 类型错误地解释成外部路由。
 */

#include "ospf_gateway/ospf_packet.hpp"
#include "ospf_gateway/route.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ospf_gateway {

constexpr std::uint16_t kRouterLsaType = 1;
constexpr std::uint16_t kNetworkLsaType = 2;
constexpr std::uint16_t kSummaryLsaType = 3;
constexpr std::uint16_t kAsbrSummaryLsaType = 4;
constexpr std::uint16_t kAsExternalLsaTypeV2 = 5;
constexpr std::uint16_t kAsExternalLsaTypeV3 = 0x4005;

/** The key that uniquely identifies one LSA in an LSDB. */
struct LsaKey {
    // 中文：三元组共同定位一条 LSA；序列号变化不会改变这个键。
    std::uint16_t type = 0;                    // 中文：LSA 类型（v2/v3 值可能不同）。
    std::uint32_t link_state_id = 0;           // 中文：链路状态标识。
    std::uint32_t advertising_router = 0;      // 中文：发布该 LSA 的 Router ID。

    bool operator<(const LsaKey& other) const noexcept;
    bool operator==(const LsaKey& other) const noexcept;
};

/** The 20-byte LSA header shared by OSPFv2 and OSPFv3. */
struct LsaHeader {
    // 中文：age/type/id/advertising_router/sequence/checksum/length 按线速字段保存。
    std::uint16_t age = 0;                     // 中文：LSA 已存在的秒数，最大为 MaxAge。
    std::uint16_t type = 0;                    // 中文：LSA 类型字段。
    std::uint32_t link_state_id = 0;           // 中文：该类型下的实例标识。
    std::uint32_t advertising_router = 0;      // 中文：原始发布者 Router ID。
    std::uint32_t sequence_number = 0x80000001U;  // 中文：实例新旧比较的主排序键。
    std::uint16_t checksum = 0;                // 中文：Fletcher 校验和。
    std::uint16_t length = 20;                 // 中文：头部加 body 的总字节数。
};

/** One decoded LSA header and its opaque body bytes. */
struct Lsa {
    // 中文：body 不含 20 字节头，serialize_lsa() 会在前面重新拼接。
    LsaHeader header;
    std::vector<std::uint8_t> body;

    /** Returns the database key represented by this LSA. */
    LsaKey key() const noexcept;
};

/** Result of trying to install an LSA into an LSDB. */
enum class LsaInstallResult {
    // 中文：用于区分首次写入、替换、旧实例丢弃和完全相同实例忽略。
    Installed,
    Replaced,
    OlderIgnored,
    SameIgnored,
};

/**
 * In-memory link-state database.
 *
 * It stores opaque LSAs, replaces newer instances, and can age entries. SPF
 * calculation is deliberately separate so this class can be reused by both
 * OSPFv2 and OSPFv3 speakers.
 */
class LinkStateDatabase {
public:
    /** Installs an LSA according to sequence/checksum ordering. */
    // 中文：序列号较新或同序列号校验和较大时替换旧实例。
    LsaInstallResult install(Lsa lsa);

    /** Removes one LSA by key and reports whether it existed. */
    // 中文：返回 false 表示键不存在，调用方可以安全地重复清理。
    bool remove(const LsaKey& key);

    /** Removes all LSAs from the database. */
    void clear() noexcept;

    /** Returns the current LSA for a key, or nullopt when absent. */
    std::optional<Lsa> find(const LsaKey& key) const;

    /** Returns a snapshot of all LSAs. */
    std::vector<Lsa> all() const;

    /** Increases LSA ages by seconds, capped at MaxAge. */
    // 中文：年龄达到 3600 后保持 MaxAge，用于触发泛洪删除而不发生回绕。
    void age(std::uint16_t seconds) noexcept;

    /** Returns the number of stored LSAs. */
    std::size_t size() const noexcept;

private:
    std::map<LsaKey, Lsa> entries_;
};

/** Decodes one LSA from bytes beginning at offset and advances offset. */
// 中文：输入可包含多条 LSA，offset 由函数推进以支持连续解析。
Lsa parse_lsa(const std::vector<std::uint8_t>& bytes, std::size_t& offset);

/** Encodes one LSA including its 20-byte header. */
// 中文：body 长度会重新写回头部 length 字段，返回完整线速字节。
std::vector<std::uint8_t> serialize_lsa(Lsa lsa);

/** Parses the body of an OSPF Link State Update packet. */
// 中文：首字段为数量，函数拒绝数量与剩余字节不一致的 LSU。
std::vector<Lsa> parse_link_state_update(const std::vector<std::uint8_t>& payload);

/** Encodes an OSPF Link State Update body containing a list of LSAs. */
// 中文：空列表仍编码为数量 0，便于调用方统一处理边界。
std::vector<std::uint8_t> serialize_link_state_update(const std::vector<Lsa>& lsas);

/** Parses an OSPF Link State Acknowledgment body. */
// 中文：LSAck 只能包含 LSA 头，不允许携带 body。
std::vector<LsaHeader> parse_link_state_acknowledgment(
    const std::vector<std::uint8_t>& payload);

/** Encodes an OSPF Link State Acknowledgment body. */
// 中文：将每个头包装成空 body 的 Lsa 后复用通用序列化路径。
std::vector<std::uint8_t> serialize_link_state_acknowledgment(
    const std::vector<LsaHeader>& headers);

/** Computes the OSPF Fletcher checksum for a serialized LSA. */
// 中文：返回值可直接写入 LsaHeader::checksum，输入必须包含完整 LSA。
std::uint16_t compute_lsa_checksum(const std::vector<std::uint8_t>& serialized_lsa);

/**
 * Creates an AS-External-LSA from a route.
 *
 * IPv4 routes are accepted for OSPFv2 and OSPFv3 IPv4 AF. IPv6 routes are
 * accepted for OSPFv3 IPv6. The returned LSA has a valid body and checksum.
 */
Lsa make_external_lsa(const Route& route,
                      OspfVersion version,
                      std::uint32_t advertising_router,
                      std::uint32_t sequence_number);

/**
 * Decodes an AS-External-LSA into a route.
 *
 * The next-hop and interface metadata are supplied by the receiving
 * interface because those values are not necessarily present in the LSA.
 */
std::optional<Route> decode_external_lsa(
    const Lsa& lsa,
    ProtocolDomain domain,
    const std::string& next_hop = {},
    std::uint32_t interface_index = 0);

} // namespace ospf_gateway
