#pragma once

/*
 * 路由领域模型：定义地址族、协议域、路由类型、规范化前缀以及路由对象。
 * 该头文件只描述数据和轻量操作；真正的地址解析、前缀掩码和策略变换
 * 位于 src/gateway.cpp 中，便于协议适配器共享同一套语义。
 */

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace ospf_gateway {

enum class AddressFamily {
    // OSPFv2 与 OSPFv3 IPv4 AF 共同使用的 IPv4 地址族。
    IPv4,
    // 仅由 OSPFv3 IPv6 域处理的 IPv6 地址族。
    IPv6,
};

enum class ProtocolDomain {
    // 传统 OSPFv2 IPv4 路由域。
    OspfV2,
    // OSPFv3 的 IPv4 Address Family 路由域。
    OspfV3IPv4,
    // OSPFv3 原生 IPv6 路由域。
    OspfV3IPv6,
};

enum class RouteType {
    // 区域内路由。
    IntraArea,
    // 区域间路由。
    InterArea,
    // 外部类型 1，度量包含内部路径代价。
    External1,
    // 外部类型 2，外部度量优先于内部路径代价。
    External2,
};

/** Converts an address family enum to a stable lowercase name. */
const char* to_string(AddressFamily family) noexcept;

/** Converts a routing-protocol domain enum to a stable lowercase name. */
const char* to_string(ProtocolDomain domain) noexcept;

/** Converts a route-type enum to a stable printable name. */
const char* to_string(RouteType type) noexcept;

class Prefix {
public:
    Prefix() = delete;

    /**
     * Parses and normalizes an IPv4 or IPv6 CIDR prefix.
     *
     * Host bits are cleared, so `10.0.0.1/8` becomes `10.0.0.0/8`.
     * Invalid addresses and prefix lengths throw std::invalid_argument.
     */
    static Prefix parse(const std::string& text);

    /** Returns whether this prefix is IPv4 or IPv6. */
    // 中文：返回前缀所属的地址族，解析后该值不会再改变。
    AddressFamily family() const noexcept { return family_; }

    /** Returns the prefix length in bits. */
    // 中文：返回 CIDR 的有效位数，IPv4 范围为 0..32，IPv6 范围为 0..128。
    std::uint8_t length() const noexcept { return length_; }

    /** Returns true when this prefix belongs to the IPv4 address family. */
    // 中文：用于协议域校验和选择网络字节序地址长度。
    bool is_ipv4() const noexcept { return family_ == AddressFamily::IPv4; }

    /** Returns true when this prefix belongs to the IPv6 address family. */
    // 中文：用于阻止 IPv6 路由误进入 OSPFv2 或 OSPFv3 IPv4 AF。
    bool is_ipv6() const noexcept { return family_ == AddressFamily::IPv6; }

    /** Returns true when `other` is the same family and is contained by this prefix. */
    // 中文：比较只读取规范化后的有效位，不受主机位或地址数组尾部影响。
    bool contains(const Prefix& other) const noexcept;

    /** Formats the normalized prefix back to CIDR notation. */
    // 中文：输出可作为 RouteTable 的稳定键，也可直接交给 inet_pton 重新编码。
    std::string to_string() const;

    /** Compares family, prefix length, and all significant address bits. */
    // 中文：由于 parse() 已清零主机位，数组整体比较即可得到确定结果。
    friend bool operator==(const Prefix& left, const Prefix& right) noexcept;

    /** Negates Prefix equality. */
    friend bool operator!=(const Prefix& left, const Prefix& right) noexcept {
        return !(left == right);
    }

private:
    Prefix(AddressFamily family, std::uint8_t length,
           const std::array<std::uint8_t, 16>& bytes)
        : family_(family), length_(length), bytes_(bytes) {}

    AddressFamily family_;
    std::uint8_t length_;
    std::array<std::uint8_t, 16> bytes_{};
};

struct Route {
    // 中文：Route 同时携带前缀、来源域和发布时需要改写的属性。
    // next_hop/interface_index 是接收接口的转发元数据，不参与前缀相等性判断。
    Prefix prefix;                         // 中文：规范化后的目标网络前缀。
    ProtocolDomain learned_from;           // 中文：产生该路由的协议域。
    RouteType route_type = RouteType::IntraArea;  // 中文：原始或导出后的路由类型。
    std::uint32_t metric = 0;              // 中文：外部度量，发布时可被策略改写。
    std::uint32_t tag = 0;                 // 中文：32 位防环标签或协议外部标签。
    std::string origin;                    // 中文：来源描述，仅用于诊断和 LSA 解码标记。
    std::string next_hop;                  // 中文：接收报文的下一跳文本地址。
    std::uint32_t interface_index = 0;     // 中文：安装 FIB 时使用的 Linux 接口索引。

    /**
     * Creates a route learned from one protocol domain.
     *
     * The constructor does not perform family/domain validation; that check is
     * performed when the route enters RouteGateway::learn(). next_hop and
     * interface_index are receive-side forwarding metadata used by Linux FIB
     * installation and are not part of the route prefix itself.
     */
    Route(Prefix route_prefix, ProtocolDomain source,
          RouteType type = RouteType::IntraArea,
          std::uint32_t route_metric = 0,
          std::uint32_t route_tag = 0,
          std::string route_origin = {},
          std::string route_next_hop = {},
          std::uint32_t route_interface_index = 0)
        : prefix(std::move(route_prefix)),
          learned_from(source),
          route_type(type),
          metric(route_metric),
          tag(route_tag),
          origin(std::move(route_origin)),
          next_hop(std::move(route_next_hop)),
          interface_index(route_interface_index) {}
};

} // namespace ospf_gateway
