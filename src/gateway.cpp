/*
 * 路由网关实现：这里完成 CIDR 规范化、前缀策略匹配、度量改写以及三域路由表
 * 的重建。所有数据都在内存中维护，Speaker 只接收每次 reconcile() 生成的快照。
 */
#include "ospf_gateway/gateway.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace ospf_gateway {

namespace {

std::uint8_t max_prefix_length(AddressFamily family) noexcept {
    // IPv4/IPv6 的地址位宽不同，先集中计算上限，避免解析逻辑散落常量。
    return family == AddressFamily::IPv4 ? 32 : 128;
}

void mask_prefix(std::array<std::uint8_t, 16>& bytes,
                 AddressFamily family,
                 std::uint8_t length) noexcept {
    // 先保留完整字节，再掩掉最后一个部分字节，最后清零地址族之外的尾部。
    const std::size_t byte_count = family == AddressFamily::IPv4 ? 4 : 16;
    const std::size_t full_bytes = length / 8;
    const std::uint8_t remainder = static_cast<std::uint8_t>(length % 8);

    if (remainder != 0 && full_bytes < byte_count) {
        bytes[full_bytes] &= static_cast<std::uint8_t>(0xffU << (8U - remainder));
    }

    const std::size_t first_zero = full_bytes + (remainder == 0 ? 0 : 1);
    for (std::size_t index = first_zero; index < byte_count; ++index) {
        bytes[index] = 0;
    }
    for (std::size_t index = byte_count; index < bytes.size(); ++index) {
        bytes[index] = 0;
    }
}

bool same_bits(const std::array<std::uint8_t, 16>& left,
               const std::array<std::uint8_t, 16>& right,
               std::uint8_t bit_count) noexcept {
    // contains() 只需比较前缀有效位，尾部主机位即使不同也不影响匹配。
    const std::size_t full_bytes = bit_count / 8;
    const std::uint8_t remainder = static_cast<std::uint8_t>(bit_count % 8);

    for (std::size_t index = 0; index < full_bytes; ++index) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    if (remainder == 0) {
        return true;
    }

    const std::uint8_t mask = static_cast<std::uint8_t>(0xffU << (8U - remainder));
    return (left[full_bytes] & mask) == (right[full_bytes] & mask);
}

std::uint32_t saturating_add(std::uint32_t left, std::uint32_t right) noexcept {
    // 发布策略的度量不能回绕；溢出时固定在协议字段可表示的最大值。
    if (std::numeric_limits<std::uint32_t>::max() - left < right) {
        return std::numeric_limits<std::uint32_t>::max();
    }
    return left + right;
}

} // namespace

const char* to_string(AddressFamily family) noexcept {
    switch (family) {
    case AddressFamily::IPv4:
        return "ipv4";
    case AddressFamily::IPv6:
        return "ipv6";
    }
    return "unknown";
}

const char* to_string(ProtocolDomain domain) noexcept {
    switch (domain) {
    case ProtocolDomain::OspfV2:
        return "ospfv2";
    case ProtocolDomain::OspfV3IPv4:
        return "ospfv3-ipv4";
    case ProtocolDomain::OspfV3IPv6:
        return "ospfv3-ipv6";
    }
    return "unknown";
}

const char* to_string(RouteType type) noexcept {
    switch (type) {
    case RouteType::IntraArea:
        return "intra-area";
    case RouteType::InterArea:
        return "inter-area";
    case RouteType::External1:
        return "external-1";
    case RouteType::External2:
        return "external-2";
    }
    return "unknown";
}

Prefix Prefix::parse(const std::string& text) {
    // 解析阶段同时完成格式校验、地址族判断和主机位清零，保证 Prefix 可直接比较。
    const std::size_t slash = text.find('/');
    if (slash == std::string::npos || slash == 0 || slash == text.size() - 1) {
        throw std::invalid_argument("prefix must use address/length notation: " + text);
    }

    const std::string address = text.substr(0, slash);
    const std::string length_text = text.substr(slash + 1);
    std::size_t parsed_length = 0;
    unsigned long length = 0;
    try {
        length = std::stoul(length_text, &parsed_length, 10);
    } catch (const std::exception&) {
        throw std::invalid_argument("invalid prefix length: " + text);
    }
    if (parsed_length != length_text.size()) {
        throw std::invalid_argument("invalid prefix length: " + text);
    }

    // 冒号是 IPv6 文本的可靠区分符；inet_pton 随后负责最终合法性验证。
    const AddressFamily family = address.find(':') == std::string::npos
                                     ? AddressFamily::IPv4
                                     : AddressFamily::IPv6;
    if (length > max_prefix_length(family)) {
        throw std::invalid_argument("prefix length out of range: " + text);
    }

    std::array<std::uint8_t, 16> bytes{};
    const int address_family = family == AddressFamily::IPv4 ? AF_INET : AF_INET6;
    if (inet_pton(address_family, address.c_str(), bytes.data()) != 1) {
        throw std::invalid_argument("invalid IP address: " + text);
    }

    // 统一把例如 10.0.0.1/8 归一化成 10.0.0.0/8，作为表键时不会产生重复路由。
    mask_prefix(bytes, family, static_cast<std::uint8_t>(length));
    return Prefix(family, static_cast<std::uint8_t>(length), bytes);
}

bool Prefix::contains(const Prefix& other) const noexcept {
    // 父前缀必须同族、长度不大于子前缀，并且前 length_ 位完全相同。
    return family_ == other.family_ && length_ <= other.length_ &&
           same_bits(bytes_, other.bytes_, length_);
}

std::string Prefix::to_string() const {
    // 只格式化已经掩码过的地址，因此返回值可以安全用于 map 的稳定键。
    char address[INET6_ADDRSTRLEN] = {};
    const int address_family = family_ == AddressFamily::IPv4 ? AF_INET : AF_INET6;
    if (inet_ntop(address_family, bytes_.data(), address, sizeof(address)) == nullptr) {
        throw std::runtime_error("failed to format IP prefix");
    }
    return std::string(address) + "/" + std::to_string(length_);
}

bool operator==(const Prefix& left, const Prefix& right) noexcept {
    return left.family_ == right.family_ && left.length_ == right.length_ &&
           left.bytes_ == right.bytes_;
}

bool RoutePolicy::permits(const Prefix& prefix) const noexcept {
    // 第一条命中规则立即返回；没有命中时使用构造函数指定的默认决策。
    for (const PrefixRule& rule : rules_) {
        if (rule.matches(prefix)) {
            return rule.permit;
        }
    }
    return default_permit_;
}

Route RoutePolicy::transform(const Route& input, ProtocolDomain destination) const {
    // transform 保留下一跳等接收元数据，只改写跨域发布所需的来源、类型、度量和标签。
    Route output = input;
    output.learned_from = destination;
    output.route_type = export_type_;
    output.metric = metric_override_.value_or(saturating_add(input.metric, metric_add_));
    output.tag = export_tag_;
    output.origin = "ospf-gateway";
    return output;
}

RouteGateway::RouteGateway(RouteSpeaker& ospf_v2,
                           RouteSpeaker& ospf_v3_ipv4,
                           RouteSpeaker& ospf_v3_ipv6,
                           RoutePolicy v2_to_v3,
                           RoutePolicy v3_to_v2,
                           std::uint32_t loop_guard_tag)
    : ospf_v2_(ospf_v2),
      ospf_v3_ipv4_(ospf_v3_ipv4),
      ospf_v3_ipv6_(ospf_v3_ipv6),
      v2_to_v3_(std::move(v2_to_v3)),
      v3_to_v2_(std::move(v3_to_v2)),
      loop_guard_tag_(loop_guard_tag) {
    // 非零标签是环路保护的前提；同时检查三个 Speaker 的域，避免路由进入错误表。
    if (loop_guard_tag_ == 0) {
        throw std::invalid_argument("loop guard tag must be non-zero");
    }
    if (ospf_v2_.domain() != ProtocolDomain::OspfV2 ||
        ospf_v3_ipv4_.domain() != ProtocolDomain::OspfV3IPv4 ||
        ospf_v3_ipv6_.domain() != ProtocolDomain::OspfV3IPv6) {
        throw std::invalid_argument("speakers do not match their protocol domains");
    }
    // 两个方向都写入同一个标签，回流路由在任意入口都能被过滤。
    v2_to_v3_.set_export_tag(loop_guard_tag_);
    v3_to_v2_.set_export_tag(loop_guard_tag_);
    ospf_v2_.set_route_learn_handler([this](Route route) {
        learn(std::move(route));
    });
    ospf_v3_ipv4_.set_route_learn_handler([this](Route route) {
        learn(std::move(route));
    });
    ospf_v3_ipv6_.set_route_learn_handler([this](Route route) {
        learn(std::move(route));
    });
}

RouteGateway::~RouteGateway() {
    ospf_v2_.set_route_learn_handler({});
    ospf_v3_ipv4_.set_route_learn_handler({});
    ospf_v3_ipv6_.set_route_learn_handler({});
}

void RouteGateway::learn(Route route) {
    // 学习动作是“写入来源表 + 立即重建两个导出快照”，因此不会保留过期导出。
    const ProtocolDomain source = route.learned_from;
    const bool valid_family =
        (source == ProtocolDomain::OspfV2 && route.prefix.is_ipv4()) ||
        (source == ProtocolDomain::OspfV3IPv4 && route.prefix.is_ipv4()) ||
        (source == ProtocolDomain::OspfV3IPv6 && route.prefix.is_ipv6());
    if (!valid_family) {
        throw std::invalid_argument("route address family does not match its protocol domain");
    }

    table_for(source).insert_or_assign(route.prefix.to_string(), std::move(route));
    reconcile();
}

void RouteGateway::withdraw(ProtocolDomain source, const Prefix& prefix) {
    // 删除不存在的键也是幂等操作；reconcile() 会同步清除对端已发布的副本。
    table_for(source).erase(prefix.to_string());
    reconcile();
}

std::vector<Route> RouteGateway::build_v2_to_v3() const {
    // OSPFv2 只能向 OSPFv3 IPv4 AF 导出 IPv4；IPv6 表从不参与此方向。
    std::vector<Route> exported;
    for (const auto& entry : v2_routes_) {
        const Route& route = entry.second;
        // 先检查环路标签，再检查策略，避免无意义地变换将被丢弃的路由。
        if (route.tag == loop_guard_tag_ || !v2_to_v3_.permits(route.prefix)) {
            continue;
        }
        exported.push_back(v2_to_v3_.transform(route, ProtocolDomain::OspfV3IPv4));
    }
    return exported;
}

std::vector<Route> RouteGateway::build_v3_to_v2() const {
    // OSPFv3 IPv4 AF 到 OSPFv2 是唯一的反向路径；原生 IPv6 路由被明确隔离。
    std::vector<Route> exported;
    for (const auto& entry : v3_ipv4_routes_) {
        const Route& route = entry.second;
        if (route.tag == loop_guard_tag_ || !v3_to_v2_.permits(route.prefix)) {
            continue;
        }
        exported.push_back(v3_to_v2_.transform(route, ProtocolDomain::OspfV2));
    }
    return exported;
}

RouteGateway::RouteTable& RouteGateway::table_for(ProtocolDomain domain) {
    // 通过域枚举集中选择存储表，未知枚举值直接报错而不是静默丢路由。
    switch (domain) {
    case ProtocolDomain::OspfV2:
        return v2_routes_;
    case ProtocolDomain::OspfV3IPv4:
        return v3_ipv4_routes_;
    case ProtocolDomain::OspfV3IPv6:
        return v3_ipv6_routes_;
    }
    throw std::invalid_argument("unknown protocol domain");
}

const RouteGateway::RouteTable& RouteGateway::table_for(ProtocolDomain domain) const {
    // const 重载供构建导出快照使用，和可写版本保持相同的域映射。
    switch (domain) {
    case ProtocolDomain::OspfV2:
        return v2_routes_;
    case ProtocolDomain::OspfV3IPv4:
        return v3_ipv4_routes_;
    case ProtocolDomain::OspfV3IPv6:
        return v3_ipv6_routes_;
    }
    throw std::invalid_argument("unknown protocol domain");
}

void RouteGateway::reconcile() {
    // 先计算完整新快照，再一次性替换 Speaker 中的导出集合，避免增量更新留下残项。
    std::vector<Route> v2_to_v3 = build_v2_to_v3();
    std::vector<Route> v3_to_v2 = build_v3_to_v2();

    ospf_v3_ipv4_.replace_external_routes(v2_to_v3);
    ospf_v2_.replace_external_routes(v3_to_v2);
    ospf_v3_ipv6_.replace_external_routes({});

    stats_.learned_v2 = v2_routes_.size();
    stats_.learned_v3_ipv4 = v3_ipv4_routes_.size();
    stats_.learned_v3_ipv6 = v3_ipv6_routes_.size();
    stats_.exported_v2_to_v3 = v2_to_v3.size();
    stats_.exported_v3_to_v2 = v3_to_v2.size();
}

} // namespace ospf_gateway
