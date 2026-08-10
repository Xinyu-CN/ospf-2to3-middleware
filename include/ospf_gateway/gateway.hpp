#pragma once

/*
 * RouteGateway 是双向重发布的协调器：分别保存三个协议域学到的路由，
 * 应用策略后更新对应 Speaker。它还负责地址族约束和非零环路标签校验。
 */

#include "ospf_gateway/policy.hpp"
#include "ospf_gateway/speaker.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

namespace ospf_gateway {

struct GatewayStats {
    // 中文：以下计数来自最近一次 reconcile()，反映当前内存表和导出快照。
    std::size_t learned_v2 = 0;           // 中文：来源为 OSPFv2 的路由数。
    std::size_t learned_v3_ipv4 = 0;      // 中文：来源为 OSPFv3 IPv4 AF 的路由数。
    std::size_t learned_v3_ipv6 = 0;      // 中文：来源为 OSPFv3 IPv6 的路由数。
    std::size_t exported_v2_to_v3 = 0;    // 中文：当前发布到 v3 IPv4 AF 的 v2 路由数。
    std::size_t exported_v3_to_v2 = 0;    // 中文：当前发布到 v2 的 v3 IPv4 路由数。
};

class RouteGateway {
public:
    /**
     * Creates a bidirectional route redistribution gateway.
     *
     * The three speakers must represent OSPFv2, OSPFv3 IPv4 AF, and OSPFv3
     * IPv6 respectively. loop_guard_tag must be non-zero and is applied to
     * exported routes so that re-imported copies are rejected.
     */
    RouteGateway(RouteSpeaker& ospf_v2,
                 RouteSpeaker& ospf_v3_ipv4,
                 RouteSpeaker& ospf_v3_ipv6,
                 RoutePolicy v2_to_v3,
                 RoutePolicy v3_to_v2,
                 std::uint32_t loop_guard_tag);

    /** Detaches receive callbacks from all attached speakers. */
    // 中文：析构时解除回调，避免 Speaker 在网关生命周期结束后访问悬空 this。
    ~RouteGateway();

    /** Inserts or replaces a learned route, then reconciles both exports. */
    // 中文：同一来源域同一前缀的新值会覆盖旧值，并立即触发双向快照重建。
    void learn(Route route);

    /** Removes one learned route from a protocol domain and reconciles exports. */
    // 中文：撤销操作幂等，找不到前缀也会执行一次导出同步。
    void withdraw(ProtocolDomain source, const Prefix& prefix);

    /** Returns counters describing the last reconciliation result. */
    // 中文：返回引用只读访问统计值，不允许调用方修改网关内部计数。
    const GatewayStats& stats() const noexcept { return stats_; }

private:
    using RouteTable = std::map<std::string, Route>;

    // 中文：从三个来源表重新计算两个 IPv4 导出集合，并清空 IPv6 导出集合。
    void reconcile();
    std::vector<Route> build_v2_to_v3() const;
    std::vector<Route> build_v3_to_v2() const;
    RouteTable& table_for(ProtocolDomain domain);
    const RouteTable& table_for(ProtocolDomain domain) const;

    RouteSpeaker& ospf_v2_;
    RouteSpeaker& ospf_v3_ipv4_;
    RouteSpeaker& ospf_v3_ipv6_;
    RoutePolicy v2_to_v3_;
    RoutePolicy v3_to_v2_;
    std::uint32_t loop_guard_tag_ = 0;
    RouteTable v2_routes_;
    RouteTable v3_ipv4_routes_;
    RouteTable v3_ipv6_routes_;
    GatewayStats stats_;
};

} // namespace ospf_gateway
