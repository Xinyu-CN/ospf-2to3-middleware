/*
 * 网关核心回归测试：覆盖前缀规范化、双向重发布、IPv6 隔离、环路标签、撤销、
 * 策略拒绝和非法输入。测试使用 MemorySpeaker，不需要 Linux 网络权限。
 */
#include "ospf_gateway/gateway.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>

using namespace ospf_gateway;

namespace {

void expect(bool condition, const char* message) {
    // 用异常中止当前用例，main() 统一打印失败原因。
    if (!condition) {
        throw std::runtime_error(message);
    }
}

RoutePolicy allow_all_ipv4() {
    // 所有网关测试的基础策略，只把关注点放在网关行为而非过滤规则本身。
    RoutePolicy policy;
    policy.add_rule({Prefix::parse("0.0.0.0/0"), true, false});
    policy.set_metric_add(10);
    return policy;
}

void test_prefix_matching() {
    // 检查包含关系以及解析时自动清除主机位的规范化行为。
    const Prefix parent = Prefix::parse("10.0.0.0/8");
    const Prefix child = Prefix::parse("10.20.0.0/16");
    const Prefix outside = Prefix::parse("11.0.0.0/8");
    expect(parent.contains(child), "parent prefix should contain child");
    expect(!parent.contains(outside), "parent prefix should not contain unrelated prefix");
    expect(Prefix::parse("10.20.0.1/16") == child,
           "host bits should be masked during prefix parsing");
}

void test_bidirectional_redistribution() {
    // 两个方向各学习一条 IPv4 路由，确认导出数量、度量、类型和标签都被改写。
    MemorySpeaker v2(ProtocolDomain::OspfV2);
    MemorySpeaker v3v4(ProtocolDomain::OspfV3IPv4);
    MemorySpeaker v3v6(ProtocolDomain::OspfV3IPv6);
    constexpr std::uint32_t loop_tag = 0x4f325633;
    RouteGateway gateway(v2, v3v4, v3v6, allow_all_ipv4(), allow_all_ipv4(), loop_tag);

    gateway.learn(Route(Prefix::parse("10.1.0.0/16"), ProtocolDomain::OspfV2,
                        RouteType::IntraArea, 20));
    gateway.learn(Route(Prefix::parse("172.16.0.0/12"), ProtocolDomain::OspfV3IPv4,
                        RouteType::InterArea, 30));

    expect(v3v4.external_routes().size() == 1, "v2 route should be exported to v3 ipv4");
    expect(v2.external_routes().size() == 1, "v3 ipv4 route should be exported to v2");
    expect(v3v4.external_routes()[0].metric == 30,
           "v2 to v3 metric policy should be applied");
    expect(v2.external_routes()[0].route_type == RouteType::External2,
           "redistributed route should become external type 2");
    expect(v2.external_routes()[0].tag == loop_tag,
           "exported route should receive the loop guard tag");
}

void test_ipv6_does_not_enter_ospfv2() {
    // 原生 IPv6 只属于 OSPFv3 IPv6 域，不能跨入任一 IPv4 域。
    MemorySpeaker v2(ProtocolDomain::OspfV2);
    MemorySpeaker v3v4(ProtocolDomain::OspfV3IPv4);
    MemorySpeaker v3v6(ProtocolDomain::OspfV3IPv6);
    RouteGateway gateway(v2, v3v4, v3v6, allow_all_ipv4(), allow_all_ipv4(), 100);

    gateway.learn(Route(Prefix::parse("2001:db8:1::/48"), ProtocolDomain::OspfV3IPv6,
                        RouteType::IntraArea, 5));

    expect(v2.external_routes().empty(), "ipv6 route must not be exported to ospfv2");
    expect(v3v4.external_routes().empty(), "ipv6 route must not enter ipv4 af");
}

void test_loop_guard_and_withdraw() {
    // 已带环路标签的路由必须拒绝；普通路由导出后撤销应同步清空对端快照。
    MemorySpeaker v2(ProtocolDomain::OspfV2);
    MemorySpeaker v3v4(ProtocolDomain::OspfV3IPv4);
    MemorySpeaker v3v6(ProtocolDomain::OspfV3IPv6);
    constexpr std::uint32_t loop_tag = 55;
    RouteGateway gateway(v2, v3v4, v3v6, allow_all_ipv4(), allow_all_ipv4(), loop_tag);

    gateway.learn(Route(Prefix::parse("192.0.2.0/24"), ProtocolDomain::OspfV2,
                        RouteType::External2, 100, loop_tag));
    expect(v3v4.external_routes().empty(), "loop-tagged route must not be re-exported");

    gateway.learn(Route(Prefix::parse("192.0.2.0/24"), ProtocolDomain::OspfV2,
                        RouteType::IntraArea, 10));
    expect(v3v4.external_routes().size() == 1, "untagged route should be exported");

    gateway.withdraw(ProtocolDomain::OspfV2, Prefix::parse("192.0.2.0/24"));
    expect(v3v4.external_routes().empty(), "withdraw should remove exported route");
}

void test_policy_deny() {
    // 只允许 10/8，验证不匹配前缀不会被发布。
    MemorySpeaker v2(ProtocolDomain::OspfV2);
    MemorySpeaker v3v4(ProtocolDomain::OspfV3IPv4);
    MemorySpeaker v3v6(ProtocolDomain::OspfV3IPv6);
    RoutePolicy policy;
    policy.add_rule({Prefix::parse("10.0.0.0/8"), true, false});
    RouteGateway gateway(v2, v3v4, v3v6, policy, allow_all_ipv4(), 100);

    gateway.learn(Route(Prefix::parse("192.0.2.0/24"), ProtocolDomain::OspfV2,
                        RouteType::IntraArea, 1));
    expect(v3v4.external_routes().empty(), "route outside policy must be denied");
}

void test_invalid_inputs() {
    // 非法前缀长度和零环路标签都应在边界处抛出 invalid_argument。
    bool invalid_prefix_rejected = false;
    try {
        (void)Prefix::parse("192.0.2.0/33");
    } catch (const std::invalid_argument&) {
        invalid_prefix_rejected = true;
    }
    expect(invalid_prefix_rejected, "invalid prefix length must be rejected");

    MemorySpeaker v2(ProtocolDomain::OspfV2);
    MemorySpeaker v3v4(ProtocolDomain::OspfV3IPv4);
    MemorySpeaker v3v6(ProtocolDomain::OspfV3IPv6);
    bool zero_tag_rejected = false;
    try {
        RouteGateway gateway(v2, v3v4, v3v6, allow_all_ipv4(), allow_all_ipv4(), 0);
        (void)gateway;
    } catch (const std::invalid_argument&) {
        zero_tag_rejected = true;
    }
    expect(zero_tag_rejected, "zero loop guard tag must be rejected");
}

} // namespace

int main() {
    // 顺序执行所有无状态用例，任意异常都会使进程返回失败。
    try {
        test_prefix_matching();
        test_bidirectional_redistribution();
        test_ipv6_does_not_enter_ospfv2();
        test_loop_guard_and_withdraw();
        test_policy_deny();
        test_invalid_inputs();
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "All ospf-gateway tests passed.\n";
    return EXIT_SUCCESS;
}
