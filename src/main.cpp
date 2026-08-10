/*
 * 命令行演示：--demo 展示三域路由重发布，--protocol-demo 展示 Hello 编解码和
 * 邻居状态迁移。该入口不打开 raw socket，适合在 macOS 等非 Linux 环境运行。
 */
#include "ospf_gateway/gateway.hpp"
#include "ospf_gateway/neighbor.hpp"
#include "ospf_gateway/ospf_packet.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace ospf_gateway;

namespace {

RoutePolicy allow_ipv4() {
    // 演示策略允许全部 IPv4，并增加固定度量，方便观察 transform() 的结果。
    RoutePolicy policy;
    policy.add_rule({Prefix::parse("0.0.0.0/0"), true, false});
    policy.set_metric_add(10);
    policy.set_export_type(RouteType::External2);
    return policy;
}

void print_routes(const char* label, const MemorySpeaker& speaker) {
    // MemorySpeaker 保存的是完整导出快照，这里按稳定顺序打印核心属性。
    std::cout << label << " (" << speaker.external_routes().size() << ")\n";
    for (const Route& route : speaker.external_routes()) {
        std::cout << "  " << route.prefix.to_string()
                  << " metric=" << route.metric
                  << " type=" << to_string(route.route_type)
                  << " tag=" << route.tag << "\n";
    }
}

int run_demo() {
    // 注入 v2、v3 IPv4 和 v3 IPv6 三条路由，验证 IPv6 不会进入 v2/v3 IPv4。
    MemorySpeaker ospf_v2(ProtocolDomain::OspfV2);
    MemorySpeaker ospf_v3_ipv4(ProtocolDomain::OspfV3IPv4);
    MemorySpeaker ospf_v3_ipv6(ProtocolDomain::OspfV3IPv6);

    constexpr std::uint32_t loop_tag = 0x4f325633;
    RouteGateway gateway(ospf_v2, ospf_v3_ipv4, ospf_v3_ipv6,
                         allow_ipv4(), allow_ipv4(), loop_tag);

    gateway.learn(Route(Prefix::parse("10.10.0.0/16"), ProtocolDomain::OspfV2,
                        RouteType::IntraArea, 20, 0, "legacy-v2"));
    gateway.learn(Route(Prefix::parse("172.20.0.0/16"), ProtocolDomain::OspfV3IPv4,
                        RouteType::InterArea, 30, 0, "modern-v3"));
    gateway.learn(Route(Prefix::parse("2001:db8:10::/48"), ProtocolDomain::OspfV3IPv6,
                        RouteType::IntraArea, 5, 0, "modern-v3"));

    print_routes("Routes exported into OSPFv2", ospf_v2);
    print_routes("Routes exported into OSPFv3 IPv4 AF", ospf_v3_ipv4);
    print_routes("Routes exported into OSPFv3 IPv6", ospf_v3_ipv6);

    const GatewayStats& stats = gateway.stats();
    std::cout << "Learned: v2=" << stats.learned_v2
              << " v3-ipv4=" << stats.learned_v3_ipv4
              << " v3-ipv6=" << stats.learned_v3_ipv6 << "\n";
    return EXIT_SUCCESS;
}

int run_protocol_demo() {
    // 构造一个 OSPFv2 Hello，经过序列化、解析后再打印邻居状态机迁移。
    OspfHeader header;
    header.version = OspfVersion::V2;
    header.type = OspfPacketType::Hello;
    header.router_id = 0x0a000001U;
    header.area_id = 0;

    OspfHello hello;
    hello.network_mask = 0xffffff00U;
    hello.router_priority = 1;
    hello.options = 2;
    hello.hello_interval = 10;
    hello.dead_interval = 40;
    hello.neighbors = {0x0a000002U};

    const std::vector<std::uint8_t> wire = serialize_ospf_hello(header, hello);
    const OspfPacket parsed_packet = parse_ospf_packet(wire);
    const OspfHello parsed_hello = parse_ospf_hello(parsed_packet);

    std::cout << "Encoded " << to_string(parsed_packet.header.version) << ' '
              << to_string(parsed_packet.header.type)
              << " packet_length=" << parsed_packet.header.packet_length
              << " neighbors=" << parsed_hello.neighbors.size() << '\n';

    NeighborStateMachine neighbor(0x0a000002U);
    const NeighborEvent events[] = {
        NeighborEvent::HelloReceived,
        NeighborEvent::TwoWayReceived,
        NeighborEvent::AdjacencyOk,
        NeighborEvent::NegotiationDone,
        NeighborEvent::ExchangeDone,
        NeighborEvent::LoadingDone,
    };
    for (const NeighborEvent event : events) {
        const NeighborTransition transition = neighbor.process(event);
        std::cout << "  " << to_string(event) << ": "
                  << to_string(transition.previous) << " -> "
                  << to_string(transition.current) << '\n';
    }
    return EXIT_SUCCESS;
}

} // namespace

int main(int argc, char** argv) {
    // 保持命令行解析最小化，未知参数显示用法并返回失败。
    if (argc == 2 && std::string(argv[1]) == "--demo") {
        return run_demo();
    }
    if (argc == 2 && std::string(argv[1]) == "--protocol-demo") {
        return run_protocol_demo();
    }

    std::cout << "ospf-gateway 0.1\n"
              << "Usage: ospf-gateway --demo | --protocol-demo\n"
              << "\n"
              << "This first version implements the route redistribution core.\n"
              << "Wire-level OSPFv2/OSPFv3 speakers are separate adapters.\n";
    return argc == 1 ? EXIT_SUCCESS : EXIT_FAILURE;
}
