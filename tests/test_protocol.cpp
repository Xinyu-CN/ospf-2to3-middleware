/*
 * 协议基础回归测试：验证 v2/v3 Hello、公共头长度、校验和、畸形输入、邻居状态机、
 * AS-External-LSA 以及 LSU/LSAck 往返编码。
 */
#include "ospf_gateway/neighbor.hpp"
#include "ospf_gateway/lsa.hpp"
#include "ospf_gateway/ospf_packet.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace ospf_gateway;

namespace {

void expect(bool condition, const char* message) {
    // 统一断言入口，让每个测试只描述协议条件和失败文本。
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void expect_invalid_packet(const std::vector<std::uint8_t>& bytes) {
    // 确认解析器拒绝空包、截断包、未知版本和声明长度不一致的包。
    bool rejected = false;
    try {
        (void)parse_ospf_packet(bytes);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    expect(rejected, "malformed OSPF packet should be rejected");
}

void test_ospfv2_hello_round_trip() {
    // v2 Hello 包含网络掩码、8 位选项和 32 位 Dead Interval。
    OspfHeader header;
    header.version = OspfVersion::V2;
    header.type = OspfPacketType::Hello;
    header.router_id = 0x01020304U;
    header.area_id = 0x00000001U;
    header.authentication_type = 0;

    OspfHello hello;
    hello.network_mask = 0xffffff00U;
    hello.router_priority = 10;
    hello.options = 0x02U;
    hello.hello_interval = 10;
    hello.dead_interval = 40;
    hello.designated_router = 0x0a000001U;
    hello.backup_designated_router = 0x0a000002U;
    hello.neighbors = {0x0a00000aU, 0x0a00000bU};

    const std::vector<std::uint8_t> wire = serialize_ospf_hello(header, hello);
    expect(wire.size() == 24 + 20 + 8, "OSPFv2 Hello wire length is incorrect");
    const OspfPacket packet = parse_ospf_packet(wire);
    const OspfHello decoded = parse_ospf_hello(packet);

    expect(packet.header.version == OspfVersion::V2, "OSPFv2 version did not round-trip");
    expect(packet.header.packet_length == wire.size(), "packet length did not round-trip");
    expect(decoded.network_mask == hello.network_mask, "OSPFv2 network mask mismatch");
    expect(decoded.router_priority == hello.router_priority, "OSPFv2 priority mismatch");
    expect(decoded.options == hello.options, "OSPFv2 options mismatch");
    expect(decoded.dead_interval == hello.dead_interval, "OSPFv2 dead interval mismatch");
    expect(decoded.neighbors == hello.neighbors, "OSPFv2 neighbors mismatch");

    const std::uint16_t checksum = compute_ospfv2_checksum(wire);
    expect(checksum != 0, "OSPFv2 checksum should be non-zero for this packet");
}

void test_ospfv3_hello_round_trip() {
    // v3 Hello 使用接口 ID、24 位选项和 16 位 Dead Interval，并验证伪首部校验和。
    OspfHeader header;
    header.version = OspfVersion::V3;
    header.type = OspfPacketType::Hello;
    header.router_id = 0xc0000201U;
    header.area_id = 0;
    header.instance_id = 64;

    OspfHello hello;
    hello.interface_id = 7;
    hello.router_priority = 1;
    hello.options = 0x000013U;
    hello.hello_interval = 5;
    hello.dead_interval = 20;
    hello.designated_router = 0xc0000201U;
    hello.backup_designated_router = 0xc0000202U;
    hello.neighbors = {0xc0000202U};

    const std::vector<std::uint8_t> wire = serialize_ospf_hello(header, hello);
    expect(wire.size() == 16 + 20 + 4, "OSPFv3 Hello wire length is incorrect");
    const OspfPacket packet = parse_ospf_packet(wire);
    const OspfHello decoded = parse_ospf_hello(packet);

    expect(packet.header.version == OspfVersion::V3, "OSPFv3 version did not round-trip");
    expect(packet.header.instance_id == 64, "OSPFv3 instance ID mismatch");
    expect(decoded.interface_id == hello.interface_id, "OSPFv3 interface ID mismatch");
    expect(decoded.options == hello.options, "OSPFv3 options mismatch");
    expect(decoded.dead_interval == hello.dead_interval, "OSPFv3 dead interval mismatch");
    expect(decoded.neighbors == hello.neighbors, "OSPFv3 neighbors mismatch");

    const std::array<std::uint8_t, 16> source{};
    const std::array<std::uint8_t, 16> destination{{
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}};
    const std::uint16_t checksum = compute_ospfv3_checksum(wire, source, destination);
    expect(checksum != 0, "OSPFv3 checksum should be non-zero for this packet");
}

void test_packet_validation() {
    // 逐类构造非法输入，覆盖公共头最早期的边界检查。
    expect_invalid_packet({});
    expect_invalid_packet({2, 1});
    expect_invalid_packet({9, 1, 0, 16});

    OspfHeader header;
    header.version = OspfVersion::V2;
    header.type = OspfPacketType::Hello;
    std::vector<std::uint8_t> packet = serialize_ospf_packet(header, {});
    packet[3] = static_cast<std::uint8_t>(packet[3] + 1);
    expect_invalid_packet(packet);
}

void test_neighbor_state_machine() {
    // 沿 Down -> Init -> 2-Way -> ExStart -> Exchange -> Loading -> Full 主路径推进，
    // 再验证序列号不匹配重启和 reset() 行为。
    NeighborStateMachine neighbor(0x0a000002U);
    expect(neighbor.state() == NeighborState::Down, "neighbor should start Down");

    expect(neighbor.process(NeighborEvent::HelloReceived).current == NeighborState::Init,
           "HelloReceived should move Down to Init");
    expect(neighbor.process(NeighborEvent::TwoWayReceived).current == NeighborState::TwoWay,
           "TwoWayReceived should move Init to TwoWay");
    expect(neighbor.process(NeighborEvent::AdjacencyOk).current == NeighborState::ExStart,
           "AdjacencyOk should move TwoWay to ExStart");
    expect(neighbor.process(NeighborEvent::NegotiationDone).current == NeighborState::Exchange,
           "NegotiationDone should move ExStart to Exchange");
    expect(neighbor.process(NeighborEvent::ExchangeDone).current == NeighborState::Loading,
           "ExchangeDone should move Exchange to Loading");
    const NeighborTransition full = neighbor.process(NeighborEvent::LoadingDone);
    expect(full.current == NeighborState::Full, "LoadingDone should move Loading to Full");
    expect(full.adjacency_established, "Full transition should report adjacency established");

    const NeighborTransition restart = neighbor.process(NeighborEvent::SequenceNumberMismatch);
    expect(restart.current == NeighborState::ExStart,
           "sequence mismatch should restart database exchange");
    neighbor.reset();
    expect(neighbor.state() == NeighborState::Down, "reset should return neighbor to Down");
}

void test_lsa_round_trip_and_database() {
    // 生成外部 LSA 后做校验、解码、LSDB 新旧实例判断以及 LSU/LSAck 往返。
    const Route original(Prefix::parse("192.0.2.0/24"), ProtocolDomain::OspfV2,
                         RouteType::External2, 123, 77, "test");
    const Lsa lsa = make_external_lsa(original, OspfVersion::V2, 0x0a000001U,
                                      0x80000001U);
    const std::vector<std::uint8_t> wire = serialize_lsa(lsa);
    expect(compute_lsa_checksum(wire) == lsa.header.checksum,
           "generated LSA checksum must match its header");

    std::size_t offset = 0;
    const Lsa decoded_lsa = parse_lsa(wire, offset);
    expect(offset == wire.size(), "LSA parser should consume the complete LSA");
    const std::optional<Route> decoded_route = decode_external_lsa(
        decoded_lsa, ProtocolDomain::OspfV2);
    expect(decoded_route.has_value(), "generated external LSA should decode");
    expect(decoded_route->prefix == original.prefix, "decoded LSA prefix mismatch");
    expect(decoded_route->metric == original.metric, "decoded LSA metric mismatch");
    expect(decoded_route->tag == original.tag, "decoded LSA tag mismatch");

    LinkStateDatabase database;
    expect(database.install(lsa) == LsaInstallResult::Installed,
           "first LSA install should succeed");
    expect(database.install(lsa) == LsaInstallResult::SameIgnored,
           "same LSA should be ignored");
    expect(database.size() == 1, "LSDB should contain one LSA");

    const std::vector<Lsa> update_lsas = parse_link_state_update(
        serialize_link_state_update({lsa}));
    expect(update_lsas.size() == 1, "LSU should round-trip one LSA");
    const std::vector<LsaHeader> ack_headers = parse_link_state_acknowledgment(
        serialize_link_state_acknowledgment({lsa.header}));
    expect(ack_headers.size() == 1, "LSAck should round-trip one header");
}

} // namespace

int main() {
    // 协议测试不依赖网络接口，适合在所有支持 C++17 的平台运行。
    try {
        test_ospfv2_hello_round_trip();
        test_ospfv3_hello_round_trip();
        test_packet_validation();
        test_neighbor_state_machine();
        test_lsa_round_trip_and_database();
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "All protocol tests passed.\n";
    return EXIT_SUCCESS;
}
