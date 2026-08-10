/*
 * 真实 OSPF Speaker：把 raw socket 的数据转换成状态机、LSDB 和 RouteGateway 可消费的
 * Route；反方向则把导出路由编码成 AS-External-LSA 并通过组播泛洪。
 */
#include "ospf_gateway/ospf_speaker.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <utility>

namespace ospf_gateway {

namespace {

std::uint32_t next_sequence(std::map<std::string, std::uint32_t>& sequences,
                            const std::string& prefix) {
    // 每个前缀独立维护 LSA 序列号，达到 MaxSequenceNumber 后回到初始合法值。
    auto iterator = sequences.find(prefix);
    if (iterator == sequences.end()) {
        iterator = sequences.emplace(prefix, 0x80000001U).first;
    } else if (iterator->second == 0x7fffffffU) {
        iterator->second = 0x80000001U;
    } else {
        ++iterator->second;
    }
    return iterator->second;
}

bool contains_router(const OspfHello& hello, std::uint32_t router_id) {
    // Hello 邻居列表包含本端 Router ID 才能从 Init 进入 2-Way。
    return std::find(hello.neighbors.begin(), hello.neighbors.end(), router_id) !=
           hello.neighbors.end();
}

} // namespace

OspfProtocolSpeaker::OspfProtocolSpeaker(
    OspfSpeakerConfig config,
    std::unique_ptr<FibInstaller> fib_installer)
    : config_(std::move(config)),
      socket_(OspfSocketConfig{config_.version, config_.interface_name,
                               config_.interface_index}),
      fib_installer_(std::move(fib_installer)) {
    // 构造阶段只校验配置，不打开 socket；资源获取由显式 start() 控制。
    validate_config();
}

OspfProtocolSpeaker::~OspfProtocolSpeaker() {
    // 析构路径复用 noexcept 的 stop()，确保异常离开作用域时释放描述符。
    stop();
}

ProtocolDomain OspfProtocolSpeaker::domain() const noexcept {
    // RouteGateway 使用该值确认 Speaker 与目标协议域一致。
    return config_.domain;
}

void OspfProtocolSpeaker::replace_external_routes(std::vector<Route> routes) {
    // 先过滤地址族，再撤销旧集合中消失的前缀，最后发布新集合。
    std::map<std::string, Route> new_routes;
    std::vector<Route> accepted_routes;
    for (Route& route : routes) {
        // Speaker 只接受与自身协议域匹配的前缀，防止错误 LSA 类型进入线速。
        const bool family_matches =
            (config_.domain == ProtocolDomain::OspfV2 && route.prefix.is_ipv4()) ||
            (config_.domain == ProtocolDomain::OspfV3IPv4 && route.prefix.is_ipv4()) ||
            (config_.domain == ProtocolDomain::OspfV3IPv6 && route.prefix.is_ipv6());
        if (!family_matches) {
            continue;
        }
        accepted_routes.push_back(std::move(route));
    }

    withdraw_removed_routes(accepted_routes);
    for (const Route& route : accepted_routes) {
        new_routes.insert_or_assign(route.prefix.to_string(), route);
    }
    exported_routes_ = std::move(new_routes);
    publish_routes(accepted_routes);
}

void OspfProtocolSpeaker::set_route_learn_handler(RouteLearnHandler handler) {
    // 回调由 RouteGateway 安装；移动赋值避免复制捕获对象。
    route_learn_handler_ = std::move(handler);
}

void OspfProtocolSpeaker::start() {
    // 启动顺序为 open -> 立即 Hello -> 恢复已有导出 -> 安排下一次定时 Hello。
    if (running_) {
        return;
    }
    socket_.open();
    running_ = true;
    next_hello_ = std::chrono::steady_clock::now();
    send_hello();
    std::vector<Route> routes;
    routes.reserve(exported_routes_.size());
    for (const auto& entry : exported_routes_) {
        routes.push_back(entry.second);
    }
    publish_routes(routes);
    next_hello_ = std::chrono::steady_clock::now() +
                  std::chrono::seconds(config_.hello_interval);
}

void OspfProtocolSpeaker::stop() noexcept {
    // 停止事件循环并清空邻居；LSDB/导出表保留，便于再次 start() 时重新泛洪。
    running_ = false;
    socket_.close();
    neighbors_.clear();
}

bool OspfProtocolSpeaker::running() const noexcept {
    return running_;
}

void OspfProtocolSpeaker::run_once(int timeout_ms) {
    // 一次迭代同时处理 Hello 定时器、poll 输入和邻居 Dead 定时器。
    if (!running_) {
        throw std::runtime_error("OSPF speaker is not running");
    }

    const auto now = std::chrono::steady_clock::now();
    if (now >= next_hello_) {
        // 先发出到期 Hello，再计算下一次发送时间，避免长时间 poll 后连续补发。
        send_hello();
        next_hello_ = now + std::chrono::seconds(config_.hello_interval);
    }

    int wait_ms = std::max(timeout_ms, 0);
    const auto until_hello = std::chrono::duration_cast<std::chrono::milliseconds>(
        next_hello_ - now).count();
    wait_ms = std::min(wait_ms, static_cast<int>(std::max<std::int64_t>(0, until_hello)));

    pollfd descriptor{};
    descriptor.fd = socket_.native_handle();
    descriptor.events = POLLIN;
    // poll 等待时间取调用方上限和下一次 Hello 到期时间的较小值。
    const int result = poll(&descriptor, 1, wait_ms);
    if (result < 0) {
        throw std::runtime_error(std::string("poll(OSPF): ") + std::strerror(errno));
    }
    if (result > 0 && (descriptor.revents & POLLIN) != 0) {
        // 一次唤醒尽可能排空非阻塞 socket，减少下一轮处理延迟。
        while (true) {
            const std::optional<OspfDatagram> datagram = socket_.receive();
            if (!datagram.has_value()) {
                break;
            }
            handle_datagram(*datagram);
        }
    }
    expire_neighbors(std::chrono::steady_clock::now());
}

void OspfProtocolSpeaker::run() {
    // run() 是守护进程使用的阻塞封装，退出条件由 stop() 修改 running_。
    while (running_) {
        run_once(1000);
    }
}

const LinkStateDatabase& OspfProtocolSpeaker::lsdb() const noexcept {
    // 返回只读引用供诊断和测试查看当前 LSDB。
    return lsdb_;
}

std::vector<OspfNeighborInfo> OspfProtocolSpeaker::neighbors() const {
    // 把内部 NeighborContext 转成独立快照，避免暴露状态机和定时器。
    std::vector<OspfNeighborInfo> result;
    result.reserve(neighbors_.size());
    for (const auto& entry : neighbors_) {
        result.push_back({entry.first,
                          entry.second.state_machine.state(),
                          entry.second.source_address,
                          entry.second.interface_index});
    }
    return result;
}

void OspfProtocolSpeaker::validate_config() const {
    // 校验域/线版本、计时器关系以及 v3 IPv6 源地址，尽早阻止不可发送配置。
    if (config_.domain == ProtocolDomain::OspfV2 && config_.version != OspfVersion::V2) {
        throw std::invalid_argument("OSPFv2 domain requires OSPFv2 wire version");
    }
    if (config_.domain != ProtocolDomain::OspfV2 && config_.version != OspfVersion::V3) {
        throw std::invalid_argument("OSPFv3 domain requires OSPFv3 wire version");
    }
    if (config_.router_id == 0 || config_.hello_interval == 0 || config_.dead_interval == 0) {
        throw std::invalid_argument("router ID and OSPF timers must be non-zero");
    }
    if (config_.dead_interval < config_.hello_interval) {
        throw std::invalid_argument("dead interval must not be less than hello interval");
    }
    if (config_.domain == ProtocolDomain::OspfV3IPv4 && !config_.source_address.empty()) {
        std::array<std::uint8_t, 16> address{};
        if (inet_pton(AF_INET6, config_.source_address.c_str(), address.data()) != 1) {
            throw std::invalid_argument("OSPFv3 source address must be IPv6");
        }
    }
}

void OspfProtocolSpeaker::send_hello() {
    // Hello 邻居列表只包含非 Down 邻居，序列化后按当前版本计算校验和并组播。
    OspfHeader header;
    header.version = config_.version;
    header.type = OspfPacketType::Hello;
    header.router_id = config_.router_id;
    header.area_id = config_.area_id;
    header.instance_id = config_.instance_id;

    OspfHello hello;
    hello.network_mask = config_.network_mask;
    hello.interface_id = config_.interface_id;
    hello.router_priority = config_.router_priority;
    hello.options = config_.options;
    hello.hello_interval = config_.hello_interval;
    hello.dead_interval = config_.dead_interval;
    for (const auto& entry : neighbors_) {
        if (entry.second.state_machine.state() != NeighborState::Down) {
            hello.neighbors.push_back(entry.first);
        }
    }

    const std::vector<std::uint8_t> payload =
        serialize_ospf_hello(header, hello);
    OspfPacket packet = parse_ospf_packet(payload);
    const std::vector<std::uint8_t> wire =
        serialize_with_checksum(packet.header, packet.payload, "ff02::5");
    socket_.send_multicast(wire);
}

void OspfProtocolSpeaker::handle_datagram(const OspfDatagram& datagram) {
    // 先验证版本、区域和自发报文，再按类型分派到 Hello/LSU/LSAck 处理器。
    const OspfPacket packet = parse_ospf_packet(datagram.packet);
    if (packet.header.version != config_.version ||
        packet.header.area_id != config_.area_id ||
        packet.header.router_id == config_.router_id) {
        return;
    }
    switch (packet.header.type) {
    case OspfPacketType::Hello:
        handle_hello(packet, datagram);
        break;
    case OspfPacketType::LinkStateUpdate:
        handle_link_state_update(packet, datagram);
        break;
    case OspfPacketType::LinkStateAcknowledgment:
        handle_link_state_acknowledgment(packet);
        break;
    default:
        break;
    }
}

void OspfProtocolSpeaker::handle_hello(const OspfPacket& packet,
                                       const OspfDatagram& datagram) {
    // 严格匹配网络掩码、实例号和两个计时器后，才更新邻居最近 Hello 时间。
    const OspfHello hello = parse_ospf_hello(packet);
    if (config_.version == OspfVersion::V2 && hello.network_mask != config_.network_mask) {
        return;
    }
    if (config_.version == OspfVersion::V3 &&
        packet.header.instance_id != config_.instance_id) {
        return;
    }
    if (hello.hello_interval != config_.hello_interval ||
        hello.dead_interval != config_.dead_interval) {
        return;
    }

    auto iterator = neighbors_.find(packet.header.router_id);
    if (iterator == neighbors_.end()) {
        iterator = neighbors_.emplace(packet.header.router_id,
                                       NeighborContext(packet.header.router_id)).first;
    }
    NeighborContext& neighbor = iterator->second;
    neighbor.source_address = datagram.source_address;
    neighbor.interface_index = datagram.interface_index;
    neighbor.last_hello = std::chrono::steady_clock::now();
    neighbor.state_machine.process(NeighborEvent::HelloReceived);
    neighbor.state_machine.process(contains_router(hello, config_.router_id)
                                       ? NeighborEvent::TwoWayReceived
                                       : NeighborEvent::OneWayReceived);
}

void OspfProtocolSpeaker::handle_link_state_update(
    const OspfPacket& packet,
    const OspfDatagram& datagram) {
    // 每条 LSA 都先进入 LSDB，再生成确认；仅新/替换实例继续泛洪，避免环路重复泛洪。
    const std::vector<Lsa> lsas = parse_link_state_update(packet.payload);
    std::vector<LsaHeader> acknowledgments;
    std::vector<Lsa> flood;
    for (const Lsa& lsa : lsas) {
        const LsaInstallResult result = lsdb_.install(lsa);
        acknowledgments.push_back(lsa.header);
        if (result == LsaInstallResult::Installed || result == LsaInstallResult::Replaced) {
            flood.push_back(lsa);
        }
        const std::optional<Route> route = decode_external_lsa(
            lsa, config_.domain, datagram.source_address, datagram.interface_index);
        if (!route.has_value()) {
            continue;
        }
        // 外部 LSA 解码成功后可选安装 FIB，再通知网关学习路由。
        if (fib_installer_) {
            fib_installer_->install(*route);
        }
        if (route_learn_handler_) {
            route_learn_handler_(*route);
        }
    }
    if (!acknowledgments.empty() && !datagram.source_address.empty()) {
        send_lsa_acknowledgment(acknowledgments, datagram.source_address);
    }
    if (!flood.empty()) {
        send_lsa_update(flood);
    }
}

void OspfProtocolSpeaker::handle_link_state_acknowledgment(
    const OspfPacket& packet) {
    // 当前阶段只验证 LSAck 格式；重传队列由后续邻接组件负责。
    (void)parse_link_state_acknowledgment(packet.payload);
}

void OspfProtocolSpeaker::send_lsa_update(const std::vector<Lsa>& lsas,
                                          bool all_designated_routers) {
    // 空集合不发送空 LSU；目标组播由调用方决定 AllSPF 或 AllDR。
    if (lsas.empty()) {
        return;
    }
    socket_.send_multicast(make_lsa_update_packet(lsas), all_designated_routers);
}

void OspfProtocolSpeaker::send_lsa_acknowledgment(
    const std::vector<LsaHeader>& headers,
    const std::string& destination) {
    // LSAck 采用邻居源地址单播，确保确认回到原发送者。
    socket_.send_unicast(make_lsa_ack_packet(headers, destination), destination);
}

void OspfProtocolSpeaker::publish_routes(const std::vector<Route>& routes) {
    // 每个前缀递增独立序列号，写入本地 LSDB 后把新 LSA 组播出去。
    if (!running_) {
        return;
    }
    std::vector<Lsa> lsas;
    for (const Route& route : routes) {
        const std::string key = route.prefix.to_string();
        const Lsa lsa = make_external_lsa(route, config_.version, config_.router_id,
                                           next_sequence(sequence_numbers_, key));
        lsdb_.install(lsa);
        lsas.push_back(lsa);
    }
    send_lsa_update(lsas);
}

void OspfProtocolSpeaker::withdraw_removed_routes(const std::vector<Route>& routes) {
    // 旧集合中不再出现的前缀以 MaxAge LSA 发布，通知邻居删除路由。
    std::map<std::string, bool> current;
    for (const Route& route : routes) {
        current[route.prefix.to_string()] = true;
    }
    std::vector<Lsa> withdrawals;
    for (const auto& entry : exported_routes_) {
        if (current.find(entry.first) != current.end()) {
            continue;
        }
        Lsa lsa = make_external_lsa(entry.second, config_.version, config_.router_id,
                                    next_sequence(sequence_numbers_, entry.first));
        lsa.header.age = 3600;
        lsdb_.install(lsa);
        withdrawals.push_back(std::move(lsa));
    }
    if (running_ && !withdrawals.empty()) {
        send_lsa_update(withdrawals);
    }
}

std::vector<std::uint8_t> OspfProtocolSpeaker::serialize_with_checksum(
    OspfHeader header,
    const std::vector<std::uint8_t>& payload,
    const std::string& destination) const {
    // 先以零 checksum 序列化，再按版本计算并重新序列化写回字段。
    header.checksum = 0;
    std::vector<std::uint8_t> wire = serialize_ospf_packet(header, payload);
    if (config_.version == OspfVersion::V2) {
        header.checksum = compute_ospfv2_checksum(wire);
    } else {
        header.checksum = compute_ospfv3_checksum(
            wire, source_ipv6_bytes(),
            [&destination] {
                std::array<std::uint8_t, 16> address{};
                if (inet_pton(AF_INET6, destination.c_str(), address.data()) != 1) {
                    throw std::invalid_argument("invalid OSPFv3 checksum destination");
                }
                return address;
            }());
    }
    return serialize_ospf_packet(header, payload);
}

std::array<std::uint8_t, 16> OspfProtocolSpeaker::source_ipv6_bytes() const {
    // v3 伪首部必须使用配置的真实 IPv6 源地址，空值或非法文本直接拒绝发送。
    std::array<std::uint8_t, 16> source{};
    if (config_.source_address.empty() ||
        inet_pton(AF_INET6, config_.source_address.c_str(), source.data()) != 1) {
        throw std::invalid_argument("OSPFv3 requires a valid IPv6 source address");
    }
    return source;
}

std::vector<std::uint8_t> OspfProtocolSpeaker::make_lsa_update_packet(
    const std::vector<Lsa>& lsas) const {
    // 构造 LSU 公共头，body 由通用 LSA 列表编码器生成。
    OspfHeader header;
    header.version = config_.version;
    header.type = OspfPacketType::LinkStateUpdate;
    header.router_id = config_.router_id;
    header.area_id = config_.area_id;
    header.instance_id = config_.instance_id;
    return serialize_with_checksum(header, serialize_link_state_update(lsas), "ff02::5");
}

std::vector<std::uint8_t> OspfProtocolSpeaker::make_lsa_ack_packet(
    const std::vector<LsaHeader>& headers,
    const std::string& destination) const {
    // 构造只含 LSA 头的 LSAck，并使用目标地址参与 v3 伪首部校验。
    OspfHeader header;
    header.version = config_.version;
    header.type = OspfPacketType::LinkStateAcknowledgment;
    header.router_id = config_.router_id;
    header.area_id = config_.area_id;
    header.instance_id = config_.instance_id;
    return serialize_with_checksum(header, serialize_link_state_acknowledgment(headers),
                                   destination);
}

void OspfProtocolSpeaker::expire_neighbors(
    std::chrono::steady_clock::time_point now) {
    // 超过 dead_interval 的邻居接收 InactivityTimerExpired，状态退回 Down。
    for (auto& entry : neighbors_) {
        NeighborContext& neighbor = entry.second;
        if (neighbor.last_hello.time_since_epoch().count() == 0) {
            continue;
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - neighbor.last_hello);
        if (elapsed.count() >= config_.dead_interval) {
            neighbor.state_machine.process(NeighborEvent::InactivityTimerExpired);
        }
    }
}

} // namespace ospf_gateway
