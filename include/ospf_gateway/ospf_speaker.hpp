#pragma once

/*
 * 真实协议 Speaker：把配置、raw socket、Hello 定时器、邻居状态机、LSDB、
 * LSA 泛洪和可选 FIB 安装串起来。完整 DD/SPF 仍由后续组件负责。
 */

#include "ospf_gateway/fib.hpp"
#include "ospf_gateway/lsa.hpp"
#include "ospf_gateway/neighbor.hpp"
#include "ospf_gateway/raw_socket.hpp"
#include "ospf_gateway/speaker.hpp"

#include <chrono>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ospf_gateway {

/** Runtime settings for one Linux OSPFv2 or OSPFv3 interface speaker. */
struct OspfSpeakerConfig {
    // 中文：一个配置对象对应一个接口上的一个协议域（v2、v3 IPv4 AF 或 v3 IPv6）。
    OspfVersion version = OspfVersion::V2;       // 中文：使用的线协议版本。
    ProtocolDomain domain = ProtocolDomain::OspfV2; // 中文：路由语义域。
    std::string interface_name;                  // 中文：承载 OSPF 的 Linux 接口。
    std::uint32_t interface_index = 0;          // 中文：0 表示由 raw socket 解析接口名。
    std::string source_address;                 // 中文：v3 IPv6 源地址和校验伪首部地址。
    std::uint32_t router_id = 0;                // 中文：本端 Router ID。
    std::uint32_t area_id = 0;                  // 中文：接口所属区域。
    std::uint8_t instance_id = 0;               // 中文：v3 Address Family 实例号。
    std::uint32_t interface_id = 0;             // 中文：v3 Hello 中的接口 ID。
    std::uint32_t network_mask = 0xffffffffU;   // 中文：v2 Hello 网络掩码。
    std::uint8_t router_priority = 1;           // 中文：DR/BDR 选举优先级。
    std::uint32_t options = 0;                  // 中文：Hello 能力位集合。
    std::uint16_t hello_interval = 10;          // 中文：发送 Hello 的周期秒数。
    std::uint32_t dead_interval = 40;           // 中文：邻居失效判定秒数。
};

/** Snapshot of one discovered neighbor. */
struct OspfNeighborInfo {
    // 中文：这是对外只读快照，避免调用方直接持有内部 NeighborContext。
    std::uint32_t router_id = 0;                // 中文：远端 Router ID。
    NeighborState state = NeighborState::Down;  // 中文：最近一次事件后的状态。
    std::string source_address;                 // 中文：远端报文源地址。
    std::uint32_t interface_index = 0;          // 中文：远端报文进入的接口。
};

/**
 * Linux-backed OSPF protocol Speaker.
 *
 * It sends/receives Hello, LSU, and LSAck packets, maintains an LSDB, creates
 * AS-External-LSAs for routes exported by RouteGateway, and reports decoded
 * external routes through RouteLearnHandler. Database Description and SPF are
 * intentionally separate follow-up components.
 */
class OspfProtocolSpeaker final : public RouteSpeaker {
public:
    /** Creates a stopped protocol speaker with optional FIB installation. */
    explicit OspfProtocolSpeaker(
        OspfSpeakerConfig config,
        std::unique_ptr<FibInstaller> fib_installer = nullptr);

    /** Stops the event loop and closes the raw socket. */
    ~OspfProtocolSpeaker() override;

    OspfProtocolSpeaker(const OspfProtocolSpeaker&) = delete;
    OspfProtocolSpeaker& operator=(const OspfProtocolSpeaker&) = delete;

    /** Returns the configured route domain. */
    ProtocolDomain domain() const noexcept override;

    /** Replaces local external routes and floods new/withdrawn LSAs. */
    // 中文：输入集合按前缀去重；消失项以 MaxAge LSA 撤销，新增项正常泛洪。
    void replace_external_routes(std::vector<Route> routes) override;

    /** Registers the callback used for routes decoded from received LSAs. */
    void set_route_learn_handler(RouteLearnHandler handler) override;

    /** Opens the raw socket and sends the first Hello immediately. */
    void start();

    /** Stops the speaker and releases the raw socket. */
    void stop() noexcept;

    /** Returns whether start() has completed and the socket is active. */
    bool running() const noexcept;

    /** Runs one poll/timer iteration, waiting up to timeout_ms. */
    // 中文：timeout_ms 只是等待上限，Hello 到期时间会进一步缩短等待。
    void run_once(int timeout_ms = 1000);

    /** Runs run_once() until stop() is called. */
    void run();

    /** Returns the current LSDB snapshot object. */
    const LinkStateDatabase& lsdb() const noexcept;

    /** Returns a snapshot of currently known neighbors. */
    // 中文：快照包含状态、源地址和接口索引，不暴露内部状态机对象。
    std::vector<OspfNeighborInfo> neighbors() const;

private:
    struct NeighborContext {
        // 中文：邻居上下文把状态机和最近 Hello 的网络元数据放在一起。
        explicit NeighborContext(std::uint32_t id)
            : state_machine(id) {}

        NeighborStateMachine state_machine;
        std::string source_address;
        std::uint32_t interface_index = 0;
        std::chrono::steady_clock::time_point last_hello{};
    };

    void validate_config() const;
    void send_hello();
    void handle_datagram(const OspfDatagram& datagram);
    void handle_hello(const OspfPacket& packet, const OspfDatagram& datagram);
    void handle_link_state_update(const OspfPacket& packet,
                                  const OspfDatagram& datagram);
    void handle_link_state_acknowledgment(const OspfPacket& packet);
    void send_lsa_update(const std::vector<Lsa>& lsas,
                         bool all_designated_routers = false);
    void send_lsa_acknowledgment(const std::vector<LsaHeader>& headers,
                                 const std::string& destination);
    void publish_routes(const std::vector<Route>& routes);
    void withdraw_removed_routes(const std::vector<Route>& routes);
    std::vector<std::uint8_t> serialize_with_checksum(OspfHeader header,
                                                       const std::vector<std::uint8_t>& payload,
                                                       const std::string& destination) const;
    std::array<std::uint8_t, 16> source_ipv6_bytes() const;
    std::vector<std::uint8_t> make_lsa_update_packet(const std::vector<Lsa>& lsas) const;
    std::vector<std::uint8_t> make_lsa_ack_packet(const std::vector<LsaHeader>& headers,
                                                  const std::string& destination) const;
    void expire_neighbors(std::chrono::steady_clock::time_point now);

    OspfSpeakerConfig config_;
    OspfRawSocket socket_;
    std::unique_ptr<FibInstaller> fib_installer_;
    LinkStateDatabase lsdb_;
    std::map<std::uint32_t, NeighborContext> neighbors_;
    std::map<std::string, Route> exported_routes_;
    std::map<std::string, std::uint32_t> sequence_numbers_;
    RouteLearnHandler route_learn_handler_;
    std::chrono::steady_clock::time_point next_hello_{};
    bool running_ = false;
};

} // namespace ospf_gateway
