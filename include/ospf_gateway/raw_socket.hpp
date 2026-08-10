#pragma once

/*
 * OSPF 原始套接字适配层。Linux 上使用 IP 协议号 89，加入 AllSPF/AllDR 组播，
 * 并把收到的 IP 头剥离成纯 OSPF 载荷；非 Linux 平台仍可编译协议核心测试。
 */

#include "ospf_gateway/ospf_packet.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ospf_gateway {

/** Linux interface and protocol parameters needed by an OSPF raw socket. */
struct OspfSocketConfig {
    // 中文：interface_index 为 0 时 open() 会由 interface_name 解析接口索引。
    OspfVersion version = OspfVersion::V2;      // 中文：决定 AF_INET 或 AF_INET6。
    std::string interface_name;                 // 中文：Linux 接口名，如 eth0。
    std::uint32_t interface_index = 0;         // 中文：内核接口索引，0 表示启动时解析。
};

/** One received OSPF payload and the interface metadata attached by the socket. */
struct OspfDatagram {
    // 中文：source_address 和 interface_index 用于邻居标识、LSAck 单播和 FIB 元数据。
    std::vector<std::uint8_t> packet;            // 中文：已剥离 IP 头的 OSPF 载荷。
    std::string source_address;                  // 中文：发送端 IPv4/IPv6 文本地址。
    std::uint32_t interface_index = 0;           // 中文：收到报文的接口索引。
};

/**
 * Thin Linux raw-socket wrapper for IP protocol 89.
 *
 * On non-Linux systems the class compiles but open/send/receive report an
 * unsupported-platform error. The wrapper joins AllSPF and AllDR routers and
 * sends with a hop limit of one, as required for an interface-local OSPF link.
 */
class OspfRawSocket {
public:
    /** Creates a closed socket object with the supplied interface settings. */
    explicit OspfRawSocket(OspfSocketConfig config);

    /** Closes the descriptor if open. */
    ~OspfRawSocket();

    OspfRawSocket(const OspfRawSocket&) = delete;
    OspfRawSocket& operator=(const OspfRawSocket&) = delete;

    /** Opens, binds, configures, and joins the OSPF multicast groups. */
    // 中文：失败会关闭已创建描述符并重新抛出，调用方无需额外回滚。
    void open();

    /** Closes the underlying descriptor and leaves multicast groups. */
    void close() noexcept;

    /** Returns whether the descriptor is currently open. */
    bool is_open() const noexcept;

    /** Returns the descriptor for use with poll/epoll. */
    // 中文：未打开时返回 -1；Speaker 只在 running() 为 true 时使用该句柄。
    int native_handle() const noexcept;

    /** Returns the resolved interface index. */
    std::uint32_t interface_index() const noexcept;

    /** Sends an OSPF payload to AllSPF or AllDR routers. */
    void send_multicast(const std::vector<std::uint8_t>& packet,
                        bool all_designated_routers = false);

    /** Sends an OSPF payload directly to one neighbor address. */
    void send_unicast(const std::vector<std::uint8_t>& packet,
                      const std::string& destination_address);

    /** Receives one packet in non-blocking mode, or nullopt when none is ready. */
    // 中文：返回的数据已去除 IP 头，source_address 是邻居可用的文本地址。
    std::optional<OspfDatagram> receive();

private:
    OspfSocketConfig config_;
    int descriptor_ = -1;
};

} // namespace ospf_gateway
