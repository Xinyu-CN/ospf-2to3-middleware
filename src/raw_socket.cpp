/*
 * 原始套接字实现：在 Linux 上配置协议号 89、接口级 TTL/HopLimit 和 OSPF 组播，
 * 并将收到的 IPv4/IPv6 网络头剥离。socket 细节集中在此，协议解析层只接触载荷。
 */
#include "ospf_gateway/raw_socket.hpp"

#include <stdexcept>
#include <utility>

#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace {

constexpr int kOspfIpProtocol = 89;

std::runtime_error system_error(const char* operation) {
    // 统一保留 errno 文本，便于区分权限、接口和内核参数错误。
    return std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

void set_nonblocking(int descriptor) {
    // Speaker 通过 poll 驱动事件循环，因此接收描述符必须设置为非阻塞。
    const int flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
        throw system_error("fcntl(O_NONBLOCK)");
    }
}

void join_ipv4_group(int descriptor, std::uint32_t interface_index,
                     const char* group_text) {
    // OSPFv2 在指定接口加入 AllSPF(224.0.0.5) 或 AllDR(224.0.0.6)。
    ip_mreqn request{};
    if (inet_pton(AF_INET, group_text, &request.imr_multiaddr) != 1) {
        throw std::runtime_error("invalid IPv4 OSPF multicast group");
    }
    request.imr_ifindex = static_cast<int>(interface_index);
    if (setsockopt(descriptor, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   &request, sizeof(request)) < 0) {
        throw system_error("setsockopt(IP_ADD_MEMBERSHIP)");
    }
}

void join_ipv6_group(int descriptor, std::uint32_t interface_index,
                     const char* group_text) {
    // OSPFv3 使用链路本地 ff02::5/ff02::6，并通过接口索引限定作用域。
    ipv6_mreq request{};
    if (inet_pton(AF_INET6, group_text, &request.ipv6mr_multiaddr) != 1) {
        throw std::runtime_error("invalid IPv6 OSPF multicast group");
    }
    request.ipv6mr_interface = interface_index;
    if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                   &request, sizeof(request)) < 0) {
        throw system_error("setsockopt(IPV6_JOIN_GROUP)");
    }
}

std::string format_ipv4(const sockaddr_in& address) {
    // 将 recvfrom 得到的 IPv4 源地址转换为回调和日志使用的文本。
    char text[INET_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET, &address.sin_addr, text, sizeof(text)) == nullptr) {
        return {};
    }
    return text;
}

std::string format_ipv6(const sockaddr_in6& address) {
    // 将 IPv6 源地址格式化为标准压缩文本。
    char text[INET6_ADDRSTRLEN] = {};
    if (inet_ntop(AF_INET6, &address.sin6_addr, text, sizeof(text)) == nullptr) {
        return {};
    }
    return text;
}

} // namespace

#endif

namespace ospf_gateway {

OspfRawSocket::OspfRawSocket(OspfSocketConfig config)
    : config_(std::move(config)) {}

OspfRawSocket::~OspfRawSocket() {
    close();
}

void OspfRawSocket::open() {
    // open() 具备幂等性：已打开时直接返回，失败时关闭半初始化描述符。
#ifdef __linux__
    if (descriptor_ >= 0) {
        return;
    }
    if (config_.interface_index == 0) {
        if (config_.interface_name.empty()) {
            throw std::invalid_argument("OSPF raw socket needs an interface name");
        }
        config_.interface_index = if_nametoindex(config_.interface_name.c_str());
        if (config_.interface_index == 0) {
            throw system_error("if_nametoindex");
        }
    }

    // 线协议版本决定底层 IP 地址族，OSPF 协议号始终为 89。
    const int family = config_.version == OspfVersion::V2 ? AF_INET : AF_INET6;
    descriptor_ = socket(family, SOCK_RAW, kOspfIpProtocol);
    if (descriptor_ < 0) {
        throw system_error("socket(SOCK_RAW, OSPF)");
    }

    try {
        set_nonblocking(descriptor_);
        int receive_buffer = 1 << 20;
        if (setsockopt(descriptor_, SOL_SOCKET, SO_RCVBUF,
                       &receive_buffer, sizeof(receive_buffer)) < 0) {
            throw system_error("setsockopt(SO_RCVBUF)");
        }

        // v2/v3 分别配置 TTL 与 HopLimit，并加入各自的两组组播地址。
        if (config_.version == OspfVersion::V2) {
            const int ttl = 1;
            const int loop = 0;
            ip_mreqn interface_request{};
            interface_request.imr_ifindex = static_cast<int>(config_.interface_index);
            setsockopt(descriptor_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
            setsockopt(descriptor_, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
            if (setsockopt(descriptor_, IPPROTO_IP, IP_MULTICAST_IF,
                           &interface_request, sizeof(interface_request)) < 0) {
                throw system_error("setsockopt(IP_MULTICAST_IF)");
            }
            join_ipv4_group(descriptor_, config_.interface_index, "224.0.0.5");
            join_ipv4_group(descriptor_, config_.interface_index, "224.0.0.6");

            sockaddr_in bind_address{};
            bind_address.sin_family = AF_INET;
            bind_address.sin_addr.s_addr = htonl(INADDR_ANY);
            if (bind(descriptor_, reinterpret_cast<sockaddr*>(&bind_address),
                     sizeof(bind_address)) < 0) {
                throw system_error("bind(AF_INET)");
            }
        } else {
            const int hops = 1;
            const int loop = 0;
            setsockopt(descriptor_, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops));
            setsockopt(descriptor_, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops));
            setsockopt(descriptor_, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop));
            if (setsockopt(descriptor_, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                           &config_.interface_index, sizeof(config_.interface_index)) < 0) {
                throw system_error("setsockopt(IPV6_MULTICAST_IF)");
            }
            join_ipv6_group(descriptor_, config_.interface_index, "ff02::5");
            join_ipv6_group(descriptor_, config_.interface_index, "ff02::6");

            sockaddr_in6 bind_address{};
            bind_address.sin6_family = AF_INET6;
            bind_address.sin6_addr = in6addr_any;
            bind_address.sin6_scope_id = config_.interface_index;
            if (bind(descriptor_, reinterpret_cast<sockaddr*>(&bind_address),
                     sizeof(bind_address)) < 0) {
                throw system_error("bind(AF_INET6)");
            }
        }
    } catch (...) {
        ::close(descriptor_);
        descriptor_ = -1;
        throw;
    }
#else
    throw std::runtime_error("OspfRawSocket is implemented only on Linux");
#endif
}

void OspfRawSocket::close() noexcept {
    // 析构和显式 stop() 都可安全调用 close()，因此这里不抛异常。
#ifdef __linux__
    if (descriptor_ >= 0) {
        ::close(descriptor_);
        descriptor_ = -1;
    }
#else
    descriptor_ = -1;
#endif
}

bool OspfRawSocket::is_open() const noexcept {
    return descriptor_ >= 0;
}

int OspfRawSocket::native_handle() const noexcept {
    return descriptor_;
}

std::uint32_t OspfRawSocket::interface_index() const noexcept {
    return config_.interface_index;
}

void OspfRawSocket::send_multicast(const std::vector<std::uint8_t>& packet,
                                   bool all_designated_routers) {
    // 根据 all_designated_routers 选择 AllSPF 或 AllDR，目标始终限于本链路。
#ifdef __linux__
    if (descriptor_ < 0) {
        throw std::runtime_error("OSPF raw socket is not open");
    }
    if (config_.version == OspfVersion::V2) {
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        const char* group = all_designated_routers ? "224.0.0.6" : "224.0.0.5";
        inet_pton(AF_INET, group, &destination.sin_addr);
        if (sendto(descriptor_, packet.data(), packet.size(), 0,
                   reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) < 0) {
            throw system_error("sendto(OSPFv2 multicast)");
        }
    } else {
        sockaddr_in6 destination{};
        destination.sin6_family = AF_INET6;
        destination.sin6_scope_id = config_.interface_index;
        const char* group = all_designated_routers ? "ff02::6" : "ff02::5";
        inet_pton(AF_INET6, group, &destination.sin6_addr);
        if (sendto(descriptor_, packet.data(), packet.size(), 0,
                   reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) < 0) {
            throw system_error("sendto(OSPFv3 multicast)");
        }
    }
#else
    (void)packet;
    (void)all_designated_routers;
    throw std::runtime_error("OspfRawSocket is implemented only on Linux");
#endif
}

void OspfRawSocket::send_unicast(const std::vector<std::uint8_t>& packet,
                                 const std::string& destination_address) {
    // LSAck 需要直接发给邻居；IPv6 目标额外携带接口 scope_id。
#ifdef __linux__
    if (descriptor_ < 0) {
        throw std::runtime_error("OSPF raw socket is not open");
    }
    if (config_.version == OspfVersion::V2) {
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        if (inet_pton(AF_INET, destination_address.c_str(), &destination.sin_addr) != 1) {
            throw std::invalid_argument("invalid OSPFv2 unicast destination");
        }
        if (sendto(descriptor_, packet.data(), packet.size(), 0,
                   reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) < 0) {
            throw system_error("sendto(OSPFv2 unicast)");
        }
    } else {
        sockaddr_in6 destination{};
        destination.sin6_family = AF_INET6;
        destination.sin6_scope_id = config_.interface_index;
        if (inet_pton(AF_INET6, destination_address.c_str(), &destination.sin6_addr) != 1) {
            throw std::invalid_argument("invalid OSPFv3 unicast destination");
        }
        if (sendto(descriptor_, packet.data(), packet.size(), 0,
                   reinterpret_cast<sockaddr*>(&destination), sizeof(destination)) < 0) {
            throw system_error("sendto(OSPFv3 unicast)");
        }
    }
#else
    (void)packet;
    (void)destination_address;
    throw std::runtime_error("OspfRawSocket is implemented only on Linux");
#endif
}

std::optional<OspfDatagram> OspfRawSocket::receive() {
    // 非阻塞接收：没有数据返回 nullopt；有数据时去掉 IP 头并保留源接口元数据。
#ifdef __linux__
    if (descriptor_ < 0) {
        throw std::runtime_error("OSPF raw socket is not open");
    }
    std::vector<std::uint8_t> buffer(65536);
    sockaddr_storage source{};
    socklen_t source_length = sizeof(source);
    const ssize_t received = recvfrom(descriptor_, buffer.data(), buffer.size(), 0,
                                      reinterpret_cast<sockaddr*>(&source), &source_length);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }
        throw system_error("recvfrom(OSPF)");
    }
    buffer.resize(static_cast<std::size_t>(received));

    std::string source_text;
    if (source.ss_family == AF_INET) {
        // raw IPv4 socket 通常返回 IP 头，需要按 IHL 处理可变长度选项。
        const auto* address = reinterpret_cast<const sockaddr_in*>(&source);
        source_text = format_ipv4(*address);
        if (!buffer.empty() && (buffer[0] >> 4U) == 4) {
            if (buffer.size() < sizeof(iphdr)) {
                throw std::runtime_error("received truncated IPv4 packet");
            }
            const std::size_t header_length = static_cast<std::size_t>(buffer[0] & 0x0fU) * 4U;
            if (header_length < sizeof(iphdr) || header_length > buffer.size()) {
                throw std::runtime_error("received invalid IPv4 header length");
            }
            buffer.erase(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(header_length));
        }
    } else if (source.ss_family == AF_INET6) {
        // IPv6 基本头固定 40 字节；扩展头由当前适配器按最小协议路径处理。
        const auto* address = reinterpret_cast<const sockaddr_in6*>(&source);
        source_text = format_ipv6(*address);
        if (!buffer.empty() && (buffer[0] >> 4U) == 6 && buffer.size() >= 40) {
            buffer.erase(buffer.begin(), buffer.begin() + 40);
        }
    }

    return OspfDatagram{std::move(buffer), std::move(source_text), config_.interface_index};
#else
    throw std::runtime_error("OspfRawSocket is implemented only on Linux");
#endif
}

} // namespace ospf_gateway
