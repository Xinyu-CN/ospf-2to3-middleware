/*
 * Linux FIB 实现：通过 rtnetlink 发送 RTM_NEWROUTE/RTM_DELROUTE 请求。
 * 非 Linux 构建仍保留相同 API，但在调用时报告平台不支持，确保协议测试可运行。
 */
#include "ospf_gateway/fib.hpp"

#include <stdexcept>
#include <array>

#ifdef __linux__

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#ifndef RTPROT_OSPF
#define RTPROT_OSPF 89
#endif

namespace {

std::runtime_error system_error(const char* operation) {
    // 把 errno 快照拼入异常，避免调用方只能看到无上下文的系统错误码。
    return std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

struct NetlinkRequest {
    nlmsghdr header{};
    rtmsg route{};
    std::array<std::uint8_t, 1024> attributes{};
};

void add_attribute(nlmsghdr* message, std::size_t capacity,
                   std::uint16_t type, const void* data, std::size_t length) {
    // rtnetlink 属性必须按 RTA_ALIGN 对齐，并同步更新消息总长度。
    const std::size_t offset = NLMSG_ALIGN(message->nlmsg_len);
    const std::size_t attribute_size = RTA_LENGTH(length);
    const std::size_t new_length = offset + RTA_ALIGN(attribute_size);
    if (new_length > capacity) {
        throw std::runtime_error("netlink route message is too large");
    }
    auto* attribute = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(message) + offset);
    attribute->rta_type = type;
    attribute->rta_len = static_cast<unsigned short>(attribute_size);
    std::memcpy(RTA_DATA(attribute), data, length);
    message->nlmsg_len = static_cast<unsigned int>(new_length);
}

void send_route_message(const nlmsghdr* message) {
    // 每次操作建立短生命周期 netlink socket，发送请求后等待内核 ACK。
    const int descriptor = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (descriptor < 0) {
        throw system_error("socket(NETLINK_ROUTE)");
    }

    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    iovec vector{const_cast<nlmsghdr*>(message), message->nlmsg_len};
    msghdr outgoing{};
    outgoing.msg_name = &kernel;
    outgoing.msg_namelen = sizeof(kernel);
    outgoing.msg_iov = &vector;
    outgoing.msg_iovlen = 1;
    if (sendmsg(descriptor, &outgoing, 0) < 0) {
        const std::runtime_error error = system_error("sendmsg(NETLINK_ROUTE)");
        close(descriptor);
        throw error;
    }

    std::array<std::uint8_t, 4096> response{};
    iovec receive_vector{response.data(), response.size()};
    msghdr incoming{};
    incoming.msg_name = &kernel;
    incoming.msg_namelen = sizeof(kernel);
    incoming.msg_iov = &receive_vector;
    incoming.msg_iovlen = 1;
    const ssize_t received = recvmsg(descriptor, &incoming, 0);
    close(descriptor);
    if (received < 0) {
        throw system_error("recvmsg(NETLINK_ROUTE)");
    }

    const auto* reply = reinterpret_cast<const nlmsghdr*>(response.data());
    if (reply->nlmsg_type == NLMSG_ERROR) {
        const auto* error = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(reply));
        if (error->error != 0) {
            errno = -error->error;
            throw system_error("kernel route operation");
        }
    }
}

} // namespace

#endif

namespace ospf_gateway {

LinuxFibInstaller::LinuxFibInstaller(std::uint32_t table)
    : table_(table) {
#ifndef __linux__
    (void)table_;
#endif
}

void LinuxFibInstaller::install(const Route& route) {
    // 将规范化 Prefix 拆成地址和长度，填入内核 rtmsg 及可选网关/接口属性。
#ifdef __linux__
    const std::string prefix_text = route.prefix.to_string();
    const std::size_t slash = prefix_text.find('/');
    const std::string address_text = prefix_text.substr(0, slash);
    const unsigned long prefix_length = std::stoul(prefix_text.substr(slash + 1));
    const int family = route.prefix.is_ipv4() ? AF_INET : AF_INET6;
    const std::size_t address_length = route.prefix.is_ipv4() ? 4 : 16;

    std::array<std::uint8_t, 16> destination{};
    if (inet_pton(family, address_text.c_str(), destination.data()) != 1) {
        throw std::invalid_argument("invalid FIB destination prefix");
    }

    NetlinkRequest request;
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    request.header.nlmsg_type = RTM_NEWROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    request.header.nlmsg_seq = 1;
    request.route.rtm_family = static_cast<unsigned char>(family);
    request.route.rtm_table = table_ < 256 ? static_cast<unsigned char>(table_) : RT_TABLE_UNSPEC;
    request.route.rtm_protocol = RTPROT_OSPF;
    request.route.rtm_scope = RT_SCOPE_UNIVERSE;
    request.route.rtm_type = RTN_UNICAST;
    request.route.rtm_dst_len = static_cast<unsigned char>(prefix_length);

    if (table_ >= 256) {
        add_attribute(&request.header, sizeof(request), RTA_TABLE, &table_, sizeof(table_));
    }
    add_attribute(&request.header, sizeof(request), RTA_DST, destination.data(), address_length);

    // next_hop 为空表示链路直连；否则追加 RTA_GATEWAY。
    if (!route.next_hop.empty()) {
        std::array<std::uint8_t, 16> gateway{};
        if (inet_pton(family, route.next_hop.c_str(), gateway.data()) != 1) {
            throw std::invalid_argument("invalid FIB next hop");
        }
        add_attribute(&request.header, sizeof(request), RTA_GATEWAY, gateway.data(), address_length);
    }
    if (route.interface_index != 0) {
        add_attribute(&request.header, sizeof(request), RTA_OIF,
                      &route.interface_index, sizeof(route.interface_index));
    }
    const std::uint32_t metric = route.metric;
    add_attribute(&request.header, sizeof(request), RTA_PRIORITY, &metric, sizeof(metric));
    send_route_message(&request.header);
#else
    (void)route;
    throw std::runtime_error("LinuxFibInstaller is implemented only on Linux");
#endif
}

void LinuxFibInstaller::withdraw(const Prefix& prefix) {
    // 删除使用与安装相同的表、地址族和前缀属性，内核据此定位路由。
#ifdef __linux__
    const std::string prefix_text = prefix.to_string();
    const std::size_t slash = prefix_text.find('/');
    const std::string address_text = prefix_text.substr(0, slash);
    const unsigned long prefix_length = std::stoul(prefix_text.substr(slash + 1));
    const int family = prefix.is_ipv4() ? AF_INET : AF_INET6;
    const std::size_t address_length = prefix.is_ipv4() ? 4 : 16;

    std::array<std::uint8_t, 16> destination{};
    if (inet_pton(family, address_text.c_str(), destination.data()) != 1) {
        throw std::invalid_argument("invalid FIB destination prefix");
    }

    NetlinkRequest request;
    request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    request.header.nlmsg_type = RTM_DELROUTE;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.header.nlmsg_seq = 1;
    request.route.rtm_family = static_cast<unsigned char>(family);
    request.route.rtm_table = table_ < 256 ? static_cast<unsigned char>(table_) : RT_TABLE_UNSPEC;
    request.route.rtm_protocol = RTPROT_OSPF;
    request.route.rtm_scope = RT_SCOPE_UNIVERSE;
    request.route.rtm_type = RTN_UNICAST;
    request.route.rtm_dst_len = static_cast<unsigned char>(prefix_length);
    if (table_ >= 256) {
        add_attribute(&request.header, sizeof(request), RTA_TABLE, &table_, sizeof(table_));
    }
    add_attribute(&request.header, sizeof(request), RTA_DST, destination.data(), address_length);
    send_route_message(&request.header);
#else
    (void)prefix;
    throw std::runtime_error("LinuxFibInstaller is implemented only on Linux");
#endif
}

} // namespace ospf_gateway
