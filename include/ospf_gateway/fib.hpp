#pragma once

/*
 * FIB 安装接口隔离了协议状态机和操作系统路由表。
 * LinuxFibInstaller 使用 rtnetlink；在非 Linux 平台上保留接口但明确报告不支持。
 */

#include "ospf_gateway/route.hpp"

#include <cstdint>

namespace ospf_gateway {

/**
 * Abstract route installer used by an OSPF speaker.
 *
 * A real daemon can replace this with a policy-aware FIB implementation. The
 * Linux implementation below writes IPv4/IPv6 unicast routes through rtnetlink.
 */
class FibInstaller {
public:
    virtual ~FibInstaller() = default;

    /** Installs or replaces one route in the forwarding table. */
    // 中文：安装失败应抛出异常，调用方据此决定是否继续处理后续 LSA。
    virtual void install(const Route& route) = 0;

    /** Removes one prefix from the forwarding table. */
    // 中文：撤销只按前缀定位，不要求调用方再次提供完整 Route 元数据。
    virtual void withdraw(const Prefix& prefix) = 0;
};

/** Linux rtnetlink implementation of FibInstaller. */
class LinuxFibInstaller final : public FibInstaller {
public:
    /** Creates an installer using the requested routing table. */
    // 中文：默认表 254 对应 Linux main table；可传入大于 255 的自定义表。
    explicit LinuxFibInstaller(std::uint32_t table = 254);

    /** Installs a route with RTM_NEWROUTE/RTM_REPLACE. */
    // 中文：使用 OSPF 协议标识、度量、下一跳和出接口属性向内核提交替换请求。
    void install(const Route& route) override;

    /** Removes a route with RTM_DELROUTE. */
    // 中文：使用同一 table 和前缀信息发送删除请求。
    void withdraw(const Prefix& prefix) override;

private:
    std::uint32_t table_ = 254;
};

} // namespace ospf_gateway
