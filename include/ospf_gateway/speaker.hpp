#pragma once

/*
 * RouteSpeaker 抽象了“向某个 OSPF 域发布路由”和“从该域学习路由”两件事。
 * MemorySpeaker 只保存内存快照，适合演示和单元测试；Linux 真实实现位于
 * ospf_speaker.hpp/cpp，不让核心网关依赖具体 socket 类型。
 */

#include "ospf_gateway/route.hpp"

#include <algorithm>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace ospf_gateway {

using RouteLearnHandler = std::function<void(Route)>;

class RouteSpeaker {
public:
    /** Destroys the protocol speaker through the interface. */
    virtual ~RouteSpeaker() = default;

    /** Returns the protocol domain represented by this speaker. */
    // 中文：返回值决定 RouteGateway 将路由放入哪个来源表或导出目标。
    virtual ProtocolDomain domain() const noexcept = 0;

    /** Replaces all external routes currently advertised by this speaker. */
    // 中文：实现应把传入集合视为完整快照，集合中没有的旧前缀必须撤销。
    virtual void replace_external_routes(std::vector<Route> routes) = 0;

    /**
     * Installs a callback for routes learned from the network.
     *
     * The default implementation is a no-op so simple test speakers do not
     * need to implement receive-side behavior.
     */
    virtual void set_route_learn_handler(RouteLearnHandler handler) {
        // 中文：默认忽略回调，使只关心发送方向的最小测试 Speaker 无需实现接收端。
        (void)handler;
    }
};

class MemorySpeaker final : public RouteSpeaker {
public:
    /** Creates an in-memory speaker for tests and demonstrations. */
    explicit MemorySpeaker(ProtocolDomain speaker_domain)
        : domain_(speaker_domain) {}

    /** Returns the configured domain of this in-memory speaker. */
    // 中文：MemorySpeaker 不做网络发送，只返回构造时保存的固定域。
    ProtocolDomain domain() const noexcept override { return domain_; }

    /** Sorts and stores the complete exported route set. */
    void replace_external_routes(std::vector<Route> routes) override {
        // 中文：按前缀文本排序，让测试结果稳定且便于人工查看。
        std::sort(routes.begin(), routes.end(), [](const Route& left, const Route& right) {
            return left.prefix.to_string() < right.prefix.to_string();
        });
        routes_ = std::move(routes);
    }

    /** Returns the most recently installed exported routes. */
    // 中文：返回只读引用，测试可直接检查网关生成的路由属性。
    const std::vector<Route>& external_routes() const noexcept {
        return routes_;
    }

private:
    ProtocolDomain domain_;
    std::vector<Route> routes_;
};

} // namespace ospf_gateway
