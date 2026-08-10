/*
 * 邻居状态机实现：只根据已验证的协议事件推进状态，不触碰网络 I/O、定时器和 LSDB。
 * 对无效状态/事件组合保持当前状态，保证调用者可以安全地重复投递事件。
 */
#include "ospf_gateway/neighbor.hpp"

namespace ospf_gateway {

const char* to_string(NeighborState state) noexcept {
    // 将枚举转换为日志稳定字符串，未知值保留兜底分支。
    switch (state) {
    case NeighborState::Down:
        return "down";
    case NeighborState::Attempt:
        return "attempt";
    case NeighborState::Init:
        return "init";
    case NeighborState::TwoWay:
        return "two-way";
    case NeighborState::ExStart:
        return "ex-start";
    case NeighborState::Exchange:
        return "exchange";
    case NeighborState::Loading:
        return "loading";
    case NeighborState::Full:
        return "full";
    }
    return "unknown";
}

const char* to_string(NeighborEvent event) noexcept {
    // 事件名用于诊断状态迁移，不参与迁移逻辑本身。
    switch (event) {
    case NeighborEvent::HelloReceived:
        return "hello-received";
    case NeighborEvent::TwoWayReceived:
        return "two-way-received";
    case NeighborEvent::OneWayReceived:
        return "one-way-received";
    case NeighborEvent::AdjacencyOk:
        return "adjacency-ok";
    case NeighborEvent::NegotiationDone:
        return "negotiation-done";
    case NeighborEvent::ExchangeDone:
        return "exchange-done";
    case NeighborEvent::LoadingDone:
        return "loading-done";
    case NeighborEvent::Kill:
        return "kill";
    case NeighborEvent::InactivityTimerExpired:
        return "inactivity-timer-expired";
    case NeighborEvent::SequenceNumberMismatch:
        return "sequence-number-mismatch";
    case NeighborEvent::BadLinkStateRequest:
        return "bad-link-state-request";
    }
    return "unknown";
}

NeighborStateMachine::NeighborStateMachine(std::uint32_t neighbor_router_id)
    : neighbor_router_id_(neighbor_router_id) {}

std::uint32_t NeighborStateMachine::neighbor_router_id() const noexcept {
    // Router ID 是邻居上下文的稳定键。
    return neighbor_router_id_;
}

NeighborState NeighborStateMachine::state() const noexcept {
    // 只读暴露当前状态，避免外部绕过 process() 修改状态。
    return state_;
}

NeighborTransition NeighborStateMachine::process(NeighborEvent event) noexcept {
    // 保存旧状态后按 OSPF 状态图处理事件，返回值同时告知是否建立 Full 邻接。
    const NeighborState previous = state_;

    switch (event) {
    case NeighborEvent::Kill:
    case NeighborEvent::InactivityTimerExpired:
        state_ = NeighborState::Down;
        break;
    case NeighborEvent::OneWayReceived:
        if (state_ != NeighborState::Down) {
            state_ = NeighborState::Init;
        }
        break;
    case NeighborEvent::HelloReceived:
        if (state_ == NeighborState::Down || state_ == NeighborState::Attempt) {
            state_ = NeighborState::Init;
        }
        break;
    case NeighborEvent::TwoWayReceived:
        if (state_ == NeighborState::Init) {
            state_ = NeighborState::TwoWay;
        }
        break;
    case NeighborEvent::AdjacencyOk:
        if (state_ == NeighborState::TwoWay) {
            state_ = NeighborState::ExStart;
        }
        break;
    case NeighborEvent::NegotiationDone:
        if (state_ == NeighborState::ExStart) {
            state_ = NeighborState::Exchange;
        }
        break;
    case NeighborEvent::ExchangeDone:
        if (state_ == NeighborState::Exchange) {
            state_ = NeighborState::Loading;
        }
        break;
    case NeighborEvent::LoadingDone:
        if (state_ == NeighborState::Loading) {
            state_ = NeighborState::Full;
        }
        break;
    case NeighborEvent::SequenceNumberMismatch:
    case NeighborEvent::BadLinkStateRequest:
        if (state_ == NeighborState::Exchange || state_ == NeighborState::Loading ||
            state_ == NeighborState::Full) {
            state_ = NeighborState::ExStart;
        }
        break;
    }

    // 即使状态没有变化也返回完整结果，调用方可以统一记录事件处理结果。
    return NeighborTransition{
        previous,
        state_,
        previous != state_,
        state_ == NeighborState::Full,
    };
}

void NeighborStateMachine::reset() noexcept {
    // 清除邻接进度，供接口重启或邻居重新发现使用。
    state_ = NeighborState::Down;
}

} // namespace ospf_gateway
