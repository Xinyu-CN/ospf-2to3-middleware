#pragma once

/*
 * 邻居状态机只处理“收到事件后状态如何变化”，不负责定时器、报文重传或 LSDB。
 * 将这些职责拆开后，协议 Speaker 可以独立替换网络 I/O，而测试可以直接验证状态表。
 */

#include <cstdint>

namespace ospf_gateway {

/** OSPF neighbor states used by the adjacency state machine. */
enum class NeighborState {
    // 尚未收到有效 Hello。
    Down,
    // 主动配置的邻居尚未建立双向通信。
    Attempt,
    // 收到对端 Hello，但本端 Router ID 尚未出现在其中。
    Init,
    // 双向 Hello 已确认，可根据接口策略建立完整邻接。
    TwoWay,
    // 开始数据库描述协商，等待主从角色确定。
    ExStart,
    // 交换数据库摘要列表。
    Exchange,
    // 根据摘要请求并接收缺失 LSA。
    Loading,
    // 数据库同步完成，邻接可用于正常泛洪。
    Full,
};

/** Events that can be delivered to a neighbor state machine. */
enum class NeighborEvent {
    // 以下事件名称对应 OSPF 邻接状态机中的输入条件。
    HelloReceived,              // 中文：收到格式正确的 Hello。
    TwoWayReceived,             // 中文：发现对端 Hello 包含本端 Router ID。
    OneWayReceived,             // 中文：对端 Hello 未包含本端 Router ID。
    AdjacencyOk,                // 中文：接口策略允许建立邻接。
    NegotiationDone,            // 中文：DD 主从协商完成。
    ExchangeDone,               // 中文：数据库摘要交换完成。
    LoadingDone,                // 中文：所有请求的 LSA 已加载。
    Kill,                       // 中文：管理性关闭邻居。
    InactivityTimerExpired,    // 中文：超过 Dead Interval 未收到 Hello。
    SequenceNumberMismatch,    // 中文：发现 DD/LSA 序列号不匹配。
    BadLinkStateRequest,        // 中文：收到无法满足的 LSR。
};

/** Returns a stable printable name for a neighbor state. */
// 中文：未知枚举值返回 "unknown"，不会抛出异常。
const char* to_string(NeighborState state) noexcept;

/** Returns a stable printable name for a neighbor event. */
// 中文：字符串用于日志，具体状态迁移仍由 NeighborStateMachine::process() 决定。
const char* to_string(NeighborEvent event) noexcept;

/** Result of processing one neighbor event. */
struct NeighborTransition {
    // 中文：process() 返回完整跃迁信息，调用方无需再次读取旧状态。
    NeighborState previous = NeighborState::Down;  // 中文：事件处理前的状态。
    NeighborState current = NeighborState::Down;   // 中文：事件处理后的状态。
    bool state_changed = false;                    // 中文：前后状态是否不同。
    bool adjacency_established = false;            // 中文：当前是否已达到 Full。
};

/**
 * Small deterministic OSPF adjacency state machine.
 *
 * It models state progression after packet validation. Timer scheduling,
 * database exchange contents, retransmission queues, and interface-level
 * neighbor discovery remain outside this class.
 */
class NeighborStateMachine {
public:
    /** Creates a state machine for one remote router ID, initially Down. */
    explicit NeighborStateMachine(std::uint32_t neighbor_router_id);

    /** Returns the remote router ID associated with this state machine. */
    std::uint32_t neighbor_router_id() const noexcept;

    /** Returns the current adjacency state. */
    NeighborState state() const noexcept;

    /** Processes one event and returns the resulting state transition. */
    // 中文：非法或不适用事件保持原状态，状态机本身不抛异常。
    NeighborTransition process(NeighborEvent event) noexcept;

    /** Forces the neighbor back to Down and clears adjacency progress. */
    void reset() noexcept;

private:
    std::uint32_t neighbor_router_id_ = 0;
    NeighborState state_ = NeighborState::Down;
};

} // namespace ospf_gateway
