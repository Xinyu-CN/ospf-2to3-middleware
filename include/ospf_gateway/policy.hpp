#pragma once

/*
 * 路由发布策略：按前缀顺序匹配规则，并在允许后统一改写度量、类型和标签。
 * 策略对象不负责选择来源域，来源域与目标域由 RouteGateway 负责校验。
 */

#include "ospf_gateway/route.hpp"

#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

namespace ospf_gateway {

struct PrefixRule {
    // 中文：规则按插入顺序执行，第一条命中的 permit 决定最终结果。
    Prefix prefix;
    bool permit = false;
    bool exact = false;

    /** Returns whether a candidate prefix matches this rule. */
    bool matches(const Prefix& candidate) const noexcept {
        // exact=true 时要求地址位和前缀长度都一致，否则允许更具体前缀继承匹配。
        if (exact && prefix != candidate) {
            return false;
        }
        return prefix.contains(candidate);
    }
};

class RoutePolicy {
public:
    /** Creates a policy with the supplied default decision when no rule matches. */
    explicit RoutePolicy(bool default_permit = false)
        : default_permit_(default_permit) {}

    /** Appends a rule; rules are evaluated in insertion order. */
    // 中文：规则列表有意保持简单，调用方可以用多条前缀覆盖实现白名单/黑名单。
    void add_rule(PrefixRule rule) { rules_.push_back(std::move(rule)); }

    /** Returns the first matching rule decision, or the configured default. */
    bool permits(const Prefix& prefix) const noexcept;

    /** Sets an absolute exported metric, overriding metric addition. */
    // 中文：设置后忽略输入路由度量与增量，适合把所有外部路由归一化为固定值。
    void set_metric_override(std::optional<std::uint32_t> metric) noexcept {
        metric_override_ = metric;
    }

    /** Adds a saturating metric offset when no absolute override is set. */
    // 中文：加法采用饱和算术，避免 uint32_t 溢出后产生过小的错误度量。
    void set_metric_add(std::uint32_t metric) noexcept {
        metric_add_ = metric;
    }

    /** Sets the route type assigned to every exported route. */
    // 中文：发布时统一指定 External1/External2 等类型。
    void set_export_type(RouteType type) noexcept {
        export_type_ = type;
    }

    /** Sets the route tag assigned to every exported route. */
    // 中文：标签用于环路保护，回流到网关时会被识别并丢弃。
    void set_export_tag(std::uint32_t tag) noexcept {
        export_tag_ = tag;
    }

    /** Copies a permitted route and rewrites its export-domain attributes. */
    Route transform(const Route& input, ProtocolDomain destination) const;

private:
    bool default_permit_ = false;
    std::vector<PrefixRule> rules_;
    std::optional<std::uint32_t> metric_override_;
    std::uint32_t metric_add_ = 0;
    RouteType export_type_ = RouteType::External2;
    std::uint32_t export_tag_ = 0;
};

} // namespace ospf_gateway
