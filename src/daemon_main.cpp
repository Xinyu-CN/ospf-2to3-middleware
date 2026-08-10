/*
 * ospf-gatewayd 入口：读取简单的 key=value 配置，创建 v2、v3 IPv4 AF 和 v3 IPv6
 * 三个 Speaker，并在信号驱动的循环中轮询它们。复杂协议逻辑由 OspfProtocolSpeaker 承担。
 */
#include "ospf_gateway/gateway.hpp"
#include "ospf_gateway/ospf_speaker.hpp"

#include <arpa/inet.h>

#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <csignal>
#include <sstream>
#include <stdexcept>
#include <string>

using namespace ospf_gateway;

namespace {

std::atomic<bool> keep_running{true};

void signal_handler(int) {
    // 信号处理器只修改原子标志，实际 socket 清理留给主循环退出后的 stop()。
    keep_running = false;
}

std::map<std::string, std::string> read_config(const std::string& path) {
    // 配置格式故意保持为无节名 key=value；# 后内容视为注释，空项直接忽略。
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("cannot open configuration file: " + path);
    }

    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(file, line)) {
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) {
            line.resize(comment);
        }
        const std::size_t equals = line.find('=');
        if (equals == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, equals);
        std::string value = line.substr(equals + 1);
        while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back()))) {
            key.pop_back();
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
            value.erase(value.begin());
        }
        if (!key.empty() && !value.empty()) {
            values[key] = value;
        }
    }
    return values;
}

std::string required(const std::map<std::string, std::string>& values,
                     const std::string& key) {
    // 对没有默认值的参数集中做存在性检查，错误信息带出具体键名。
    const auto iterator = values.find(key);
    if (iterator == values.end() || iterator->second.empty()) {
        throw std::invalid_argument("missing configuration key: " + key);
    }
    return iterator->second;
}

std::uint32_t parse_ipv4(const std::string& text) {
    // 配置中的 Router ID、Area ID 和网络掩码以点分十进制输入，内部统一保存主机序。
    in_addr address{};
    if (inet_pton(AF_INET, text.c_str(), &address) != 1) {
        throw std::invalid_argument("invalid IPv4 value: " + text);
    }
    return ntohl(address.s_addr);
}

std::uint32_t parse_u32(const std::map<std::string, std::string>& values,
                        const std::string& key,
                        std::uint32_t fallback) {
    // 支持 stoul 的十进制/0x 前缀语法，并拒绝尾随字符和超过 32 位的数值。
    const auto iterator = values.find(key);
    if (iterator == values.end()) {
        return fallback;
    }
    std::size_t parsed = 0;
    const unsigned long value = std::stoul(iterator->second, &parsed, 0);
    if (parsed != iterator->second.size() || value > 0xffffffffUL) {
        throw std::invalid_argument("invalid integer configuration value: " + key);
    }
    return static_cast<std::uint32_t>(value);
}

std::uint16_t parse_u16(const std::map<std::string, std::string>& values,
                        const std::string& key,
                        std::uint16_t fallback) {
    // 在通用 32 位解析基础上再约束 Hello 等 16 位字段范围。
    const std::uint32_t value = parse_u32(values, key, fallback);
    if (value > 0xffffU) {
        throw std::invalid_argument("16-bit configuration value is too large: " + key);
    }
    return static_cast<std::uint16_t>(value);
}

RoutePolicy allow_all(AddressFamily family) {
    // 守护进程示例默认允许整个目标地址族，实际部署应替换为精确过滤策略。
    RoutePolicy policy;
    policy.add_rule({Prefix::parse(family == AddressFamily::IPv4 ? "0.0.0.0/0" : "::/0"),
                     true, false});
    policy.set_metric_add(1);
    policy.set_export_type(RouteType::External2);
    return policy;
}

int run_daemon(const std::string& config_path) {
    // 从同一接口派生三个协议配置，只有 v3 IPv4 AF 使用实例号 64。
    const std::map<std::string, std::string> values = read_config(config_path);
    const std::string interface_name = required(values, "interface");
    const std::uint32_t router_id = parse_ipv4(required(values, "router-id"));
    const std::uint32_t area_id = parse_ipv4(values.count("area-id") != 0
                                                 ? values.at("area-id")
                                                 : "0.0.0.0");
    const std::string source_ipv6 = required(values, "ipv6-source");

    OspfSpeakerConfig v2_config;
    v2_config.version = OspfVersion::V2;
    v2_config.domain = ProtocolDomain::OspfV2;
    v2_config.interface_name = interface_name;
    v2_config.router_id = router_id;
    v2_config.area_id = area_id;
    v2_config.network_mask = parse_ipv4(values.count("v2-network-mask") != 0
                                             ? values.at("v2-network-mask")
                                             : "255.255.255.0");
    v2_config.hello_interval = parse_u16(values, "hello-interval", 10);
    v2_config.dead_interval = parse_u32(values, "dead-interval", 40);

    OspfSpeakerConfig v3_ipv4_config;
    v3_ipv4_config.version = OspfVersion::V3;
    v3_ipv4_config.domain = ProtocolDomain::OspfV3IPv4;
    v3_ipv4_config.interface_name = interface_name;
    v3_ipv4_config.source_address = source_ipv6;
    v3_ipv4_config.router_id = router_id;
    v3_ipv4_config.area_id = area_id;
    v3_ipv4_config.instance_id = 64;
    v3_ipv4_config.interface_id = parse_u32(values, "v3-interface-id", 1);
    v3_ipv4_config.hello_interval = v2_config.hello_interval;
    v3_ipv4_config.dead_interval = v2_config.dead_interval;

    OspfSpeakerConfig v3_ipv6_config = v3_ipv4_config;
    v3_ipv6_config.domain = ProtocolDomain::OspfV3IPv6;
    v3_ipv6_config.instance_id = 0;

    // Speaker 按声明顺序构造，随后由 RouteGateway 安装回调并负责双向重发布。
    OspfProtocolSpeaker v2(std::move(v2_config), std::make_unique<LinuxFibInstaller>());
    OspfProtocolSpeaker v3_ipv4(std::move(v3_ipv4_config),
                                std::make_unique<LinuxFibInstaller>());
    OspfProtocolSpeaker v3_ipv6(std::move(v3_ipv6_config),
                                std::make_unique<LinuxFibInstaller>());

    constexpr std::uint32_t loop_tag = 0x4f325633U;
    RouteGateway gateway(v2, v3_ipv4, v3_ipv6,
                         allow_all(AddressFamily::IPv4),
                         allow_all(AddressFamily::IPv4),
                         loop_tag);

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    v2.start();
    v3_ipv4.start();
    v3_ipv6.start();
    std::cout << "ospf-gatewayd started on " << interface_name << '\n';

    // 三个 run_once 轮流执行，100ms 上限使 Ctrl-C 能及时退出。
    while (keep_running) {
        v2.run_once(100);
        v3_ipv4.run_once(100);
        v3_ipv6.run_once(100);
    }

    v3_ipv6.stop();
    v3_ipv4.stop();
    v2.stop();
    return EXIT_SUCCESS;
}

} // namespace

int main(int argc, char** argv) {
    // 守护进程只接受 --config 一个选项，异常统一转为非零退出码。
    if (argc != 3 || std::string(argv[1]) != "--config") {
        std::cerr << "Usage: ospf-gatewayd --config <file>\n";
        return EXIT_FAILURE;
    }
    try {
        return run_daemon(argv[2]);
    } catch (const std::exception& error) {
        std::cerr << "ospf-gatewayd: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
