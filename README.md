# OSPFv2 <-> OSPFv3 Gateway

这是一个 C++17 项目，用于实现 OSPFv2 IPv4 域与 OSPFv3 IPv4 AF 之间的路由重发布核心。

当前版本分为路由重发布核心、协议基础层和 Linux 运行时：

- OSPFv2、OSPFv3 IPv4 AF、OSPFv3 IPv6 使用独立的路由域模型。
- 两侧路由通过本地 RIB 逻辑重新发布，不转发或伪造对端的 OSPF 报文。
- IPv4 路由可以在 OSPFv2 与 OSPFv3 IPv4 AF 之间双向发布。
- IPv6 路由不会进入 OSPFv2。
- 支持前缀过滤、度量值增加、外部路由类型和 32 位防环标签。
- 协议 Speaker 使用接口隔离，当前提供内存 Speaker 作为测试和演示适配器。
- 提供 OSPFv2/OSPFv3 通用报文头编解码。
- 提供 OSPFv2 和 OSPFv3 Hello 报文编解码。
- 提供 OSPFv2 校验和、带 IPv6 伪首部的 OSPFv3 校验和计算。
- 提供经过协议报文验证后的邻居状态机骨架：Down、Init、2-Way、ExStart、Exchange、Loading、Full。
- Linux 下提供 IP protocol 89 raw socket，加入 AllSPF/AllDR 组播并支持单播 LSAck。
- 提供 Hello 周期定时器、Dead 定时器和邻居发现。
- 提供 LSDB、LSU/LSAck 编解码、LSA 新旧版本比较和老化。
- 支持 OSPFv2 AS-External-LSA 与 OSPFv3 AS-External-LSA 的生成和解析。
- Linux 下通过 rtnetlink 安装和撤销 IPv4/IPv6 单播路由。
- 提供 `ospf-gatewayd --config` 守护进程入口，同时启动 OSPFv2、OSPFv3 IPv4 AF 和 OSPFv3 IPv6 Speaker。

当前 Linux 运行时已经接入真实网络 I/O；macOS 仅用于编译和协议单元测试，raw socket/FIB 会报告不支持的平台错误。

当前仍未实现完整的 Database Description 主从协商、SPF 计算、Router-LSA/Network-LSA 拓扑建模、区域间路由、NSSA、认证和 Graceful Restart。因此这版可以用于协议实验和外部路由重发布开发，不能直接当作生产 OSPF 路由器替代品。

协议报文格式以 OSPFv2、OSPFv3 和 OSPFv3 Address Family 规范为依据；OSPFv2/OSPFv3 的协议语义和地址族差异不能通过简单复制 LSA 来消除。

## 构建

需要 C++17 编译器和 CMake 3.16 或更高版本：

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

当前环境没有安装 CMake，也可以直接用 Apple Clang 验证：

```sh
c++ -std=c++17 -Wall -Wextra -Wpedantic \
  -Iinclude src/gateway.cpp src/main.cpp -o ospf-gateway
c++ -std=c++17 -Wall -Wextra -Wpedantic \
  -Iinclude src/gateway.cpp tests/test_gateway.cpp -o ospf-gateway-tests
./ospf-gateway-tests
./ospf-gateway-protocol-tests
./ospf-gateway --demo
./ospf-gateway --protocol-demo
```

## Linux 守护进程

需要 root 或 `CAP_NET_RAW`、`CAP_NET_ADMIN`，并在 Linux 上运行：

```sh
sudo ./ospf-gatewayd --config examples/ospf-gateway.conf
```

配置文件会在同一接口上创建：

- OSPFv2 IPv4 Speaker
- OSPFv3 IPv4 AF Speaker，Instance ID 64
- OSPFv3 IPv6 Speaker，Instance ID 0

收到外部 LSA 后，Speaker 会写入 LSDB、发送 LSAck、尝试安装 Linux FIB，并把路由回调给 `RouteGateway`。网关随后根据策略把 IPv4 路由发布到另一协议域。

示例配置见 [`examples/ospf-gateway.conf`](examples/ospf-gateway.conf)。生产部署前需要将 `interface`、`router-id`、`ipv6-source` 和 `v3-interface-id` 改为实际值，并在隔离的 network namespace 或实验设备上验证。

## 函数说明

所有公开函数的参数、返回值、异常条件和状态影响都写在头文件的中文/英文 Doxygen 注释中；完整的按模块函数索引见 [`docs/API.md`](docs/API.md)。

## 下一步

下一阶段应实现 `RouteSpeaker` 的真实适配器：

1. Database Description 主从协商和完整邻接建立。
2. Router-LSA/Network-LSA 建模及 SPF 计算。
3. 区域间、Stub、NSSA 和认证支持。
4. 外部 LSA 刷新、MaxAge 泛洪和重启恢复。
5. 多接口、VRF、BFD 和完整配置管理。

协议适配器接入前，建议先在网络命名空间或容器拓扑中验证本项目的重发布策略，尤其是环路标签、默认路由和双向撤销行为。
