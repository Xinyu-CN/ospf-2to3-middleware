# API 函数说明

本文档对应当前代码版本。头文件中也保留了 Doxygen 注释，便于在 IDE 中直接查看。

## `route.hpp`

### `to_string(AddressFamily)`

把 `IPv4` 或 `IPv6` 转换成稳定的字符串。函数不分配内存，也不会抛异常。

### `to_string(ProtocolDomain)`

把 `OspfV2`、`OspfV3IPv4` 或 `OspfV3IPv6` 转换成日志用名称。它只负责显示，不改变协议域。

### `to_string(RouteType)`

把区域内、区域间、External-1、External-2 转换成稳定名称。

### `Prefix::parse(const std::string&)`

解析 CIDR 文本并返回规范化前缀。输入必须是 `地址/长度`；IPv4 长度范围是 0 到 32，IPv6 长度范围是 0 到 128。主机位会被清零，非法输入抛出 `std::invalid_argument`。

### `Prefix::family()` / `length()` / `is_ipv4()` / `is_ipv6()`

这些访问函数只读取前缀元数据。它们都是 `noexcept`，适合在策略匹配和日志代码中调用。

### `Prefix::contains(const Prefix&)`

判断另一个前缀是否属于当前前缀。只有地址族相同，并且当前前缀长度不大于候选前缀时才可能匹配。

### `Prefix::to_string()`

返回已经规范化的 CIDR 文本，例如 `10.0.0.1/8` 会返回 `10.0.0.0/8`。

### `operator==(Prefix, Prefix)` / `operator!=(Prefix, Prefix)`

比较地址族、长度和规范化后的地址字节。由于前缀在解析时已经规范化，比较结果不会受到主机位影响。

### `Route::Route(...)`

创建一条路由记录。它保存前缀、来源协议域、路由类型、度量值、标签和来源描述。构造函数本身不验证前缀和协议域是否匹配，这项校验由 `RouteGateway::learn()` 完成。
`next_hop` 和 `interface_index` 保存接收接口提供的转发元数据，供 Linux FIB 安装使用。

## `policy.hpp`

### `PrefixRule::matches(const Prefix&)`

执行一条前缀规则。`exact=true` 要求完全相等；否则允许当前规则前缀包含候选前缀。

### `RoutePolicy::RoutePolicy(bool)`

创建策略并设置无规则匹配时的默认动作。默认值是拒绝。

### `RoutePolicy::add_rule(PrefixRule)`

按添加顺序追加规则。匹配时第一条命中的规则决定允许或拒绝，因此规则顺序会影响结果。

### `RoutePolicy::permits(const Prefix&)`

返回前缀是否允许发布。函数只做匹配，不修改策略。

### `set_metric_override()` / `set_metric_add()`

分别设置绝对度量值和度量增量。绝对值优先；没有绝对值时使用饱和加法，避免无符号整数溢出回绕。

### `set_export_type(RouteType)`

设置发布到另一侧时使用的路由类型，通常用于 External-1 或 External-2。

### `set_export_tag(uint32_t)`

设置发布路由的标签。网关用这个标签进行防环过滤。

### `RoutePolicy::transform(const Route&, ProtocolDomain)`

复制输入路由并重写目标协议域、路由类型、度量值、标签和来源字符串。它不负责判断是否允许，调用者应先调用 `permits()`。

## `speaker.hpp`

### `RouteSpeaker::~RouteSpeaker()`

虚析构函数，保证通过接口指针释放具体 Speaker 时行为正确。

### `RouteSpeaker::domain()`

返回 Speaker 对应的协议域。`RouteGateway` 构造时用它检查 Speaker 是否接错。

### `RouteSpeaker::replace_external_routes()`

用完整集合替换当前发布路由。真实协议适配器应在这里生成、刷新或撤销外部 LSA；当前 `MemorySpeaker` 只保存集合。

### `MemorySpeaker::MemorySpeaker(ProtocolDomain)`

创建内存适配器，主要用于单元测试和命令行演示。

### `MemorySpeaker::external_routes()`

返回最近一次安装的外部路由集合。返回的是只读引用，生命周期由 Speaker 管理。

## `gateway.hpp`

### `RouteGateway::RouteGateway(...)`

建立 OSPFv2、OSPFv3 IPv4 AF、OSPFv3 IPv6 三个域之间的路由重发布关系。构造时检查 Speaker 域，并拒绝零防环标签。

### `RouteGateway::learn(Route)`

插入或替换某协议域中的一条学习路由，然后重新计算两侧的发布集合。它会检查 IPv4/IPv6 与协议域是否匹配。

### `RouteGateway::withdraw(ProtocolDomain, Prefix)`

删除指定域中的前缀，并立即重新发布新的完整集合。

### `RouteGateway::stats()`

返回最近一次同步的学习和发布计数。返回只读引用，不触发重新计算。

### `RouteGateway::reconcile()`

内部函数。根据三张输入路由表重新生成 OSPFv2 和 OSPFv3 IPv4 AF 的导出集合，并清空 OSPFv3 IPv6 的外部集合。

### `build_v2_to_v3()` / `build_v3_to_v2()`

内部函数。依次执行防环标签检查、前缀策略检查和策略转换，生成目标域的外部路由列表。

### `table_for(ProtocolDomain)`

内部函数。把协议域映射到对应的内存路由表。未知枚举值会抛出 `std::invalid_argument`。

## `ospf_packet.hpp`

### `to_string(OspfVersion)` / `to_string(OspfPacketType)`

把协议版本或报文类型转换成日志用名称。

### `ospf_header_length(OspfVersion)`

返回 OSPFv2 或 OSPFv3 的公共报文头长度。它只用于编解码边界计算。

### `parse_ospf_packet(const vector<uint8_t>&)`

解析一个完整的 OSPF 报文，检查版本、类型、最小头长度和声明长度。它不会自动验证 checksum，因为 OSPFv3 checksum 需要 IPv6 源/目的地址。

### `serialize_ospf_packet(OspfHeader, payload)`

生成公共报文头和任意 payload，并自动更新 `packet_length`。它保留传入的 checksum 字段，调用者可以先序列化、计算 checksum，再重新序列化。

### `parse_ospf_hello(const OspfPacket&)`

解析 OSPFv2 或 OSPFv3 Hello body。它根据版本解释字段，检查固定部分长度以及邻居 Router ID 列表是否按 4 字节对齐。

### `serialize_ospf_hello(OspfHeader, OspfHello)`

根据头部版本生成 OSPFv2 或 OSPFv3 Hello。它会检查 OSPFv2 options、OSPFv3 options 和 OSPFv3 dead interval 的位宽限制。

### `internet_checksum(vector<uint8_t>)`

计算标准 Internet checksum。它是基础工具，不自动知道数据属于 OSPFv2 还是 OSPFv3。

### `compute_ospfv2_checksum(vector<uint8_t>)`

解析并校验输入是 OSPFv2 报文，然后把 checksum 字段置零，排除 OSPFv2 认证字段后计算 checksum。

### `compute_ospfv3_checksum(vector<uint8_t>, source, destination)`

解析并校验输入是 OSPFv3 报文，把 checksum 字段置零，并将 IPv6 源地址、目的地址、payload 长度和 OSPF Next Header 值加入伪首部后计算 checksum。

## `neighbor.hpp`

### `to_string(NeighborState)` / `to_string(NeighborEvent)`

把邻居状态或状态机事件转换成日志名称。

### `NeighborStateMachine::NeighborStateMachine(uint32_t)`

创建一个远端 Router ID 对应的邻居状态机，初始状态为 Down。

### `neighbor_router_id()` / `state()`

读取远端 Router ID 和当前状态，不修改状态。

### `process(NeighborEvent)`

处理一个已经由上层验证过的事件，返回旧状态、新状态、是否发生变化以及是否进入 Full。该函数不负责定时器、报文重传、LSDB 或主从协商数据。

### `reset()`

强制邻居回到 Down，用于接口关闭、邻居失效或测试清理。

## `lsa.hpp`

### `LsaKey::operator<` / `operator==`

按 LSA Type、Link State ID、Advertising Router 排序或比较，用于 LSDB 的稳定键。

### `Lsa::key()`

从 LSA 头部生成 LSDB 键，不读取 body。

### `LinkStateDatabase::install()`

按序列号和校验和比较新旧 LSA。新键会插入，新实例会替换，旧实例和完全相同实例会被忽略。

### `LinkStateDatabase::find()` / `all()` / `size()`

分别读取单条 LSA、完整快照和当前条目数。返回值是拷贝，调用者不会修改 LSDB 内部状态。

### `LinkStateDatabase::remove()` / `clear()`

删除单条 LSA 或清空 LSDB。

### `LinkStateDatabase::age()`

给全部 LSA 增加年龄，最大封顶为 MaxAge。真正的 MaxAge 泛洪和删除策略由 Speaker 上层负责。

### `parse_lsa()` / `serialize_lsa()`

在 20 字节 LSA 头和 opaque body 之间转换，并检查长度边界。

### `parse_link_state_update()` / `serialize_link_state_update()`

处理 LSU body 的 LSA 数量字段和连续 LSA 列表。

### `parse_link_state_acknowledgment()` / `serialize_link_state_acknowledgment()`

处理 LSAck body 中只包含 LSA header 的格式。

### `compute_lsa_checksum()`

计算 LSA Fletcher checksum，计算时忽略 Age 和已有 checksum 字段。

### `make_external_lsa()` / `decode_external_lsa()`

在 Route 与 AS-External-LSA 之间转换。下一跳和接口索引不强行编码进 LSA，而由接收接口补充。

## `raw_socket.hpp`

### `OspfRawSocket::open()` / `close()`

在 Linux 创建 IP protocol 89 raw socket，绑定接口，设置非阻塞模式，加入 OSPF AllSPF/AllDR 组播。非 Linux 平台会报告不支持。

### `send_multicast()` / `send_unicast()`

分别向 AllSPF/AllDR 或指定邻居发送 OSPF payload。socket 类不解析 payload，也不管理协议状态。

### `receive()`

以非阻塞方式读取一条 datagram，去除可能存在的 IPv4/IPv6 外层头，并返回 OSPF payload、源地址和接口索引。

## `fib.hpp`

### `LinuxFibInstaller::install()`

使用 `RTM_NEWROUTE` 和 rtnetlink 安装或替换路由，支持 IPv4/IPv6 目的前缀、下一跳、接口索引、metric 和指定路由表。

### `LinuxFibInstaller::withdraw()`

使用 `RTM_DELROUTE` 按前缀删除内核路由。

## `ospf_speaker.hpp`

### `OspfProtocolSpeaker::start()` / `stop()`

启动或停止 raw socket、Hello 定时器和接收事件循环。

### `run_once()` / `run()`

`run_once()`执行一轮 poll、Hello 定时器、收包和 Dead 定时器检查；`run()`持续执行直到 stop。

### `replace_external_routes()`

接收网关发布的路由集合，生成新的 AS-External-LSA；消失的路由生成 MaxAge LSA，并通过 LSU 发送。

### `handle_hello()`

验证区域、Instance ID、网络掩码、Hello/Dead interval，刷新邻居时间并驱动邻居状态机。

### `handle_link_state_update()`

解析 LSU、更新 LSDB、解析外部 LSA、安装 FIB、调用 RouteLearnHandler、发送 LSAck，并对新 LSA 做组播泛洪。

### `handle_link_state_acknowledgment()`

解析 LSAck header 列表。目前只完成接收和格式校验，重传队列还未实现。

### `set_route_learn_handler()`

注册网络学习路由回调。RouteGateway 构造时会自动注册，析构时自动解绑。

## `daemon_main.cpp`

### `ospf-gatewayd --config <file>`

读取简单的 `key=value` 配置，构造三个真实 Speaker、RouteGateway 和 LinuxFibInstaller，然后注册 SIGINT/SIGTERM，进入事件循环。

## 当前未覆盖的函数级功能

以下功能还没有对应实现函数，因此不能把当前程序当成完整路由器部署：

- raw socket 收发和 TTL/IPv6 Hop Limit 检查
- 接口 Hello 定时器和 Dead 定时器
- DR/BDR 选举
- Database Description 主从协商
- LSDB 安装、老化、泛洪和确认
- Router-LSA、Network-LSA、AS-External-LSA 生成
- Linux FIB/VRF 安装
