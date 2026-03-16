# WireGuard Agent Tunneling - 完整技术设计文档

**版本**: 1.0
**日期**: 2026-03-14
**状态**: 已批准实施

---

## 目录

1. [执行摘要](#执行摘要)
2. [架构决策](#架构决策)
3. [技术参考](#技术参考)
4. [系统设计](#系统设计)
5. [实施计划](#实施计划)
6. [测试策略](#测试策略)
7. [运维指南](#运维指南)

---

## 执行摘要

### 问题陈述

Devolutions Gateway当前只能直连到可公网访问的目标服务器。许多企业的服务器位于NAT后面或防火墙内网，无法直接访问。需要一个agent-based tunneling解决方案，让Gateway能够访问这些内网资源。

### 解决方案

使用**WireGuard作为加密传输层** + **自定义TCP中继协议**，Agent安装在内网，主动连接Gateway建立加密隧道，Gateway通过隧道访问内网服务器。

### 核心优势

- ✅ **零防火墙配置**：Agent只需出站UDP连接
- ✅ **自动NAT穿越**：WireGuard内置endpoint roaming
- ✅ **高性能**：避免双重TCP栈，吞吐量高
- ✅ **安全**：WireGuard Noise协议 + JWT授权
- ✅ **易管理**：集中在DVLS配置，用户透明

### 非目标

- ❌ 不做完整IP层VPN（不使用smoltcp）
- ❌ 不替换现有的直连模式
- ❌ 不处理UDP协议（仅TCP）

---

## 架构决策

### ADR-001: 使用TCP中继而非完整IP隧道

**日期**: 2026-03-14
**状态**: 已接受

#### 上下文

有两种技术方案：
- 方案A：完整IP隧道（WireGuard + smoltcp用户空间TCP栈）
- 方案B：TCP中继（WireGuard作为加密传输 + 自定义中继协议）

#### 决策

选择**方案B（TCP中继）**

#### 理由

| 指标 | 方案A（IP隧道） | 方案B（TCP中继） |
|------|----------------|-----------------|
| 吞吐量（100ms RTT） | ~5 Mbps（smoltcp窗口限制） | ~100+ Mbps（真实TCP） |
| 重传行为 | 双重TCP栈级联 | 单层TCP |
| 内存/连接 | ~128KB（smoltcp缓冲区） | ~0（内核TCP） |
| 实现复杂度 | ~6000 LoC | ~3000 LoC |
| RDP兼容性 | 需处理窗口缩放 | 原生支持 |

#### 后果

- ✅ 性能优秀，适合高带宽协议（RDP）
- ✅ 实现更简单
- ❌ 只支持TCP（不支持UDP协议）
- ❌ 需要自定义中继协议（但可参考JMUX）

---

### ADR-002: 路由映射由DVLS决策，Gateway验证执行

**日期**: 2026-03-14
**状态**: 已接受

#### 上下文

需要确定"哪个Agent访问哪个目标"的路由决策由谁负责：
- Gateway维护路由表
- DVLS维护路由表
- Agent自报告能力

#### 决策

**分层架构**：
1. **Agent声明能力**：注册时声明可访问的子网（如192.168.1.0/24）
2. **Gateway存储能力**：维护Agent → 子网映射
3. **DVLS做决策**：管理员配置Server → Agent映射
4. **Gateway执行+验证**：根据JWT路由，并验证Agent确实能访问目标

#### 理由

- ✅ 职责清晰：DVLS管理，Gateway执行
- ✅ 与现有架构一致（DVLS是管理中心）
- ✅ 安全：Gateway双重验证
- ✅ 灵活：支持静态配置和动态发现

#### 后果

- Gateway需要提供Agent查询API（GET /jet/agents）
- DVLS需要同步Agent列表
- JWT需要扩展`jet_agent_id`字段

---

### ADR-003: WireGuard Keepalive由Agent主动维护

**日期**: 2026-03-14
**状态**: 已接受

#### 决策

Agent配置`persistent_keepalive = 25秒`，Gateway端不配置keepalive。

#### 理由

- Agent通常在NAT后面，必须主动发keepalive保持NAT映射
- Gateway在公网，作为responder不需要主动发包
- 25秒足够覆盖大部分NAT超时（30-120秒）

---

## 技术参考

### boringtun v0.7.0 API

#### 核心结构

```rust
use boringtun::noise::Tunn;
use boringtun::x25519::{StaticSecret, PublicKey};

// 创建Tunn（每个peer一个实例）
let tunn = Tunn::new(
    private_key: StaticSecret,
    peer_public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,  // Agent: Some(25), Gateway: None
    index: u32,                         // 会话索引（24位）
    rate_limiter: Option<Arc<RateLimiter>>,
)?;
```

#### 关键方法

```rust
// 加密IP包 → WireGuard UDP包
pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a>
// 返回 WriteToNetwork(data) → 通过UDP发送

// 解密WireGuard UDP包 → IP包
pub fn decapsulate<'a>(
    &mut self,
    src_addr: Option<IpAddr>,
    datagram: &[u8],
    dst: &'a mut [u8]
) -> TunnResult<'a>
// 返回 WriteToTunnelV4(data, addr) → 解密后的IP包

// 定时器维护（每250ms调用一次）
pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a>
// 返回 WriteToNetwork → 发送keepalive
// 返回 Err(ConnectionExpired) → 需要重连

// 主动发起握手
pub fn format_handshake_initiation<'a>(
    &mut self, dst: &'a mut [u8], force_resend: bool
) -> TunnResult<'a>
```

#### TunnResult枚举

```rust
pub enum TunnResult<'a> {
    Done,                                     // 无操作
    Err(WireGuardError),                      // 错误
    WriteToNetwork(&'a mut [u8]),             // 发送UDP包
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),  // 解密后的IPv4包
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),  // 解密后的IPv6包
}
```

#### 关键注意事项

1. **Flush循环**：每次`decapsulate`返回`WriteToNetwork`后，必须循环调用`decapsulate(None, &[], dst)`直到返回`Done`，否则握手响应包会丢失。

2. **缓冲区大小**：`encapsulate`的目标缓冲区必须至少`max(src.len() + 32, 148)`字节，否则panic。

3. **Endpoint更新**：Gateway必须在每次收到包时更新peer的endpoint地址，支持NAT穿越。

---

### 中继协议定义

#### 消息格式（7字节头 + payload）

```
┌─────────┬──────────┬────────┬─────────────┐
│ stream  │   msg    │ length │   payload   │
│   id    │   type   │        │             │
│ 4 bytes │  1 byte  │ 2 bytes│   N bytes   │
└─────────┴──────────┴────────┴─────────────┘
```

#### 消息类型

```rust
#[repr(u8)]
pub enum RelayMsgType {
    Connect = 0x01,    // Gateway → Agent: 请求连接目标
    Connected = 0x02,  // Agent → Gateway: 连接成功
    Data = 0x03,       // 双向: TCP数据
    Close = 0x04,      // 双向: 关闭流
    Error = 0x05,      // Agent → Gateway: 连接失败
}
```

#### CONNECT消息

```rust
// Gateway → Agent
{
    stream_id: 7,
    msg_type: Connect,
    payload: "192.168.1.10:3389"  // 目标地址（字符串）
}
```

#### DATA消息

```rust
// 双向
{
    stream_id: 7,
    msg_type: Data,
    payload: [0x03, 0x00, 0x00, ...]  // 原始TCP字节
}
```

#### 封装进WireGuard

```
中继协议消息
    ↓
封装进"假"IP包（协议号：253，实验性）
    ↓
boringtun::encapsulate
    ↓
WireGuard加密UDP包
    ↓
发送到peer
```

---

### 网络地址分配

#### Tunnel网络：10.10.0.0/16

```
10.10.0.1        - Gateway（固定）
10.10.0.2        - Agent #1
10.10.0.3        - Agent #2
...
10.10.255.254    - Agent #65533（最多65K个Agent）
```

#### 分配策略

```rust
pub struct TunnelIpAllocator {
    next_ip: AtomicU32,  // 从0x0A0A0002开始（10.10.0.2）
    allocated: DashMap<Ipv4Addr, Uuid>,
}

// 分配逻辑：递增，不回收（避免复用冲突）
```

#### 目标子网示例

```
Agent-1 (tunnel_ip=10.10.0.2) → allowed_subnets=[192.168.1.0/24]
Agent-2 (tunnel_ip=10.10.0.3) → allowed_subnets=[10.0.5.0/24, 172.16.0.0/16]
```

---

## 系统设计

### 整体架构

```
┌─────────────┐
│   用户      │
│  (家里)     │
└──────┬──────┘
       │ 1. DVLS选择"Server-A (192.168.1.10)"
       ↓
┌─────────────┐
│    DVLS     │ 2. 生成JWT: {"dst_hst": "192.168.1.10:3389",
│             │              "jet_agent_id": "agent-1-uuid"}
└──────┬──────┘
       │ 3. 连接gateway.example.com:8181 (带JWT)
       ↓
┌─────────────────────────────────────────────────────┐
│  Gateway (公网)                                      │
│  ┌───────────────┐        ┌──────────────────┐     │
│  │ generic_client│ ─────> │ WireGuard        │     │
│  │               │        │ Listener         │     │
│  │ JWT → Agent ID│        │ (UDP :51820)     │     │
│  └───────────────┘        └────────┬─────────┘     │
└──────────────────────────────────────┼──────────────┘
                                      │
       ═══════════════════════════════╪═══════════════
       ║  WireGuard Tunnel (加密)     ║
       ║  10.10.0.1 ↔ 10.10.0.2       ║
       ║  CONNECT/DATA/CLOSE 消息     ║
       ═══════════════════════════════╪═══════════════
                                      │
┌──────────────────────────────────────┼──────────────┐
│  Agent-1 (办公室NAT后)               ↓              │
│  ┌──────────────────┐    ┌──────────────────┐      │
│  │ WireGuard Client │ ←─ │ Relay Handler    │      │
│  │ (出站UDP)        │    │ (解析CONNECT消息) │      │
│  └──────────────────┘    └────────┬─────────┘      │
│                                   │                 │
│                              TcpStream::connect     │
└───────────────────────────────────┼─────────────────┘
                                    ↓
                          ┌──────────────────┐
                          │  目标服务器      │
                          │ 192.168.1.10     │
                          │   :3389          │
                          └──────────────────┘
```

### Gateway端数据结构

```rust
// devolutions-gateway/src/wireguard/listener.rs

pub struct WireGuardListener {
    udp_socket: Arc<UdpSocket>,
    peers: Arc<DashMap<Uuid, Arc<AgentPeer>>>,  // Agent ID → Peer
    pubkey_to_agent: Arc<DashMap<[u8; 32], Uuid>>,
    tunnel_ip_to_agent: Arc<DashMap<Ipv4Addr, Uuid>>,
    gateway_private_key: StaticSecret,
    gateway_tunnel_ip: Ipv4Addr,  // 10.10.0.1
    rate_limiter: Arc<RateLimiter>,
}

pub struct AgentPeer {
    agent_id: Uuid,
    name: String,
    tunnel_ip: Ipv4Addr,                        // 10.10.0.2
    tunn: Mutex<Tunn>,                          // WireGuard实例
    endpoint: RwLock<SocketAddr>,               // 真实UDP地址（动态）
    allowed_subnets: Vec<IpNetwork>,            // 可访问的目标子网
    active_streams: DashMap<u32, StreamHandle>, // stream_id → TCP连接
    next_stream_id: AtomicU32,
    last_handshake: RwLock<Option<Instant>>,
    status: RwLock<AgentStatus>,
}

pub struct StreamHandle {
    target: SocketAddr,
    tx: mpsc::Sender<Bytes>,  // 发送到Agent的数据
    rx: mpsc::Receiver<Bytes>, // 从Agent接收的数据
    created_at: Instant,
}
```

### Agent端数据结构

```rust
// devolutions-gateway-agent/src/tunnel.rs

pub struct TunnelManager {
    agent_id: Uuid,
    gateway_endpoint: SocketAddr,
    tunn: Arc<Mutex<Tunn>>,
    udp_socket: Arc<UdpSocket>,
    active_streams: Arc<DashMap<u32, TcpStream>>,  // stream_id → 真实TCP
}
```

### 配置文件格式

#### Gateway配置 (`gateway.json`)

> Historical note: the static `Peers` and `AllowedSubnets` example below is obsolete.
> The current implementation uses dynamic enrollment for peer identity and runtime route advertisement for subnet ownership.

```json
{
    "Listeners": [
        { "InternalUrl": "https://*:7171", "ExternalUrl": "https://gw.example.com:7171" },
        { "InternalUrl": "tcp://*:8181", "ExternalUrl": "tcp://gw.example.com:8181" },
        { "InternalUrl": "wg://*:51820", "ExternalUrl": "udp://gw.example.com:51820" }
    ],
    "WireGuard": {
        "Enabled": true,
        "PrivateKeyFile": "C:\\ProgramData\\Devolutions\\Gateway\\wg_private.key",
        "TunnelNetwork": "10.10.0.0/16",
        "GatewayIp": "10.10.0.1"
    }
}
```

#### Agent配置 (`agent.toml`)

```toml
agent_id = "550e8400-e29b-41d4-a716-446655440000"
gateway_endpoint = "gw.example.com:51820"
private_key_file = "C:\\ProgramData\\Devolutions\\Agent\\wg_private.key"
gateway_public_key = "base64-encoded-gateway-public-key"
assigned_tunnel_ip = "10.10.0.2"
allowed_subnets = ["192.168.1.0/24", "10.200.0.0/16"]
log_level = "info"

[control_channel]
url = "wss://gw.example.com:7171/jet/agents/control"
heartbeat_interval_secs = 30
```

---

## 实施计划

### Phase 0: 共享Crates（第1-2天）

**目标**: 创建共享库和协议定义

#### 新建文件

```
crates/
  tunnel-proto/
    Cargo.toml
    src/
      lib.rs          # 公共导出
      message.rs      # RelayMessage, RelayMsgType
      codec.rs        # 编解码逻辑
      stream.rs       # StreamId分配器

  wireguard-tunnel/
    Cargo.toml
    src/
      lib.rs          # 公共导出
      tunn_wrapper.rs # Tunn封装
      ip_packet.rs    # IP包构造/解析
      error.rs        # 错误类型
```

#### 关键依赖

```toml
# tunnel-proto/Cargo.toml
[dependencies]
bytes = "1.10"
thiserror = "2"
tracing = "0.1"

# wireguard-tunnel/Cargo.toml
[dependencies]
boringtun = "0.7"
tunnel-proto = { path = "../tunnel-proto" }
tokio = { version = "1.45", features = ["net", "sync", "time"] }
tracing = "0.1"
thiserror = "2"
uuid = "1.17"
dashmap = "6"
parking_lot = "0.12"
```

#### 验收标准

- [ ] `tunnel-proto`可以编解码所有消息类型
- [ ] `wireguard-tunnel`可以创建Tunn实例
- [ ] 单元测试通过

---

### Phase 1: Gateway端集成（第3-5天）

**目标**: Gateway支持WireGuard监听和Agent路由

#### 修改文件

```
devolutions-gateway/
  Cargo.toml           # 添加依赖
  src/
    config.rs          # 扩展WireGuardConfig
    lib.rs             # 导出wireguard模块
    main.rs            # 启动WireGuard listener
    generic_client.rs  # 添加Agent路由逻辑

    wireguard/         # 新建
      mod.rs           # 模块导出
      listener.rs      # WireGuardListener实现
      peer.rs          # AgentPeer管理
      router.rs        # 路由逻辑
      config.rs        # 配置解析
```

#### 关键实现

**`config.rs`扩展**:
```rust
#[derive(Deserialize, Debug, Clone)]
pub struct WireGuardConfig {
    pub enabled: bool,
    pub private_key_file: PathBuf,
    pub tunnel_network: String,  // "10.10.0.0/16"
    pub gateway_ip: Ipv4Addr,    // 10.10.0.1
}
```

**`generic_client.rs`修改**（行114附近）:
```rust
let ((mut server_stream, server_addr), selected_target) =
    if let Some(agent_id) = claims.jet_agent_id {
        // 通过WireGuard Agent路由
        trace!(?agent_id, "Routing via WireGuard agent");

        let wg_listener = conf.wireguard_listener
            .as_ref()
            .context("WireGuard not configured")?;

        wg_listener.connect_via_agent(agent_id, &targets).await?
    } else {
        // 直连
        utils::successive_try(&targets, utils::tcp_connect).await?
    };
```

#### 验收标准

- [ ] Gateway启动时初始化WireGuard listener（UDP :51820）
- [ ] 可以从配置文件加载peer列表
- [ ] generic_client可以根据JWT中的`jet_agent_id`路由
- [ ] 日志显示WireGuard握手成功

---

### Phase 2: Agent端实现（第6-8天）

**目标**: 完整的Agent二进制，可注册、连接、转发

#### 新建项目

```
devolutions-gateway-agent/
  Cargo.toml
  src/
    main.rs            # 入口、CLI
    config.rs          # 配置加载
    tunnel.rs          # WireGuard tunnel管理
    relay.rs           # 中继协议处理
    registration.rs    # 注册逻辑
    tcp_bridge.rs      # TCP连接桥接
    service.rs         # Windows服务/systemd集成
```

#### 关键实现

**`tunnel.rs`核心循环**:
```rust
pub async fn run_tunnel(config: AgentConfig) -> Result<()> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;
    let tunn = Arc::new(Mutex::new(Tunn::new(
        config.private_key,
        config.gateway_public_key,
        None,
        Some(25),  // keepalive
        0,
        None,
    )?));

    // 发起握手
    initiate_handshake(&udp, &tunn, &config.gateway_endpoint).await?;

    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let mut udp_buf = vec![0u8; 65536];
    let mut dst_buf = vec![0u8; 65536];
    let streams = Arc::new(DashMap::new());

    loop {
        tokio::select! {
            _ = timer.tick() => {
                handle_timer(&udp, &tunn, &config, &mut dst_buf).await?;
            }

            result = udp.recv_from(&mut udp_buf) => {
                let (n, addr) = result?;
                handle_udp_packet(
                    &udp, &tunn, &streams,
                    &udp_buf[..n], &mut dst_buf, addr
                ).await?;
            }
        }
    }
}
```

**`relay.rs`处理CONNECT**:
```rust
async fn handle_connect_message(
    stream_id: u32,
    target: &str,
    streams: &DashMap<u32, TcpStream>,
) -> Result<()> {
    let tcp_stream = TcpStream::connect(target).await?;
    streams.insert(stream_id, tcp_stream);

    // 发送CONNECTED响应
    send_relay_message(RelayMessage::connected(stream_id)).await?;

    // 启动双向桥接
    tokio::spawn(tcp_to_relay_bridge(stream_id, tcp_stream));

    Ok(())
}
```

#### 验收标准

- [ ] Agent可以成功注册（手动配置密钥）
- [ ] WireGuard握手成功
- [ ] 收到CONNECT消息后可以连接目标
- [ ] 双向数据转发正常
- [ ] Windows服务/systemd单元工作

---

### Phase 3: 端到端集成测试（第9-10天）

**目标**: 完整流程可用

#### 测试场景

1. **基本连接测试**
   - 启动Gateway（加载Agent配置）
   - 启动Agent
   - 使用jetsocat连接（JWT包含`jet_agent_id`）
   - 验证数据转发

2. **RDP真实场景**
   - Agent在内网，可访问192.168.1.10:3389
   - 用户通过Gateway RDP到该服务器
   - 验证RDP会话正常

3. **Agent故障恢复**
   - Agent崩溃后重启
   - 重新握手成功
   - 现有连接失败，新连接正常

4. **性能测试**
   - iperf3通过tunnel
   - 目标：>50 Mbps吞吐量
   - 延迟：<10ms增加

#### 验收标准

- [ ] 所有测试场景通过
- [ ] 日志清晰，可调试
- [ ] 性能达标

---

### Phase 4: 管理界面（可选，第11-12天）

**目标**: 在gateway-ui添加Agent管理

#### 新建页面

```
webapp/apps/gateway-ui/src/app/
  agents/
    agents-list.component.ts
    agent-detail.component.ts
    agent-registration.component.ts
```

#### 功能

- [ ] Agent列表（名称、状态、隧道IP、最后在线时间）
- [ ] 生成注册token
- [ ] Agent详情（允许的子网、活跃连接数）
- [ ] Agent删除（撤销）

---

## 测试策略

### 单元测试

**tunnel-proto**:
- [ ] 消息编解码正确性
- [ ] 边界条件（最大payload）
- [ ] 错误处理

**wireguard-tunnel**:
- [ ] Tunn创建和销毁
- [ ] IP包构造正确性

### 集成测试

**Gateway + Agent**:
```rust
#[tokio::test]
async fn test_end_to_end_connection() {
    // 1. 启动Gateway（测试端口）
    let gateway = spawn_test_gateway().await;

    // 2. 启动Agent
    let agent = spawn_test_agent().await;

    // 3. 等待握手
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 4. 启动mock RDP服务器
    let mock_server = spawn_mock_tcp_server("127.0.0.1:13389").await;

    // 5. 通过Gateway连接
    let jwt = generate_test_jwt(agent_id, "192.168.1.10:3389");
    let client = connect_with_jwt(&gateway.addr, &jwt).await;

    // 6. 发送测试数据
    client.write_all(b"test data").await.unwrap();

    // 7. 验证mock服务器收到
    assert_eq!(mock_server.recv().await, b"test data");
}
```

### 性能测试

```bash
# 吞吐量测试
iperf3 -c gateway.example.com -p 8181 --jwt <token>

# 延迟测试
ping -c 100 <through-tunnel>

# 并发测试
ab -n 10000 -c 100 <gateway-endpoint>
```

---

## 运维指南

### 部署检查清单

**Gateway端**:
- [ ] 配置`gateway.json`中的WireGuard section
- [ ] 生成Gateway WireGuard密钥
- [ ] 打开防火墙UDP 51820
- [ ] 重启Gateway服务

**Agent端**:
- [ ] 安装Agent二进制
- [ ] 配置`agent.toml`
- [ ] 配置Windows服务/systemd
- [ ] 启动Agent
- [ ] 验证日志显示"WireGuard handshake successful"

### 故障排查

#### Agent无法连接Gateway

```bash
# 1. 检查UDP连通性
nc -u -v gw.example.com 51820

# 2. 检查Agent日志
tail -f /var/log/devolutions-agent/agent.log
# 查找: "ConnectionExpired" 或 "handshake failed"

# 3. 验证密钥配置
# Gateway配置的Agent公钥必须匹配Agent的私钥
```

#### 连接建立但数据不通

```bash
# 1. 检查allowed_subnets配置
# Gateway: agent.allowed_subnets 必须包含目标IP

# 2. 检查Agent端网络
# Agent必须能真实访问目标IP
ping 192.168.1.10  # 从Agent机器

# 3. 抓包分析
tcpdump -i any -n port 51820  # Gateway端
```

#### 性能差

```bash
# 1. 检查MTU
# 确保路径MTU至少1420

# 2. 检查CPU使用
# WireGuard加密占用CPU，确保Gateway有足够资源

# 3. 检查并发连接数
# 单个Agent建议不超过100并发流
```

### 监控指标

| 指标 | 阈值 | 告警 |
|------|------|------|
| Agent心跳间隔 | > 90秒 | Critical |
| WireGuard握手失败率 | > 5% | Warning |
| 隧道延迟 | > 100ms | Warning |
| 活跃流数量 | > 200/agent | Warning |
| UDP丢包率 | > 1% | Warning |

---

## 安全考虑

### 威胁模型

| 威胁 | 缓解措施 |
|------|---------|
| 伪造Agent | 注册token + WireGuard密钥双重认证 |
| 中间人攻击 | WireGuard Noise协议，端到端加密 |
| 重放攻击 | WireGuard内置replay protection |
| 未授权访问 | JWT验证 + allowed_subnets检查 |
| DoS攻击 | RateLimiter + 连接数限制 |

### 密钥管理

- **Gateway私钥**: 存储在`PrivateKeyFile`，权限600
- **Agent私钥**: Windows DPAPI加密 / Linux文件权限600
- **注册Token**: 256位CSPRNG，15分钟过期，一次性使用
- **JWT**: DVLS签名，包含过期时间和Agent ID

---

## 未来扩展

### Phase 5+

- [ ] **QUIC作为备选传输**：UDP被阻时fallback到QUIC over TCP/443
- [ ] **Agent健康评分**：根据延迟、丢包率选择最佳Agent
- [ ] **多Gateway HA**：Agent同时连接多个Gateway
- [ ] **动态子网发现**：Agent自动扫描并报告可达子网
- [ ] **UDP协议支持**：通过中继协议携带UDP包
- [ ] **P2P模式**：Gateway协助NAT穿越后，Client直连Agent（类似Tailscale）

---

## 参考资料

### 外部文档

- [WireGuard Protocol Specification](https://www.wireguard.com/papers/wireguard.pdf)
- [boringtun GitHub](https://github.com/cloudflare/boringtun)
- [Noise Protocol Framework](https://noiseprotocol.org/)

### 内部文档

- `devolutions-gateway/README.md` - Gateway总体架构
- `crates/jmux-proxy/` - JMUX协议参考（类似的多路复用设计）
- `devolutions-gateway/src/token.rs` - JWT claims定义

---

## 附录A: 完整数据流示例

### 场景：用户RDP连接到内网服务器

```
1. 用户在DVLS点击 "Beijing-RDP-Server (192.168.1.10)"

2. DVLS查询数据库:
   SELECT route_via_agent FROM servers WHERE host = '192.168.1.10'
   → agent_id = "550e8400-e29b-41d4-a716-446655440000"

3. DVLS生成JWT:
   {
     "jet_aid": "session-uuid",
     "jet_ap": "rdp",
     "jet_cm": "fwd",
     "dst_hst": "192.168.1.10:3389",
     "jet_agent_id": "550e8400-e29b-41d4-a716-446655440000",  ← 关键
     "jet_ttl": 3600,
     ...
   }

4. 用户RDP客户端连接 gateway.example.com:8181
   发送RDP Pre-Connection Blob包含上述JWT

5. Gateway接收:
   generic_client::serve()
   → read_pcb()
   → extract_association_claims()
   → 发现 claims.jet_agent_id 存在

6. Gateway路由决策:
   let peer = wireguard_listener.peers.get(&claims.jet_agent_id)?;
   // peer.tunnel_ip = 10.10.0.2
   // peer.allowed_subnets = [192.168.1.0/24]

   验证: peer.can_reach("192.168.1.10") → true ✓

7. Gateway分配stream_id并发送CONNECT:
   stream_id = peer.next_stream_id.fetch_add(1) → 7

   relay_msg = RelayMessage {
     stream_id: 7,
     msg_type: Connect,
     payload: "192.168.1.10:3389",
   }

   ip_packet = build_ip_packet(
     src: 10.10.0.1,
     dst: 10.10.0.2,
     protocol: 253,  // 实验性
     payload: relay_msg.encode(),
   )

   tunn.encapsulate(&ip_packet, &mut dst_buf)
   → WriteToNetwork(encrypted_udp_packet)

   udp.send_to(encrypted_udp_packet, peer.endpoint)

8. Agent收到UDP包:
   udp.recv_from() → (n, gateway_addr)

   tunn.decapsulate(Some(gateway_addr.ip()), &udp_buf[..n], &mut dst_buf)
   → WriteToTunnelV4(decrypted_ip_packet, 10.10.0.1)

   extract_ip_payload(decrypted_ip_packet)
   → relay_bytes

   RelayMessage::decode(relay_bytes)
   → Ok(RelayMessage { stream_id: 7, msg_type: Connect, payload: "192.168.1.10:3389" })

9. Agent处理CONNECT:
   let tcp_stream = TcpStream::connect("192.168.1.10:3389").await?;
   active_streams.insert(7, tcp_stream.clone());

   发送CONNECTED响应:
   send_relay_message(RelayMessage::connected(7))

10. Gateway收到CONNECTED:
    建立双向桥接:
    - Client RDP ↔ Gateway WireGuard ↔ Agent WireGuard ↔ Agent TCP ↔ 192.168.1.10:3389

11. 数据流（Client → Server）:
    Client发送RDP数据
    → Gateway收到
    → 打包成RelayMessage::Data(stream_id=7, payload=rdp_bytes)
    → 封装进IP包
    → WireGuard加密
    → UDP发送
    → Agent解密
    → 解析RelayMessage
    → 写入TcpStream(stream_id=7)
    → 192.168.1.10:3389

12. 数据流（Server → Client）:
    192.168.1.10:3389发送响应
    → Agent的TcpStream读取
    → 打包成RelayMessage::Data(stream_id=7, payload)
    → 封装进IP包
    → WireGuard加密
    → UDP发送
    → Gateway解密
    → 解析RelayMessage
    → 写入Client连接
    → Client RDP接收

13. 会话结束:
    Client关闭连接
    → Gateway发送RelayMessage::Close(stream_id=7)
    → Agent收到
    → 关闭TcpStream
    → 从active_streams移除
```

---

**文档结束**

此设计已经过技术评审并批准实施。任何重大变更需要更新此文档并重新评审。
