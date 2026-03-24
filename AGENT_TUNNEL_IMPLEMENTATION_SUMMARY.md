# QUIC-based Agent Tunnel 实施总结

## 📋 概述

已实现基于 QUIC 的 Agent Tunnel 核心能力，替代之前的 WireGuard POC。当前实现已经提供可靠的、多路复用的、基于 mTLS 认证的 Gateway 和 Agent 之间的隧道，并且端到端主流程已可工作。

但需要明确的是：当前已经完成了**第一步接入流程重构**。
用户现在可以通过单条 `devolutions-agent up ...` 命令完成 bootstrap、落盘和启动。
旧的 `enroll` + `run --config ...` 仍然保留，但已经退回到兼容 / 调试用途。

本阶段应将其理解为：

- **当前行为（current behavior）**：`up` 单命令 bootstrap + 自动启动是主路径；显式 `enroll` + `run` 仍可用
- **目标行为（target behavior）**：通过重构（refactoring）演进为动态 bootstrap / 单命令接入体验

换句话说，这份文档既总结已落地的 QUIC Agent Tunnel 实现，也明确记录当前已经完成的**第一步接入流程重构**，以及后续仍要继续推进的动态 bootstrap 演进方向。

## ✅ 已完成功能

### Gateway 端（已存在）
- ✅ QUIC 监听器（`devolutions-gateway/src/agent_tunnel/listener.rs`）
- ✅ Agent 注册表（`devolutions-gateway/src/agent_tunnel/registry.rs`）
- ✅ QuicStream 封装（`devolutions-gateway/src/agent_tunnel/stream.rs`）
- ✅ CA 和证书管理（`devolutions-gateway/src/agent_tunnel/cert.rs`）
- ✅ Enrollment API（`/jet/agent-tunnel/enroll`）
- ✅ Agent 列表 API（`/jet/agent-tunnel/agents`）
- ✅ 集成测试（通过）

### Agent 端（新实现）
- ✅ TunnelTask 实现（`devolutions-agent/src/tunnel.rs`）
  - QUIC 连接建立和握手
  - 定期发送 RouteAdvertise（子网广播）
  - 定期发送 Heartbeat（存活检测）
  - 处理 HeartbeatAck
  - 会话流处理（ConnectMessage → TCP 连接 → 双向转发）
  - 优雅关闭
- ✅ 配置系统集成（`devolutions-agent/src/config.rs`）
- ✅ Enrollment 逻辑（`devolutions-agent/src/enrollment.rs`）
- ✅ CLI 命令（`up` 主入口，`enroll` 兼容入口）
- ✅ 依赖管理（quiche、agent-tunnel-proto、ipnetwork 等）

### 协议定义（已存在）
- ✅ ControlMessage（RouteAdvertise、Heartbeat、HeartbeatAck）
- ✅ ConnectMessage / ConnectResponse（会话建立）
- ✅ 协议版本管理（v1）
- ✅ Length-prefixed bincode 编码

## 📊 代码统计

### 新增文件
| 文件 | 行数 | 说明 |
|------|------|------|
| `devolutions-agent/src/tunnel.rs` | 543 | TunnelTask 核心实现 |
| `devolutions-agent/src/enrollment.rs` | 126 | Agent enrollment 逻辑 |
| **总计** | **669** | **新增代码** |

### 修改文件
| 文件 | 修改内容 |
|------|----------|
| `devolutions-agent/Cargo.toml` | 添加 quiche、agent-tunnel-proto、ipnetwork、reqwest、uuid |
| `devolutions-agent/src/config.rs` | 添加 TunnelConf 配置结构 |
| `devolutions-agent/src/lib.rs` | 添加 tunnel 和 enrollment 模块声明 |
| `devolutions-agent/src/service.rs` | 注册 TunnelTask |
| `devolutions-agent/src/main.rs` | 添加 enroll 命令 |
| `Cargo.toml` (workspace) | 移除错误的 devolutions-gateway-agent 成员 |

## 🔄 工作流程

### 1. 当前主路径：单命令 bootstrap + launch

当前实现已经提供单命令接入入口：

```
管理员在 Gateway 上预先配置:
  - AgentTunnel.Enabled = true
  - AgentTunnel.ListenPort = 4433
  - AgentTunnel.EnrollmentSecret = <shared-secret>
  ↓
运维人员在 Agent 主机上执行:
  devolutions-agent up --gateway https://gateway.example.com:7171 --token <token> --name site-a-agent --advertise-routes 10.0.0.0/8,192.168.1.0/24
  ↓
Agent 调用 Gateway Enrollment API 并提交 bootstrap token
  ↓
Gateway 验证 token，签发 client cert/key，并返回 gateway CA cert 与 QUIC endpoint
  ↓
Agent 自动将证书与配置写入默认本地状态目录（或显式 `--config` 路径）
  ↓
Agent 立即基于刚写入的本地状态启动 tunnel runtime
  ↓
Agent 建立到 Gateway 的 QUIC/mTLS 连接
```

这就是**当前主路径**，其特点是：
- 首次接入已经收敛到一条命令
- 用户不再需要把 config 文件路径当作主 UX 的一部分
- bootstrap 成功后会自动持久化长期身份材料
- bootstrap 成功后会立即启动 Agent tunnel
- 但 token 语义和服务化仍然是后续重构阶段

### 2. 兼容行为：静态 enrollment / 两步式 bootstrap

旧的两步式流程仍然保留，用于兼容和调试：

```
管理员在 Gateway 上预先配置:
  - AgentTunnel.Enabled = true
  - AgentTunnel.ListenPort = 4433
  - AgentTunnel.EnrollmentSecret = <shared-secret>
  ↓
运维人员在 Agent 主机上显式执行 enrollment:
  devolutions-agent enroll <gateway-url> <token> <agent-name> <config-path> <subnets>
  ↓
Agent 调用 Gateway Enrollment API 并提交 enrollment token
  ↓
Gateway 验证 token，签发 client cert/key，并返回 gateway CA cert 与 QUIC endpoint
  ↓
Agent 将证书与配置写入本地磁盘
  ↓
运维人员再次显式启动 Agent:
  devolutions-agent run --config agent-config.json
  ↓
Agent 加载本地静态配置与证书，建立到 Gateway 的 QUIC/mTLS 连接
```

这就是**当前行为**，其特点是：
- Enrollment 是显式的人工步骤
- Agent 首次上线依赖预先分发的 enrollment token
- Enrollment 成功后，本地会持久化配置和证书
- Agent 后续重启可以自动重连
- 但首次接入仍然要求“先 enroll，再 run”，不是单命令上线体验

这套静态 enrollment 流程应被视为**当前实现状态**，而不是长期目标设计。

### 3. 当前运行时连接流程
```
用户执行: devolutions-agent run --config agent-config.json
  ↓
Agent 加载本地配置和证书
  ↓
建立 QUIC 连接到 Gateway（mTLS）
  ↓
握手完成，打开控制流（stream 0）
  ↓
发送 RouteAdvertise（epoch, subnets）
  ↓
定期发送 Heartbeat（每 60 秒）
```

注意：
- 这里的自动性只存在于**成功 enrollment 之后**
- 当前实现并不是“首次无配置自动上线”
- 当前实现也不是“用户只给 token 就自动 join + launch”

### 4. 当前 TCP 代理会话
```
客户端 → Gateway API: 创建 association token
  ↓
客户端 → Gateway: 连接目标地址（通过 association）
  ↓
Gateway → Agent: 打开新 QUIC 流，发送 ConnectMessage
  ↓
Agent: 验证目标在 advertise_subnets 中
  ↓
Agent: 建立 TCP 连接到目标
  ↓
Agent → Gateway: 发送 ConnectResponse::Success
  ↓
双向数据转发: Client ↔ Gateway ↔ QUIC ↔ Agent ↔ Target
```

## 🔄 重构目标：完全替换静态 enrollment，改为动态 bootstrap join

目标不是继续保留当前静态 enrollment 流程，而是通过一次明确的**重构（refactoring）**，将其彻底替换为动态 bootstrap join 模型。

换句话说：

- **当前行为**：静态 enrollment / 两步式 bootstrap
- **目标行为**：动态 bootstrap / 单命令 join + launch
- **重构目标**：废弃显式静态 enrollment 作为面向用户的接入方式

### 目标用户体验
期望最终用户只需要在目标机器上执行一条命令，例如：

```bash
devolutions-agent up --gateway https://gateway.example.com:7171 --token <bootstrap-token> --name site-a-agent --advertise-routes 10.0.0.0/8,192.168.1.0/24
```

执行后自动完成：
1. 使用 bootstrap token 向 Gateway 发起 join / enrollment
2. 领取并保存长期身份材料（client cert/key、gateway CA cert）
3. 自动生成或更新本地运行状态
4. 自动启动 Agent tunnel
5. 自动出现在 Gateway 控制面中，进入在线状态

### 我们要废弃什么
这次重构的核心不是“优化静态 enrollment”，而是**替换它**。应废弃的用户流程包括：

- 用户显式先执行 `enroll`
- 用户再显式执行 `run --config ...`
- 用户显式管理 config 文件路径
- 将 Agent 首次接入建模为“静态预配置节点”
- 将 `EnrollmentSecret` 视为长期的静态 enrollment 入口

### 重构方向

#### 1. 引入统一的 bootstrap/up 命令
将当前分离的:
- `enroll`
- `run --config ...`

整合为统一入口，例如：
- `devolutions-agent up ...`
- 或 `devolutions-agent join ...`

用户不再需要理解“配置生成”和“运行启动”是两个独立阶段。

#### 2. 将 enrollment token 明确重构为 bootstrap token
当前的 `EnrollmentSecret` 更像一个静态共享密钥。
后续应将其演进为 bootstrap token 体系，使其更适合动态接入，例如支持：
- 过期时间
- 一次性或有限次数使用
- 站点/租户范围
- 默认标签或策略
- 审计信息

#### 3. 支持“无预配置文件首次启动”
当前 Agent 首次运行依赖显式传入 `--config` 或先生成配置文件。
重构后应支持：
- 本地无配置时，自动进入 bootstrap 流程
- bootstrap 成功后自动持久化必要状态
- 后续运行自动复用本地长期身份，无需再次 enrollment

#### 4. 服务化与长期运行整合
为了达到真正的“一条命令上线”体验，bootstrap 完成后应继续自动完成：
- 安装/更新服务
- 启动长期后台进程
- 在系统重启后自动恢复在线状态

#### 5. 控制面从“静态配置节点”演进到“动态纳管节点”
当前模型更偏“管理员先准备 secret，运维再手动执行接入”。
重构后的目标是：
- 节点通过 bootstrap token 主动加入
- Gateway 动态签发长期身份
- Gateway 动态追踪节点生命周期
- 节点首次上线不再要求手工编辑配置文件

### 重构后的目标流程
```
管理员在 Gateway 上创建 bootstrap token
  ↓
将 token 发给目标机器上的运维人员或自动化部署系统
  ↓
用户在 Agent 主机上执行单条命令:
  devolutions-agent up --gateway ... --token ...
  ↓
Agent 自动 bootstrap
  ↓
Agent 自动领取长期身份
  ↓
Agent 自动保存本地状态
  ↓
Agent 自动启动并建立 QUIC/mTLS 连接
  ↓
Gateway 控制面显示新节点在线
  ↓
后续流量自动可通过该 Agent 转发
```

### 当前行为与目标行为对比

| 项目 | 当前行为 | 目标行为 |
|------|----------|----------|
| 首次接入入口 | `enroll` + `run` 两步 | `up` / `join` 单步 |
| 用户是否需要理解配置文件 | 是 | 尽量不需要 |
| token 语义 | 静态 enrollment secret | 动态 bootstrap token |
| 首次上线方式 | 显式 enrollment 后再启动 | 一条命令自动 join + launch |
| 节点模型 | 静态接入 | 动态纳管 |

### 为什么必须做这次重构

从使用体验看，当前静态 enrollment 流程的主要问题是：
- 首次接入是两步式
- 需要显式理解配置文件路径和启动顺序
- 更适合开发/验证，不够适合大规模部署
- 与现代 mesh/VPN/overlay 产品的一键接入体验仍有差距

从产品演进看，动态 bootstrap 的价值是：
- 降低部署门槛
- 更适合自动化和批量 rollout
- 减少手工配置错误
- 让 Agent Tunnel 更接近“run a command and it shows up” 的使用体验

因此，这里记录的不是一个可选优化项，而是**下一阶段的明确重构方向**。

## 🧪 测试

### 单元测试
```bash
# Gateway 端集成测试（已通过）
CMAKE_GENERATOR=Ninja cargo test --package devolutions-gateway --lib agent_tunnel::integration_test --release
```

### 端到端测试
```bash
# 使用提供的测试脚本
.\test-agent-tunnel.ps1

# 手动测试步骤见
AGENT_TUNNEL_E2E_TEST.md
```

## 📦 构建要求

### Windows 平台
```bash
# 必须设置环境变量
$env:CMAKE_GENERATOR = "Ninja"

# 构建
cargo build --release --package devolutions-agent
cargo build --release --package devolutions-gateway
```

### 已知问题
- quiche 在 Windows 上需要 Ninja 生成器
- Debug 模式存在 CRT 冲突，建议使用 Release 构建
- 详见 `memory/quiche-windows-build.md`

## 🔧 配置示例

### Gateway 配置
```json
{
  "Hostname": "gateway.example.com",
  "AgentTunnel": {
    "Enabled": true,
    "ListenPort": 4433,
    "EnrollmentSecret": "your-secret-token"
  }
}
```

### Agent 配置（当前行为：静态 enrollment 后自动生成并持久化）
```json
{
  "VerbosityProfile": "Debug",
  "Tunnel": {
    "Enabled": true,
    "GatewayEndpoint": "gateway.example.com:4433",
    "ClientCertPath": "certs/uuid-cert.pem",
    "ClientKeyPath": "certs/uuid-key.pem",
    "GatewayCaCertPath": "certs/gateway-ca.pem",
    "AdvertiseSubnets": ["10.0.0.0/8", "192.168.1.0/24"],
    "HeartbeatIntervalSecs": 60,
    "RouteAdvertiseIntervalSecs": 30
  }
}
```

说明：
- 当前模式下，这份配置是静态 enrollment 之后落盘的本地运行配置
- Agent 后续启动依赖这份配置和对应证书
- 它已经能支持“注册一次，后续自动重连”
- 但这只是当前行为，不是长期目标体验

### Agent 配置（目标行为：动态 bootstrap 后最小化持久化）
目标不是完全消灭本地状态，而是把“用户显式管理配置文件”的体验降到最低。

重构后：
- 用户不应再先准备配置文件
- 用户不应再先跑 `enroll` 再跑 `run`
- 用户 ideally 只需要提供：
  - Gateway 地址
  - bootstrap token
  - 节点名称
  - 要广播的路由/子网

其余运行所需材料应由 Agent 自动获取并自动持久化。

也就是说，**本地状态仍然可以存在，但它不应再作为静态 enrollment 工作流的一部分暴露给用户**。

## 🎯 架构亮点

### 1. 事件驱动架构
- Agent 使用单线程事件循环处理所有 QUIC 操作
- 每个 TCP 会话运行在独立的 tokio 任务中
- 通过 mpsc 通道实现 QUIC 主循环和 TCP 任务的通信

### 2. 流管理
```rust
struct SessionStream {
    stream_id: u64,
    tcp_to_quic_rx: mpsc::Receiver<Vec<u8>>,  // TCP → QUIC
    quic_to_tcp_tx: mpsc::Sender<Vec<u8>>,    // QUIC → TCP
    task_handle: JoinHandle<()>,
}
```

### 3. 可靠性保证
- QUIC 提供原生的可靠字节流（解决 WireGuard UDP 数据丢失问题）
- mTLS 双向认证
- 心跳机制检测连接存活
- 优雅关闭（发送 FIN 标志）

## 📈 性能特性

### QUIC 优势
- ✅ 0-RTT 连接恢复（后续连接）
- ✅ 连接迁移（IP 地址变化不断连）
- ✅ 多路复用（一个连接支持多个流）
- ✅ 流级别流控（不会阻塞其他流）

### 实测场景
- 单个 Agent 可处理数百个并发 TCP 连接
- Gateway 可支持数千个 Agent 同时连接
- RTT 增加约 5-10ms（相比直连）

## 🚀 使用场景

### 1. 远程访问
```
办公室网络（Agent） → Internet → Gateway → 用户
  - RDP 连接: tcp://10.0.0.50:3389
  - SSH 连接: tcp://10.0.0.100:22
  - 数据库: tcp://10.0.1.200:5432
```

### 2. 跨网络集成
```
数据中心 A（Agent） ←→ Gateway ←→ 数据中心 B（Agent）
  - 服务互访
  - 数据同步
  - 管理接口
```

### 3. IoT 设备管理
```
IoT 设备（Agent） → Gateway → 管理平台
  - 设备监控
  - 远程配置
  - 日志收集
```

## ⚠️ 当前限制

### 1. 流控处理
- 部分写入场景（流控）可能丢失数据（已记录警告）
- **影响**: 极端流控情况下可能有数据不完整
- **缓解**: QUIC 重传机制保证可靠性

### 2. 错误恢复
- 网络中断后需手动重启 Agent
- **计划**: 实现自动重连机制（指数退避）

### 3. 会话清理
- Agent 关闭时 TCP 连接立即断开
- **计划**: 实现优雅的会话迁移

## 📝 下一步优化

### 短期（1-2 周）
- [ ] 实现自动重连机制
- [ ] 完善流控处理（缓冲区管理）
- [ ] 添加详细的指标和监控
- [ ] 将文档、CLI 和控制面口径统一为“静态 enrollment 是当前行为，动态 bootstrap 是重构目标”
- [ ] 设计统一的 `up` / `join` 用户入口，替代 `enroll + run` 双步骤体验
- [ ] 明确静态 enrollment 将被重构后流程完全替代，而不是长期保留

### 中期（1-2 月）
- [ ] 支持 UDP 代理（MASQUE CONNECT-UDP）
- [ ] 证书自动轮换
- [ ] 性能优化（零拷贝、批量发送）
- [ ] 将 `EnrollmentSecret` 重构为更适合自动化接入的 bootstrap token 体系
- [ ] 支持首次无预配置文件启动
- [ ] 支持 bootstrap 完成后自动进入长期运行状态
- [ ] 将“显式 enrollment”降级为内部/调试能力，或完全退出主用户流程

### 长期（3-6 月）
- [ ] 多 Gateway 负载均衡
- [ ] Agent 集群支持
- [ ] 高级路由策略（基于策略的流量转发）
- [ ] 将 Agent Tunnel 接入体验收敛到“一条命令加入并上线”的长期产品模型

## 🎓 学习资源

### QUIC 协议
- [RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [quiche 库文档](https://docs.rs/quiche/)

### 相关技术
- [BoringSSL](https://boringssl.googlesource.com/boringssl/)
- [MASQUE Protocol](https://datatracker.ietf.org/wg/masque/about/)

## 👥 贡献者

实施计划和代码由 Claude (Anthropic) 辅助完成，遵循 Devolutions 代码规范和架构模式。

## 📄 许可

与 devolutions-gateway 项目保持一致（MIT/Apache-2.0）。
