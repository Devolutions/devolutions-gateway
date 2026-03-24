# Agent Tunnel 端到端测试指南

## 📌 文档定位

本文档描述的是 **当前实现状态（current behavior）** 下的端到端测试方式，并明确说明未来的 **目标重构方向（target behavior）**。

需要特别强调：

- **当前行为**：`devolutions-agent up ...` 已实现单命令 bootstrap + 自动 launch，`enroll` + `run` 作为兼容路径保留
- **目标行为**：继续把当前实现推进到更完整的动态 bootstrap token / 服务化接入体验
- 因此，本文中的测试步骤默认验证的是**当前已实现的第一步重构**，而不是未来完整目标形态

当前主路径是：

1. 用户执行 `devolutions-agent up ...`
2. Agent 自动 bootstrap
3. Agent 自动获取证书和本地配置
4. Agent 自动启动并连接 Gateway

兼容路径仍然是：

1. 运维人员显式执行 enrollment
2. Agent 获取证书和本地配置
3. 运维人员再显式启动 Agent
4. Agent 基于落盘状态连接 Gateway

目标动态 bootstrap 行为则是：

1. 用户在 Agent 主机上执行单条 `up` / `join` 命令
2. Agent 自动 bootstrap
3. Agent 自动获取长期身份并保存本地状态
4. Agent 自动启动并在线显示于 Gateway 控制面

换句话说：

- **当前测试覆盖** = QUIC tunnel 主流程 + 当前单命令 bootstrap 主路径 + 兼容 enrollment 路径
- **重构目标** = 将当前实现继续演进为更完整的动态 bootstrap join

## 前置条件

### 环境要求
- Windows 系统（或支持 quiche 的平台）
- `CMAKE_GENERATOR=Ninja` 环境变量（Windows 必需）
- 已安装 Ninja build system
- 两台网络可达的机器或本地测试环境

### 构建项目

```bash
# 设置环境变量
$env:CMAKE_GENERATOR="Ninja"

# 构建 Gateway
cargo build --release --package devolutions-gateway

# 构建 Agent
cargo build --release --package devolutions-agent
```

## 测试步骤

## 当前主路径：单命令 bootstrap / 自动 launch

下面的步骤验证的是**当前实现**：

1. 先在 Gateway 侧准备 enrollment secret
2. 在 Agent 主机上执行 `devolutions-agent up ...`
3. 让 Agent 自动保存状态并自动启动
4. 验证 Agent 在线并完成端到端转发

这是当前主路径。
旧的 `enroll` + `run` 仍可用于兼容和调试，但不再是首选 onboarding 方式。

### Step 1: 配置并启动 Gateway

创建 Gateway 配置文件 `gateway.json`:

```json
{
  "Hostname": "gateway.example.local",
  "Listeners": [
    {
      "InternalUrl": "http://0.0.0.0:7171"
    }
  ],
  "AgentTunnel": {
    "Enabled": true,
    "ListenPort": 4433,
    "EnrollmentSecret": "test-secret-token-12345"
  }
}
```

启动 Gateway:

```bash
.\target\release\devolutions-gateway.exe run --config gateway.json
```

验证日志输出包含：
```
INFO devolutions_gateway::agent_tunnel: Agent tunnel listener started on 0.0.0.0:4433
```

### Step 2: Agent Bootstrap And Launch（当前主路径）

在 Agent 机器上执行单命令 bootstrap：

```bash
.\\target\\release\\devolutions-agent.exe up \\
  --gateway "http://localhost:7171" \\
  --token "test-secret-token-12345" \\
  --name "test-agent-1" \\
  --advertise-routes "10.0.0.0/8,192.168.1.0/24"
```

**参数说明:**
- `--gateway` - Gateway HTTP API URL
- `--token` - Bootstrap / enrollment token（与 Gateway 配置匹配）
- `--name` - Agent 友好名称
- `--advertise-routes` - 要 advertise 的子网（逗号分隔）
- `--config` - 可选。覆盖默认状态文件位置，仅用于兼容 / 调试

**预期输出:**
```
Bootstrapping agent with Gateway...
  Gateway URL: http://localhost:7171
  Agent Name: test-agent-1
  Config Path: C:\ProgramData\Devolutions\Agent\agent.json
  Advertised Routes: ["10.0.0.0/8", "192.168.1.0/24"]
✓ Bootstrap successful
  Agent ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Agent Name: test-agent-1
  Gateway Endpoint: gateway.example.local:4433
  Config Path: C:\ProgramData\Devolutions\Agent\agent.json
Starting agent tunnel...
INFO devolutions_agent::tunnel: Starting QUIC agent tunnel
INFO devolutions_agent::tunnel: Connecting to gateway gateway_addr=gateway.example.local:4433
INFO devolutions_agent::tunnel: QUIC connection established
```

检查生成的文件:
```bash
cat C:\ProgramData\Devolutions\Agent\agent.json
ls C:\ProgramData\Devolutions\Agent\certs\
```

**说明：**
- 这里生成的 `agent.json` 和 `certs/` 目录代表的是当前主路径下的本地持久化状态
- 当前实现已经不再要求用户手动执行第二个 `run` 命令
- 兼容路径仍然允许显式 `enroll` + `run --config ...`

### Step 2b: Agent Enrollment（兼容路径）

在 Agent 机器上显式执行 enrollment：


```bash
.\target\release\devolutions-agent.exe enroll \
  "http://localhost:7171" \
  "test-secret-token-12345" \
  "test-agent-1" \
  "agent-config.json" \
  "10.0.0.0/8,192.168.1.0/24"
```

**参数说明:**
- `http://localhost:7171` - Gateway HTTP API URL
- `test-secret-token-12345` - Enrollment secret（与 Gateway 配置匹配）
- `test-agent-1` - Agent 友好名称
- `agent-config.json` - 生成的配置文件路径
- `10.0.0.0/8,192.168.1.0/24` - 要 advertise 的子网（逗号分隔）

**预期输出:**
```
Enrolling agent with Gateway...
  Gateway URL: http://localhost:7171
  Agent Name: test-agent-1
  Subnets: ["10.0.0.0/8", "192.168.1.0/24"]
✓ Enrollment successful
  Agent ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
  Agent Name: test-agent-1
✓ Certificates saved
  Client cert: certs\xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-cert.pem
  Client key: certs\xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx-key.pem
  Gateway CA: certs\gateway-ca.pem
✓ Configuration saved: agent-config.json

Enrollment complete! You can now run the agent with:
  devolutions-agent run --config agent-config.json
```

检查生成的文件:
```bash
cat agent-config.json
ls certs/
```

**说明：**
- 这里生成的 `agent-config.json` 和 `certs/` 目录代表的是**当前静态 enrollment 行为**下的本地持久化状态
- 当前实现要求运维人员先完成这一步，再显式启动 Agent
- 这正是后续要被重构掉的“两步式接入”体验

### Step 3: 启动 Agent（兼容路径）


```bash
.\target\release\devolutions-agent.exe run --config agent-config.json
```

**预期日志:**
```
INFO devolutions_agent::tunnel: Starting QUIC agent tunnel
INFO devolutions_agent::tunnel: Connecting to gateway gateway_addr=gateway.example.local:4433
INFO devolutions_agent::tunnel: QUIC connection established
INFO devolutions_agent::tunnel: Sent initial RouteAdvertise epoch=1
```

### Step 4: 验证 Agent 连接（当前行为）

在 Gateway 端，检查已连接的 Agent:

```bash
curl http://localhost:7171/jet/agent-tunnel/agents
```

**预期响应:**
```json
[
  {
    "agent_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "agent_name": "test-agent-1",
    "connected_at": "2026-03-24T...",
    "last_heartbeat": "2026-03-24T...",
    "advertised_subnets": ["10.0.0.0/8", "192.168.1.0/24"],
    "active_sessions": 0
  }
]
```

### Step 5: 端到端连接测试（当前行为）

#### 5.1 准备测试环境

在 Agent 可达的网络中启动一个测试服务（例如 SSH 或简单的 TCP echo server）:

```bash
# 启动 Python TCP echo server（仅测试用）
python -c "
import socket
s = socket.socket()
s.bind(('0.0.0.0', 2222))
s.listen(1)
print('Echo server listening on port 2222')
while True:
    c, addr = s.accept()
    print(f'Connection from {addr}')
    while True:
        data = c.recv(1024)
        if not data: break
        c.sendall(data)
    c.close()
"
```

#### 5.2 通过 Gateway 连接

假设测试服务运行在 `10.0.0.50:2222`，使用 jetsocat 或直接 TCP 连接:

```bash
# 创建 association token（需要 Gateway API token）
curl -X POST http://localhost:7171/jet/association \
  -H "Authorization: Bearer $GATEWAY_TOKEN" \
  -d '{
    "jet_agent_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "jet_ttl": 300,
    "target": "tcp://10.0.0.50:2222"
  }'

# 使用返回的 token 连接
jetsocat 10.0.0.50:2222 --token $ASSOCIATION_TOKEN

# 或使用 telnet 测试
echo "Hello Agent Tunnel" | netcat localhost <gateway_proxy_port>
```

### Step 6: 验证数据流

**Gateway 日志应显示:**
```
INFO devolutions_gateway::agent_tunnel: New session stream_id=X session_id=Y target=10.0.0.50:2222
```

**Agent 日志应显示:**
```
INFO devolutions_agent::tunnel: Received ConnectMessage stream_id=X session_id=Y target=10.0.0.50:2222
INFO devolutions_agent::tunnel: TCP connection established stream_id=X target=10.0.0.50:2222
INFO devolutions_agent::tunnel: Session stream started stream_id=X
```

### Step 7: 健康检查

定期检查 Agent 状态:

```bash
# 查看 Agent 日志中的 Heartbeat
# 应该每 60 秒看到:
TRACE devolutions_agent::tunnel: Sent Heartbeat active_streams=N

# 查看 Gateway 侧的 Agent 列表
curl http://localhost:7171/jet/agent-tunnel/agents | jq
```

## 🔄 目标重构方向：动态 bootstrap join

我们希望通过一次明确的重构（refactoring），**完全替换当前静态 enrollment 工作流**，而不是长期保留它。

### 目标行为

目标不是继续要求用户：

1. 先执行 `enroll`
2. 再显式执行 `run --config ...`

目标是让用户在 Agent 主机上只执行一条命令，例如：

```bash
devolutions-agent up --gateway http://localhost:7171 --token <bootstrap-token> --name test-agent-1 --advertise-routes 10.0.0.0/8,192.168.1.0/24
```

然后自动完成：

1. 动态 bootstrap
2. 获取长期身份材料
3. 自动保存本地状态
4. 自动启动 Agent
5. 自动在 Gateway 控制面显示为在线

### 当前行为与目标行为对比

| 项目 | 当前行为 | 目标行为 |
|------|----------|----------|
| 首次接入入口 | `enroll` + `run` 两步 | `up` / `join` 单步 |
| 用户是否需要理解配置文件 | 是 | 尽量不需要 |
| token 语义 | 静态 enrollment secret | 动态 bootstrap token |
| 首次上线方式 | 显式 enrollment 后再启动 | 一条命令自动 join + launch |
| 节点模型 | 静态接入 | 动态纳管 |

### 为什么要重构

当前两步式流程虽然可工作，但它的问题是：

- 首次接入需要人工理解两个阶段
- 用户需要关心配置文件路径和启动顺序
- 更适合开发/验证，不够适合大规模部署
- 与现代 mesh / overlay 产品的一键接入体验仍有明显差距

因此，本文记录的 E2E 测试结果只能说明：

> 当前静态 enrollment + QUIC tunnel 主流程已经可工作

而不能说明：

> 动态 bootstrap / 单命令接入体验已经完成

## 故障排查

### Agent 无法连接

1. **检查网络连通性:**
   ```bash
   # 从 Agent 机器测试 Gateway QUIC 端口
   nc -zvu <gateway-ip> 4433
   ```

2. **检查证书:**
   ```bash
   # 验证证书文件存在
   ls -la certs/

   # 检查证书有效期
   openssl x509 -in certs/gateway-ca.pem -noout -dates
   ```

3. **检查配置:**
   ```bash
   # 确认 gateway_endpoint 正确
   cat agent-config.json | jq .Tunnel.GatewayEndpoint
   ```

### Enrollment 失败（当前行为）

1. **HTTP 401 Unauthorized:**
   - 检查 enrollment_secret 是否匹配

2. **HTTP 404 Not Found:**
   - Gateway 的 agent_tunnel 未启用
   - 检查 Gateway 配置中 `AgentTunnel.Enabled = true`

3. **Connection refused:**
   - Gateway 未启动
   - 防火墙阻止 7171 端口

### 会话连接失败

1. **Target not in advertised subnets:**
   - 检查 Agent 配置中的 `AdvertiseSubnets`
   - 确保目标 IP 在 advertised 子网内

2. **TCP connect failed:**
   - 从 Agent 机器测试直接 TCP 连接:
     ```bash
     telnet <target-ip> <target-port>
     ```

## 性能测试

### 吞吐量测试

```bash
# 使用 iperf3 测试
# 在 Agent 侧网络启动 iperf3 server
iperf3 -s -p 5201

# 从 Gateway 侧通过 tunnel 连接
iperf3 -c <agent-network-ip> -p 5201 --via-tunnel
```

### 延迟测试

```bash
# 持续监控 RTT
while true; do
  curl -s http://localhost:7171/jet/agent-tunnel/agents | \
    jq '.[0].last_heartbeat_rtt_ms'
  sleep 5
done
```

### 并发连接测试

```bash
# 同时建立多个会话
for i in {1..10}; do
  (echo "Session $i" | netcat <target> <port> > /dev/null) &
done
wait

# 检查 active_sessions 计数
curl http://localhost:7171/jet/agent-tunnel/agents | jq '.[0].active_sessions'
```

## 已知限制

1. **当前接入体验仍为静态 enrollment**
   - 当前仍要求显式执行 enrollment，再显式启动 Agent
   - 这是当前行为，不是目标体验

2. **会话流重传:** QUIC 流的部分写入可能被忽略（流控场景）
3. **优雅关闭:** Agent 关闭时 TCP 连接可能立即断开
4. **错误恢复:** 网络中断后需要手动重启 Agent

## 下一步优化 / 重构方向

- [ ] 实现自动重连机制
- [ ] 添加会话流的完整流控处理
- [ ] 支持 UDP 代理（MASQUE CONNECT-UDP）
- [ ] 添加性能指标和监控
- [ ] 证书自动轮换
- [ ] 将静态 enrollment / 两步式接入流程重构为动态 bootstrap join
- [ ] 设计统一的 `up` / `join` 用户入口，替代 `enroll + run`
- [ ] 支持首次无预配置文件启动
- [ ] 将“静态预配置 Agent”模型演进为“动态纳管 Agent”模型
