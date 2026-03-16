# WireGuard Agent Tunneling - End-to-End Testing Guide

This guide explains how to run the complete end-to-end test for WireGuard agent tunneling.

## Test Architecture

```
[Test Client]
    ↓ TCP + RDP PCB + JWT (jet_agent_id)
[Gateway] (localhost:8181)
    ↓ WireGuard tunnel (UDP :51820)
[Agent in Docker]
    ↓ Local TCP
[HTTP Server in Docker] (:8080 inside container)
```

## Prerequisites

1. **Docker** installed and running
2. **PowerShell** (for test scripts)
3. **Provisioner key** for signing JWTs (see below)

## Quick Start

### 1. Generate Provisioner Key (if you don't have one)

```powershell
# Generate provisioner keypair
openssl genrsa -out devolutions-gateway/provisioner-private.pem 2048
openssl rsa -in devolutions-gateway/provisioner-private.pem -pubout -out devolutions-gateway/provisioner-public.pem
```

### 2. Run the Test Setup

```powershell
# Build and start the test environment
.\test-wireguard.ps1

# This will:
# - Build the agent Docker image
# - Generate WireGuard keypairs for Gateway and Agent
# - Create configuration files
# - Start the agent container with HTTP server
# - Start the Gateway
# - Generate a test JWT token
```

### 3. Verify the Setup

**Check Agent logs:**
```powershell
docker logs -f wireguard-agent-test
```

**Expected logs:**
```
Starting HTTP server on :8080...
HTTP server started (PID: ...)
Starting agent...
Initiating WireGuard handshake with gateway
Handshake initiation packets sent
```

**Check Gateway logs:**
Look for:
```
WireGuard listener bound
Registered WireGuard peer agent_id=00000000-0000-0000-0000-000000000001
```

### 4. Run the Test Client

```powershell
# Use the token printed by test-wireguard.ps1
.\test-client.ps1 -Token "<your-generated-token>"
```

**Expected output:**
```
=== Testing WireGuard Tunnel Connection ===
[1] Connecting to Gateway (localhost:8181)...
  Connected!
[2] Sending RDP PCB with JWT token...
  PCB sent!
[3] Sending HTTP GET request...
  Request sent!
[4] Reading response...

=== RESPONSE ===
HTTP/1.0 200 OK
...
<h1>Hello from Agent Container!</h1><p>IP: 172.17.0.2</p>
=== END ===

✅ TEST PASSED! Successfully connected through WireGuard tunnel!
```

### 5. Cleanup

```powershell
.\test-wireguard.ps1 -Clean
```

## Manual Testing Steps

If you want to test manually without the script:

### 1. Start Components Manually

**Terminal 1 - Agent Container:**
```powershell
docker run -it --rm `
  --name wireguard-agent-test `
  --add-host host.docker.internal:host-gateway `
  -v "$PWD\test-output\agent-config.toml:/app/agent-config.toml:ro" `
  -p 8888:8080 `
  devolutions-gateway-agent-test
```

**Terminal 2 - Gateway:**
```powershell
cargo run --bin devolutions-gateway -- --config test-output/gateway-test.json
```

### 2. Generate Token

```powershell
cargo run --manifest-path tools\tokengen\Cargo.toml -- sign `
  --provisioner-key devolutions-gateway\provisioner-private.pem `
  forward `
  --dst-hst "127.0.0.1:8080" `
  --jet-agent-id "00000000-0000-0000-0000-000000000001"
```

### 3. Test Connection

Use the test client script or any TCP client that can send RDP PCB.

## Debugging

### Check WireGuard Handshake

**Agent side:**
```powershell
docker logs wireguard-agent-test | Select-String "handshake"
```

**Gateway side:**
Check Gateway terminal for:
```
WireGuard listener initialized
```

### Check Relay Protocol

**Agent receiving CONNECT:**
```
Received relay message msg_type=Connect
Received CONNECT request target="127.0.0.1:8080"
Successfully connected to target
```

**Gateway logs:**
```
Sent CONNECT request to agent
```

### Test HTTP Server Directly

```powershell
# Test that the HTTP server is running
curl http://localhost:8888
```

Expected: `<h1>Hello from Agent Container!</h1>`

### Common Issues

**Issue: Agent can't connect to Gateway**
- Ensure Gateway is listening on UDP :51820
- Check `host.docker.internal` resolves (Docker Desktop required)
- Verify firewall allows UDP :51820

**Issue: WireGuard handshake fails**
- Verify keypairs match in both configs
- Check Gateway logs for decapsulation errors
- Ensure private keys are correctly base64-encoded

**Issue: CONNECT fails**
- Verify agent can reach the target (127.0.0.1:8080 inside container)
- Check `advertise_subnets` in agent config includes the target network
- Look for "Failed to connect to" errors in agent logs

**Issue: Token generation fails**
- Ensure provisioner key exists at the specified path
- Verify tokengen compiled successfully (`cargo check --manifest-path tools/tokengen/Cargo.toml`)

## Next Steps

After successful testing:

1. **Performance testing**: Use `iperf3` through the tunnel
2. **RDP testing**: Test with actual RDP client
3. **Multi-agent**: Add more agents to test routing
4. **NAT traversal**: Test agent behind NAT

## Multi-Agent TDD Matrix

## Route Selection Contract

For overlapping advertised subnets, Gateway must select exactly one winning agent.
The winner is the online agent that most recently established priority for that subnet.

Once a winner is selected for a connection attempt, Gateway must only use that agent.
It must never try another agent as a fallback for the same connection attempt.

If the winning agent cannot connect to the target, the connection attempt must fail.
Fallback to another agent only happens when the route table changes, for example because the current winner goes offline and its advertised routes disappear.

This distinction is intentional:

- Route ownership can be resolved from advertisements for diagnostics or higher layers.
- Gateway data-plane routing only uses an agent when the token explicitly carries `jet_agent_id`.
- Connection retry across multiple agents must never happen.

### Unit Tests

```text
+----+------------------------------------------+--------------------------------------+--------------------------------------+----------------------------------------------+
| ID | 测试名称                                 | 场景设置                             | 操作                                 | 预期结果                                     |
+----+------------------------------------------+--------------------------------------+--------------------------------------+----------------------------------------------+
| U1 | 单路由命中                               | Agent A online，advertise 10.200.1.0/24 | 选择目标 10.200.1.10                 | select_agent_for_target 返回 Agent A         |
| U2 | 无路由不命中                             | Agent A online，无 advertise         | 选择目标 10.200.1.10                 | 返回 None                                    |
| U3 | offline agent 不参与选路                 | Agent A advertise 10.200.1.0/24，但 offline | 选择目标 10.200.1.10            | 返回 None                                    |
| U4 | overlap subnet 最新 advertisement 胜出   | Agent A/B 都 online，都 advertise 同一 subnet | 先 A 后 B advertise           | 选择结果为 Agent B                           |
| U5 | winner offline 后回退                    | A/B 都 advertise，同 subnet，B 最新  | 将 B 标记 offline                    | 选择结果切回 Agent A                         |
| U6 | reconnect 后重新接管                     | A/B 都 advertise，同 subnet，B 最新，后掉线 | B reconnect 并 re-advertise     | 选择结果重新变为 Agent B                     |
| U7 | 指定 jet_agent_id 但 agent 无该路由      | Token 指定 Agent A，A 不含目标 subnet | connect_via_agent(Agent A, target) | 返回错误，不 fallback 到 direct/其他 agent   |
| U8 | 同 epoch 重发是否更新 winner 语义        | A/B 都 online，A 先 advertise，B 后 advertise | A/B 周期性重发                  | 行为需明确：按“最新收到”还是“首次 epoch”     |
+----+------------------------------------------+--------------------------------------+--------------------------------------+----------------------------------------------+
```

### Docker End-to-End Tests

```text
+----+------------------------------------------+--------------------------------------------+------------------------------------------+--------------------------------------------------+
| ID | E2E 测试名称                             | Docker / 网络布局                           | 操作                                     | 预期结果                                         |
+----+------------------------------------------+--------------------------------------------+------------------------------------------+--------------------------------------------------+
| E0 | 单 Agent dynamic enrollment 基本通路     | Gateway + enrolled Docker agent + http target | UI/API 生成 enrollment string -> agent enroll -> run | 返回 "Hello from Agent Container!"      |
| E1 | 单 Agent 动态 advertise 基本通路         | Gateway + agent-a + http-a                 | 请求 tcp://10.200.1.10:8080              | 返回 "Hello from Agent A"                        |
| E2 | 双 Agent 首包识别                        | Gateway + agent-a + agent-b                | 先起 A，再起 B                           | Gateway 能识别 B，B 进入 online + advertised     |
| E3 | 未指定 agent 不自动走隧道                | Gateway + agent-a                           | token 不带 `jet_agent_id`，请求同一目标   | 请求失败，不会偷偷命中 agent                     |
| E4 | 显式 jet_agent_id 强制走指定 agent       | A/B 都 online，只有 B token 指定           | token 指定 B                             | 请求成功并命中 B                                 |
| E5 | 显式 agent 离线时直接失败                | 承接 E4，停掉 B                             | token 仍指定 B                           | 请求失败，不会回退到 A                           |
| E6 | reconnect 后显式 agent 恢复              | 承接 E5                                     | 重启 B，再请求同一目标 IP                 | 返回 B                                           |
| E7 | Agent 不 advertise 时显式连接失败        | B online 但不 advertise                    | token 指定 B                             | 请求失败                                         |
| E8 | 改 subnet 只重启 agent，不重启 Gateway   | A 初始 advertise subnet X                  | 重启 A，改为 advertise subnet Y           | X 验证失败，Y 验证成功                           |
| E9 | `/jet/agents/resolve-target` 反映 winner | A/B advertise 同一 subnet                  | 查询同一目标 IP                           | 返回最新 advertisement 的 agent 在首位           |
+----+------------------------------------------+--------------------------------------------+------------------------------------------+--------------------------------------------------+
```

### Observability

```text
+----+------------------------------------------+------------------------------+--------------------------------------+----------------------------------------------+
| ID | 观察点                                   | 采集位置                     | 要看什么                             | 用来证明什么                                 |
+----+------------------------------------------+------------------------------+--------------------------------------+----------------------------------------------+
| O1 | peer 识别                                | Gateway 日志                 | 新 endpoint 是否被归属到正确 Agent   | 多 Agent 首包识别是否成立                    |
| O2 | route advertisement 接收                 | Gateway 日志 / /jet/agents   | epoch、subnet_count、advertised_subnets | runtime route 是否真的生效                 |
| O3 | 路由 owner / 显式 agent                  | Gateway 日志                 | selected agent_id                    | 是否只在显式指定时走 agent                    |
| O4 | offline 清理                             | Gateway 日志 / /jet/agents   | agent status 变 offline，routes 消失 | 离线即无路由是否成立                        |
| O5 | reconnect 重通告                         | Agent/Gateway 日志           | reconnect 后重新出现 RouteAdvertise  | re-advertise 是否自动发生                    |
| O6 | 实际流量命中哪个后端                     | HTTP 响应体                  | "Hello from Agent A/B"               | 不是只更新状态，而是真的选到了对的 agent     |
+----+------------------------------------------+------------------------------+--------------------------------------+----------------------------------------------+
```

## Files Created

- `Dockerfile.agent-test`: Agent container with HTTP server
- `test-wireguard.ps1`: Main test setup script
- `test-client.ps1`: Simple test client
- `test-output/`: Generated configs and keys (gitignored)
