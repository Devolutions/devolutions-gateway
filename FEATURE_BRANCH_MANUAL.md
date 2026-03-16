# WireGuard Agent Tunneling — Feature Branch Manual

Branch: `fix/wireguard-agent-routing-hardening`

This guide walks you through setting up a WireGuard agent on your home lab so you can remotely SSH (or RDP/VNC) into internal machines through a deployed Devolutions Gateway instance.

## Architecture

```
Your browser (anywhere)
  → HTTPS → Gateway (public, deployed on Coolify)
      → WireGuard UDP tunnel → Agent (your home lab)
          → TCP → Target SSH server (192.168.1.x:22)
```

## Prerequisites

- A Linux machine in your home lab (Ubuntu/Debian recommended)
- That machine can reach the internet (to connect to the Gateway)
- That machine can reach other machines on your home lab network via SSH/RDP/etc.
- Gateway URL and login credentials (ask Irving)

## Step 1: Compile the Agent

On your home lab Linux machine:

```bash
# Install Rust (skip if already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Clone and checkout the branch
git clone https://github.com/Devolutions/devolutions-gateway.git
cd devolutions-gateway
git checkout fix/wireguard-agent-routing-hardening

# Build in release mode
cargo build --release -p devolutions-gateway-agent

# Binary is at: target/release/devolutions-gateway-agent
```

## Step 2: Generate an Enrollment Command

1. Open the Gateway URL in your browser
2. Log in with the credentials you were given
3. Go to the **Agent Enrollment** page
4. **API Base URL** and **WireGuard Host** are auto-populated with the Gateway domain
5. Give your agent a name (e.g. `home-lab-agent`)
6. Click **Generate Quick Start Command**
7. Copy the enrollment string (starts with `dgw-enroll:v1:...`)

## Step 3: Enroll the Agent

```bash
cd target/release

# Paste your enrollment string and set your home lab subnet
./devolutions-gateway-agent enroll \
  --enrollment-string "<ENROLLMENT_STRING>" \
  --config agent-config.toml \
  --advertise-subnet 192.168.1.0/24
```

Replace `192.168.1.0/24` with your actual home lab network range. If you have multiple subnets, repeat the flag:

```bash
./devolutions-gateway-agent enroll \
  --enrollment-string "<ENROLLMENT_STRING>" \
  --config agent-config.toml \
  --advertise-subnet 192.168.1.0/24 \
  --advertise-subnet 10.0.0.0/8
```

This writes `agent-config.toml` with all WireGuard credentials.

## Step 4: Start the Agent

```bash
# Foreground (useful for debugging)
./devolutions-gateway-agent run --config agent-config.toml

# Or background
nohup ./devolutions-gateway-agent run --config agent-config.toml &> agent.log &
```

Once running, your agent should appear as **online** in the Gateway UI agent list.

## Step 5: Connect via SSH

1. Go back to the Gateway web UI
2. Create a new SSH session targeting a home lab **internal IP** (e.g. `192.168.1.100:22`)
3. The Gateway routes traffic through the WireGuard tunnel → your agent → target machine
4. Enter SSH username and password — you're in

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Agent shows offline | Check agent process is running. Check UDP 51820 is open on Gateway. |
| Enrollment fails | Make sure the enrollment string hasn't expired. Generate a new one. |
| SSH connection refused | Verify `--advertise-subnet` covers the target IP. Verify the target machine has SSH enabled. |
| Agent can't reach Gateway | Check that your home lab machine can reach the Gateway's public IP on UDP port 51820. |

## Debug Logging

```bash
RUST_LOG=debug ./devolutions-gateway-agent run --config agent-config.toml
```

## Notes

- The agent must stay running. If it disconnects, just `run` again — no re-enrollment needed.
- The `--advertise-subnet` flag tells the Gateway which IPs this agent can reach. Traffic to IPs outside your advertised subnets won't be routed to your agent.
- The enrollment token is single-use. If you need to re-enroll, generate a new one from the UI.
