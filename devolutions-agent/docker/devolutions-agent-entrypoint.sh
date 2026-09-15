#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${DAGENT_CONFIG_PATH}"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

if [ -n "${PSU_SERVER_URL:-}" ] && [ -n "${PSU_APP_TOKEN:-}" ]; then
    psu_agent_config=$(cat <<EOF
  "PsuAgent": {
    "Enabled": true,
    "ServerUrl": "$(json_escape "${PSU_SERVER_URL}")",
    "AgentId": "$(json_escape "${PSU_AGENT_ID:-devo-agent-linux}")",
    "DisplayName": "$(json_escape "${PSU_DISPLAY_NAME:-Devolutions Agent Linux}")",
    "AppToken": "$(json_escape "${PSU_APP_TOKEN}")",
    "PowerShell": {
      "ExecutablePath": "$(json_escape "${PSU_POWERSHELL_EXECUTABLE:-${POWERSHELL_EXECUTABLE:-pwsh}}")"
    }
  }
EOF
)
elif [ -n "${PSU_SERVER_URL:-}" ] || [ -n "${PSU_APP_TOKEN:-}" ]; then
    echo "PSU_SERVER_URL and PSU_APP_TOKEN must both be set to enable the PSU agent" >&2
    exit 1
else
    psu_agent_config='  "PsuAgent": { "Enabled": false }'
fi

cat > "${DAGENT_CONFIG_PATH}/agent.json" <<EOF
{
  "Updater": {
    "Enabled": false
  },
  "Session": {
    "Enabled": false
  },
${psu_agent_config}
}
EOF

exec /opt/devolutions/agent/devolutions-agent run
