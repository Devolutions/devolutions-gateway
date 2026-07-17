#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${DAGENT_CONFIG_PATH}"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

if [ -z "${PSU_APP_TOKEN:-}" ]; then
    echo "PSU_APP_TOKEN is required" >&2
    exit 1
fi
app_token_property="    \"AppToken\": \"$(json_escape "${PSU_APP_TOKEN}")\","

cat > "${DAGENT_CONFIG_PATH}/agent.json" <<EOF
{
  "Updater": {
    "Enabled": false
  },
  "Session": {
    "Enabled": false
  },
  "PsuAgent": {
    "Enabled": true,
    "ServerUrl": "$(json_escape "${PSU_SERVER_URL:-http://host.docker.internal:5006}")",
    "AgentId": "$(json_escape "${PSU_AGENT_ID:-devo-agent-linux}")",
    "DisplayName": "$(json_escape "${PSU_DISPLAY_NAME:-Devolutions Agent Linux}")",
${app_token_property}
    "PowerShell": {
      "ExecutablePath": "$(json_escape "${POWERSHELL_EXECUTABLE:-pwsh}")"
    }
  }
}
EOF

exec /opt/devolutions/agent/devolutions-agent run