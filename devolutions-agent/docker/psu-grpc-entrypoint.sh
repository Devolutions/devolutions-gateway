#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${DAGENT_CONFIG_PATH}"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

IFS=',' read -r -a hubs <<< "${PSU_HUBS:-default}"
hubs_json=""
for hub in "${hubs[@]}"; do
    hub="${hub#${hub%%[![:space:]]*}}"
    hub="${hub%${hub##*[![:space:]]}}"
    if [ -z "${hub}" ]; then
        continue
    fi

    if [ -n "${hubs_json}" ]; then
        hubs_json="${hubs_json}, "
    fi
    hubs_json="${hubs_json}\"$(json_escape "${hub}")\""
done

if [ -z "${hubs_json}" ]; then
    hubs_json='"default"'
fi

app_token_property=""
if [ -n "${PSU_APP_TOKEN:-}" ]; then
    app_token_property="    \"AppToken\": \"$(json_escape "${PSU_APP_TOKEN}")\","
fi

cat > "${DAGENT_CONFIG_PATH}/agent.json" <<EOF
{
  "Updater": {
    "Enabled": false
  },
  "Session": {
    "Enabled": false
  },
  "PsuGrpcAgent": {
    "Enabled": true,
    "ServerUrl": "$(json_escape "${PSU_SERVER_URL:-http://host.docker.internal:5006}")",
    "AgentId": "$(json_escape "${PSU_AGENT_ID:-devo-agent-linux}")",
    "DisplayName": "$(json_escape "${PSU_DISPLAY_NAME:-Devolutions Agent Linux}")",
${app_token_property}
    "Hubs": [ ${hubs_json} ],
    "PowerShell": {
      "ExecutablePath": "$(json_escape "${POWERSHELL_EXECUTABLE:-pwsh}")"
    }
  }
}
EOF

exec /opt/devolutions/agent/devolutions-agent run