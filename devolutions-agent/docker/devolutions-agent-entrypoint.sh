#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${DAGENT_CONFIG_PATH}"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

if [ -n "${PSU_SERVER_URL:-}" ] && [ -n "${PSU_APP_TOKEN:-}" ]; then
    IFS=',' read -r -a hubs <<< "${PSU_HUBS:-}"
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

    psu_agent_config=$(cat <<EOF
  "PsuAgent": {
    "Enabled": true,
    "ServerUrl": "$(json_escape "${PSU_SERVER_URL}")",
    "AgentId": "$(json_escape "${PSU_AGENT_ID:-devo-agent-linux}")",
    "DisplayName": "$(json_escape "${PSU_DISPLAY_NAME:-Devolutions Agent Linux}")",
    "AppToken": "$(json_escape "${PSU_APP_TOKEN}")",
    "Hubs": [ ${hubs_json} ],
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
