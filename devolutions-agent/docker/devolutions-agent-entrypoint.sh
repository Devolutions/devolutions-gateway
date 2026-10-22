#!/usr/bin/env bash
set -euo pipefail

mkdir -p "${DAGENT_CONFIG_PATH}"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

if [ -n "${PSU_DEVICE_ROOT_THUMBPRINT:-}" ]; then
    if [ -z "${PSU_SERVER_URL:-}" ] || [ -z "${PSU_DEVICE_STATE_DIRECTORY:-}" ]; then
        echo "PSU device mode requires PSU_SERVER_URL and PSU_DEVICE_STATE_DIRECTORY on a persistent writable volume" >&2
        exit 1
    fi
    if [ -n "${PSU_APP_TOKEN:-}" ]; then
        echo "PSU_APP_TOKEN must not be set in PSU device mode" >&2
        exit 1
    fi
    token_config=''
    if [ -n "${PSU_ENROLLMENT_TOKEN:-}" ]; then
        token_config=", \"EnrollmentToken\": \"$(json_escape "${PSU_ENROLLMENT_TOKEN}")\""
    fi
    hardware_config=''
    if [ -n "${PSU_DEVICE_HARDWARE_ID:-}" ]; then
        hardware_config=", \"HardwareId\": \"$(json_escape "${PSU_DEVICE_HARDWARE_ID}")\""
    fi
    psu_agent_config=$(cat <<EOF
  "PsuAgent": {
    "Enabled": true,
    "ServerUrl": "$(json_escape "${PSU_SERVER_URL}")",
    "DisplayName": "$(json_escape "${PSU_DISPLAY_NAME:-Devolutions Agent Linux}")",
    "DeviceEnrollment": {
      "RootThumbprint": "$(json_escape "${PSU_DEVICE_ROOT_THUMBPRINT}")",
      "StateDirectory": "$(json_escape "${PSU_DEVICE_STATE_DIRECTORY}")"${token_config}${hardware_config}
    },
    "PowerShell": {
      "ExecutablePath": "$(json_escape "${PSU_POWERSHELL_EXECUTABLE:-${POWERSHELL_EXECUTABLE:-pwsh}}")"
    }
  }
EOF
)
elif [ -n "${PSU_ENROLLMENT_TOKEN:-}" ] || [ -n "${PSU_DEVICE_STATE_DIRECTORY:-}" ] || [ -n "${PSU_DEVICE_HARDWARE_ID:-}" ]; then
    echo "PSU device settings require PSU_DEVICE_ROOT_THUMBPRINT" >&2
    exit 1
elif [ -n "${PSU_SERVER_URL:-}" ] && [ -n "${PSU_APP_TOKEN:-}" ]; then
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

umask 077
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
