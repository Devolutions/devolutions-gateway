#!/bin/sh
# Installs Devolutions Agent, turns on Device Management and enrolls the device with Devolutions Server.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Devolutions/devolutions-gateway/master/package/install/install-agent.sh | sudo DEVOLUTIONS_ENROLLMENT_TOKEN='dvaet1...' sh
#
# Optional environment variables:
#   DEVOLUTIONS_AGENT_INSTALLER_URL     Installs this .deb package instead of the latest published one.
#   DEVOLUTIONS_AGENT_INSTALLER_SHA256  Expected SHA-256 of the package set by DEVOLUTIONS_AGENT_INSTALLER_URL.
#
# Only Debian-based x64 distributions are supported. The script never writes the token.

set -eu

PRODUCT_INFO_URL='https://devolutions.net/productinfo.json'
AGENT_BIN='/usr/bin/devolutions-agent'
CONFIG_DIR='/etc/devolutions-agent'
CONFIG_PATH="$CONFIG_DIR/agent.json"
SERVICE_NAME='devolutions-agent'

fail() {
    unset DEVOLUTIONS_ENROLLMENT_TOKEN
    printf 'Devolutions Agent installation failed: %s\n' "$1" >&2
    exit 1
}

info() {
    printf '%s\n' "$1"
}

download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        fail 'curl or wget is required.'
    fi
}

[ "$(id -u)" -eq 0 ] || fail 'run this script as root, for example with sudo.'

TOKEN="${DEVOLUTIONS_ENROLLMENT_TOKEN:-}"
case "$TOKEN" in
    dvaet1.*) ;;
    *) fail 'set DEVOLUTIONS_ENROLLMENT_TOKEN to the enrollment token from Remote Desktop Manager.' ;;
esac

[ "$(uname -s)" = 'Linux' ] || fail 'only Linux is supported.'

case "$(uname -m)" in
    x86_64 | amd64) ;;
    aarch64 | arm64) fail 'arm64 is not supported yet. Use an x64 device.' ;;
    *) fail "the $(uname -m) architecture is not supported." ;;
esac

if ! command -v dpkg >/dev/null 2>&1; then
    if command -v rpm >/dev/null 2>&1; then
        fail 'RPM-based distributions are not supported yet. Use a Debian-based distribution such as Debian or Ubuntu.'
    fi
    fail 'dpkg is missing. Only Debian-based distributions are supported.'
fi

INSTALLER_URL="${DEVOLUTIONS_AGENT_INSTALLER_URL:-}"
EXPECTED_HASH="${DEVOLUTIONS_AGENT_INSTALLER_SHA256:-}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

if [ -z "$INSTALLER_URL" ]; then
    info 'Reading the latest Devolutions Agent version...'
    download "$PRODUCT_INFO_URL" "$WORK_DIR/productinfo.json"

    # Prints the URL and the hash of the first x64 .deb in Agent.Current, which comes before Agent.Beta.
    FILE_INFO="$(tr '{},' '\n\n\n' < "$WORK_DIR/productinfo.json" | awk '
        /"Agent"[[:space:]]*:/ { agent = 1 }
        agent && /"Url"[[:space:]]*:/ && /devolutions-agent-[^"]*-x64\.deb"/ { url = $0 }
        agent && url != "" && /"Hash"[[:space:]]*:/ { hash = $0; exit }
        END { print url; print hash }
    ' | sed -n 's/.*:[[:space:]]*"\(.*\)".*/\1/p')"
    INSTALLER_URL="$(printf '%s\n' "$FILE_INFO" | sed -n '1p')"
    EXPECTED_HASH="$(printf '%s\n' "$FILE_INFO" | sed -n '2p')"
    [ -n "$INSTALLER_URL" ] || fail 'no Devolutions Agent package is available for Linux x64.'
fi

PACKAGE_PATH="$WORK_DIR/devolutions-agent.deb"
info "Downloading $INSTALLER_URL..."
download "$INSTALLER_URL" "$PACKAGE_PATH"

if [ -n "$EXPECTED_HASH" ]; then
    command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum is required to check the package.'
    ACTUAL_HASH="$(sha256sum "$PACKAGE_PATH" | cut -d ' ' -f 1 | tr 'A-F' 'a-f')"
    EXPECTED_HASH="$(printf '%s' "$EXPECTED_HASH" | tr 'A-F' 'a-f')"
    [ "$ACTUAL_HASH" = "$EXPECTED_HASH" ] || fail 'the SHA-256 hash of the downloaded package is not correct.'
else
    info 'Warning: the package hash is not checked because DEVOLUTIONS_AGENT_INSTALLER_SHA256 is not set.' >&2
fi

info 'Installing Devolutions Agent...'
if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$PACKAGE_PATH" >/dev/null || fail 'apt-get could not install the package.'
else
    dpkg -i "$PACKAGE_PATH" >/dev/null || fail 'dpkg could not install the package.'
fi

[ -x "$AGENT_BIN" ] || fail "$AGENT_BIN is missing after the installation."

mkdir -p "$CONFIG_DIR"
[ -f "$CONFIG_PATH" ] || "$AGENT_BIN" config init >/dev/null

info 'Turning on Device Management...'
if command -v python3 >/dev/null 2>&1; then
    python3 - "$CONFIG_PATH" <<'EOF' || fail "could not update $CONFIG_PATH."
import json, sys
path = sys.argv[1]
try:
    with open(path, encoding="utf-8-sig") as file:
        config = json.load(file)
except FileNotFoundError:
    config = {}
config["DeviceManagement"] = {"Enabled": True}
with open(path, "w", encoding="utf-8") as file:
    json.dump(config, file, indent=2)
    file.write("\n")
EOF
elif [ ! -s "$CONFIG_PATH" ]; then
    printf '{\n  "DeviceManagement": { "Enabled": true }\n}\n' > "$CONFIG_PATH"
elif ! grep -q '"DeviceManagement"' "$CONFIG_PATH"; then
    sed -i '0,/{/s//{\n  "DeviceManagement": { "Enabled": true },/' "$CONFIG_PATH" || fail "could not update $CONFIG_PATH."
else
    fail "python3 is required to update the DeviceManagement section in $CONFIG_PATH."
fi

info 'Enrolling the device...'
if ! printf '%s\n' "$TOKEN" | "$AGENT_BIN" identity enroll - >/dev/null; then
    fail 'the enrollment command failed.'
fi
TOKEN=''
unset TOKEN DEVOLUTIONS_ENROLLMENT_TOKEN

info 'Restarting the Devolutions Agent service...'
if [ -d /run/systemd/system ]; then
    if ! systemctl cat "$SERVICE_NAME" >/dev/null 2>&1; then
        "$AGENT_BIN" create >/dev/null
        systemctl daemon-reload
    fi
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    systemctl restart "$SERVICE_NAME" || fail "could not start the $SERVICE_NAME service."
else
    fail 'systemd is required to run the Devolutions Agent service.'
fi

info 'Devolutions Agent is installed. The device enrolls with Devolutions Server in a few seconds.'
