#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# RPM Package Installation Test for Devolutions Gateway
#
# Runs inside a Rocky Linux (RHEL-compatible) container to validate:
#   - Package installs correctly via dnf
#   - Expected files and directories are present
#   - Binary is functional (--help, --config-init-only)
#   - systemd unit file is installed (part of the .rpm package)
#   - Default configuration file is generated
#   - Config directory has secure permissions
#   - Service starts, responds to health check, and stops cleanly
#   - Package uninstall removes files but preserves config
#
# Environment variables (required):
#   PACKAGE_FILE   Absolute path to the .rpm file inside the container.
#   VERSION        Expected package version (e.g. 2026.1.0).
#   PACKAGE_NAME   Package name (e.g. devolutions-gateway).
#
# LIMITATION — systemd in containers:
#   Docker containers do not normally run systemd. The RPM postinst
#   gates service enable/start on /run/systemd/system. When systemd is
#   not detected, the service is started directly for the health check.
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Validate environment ──────────────────────────────────────────────────────

: "${PACKAGE_FILE:?PACKAGE_FILE must be set}"
: "${VERSION:?VERSION must be set}"
: "${PACKAGE_NAME:?PACKAGE_NAME must be set}"

# ── Constants ─────────────────────────────────────────────────────────────────

BINARY=/usr/bin/devolutions-gateway
LIB_DIR=/usr/lib/devolutions-gateway
LIB_PATH=$LIB_DIR/libxmf.so
WEBAPP_DIR=/usr/share/devolutions-gateway/webapp
CONFIG_DIR=/etc/devolutions-gateway
CONFIG_FILE=$CONFIG_DIR/gateway.json

# The .rpm package bundles the unit file directly (installed by fpm/rpm).
UNIT_FILE_PATHS=(
    /usr/lib/systemd/system/devolutions-gateway.service
    /lib/systemd/system/devolutions-gateway.service
)

# The library is in a non-standard path; cover the LD_LIBRARY_PATH lookup
# case in addition to RPATH or env-var-based resolution the binary may use.
export LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# ── Source shared library ─────────────────────────────────────────────────────

# shellcheck source=smoke-test-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/smoke-test-lib.sh"

# ── Diagnostics (rpm-specific) ────────────────────────────────────────────────

diagnostics() {
    echo ""
    echo "── Diagnostics ──────────────────────────────────────────────"
    echo ""
    echo "Package metadata:"
    rpm -qip "$PACKAGE_FILE" 2>/dev/null || echo "  (rpm query failed)"
    echo ""
    echo "Package file list:"
    rpm -qlp "$PACKAGE_FILE" 2>/dev/null || echo "  (rpm query failed)"
    echo ""
    echo "Config directory:"
    ls -la "$CONFIG_DIR/" 2>/dev/null || echo "  (not found)"
    echo "────────────────────────────────────────────────────────────"
}

# ── Main ══════════════════════════════════════════════════════════════════════

echo "════════════════════════════════════════════════════════════════"
echo "  RPM Package Installation Test"
echo "  Package: $(basename "$PACKAGE_FILE")"
echo "  Version: $VERSION"
echo "  Container: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo unknown)"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ── Install ───────────────────────────────────────────────────────────────────

info "Installing prerequisites…"
PREREQ_LOG=$(mktemp)
if dnf install -y -q file python3 openssl > "$PREREQ_LOG" 2>&1; then
    rm -f "$PREREQ_LOG"
else
    echo "Prerequisites installation output:"
    cat "$PREREQ_LOG"
    rm -f "$PREREQ_LOG"
    fail "Prerequisites installation failed (file, python3, openssl)"
    diagnostics
    summary
fi
# Rocky Linux ships curl-minimal which conflicts with the full curl package.
# Verify the binary is available (provided by curl-minimal) rather than
# installing curl explicitly.
if ! command -v curl >/dev/null 2>&1; then
    fail "curl binary not found; expected curl-minimal to be present on Rocky Linux"
    summary
fi

info "Installing package: $(basename "$PACKAGE_FILE")"
# Use dnf to resolve and satisfy dependencies automatically.
# The package declares a glibc dependency; Rocky Linux provides glibc 2.28+.
INSTALL_LOG=$(mktemp)
if dnf install -y "$PACKAGE_FILE" > "$INSTALL_LOG" 2>&1; then
    pass "Package installation succeeded"
else
    echo "Installation output:"
    cat "$INSTALL_LOG"
    fail "Package installation failed"
    diagnostics
    summary
fi
rm -f "$INSTALL_LOG"

# ── Package metadata ──────────────────────────────────────────────────────────

info "Checking package metadata…"
INSTALLED_VERSION=$(rpm -qi "$PACKAGE_NAME" 2>/dev/null | grep '^Version' | awk -F: '{print $2}' | tr -d ' ')
if echo "$INSTALLED_VERSION" | grep -q "$VERSION"; then
    pass "Installed version ($INSTALLED_VERSION) contains expected version ($VERSION)"
else
    fail "Version mismatch: installed=$INSTALLED_VERSION expected contains=$VERSION"
fi

# ── File existence ────────────────────────────────────────────────────────────

info "Checking expected files and directories…"
check_binary_executable
check_native_library
check_webapp
check_config_dir

# ── Config directory permissions ──────────────────────────────────────────────

info "Checking config directory permissions…"
check_config_dir_permissions

# ── Binary functionality ──────────────────────────────────────────────────────

info "Checking binary functionality…"
check_binary_help

# ── Config initialization ─────────────────────────────────────────────────────
# The postinst always runs --config-init-only regardless of systemd presence.

info "Checking config initialization…"
check_config_init

# ── Config file permissions ───────────────────────────────────────────────────

info "Checking config file permissions…"
check_config_file_permissions

# ── systemd unit file ─────────────────────────────────────────────────────────
# The .rpm package bundles the unit file directly, so it must be present
# after installation regardless of whether systemd is running.

info "Checking systemd unit file…"
check_unit_file "fail"

# ── Single ExecStart directive ────────────────────────────────────────────────
# Regression guard: two ExecStart= lines make systemd refuse to start the service.

info "Checking service file has exactly one ExecStart directive…"
check_single_execstart

# ── Preset file ───────────────────────────────────────────────────────────────
# The .rpm package bundles a preset file so systemctl preset enables the service.

info "Checking systemd preset file…"
PRESET_FILE=/usr/lib/systemd/system-preset/85-devolutions-gateway.preset
if [ -f "$PRESET_FILE" ]; then
    pass "Preset file exists: $PRESET_FILE"
    if grep -q 'enable devolutions-gateway.service' "$PRESET_FILE"; then
        pass "Preset file enables devolutions-gateway.service"
    else
        fail "Preset file does not contain 'enable devolutions-gateway.service': $PRESET_FILE"
    fi
else
    fail "Preset file not found: $PRESET_FILE"
fi

# ── Service enabled via systemd ───────────────────────────────────────────────
# Verify that systemctl preset (run by postinst) actually enabled the service.

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    info "Checking service is enabled via systemd…"
    ENABLED_STATUS=$(systemctl is-enabled devolutions-gateway 2>/dev/null || echo "disabled")
    if [ "$ENABLED_STATUS" = "enabled" ]; then
        pass "Service is enabled after install: $ENABLED_STATUS"
    else
        fail "Service is not enabled after install ($ENABLED_STATUS, expected 'enabled')"
    fi
fi

# ── Provisioner key ───────────────────────────────────────────────────────────
# The gateway requires a provisioner public key to start.
# Generate a key pair and place the public key where gateway.json points.

info "Generating provisioner key…"
check_provisioner_key

# ── Service health ────────────────────────────────────────────────────────────

info "Checking service health…"
check_service_health

# ── Uninstall ─────────────────────────────────────────────────────────────────

info "Checking package uninstall…"
REMOVE_LOG=$(mktemp)
if dnf remove -y "$PACKAGE_NAME" >"$REMOVE_LOG" 2>&1; then
    pass "Package removal succeeded"
else
    echo "Removal output:"
    cat "$REMOVE_LOG"
    fail "Package removal failed"
fi
rm -f "$REMOVE_LOG"
check_post_uninstall

# ── Final output ──────────────────────────────────────────────────────────────

diagnostics
summary
