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
    rpm -qi "$PACKAGE_NAME" 2>/dev/null || echo "  (not installed)"
    echo ""
    echo "Package file list:"
    rpm -ql "$PACKAGE_NAME" 2>/dev/null || echo "  (not installed)"
    echo ""
    echo "Config directory:"
    ls -la "$CONFIG_DIR/" 2>/dev/null || echo "  (not found)"
    echo ""
    echo "Binary info:"
    ls -la "$BINARY" 2>/dev/null || echo "  (not found)"
    file "$BINARY" 2>/dev/null || true
    echo ""
    echo "Dynamic library dependencies (ldd):"
    ldd "$BINARY" 2>/dev/null || echo "  (ldd failed or binary not found)"
    echo ""
    echo "Webapp directory:"
    ls -laR "$WEBAPP_DIR/" 2>/dev/null | head -40 || echo "  (not found)"
    echo ""
    echo "Library directory:"
    ls -la "$LIB_DIR/" 2>/dev/null || echo "  (not found)"
    echo ""
    echo "systemd unit files:"
    UNIT_FILES=$(find /lib/systemd /usr/lib/systemd /etc/systemd -name '*devolutions*' 2>/dev/null || true)
    if [ -n "$UNIT_FILES" ]; then echo "$UNIT_FILES"; else echo "  (none found)"; fi
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

# ── systemd unit file ─────────────────────────────────────────────────────────
# The .rpm package bundles the unit file directly, so it must be present
# after installation regardless of whether systemd is running.

info "Checking systemd unit file…"
check_unit_file "fail"

# ── Single ExecStart directive ────────────────────────────────────────────────
# Regression guard: two ExecStart= lines make systemd refuse to start the service.

info "Checking service file has exactly one ExecStart directive…"
check_single_execstart

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
