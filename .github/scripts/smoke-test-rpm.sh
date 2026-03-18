#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# RPM Package Installation Test for Devolutions Gateway
#
# Runs inside a Rocky Linux 9 (RHEL 9-compatible) container to validate:
#   - Package installs correctly via dnf
#   - Expected files and directories are present
#   - Binary is functional (--help, --config-init-only)
#   - Service registration creates the expected systemd unit file
#   - Default configuration file is generated
#
# Environment variables (required):
#   PACKAGE_FILE   Absolute path to the .rpm file inside the container.
#   VERSION        Expected package version (e.g. 2026.1.0).
#   PACKAGE_NAME   Package name (e.g. devolutions-gateway).
#
# LIMITATION — systemd in containers:
#   Docker containers do not normally run systemd. The RPM postinst
#   script (after-install) gates ALL service-related actions on the
#   presence of /run/systemd/system. This means:
#     - Config initialization is skipped.
#     - Service registration is skipped (no unit file is created).
#     - Service enable/start is skipped.
#   This script compensates by running --config-init-only and
#   service register manually.
#
# DIFFERENCE FROM DEB:
#   The .deb package includes the systemd unit file directly (installed
#   by dpkg via dh_installsystemd). The .rpm package does NOT bundle the
#   unit file; instead, the postinst calls `devolutions-gateway service
#   register` to create it at install time. This means that in a container
#   without systemd, the unit file will only exist if we manually run
#   `service register`.
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

# The .rpm package does NOT bundle the unit file; it is created by
# `devolutions-gateway service register` at install time (or manually below).
UNIT_FILE_PATHS=(
    /etc/systemd/system/devolutions-gateway.service
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
    UNIT_FILES=$(find /lib/systemd /usr/lib/systemd /etc/systemd -name '*devolutions*' 2>/dev/null)
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
if dnf install -y -q file python3 > "$PREREQ_LOG" 2>&1; then
    rm -f "$PREREQ_LOG"
else
    echo "Prerequisites installation output:"
    cat "$PREREQ_LOG"
    rm -f "$PREREQ_LOG"
    fail "Prerequisites installation failed (file, python3)"
    diagnostics
    summary
fi

info "Installing package: $(basename "$PACKAGE_FILE")"
# Use dnf to resolve and satisfy dependencies automatically.
# The package declares a glibc dependency; Rocky Linux 9 provides glibc 2.34+.
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

# ── Binary functionality ──────────────────────────────────────────────────────

info "Checking binary functionality…"
check_binary_help

# ── Config initialization ─────────────────────────────────────────────────────
# RPM postinst runs --config-init-only only when systemd is present.
# In a container without systemd we run it manually.

info "Checking config initialization…"
check_config_init

# ── Service registration ──────────────────────────────────────────────────────
# The RPM does NOT bundle the systemd unit file. The postinst calls
# `devolutions-gateway service register` to create it. In containers
# without systemd, the postinst skips this, so we try it manually.

info "Checking service registration…"
info "Running service registration manually…"
SERVICE_REG_OUTPUT=$("$BINARY" service register 2>&1) && SERVICE_REG_RC=$? || SERVICE_REG_RC=$?
if [ "$SERVICE_REG_RC" -eq 0 ]; then
    pass "Service registration command succeeded"
else
    warn "Service registration returned exit code $SERVICE_REG_RC (may require systemd)."
    info "Output: $SERVICE_REG_OUTPUT"
fi

# ── systemd unit file ─────────────────────────────────────────────────────────
# Unit file is only present if service register succeeded above;
# absence is a warning rather than a hard failure.

info "Checking systemd unit file…"
check_unit_file "warn"

# ── Service startup (best-effort) ─────────────────────────────────────────────

check_service_startup

# ── Final output ──────────────────────────────────────────────────────────────

diagnostics
summary
