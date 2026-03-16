#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────────
# DEB Package Installation Test for Devolutions Gateway
#
# Runs inside an Ubuntu container to validate:
#   - Package installs correctly via dpkg/apt
#   - Expected files and directories are present
#   - Binary is functional (--help, --config-init-only)
#   - systemd unit file is installed (part of the .deb package)
#   - Default configuration file is generated
#
# LIMITATION — systemd in containers:
#   Docker containers do not normally run systemd, so the postinst script
#   skips config initialization and service enablement (both gated on
#   /run/systemd/system). This script compensates by running
#   --config-init-only manually. Full service start/stop validation is
#   best-effort and only attempted when systemd is detected.
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ── Test bookkeeping ─────────────────────────────────────────────────────────

TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    echo "✅ PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo "❌ FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

info() {
    echo "ℹ️  $1"
}

warn() {
    echo "⚠️  WARN: $1"
}

diagnostics() {
    echo ""
    echo "── Diagnostics ──────────────────────────────────────────────"
    echo ""
    echo "Package metadata:"
    dpkg -s "$PACKAGE_NAME" 2>/dev/null || echo "  (not installed)"
    echo ""
    echo "Package file list:"
    dpkg -L "$PACKAGE_NAME" 2>/dev/null || echo "  (not installed)"
    echo ""
    echo "Config directory:"
    ls -la /etc/devolutions-gateway/ 2>/dev/null || echo "  (not found)"
    echo ""
    echo "Binary info:"
    ls -la /usr/bin/devolutions-gateway 2>/dev/null || echo "  (not found)"
    file /usr/bin/devolutions-gateway 2>/dev/null || true
    echo ""
    echo "Webapp directory:"
    ls -laR /usr/share/devolutions-gateway/webapp/ 2>/dev/null | head -40 || echo "  (not found)"
    echo ""
    echo "Library directory:"
    ls -la /usr/lib/devolutions-gateway/ 2>/dev/null || echo "  (not found)"
    echo ""
    echo "systemd unit files:"
    find /lib/systemd /usr/lib/systemd /etc/systemd -name '*devolutions*' 2>/dev/null || echo "  (none found)"
    echo "────────────────────────────────────────────────────────────"
}

summary() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Test Summary: $TESTS_PASSED passed, $TESTS_FAILED failed"
    echo "════════════════════════════════════════════════════════════════"
    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi
}

# ── Validate environment ─────────────────────────────────────────────────────

: "${PACKAGE_FILE:?PACKAGE_FILE must be set}"
: "${VERSION:?VERSION must be set}"
: "${PACKAGE_NAME:?PACKAGE_NAME must be set}"

echo "════════════════════════════════════════════════════════════════"
echo "  DEB Package Installation Test"
echo "  Package: $(basename "$PACKAGE_FILE")"
echo "  Version: $VERSION"
echo "  Container: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')"
echo "════════════════════════════════════════════════════════════════"
echo ""

# ── Install the package ──────────────────────────────────────────────────────

info "Updating apt and installing prerequisites…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq file > /dev/null 2>&1

info "Installing package: $(basename "$PACKAGE_FILE")"

# Use apt-get install with the .deb path; this resolves dependencies
# automatically. Show output only on failure.
INSTALL_LOG=$(mktemp)
if apt-get install -y "$PACKAGE_FILE" > "$INSTALL_LOG" 2>&1; then
    pass "Package installation succeeded"
else
    echo "Installation output:"
    cat "$INSTALL_LOG"
    fail "Package installation failed"
    diagnostics
    summary
fi
rm -f "$INSTALL_LOG"

# ── Package metadata ─────────────────────────────────────────────────────────

info "Checking package metadata…"

if dpkg -s "$PACKAGE_NAME" > /dev/null 2>&1; then
    pass "Package is registered in dpkg database"
else
    fail "Package not found in dpkg database"
fi

INSTALLED_VERSION=$(dpkg -s "$PACKAGE_NAME" 2>/dev/null | grep '^Version:' | awk '{print $2}')
if echo "$INSTALLED_VERSION" | grep -q "$VERSION"; then
    pass "Installed version ($INSTALLED_VERSION) contains expected version ($VERSION)"
else
    fail "Version mismatch: installed=$INSTALLED_VERSION expected contains=$VERSION"
fi

# ── File existence checks ────────────────────────────────────────────────────

info "Checking expected files and directories…"

# Main binary.
if [ -x /usr/bin/devolutions-gateway ]; then
    pass "Main binary exists and is executable: /usr/bin/devolutions-gateway"
else
    fail "Main binary missing or not executable: /usr/bin/devolutions-gateway"
fi

# Native library.
if [ -f /usr/lib/devolutions-gateway/libxmf.so ]; then
    pass "Native library exists: /usr/lib/devolutions-gateway/libxmf.so"
else
    fail "Native library missing: /usr/lib/devolutions-gateway/libxmf.so"
fi

# Webapp directory.
if [ -d /usr/share/devolutions-gateway/webapp ]; then
    pass "Webapp directory exists: /usr/share/devolutions-gateway/webapp/"
else
    fail "Webapp directory missing: /usr/share/devolutions-gateway/webapp/"
fi

# Webapp client — expect at least an index.html.
if find /usr/share/devolutions-gateway/webapp/client -name 'index.html' 2>/dev/null | grep -q .; then
    pass "Webapp client contains index.html"
else
    fail "Webapp client missing index.html"
fi

# Config directory (the postinst creates this unconditionally).
if [ -d /etc/devolutions-gateway ]; then
    pass "Config directory exists: /etc/devolutions-gateway/"
else
    fail "Config directory missing: /etc/devolutions-gateway/"
fi

# ── systemd unit file ────────────────────────────────────────────────────────
# The .deb package installs the unit file via dh_installsystemd,
# so it should be present regardless of whether systemd is running.

info "Checking systemd unit file…"

UNIT_FILE=""
for path in \
    /lib/systemd/system/devolutions-gateway.service \
    /usr/lib/systemd/system/devolutions-gateway.service; do
    if [ -f "$path" ]; then
        UNIT_FILE="$path"
        break
    fi
done

if [ -n "$UNIT_FILE" ]; then
    pass "systemd unit file installed: $UNIT_FILE"

    if grep -q '/usr/bin/devolutions-gateway' "$UNIT_FILE"; then
        pass "Unit file references correct binary path"
    else
        fail "Unit file does not reference /usr/bin/devolutions-gateway"
    fi
else
    fail "systemd unit file not found in expected locations"
fi

# ── Binary functionality ─────────────────────────────────────────────────────

info "Checking binary functionality…"

HELP_OUTPUT=$(/usr/bin/devolutions-gateway --help 2>&1) && HELP_RC=$? || HELP_RC=$?
if [ "$HELP_RC" -eq 0 ] || echo "$HELP_OUTPUT" | grep -qi 'gateway\|usage\|help'; then
    pass "Binary responds to --help"
else
    fail "Binary does not respond to --help (exit code: $HELP_RC)"
fi

# ── Config initialization ────────────────────────────────────────────────────
# The postinst runs --config-init-only only when systemd is present.
# In a container without systemd we run it manually.

info "Checking config initialization…"

if [ ! -f /etc/devolutions-gateway/gateway.json ]; then
    info "Config file not generated by postinst (expected without systemd)."
    info "Running config initialization manually…"

    if /usr/bin/devolutions-gateway --config-init-only > /dev/null 2>&1; then
        pass "Config initialization command succeeded"
    else
        fail "Config initialization command failed"
    fi
fi

if [ -f /etc/devolutions-gateway/gateway.json ]; then
    pass "Default config file exists: /etc/devolutions-gateway/gateway.json"
else
    fail "Default config file missing after initialization: /etc/devolutions-gateway/gateway.json"
fi

# ── Package file list completeness ───────────────────────────────────────────

info "Checking package file list completeness…"

FILE_COUNT=$(dpkg -L "$PACKAGE_NAME" | wc -l)
if [ "$FILE_COUNT" -gt 5 ]; then
    pass "Package file list contains $FILE_COUNT entries"
else
    fail "Package file list suspiciously small ($FILE_COUNT entries)"
fi

# ── Best-effort: service startup ─────────────────────────────────────────────

info "[Best-effort] Checking service startup…"
warn "systemd service startup testing is best-effort in containers."
warn "Full service validation requires a real systemd environment."

if [ -d /run/systemd/system ]; then
    info "systemd detected; attempting service start…"
    if systemctl start devolutions-gateway 2>&1; then
        pass "[Best-effort] Service started successfully"
        systemctl status devolutions-gateway 2>&1 || true
    else
        warn "Service start failed (expected in some container environments)."
    fi
else
    info "No systemd detected; skipping service startup test."
fi

# ── Final output ─────────────────────────────────────────────────────────────

diagnostics
summary
