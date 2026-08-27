#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Shared library for Devolutions Gateway Linux packaging smoke tests.
# Sourced by smoke-test-deb.sh and smoke-test-rpm.sh.
#
# Expects the following constants to be defined in the sourcing script
# before any check function is called:
#   BINARY          Path to the gateway binary.
#   LIB_DIR         Directory containing native libraries.
#   LIB_PATH        Path to libxmf.so.
#   WEBAPP_DIR      Path to the webapp root directory.
#   CONFIG_DIR      Path to the config directory.
#   CONFIG_FILE     Path to gateway.json.
#   UNIT_FILE_PATHS Array of candidate systemd unit file paths (in priority order).
# ──────────────────────────────────────────────────────────────────────────────

# ── Test bookkeeping ──────────────────────────────────────────────────────────

TESTS_PASSED=0
TESTS_FAILED=0

pass() { echo "✅ PASS: $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo "❌ FAIL: $1" >&2; TESTS_FAILED=$((TESTS_FAILED + 1)); }
info() { echo "ℹ️  $1"; }
warn() { echo "⚠️  WARN: $1"; }

# ── Summary ───────────────────────────────────────────────────────────────────

summary() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  Test Summary: $TESTS_PASSED passed, $TESTS_FAILED failed"
    echo "════════════════════════════════════════════════════════════════"
    if [ "$TESTS_FAILED" -gt 0 ]; then
        exit 1
    fi
}

# ── Helpers ───────────────────────────────────────────────────────────────────

# Returns 0 if systemd is running AND the unit file is installed on disk.
systemd_and_unit_available() {
    [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 || return 1
    for path in "${UNIT_FILE_PATHS[@]}"; do
        [ -f "$path" ] && return 0
    done
    return 1
}

# ── Check functions ───────────────────────────────────────────────────────────

check_binary_executable() {
    if [ -x "$BINARY" ]; then
        pass "Main binary exists and is executable: $BINARY"
    else
        fail "Main binary missing or not executable: $BINARY"
    fi
}

check_native_library() {
    if [ -f "$LIB_PATH" ] && file "$LIB_PATH" 2>/dev/null | grep -q 'ELF'; then
        pass "Native library exists and is a valid ELF: $LIB_PATH"
    else
        fail "Native library missing or not a valid ELF: $LIB_PATH"
    fi
}

check_webapp() {
    if [ -d "$WEBAPP_DIR" ]; then
        pass "Webapp directory exists: $WEBAPP_DIR"
    else
        fail "Webapp directory missing: $WEBAPP_DIR"
    fi
    for app in client player; do
        if [ -f "$WEBAPP_DIR/$app/index.html" ]; then
            pass "Webapp $app entry point exists: $WEBAPP_DIR/$app/index.html"
        else
            fail "Webapp $app entry point missing: $WEBAPP_DIR/$app/index.html"
        fi
    done
}

check_config_dir() {
    if [ -d "$CONFIG_DIR" ]; then
        pass "Config directory exists: $CONFIG_DIR"
    else
        fail "Config directory missing: $CONFIG_DIR"
    fi
}

check_config_dir_permissions() {
    local perms
    perms=$(stat -c '%a' "$CONFIG_DIR" 2>/dev/null)
    if [ "$perms" = "750" ]; then
        pass "Config directory has secure permissions ($perms): $CONFIG_DIR"
    else
        fail "Config directory has insecure permissions ($perms, expected 750): $CONFIG_DIR"
    fi
}

check_binary_help() {
    HELP_OUTPUT=$("$BINARY" --help 2>&1) && HELP_RC=$? || HELP_RC=$?
    if [ "$HELP_RC" -eq 0 ] || echo "$HELP_OUTPUT" | grep -qi 'gateway\|usage\|help'; then
        pass "Binary responds to --help"
    else
        fail "Binary does not respond to --help (exit code: $HELP_RC)"
    fi
}

check_config_init() {
    if [ -f "$CONFIG_FILE" ]; then
        pass "Default config file exists: $CONFIG_FILE"
        if python3 -c "import json; json.load(open('$CONFIG_FILE'))" 2>/dev/null; then
            pass "$(basename "$CONFIG_FILE") is valid JSON"
        else
            fail "$(basename "$CONFIG_FILE") exists but is not valid JSON"
        fi
    else
        fail "Default config file missing after installation: $CONFIG_FILE"
    fi
}

# Usage: check_unit_file <fail|warn>
# Searches UNIT_FILE_PATHS in order; on absence, either fails or warns.
check_unit_file() {
    local on_absent="$1"
    local unit_file=""
    for path in "${UNIT_FILE_PATHS[@]}"; do
        if [ -f "$path" ]; then
            unit_file="$path"
            break
        fi
    done

    if [ -n "$unit_file" ]; then
        pass "systemd unit file exists: $unit_file"
        if grep -q "$BINARY" "$unit_file"; then
            pass "Unit file references correct binary path"
        else
            fail "Unit file does not reference $BINARY"
        fi
    elif [ "$on_absent" = "fail" ]; then
        fail "systemd unit file not found"
    else
        warn "systemd unit file not found after registration attempt."
        info "This is expected in container environments without systemd."
    fi
}

check_single_execstart() {
    local unit_file="" count
    for path in "${UNIT_FILE_PATHS[@]}"; do
        if [ -f "$path" ]; then
            unit_file="$path"
            break
        fi
    done
    if [ -z "$unit_file" ]; then
        warn "Skipping ExecStart check: no unit file found (check_unit_file already reported this)."
        return
    fi
    # Match only non-empty ExecStart= lines; bare 'ExecStart=' is a reset directive.
    count=$(grep -c '^ExecStart=[^[:space:]]' "$unit_file" 2>/dev/null || true)
    if [ "$count" -eq 1 ]; then
        pass "Service file has exactly one ExecStart directive"
    else
        fail "Service file has $count ExecStart directives (expected exactly 1)"
    fi
}

check_config_file_permissions() {
    if [ ! -f "$CONFIG_FILE" ]; then
        fail "Config file not found, cannot check permissions: $CONFIG_FILE"
        return
    fi
    local perms
    perms=$(stat -c '%a' "$CONFIG_FILE" 2>/dev/null)
    if [ "$perms" = "600" ]; then
        pass "Config file has secure permissions ($perms): $CONFIG_FILE"
    else
        fail "Config file has insecure permissions ($perms, expected 600): $CONFIG_FILE"
    fi
}

check_service_not_auto_started() {
    if ! systemd_and_unit_available; then
        info "systemd not available — skipping auto-start check"
        return
    fi
    # The service requires a provisioner key to start. Since the key is not
    # present immediately after install, auto-starting the service would cause
    # it to fail immediately. The postinst is therefore expected to only enable
    # the service, not start it. A status of "active" or "failed" both indicate
    # the postinst incorrectly attempted to start the service.
    local status
    status=$(systemctl is-active devolutions-gateway 2>/dev/null || true)
    case "$status" in
        inactive)
            pass "Service is inactive after install (not auto-started)" ;;
        active|failed|activating)
            fail "Service was auto-started after install ($status) — postinst should only enable, not start" ;;
        *)
            warn "Unexpected service state after install: $status" ;;
    esac
}

check_provisioner_key() {
    info "Generating RSA-2048 provisioner key pair with openssl…"
    KEY_LOG=$(mktemp)
    if openssl genrsa -out "$CONFIG_DIR/provisioner.key" 2048 >"$KEY_LOG" 2>&1 \
        && openssl rsa -in "$CONFIG_DIR/provisioner.key" \
               -pubout -out "$CONFIG_DIR/provisioner.pem" >>"$KEY_LOG" 2>&1; then
        chmod 600 "$CONFIG_DIR/provisioner.key"
        pass "Provisioner key pair generated: $CONFIG_DIR/provisioner.pem"
    else
        echo "openssl output:"
        cat "$KEY_LOG"
        fail "Failed to generate provisioner key pair"
    fi
    rm -f "$KEY_LOG"
}

check_service_health() {
    local health_url="http://localhost:7171/jet/health"
    local gateway_pid=""
    local gateway_log=""

    if systemd_and_unit_available; then
        info "systemd available — using systemctl start/stop"
        if ! systemctl start devolutions-gateway >/dev/null 2>&1; then
            fail "systemctl start devolutions-gateway failed"
            echo "Service logs:"
            journalctl -u devolutions-gateway --no-pager -n 50 2>/dev/null || true
            return
        fi
    else
        info "systemd not available — starting binary directly"
        gateway_log=$(mktemp)
        "$BINARY" 2>"$gateway_log" &
        gateway_pid=$!
    fi

    # Wait for the service to be ready (up to 10 s).
    local i=0
    while [ "$i" -lt 10 ]; do
        curl -sf -H 'Accept: application/json' "$health_url" >/dev/null 2>&1 && break
        sleep 1
        i=$((i + 1))
    done

    local health_output health_rc
    health_output=$(curl -sf -H 'Accept: application/json' "$health_url" 2>/dev/null) && health_rc=$? || health_rc=$?

    # Stop the service.
    if systemd_and_unit_available; then
        systemctl stop devolutions-gateway >/dev/null 2>&1 || true
    elif [ -n "$gateway_pid" ]; then
        kill "$gateway_pid" 2>/dev/null || true
        wait "$gateway_pid" 2>/dev/null || true
    fi

    if [ "$health_rc" -eq 0 ]; then
        pass "Health endpoint responded: $health_output"
        # Verify the version field in the health response matches expected.
        local health_version
        health_version=$(python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('version',''))" <<< "$health_output" 2>/dev/null) || health_version=""
        if [ -n "$health_version" ] && echo "$health_version" | grep -qF "$VERSION"; then
            pass "Health response version ($health_version) matches expected ($VERSION)"
        elif [ -n "$health_version" ]; then
            fail "Health response version ($health_version) does not match expected ($VERSION)"
        else
            warn "Could not extract version from health response"
        fi
    else
        fail "Health endpoint did not respond at $health_url after 10 s"
        if systemd_and_unit_available; then
            echo "Service logs:"
            journalctl -u devolutions-gateway --no-pager -n 50 2>/dev/null || true
        elif [ -n "$gateway_log" ] && [ -f "$gateway_log" ]; then
            echo "Gateway process output:"
            cat "$gateway_log"
        fi
    fi

    [ -n "$gateway_log" ] && rm -f "$gateway_log"
}

check_post_uninstall() {
    if [ ! -f "$BINARY" ]; then
        pass "Binary removed after uninstall"
    else
        fail "Binary still present after uninstall: $BINARY"
    fi

    local unit_file_found=0
    for path in "${UNIT_FILE_PATHS[@]}"; do
        if [ -f "$path" ]; then
            unit_file_found=1
            break
        fi
    done
    if [ "$unit_file_found" -eq 0 ]; then
        pass "Unit file removed after uninstall"
    else
        fail "Unit file still present after uninstall"
    fi

    if [ -d "$CONFIG_DIR" ]; then
        pass "Config directory preserved after uninstall: $CONFIG_DIR"
    else
        fail "Config directory was removed after uninstall (should be preserved)"
    fi
}
