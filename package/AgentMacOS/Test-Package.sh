#!/bin/sh

# Installs, upgrades, and uninstalls the Devolutions Agent macOS package, checking the launchd service at each step.
# Changes the system it runs on, so only run it on a disposable machine such as a CI runner.

set -eu

PKG="$1"
LABEL="com.devolutions.agent"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
DATA_DIR="/Library/Application Support/Devolutions Agent"
LOG_DIR="/Library/Logs/Devolutions Agent"

fail() {
	echo "FAIL: $*" >&2
	sudo /bin/launchctl print "system/$LABEL" >&2 || true
	sudo cat "$LOG_DIR/agent.stderr.log" >&2 || true
	exit 1
}

# Polls because launchd starts and stops the job asynchronously.
wait_for_state() {
	expected="$1"
	for _ in $(seq 1 30); do
		state="$(sudo /bin/launchctl print "system/$LABEL" 2>/dev/null | awk '/^\tstate = / { sub(/^\tstate = /, ""); print; exit }')"
		[ "$state" = "$expected" ] && return 0
		sleep 1
	done
	fail "expected the service to be $expected, got '${state:-not loaded}'"
}

install_pkg() {
	sudo /usr/sbin/installer -pkg "$PKG" -target / || fail "installer failed"
}

# oracle: regression #2192 (pre-existing data-directory permissions and ACLs)
echo "Preparing an existing data directory with broad permissions"
sudo mkdir -p "$DATA_DIR"
sudo chown "$(id -un)" "$DATA_DIR"
sudo chmod 755 "$DATA_DIR"
sudo chmod +a "everyone allow list,search,readattr" "$DATA_DIR"

echo "Installing $PKG"
install_pkg

[ -x /usr/local/bin/devolutions-agent ] || fail "binary not installed"
[ -x /usr/local/bin/devolutions-agent-uninstall ] || fail "uninstall script not installed"
[ "$(stat -f '%Su:%Sg %Lp' "$PLIST")" = "root:wheel 644" ] || fail "unexpected plist ownership or mode"
# oracle: regression #2192 (the root daemon must not search a user-writable prefix)
[ "$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:PATH' "$PLIST")" = "/usr/local/microsoft/powershell/7:/usr/bin:/bin:/usr/sbin:/sbin" ] || fail "unexpected daemon PATH"
[ "$(sudo stat -f '%Su:%Sg %Lp' "$DATA_DIR")" = "root:wheel 700" ] || fail "unexpected data directory ownership or mode"
if sudo /bin/ls -lde "$DATA_DIR" | /usr/bin/grep -q 'group:everyone'; then
	fail "data directory still has a broad ACL"
fi
sudo test -f "$DATA_DIR/agent.json" || fail "configuration not initialized"
wait_for_state running

echo "Stopping and starting through the agent command line"
sudo /usr/local/bin/devolutions-agent stop
wait_for_state "not running"
sudo /usr/local/bin/devolutions-agent start
wait_for_state running

echo "Upgrading over the installed package"
install_pkg
wait_for_state running

echo "Uninstalling"
sudo /usr/local/bin/devolutions-agent-uninstall --purge
sudo /bin/launchctl print "system/$LABEL" >/dev/null 2>&1 && fail "service still loaded after uninstall"
for path in /usr/local/bin/devolutions-agent /usr/local/bin/devolutions-agent-uninstall "$PLIST" "$DATA_DIR" "$LOG_DIR"; do
	[ -e "$path" ] && fail "$path still present after uninstall"
done
/usr/sbin/pkgutil --pkg-info "$LABEL" >/dev/null 2>&1 && fail "package receipt still present after uninstall"

echo "PASS"
