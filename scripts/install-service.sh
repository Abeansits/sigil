#!/usr/bin/env bash
set -euo pipefail

LABEL="com.sigil.conductor"
PLIST_SRC="$(cd "$(dirname "$0")" && pwd)/sigil.plist"
PLIST_DST="$HOME/Library/LaunchAgents/${LABEL}.plist"
SIGIL_DIR="$HOME/.sigil"
LOG_DIR="$SIGIL_DIR/logs"
WRAPPER="$SIGIL_DIR/sigil-run.sh"

# --- preflight ---

if [[ "$(uname)" != "Darwin" ]]; then
  echo "Error: this script only works on macOS." >&2
  exit 1
fi

if ! command -v sigil &>/dev/null; then
  echo "Error: 'sigil' not found in PATH. Install it first:" >&2
  echo "  cargo install --path crates/sigil-cli" >&2
  exit 1
fi

SIGIL_BIN="$(command -v sigil)"

# --- store token in Keychain (interactive, one-time) ---

if ! security find-generic-password -s "sigil-telegram-token" -a "$USER" &>/dev/null; then
  echo "No Keychain entry found for sigil-telegram-token."
  echo "You can store your token now, or skip and add it later with:"
  echo "  security add-generic-password -s sigil-telegram-token -a \$USER -w <token>"
  read -rp "Store Telegram token now? [y/N] " yn
  if [[ "${yn,,}" == "y" ]]; then
    read -rsp "Paste your Telegram bot token: " token
    echo
    security add-generic-password -s "sigil-telegram-token" -a "$USER" -w "$token"
    echo "Token stored in Keychain."
  fi
fi

# --- create directories ---

mkdir -p "$LOG_DIR"
echo "Created $LOG_DIR"

# --- write wrapper script ---

cat > "$WRAPPER" <<SCRIPT
#!/usr/bin/env bash
# Wrapper for launchd — loads secrets from Keychain, then execs sigil.

set -euo pipefail

SIGIL_TELEGRAM_TOKEN="\$(
  security find-generic-password -s sigil-telegram-token -a "\$USER" -w 2>/dev/null
)"

if [[ -z "\$SIGIL_TELEGRAM_TOKEN" ]]; then
  echo "Error: could not read sigil-telegram-token from Keychain." >&2
  echo "Store it with: security add-generic-password -s sigil-telegram-token -a \\\$USER -w <token>" >&2
  exit 1
fi

export SIGIL_TELEGRAM_TOKEN

exec "$SIGIL_BIN" run --bridge telegram --interval 30
SCRIPT

chmod +x "$WRAPPER"
echo "Wrote wrapper to $WRAPPER"

# --- install plist ---

# launchd doesn't expand ~ or $HOME, so we substitute the real path.
sed "s|PLACEHOLDER_HOME|$HOME|g" "$PLIST_SRC" > "$PLIST_DST"
echo "Installed plist to $PLIST_DST"

# --- load service ---

# Unload first if already loaded (ignore errors).
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true

launchctl bootstrap "gui/$(id -u)" "$PLIST_DST"
echo "Service loaded."

# --- verify ---

sleep 2
if launchctl print "gui/$(id -u)/$LABEL" &>/dev/null; then
  echo "Service $LABEL is running."
  echo "Logs: $LOG_DIR/sigil.log"
else
  echo "Warning: service does not appear to be running." >&2
  echo "Check: launchctl print gui/$(id -u)/$LABEL" >&2
  echo "Logs:  $LOG_DIR/sigil.log" >&2
  exit 1
fi
