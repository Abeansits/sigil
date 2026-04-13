#!/usr/bin/env bash
set -euo pipefail

LABEL="com.sigil.conductor"
PLIST_DST="$HOME/Library/LaunchAgents/${LABEL}.plist"
SIGIL_DIR="$HOME/.sigil"
WRAPPER="$SIGIL_DIR/sigil-run.sh"

# --- unload service ---

if launchctl print "gui/$(id -u)/$LABEL" &>/dev/null; then
  launchctl bootout "gui/$(id -u)/$LABEL"
  echo "Service unloaded."
else
  echo "Service was not loaded."
fi

# --- remove plist ---

if [[ -f "$PLIST_DST" ]]; then
  rm "$PLIST_DST"
  echo "Removed $PLIST_DST"
fi

# --- remove wrapper ---

if [[ -f "$WRAPPER" ]]; then
  rm "$WRAPPER"
  echo "Removed $WRAPPER"
fi

# --- Keychain entry ---

echo ""
echo "Note: the Keychain entry (sigil-telegram-token) was NOT removed."
echo "To remove it manually:"
echo "  security delete-generic-password -s sigil-telegram-token -a \$USER"

echo ""
echo "Log directory ($SIGIL_DIR/logs/) was NOT removed."
echo "To clean up completely: rm -rf $SIGIL_DIR/logs/"
