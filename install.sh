#!/bin/sh
# lanlookout installer.
#
# Run it as the user who will run the monitor, from the repository root:
#
#   sh install.sh
#
# It is idempotent and never overwrites an existing real config.
# What it does:
#   1. Creates ~/.config/lanlookout/ (mode 700) and copies
#      examples/config.example.json to config.json if none exists yet.
#      EDIT config.json afterwards (nodes, ssh_user, ftl_db).
#   2. Creates the state directory ~/.local/state/dns-watch/ (mode 700).
#   3. Generates the systemd units from systemd/*.in with your user
#      name and this directory substituted, installs them into
#      /etc/systemd/system (via sudo; skipped with a printed fallback
#      if sudo is unavailable), reloads systemd and enables the timer.
#
# After installing:
#   python3 dns_watch.py --bootstrap   # once, to seed the baseline
#   python3 dns_watch.py --dry-run     # preview
# The timer then runs the monitor every 30 minutes.
set -eu

SRC="$(cd "$(dirname "$0")" && pwd)"
RUN_USER="$(id -un)"
CONFIG_DIR="$HOME/.config/lanlookout"
STATE_DIR="$HOME/.local/state/dns-watch"
UNIT_DIR="${LANLOOKOUT_UNIT_DIR:-/etc/systemd/system}"

echo "lanlookout install: user=$RUN_USER src=$SRC"

# 1. Config
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"
if [ -f "$CONFIG_DIR/config.json" ]; then
  echo "  config: $CONFIG_DIR/config.json already exists, kept"
else
  cp "$SRC/examples/config.example.json" "$CONFIG_DIR/config.json"
  echo "  config: created $CONFIG_DIR/config.json from the example - EDIT IT (nodes, ssh_user, ftl_db)"
fi

# 2. State directory
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
echo "  state:  $STATE_DIR ready"

# 3. systemd units
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT
UNITS="lanlookout.service lanlookout.timer lanlookout-fastlane.service lanlookout-fastlane.timer lanlookout-intel.service lanlookout-intel.timer"
for u in $UNITS; do
  sed -e "s|__USER__|$RUN_USER|g" -e "s|__INSTALL_DIR__|$SRC|g" \
    "$SRC/systemd/$u.in" > "$TMPD/$u"
done

install_units() {
  for u in $UNITS; do cp "$TMPD/$u" "$UNIT_DIR/"; done
}
if [ -w "$UNIT_DIR" ]; then
  install_units
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  for u in $UNITS; do sudo cp "$TMPD/$u" "$UNIT_DIR/"; done
else
  echo "  units:  cannot write $UNIT_DIR (no writable dir, no passwordless sudo)."
  echo "          Generated units are shown below; install them manually:"
  echo "            sudo cp <generated> $UNIT_DIR/ && sudo systemctl daemon-reload && sudo systemctl enable --now lanlookout.timer"
  for u in $UNITS; do
    echo "--- $u"; cat "$TMPD/$u"
  done
  echo "  done (config and state are in place; units are not)"
  exit 0
fi
echo "  units:  installed into $UNIT_DIR"

if command -v systemctl >/dev/null 2>&1; then
  SCTL="systemctl"
  [ -w "$UNIT_DIR" ] || SCTL="sudo systemctl"
  $SCTL daemon-reload >/dev/null 2>&1 || true
  if $SCTL enable --now lanlookout.timer >/dev/null 2>&1; then
    echo "  timer:  lanlookout.timer enabled (every 30 min, :07/:37)"
  else
    echo "  timer:  units installed; enable manually: $SCTL enable --now lanlookout.timer"
  fi
  if $SCTL enable --now lanlookout-fastlane.timer >/dev/null 2>&1; then
    echo "  timer:  lanlookout-fastlane.timer enabled (every 5 min)"
  else
    echo "  timer:  fast lane installed; enable manually: $SCTL enable --now lanlookout-fastlane.timer"
  fi
  if $SCTL enable --now lanlookout-intel.timer >/dev/null 2>&1; then
    echo "  timer:  lanlookout-intel.timer enabled (daily intel refresh)"
  else
    echo "  timer:  intel refresh installed; enable manually: $SCTL enable --now lanlookout-intel.timer"
  fi
fi

echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/config.json (nodes, ssh_user, ftl_db)"
echo "  2. Optional: cp examples/nextcloud-config.example.json $CONFIG_DIR/nextcloud.json (Talk notifications)"
echo "  3. Optional: create $CONFIG_DIR/device_names.json (MAC -> name)"
echo "  4. python3 $SRC/dns_watch.py --bootstrap && python3 $SRC/dns_watch.py --dry-run"
