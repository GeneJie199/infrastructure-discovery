#!/usr/bin/env sh
set -eu

SOURCE=${1:-./infrascout}
PREFIX=${PREFIX:-/usr/local}
STATE_DIR=${STATE_DIR:-/var/lib/infrascout}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -f "$SOURCE" ] && [ "$SOURCE" = "./infrascout" ] && [ -f "./bin/infrascout" ]; then
  SOURCE=./bin/infrascout
fi

if [ ! -f "$SOURCE" ]; then
  echo "binary not found: $SOURCE" >&2
  echo "usage: sudo ./scripts/install.sh [path-to-infrascout]" >&2
  exit 1
fi

install -d -m 0755 "$PREFIX/bin" "$STATE_DIR"
install -m 0755 "$SOURCE" "$PREFIX/bin/infrascout"
echo "installed $PREFIX/bin/infrascout"
echo "state directory: $STATE_DIR"
if [ "${INSTALL_SERVICE:-0}" = "1" ]; then
  UNIT_FILE=${UNIT_FILE:-$SCRIPT_DIR/infrascout.service}
  if [ ! -f "$UNIT_FILE" ]; then
    UNIT_FILE=$SCRIPT_DIR/../deploy/infrascout.service
  fi
  if [ ! -f "$UNIT_FILE" ]; then
    echo "systemd unit not found; set UNIT_FILE=/path/to/infrascout.service" >&2
    exit 1
  fi
  install -m 0644 "$UNIT_FILE" /etc/systemd/system/infrascout.service
  systemctl daemon-reload
  systemctl enable infrascout
  echo "systemd unit installed and enabled; start it after the first baseline"
fi
echo "next: sudo infrascout up --state-dir $STATE_DIR"
