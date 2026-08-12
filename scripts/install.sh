#!/usr/bin/env sh
set -eu

SOURCE=${1:-./infrascout}
PREFIX=${PREFIX:-/usr/local}
STATE_DIR=${STATE_DIR:-/var/lib/infrascout}

if [ ! -f "$SOURCE" ]; then
  echo "binary not found: $SOURCE" >&2
  echo "usage: sudo ./scripts/install.sh [path-to-infrascout]" >&2
  exit 1
fi

install -d -m 0755 "$PREFIX/bin" "$STATE_DIR"
install -m 0755 "$SOURCE" "$PREFIX/bin/infrascout"
echo "installed $PREFIX/bin/infrascout"
echo "state directory: $STATE_DIR"
echo "next: sudo infrascout baseline --state-dir $STATE_DIR"
