#!/usr/bin/env sh
set -eu

ACTION=${1:-install}
case "$ACTION" in
  install|doctor|uninstall|purge) shift ;;
  *) ACTION=install ;;
esac

SOURCE=${1:-./infrascout}
CHECKSUMS=${2:-}
PREFIX=${PREFIX:-/usr/local}
STATE_DIR=${STATE_DIR:-/var/lib/infrascout}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
BINARY="$PREFIX/bin/infrascout"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

require_root() {
  [ "$(id -u)" -eq 0 ] || { echo "this action requires root; run with sudo" >&2; exit 1; }
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

verify_checksum() {
  [ -n "$CHECKSUMS" ] || return 0
  [ -f "$CHECKSUMS" ] || { echo "checksum file not found: $CHECKSUMS" >&2; exit 1; }
  name=$(basename "$SOURCE")
  expected=$(awk -v name="$name" '$2 == name || $2 == "*" name { print $1; exit }' "$CHECKSUMS")
  [ -n "$expected" ] || { echo "checksum entry not found for $name" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$SOURCE" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$SOURCE" | awk '{print $1}')
  fi
  [ "$actual" = "$expected" ] || { echo "SHA-256 verification failed for $SOURCE" >&2; exit 1; }
  echo "verified SHA-256 for $name"
}

case "$ACTION" in
  install)
    require_root
    if [ ! -f "$SOURCE" ] && [ "$SOURCE" = "./infrascout" ] && [ -f "./bin/infrascout" ]; then SOURCE=./bin/infrascout; fi
    [ -f "$SOURCE" ] || { echo "binary not found: $SOURCE" >&2; echo "usage: sudo sh scripts/install.sh install [infrascout] [checksums.txt]" >&2; exit 1; }
    verify_checksum
    install -d -m 0755 "$PREFIX/bin" "$STATE_DIR"
    install -m 0755 "$SOURCE" "$BINARY"
    if [ "${INSTALL_SERVICE:-0}" = 1 ]; then
      unit="$SCRIPT_DIR/../deploy/infrascout.service"
      [ -f "$unit" ] || { echo "systemd unit not found: $unit" >&2; exit 1; }
      install -m 0644 "$unit" "$SYSTEMD_DIR/infrascout.service"
      if has_systemd; then
        systemctl daemon-reload
        systemctl enable infrascout.service
      fi
    fi
    "$BINARY" version
    echo "installed $BINARY"
    echo "state directory: $STATE_DIR"
    echo "next: sudo $BINARY up --state-dir $STATE_DIR"
    ;;
  doctor)
    [ -x "$BINARY" ] || { echo "infrascout is not installed at $BINARY" >&2; exit 1; }
    [ -d "$STATE_DIR" ] && [ -r "$STATE_DIR" ] || { echo "state directory is unavailable: $STATE_DIR" >&2; exit 1; }
    "$BINARY" version
    echo "doctor: binary and state directory are ready"
    ;;
  uninstall)
    require_root
    has_systemd && systemctl disable --now infrascout.service >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DIR/infrascout.service" "$BINARY"
    has_systemd && systemctl daemon-reload || true
    echo "removed InfraScout binaries; preserved $STATE_DIR"
    ;;
  purge)
    require_root
    case "$STATE_DIR" in
      */infrascout|*/infrascout/*) ;;
      *) echo "refusing to purge unexpected state directory: $STATE_DIR" >&2; exit 1 ;;
    esac
    [ "${INFRASCOUT_CONFIRM_PURGE:-}" = "$STATE_DIR" ] || { echo "set INFRASCOUT_CONFIRM_PURGE to the exact state directory" >&2; exit 1; }
    rm -rf "$STATE_DIR"
    echo "purged $STATE_DIR"
    ;;
esac
