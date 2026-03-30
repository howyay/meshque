#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./macos-up.sh <network> <token> [signal-server]

Starts meshque in the background on macOS for manual testing.

Environment overrides:
  MESHQUE_BIN           Path to meshque binary (default: ./meshque)
  MESHQUE_TUN_NAME      utun interface name hint (default: utun9)
  MESHQUE_IDENTITY_FILE Identity file path (default: /tmp/meshque-mac-peer.json)
  MESHQUE_PID_FILE      PID file path (default: /tmp/meshque-mac-peer.pid)
  MESHQUE_LOG_FILE      Log file path (default: /tmp/meshque-mac-peer.log)
EOF
}

NETWORK="${1:-}"
TOKEN="${2:-}"
SIGNAL_SERVER="${3:-https://meshque-signaling.haoye.workers.dev}"

if [[ -z "$NETWORK" || -z "$TOKEN" ]]; then
  usage
  exit 1
fi

BINARY="${MESHQUE_BIN:-./meshque}"
TUN_NAME="${MESHQUE_TUN_NAME:-utun9}"
IDENTITY_FILE="${MESHQUE_IDENTITY_FILE:-/tmp/meshque-mac-peer.json}"
PID_FILE="${MESHQUE_PID_FILE:-/tmp/meshque-mac-peer.pid}"
LOG_FILE="${MESHQUE_LOG_FILE:-/tmp/meshque-mac-peer.log}"

BINARY_DIR="$(cd "$(dirname "$BINARY")" && pwd)"
BINARY_PATH="$BINARY_DIR/$(basename "$BINARY")"

if [[ ! -f "$BINARY_PATH" ]]; then
  printf 'meshque binary not found: %s\n' "$BINARY_PATH" >&2
  exit 1
fi

if [[ -f "$PID_FILE" ]]; then
  EXISTING_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "$EXISTING_PID" ]] && sudo kill -0 "$EXISTING_PID" 2>/dev/null; then
    printf 'meshque already running (pid %s). Stop it first with ./macos-down.sh\n' "$EXISTING_PID" >&2
    exit 1
  fi
  rm -f "$PID_FILE"
fi

chmod +x "$BINARY_PATH"
xattr -dr com.apple.quarantine "$BINARY_PATH" 2>/dev/null || true
codesign --sign - "$BINARY_PATH" >/dev/null 2>&1 || true
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "$BINARY_PATH" >/dev/null 2>&1 || true
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp "$BINARY_PATH" >/dev/null 2>&1 || true

rm -f "$LOG_FILE"

sudo env \
  BINARY_PATH="$BINARY_PATH" \
  NETWORK="$NETWORK" \
  TOKEN="$TOKEN" \
  SIGNAL_SERVER="$SIGNAL_SERVER" \
  IDENTITY_FILE="$IDENTITY_FILE" \
  TUN_NAME="$TUN_NAME" \
  PID_FILE="$PID_FILE" \
  LOG_FILE="$LOG_FILE" \
  sh -c 'nohup "$BINARY_PATH" up --network "$NETWORK" --token "$TOKEN" --signal-server "$SIGNAL_SERVER" --identity-file "$IDENTITY_FILE" --tun-name "$TUN_NAME" -v >"$LOG_FILE" 2>&1 < /dev/null & echo $! > "$PID_FILE"'

sleep 2

PID="$(cat "$PID_FILE")"
if sudo kill -0 "$PID" 2>/dev/null; then
  printf 'meshque started.\n'
  printf '  pid: %s\n' "$PID"
  printf '  log: %s\n' "$LOG_FILE"
  printf '  identity: %s\n' "$IDENTITY_FILE"
  printf '  signal-server: %s\n' "$SIGNAL_SERVER"
  printf '  tun-name: %s\n' "$TUN_NAME"
  printf '\nTail logs with:\n  tail -f %s\n' "$LOG_FILE"
else
  printf 'meshque failed to stay running. Recent log output:\n' >&2
  cat "$LOG_FILE" >&2 || true
  exit 1
fi
