#!/usr/bin/env bash
set -euo pipefail

PID_FILE="${MESHQUE_PID_FILE:-/tmp/meshque-mac-peer.pid}"
LOG_FILE="${MESHQUE_LOG_FILE:-/tmp/meshque-mac-peer.log}"

if [[ ! -f "$PID_FILE" ]]; then
  printf 'No meshque pid file found at %s\n' "$PID_FILE"
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ -z "$PID" ]]; then
  printf 'PID file was empty; removing it.\n'
  rm -f "$PID_FILE"
  exit 0
fi

if sudo kill -0 "$PID" 2>/dev/null; then
  sudo kill "$PID" 2>/dev/null || true
  sleep 1
  if sudo kill -0 "$PID" 2>/dev/null; then
    sudo kill -9 "$PID" 2>/dev/null || true
  fi
  printf 'Stopped meshque pid %s\n' "$PID"
else
  printf 'meshque pid %s was not running\n' "$PID"
fi

rm -f "$PID_FILE"
printf 'Log file retained at %s\n' "$LOG_FILE"
