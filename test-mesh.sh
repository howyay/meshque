#!/usr/bin/env bash
set -e

# Test mesh networking with 3 peers on localhost.
# Requires: sudo (for TUN devices), signaling server on localhost:8787
#
# Usage:
#   1. Start signaling server: cd signaling && PORT=8787 npx tsx entry/node.ts
#   2. Build: cargo build -p meshque --release
#   3. Run: sudo bash test-mesh.sh

BINARY="./target/release/meshque"
SIGNAL="http://localhost:8787"
NETWORK="test-$(date +%s)"
TOKEN="test-token-$$"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Build first: cargo build -p meshque --release"
    exit 1
fi

if ! curl -s "$SIGNAL/health" | grep -q '"ok"'; then
    echo "Signaling server not running at $SIGNAL"
    echo "Start it: cd signaling && PORT=8787 npx tsx entry/node.ts"
    exit 1
fi

echo "=== meshque mesh test ==="
echo "Network: $NETWORK"
echo "Signal:  $SIGNAL"
echo ""

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kill $P1 $P2 $P3 2>/dev/null
    wait $P1 $P2 $P3 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

# Start 3 peers with different listen ports, TUN names, and localhost endpoints
echo "Starting peer 1..."
$BINARY up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4001 --tun-name mesh1 \
    --advertise-endpoint 127.0.0.1:4001 -v &
P1=$!
sleep 3

echo "Starting peer 2..."
$BINARY up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4002 --tun-name mesh2 \
    --advertise-endpoint 127.0.0.1:4002 -v &
P2=$!
sleep 3

echo "Starting peer 3..."
$BINARY up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4003 --tun-name mesh3 \
    --advertise-endpoint 127.0.0.1:4003 -v &
P3=$!
sleep 8

echo ""
echo "=== Testing connectivity ==="

# Check TUN devices exist
echo "TUN devices:"
for i in 1 2 3; do
    if ip link show mesh$i >/dev/null 2>&1; then
        addr=$(ip -4 addr show mesh$i | grep inet | awk '{print $2}')
        echo "  mesh$i: UP ($addr)"
    else
        echo "  mesh$i: MISSING"
    fi
done

echo ""
echo "Ping tests:"

# Ping from peer 1 (100.64.0.1) to peer 2 (100.64.0.2)
if ping -c 2 -W 3 -I mesh1 100.64.0.2 >/dev/null 2>&1; then
    echo "  P1 → P2 (100.64.0.1 → 100.64.0.2): OK ✓"
else
    echo "  P1 → P2 (100.64.0.1 → 100.64.0.2): FAIL ✗"
fi

# Ping from peer 1 to peer 3
if ping -c 2 -W 3 -I mesh1 100.64.0.3 >/dev/null 2>&1; then
    echo "  P1 → P3 (100.64.0.1 → 100.64.0.3): OK ✓"
else
    echo "  P1 → P3 (100.64.0.1 → 100.64.0.3): FAIL ✗"
fi

# Ping from peer 2 to peer 3
if ping -c 2 -W 3 -I mesh2 100.64.0.3 >/dev/null 2>&1; then
    echo "  P2 → P3 (100.64.0.2 → 100.64.0.3): OK ✓"
else
    echo "  P2 → P3 (100.64.0.2 → 100.64.0.3): FAIL ✗"
fi

# Reverse direction
if ping -c 2 -W 3 -I mesh3 100.64.0.1 >/dev/null 2>&1; then
    echo "  P3 → P1 (100.64.0.3 → 100.64.0.1): OK ✓"
else
    echo "  P3 → P1 (100.64.0.3 → 100.64.0.1): FAIL ✗"
fi

echo ""
echo "=== Test complete ==="
