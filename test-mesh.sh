#!/usr/bin/env bash
set -e

# Test mesh networking with 3 peers using network namespaces.
# Each peer runs in its own namespace to avoid local routing table conflicts.
#
# Requires: sudo, signaling server on localhost:8787
#
# Usage:
#   1. Start signaling server: cd signaling && PORT=8787 npx tsx entry/node.ts
#   2. Build: cargo build -p meshque --release
#   3. Run: sudo bash test-mesh.sh

BINARY="$(pwd)/target/release/meshque"
NETWORK="test-$(date +%s)"
TOKEN="test-token-$$"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Build first: cargo build -p meshque --release"
    exit 1
fi

if ! curl -s "http://localhost:8787/health" | grep -q '"ok"'; then
    echo "Signaling server not running at localhost:8787"
    echo "Start it: cd signaling && PORT=8787 npx tsx entry/node.ts"
    exit 1
fi

cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    for i in 1 2 3; do
        ip netns pids mq-ns$i 2>/dev/null | xargs -r kill 2>/dev/null
        ip link del veth-mq$i 2>/dev/null
        ip netns del mq-ns$i 2>/dev/null
    done
    ip link del mq-br0 2>/dev/null
    iptables -D INPUT -i mq-br0 -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i mq-br0 -j ACCEPT 2>/dev/null
    iptables -D FORWARD -o mq-br0 -j ACCEPT 2>/dev/null
    rm -rf "$IDENTITY_DIR" 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

echo "=== meshque mesh test ==="
echo "Network: $NETWORK"
echo ""

# Bridge for inter-namespace communication
ip link add mq-br0 type bridge
ip addr add 10.0.0.1/24 dev mq-br0
ip link set mq-br0 up
sysctl -qw net.ipv4.ip_forward=1
iptables -I INPUT -i mq-br0 -j ACCEPT 2>/dev/null
iptables -I FORWARD -i mq-br0 -j ACCEPT 2>/dev/null
iptables -I FORWARD -o mq-br0 -j ACCEPT 2>/dev/null

# Create namespaces with veth pairs to bridge
for i in 1 2 3; do
    ip netns add mq-ns$i
    ip link add veth-mq$i type veth peer name veth-peer$i
    ip link set veth-peer$i netns mq-ns$i
    ip link set veth-mq$i master mq-br0
    ip link set veth-mq$i up
    ip netns exec mq-ns$i ip addr add 10.0.0.$((i+1))/24 dev veth-peer$i
    ip netns exec mq-ns$i ip link set veth-peer$i up
    ip netns exec mq-ns$i ip link set lo up
    ip netns exec mq-ns$i ip route add default via 10.0.0.1
done

SIGNAL="http://10.0.0.1:8787"
IDENTITY_DIR="/tmp/meshque-identities-$NETWORK"
mkdir -p "$IDENTITY_DIR"

echo "Starting peer 1..."
ip netns exec mq-ns1 "$BINARY" up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4001 --tun-name mesh1 \
    --identity-file "$IDENTITY_DIR/peer1.json" \
    --advertise-endpoint 10.0.0.2:4001 -v &
P1=$!
sleep 3

echo "Starting peer 2..."
ip netns exec mq-ns2 "$BINARY" up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4002 --tun-name mesh2 \
    --identity-file "$IDENTITY_DIR/peer2.json" \
    --advertise-endpoint 10.0.0.3:4002 -v &
P2=$!
sleep 3

echo "Starting peer 3..."
ip netns exec mq-ns3 "$BINARY" up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4003 --tun-name mesh3 \
    --identity-file "$IDENTITY_DIR/peer3.json" \
    --advertise-endpoint 10.0.0.4:4003 -v &
P3=$!
echo "Waiting for peers to discover each other and connect..."
sleep 15

echo ""
echo "=== Testing connectivity ==="

echo "TUN devices:"
for i in 1 2 3; do
    addr=$(ip netns exec mq-ns$i ip -4 addr show mesh$i 2>/dev/null | grep inet | awk '{print $2}')
    if [ -n "$addr" ]; then
        echo "  mesh$i (ns$i): UP ($addr)"
    else
        echo "  mesh$i (ns$i): MISSING"
    fi
done

echo ""
echo "Ping tests:"

if ip netns exec mq-ns1 ping -c 2 -W 3 100.64.0.2 >/dev/null 2>&1; then
    echo "  P1 -> P2 (100.64.0.1 -> 100.64.0.2): OK"
else
    echo "  P1 -> P2 (100.64.0.1 -> 100.64.0.2): FAIL"
fi

if ip netns exec mq-ns1 ping -c 2 -W 3 100.64.0.3 >/dev/null 2>&1; then
    echo "  P1 -> P3 (100.64.0.1 -> 100.64.0.3): OK"
else
    echo "  P1 -> P3 (100.64.0.1 -> 100.64.0.3): FAIL"
fi

if ip netns exec mq-ns2 ping -c 2 -W 3 100.64.0.3 >/dev/null 2>&1; then
    echo "  P2 -> P3 (100.64.0.2 -> 100.64.0.3): OK"
else
    echo "  P2 -> P3 (100.64.0.2 -> 100.64.0.3): FAIL"
fi

if ip netns exec mq-ns3 ping -c 2 -W 3 100.64.0.1 >/dev/null 2>&1; then
    echo "  P3 -> P1 (100.64.0.3 -> 100.64.0.1): OK"
else
    echo "  P3 -> P1 (100.64.0.3 -> 100.64.0.1): FAIL"
fi

echo ""
echo "=== Reconnection test ==="
echo "Killing peer 2..."
kill $P2 2>/dev/null || true
wait $P2 2>/dev/null || true
sleep 2

echo "Verifying P1 -> P2 fails after kill..."
if ip netns exec mq-ns1 ping -c 1 -W 2 100.64.0.2 >/dev/null 2>&1; then
    echo "  P1 -> P2: still reachable (unexpected)"
else
    echo "  P1 -> P2: unreachable (expected)"
fi

echo "Restarting peer 2..."
ip netns exec mq-ns2 "$BINARY" up --network "$NETWORK" --token "$TOKEN" \
    --signal-server "$SIGNAL" --listen 0.0.0.0:4002 --tun-name mesh2 \
    --identity-file "$IDENTITY_DIR/peer2.json" \
    --advertise-endpoint 10.0.0.3:4002 -v &
P2=$!
echo "Waiting for reconnection (30s)..."
sleep 30

echo "Verifying connectivity after reconnection..."
if ip netns exec mq-ns1 ping -c 2 -W 3 100.64.0.2 >/dev/null 2>&1; then
    echo "  P1 -> P2: OK (reconnected)"
else
    echo "  P1 -> P2: FAIL (reconnection failed)"
fi

if ip netns exec mq-ns2 ping -c 2 -W 3 100.64.0.3 >/dev/null 2>&1; then
    echo "  P2 -> P3: OK (reconnected)"
else
    echo "  P2 -> P3: FAIL (reconnection failed)"
fi

echo ""
echo "=== Test complete ==="
