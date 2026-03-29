# Phase 1b — Untested Components

Items that require root/CAP_NET_ADMIN, real network infrastructure, or multi-machine setup.

## Requires Root (manual testing)

| Component | What to test | How |
|---|---|---|
| TUN device creation | `tun-rs` creates `meshque0` interface | `sudo meshque connect --direct ... --role responder` |
| TUN IP assignment | Interface gets 100.64.0.1/10 CGNAT address | `ip addr show meshque0` |
| TUN MTU | MTU matches `tunnel_mtu()` | `ip link show meshque0` |
| Packet loop (TUN→tunnel) | Packet written to TUN arrives as CONNECT-IP datagram | `ping -I meshque0 100.64.0.2` from responder |
| Packet loop (tunnel→TUN) | CONNECT-IP datagram delivered to TUN | `ping -I meshque1 100.64.0.1` from initiator |
| Two-process loopback | Two `meshque` on localhost with separate TUNs | Both `sudo`, verify bidirectional ping |

### Manual test script (direct mode)

```bash
# Terminal 1 (responder)
sudo meshque connect --direct 127.0.0.1:4433 --role responder --listen 127.0.0.1:4433 -v

# Terminal 2 (initiator)
sudo meshque connect --direct 127.0.0.1:4433 --role initiator -v

# Terminal 3 (verify)
ping -c 3 100.64.0.1  # from initiator's perspective
ping -c 3 100.64.0.2  # from responder's perspective
```

## Requires Multi-Machine Setup

| Component | What to test |
|---|---|
| Cross-network tunnel | Two machines on different networks, signaling → STUN → hole punch → tunnel |
| NAT hole punching (real NAT) | Both peers behind different NATs, verify UDP mapping creation |
| Symmetric NAT warning | One or both peers behind symmetric NAT — verify warning message |
| Cert fingerprint pinning (cross-network) | Initiator verifies responder cert fingerprint from signaling |

### Manual test script (signaling mode)

```bash
# Start signaling server
cd signaling && pnpm dev  # runs on :8787

# Machine A
meshque connect my-secret-room --signal-server http://signal-server:8787 -v

# Machine B
meshque connect my-secret-room --signal-server http://signal-server:8787 -v

# Both machines should get virtual IPs and be able to ping each other
```

## Verified (no root needed)

| Component | Verified by |
|---|---|
| STUN discovery (3 servers) | Smoke test — discovers public IP, classifies NAT as cone |
| Signaling client (join/poll/exchange) | Smoke test — two processes through local signaling server |
| Cert fingerprint generation | Smoke test — sha256 fingerprints generated and exchanged |
| Hole punch packet burst | Smoke test — 10 UDP packets sent to peer's reflexive addr |
| QUIC + H3 + CONNECT-IP handshake | Integration tests (4 tests in connection_flow.rs) |
| ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT | Integration tests + smoke test |
| Graceful shutdown (Ctrl-C) | SIGINT handler in main.rs |

## Not Yet Implemented

| Component | Status |
|---|---|
| Reconnection logic | Not implemented — connection drop = process exit |
| Exponential backoff | Not implemented |
