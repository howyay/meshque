# Phase 1b — Untested Components

Items that require root/CAP_NET_ADMIN, real network infrastructure, or Phase 1c completion.

## Requires Root (manual testing)

| Component | What to test | How |
|---|---|---|
| TUN device creation | `tun-rs` creates `meshque0` interface | `sudo meshque connect --direct ... --role responder` |
| TUN IP assignment | Interface gets 100.64.0.1/10 CGNAT address | `ip addr show meshque0` |
| TUN MTU | MTU matches `tunnel_mtu()` | `ip link show meshque0` |
| Packet loop (TUN→tunnel) | Packet written to TUN arrives as CONNECT-IP datagram | `ping -I meshque0 100.64.0.2` from responder |
| Packet loop (tunnel→TUN) | CONNECT-IP datagram delivered to TUN | `ping -I meshque1 100.64.0.1` from initiator |
| Two-process loopback | Two `meshque` on localhost with separate TUNs | Both `sudo`, verify bidirectional ping |

### Manual test script

```bash
# Terminal 1 (responder)
sudo meshque connect --direct 127.0.0.1:4433 --role responder --listen 127.0.0.1:4433 -v

# Terminal 2 (initiator)
sudo meshque connect --direct 127.0.0.1:4433 --role initiator -v

# Terminal 3 (verify)
ping -c 3 100.64.0.1  # from initiator's perspective
ping -c 3 100.64.0.2  # from responder's perspective
```

## Requires Phase 1c (signaling server)

| Component | What to test |
|---|---|
| Signaling client (`signaling.rs`) | Not yet implemented — stub only |
| Room join/poll/exchange flow | Peer discovers partner via signaling |
| Cert fingerprint pinning | Client verifies server cert matches fingerprint from signaling |

## Requires Real Network / NAT

| Component | What to test |
|---|---|
| STUN binding | Discover reflexive address via public STUN server |
| NAT type detection | Cone vs symmetric classification |
| UDP hole punching | Simultaneous send to create NAT mapping |
| Cross-network tunnel | Two machines on different networks, tunnel works |

## Requires Implementation (not yet built)

| Component | Status |
|---|---|
| Reconnection logic | Not implemented — connection drop = process exit |
| Cert fingerprint pinning | Certs generated but fingerprint not verified against signaling data |
| Graceful shutdown (SIGTERM) | Not implemented — process just exits |
| `nat.rs` | Not yet written (Phase 1b spec lists it) |
| `signaling.rs` | Stub — no HTTP client logic |
