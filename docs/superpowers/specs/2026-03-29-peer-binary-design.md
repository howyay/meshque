# Phase 1b Spec: meshque Peer Binary

A single Rust binary that creates a point-to-point IP tunnel over MASQUE CONNECT-IP, bridging a TUN device to an HTTP/3 session.

## Goal

Two machines run `meshque`. They connect via a signaling server, punch through NAT, and establish a MASQUE CONNECT-IP tunnel. Each machine gets a virtual IP in the CGNAT range (100.64.0.0/10). Applications use the network normally — `ping`, `ssh`, etc. all work. To network observers, all traffic looks like HTTPS on port 443.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      meshque binary                          │
├──────────────┬───────────────────────────────────────────────┤
│   CLI layer  │  clap — parse args, config, run subcommands  │
├──────────────┴───────────────────────────────────────────────┤
│                    Tunnel Engine                             │
│  ┌─────────┐     ┌──────────────────┐     ┌──────────────┐  │
│  │   TUN   │◄───►│   Packet Loop    │◄───►│  CONNECT-IP  │  │
│  │ device  │     │  (tokio::select) │     │   Session    │  │
│  └─────────┘     └──────────────────┘     └──────────────┘  │
├──────────────────────────────────────────────────────────────┤
│                    Connection Manager                        │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────────┐  │
│  │ Signaling│───►│ NAT Traversal│───►│  QUIC/H3 Setup    │  │
│  │  Client  │    │ (STUN + hole │    │  (quinn + h3 +    │  │
│  │          │    │   punch)     │    │   connect-ip)     │  │
│  └──────────┘    └──────────────┘    └───────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Core Loop

The tunnel engine is two concurrent tasks:

```rust
let parts = session.into_parts();

// Task 1: TUN → tunnel (local packets out)
loop {
    let packet = tun.read_packet().await?;
    parts.datagram_send.send_ip_packet(&packet)?;
}

// Task 2: tunnel → TUN (remote packets in)
loop {
    let packet = parts.datagram_recv.recv_ip_packet().await?;
    tun.write_packet(&packet).await?;
}
```

A third task handles capsule control plane (address assignment, route advertisement) — typically only at session start.

### Dual Role

Every peer is BOTH client and proxy simultaneously:
- **As proxy**: listens on port 443 (or configured port), accepts CONNECT-IP sessions
- **As client**: connects to the peer's proxy via the signaling-provided endpoint

For Phase 1, one peer initiates (client) and the other responds (proxy). The roles are determined by the signaling server (first to join the room is the initiator).

## Dependencies

| Crate | Purpose |
|---|---|
| `connect-ip` | Our RFC 9484 crate (Phase 1a) |
| `quinn` | QUIC transport |
| `h3` / `h3-quinn` / `h3-datagram` | HTTP/3 |
| `tun-rs` | Cross-platform TUN device (Linux + macOS) |
| `tokio` | Async runtime |
| `clap` | CLI argument parsing |
| `tracing` / `tracing-subscriber` | Structured logging |
| `serde` / `serde_json` | Config serialization |
| `rcgen` / `rustls` | Self-signed cert generation for QUIC |
| `reqwest` | HTTP client for signaling server |
| `stun-rs` or `stun` | STUN client for NAT traversal |

## CLI Design

```
meshque — mesh VPN over MASQUE

USAGE:
    meshque connect <room-code> [OPTIONS]

OPTIONS:
    --signal-server <URL>   Signaling server URL (default: https://signal.meshque.dev)
    --listen <ADDR:PORT>    Local listen address (default: 0.0.0.0:443)
    --tun-name <NAME>       TUN device name (default: meshque0)
    --tun-address <CIDR>    Virtual IP (default: auto-assigned by peer negotiation)
    --mtu <SIZE>            TUN MTU (default: computed from QUIC datagram size)
    --verbose               Enable debug logging
```

### Minimal Flow (MVP)

```bash
# Machine A (will be the proxy/responder)
meshque connect secret-room-42

# Machine B (will be the client/initiator)
meshque connect secret-room-42

# After connection:
# Machine A: 100.64.0.1 on meshque0
# Machine B: 100.64.0.2 on meshque0
# Both can: ping 100.64.0.1 / ping 100.64.0.2
```

## Connection Sequence

```
Machine A                     Signaling Server                    Machine B
    │                               │                                 │
    │── POST /rooms/join ──────────►│                                 │
    │   {room: "secret-room-42"}    │                                 │
    │◄── {role: "responder",        │                                 │
    │     peer_id: "A"}             │                                 │
    │                               │                                 │
    │                               │◄── POST /rooms/join ────────────│
    │                               │    {room: "secret-room-42"}     │
    │                               │──► {role: "initiator",          │
    │                               │     peer_id: "B"}               │
    │                               │                                 │
    │── STUN binding ──────────────►│ (or public STUN server)         │
    │◄── reflexive addr A_pub ──────│                                 │
    │── POST /rooms/exchange ──────►│                                 │
    │   {endpoint: A_pub}           │                                 │
    │                               │◄── STUN binding ────────────────│
    │                               │──► reflexive addr B_pub ────────│
    │                               │◄── POST /rooms/exchange ────────│
    │                               │    {endpoint: B_pub}            │
    │◄── {peer_endpoint: B_pub} ────│                                 │
    │                               │──► {peer_endpoint: A_pub} ──────│
    │                               │                                 │
    │◄═══════════ UDP hole punch (simultaneous) ═════════════════════►│
    │                               │                                 │
    │◄══════════════ QUIC handshake ═════════════════════════════════►│
    │   (B connects to A as client, A is proxy)                       │
    │                               │                                 │
    │◄═══════════ CONNECT-IP session ════════════════════════════════►│
    │   (address assignment, route advertisement)                     │
    │                               │                                 │
    │◄═══════════ IP packets over HTTP datagrams ═══════════════════►│
```

## TUN Device

### Linux

Using `tun-rs` which wraps `/dev/net/tun` + `ioctl`:

```rust
let mut config = tun_rs::Configuration::default();
config.name("meshque0");
config.address_with_prefix(Ipv4Addr::new(100, 64, 0, 1), 10);
config.mtu(tunnel_mtu);
config.up();
let tun = tun_rs::create_as_async(&config)?;
```

Read/write is `AsyncRead`/`AsyncWrite` compatible — integrates with tokio natively.

### macOS

Same `tun-rs` crate, different backend (`utun` via system socket). The API is identical:

```rust
// Same code works on macOS — tun-rs handles platform differences
let tun = tun_rs::create_as_async(&config)?;
```

### MTU

The TUN MTU should be set to the tunnel MTU from `session.tunnel_mtu()`. For typical QUIC connections over the internet (1200-byte datagrams), the effective tunnel MTU is approximately 1198 bytes after HTTP/3 + Context ID overhead. This is below the IPv6 minimum of 1280, so only IPv4 traffic is reliable in Phase 1.

## CGNAT Addressing (100.64.0.0/10)

For Phase 1 (two peers only), addressing is simple:
- Responder (proxy): 100.64.0.1/32
- Initiator (client): 100.64.0.2/32

The proxy sends ADDRESS_ASSIGN to the client after session establishment. The client configures its TUN device with the assigned address.

For Phase 2 (mesh), a more sophisticated IPAM scheme will be needed.

## Self-Signed Certificates

Each peer generates an ephemeral self-signed certificate at startup for QUIC/TLS:

```rust
let cert = rcgen::generate_simple_self_signed(vec!["meshque-peer".into()])?;
```

The certificate fingerprint is exchanged via the signaling server during connection setup. The client pins to the expected fingerprint — no CA trust chain needed.

## Error Handling & Reconnection

- If the QUIC connection drops, the peer attempts to reconnect via the signaling server
- TUN device stays up during reconnection (no IP flap)
- Exponential backoff on reconnection attempts (1s, 2s, 4s, 8s, max 30s)
- Graceful shutdown on SIGTERM/SIGINT — clean QUIC close, TUN teardown

## Project Structure

```
meshque/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point (clap)
│   ├── config.rs            # Configuration types
│   ├── tunnel.rs            # Core packet loop (TUN ↔ CONNECT-IP)
│   ├── connection.rs        # Connection manager (signaling + NAT + QUIC)
│   ├── signaling.rs         # Signaling server HTTP client
│   ├── nat.rs               # STUN client + hole punching
│   └── tun.rs               # TUN device abstraction
└── connect-ip/              # (existing crate, workspace member)
```

## Testing Strategy

1. **Loopback tunnel test**: Create TUN, write IP packet, verify it arrives via CONNECT-IP session, and vice versa — all on localhost, no NAT
2. **Two-process test**: Start two `meshque` processes on the same machine with different TUN devices, verify `ping` works between them
3. **Manual NAT test**: Two machines on different networks, verify connectivity (requires real infrastructure)

## Scope Boundaries

**In scope:**
- Single binary, two-peer tunnel
- Linux + macOS TUN
- CGNAT addressing (hardcoded two-peer scheme)
- Self-signed certs with fingerprint pinning
- Signaling client (HTTP)
- STUN client + hole punching
- Reconnection logic

**Out of scope (Phase 2+):**
- Multi-peer mesh
- Persistent identity
- IP routing / forwarding between peers
- DNS resolution of peer names
- Access control
