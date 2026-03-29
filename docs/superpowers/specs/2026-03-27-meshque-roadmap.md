# meshque — Project Roadmap

A mesh VPN that tunnels IP traffic over MASQUE (CONNECT-IP / RFC 9484) on HTTP/3 port 443, with support for stacking third-party WireGuard VPNs.

## Architecture

meshque consists of two main components:

### Peer Software (Rust)

A single binary that runs on each device in the mesh. Every peer acts as both a MASQUE CONNECT-IP client (initiator) and proxy (responder). The distinction is only about who initiates the QUIC connection — once established, the tunnel is fully bidirectional.

Each peer:
- Creates a TUN device and assigns a CGNAT address (100.64.0.0/10)
- Establishes MASQUE CONNECT-IP sessions over HTTP/3 on port 443
- Reads IP packets from TUN, encapsulates them in HTTP datagrams, sends to peer
- Receives HTTP datagrams from peer, decapsulates, writes IP packets to TUN

Platform-specific code is isolated to TUN device setup:
- Linux: `/dev/net/tun` via `ioctl`
- macOS: `utun` via system socket

Key libraries: `quinn` (QUIC), `h3` (HTTP/3).

### Signaling Server (TypeScript)

A lightweight coordination service for peer discovery and NAT hole-punching. Platform-agnostic — deployable to Cloudflare Workers, Vercel, Netlify, bare metal, or any VPS.

Responsibilities:
- Room creation via pre-shared codes (MVP auth)
- Relay peer IP:port for STUN-based NAT hole-punching
- NAT type detection assistance (respond to binding requests from multiple endpoints)

Architecture:
- Pure TypeScript core with no platform-specific APIs
- Hono (or similar) for HTTP portability across runtimes
- Adapter pattern for platform-specific storage (Workers KV, Vercel KV, Redis, in-memory)
- Stateless REST API — room state is ephemeral

## Protocol Stack

```
┌─────────────────────────┐
│   Applications          │  (use the network normally)
├─────────────────────────┤
│   TUN Device            │  (virtual network interface)
├─────────────────────────┤
│   IP Routing            │  (CGNAT 100.64.0.0/10)
├─────────────────────────┤
│   MASQUE CONNECT-IP     │  (RFC 9484 — full IP packets in HTTP datagrams)
├─────────────────────────┤
│   HTTP/3                │  (Extended CONNECT)
├─────────────────────────┤
│   QUIC                  │  (encrypted, multiplexed, on port 443)
├─────────────────────────┤
│   UDP                   │  (underlying transport)
└─────────────────────────┘
```

All traffic appears as standard HTTPS on port 443 to network observers.

## NAT Traversal (MVP)

STUN-based UDP hole-punching for cone NATs:

1. Both peers register with the signaling server, providing a room code
2. Each peer sends STUN-like binding requests to discover their public IP:port
3. Signaling server relays each peer's public endpoint to the other
4. Both peers simultaneously send UDP packets to each other's public endpoint
5. NAT mappings are created, QUIC handshake proceeds through the punched hole

NAT type detection is built into the client — if a symmetric NAT is detected, the user is warned that connectivity may fail. Relay fallback is deferred to Phase 4.

## Roadmap

### Phase 1 — Point-to-Point Tunnel

Two peers establish an IP tunnel over MASQUE CONNECT-IP.

Scope:
- **`connect-ip` crate** — standalone Rust library implementing RFC 9484 (CONNECT-IP) on top of quinn + h3. Published as an independent crate, usable outside meshque. Client and proxy APIs.
- MASQUE CONNECT-IP client + proxy in Rust using the above crate
- TUN device: macOS for initiator, Linux for responder
- Signaling server on Cloudflare Workers (first deployment target)
- STUN-based NAT hole-punching (cone NAT support)
- NAT type detection on client
- CGNAT addressing (100.64.0.0/10)
- Pre-shared token auth via signaling server

Deliverables:
- `connect-ip` crate: the first production-quality Rust implementation of RFC 9484
- Two machines behind NATs can ping each other over virtual IPs, all traffic concealed as HTTPS on port 443

### Phase 2 — Mesh Networking

Multiple peers form a mesh where every peer is both MASQUE client and proxy.

Scope:
- Multi-peer coordination (evolve signaling server into control plane)
- Mesh routing — path selection, relay through intermediate peers
- Peer discovery and registration
- Persistent peer identity
- Connection health monitoring and automatic failover

Deliverable: 3+ devices form a mesh network. Any device can reach any other, with automatic relay through intermediate peers when direct connection fails.

### Phase 3 — WireGuard VPN Stacking

Users bring their own WireGuard VPN provider alongside the mesh.

Scope:
- WireGuard config import (`.conf` files from Mullvad, ProtonVPN, IVPN, etc.)
- Split tunnel routing: mesh subnet (CGNAT) via MASQUE, default route via WireGuard
- Adaptive IP routing when both tunnels are active
- Provider-agnostic — any WireGuard config works

Deliverable: User connects to mesh VPN and their chosen WireGuard provider simultaneously. Mesh traffic routes through MASQUE, general internet through WireGuard. No conflicts.

### Phase 4 — Product Features

Scope:
- OIDC SSO (gate control plane behind identity provider)
- Transparent SSH (no CA setup on target machines)
- ACLs / access policies
- DNS (MagicDNS-equivalent — resolve peers by name)
- Symmetric NAT relay fallback

## Deferred

- Licensing decision
- Browser-based client
- Mobile platforms (iOS, Android)

## Reference Implementations

- **Headscale** (BSD 3-Clause) — coordination server design
- **NetBird** (BSD 3-Clause client, AGPL server) — peer agent architecture, TUN device management, server design. Safe to reference since meshque will be open source.
- **quic-go/connect-ip-go** (MIT) — Go CONNECT-IP implementation, v0.1.0. Reference for protocol details, not production-quality.
- **Usque** (Go) — reverse-engineered Cloudflare WARP MASQUE client. Reference for CONNECT-IP/WARP interop details.
- **masque-vpn** (Go) — educational MASQUE VPN. Reference for architecture patterns.
- **masquerade** (Rust, quiche) — only Rust MASQUE impl, CONNECT-UDP only, early prototype. Reference for Rust-specific patterns.
