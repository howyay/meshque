# Phase 2 Spec: Mesh Networking MVP

Evolve meshque from a point-to-point tunnel into a full-mesh VPN where N peers can join a network and reach each other by virtual IP.

## Goal

```bash
# Machine A
sudo meshque up --network mynet --token secret123

# Machine B
sudo meshque up --network mynet --token secret123

# Machine C
sudo meshque up --network mynet --token secret123

# All three can ping each other:
# A (100.64.0.1) ↔ B (100.64.0.2) ↔ C (100.64.0.3)
```

## Architecture

### Signaling Server

Replace 2-peer rooms with N-peer networks.

**Data model:**
```typescript
interface Network {
  name: string;
  token_hash: string;          // SHA-256 of the shared token
  created_at: number;
  peers: NetworkPeer[];
  next_ip: number;             // Next IP offset to assign (1, 2, 3...)
}

interface NetworkPeer {
  peer_id: string;
  assigned_ip: string;         // "100.64.0.X"
  cert_fingerprint: string;
  endpoint?: string;           // STUN-discovered public addr
  nat_type?: string;
  joined_at: number;
  last_seen: number;           // Heartbeat timestamp
}
```

**Endpoints:**

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/networks/join` | Join/create network, get assigned IP + peer list |
| POST | `/networks/exchange` | Submit STUN endpoint for pairwise connection |
| GET | `/networks/peers` | Poll for updated peer list (new joins, departures) |
| POST | `/networks/leave` | Leave the network |

**Authentication:** Token is hashed (SHA-256) before storage. Client sends raw token, server hashes and compares. This prevents token leakage from storage.

**IP allocation:** Sequential from 100.64.0.1. Server tracks `next_ip` counter. When a peer leaves, their IP is NOT recycled (simplicity — the /10 range has ~4M addresses).

**Join response includes full peer list** so the new peer knows who to connect to immediately.

**TTL:** Networks expire 1 hour after last heartbeat from any peer. Peers send heartbeats via `/networks/peers` poll (every 30s).

### Peer Binary

**Peer table:** `HashMap<Ipv4Addr, PeerTunnel>` mapping virtual IP → active tunnel.

```
┌──────────────────────────────────────────────────────┐
│                    meshque binary                     │
├──────────────────────────────────────────────────────┤
│   CLI: up / down / status / peers                    │
├──────────────────────────────────────────────────────┤
│                  Network Manager                     │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Signaling│  │  Peer Table  │  │  Connection   │  │
│  │  Poller  │──│  (IP→Tunnel) │──│   Factory     │  │
│  └──────────┘  └──────────────┘  └───────────────┘  │
├──────────────────────────────────────────────────────┤
│   TUN Device + Packet Router                         │
│   read packet → lookup dest IP → send to tunnel      │
│   recv from any tunnel → write to TUN                │
├──────────────────────────────────────────────────────┤
│   Per-Peer CONNECT-IP Tunnels                        │
│   [Peer B tunnel] [Peer C tunnel] [Peer D tunnel]   │
└──────────────────────────────────────────────────────┘
```

**Packet routing:**
1. TUN read → extract IPv4 dest from packet header bytes [16..20]
2. Look up dest in peer table → get tunnel
3. Send packet via that tunnel's datagram sender
4. If dest not found → drop (or ICMP unreachable in future)

**Inbound:** All tunnels feed into a single TUN write path. Each tunnel's recv task writes to the shared TUN device.

**Signaling poller:** Background task polls `/networks/peers` every 30s. When new peers appear, spawn connection task. When peers disappear, tear down tunnel.

**Connection factory:** For each new peer, performs STUN + hole punch + QUIC + CONNECT-IP handshake. The peer with the lower IP is always the initiator (deterministic role assignment — no signaling coordination needed).

### CLI

```
meshque up --network <name> --token <token> [OPTIONS]
  --signal-server <URL>    Default: https://meshque-signaling.haoye.workers.dev
  --listen <ADDR:PORT>     Default: 0.0.0.0:443
  --tun-name <NAME>        Default: meshque0
  -v, --verbose            Debug logging

meshque down
  (sends /networks/leave, tears down TUN)

meshque status
  Shows: network name, local IP, # connected peers, uptime

meshque peers
  Shows: table of peers with IP, endpoint, latency, status
```

`meshque up` runs as a foreground daemon. `meshque down/status/peers` are one-shot commands that communicate with the running daemon via a local Unix socket (or just query the signaling server directly for MVP simplicity).

For MVP: `status` and `peers` will query the signaling server directly (no daemon socket). `down` will just be Ctrl-C on the `up` process.

## Connection Sequence (N peers)

```
Peer C joins a network where A and B already exist:

1. C → POST /networks/join {network: "mynet", token: "secret123", ...}
   ← {assigned_ip: "100.64.0.3", peers: [{ip: "100.64.0.1", ...}, {ip: "100.64.0.2", ...}]}

2. C does STUN discovery → gets reflexive addr C_pub

3. C → POST /networks/exchange {endpoint: C_pub, ...}

4. C needs to connect to A and B. For each:
   a. C polls /networks/peers to get A's endpoint
   b. Hole punch C ↔ A
   c. Lower-IP peer initiates QUIC (A initiates to C since 100.64.0.1 < 100.64.0.3)
   d. CONNECT-IP session established
   e. No ADDRESS_ASSIGN needed — IPs already assigned by signaling server

5. Meanwhile A and B see C in their poll responses → they also initiate connections to C
   (deterministic: A initiates to C, C initiates to B since 100.64.0.3 > 100.64.0.2)
```

**Role determination:** The peer with the LOWER virtual IP is always the QUIC client (initiator). This is deterministic — both peers independently compute the same answer with no coordination.

**No ADDRESS_ASSIGN in mesh mode:** The signaling server assigns IPs. The CONNECT-IP session is used purely for IP packet tunneling. Capsule exchange is skipped.

## Scope

**In scope:**
- N-peer full mesh (every peer connects to every other peer)
- Server-side IP allocation
- Token-based network authentication
- Automatic peer discovery via polling
- Deterministic role assignment (lower IP = initiator)
- Per-peer CONNECT-IP tunnels
- TUN packet routing by destination IP
- CLI: up, status, peers

**Out of scope (future):**
- Relay through intermediate peers (for symmetric NAT)
- Persistent identity
- ACLs / access policies
- DNS (peer name resolution)
- WireGuard stacking
- Daemon mode with IPC socket
