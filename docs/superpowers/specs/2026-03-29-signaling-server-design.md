# Phase 1c Spec: meshque Signaling Server

A lightweight coordination service for peer discovery and NAT hole-punching. TypeScript on Cloudflare Workers (first target), portable to any runtime.

## Goal

Two peers running `meshque` can find each other using a shared room code, exchange network endpoints, and establish a direct connection — even when both are behind NAT. The signaling server facilitates this without ever seeing tunnel traffic.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Signaling Server                          │
├─────────────────────────────────────────────────────────────┤
│   Hono (HTTP framework)                                      │
│   ┌───────────────────────────────────────────────────────┐ │
│   │  POST /api/rooms/join          → join or create room  │ │
│   │  POST /api/rooms/exchange      → exchange endpoints   │ │
│   │  GET  /api/rooms/poll          → poll for peer info   │ │
│   │  POST /api/rooms/leave         → leave room           │ │
│   └───────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────┤
│   Storage Adapter (interface)                                │
│   ┌──────────────┬──────────────┬──────────────────────┐   │
│   │ Workers KV   │  In-Memory   │  Redis (future)      │   │
│   └──────────────┴──────────────┴──────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Stateless REST** — no WebSockets, no long-lived connections. Peers poll.
2. **Ephemeral rooms** — rooms auto-expire after 5 minutes of inactivity
3. **No tunnel traffic** — the server only relays metadata (endpoints, fingerprints)
4. **Platform-agnostic** — Hono runs on Workers, Node, Deno, Bun
5. **Zero auth infrastructure** — pre-shared room code is the only "auth" for MVP

## API

### POST /api/rooms/join

Join or create a room. First peer becomes responder, second becomes initiator.

**Request:**
```json
{
  "room_code": "secret-room-42",
  "peer_id": "random-uuid",
  "cert_fingerprint": "sha256:abcdef1234..."
}
```

**Response (first peer — room created, waiting):**
```json
{
  "status": "waiting",
  "role": "responder",
  "peer_id": "random-uuid"
}
```

**Response (second peer — room joined, peer info available):**
```json
{
  "status": "paired",
  "role": "initiator",
  "peer_id": "random-uuid",
  "peer": {
    "peer_id": "other-uuid",
    "cert_fingerprint": "sha256:fedcba4321..."
  }
}
```

**Response (room full):**
```json
{
  "status": "error",
  "message": "Room is full (max 2 peers for Phase 1)"
}
```

### POST /api/rooms/exchange

Exchange NAT traversal information after joining.

**Request:**
```json
{
  "room_code": "secret-room-42",
  "peer_id": "random-uuid",
  "endpoint": "203.0.113.5:12345",
  "nat_type": "cone"
}
```

**Response (peer hasn't exchanged yet):**
```json
{
  "status": "waiting"
}
```

**Response (peer has exchanged):**
```json
{
  "status": "ready",
  "peer_endpoint": "198.51.100.10:54321",
  "peer_nat_type": "cone"
}
```

### GET /api/rooms/poll

Poll for updates (used when the peer hasn't arrived yet).

**Query params:** `room_code`, `peer_id`

**Response:** Same as join response, but reflects current state. Returns peer info once available.

### POST /api/rooms/leave

Explicit cleanup (optional — rooms expire anyway).

## Data Model

```typescript
interface Room {
  code: string;
  created_at: number;          // unix timestamp
  expires_at: number;          // created_at + 300s
  peers: Peer[];               // max 2 for Phase 1
}

interface Peer {
  peer_id: string;
  role: "responder" | "initiator";
  cert_fingerprint: string;
  endpoint?: string;           // set after STUN discovery
  nat_type?: "cone" | "symmetric" | "unknown";
  joined_at: number;
}
```

### Storage

Rooms are stored as JSON blobs keyed by room code. For Workers KV:

```typescript
await kv.put(`room:${code}`, JSON.stringify(room), {
  expirationTtl: 300, // 5 min auto-expire
});
```

### Storage Adapter Interface

```typescript
interface StorageAdapter {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
}

// Implementations:
class WorkersKVAdapter implements StorageAdapter { ... }
class InMemoryAdapter implements StorageAdapter { ... }
```

## NAT Traversal

The signaling server's role in NAT traversal is minimal — it just relays endpoints. The actual STUN and hole-punching logic lives in the peer binary (Phase 1b).

### Flow

1. Each peer does STUN binding to discover its reflexive address (using a public STUN server like `stun.l.google.com:19302`)
2. Each peer sends its reflexive address to the signaling server via `/exchange`
3. The signaling server relays the other peer's address
4. Both peers simultaneously send UDP packets to each other's reflexive address
5. NAT creates mappings, QUIC handshake proceeds through the "hole"

### NAT Type Detection

The peer binary determines its NAT type by sending STUN bindings from the same local socket to multiple STUN servers. If all return the same reflexive address → cone NAT (hole-punchable). If they differ → symmetric NAT (warn the user).

The NAT type is reported to the signaling server so the other peer knows what to expect.

### When Hole-Punching Fails

For Phase 1:
- If both peers are behind symmetric NATs, the connection will fail
- The CLI prints a clear error: "Both peers are behind symmetric NATs. Direct connection is not possible. Relay support is coming in Phase 4."
- No relay fallback in Phase 1

## Security

### Room Code as Shared Secret

The room code is the only authentication. This is intentionally simple for MVP:
- Room codes should be reasonably long and random (e.g. 6+ words from a word list, or a UUID)
- The signaling server doesn't validate strength — that's the user's responsibility
- Room data is ephemeral (5-min TTL) — limited window for guessing

### Certificate Fingerprint Pinning

The real security is in the QUIC/TLS layer:
- Each peer generates an ephemeral self-signed cert
- The cert fingerprint is exchanged via the signaling server
- When the QUIC handshake happens, each peer verifies the other's cert matches the fingerprint
- Even if someone intercepts the signaling exchange, they can't MITM the QUIC connection without the private key

### Future (Phase 4)

- Replace room codes with OIDC SSO
- Persistent peer identities
- ACLs on the signaling server

## Project Structure

```
signaling/
├── package.json
├── tsconfig.json
├── src/
│   ├── app.ts                 # Hono app factory — pure, no runtime imports
│   ├── routes/
│   │   └── rooms.ts           # Room join/exchange/poll/leave handlers
│   ├── storage/
│   │   ├── adapter.ts         # StorageAdapter interface
│   │   ├── memory.ts          # In-memory (dev, self-hosted, Vercel serverless)
│   │   ├── workers-kv.ts      # Cloudflare Workers KV
│   │   └── redis.ts           # Redis/Upstash (VPS, Vercel KV)
│   ├── types.ts               # Room, Peer interfaces
│   └── validation.ts          # Request validation
├── entry/
│   ├── workers.ts             # Cloudflare Workers entry (wrangler)
│   ├── node.ts                # Node/Bun entry (standalone server)
│   └── vercel.ts              # Vercel serverless entry
├── wrangler.toml              # Workers deploy config (optional)
├── vercel.json                # Vercel deploy config (optional)
└── test/
    ├── rooms.test.ts          # API tests with in-memory storage
    └── storage.test.ts        # Storage adapter tests
```

### Runtime Isolation

The core app (`src/app.ts`) is a pure Hono app factory that takes a `StorageAdapter` parameter. It imports nothing from any runtime — no `process`, no `Deno`, no Workers globals:

```typescript
// src/app.ts — zero platform imports
import { Hono } from "hono";
import { roomRoutes } from "./routes/rooms";
import type { StorageAdapter } from "./storage/adapter";

export function createApp(storage: StorageAdapter) {
  const app = new Hono();
  app.route("/api/rooms", roomRoutes(storage));
  return app;
}
```

Each entry point wires the platform-specific storage:

```typescript
// entry/workers.ts
import { createApp } from "../src/app";
import { WorkersKVAdapter } from "../src/storage/workers-kv";
export default {
  fetch(req, env) {
    return createApp(new WorkersKVAdapter(env.ROOMS_KV)).fetch(req);
  },
};

// entry/node.ts
import { serve } from "@hono/node-server";
import { createApp } from "../src/app";
import { MemoryAdapter } from "../src/storage/memory";
serve(createApp(new MemoryAdapter()));

// entry/vercel.ts
import { handle } from "hono/vercel";
import { createApp } from "../src/app";
import { RedisAdapter } from "../src/storage/redis";
export default handle(createApp(new RedisAdapter(process.env.REDIS_URL)));
```

### Storage Adapters

All adapters implement the same interface. The core app never touches platform APIs:

| Adapter | Best For | TTL Support |
|---|---|---|
| `MemoryAdapter` | Dev, testing, single-process VPS | setTimeout-based expiry |
| `WorkersKVAdapter` | Cloudflare Workers | Native `expirationTtl` |
| `RedisAdapter` | VPS, Vercel, any hosted Redis | Native `EX` expiry |

## Deployment

### Cloudflare Workers

```bash
cd signaling && npx wrangler deploy
```

### Self-hosted VPS (Node/Bun)

```bash
cd signaling && npx tsx entry/node.ts
# Or with pm2: pm2 start entry/node.ts --interpreter tsx
```

Uses in-memory storage by default (fine for single-instance). Set `REDIS_URL` env var to use Redis for multi-instance.

### Vercel

```bash
cd signaling && npx vercel deploy
```

Uses Vercel KV (Redis) for storage. Set `REDIS_URL` via Vercel dashboard.

### Local Development

```bash
cd signaling && npm run dev  # starts Hono dev server with in-memory storage
```

## Testing Strategy

1. **Unit tests**: Room state machine (join → pair → exchange → ready) with in-memory adapter
2. **Integration tests**: Full HTTP API flow with the Hono test client
3. **End-to-end**: Two `meshque` peer processes connecting through a local signaling server (part of Phase 1b testing)

## Scope Boundaries

**In scope:**
- Room-based peer matching (2 peers per room)
- Endpoint exchange for NAT traversal
- Certificate fingerprint relay
- Workers KV storage
- In-memory storage for dev
- 5-minute room TTL

**Out of scope (Phase 2+):**
- Multi-peer rooms (mesh)
- Persistent peer identity
- OIDC/SSO authentication
- ACLs
- WebSocket push (peers poll for now)
- TURN relay
