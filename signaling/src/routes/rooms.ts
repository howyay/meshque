import { Hono } from "hono";
import type { StorageAdapter } from "../storage/adapter.js";
import type { Room, Peer } from "../types.js";
import {
  validateRoomCode,
  validatePeerId,
  validateCertFingerprint,
  validateEndpoint,
  validateNatType,
} from "../validation.js";

const ROOM_TTL_SECONDS = 300; // 5 minutes
const MAX_PEERS = 2;

function roomKey(code: string): string {
  return `room:${code}`;
}

async function getRoom(
  storage: StorageAdapter,
  code: string,
): Promise<Room | null> {
  const raw = await storage.get(roomKey(code));
  if (!raw) return null;
  return JSON.parse(raw) as Room;
}

async function putRoom(storage: StorageAdapter, room: Room): Promise<void> {
  const remainingTtl = Math.max(
    1,
    Math.ceil((room.expires_at - Date.now()) / 1000),
  );
  await storage.put(roomKey(room.code), JSON.stringify(room), remainingTtl);
}

function findPeer(room: Room, peerId: string): Peer | undefined {
  return room.peers.find((p) => p.peer_id === peerId);
}

function otherPeer(room: Room, peerId: string): Peer | undefined {
  return room.peers.find((p) => p.peer_id !== peerId);
}

export function roomRoutes(storage: StorageAdapter): Hono {
  const app = new Hono();

  // POST /join
  app.post("/join", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ status: "error", message: "Invalid JSON" }, 400);

    const { room_code, peer_id, cert_fingerprint } = body;

    if (!validateRoomCode(room_code))
      return c.json({ status: "error", message: "Invalid room_code" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);
    if (!validateCertFingerprint(cert_fingerprint))
      return c.json(
        { status: "error", message: "Invalid cert_fingerprint" },
        400,
      );

    let room = await getRoom(storage, room_code);

    // Peer rejoining the same room
    if (room && findPeer(room, peer_id)) {
      const peer = findPeer(room, peer_id)!;
      const other = otherPeer(room, peer_id);

      if (other) {
        return c.json({
          status: "paired",
          role: peer.role,
          peer_id: peer.peer_id,
          peer: {
            peer_id: other.peer_id,
            cert_fingerprint: other.cert_fingerprint,
          },
        });
      }
      return c.json({
        status: "waiting",
        role: peer.role,
        peer_id: peer.peer_id,
      });
    }

    if (!room) {
      // First peer creates the room, becomes responder
      const now = Date.now();
      room = {
        code: room_code,
        created_at: now,
        expires_at: now + ROOM_TTL_SECONDS * 1000,
        peers: [
          {
            peer_id,
            role: "responder",
            cert_fingerprint,
            joined_at: now,
          },
        ],
      };
      await putRoom(storage, room);
      return c.json({
        status: "waiting",
        role: "responder" as const,
        peer_id,
      });
    }

    if (room.peers.length >= MAX_PEERS) {
      return c.json(
        {
          status: "error",
          message: "Room is full (max 2 peers for Phase 1)",
        },
        409,
      );
    }

    // Second peer joins, becomes initiator
    const now = Date.now();
    const newPeer: Peer = {
      peer_id,
      role: "initiator",
      cert_fingerprint,
      joined_at: now,
    };
    room.peers.push(newPeer);
    // Refresh TTL
    room.expires_at = now + ROOM_TTL_SECONDS * 1000;
    await putRoom(storage, room);

    const other = otherPeer(room, peer_id)!;
    return c.json({
      status: "paired",
      role: "initiator" as const,
      peer_id,
      peer: {
        peer_id: other.peer_id,
        cert_fingerprint: other.cert_fingerprint,
      },
    });
  });

  // POST /exchange
  app.post("/exchange", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ status: "error", message: "Invalid JSON" }, 400);

    const { room_code, peer_id, endpoint, nat_type } = body;

    if (!validateRoomCode(room_code))
      return c.json({ status: "error", message: "Invalid room_code" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);
    if (!validateEndpoint(endpoint))
      return c.json({ status: "error", message: "Invalid endpoint" }, 400);
    if (nat_type !== undefined && !validateNatType(nat_type))
      return c.json({ status: "error", message: "Invalid nat_type" }, 400);

    const room = await getRoom(storage, room_code);
    if (!room)
      return c.json({ status: "error", message: "Room not found" }, 404);

    const peer = findPeer(room, peer_id);
    if (!peer)
      return c.json({ status: "error", message: "Peer not in room" }, 403);

    // Store this peer's endpoint
    peer.endpoint = endpoint;
    peer.nat_type = nat_type ?? "unknown";
    room.expires_at = Date.now() + ROOM_TTL_SECONDS * 1000;
    await putRoom(storage, room);

    const other = otherPeer(room, peer_id);
    if (other?.endpoint) {
      return c.json({
        status: "ready",
        peer_endpoint: other.endpoint,
        peer_nat_type: other.nat_type ?? "unknown",
      });
    }

    return c.json({ status: "waiting" });
  });

  // GET /poll
  app.get("/poll", async (c) => {
    const room_code = c.req.query("room_code");
    const peer_id = c.req.query("peer_id");

    if (!validateRoomCode(room_code))
      return c.json({ status: "error", message: "Invalid room_code" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);

    const room = await getRoom(storage, room_code);
    if (!room)
      return c.json({ status: "error", message: "Room not found" }, 404);

    const peer = findPeer(room, peer_id);
    if (!peer)
      return c.json({ status: "error", message: "Peer not in room" }, 403);

    const other = otherPeer(room, peer_id);

    // Check if peer has exchanged endpoints
    if (other?.endpoint && peer.endpoint) {
      return c.json({
        status: "ready",
        role: peer.role,
        peer: {
          peer_id: other.peer_id,
          cert_fingerprint: other.cert_fingerprint,
          endpoint: other.endpoint,
          nat_type: other.nat_type ?? "unknown",
        },
      });
    }

    if (other) {
      return c.json({
        status: "paired",
        role: peer.role,
        peer: {
          peer_id: other.peer_id,
          cert_fingerprint: other.cert_fingerprint,
        },
      });
    }

    return c.json({
      status: "waiting",
      role: peer.role,
      peer_id: peer.peer_id,
    });
  });

  // POST /leave
  app.post("/leave", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ status: "error", message: "Invalid JSON" }, 400);

    const { room_code, peer_id } = body;

    if (!validateRoomCode(room_code))
      return c.json({ status: "error", message: "Invalid room_code" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);

    const room = await getRoom(storage, room_code);
    if (!room) return c.json({ status: "ok" });

    room.peers = room.peers.filter((p) => p.peer_id !== peer_id);

    if (room.peers.length === 0) {
      await storage.delete(roomKey(room_code));
    } else {
      await putRoom(storage, room);
    }

    return c.json({ status: "ok" });
  });

  return app;
}
