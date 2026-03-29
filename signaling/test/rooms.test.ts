import { describe, it, expect, beforeEach } from "vitest";
import { createApp } from "../src/app.js";
import { MemoryAdapter } from "../src/storage/memory.js";
import type { Hono } from "hono";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

let app: Hono;

beforeEach(() => {
  app = createApp(new MemoryAdapter());
});

function post(path: string, body: unknown) {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function get(path: string) {
  return app.request(path);
}

async function json(res: Response): Promise<Json> {
  return res.json();
}

describe("POST /api/rooms/join", () => {
  it("first peer creates room and becomes responder", async () => {
    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data).toEqual({
      status: "waiting",
      role: "responder",
      peer_id: "peer-a",
    });
  });

  it("second peer joins and becomes initiator with peer info", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data).toEqual({
      status: "paired",
      role: "initiator",
      peer_id: "peer-b",
      peer: {
        peer_id: "peer-a",
        cert_fingerprint: "sha256:aaa",
      },
    });
  });

  it("third peer is rejected (room full)", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-c",
      cert_fingerprint: "sha256:ccc",
    });
    expect(res.status).toBe(409);
    const data = await json(res);
    expect(data.status).toBe("error");
    expect(data.message).toContain("full");
  });

  it("same peer can rejoin and get current state", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    // Rejoin same room
    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("waiting");
    expect(data.role).toBe("responder");
  });

  it("rejoin after paired returns peer info", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    const data = await json(res);
    expect(data.status).toBe("paired");
    expect(data.peer.peer_id).toBe("peer-b");
  });

  it("rejects missing room_code", async () => {
    const res = await post("/api/rooms/join", {
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    expect(res.status).toBe(400);
  });

  it("rejects missing peer_id", async () => {
    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      cert_fingerprint: "sha256:aaa",
    });
    expect(res.status).toBe(400);
  });

  it("rejects missing cert_fingerprint", async () => {
    const res = await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
    });
    expect(res.status).toBe(400);
  });

  it("rejects invalid JSON body", async () => {
    const res = await app.request("/api/rooms/join", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json",
    });
    expect(res.status).toBe(400);
  });

  it("separate rooms are independent", async () => {
    await post("/api/rooms/join", {
      room_code: "room-1",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/rooms/join", {
      room_code: "room-2",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    const data = await json(res);
    expect(data.status).toBe("waiting");
    expect(data.role).toBe("responder");
  });
});

describe("POST /api/rooms/exchange", () => {
  it("stores endpoint and returns waiting when peer hasn't exchanged", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "203.0.113.5:12345",
      nat_type: "cone",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("waiting");
  });

  it("returns peer endpoint when both have exchanged", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "203.0.113.5:12345",
      nat_type: "cone",
    });

    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-b",
      endpoint: "198.51.100.10:54321",
      nat_type: "symmetric",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data).toEqual({
      status: "ready",
      peer_endpoint: "203.0.113.5:12345",
      peer_nat_type: "cone",
    });
  });

  it("first peer can re-exchange and get peer info", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "203.0.113.5:12345",
    });
    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-b",
      endpoint: "198.51.100.10:54321",
    });

    // Re-exchange from peer-a should now see peer-b's endpoint
    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "203.0.113.5:12345",
    });
    const data = await json(res);
    expect(data.status).toBe("ready");
    expect(data.peer_endpoint).toBe("198.51.100.10:54321");
  });

  it("rejects exchange for non-existent room", async () => {
    const res = await post("/api/rooms/exchange", {
      room_code: "ghost-room",
      peer_id: "peer-a",
      endpoint: "1.2.3.4:5678",
    });
    expect(res.status).toBe(404);
  });

  it("rejects exchange from unknown peer", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "intruder",
      endpoint: "1.2.3.4:5678",
    });
    expect(res.status).toBe(403);
  });

  it("rejects invalid endpoint format", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "not-an-endpoint",
    });
    expect(res.status).toBe(400);
  });

  it("nat_type defaults to unknown", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "1.2.3.4:5678",
      // no nat_type
    });
    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-b",
      endpoint: "5.6.7.8:1234",
    });

    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-b",
      endpoint: "5.6.7.8:1234",
    });
    const data = await json(res);
    expect(data.peer_nat_type).toBe("unknown");
  });

  it("accepts IPv6 endpoint", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "[::1]:443",
    });
    expect(res.status).toBe(200);
  });
});

describe("GET /api/rooms/poll", () => {
  it("returns waiting when alone in room", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await get(
      "/api/rooms/poll?room_code=test-room&peer_id=peer-a",
    );
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("waiting");
    expect(data.role).toBe("responder");
  });

  it("returns paired after second peer joins", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await get(
      "/api/rooms/poll?room_code=test-room&peer_id=peer-a",
    );
    const data = await json(res);
    expect(data.status).toBe("paired");
    expect(data.peer.peer_id).toBe("peer-b");
    expect(data.peer.cert_fingerprint).toBe("sha256:bbb");
  });

  it("returns ready after both exchange endpoints", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-a",
      endpoint: "1.2.3.4:5678",
      nat_type: "cone",
    });
    await post("/api/rooms/exchange", {
      room_code: "test-room",
      peer_id: "peer-b",
      endpoint: "5.6.7.8:1234",
      nat_type: "symmetric",
    });

    const res = await get(
      "/api/rooms/poll?room_code=test-room&peer_id=peer-a",
    );
    const data = await json(res);
    expect(data.status).toBe("ready");
    expect(data.peer.endpoint).toBe("5.6.7.8:1234");
    expect(data.peer.nat_type).toBe("symmetric");
  });

  it("returns 404 for non-existent room", async () => {
    const res = await get(
      "/api/rooms/poll?room_code=ghost-room&peer_id=peer-a",
    );
    expect(res.status).toBe(404);
  });

  it("returns 403 for unknown peer", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await get(
      "/api/rooms/poll?room_code=test-room&peer_id=intruder",
    );
    expect(res.status).toBe(403);
  });
});

describe("POST /api/rooms/leave", () => {
  it("removes peer from room", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/rooms/leave", {
      room_code: "test-room",
      peer_id: "peer-a",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("ok");

    // Peer-b should now be alone
    const poll = await get(
      "/api/rooms/poll?room_code=test-room&peer_id=peer-b",
    );
    const pollData = await json(poll);
    expect(pollData.status).toBe("waiting");
  });

  it("deletes room when last peer leaves", async () => {
    await post("/api/rooms/join", {
      room_code: "test-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    await post("/api/rooms/leave", {
      room_code: "test-room",
      peer_id: "peer-a",
    });

    // Room should be gone
    const res = await get(
      "/api/rooms/poll?room_code=test-room&peer_id=peer-a",
    );
    expect(res.status).toBe(404);
  });

  it("leave from non-existent room is ok", async () => {
    const res = await post("/api/rooms/leave", {
      room_code: "ghost-room",
      peer_id: "peer-a",
    });
    expect(res.status).toBe(200);
  });
});

describe("GET /health", () => {
  it("returns ok", async () => {
    const res = await get("/health");
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("ok");
  });
});

describe("full flow — end-to-end", () => {
  it("two peers join, exchange, and reach ready state", async () => {
    // Step 1: Peer A joins (becomes responder)
    const joinA = await post("/api/rooms/join", {
      room_code: "e2e-room",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaaa",
    });
    expect((await json(joinA)).status).toBe("waiting");

    // Step 2: Peer B joins (becomes initiator, gets A's info)
    const joinB = await post("/api/rooms/join", {
      room_code: "e2e-room",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbbb",
    });
    const joinBData = await json(joinB);
    expect(joinBData.status).toBe("paired");
    expect(joinBData.peer.cert_fingerprint).toBe("sha256:aaaa");

    // Step 3: Peer A polls and discovers B
    const pollA = await get(
      "/api/rooms/poll?room_code=e2e-room&peer_id=peer-a",
    );
    const pollAData = await json(pollA);
    expect(pollAData.status).toBe("paired");
    expect(pollAData.peer.peer_id).toBe("peer-b");

    // Step 4: Both exchange endpoints
    const exA = await post("/api/rooms/exchange", {
      room_code: "e2e-room",
      peer_id: "peer-a",
      endpoint: "203.0.113.5:12345",
      nat_type: "cone",
    });
    expect((await json(exA)).status).toBe("waiting");

    const exB = await post("/api/rooms/exchange", {
      room_code: "e2e-room",
      peer_id: "peer-b",
      endpoint: "198.51.100.10:54321",
      nat_type: "cone",
    });
    const exBData = await json(exB);
    expect(exBData.status).toBe("ready");
    expect(exBData.peer_endpoint).toBe("203.0.113.5:12345");

    // Step 5: Peer A polls and gets B's endpoint
    const pollA2 = await get(
      "/api/rooms/poll?room_code=e2e-room&peer_id=peer-a",
    );
    const pollA2Data = await json(pollA2);
    expect(pollA2Data.status).toBe("ready");
    expect(pollA2Data.peer.endpoint).toBe("198.51.100.10:54321");
    expect(pollA2Data.peer.nat_type).toBe("cone");
  });
});
