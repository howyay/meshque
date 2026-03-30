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

describe("POST /api/networks/join", () => {
  it("first peer creates network and gets IP .1", async () => {
    const res = await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("joined");
    expect(data.assigned_ip).toBe("100.64.0.1");
    expect(data.peers).toEqual([]);
  });

  it("second peer gets IP .2 and sees first peer", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("joined");
    expect(data.assigned_ip).toBe("100.64.0.2");
    expect(data.peers).toHaveLength(1);
    expect(data.peers[0].peer_id).toBe("peer-a");
    expect(data.peers[0].assigned_ip).toBe("100.64.0.1");
    expect(data.peers[0].cert_fingerprint).toBe("sha256:aaa");
  });

  it("third peer gets IP .3 and sees both existing peers", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-c",
      cert_fingerprint: "sha256:ccc",
    });
    const data = await json(res);
    expect(data.status).toBe("joined");
    expect(data.assigned_ip).toBe("100.64.0.3");
    expect(data.peers).toHaveLength(2);
    const ips = data.peers.map((p: Json) => p.assigned_ip).sort();
    expect(ips).toEqual(["100.64.0.1", "100.64.0.2"]);
  });

  it("wrong token is rejected", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/networks/join", {
      network: "testnet",
      token: "wrong-secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    expect(res.status).toBe(403);
  });

  it("peer can rejoin and keep same IP", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa-new",
    });
    const data = await json(res);
    expect(data.status).toBe("joined");
    expect(data.assigned_ip).toBe("100.64.0.1");
  });

  it("separate networks are independent", async () => {
    await post("/api/networks/join", {
      network: "net-1",
      token: "token-1",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/networks/join", {
      network: "net-2",
      token: "token-2",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    const data = await json(res);
    expect(data.assigned_ip).toBe("100.64.0.1"); // .1 in its own network
    expect(data.peers).toEqual([]);
  });

  it("rejects missing fields", async () => {
    const res = await post("/api/networks/join", { network: "testnet" });
    expect(res.status).toBe(400);
  });
});

describe("POST /api/networks/exchange", () => {
  it("stores endpoint and returns updated peer list", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/networks/exchange", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      endpoint: "1.2.3.4:5678",
      nat_type: "cone",
    });
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("ok");
    expect(data.peers).toHaveLength(1);
    expect(data.peers[0].peer_id).toBe("peer-b");
    expect(data.peers[0].endpoint).toBeNull(); // peer-b hasn't exchanged yet
  });

  it("shows peer endpoints after both exchange", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    await post("/api/networks/exchange", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      endpoint: "1.2.3.4:5678",
    });

    const res = await post("/api/networks/exchange", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      endpoint: "5.6.7.8:1234",
    });
    const data = await json(res);
    expect(data.peers[0].endpoint).toBe("1.2.3.4:5678");
  });

  it("rejects wrong token", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/networks/exchange", {
      network: "testnet",
      token: "wrong",
      peer_id: "peer-a",
      endpoint: "1.2.3.4:5678",
    });
    expect(res.status).toBe(403);
  });
});

describe("GET /api/networks/peers", () => {
  it("returns current peer list", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await get(
      "/api/networks/peers?network=testnet&token=secret&peer_id=peer-a",
    );
    expect(res.status).toBe(200);
    const data = await json(res);
    expect(data.status).toBe("ok");
    expect(data.assigned_ip).toBe("100.64.0.1");
    expect(data.peers).toHaveLength(1);
    expect(data.peers[0].peer_id).toBe("peer-b");
  });

  it("reflects new peers joining", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    // Initially alone
    let res = await get(
      "/api/networks/peers?network=testnet&token=secret&peer_id=peer-a",
    );
    let data = await json(res);
    expect(data.peers).toHaveLength(0);

    // Peer B joins
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    // Now sees peer B
    res = await get(
      "/api/networks/peers?network=testnet&token=secret&peer_id=peer-a",
    );
    data = await json(res);
    expect(data.peers).toHaveLength(1);
    expect(data.peers[0].peer_id).toBe("peer-b");
  });

  it("reflects peers leaving", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    await post("/api/networks/leave", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
    });

    const res = await get(
      "/api/networks/peers?network=testnet&token=secret&peer_id=peer-a",
    );
    const data = await json(res);
    expect(data.peers).toHaveLength(0);
  });

  it("rejects wrong token", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await get(
      "/api/networks/peers?network=testnet&token=wrong&peer_id=peer-a",
    );
    expect(res.status).toBe(403);
  });
});

describe("POST /api/networks/leave", () => {
  it("removes peer from network", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });

    const res = await post("/api/networks/leave", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
    });
    expect(res.status).toBe(200);
    expect((await json(res)).status).toBe("ok");

    // Peer B is now alone
    const peers = await get(
      "/api/networks/peers?network=testnet&token=secret&peer_id=peer-b",
    );
    const data = await json(peers);
    expect(data.peers).toHaveLength(0);
  });

  it("deletes network when last peer leaves", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    await post("/api/networks/leave", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
    });

    // Network gone
    const res = await get(
      "/api/networks/peers?network=testnet&token=secret&peer_id=peer-a",
    );
    expect(res.status).toBe(404);
  });

  it("rejects wrong token", async () => {
    await post("/api/networks/join", {
      network: "testnet",
      token: "secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });

    const res = await post("/api/networks/leave", {
      network: "testnet",
      token: "wrong",
      peer_id: "peer-a",
    });
    expect(res.status).toBe(403);
  });
});

describe("full mesh flow — 3 peers", () => {
  it("three peers join, exchange endpoints, and see each other", async () => {
    // Peer A creates network
    const joinA = await post("/api/networks/join", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-a",
      cert_fingerprint: "sha256:aaa",
    });
    const dataA = await json(joinA);
    expect(dataA.assigned_ip).toBe("100.64.0.1");
    expect(dataA.peers).toHaveLength(0);

    // Peer B joins
    const joinB = await post("/api/networks/join", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-b",
      cert_fingerprint: "sha256:bbb",
    });
    const dataB = await json(joinB);
    expect(dataB.assigned_ip).toBe("100.64.0.2");
    expect(dataB.peers).toHaveLength(1);

    // Peer C joins
    const joinC = await post("/api/networks/join", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-c",
      cert_fingerprint: "sha256:ccc",
    });
    const dataC = await json(joinC);
    expect(dataC.assigned_ip).toBe("100.64.0.3");
    expect(dataC.peers).toHaveLength(2);

    // All exchange endpoints
    await post("/api/networks/exchange", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-a",
      endpoint: "1.1.1.1:443",
      nat_type: "cone",
    });
    await post("/api/networks/exchange", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-b",
      endpoint: "2.2.2.2:443",
      nat_type: "cone",
    });
    await post("/api/networks/exchange", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-c",
      endpoint: "3.3.3.3:443",
      nat_type: "cone",
    });

    // Peer A sees B and C with endpoints
    const peersA = await get(
      "/api/networks/peers?network=mesh&token=mesh-secret&peer_id=peer-a",
    );
    const peersAData = await json(peersA);
    expect(peersAData.peers).toHaveLength(2);

    const endpoints = peersAData.peers.map((p: Json) => p.endpoint).sort();
    expect(endpoints).toEqual(["2.2.2.2:443", "3.3.3.3:443"]);

    // Peer C leaves
    await post("/api/networks/leave", {
      network: "mesh",
      token: "mesh-secret",
      peer_id: "peer-c",
    });

    // Peer A only sees B now
    const peersA2 = await get(
      "/api/networks/peers?network=mesh&token=mesh-secret&peer_id=peer-a",
    );
    const peersA2Data = await json(peersA2);
    expect(peersA2Data.peers).toHaveLength(1);
    expect(peersA2Data.peers[0].peer_id).toBe("peer-b");
  });
});
