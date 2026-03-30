import { Hono } from "hono";
import type { StorageAdapter } from "../storage/adapter.js";
import type { Network, NetworkPeer } from "../types.js";
import {
  validatePeerId,
  validateCertFingerprint,
  validateEndpoint,
  validateNatType,
} from "../validation.js";

const NETWORK_TTL_SECONDS = 3600; // 1 hour since last activity
const CGNAT_BASE = "100.64.0.";

function networkKey(name: string): string {
  return `net:${name}`;
}

async function getNetwork(
  storage: StorageAdapter,
  name: string,
): Promise<Network | null> {
  const raw = await storage.get(networkKey(name));
  if (!raw) return null;
  return JSON.parse(raw) as Network;
}

async function putNetwork(
  storage: StorageAdapter,
  network: Network,
): Promise<void> {
  const remainingTtl = Math.max(
    1,
    Math.ceil((network.expires_at - Date.now()) / 1000),
  );
  await storage.put(
    networkKey(network.name),
    JSON.stringify(network),
    remainingTtl,
  );
}

function validateNetworkName(name: unknown): name is string {
  return typeof name === "string" && name.length >= 1 && name.length <= 256;
}

function validateToken(token: unknown): token is string {
  return typeof token === "string" && token.length >= 1 && token.length <= 512;
}

async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function networkRoutes(storage: StorageAdapter): Hono {
  const app = new Hono();

  // POST /join — join or create a network
  app.post("/join", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ status: "error", message: "Invalid JSON" }, 400);

    const { network: networkName, token, peer_id, cert_fingerprint } = body;

    if (!validateNetworkName(networkName))
      return c.json({ status: "error", message: "Invalid network name" }, 400);
    if (!validateToken(token))
      return c.json({ status: "error", message: "Invalid token" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);
    if (!validateCertFingerprint(cert_fingerprint))
      return c.json(
        { status: "error", message: "Invalid cert_fingerprint" },
        400,
      );

    const tokenHash = await hashToken(token);
    const now = Date.now();

    let network = await getNetwork(storage, networkName);

    if (network) {
      // Verify token
      if (network.token_hash !== tokenHash) {
        return c.json(
          { status: "error", message: "Invalid token for this network" },
          403,
        );
      }

      // Check if peer is rejoining
      const existing = network.peers.find((p) => p.peer_id === peer_id);
      if (existing) {
        existing.cert_fingerprint = cert_fingerprint;
        existing.last_seen = now;
        existing.endpoint = undefined; // Reset endpoint on rejoin
        network.expires_at = now + NETWORK_TTL_SECONDS * 1000;
        await putNetwork(storage, network);

        const otherPeers = network.peers
          .filter((p) => p.peer_id !== peer_id)
          .map(peerView);

        return c.json({
          status: "joined",
          assigned_ip: existing.assigned_ip,
          peers: otherPeers,
        });
      }

      // New peer joining existing network
      const assignedIp = `${CGNAT_BASE}${network.next_ip}`;
      const newPeer: NetworkPeer = {
        peer_id,
        assigned_ip: assignedIp,
        cert_fingerprint,
        joined_at: now,
        last_seen: now,
      };
      network.peers.push(newPeer);
      network.next_ip++;
      network.expires_at = now + NETWORK_TTL_SECONDS * 1000;
      await putNetwork(storage, network);

      const otherPeers = network.peers
        .filter((p) => p.peer_id !== peer_id)
        .map(peerView);

      return c.json({
        status: "joined",
        assigned_ip: assignedIp,
        peers: otherPeers,
      });
    }

    // Create new network
    const assignedIp = `${CGNAT_BASE}1`;
    const newNetwork: Network = {
      name: networkName,
      token_hash: tokenHash,
      created_at: now,
      expires_at: now + NETWORK_TTL_SECONDS * 1000,
      peers: [
        {
          peer_id,
          assigned_ip: assignedIp,
          cert_fingerprint,
          joined_at: now,
          last_seen: now,
        },
      ],
      next_ip: 2,
    };
    await putNetwork(storage, newNetwork);

    return c.json({
      status: "joined",
      assigned_ip: assignedIp,
      peers: [],
    });
  });

  // POST /exchange — submit STUN-discovered endpoint
  app.post("/exchange", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ status: "error", message: "Invalid JSON" }, 400);

    const { network: networkName, token, peer_id, endpoint, nat_type } = body;

    if (!validateNetworkName(networkName))
      return c.json({ status: "error", message: "Invalid network name" }, 400);
    if (!validateToken(token))
      return c.json({ status: "error", message: "Invalid token" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);
    if (!validateEndpoint(endpoint))
      return c.json({ status: "error", message: "Invalid endpoint" }, 400);
    if (nat_type !== undefined && !validateNatType(nat_type))
      return c.json({ status: "error", message: "Invalid nat_type" }, 400);

    const tokenHash = await hashToken(token);
    const network = await getNetwork(storage, networkName);

    if (!network)
      return c.json({ status: "error", message: "Network not found" }, 404);
    if (network.token_hash !== tokenHash)
      return c.json({ status: "error", message: "Invalid token" }, 403);

    const peer = network.peers.find((p) => p.peer_id === peer_id);
    if (!peer)
      return c.json({ status: "error", message: "Peer not in network" }, 403);

    peer.endpoint = endpoint;
    peer.nat_type = nat_type ?? "unknown";
    peer.last_seen = Date.now();
    network.expires_at = Date.now() + NETWORK_TTL_SECONDS * 1000;
    await putNetwork(storage, network);

    const otherPeers = network.peers
      .filter((p) => p.peer_id !== peer_id)
      .map(peerView);

    return c.json({
      status: "ok",
      peers: otherPeers,
    });
  });

  // GET /peers — poll for updated peer list (also serves as heartbeat)
  app.get("/peers", async (c) => {
    const networkName = c.req.query("network");
    const token = c.req.query("token");
    const peer_id = c.req.query("peer_id");

    if (!validateNetworkName(networkName))
      return c.json({ status: "error", message: "Invalid network name" }, 400);
    if (!validateToken(token))
      return c.json({ status: "error", message: "Invalid token" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);

    const tokenHash = await hashToken(token!);
    const network = await getNetwork(storage, networkName!);

    if (!network)
      return c.json({ status: "error", message: "Network not found" }, 404);
    if (network.token_hash !== tokenHash)
      return c.json({ status: "error", message: "Invalid token" }, 403);

    const peer = network.peers.find((p) => p.peer_id === peer_id);
    if (!peer)
      return c.json({ status: "error", message: "Peer not in network" }, 403);

    // Update heartbeat
    peer.last_seen = Date.now();
    network.expires_at = Date.now() + NETWORK_TTL_SECONDS * 1000;
    await putNetwork(storage, network);

    const otherPeers = network.peers
      .filter((p) => p.peer_id !== peer_id)
      .map(peerView);

    return c.json({
      status: "ok",
      assigned_ip: peer.assigned_ip,
      peers: otherPeers,
    });
  });

  // POST /leave — leave the network
  app.post("/leave", async (c) => {
    const body = await c.req.json().catch(() => null);
    if (!body) return c.json({ status: "error", message: "Invalid JSON" }, 400);

    const { network: networkName, token, peer_id } = body;

    if (!validateNetworkName(networkName))
      return c.json({ status: "error", message: "Invalid network name" }, 400);
    if (!validateToken(token))
      return c.json({ status: "error", message: "Invalid token" }, 400);
    if (!validatePeerId(peer_id))
      return c.json({ status: "error", message: "Invalid peer_id" }, 400);

    const tokenHash = await hashToken(token);
    const network = await getNetwork(storage, networkName);
    if (!network) return c.json({ status: "ok" });
    if (network.token_hash !== tokenHash)
      return c.json({ status: "error", message: "Invalid token" }, 403);

    network.peers = network.peers.filter((p) => p.peer_id !== peer_id);

    if (network.peers.length === 0) {
      await storage.delete(networkKey(networkName));
    } else {
      network.expires_at = Date.now() + NETWORK_TTL_SECONDS * 1000;
      await putNetwork(storage, network);
    }

    return c.json({ status: "ok" });
  });

  return app;
}

function peerView(p: NetworkPeer) {
  return {
    peer_id: p.peer_id,
    assigned_ip: p.assigned_ip,
    cert_fingerprint: p.cert_fingerprint,
    endpoint: p.endpoint ?? null,
    nat_type: p.nat_type ?? "unknown",
  };
}
