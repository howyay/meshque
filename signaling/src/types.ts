// Phase 1: Point-to-point rooms
export interface Peer {
  peer_id: string;
  role: "responder" | "initiator";
  cert_fingerprint: string;
  endpoint?: string;
  nat_type?: "cone" | "symmetric" | "unknown";
  joined_at: number;
}

export interface Room {
  code: string;
  created_at: number;
  expires_at: number;
  peers: Peer[];
}

// Phase 2: Mesh networks
export interface NetworkPeer {
  peer_id: string;
  assigned_ip: string;
  cert_fingerprint: string;
  endpoint?: string;
  nat_type?: "cone" | "symmetric" | "unknown";
  joined_at: number;
  last_seen: number;
}

export interface Network {
  name: string;
  token_hash: string;
  created_at: number;
  expires_at: number;
  peers: NetworkPeer[];
  next_ip: number;
}
