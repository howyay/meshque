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
