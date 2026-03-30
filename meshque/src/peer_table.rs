use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use connect_ip_rs::session::IpDatagramSender;
use tokio::sync::RwLock;

/// Thread-safe routing table: virtual IP → tunnel sender.
#[derive(Clone)]
pub struct PeerTable {
    inner: Arc<RwLock<PeerTableState>>,
}

struct PeerEntry {
    sender: IpDatagramSender<h3_quinn::Connection>,
    peer_id: String,
    generation: u64,
}

struct PeerTableState {
    entries: HashMap<Ipv4Addr, PeerEntry>,
    next_generation: u64,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeerTableState {
                entries: HashMap::new(),
                next_generation: 1,
            })),
        }
    }

    /// Add or update a peer's tunnel sender.
    pub async fn insert(
        &self,
        ip: Ipv4Addr,
        peer_id: String,
        sender: IpDatagramSender<h3_quinn::Connection>,
    ) -> u64 {
        let mut table = self.inner.write().await;
        let generation = table.next_generation;
        table.next_generation += 1;
        table.entries.insert(
            ip,
            PeerEntry {
                sender,
                peer_id,
                generation,
            },
        );
        generation
    }

    pub async fn remove_if_generation(&self, ip: &Ipv4Addr, generation: u64) -> bool {
        let mut table = self.inner.write().await;
        let matches = table
            .entries
            .get(ip)
            .map(|entry| entry.generation == generation)
            .unwrap_or(false);
        if matches {
            table.entries.remove(ip);
            true
        } else {
            false
        }
    }

    /// Route a packet to the correct peer based on destination IP.
    /// Returns false if no route found.
    pub async fn route_packet(&self, packet: &[u8]) -> bool {
        if packet.len() < 20 {
            return false;
        }
        // Extract IPv4 destination address from packet header bytes [16..20]
        let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        let mut table = self.inner.write().await;
        if let Some(entry) = table.entries.get_mut(&dest_ip) {
            match entry.sender.send_ip_packet(packet) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(dest = %dest_ip, error = %e, "Failed to send to peer");
                    false
                }
            }
        } else {
            tracing::trace!(dest = %dest_ip, "No route for packet");
            false
        }
    }

    /// Get list of connected peer IPs.
    pub async fn connected_peers(&self) -> Vec<(Ipv4Addr, String)> {
        let table = self.inner.read().await;
        table
            .entries
            .iter()
            .map(|(ip, e)| (*ip, e.peer_id.clone()))
            .collect()
    }

    /// Wrap a datagram sender for the peer table (type alias for convenience).
    pub fn make_sender(
        sender: IpDatagramSender<h3_quinn::Connection>,
    ) -> IpDatagramSender<h3_quinn::Connection> {
        sender
    }
}
