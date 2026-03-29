use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// STUN Binding Request (RFC 8489, simplified)
/// We only need the Binding method to discover our reflexive address.
const STUN_BINDING_REQUEST: [u8; 20] = [
    0x00, 0x01, // Type: Binding Request
    0x00, 0x00, // Length: 0 (no attributes)
    0x21, 0x12, 0xa4, 0x42, // Magic cookie
    // Transaction ID (12 bytes — random but fixed for our simple use)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Result of STUN discovery.
#[derive(Debug)]
pub struct StunResult {
    /// Our public (reflexive) address as seen by the STUN server.
    pub reflexive_addr: SocketAddr,
    /// NAT type classification.
    pub nat_type: NatType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// Same reflexive address from multiple STUN servers — hole-punchable.
    Cone,
    /// Different reflexive addresses — not reliably hole-punchable.
    Symmetric,
    /// Only got one response — can't determine.
    Unknown,
}

impl NatType {
    pub fn as_str(&self) -> &'static str {
        match self {
            NatType::Cone => "cone",
            NatType::Symmetric => "symmetric",
            NatType::Unknown => "unknown",
        }
    }
}

/// Discover our public address via STUN and classify NAT type.
/// Uses the provided socket so the reflexive address corresponds to the socket we'll use for QUIC.
pub async fn stun_discover(socket: &UdpSocket) -> Result<StunResult> {
    let mut reflexive_addrs = Vec::new();

    for server in STUN_SERVERS {
        match stun_binding(socket, server).await {
            Ok(addr) => {
                info!(server, reflexive = %addr, "STUN binding succeeded");
                reflexive_addrs.push(addr);
            }
            Err(e) => {
                warn!(server, error = %e, "STUN binding failed");
            }
        }
    }

    if reflexive_addrs.is_empty() {
        bail!("all STUN servers failed — cannot discover public address");
    }

    let first = reflexive_addrs[0];
    let nat_type = if reflexive_addrs.len() < 2 {
        NatType::Unknown
    } else if reflexive_addrs.iter().all(|a| a == &first) {
        NatType::Cone
    } else {
        NatType::Symmetric
    };

    info!(
        reflexive = %first,
        nat_type = nat_type.as_str(),
        responses = reflexive_addrs.len(),
        "NAT discovery complete"
    );

    Ok(StunResult {
        reflexive_addr: first,
        nat_type,
    })
}

/// Send a STUN Binding Request and parse the XOR-MAPPED-ADDRESS from the response.
async fn stun_binding(socket: &UdpSocket, server: &str) -> Result<SocketAddr> {
    let server_addr: SocketAddr = tokio::net::lookup_host(server)
        .await
        .context("DNS lookup failed")?
        .next()
        .context("no addresses for STUN server")?;

    // Build a STUN binding request with a random transaction ID
    let mut request = STUN_BINDING_REQUEST;
    // Randomize transaction ID
    let tid: [u8; 12] = rand_tid();
    request[8..20].copy_from_slice(&tid);

    socket.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .context("STUN timeout")?
        .context("recv failed")?;

    parse_stun_response(&buf[..n], &tid)
}

/// Parse a STUN Binding Response to extract XOR-MAPPED-ADDRESS.
fn parse_stun_response(data: &[u8], expected_tid: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < 20 {
        bail!("STUN response too short");
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != 0x0101 {
        bail!("not a STUN Binding Response (type: {msg_type:#06x})");
    }

    // Verify transaction ID
    if &data[8..20] != expected_tid {
        bail!("STUN transaction ID mismatch");
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        bail!("STUN response truncated");
    }

    // Parse attributes looking for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
    let mut offset = 20;
    let end = 20 + msg_len;

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let attr_start = offset + 4;

        if attr_start + attr_len > end {
            break;
        }

        match attr_type {
            0x0020 => {
                // XOR-MAPPED-ADDRESS
                return parse_xor_mapped_address(&data[attr_start..attr_start + attr_len]);
            }
            0x0001 => {
                // MAPPED-ADDRESS (fallback)
                return parse_mapped_address(&data[attr_start..attr_start + attr_len]);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundary
        offset = attr_start + ((attr_len + 3) & !3);
    }

    bail!("no MAPPED-ADDRESS or XOR-MAPPED-ADDRESS in STUN response");
}

fn parse_xor_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        bail!("XOR-MAPPED-ADDRESS too short");
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]) ^ 0x2112; // XOR with magic cookie upper 16 bits

    match family {
        0x01 => {
            // IPv4
            let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ 0x2112A442;
            let ip = std::net::Ipv4Addr::from(xor_ip);
            Ok(SocketAddr::new(ip.into(), xor_port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                bail!("XOR-MAPPED-ADDRESS IPv6 too short");
            }
            // XOR with magic cookie + transaction ID (but we don't reconstruct TID here)
            // For simplicity, fall back to MAPPED-ADDRESS for IPv6
            bail!("IPv6 XOR-MAPPED-ADDRESS parsing not implemented");
        }
        _ => bail!("unknown address family: {family}"),
    }
}

fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        bail!("MAPPED-ADDRESS too short");
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(ip.into(), port))
        }
        0x02 => {
            if data.len() < 20 {
                bail!("MAPPED-ADDRESS IPv6 too short");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => bail!("unknown address family: {family}"),
    }
}

/// Generate a random 12-byte transaction ID.
fn rand_tid() -> [u8; 12] {
    let mut tid = [0u8; 12];
    // Use wall-clock nanoseconds as a simple entropy source
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    tid[0..8].copy_from_slice(&(now as u64).to_le_bytes());
    // Mix in process ID
    let pid = std::process::id();
    tid[8..12].copy_from_slice(&pid.to_le_bytes());
    tid
}

/// Attempt UDP hole-punching by sending packets to the peer's reflexive address.
/// Both peers call this simultaneously. The first packet through creates the NAT mapping.
pub async fn hole_punch(socket: &UdpSocket, peer_addr: SocketAddr) -> Result<()> {
    info!(peer = %peer_addr, "Starting UDP hole punch");

    // Send a burst of empty UDP packets to the peer's reflexive address.
    // The NAT on our side creates a mapping, and if the peer does the same,
    // the QUIC handshake packets will pass through.
    for i in 0..10 {
        let payload = [0u8; 1]; // Minimal packet
        match socket.send_to(&payload, peer_addr).await {
            Ok(_) => debug!(attempt = i, "Sent hole-punch packet"),
            Err(e) => warn!(attempt = i, error = %e, "Hole-punch send failed"),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    info!("Hole punch sequence complete");
    Ok(())
}
