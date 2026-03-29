use std::net::SocketAddr;
use std::str::FromStr;

use anyhow::bail;

/// Role in the connection: initiator (client) or responder (proxy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "initiator" | "client" => Ok(Role::Initiator),
            "responder" | "proxy" | "server" => Ok(Role::Responder),
            _ => bail!("invalid role '{}': expected 'initiator' or 'responder'", s),
        }
    }
}

/// Configuration for a meshque connection.
pub struct Config {
    /// Room code for signaling server (None if using --direct).
    pub room_code: Option<String>,
    /// Direct peer address (skips signaling).
    pub direct_addr: Option<String>,
    /// Role: initiator (connects to peer) or responder (listens for peer).
    pub role: Role,
    /// Signaling server URL.
    pub signal_server: String,
    /// Local listen address for proxy/responder mode.
    pub listen_addr: SocketAddr,
    /// TUN device name.
    pub tun_name: String,
}
