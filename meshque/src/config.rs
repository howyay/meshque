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

/// Configuration for Phase 1 point-to-point connection.
pub struct Config {
    pub room_code: Option<String>,
    pub direct_addr: Option<String>,
    pub role: Role,
    pub signal_server: String,
    pub listen_addr: SocketAddr,
    pub tun_name: String,
}

/// Configuration for Phase 2 mesh networking.
pub struct MeshConfig {
    pub network: String,
    pub token: String,
    pub signal_server: String,
    pub listen_addr: SocketAddr,
    pub tun_name: String,
}
