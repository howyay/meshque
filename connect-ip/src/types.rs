use std::net::IpAddr;

/// IP version identifier used in capsule wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

impl IpVersion {
    /// Parse from wire format byte. Returns None for invalid values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            4 => Some(Self::V4),
            6 => Some(Self::V6),
            _ => None,
        }
    }

    /// Byte length of an IP address for this version.
    pub fn addr_len(self) -> usize {
        match self {
            Self::V4 => 4,
            Self::V6 => 16,
        }
    }

    /// Maximum valid prefix length for this version.
    pub fn max_prefix_len(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

impl From<&IpAddr> for IpVersion {
    fn from(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

/// The `:protocol` value for CONNECT-IP Extended CONNECT requests.
pub const CONNECT_IP_PROTOCOL: &str = "connect-ip";

/// Default URI template path for CONNECT-IP.
pub const DEFAULT_URI_TEMPLATE: &str = "/.well-known/masque/ip/{target}/{ipproto}/";
