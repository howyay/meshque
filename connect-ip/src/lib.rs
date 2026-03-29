pub mod capsule;
pub mod client;
pub mod datagram;
pub mod error;
pub mod proxy;
pub mod session;
pub mod types;
pub mod varint;

pub use capsule::address::{AddressAssign, AddressRequest, AssignedAddress, RequestedAddress};
pub use capsule::route::{IpAddressRange, RouteAdvertisement};
pub use client::{ConnectIpClient, ConnectIpClientSession};
pub use error::Error;
pub use proxy::{ConnectIpProxy, ConnectIpRequest};
pub use session::{
    Capsule, CapsuleReader, CapsuleWriter, ConnectIpSession, IpDatagramReceiver,
    IpDatagramSender, SessionParts,
};
pub use types::IpVersion;
