pub mod address;
pub mod codec;
pub mod route;

/// Known capsule type values from RFC 9297 and RFC 9484.
pub mod capsule_type {
    /// HTTP Datagram capsule (RFC 9297 §3.5)
    pub const DATAGRAM: u64 = 0x00;
    /// Address assignment (RFC 9484 §4.7.1)
    pub const ADDRESS_ASSIGN: u64 = 0x01;
    /// Address request (RFC 9484 §4.7.2)
    pub const ADDRESS_REQUEST: u64 = 0x02;
    /// Route advertisement (RFC 9484 §4.7.3)
    pub const ROUTE_ADVERTISEMENT: u64 = 0x03;
}
