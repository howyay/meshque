# Phase 1a Spec: `connect-ip` Crate

A production-quality Rust implementation of RFC 9484 (Proxying IP in HTTP / CONNECT-IP) built on `quinn` and `h3`.

## Goal

Provide a standalone, reusable Rust crate (`connect-ip`) that implements the CONNECT-IP protocol over HTTP/3. It should be publishable to crates.io independently of meshque, usable by anyone who wants to tunnel IP packets through an HTTP/3 proxy.

## Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `quinn` | 0.11.x | QUIC transport (DATAGRAM frames, connection management) |
| `h3` | 0.0.8 | HTTP/3 protocol (Extended CONNECT, request/response) |
| `h3-quinn` | — | Quinn transport adapter for h3 |
| `h3-datagram` | 0.0.2 | HTTP Datagrams (RFC 9297) for IP packet transport |
| `tokio` | 1.x | Async runtime |
| `bytes` | 1.x | Buffer management |

## Architecture

The crate exposes two primary APIs: **Client** (initiator) and **Proxy** (responder). Both share the capsule protocol and datagram framing layers.

```
┌──────────────────────────────────────────┐
│              connect-ip crate            │
├────────────────┬─────────────────────────┤
│   Client API   │      Proxy API          │
├────────────────┴─────────────────────────┤
│          Session Management              │
│  (address negotiation, route exchange)   │
├──────────────────────────────────────────┤
│         Capsule Protocol Layer           │
│  (encode/decode RFC 9297 capsules)       │
├──────────────────────────────────────────┤
│       IP Datagram Framing Layer          │
│  (Context ID + IP packet in HTTP DG)     │
├──────────────────────────────────────────┤
│     h3 + h3-datagram + h3-quinn          │
├──────────────────────────────────────────┤
│               quinn (QUIC)               │
└──────────────────────────────────────────┘
```

### Module Structure

```
connect-ip/
├── src/
│   ├── lib.rs              # Public API re-exports
│   ├── client.rs           # Client (initiator) API
│   ├── proxy.rs            # Proxy (responder) API
│   ├── session.rs          # Shared session state, lifecycle
│   ├── capsule/
│   │   ├── mod.rs          # Capsule protocol framing (RFC 9297 §3)
│   │   ├── codec.rs        # Encode/decode capsule TLV frames
│   │   ├── address.rs      # ADDRESS_ASSIGN (0x01), ADDRESS_REQUEST (0x02)
│   │   └── route.rs        # ROUTE_ADVERTISEMENT (0x03)
│   ├── datagram.rs         # IP-in-HTTP-datagram framing (Context ID + packet)
│   ├── types.rs            # Shared types (IpAddress, IpRange, Protocol constants)
│   └── error.rs            # Error types
├── tests/
│   ├── loopback.rs         # Client <-> Proxy over localhost
│   ├── capsule_codec.rs    # Unit tests for capsule encoding/decoding
│   ├── datagram_framing.rs # Unit tests for IP datagram framing
│   ├── address_negotiation.rs # Address assign/request flows
│   ├── route_exchange.rs   # Route advertisement flows
│   └── interop/
│       └── go_proxy.rs     # Test against connect-ip-go proxy
├── fuzz/
│   ├── fuzz_capsule.rs     # Fuzz capsule parser
│   └── fuzz_datagram.rs    # Fuzz datagram parser
├── benches/
│   └── throughput.rs       # Throughput benchmark (packets/sec, bytes/sec)
├── examples/
│   ├── simple_client.rs    # Minimal client example
│   └── simple_proxy.rs     # Minimal proxy example
└── Cargo.toml
```

## Protocol Implementation Details

### Extended CONNECT Handling

h3 supports Extended CONNECT but has no `Protocol::CONNECT_IP` constant. The crate will parse the `:protocol` header manually:

```rust
// Check for connect-ip protocol on incoming request
let protocol = request.extensions().get::<h3::ext::Protocol>();
match protocol {
    Some(p) if p.as_str() == "connect-ip" => { /* handle */ }
    _ => { /* reject */ }
}
```

The crate follows the pattern established by `h3-webtransport` for session management: wrap the h3 connection, validate the protocol header, and create a session scoped to the HTTP stream.

### Capsule Protocol Layer (RFC 9297 §3 — new code)

This is the biggest gap in the Rust ecosystem. The crate implements the capsule protocol framing from scratch:

**Wire format:**
```
Capsule {
  Capsule Type (variable-length integer),
  Capsule Length (variable-length integer),
  Capsule Value (Capsule Length bytes),
}
```

**Capsule types implemented:**

| Type | Value | Direction | Purpose |
|------|-------|-----------|---------|
| `DATAGRAM` | 0x00 | Both | HTTP Datagram payload (fallback when QUIC DG unavailable) |
| `ADDRESS_ASSIGN` | 0x01 | Both | Assign IP addresses/prefixes to peer |
| `ADDRESS_REQUEST` | 0x02 | Both | Request IP address assignment |
| `ROUTE_ADVERTISEMENT` | 0x03 | Both | Advertise reachable IP ranges |

Unknown capsule types are silently skipped per RFC 9297.

**Codec design:**
- Streaming decoder: reads from the HTTP stream incrementally, does not buffer entire capsule before processing (per RFC 9297 SHOULD)
- Encoder: writes capsule frames to the HTTP stream
- Variable-length integer encoding/decoding per QUIC RFC 9000 §16

### CONNECT-IP Capsules (RFC 9484 §4.7)

**ADDRESS_ASSIGN (0x01):**
```rust
pub struct AddressAssign {
    pub addresses: Vec<AssignedAddress>,
}

pub struct AssignedAddress {
    pub request_id: u64,       // 0 if unsolicited
    pub ip_version: IpVersion, // 4 or 6
    pub address: IpAddr,
    pub prefix_length: u8,
}
```
Each capsule carries the full set of assigned addresses. Omitted addresses from a previous capsule are implicitly removed.

**ADDRESS_REQUEST (0x02):**
```rust
pub struct AddressRequest {
    pub addresses: Vec<RequestedAddress>, // must be non-empty
}

pub struct RequestedAddress {
    pub request_id: u64,       // unique, non-zero, never reused
    pub ip_version: IpVersion,
    pub address: IpAddr,       // all-zeros = "assign any"
    pub prefix_length: u8,
}
```
Must contain at least one entry. Receiver responds with ADDRESS_ASSIGN matching the request IDs. Denial is signaled with all-zeros address and max prefix length.

**ROUTE_ADVERTISEMENT (0x03):**
```rust
pub struct RouteAdvertisement {
    pub ranges: Vec<IpAddressRange>, // must be sorted per RFC
}

pub struct IpAddressRange {
    pub ip_version: IpVersion,
    pub start: IpAddr,
    pub end: IpAddr,
    pub ip_protocol: u8,       // 0 = all protocols
}
```
Ranges must be sorted: by IP version, then protocol, then non-overlapping address order. Encoder enforces sorting. Decoder validates and aborts the stream on violation.

### IP Datagram Framing (RFC 9484 §6)

IP packets flow as HTTP Datagrams:

```
IP Proxying HTTP Datagram Payload {
  Context ID (variable-length integer),  // 0 = IP packet
  Payload (..),                          // full IP packet (v4 or v6)
}
```

- Context ID 0: carries a complete IP packet (from IP version field to last byte)
- Context ID > 0: reserved for future extensions, silently dropped or buffered (~1 RTT)
- Client allocates even context IDs, proxy allocates odd

The crate wraps `h3-datagram` to prepend/strip the Context ID:

```rust
pub struct IpDatagramSender { /* wraps h3-datagram sender */ }
pub struct IpDatagramReceiver { /* wraps h3-datagram receiver */ }

impl IpDatagramSender {
    /// Send an IP packet through the tunnel
    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<(), Error>;
}

impl IpDatagramReceiver {
    /// Receive the next IP packet from the tunnel
    pub async fn recv_ip_packet(&self) -> Result<Bytes, Error>;
}
```

### MTU Handling

Per RFC 9484 §5:
- IPv6 requires link MTU of at least 1280 bytes
- On session establishment, the proxy sends an ICMPv6 echo request with 1232-byte payload to verify MTU
- If MTU is too low for IPv6 minimum, the session stream MUST be aborted
- Oversized packets are dropped and an ICMPv6 Packet Too Big message is sent back through the tunnel

The crate queries `quinn::Connection::max_datagram_size()` to determine the maximum payload, subtracts HTTP/3 framing overhead and Context ID, and reports the effective tunnel MTU.

### Hop Count / TTL

Per RFC 9484 §4.3:
- Decrement IP TTL/Hop Limit on encapsulation (entering the tunnel), not on decapsulation (leaving)
- This is the responsibility of the consumer (meshque), not the crate. The crate provides a utility function but does not modify packets automatically.

## Public API

### Client

```rust
pub struct ConnectIpClient { /* ... */ }

impl ConnectIpClient {
    /// Connect to a CONNECT-IP proxy
    pub async fn connect(
        endpoint: &quinn::Endpoint,
        proxy_addr: SocketAddr,
        server_name: &str,
        target: &str,          // hostname, IP prefix, or "*"
        ip_protocol: &str,     // 0-255 or "*"
    ) -> Result<ConnectIpSession, Error>;
}
```

### Proxy

```rust
pub struct ConnectIpProxy { /* ... */ }

impl ConnectIpProxy {
    /// Accept incoming CONNECT-IP requests
    pub async fn accept(
        connection: h3::server::Connection<h3_quinn::Connection, Bytes>,
    ) -> Result<ConnectIpRequest, Error>;
}

pub struct ConnectIpRequest {
    pub target: String,
    pub ip_protocol: String,
    /* ... */
}

impl ConnectIpRequest {
    /// Accept the request and create a session
    pub async fn accept(self) -> Result<ConnectIpSession, Error>;

    /// Reject the request with an HTTP error status
    pub async fn reject(self, status: u16) -> Result<(), Error>;
}
```

### Session (shared between client and proxy)

```rust
pub struct ConnectIpSession { /* ... */ }

impl ConnectIpSession {
    /// Send an IP packet through the tunnel
    pub async fn send_ip_packet(&self, packet: &[u8]) -> Result<(), Error>;

    /// Receive the next IP packet from the tunnel
    pub async fn recv_ip_packet(&self) -> Result<Bytes, Error>;

    /// Request address assignment from peer
    pub async fn request_addresses(
        &self,
        requests: Vec<RequestedAddress>,
    ) -> Result<Vec<AssignedAddress>, Error>;

    /// Assign addresses to peer
    pub async fn assign_addresses(
        &self,
        addresses: Vec<AssignedAddress>,
    ) -> Result<(), Error>;

    /// Advertise routes to peer
    pub async fn advertise_routes(
        &self,
        ranges: Vec<IpAddressRange>,
    ) -> Result<(), Error>;

    /// Receive route advertisements from peer
    pub async fn recv_routes(&self) -> Result<Vec<IpAddressRange>, Error>;

    /// Get the effective tunnel MTU
    pub fn tunnel_mtu(&self) -> usize;

    /// Close the session
    pub async fn close(self) -> Result<(), Error>;
}
```

## Error Handling

Per the RFCs, errors are handled as:

| Condition | Action |
|-----------|--------|
| Malformed capsule | Abort the HTTP stream (RFC 9297 §3.3) |
| ADDRESS_REQUEST with zero entries | Abort the stream |
| ROUTE_ADVERTISEMENT unsorted | Abort the stream |
| Unknown Context ID in datagram | Drop silently or buffer ~1 RTT |
| Unknown capsule type | Skip silently |
| Malformed Extended CONNECT request | HTTP 400 (proxy side) |
| Invalid target/ipproto URI variables | HTTP 400 (proxy side) |
| DNS resolution failure for target | HTTP 502 with Proxy-Status header |
| MTU too low for IPv6 | Abort the stream |

The crate uses a typed error enum:

```rust
pub enum Error {
    /// QUIC connection error
    Quic(quinn::ConnectionError),
    /// HTTP/3 error
    Http3(h3::Error),
    /// Malformed capsule data
    MalformedCapsule { capsule_type: u64, detail: String },
    /// Protocol violation (e.g. unsorted routes, empty address request)
    ProtocolViolation(String),
    /// Stream was aborted by peer
    StreamAborted,
    /// MTU too low for IPv6 minimum (1280 bytes)
    MtuTooLow { available: usize },
    /// Session is closed
    SessionClosed,
}
```

## Validation Strategy

### 1. RFC Conformance Tests

Systematic testing of every MUST/SHOULD from the RFCs:

- Capsule encoding roundtrips (encode -> decode -> compare)
- Correct rejection of malformed capsules (truncated, oversized length, wrong types)
- ADDRESS_REQUEST with zero entries aborts stream
- ROUTE_ADVERTISEMENT sorting validation and rejection
- Context ID 0 carries IP packets, non-zero handled correctly
- Extended CONNECT request validation (correct headers, protocol value)
- HTTP 400 on malformed requests
- MTU verification flow

### 2. Interop Testing

- **connect-ip-go proxy**: run the Go proxy, connect with our Rust client, send IP packets bidirectionally
- **connect-ip-go client**: run our Rust proxy, connect with the Go client
- **Cloudflare WARP servers**: attempt connection to live WARP infrastructure with our client (best real-world conformance test)

Interop tests live in `tests/interop/` and are gated behind a feature flag (`--features interop`) since they require external processes or network access.

### 3. Fuzz Testing

Using `cargo-fuzz` / `libfuzzer`:
- `fuzz_capsule`: feed random bytes to the capsule decoder. Must never panic, must reject gracefully.
- `fuzz_datagram`: feed random bytes to the datagram framer. Same requirements.

### 4. Benchmarks

Using `criterion`:
- Throughput: packets per second and bytes per second through a loopback tunnel
- Latency: time from `send_ip_packet` to `recv_ip_packet` over loopback
- Capsule encoding/decoding throughput

### 5. Pre-1.0 (deferred)

- Sustained load testing (hours of traffic, check for memory leaks)
- Security audit of parser code
- Broader interop matrix (masquerade, other implementations as they appear)

## Scope Boundaries

**In scope:**
- RFC 9484 (CONNECT-IP) — full implementation
- RFC 9297 (HTTP Datagrams + Capsule Protocol) — capsule framing layer
- HTTP/3 only (no HTTP/2 or HTTP/1.1 fallback)
- Client and proxy APIs
- Capsule codec (ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT)
- IP datagram framing (Context ID + packet)
- MTU handling
- Examples and documentation

**Out of scope (handled by meshque, not this crate):**
- TUN device creation/management
- NAT traversal / hole-punching
- Signaling / peer discovery
- IP routing decisions
- TTL decrement (utility function provided, not auto-applied)
- Authentication / authorization policy
- HTTP/2 and HTTP/1.1 support (future consideration)
