# `connect-ip` Crate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone, publishable Rust crate implementing RFC 9484 (CONNECT-IP) over HTTP/3, providing client and proxy APIs for tunneling IP packets through HTTP/3 connections.

**Architecture:** The crate layers on top of `quinn` (QUIC) and `h3` (HTTP/3). It implements the capsule protocol framing (RFC 9297), CONNECT-IP capsule types (ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT), IP datagram framing with Context IDs, and exposes `ConnectIpClient`, `ConnectIpProxy`, and `ConnectIpSession` as the public API. The h3-webtransport crate is used as an architectural reference — we follow the same pattern of consuming the h3 `Connection` into a session struct.

**Tech Stack:** Rust, quinn 0.11.x, h3 0.0.8, h3-quinn, h3-datagram 0.0.2, tokio, bytes, rcgen (test certs), cargo-fuzz, criterion

---

## File Structure

```
connect-ip/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Re-exports public API
│   ├── varint.rs           # QUIC variable-length integer encode/decode (RFC 9000 §16)
│   ├── capsule/
│   │   ├── mod.rs          # CapsuleType enum, Capsule struct, stream reader/writer
│   │   ├── codec.rs        # Low-level capsule TLV encode/decode on byte buffers
│   │   ├── address.rs      # AddressAssign, AddressRequest, AssignedAddress, RequestedAddress
│   │   └── route.rs        # RouteAdvertisement, IpAddressRange
│   ├── datagram.rs         # IpDatagramSender, IpDatagramReceiver (Context ID framing)
│   ├── session.rs          # ConnectIpSession (shared between client and proxy)
│   ├── client.rs           # ConnectIpClient
│   ├── proxy.rs            # ConnectIpProxy, ConnectIpRequest
│   ├── types.rs            # IpVersion enum, shared constants
│   └── error.rs            # Error enum
├── tests/
│   ├── helpers/
│   │   └── mod.rs          # Shared test infra: cert generation, endpoint setup
│   ├── varint.rs           # Varint encode/decode tests
│   ├── capsule_codec.rs    # Capsule TLV framing tests
│   ├── address_capsules.rs # ADDRESS_ASSIGN / ADDRESS_REQUEST encode/decode tests
│   ├── route_capsules.rs   # ROUTE_ADVERTISEMENT encode/decode tests
│   ├── datagram_framing.rs # Context ID + IP packet framing tests
│   ├── loopback.rs         # Full client <-> proxy integration over localhost
│   └── address_negotiation.rs # Address request/assign flow over loopback
├── fuzz/
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── fuzz_capsule.rs
│       └── fuzz_datagram.rs
├── benches/
│   └── throughput.rs
└── examples/
    ├── simple_proxy.rs
    └── simple_client.rs
```

---

### Task 1: Project Scaffold and Dependencies

**Files:**
- Create: `connect-ip/Cargo.toml`
- Create: `connect-ip/src/lib.rs`
- Create: `connect-ip/src/error.rs`
- Create: `connect-ip/src/types.rs`

- [ ] **Step 1: Create Cargo.toml**

```toml
[package]
name = "connect-ip"
version = "0.1.0"
edition = "2021"
license = "MIT OR Apache-2.0"
description = "RFC 9484 CONNECT-IP implementation over HTTP/3"
repository = "https://github.com/TODO/connect-ip"

[dependencies]
quinn = "0.11"
h3 = "0.0.8"
h3-quinn = "0.0.9"
h3-datagram = "0.0.2"
tokio = { version = "1", features = ["full"] }
bytes = "1"
thiserror = "2"
tracing = "0.1"

[dev-dependencies]
rcgen = "0.13"
rustls = { version = "0.23", features = ["ring"] }
tokio = { version = "1", features = ["full", "test-util"] }
criterion = { version = "0.5", features = ["async_tokio"] }

[features]
interop = []

[[bench]]
name = "throughput"
harness = false
```

- [ ] **Step 2: Create src/types.rs**

```rust
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
```

- [ ] **Step 3: Create src/error.rs**

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("QUIC connection error: {0}")]
    Quic(#[from] quinn::ConnectionError),

    #[error("HTTP/3 error: {0}")]
    H3(#[from] h3::Error),

    #[error("HTTP/3 stream error: {0}")]
    H3Stream(#[from] h3::error::StreamError),

    #[error("malformed capsule (type {capsule_type:#x}): {detail}")]
    MalformedCapsule { capsule_type: u64, detail: String },

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("stream aborted by peer")]
    StreamAborted,

    #[error("MTU too low for IPv6 minimum: {available} bytes available, 1280 required")]
    MtuTooLow { available: usize },

    #[error("session closed")]
    SessionClosed,

    #[error("invalid varint encoding")]
    InvalidVarint,

    #[error("datagram send error: {0}")]
    DatagramSend(String),

    #[error("unexpected end of data")]
    UnexpectedEof,
}
```

- [ ] **Step 4: Create src/lib.rs**

```rust
pub mod capsule;
pub mod client;
pub mod datagram;
pub mod error;
pub mod proxy;
pub mod session;
pub mod types;
pub mod varint;

pub use client::ConnectIpClient;
pub use error::Error;
pub use proxy::{ConnectIpProxy, ConnectIpRequest};
pub use session::ConnectIpSession;
pub use types::IpVersion;
```

- [ ] **Step 5: Create stub modules so the crate compiles**

Create empty files so `cargo check` passes:

`src/varint.rs`:
```rust
// Implemented in Task 2
```

`src/capsule/mod.rs`:
```rust
pub mod codec;
pub mod address;
pub mod route;
// Implemented in Task 3
```

`src/capsule/codec.rs`:
```rust
// Implemented in Task 3
```

`src/capsule/address.rs`:
```rust
// Implemented in Task 4
```

`src/capsule/route.rs`:
```rust
// Implemented in Task 5
```

`src/datagram.rs`:
```rust
// Implemented in Task 6
```

`src/session.rs`:
```rust
// Implemented in Task 7
```

`src/client.rs`:
```rust
pub struct ConnectIpClient;
// Implemented in Task 8
```

`src/proxy.rs`:
```rust
pub struct ConnectIpProxy;
pub struct ConnectIpRequest;
// Implemented in Task 9
```

- [ ] **Step 6: Verify the crate compiles**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo check`
Expected: compiles with no errors (warnings about unused are fine)

- [ ] **Step 7: Initialize git and commit**

```bash
cd /home/haoye/Source/ipowt
git init
echo -e "target/\n.superpowers/" > .gitignore
git add .gitignore connect-ip/ docs/
git commit -m "feat: scaffold connect-ip crate and project docs"
```

---

### Task 2: Variable-Length Integer Encoding (RFC 9000 §16)

QUIC variable-length integers are used throughout capsule framing and HTTP datagram Context IDs. This is foundational — every subsequent task depends on it.

**Files:**
- Modify: `connect-ip/src/varint.rs`
- Create: `connect-ip/tests/varint.rs`

- [ ] **Step 1: Write the failing tests**

`connect-ip/tests/varint.rs`:
```rust
use bytes::{Buf, BufMut, BytesMut};
use connect_ip::varint;

#[test]
fn encode_decode_single_byte() {
    // Values 0-63 encode as 1 byte (2-bit prefix 00)
    let mut buf = BytesMut::new();
    varint::encode(0, &mut buf);
    assert_eq!(buf.as_ref(), &[0x00]);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 0);

    let mut buf = BytesMut::new();
    varint::encode(37, &mut buf);
    assert_eq!(buf.as_ref(), &[0x25]);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 37);

    let mut buf = BytesMut::new();
    varint::encode(63, &mut buf);
    assert_eq!(buf.as_ref(), &[0x3f]);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 63);
}

#[test]
fn encode_decode_two_byte() {
    // Values 64-16383 encode as 2 bytes (2-bit prefix 01)
    let mut buf = BytesMut::new();
    varint::encode(64, &mut buf);
    assert_eq!(buf.len(), 2);
    assert_eq!(buf[0] >> 6, 0b01); // prefix bits
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 64);

    let mut buf = BytesMut::new();
    varint::encode(16383, &mut buf);
    assert_eq!(buf.len(), 2);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 16383);
}

#[test]
fn encode_decode_four_byte() {
    // Values 16384-1073741823 encode as 4 bytes (2-bit prefix 10)
    let mut buf = BytesMut::new();
    varint::encode(16384, &mut buf);
    assert_eq!(buf.len(), 4);
    assert_eq!(buf[0] >> 6, 0b10);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 16384);

    let mut buf = BytesMut::new();
    varint::encode(1_073_741_823, &mut buf);
    assert_eq!(buf.len(), 4);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 1_073_741_823);
}

#[test]
fn encode_decode_eight_byte() {
    // Values 1073741824-4611686018427387903 encode as 8 bytes (2-bit prefix 11)
    let mut buf = BytesMut::new();
    varint::encode(1_073_741_824, &mut buf);
    assert_eq!(buf.len(), 8);
    assert_eq!(buf[0] >> 6, 0b11);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), 1_073_741_824);

    let mut buf = BytesMut::new();
    let max = 4_611_686_018_427_387_903u64;
    varint::encode(max, &mut buf);
    assert_eq!(buf.len(), 8);
    assert_eq!(varint::decode(&mut buf.freeze()).unwrap(), max);
}

#[test]
fn decode_empty_buffer_returns_error() {
    let mut buf = bytes::Bytes::new();
    assert!(varint::decode(&mut buf).is_err());
}

#[test]
fn decode_truncated_buffer_returns_error() {
    // 2-byte prefix but only 1 byte present
    let mut buf = bytes::Bytes::from_static(&[0x40]);
    assert!(varint::decode(&mut buf).is_err());
}

#[test]
fn encoded_length_matches_spec() {
    assert_eq!(varint::encoded_len(0), 1);
    assert_eq!(varint::encoded_len(63), 1);
    assert_eq!(varint::encoded_len(64), 2);
    assert_eq!(varint::encoded_len(16383), 2);
    assert_eq!(varint::encoded_len(16384), 4);
    assert_eq!(varint::encoded_len(1_073_741_823), 4);
    assert_eq!(varint::encoded_len(1_073_741_824), 8);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test varint`
Expected: FAIL — `varint::encode`, `varint::decode`, `varint::encoded_len` not found

- [ ] **Step 3: Implement varint module**

`connect-ip/src/varint.rs`:
```rust
use bytes::{Buf, BufMut};

use crate::error::Error;

/// Maximum value representable as a QUIC variable-length integer.
pub const MAX_VALUE: u64 = 4_611_686_018_427_387_903;

/// Returns the encoded byte length for a given value.
///
/// Panics if `value` exceeds `MAX_VALUE`.
pub fn encoded_len(value: u64) -> usize {
    if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else if value <= 1_073_741_823 {
        4
    } else if value <= MAX_VALUE {
        8
    } else {
        panic!("varint value {value} exceeds maximum {MAX_VALUE}");
    }
}

/// Encode a variable-length integer into the buffer.
///
/// Panics if `value` exceeds `MAX_VALUE`.
pub fn encode(value: u64, buf: &mut impl BufMut) {
    match encoded_len(value) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        8 => buf.put_u64(0xC000_0000_0000_0000 | value),
        _ => unreachable!(),
    }
}

/// Decode a variable-length integer from the buffer.
///
/// Advances the buffer past the consumed bytes.
/// Returns `Error::InvalidVarint` if the buffer is too short.
pub fn decode(buf: &mut impl Buf) -> Result<u64, Error> {
    if !buf.has_remaining() {
        return Err(Error::InvalidVarint);
    }

    let first = buf.chunk()[0];
    let prefix = first >> 6;
    let len = 1 << prefix; // 1, 2, 4, or 8

    if buf.remaining() < len {
        return Err(Error::InvalidVarint);
    }

    let value = match len {
        1 => buf.get_u8() as u64,
        2 => (buf.get_u16() & 0x3FFF) as u64,
        4 => (buf.get_u32() & 0x3FFF_FFFF) as u64,
        8 => buf.get_u64() & 0x3FFF_FFFF_FFFF_FFFF,
        _ => unreachable!(),
    };

    Ok(value)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test varint`
Expected: all 7 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/varint.rs connect-ip/tests/varint.rs
git commit -m "feat: implement QUIC variable-length integer encoding (RFC 9000 §16)"
```

---

### Task 3: Capsule Protocol Framing (RFC 9297 §3)

The capsule TLV (type-length-value) codec. This is the wire format layer that all capsule types build on.

**Files:**
- Modify: `connect-ip/src/capsule/mod.rs`
- Modify: `connect-ip/src/capsule/codec.rs`
- Create: `connect-ip/tests/capsule_codec.rs`

- [ ] **Step 1: Write the failing tests**

`connect-ip/tests/capsule_codec.rs`:
```rust
use bytes::{Bytes, BytesMut};
use connect_ip::capsule::codec::{encode_capsule, decode_capsule, RawCapsule};

#[test]
fn roundtrip_empty_payload() {
    let capsule = RawCapsule {
        capsule_type: 0x01,
        payload: Bytes::new(),
    };
    let mut buf = BytesMut::new();
    encode_capsule(&capsule, &mut buf);

    let decoded = decode_capsule(&mut buf.freeze()).unwrap().unwrap();
    assert_eq!(decoded.capsule_type, 0x01);
    assert!(decoded.payload.is_empty());
}

#[test]
fn roundtrip_with_payload() {
    let payload = Bytes::from_static(b"hello");
    let capsule = RawCapsule {
        capsule_type: 0x03,
        payload: payload.clone(),
    };
    let mut buf = BytesMut::new();
    encode_capsule(&capsule, &mut buf);

    let decoded = decode_capsule(&mut buf.freeze()).unwrap().unwrap();
    assert_eq!(decoded.capsule_type, 0x03);
    assert_eq!(decoded.payload, payload);
}

#[test]
fn roundtrip_large_type() {
    // Type value requiring 4-byte varint
    let capsule = RawCapsule {
        capsule_type: 0x00100000,
        payload: Bytes::from_static(&[0xAA; 100]),
    };
    let mut buf = BytesMut::new();
    encode_capsule(&capsule, &mut buf);

    let decoded = decode_capsule(&mut buf.freeze()).unwrap().unwrap();
    assert_eq!(decoded.capsule_type, 0x00100000);
    assert_eq!(decoded.payload.len(), 100);
}

#[test]
fn decode_empty_returns_none() {
    let mut buf = Bytes::new();
    assert!(decode_capsule(&mut buf).unwrap().is_none());
}

#[test]
fn decode_truncated_type_returns_none() {
    // 2-byte varint type, but only 1 byte present
    let mut buf = Bytes::from_static(&[0x40]);
    // Not enough data — should return None (incomplete)
    assert!(decode_capsule(&mut buf).is_none() || decode_capsule(&mut Bytes::from_static(&[0x40])).is_err());
}

#[test]
fn decode_truncated_payload_returns_none() {
    // Type=1 (1 byte), Length=10 (1 byte), but only 3 bytes of payload
    let mut buf = Bytes::from_static(&[0x01, 0x0A, 0xAA, 0xBB, 0xCC]);
    // Length says 10 but only 3 payload bytes — incomplete
    let result = decode_capsule(&mut buf);
    // Should be Err or None depending on design — we treat it as incomplete (None)
    assert!(result.is_err() || result.unwrap().is_none());
}

#[test]
fn multiple_capsules_in_sequence() {
    let c1 = RawCapsule { capsule_type: 0x01, payload: Bytes::from_static(b"abc") };
    let c2 = RawCapsule { capsule_type: 0x02, payload: Bytes::from_static(b"de") };

    let mut buf = BytesMut::new();
    encode_capsule(&c1, &mut buf);
    encode_capsule(&c2, &mut buf);
    let mut data = buf.freeze();

    let d1 = decode_capsule(&mut data).unwrap().unwrap();
    assert_eq!(d1.capsule_type, 0x01);
    assert_eq!(d1.payload, Bytes::from_static(b"abc"));

    let d2 = decode_capsule(&mut data).unwrap().unwrap();
    assert_eq!(d2.capsule_type, 0x02);
    assert_eq!(d2.payload, Bytes::from_static(b"de"));

    // No more capsules
    assert!(decode_capsule(&mut data).unwrap().is_none());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test capsule_codec`
Expected: FAIL — `capsule::codec` functions not found

- [ ] **Step 3: Implement capsule codec**

`connect-ip/src/capsule/codec.rs`:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;
use crate::varint;

/// A raw capsule with type and undecoded payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCapsule {
    pub capsule_type: u64,
    pub payload: Bytes,
}

/// Encode a capsule into the buffer (type + length + payload).
pub fn encode_capsule(capsule: &RawCapsule, buf: &mut BytesMut) {
    varint::encode(capsule.capsule_type, buf);
    varint::encode(capsule.payload.len() as u64, buf);
    buf.put_slice(&capsule.payload);
}

/// Attempt to decode one capsule from the buffer.
///
/// Returns:
/// - `Ok(Some(capsule))` if a complete capsule was decoded (buffer is advanced)
/// - `Ok(None)` if the buffer is empty (no more capsules)
/// - `Err(...)` if the data is malformed or the buffer has a partial capsule
pub fn decode_capsule(buf: &mut Bytes) -> Result<Option<RawCapsule>, Error> {
    if !buf.has_remaining() {
        return Ok(None);
    }

    // Save position so we can check if we have enough data
    let mut peek = buf.clone();

    let capsule_type = match varint::decode(&mut peek) {
        Ok(v) => v,
        Err(_) => return Err(Error::UnexpectedEof),
    };

    let length = match varint::decode(&mut peek) {
        Ok(v) => v,
        Err(_) => return Err(Error::UnexpectedEof),
    };

    let length = length as usize;
    if peek.remaining() < length {
        return Err(Error::UnexpectedEof);
    }

    let payload = peek.split_to(length);

    // All good — commit the read by updating the original buffer
    *buf = peek;

    Ok(Some(RawCapsule {
        capsule_type,
        payload,
    }))
}
```

- [ ] **Step 4: Update capsule/mod.rs with known capsule types**

`connect-ip/src/capsule/mod.rs`:
```rust
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test capsule_codec`
Expected: all 7 tests PASS

Note: the `decode_truncated_payload_returns_none` test asserts `Err` or `None` — our implementation returns `Err(UnexpectedEof)` for truncated data. Adjust the test assertion if needed:

```rust
#[test]
fn decode_truncated_payload_returns_error() {
    let mut buf = Bytes::from_static(&[0x01, 0x0A, 0xAA, 0xBB, 0xCC]);
    assert!(decode_capsule(&mut buf).is_err());
}
```

- [ ] **Step 6: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/capsule/mod.rs connect-ip/src/capsule/codec.rs connect-ip/tests/capsule_codec.rs
git commit -m "feat: implement capsule protocol TLV framing (RFC 9297 §3)"
```

---

### Task 4: ADDRESS_ASSIGN and ADDRESS_REQUEST Capsules (RFC 9484 §4.7.1–4.7.2)

**Files:**
- Modify: `connect-ip/src/capsule/address.rs`
- Create: `connect-ip/tests/address_capsules.rs`

- [ ] **Step 1: Write the failing tests**

`connect-ip/tests/address_capsules.rs`:
```rust
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use connect_ip::capsule::address::{
    AddressAssign, AddressRequest, AssignedAddress, RequestedAddress,
    encode_address_assign, decode_address_assign,
    encode_address_request, decode_address_request,
};
use connect_ip::types::IpVersion;

#[test]
fn roundtrip_address_assign_ipv4() {
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 1,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            prefix_length: 32,
        }],
    };

    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.addresses.len(), 1);
    assert_eq!(decoded.addresses[0].request_id, 1);
    assert_eq!(decoded.addresses[0].ip_version, IpVersion::V4);
    assert_eq!(decoded.addresses[0].address, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)));
    assert_eq!(decoded.addresses[0].prefix_length, 32);
}

#[test]
fn roundtrip_address_assign_ipv6() {
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 0, // unsolicited
            ip_version: IpVersion::V6,
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            prefix_length: 128,
        }],
    };

    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.addresses.len(), 1);
    assert_eq!(decoded.addresses[0].request_id, 0);
    assert_eq!(decoded.addresses[0].ip_version, IpVersion::V6);
    assert_eq!(decoded.addresses[0].prefix_length, 128);
}

#[test]
fn roundtrip_address_assign_multiple() {
    let assign = AddressAssign {
        addresses: vec![
            AssignedAddress {
                request_id: 1,
                ip_version: IpVersion::V4,
                address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
                prefix_length: 32,
            },
            AssignedAddress {
                request_id: 2,
                ip_version: IpVersion::V6,
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix_length: 128,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();
    assert_eq!(decoded.addresses.len(), 2);
    assert_eq!(decoded.addresses[0].request_id, 1);
    assert_eq!(decoded.addresses[1].request_id, 2);
}

#[test]
fn roundtrip_address_assign_empty() {
    // Empty address list is valid (removes all previously assigned)
    let assign = AddressAssign { addresses: vec![] };
    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let decoded = decode_address_assign(&mut buf.freeze()).unwrap();
    assert!(decoded.addresses.is_empty());
}

#[test]
fn roundtrip_address_request() {
    let request = AddressRequest {
        addresses: vec![RequestedAddress {
            request_id: 42,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED), // "assign any"
            prefix_length: 32,
        }],
    };

    let mut buf = BytesMut::new();
    encode_address_request(&request, &mut buf);
    let decoded = decode_address_request(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.addresses.len(), 1);
    assert_eq!(decoded.addresses[0].request_id, 42);
    assert_eq!(decoded.addresses[0].address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
}

#[test]
fn address_request_empty_is_error() {
    // RFC 9484: ADDRESS_REQUEST must contain at least one entry
    let request = AddressRequest { addresses: vec![] };
    let mut buf = BytesMut::new();
    encode_address_request(&request, &mut buf);
    let result = decode_address_request(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn address_request_zero_request_id_is_error() {
    // RFC 9484: request_id must be non-zero
    let request = AddressRequest {
        addresses: vec![RequestedAddress {
            request_id: 0,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 32,
        }],
    };
    let mut buf = BytesMut::new();
    encode_address_request(&request, &mut buf);
    let result = decode_address_request(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn address_assign_prefix_validation() {
    // Prefix length 24 with address 100.64.0.1 — lower bits non-zero should error
    let assign = AddressAssign {
        addresses: vec![AssignedAddress {
            request_id: 1,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            prefix_length: 24, // lower 8 bits of addr are non-zero
        }],
    };
    let mut buf = BytesMut::new();
    encode_address_assign(&assign, &mut buf);
    let result = decode_address_assign(&mut buf.freeze());
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test address_capsules`
Expected: FAIL

- [ ] **Step 3: Implement address capsule types**

`connect-ip/src/capsule/address.rs`:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::Error;
use crate::types::IpVersion;
use crate::varint;

/// ADDRESS_ASSIGN capsule payload (RFC 9484 §4.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressAssign {
    pub addresses: Vec<AssignedAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip_version: IpVersion,
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// ADDRESS_REQUEST capsule payload (RFC 9484 §4.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRequest {
    pub addresses: Vec<RequestedAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAddress {
    pub request_id: u64,
    pub ip_version: IpVersion,
    pub address: IpAddr,
    pub prefix_length: u8,
}

/// Encode an ADDRESS_ASSIGN payload (not including the capsule TLV header).
pub fn encode_address_assign(assign: &AddressAssign, buf: &mut BytesMut) {
    for addr in &assign.addresses {
        varint::encode(addr.request_id, buf);
        buf.put_u8(addr.ip_version as u8);
        encode_ip_addr(&addr.address, buf);
        buf.put_u8(addr.prefix_length);
    }
}

/// Decode an ADDRESS_ASSIGN payload.
pub fn decode_address_assign(buf: &mut Bytes) -> Result<AddressAssign, Error> {
    let mut addresses = Vec::new();
    while buf.has_remaining() {
        let request_id = varint::decode(buf)?;
        let ip_version = IpVersion::from_u8(buf_get_u8(buf)?)
            .ok_or_else(|| Error::MalformedCapsule {
                capsule_type: 0x01,
                detail: "invalid IP version".into(),
            })?;
        let address = decode_ip_addr(ip_version, buf)?;
        let prefix_length = buf_get_u8(buf)?;

        if prefix_length > ip_version.max_prefix_len() {
            return Err(Error::MalformedCapsule {
                capsule_type: 0x01,
                detail: format!(
                    "prefix length {prefix_length} exceeds max {} for {:?}",
                    ip_version.max_prefix_len(),
                    ip_version
                ),
            });
        }

        // Validate lower bits are zero when prefix_length < max
        validate_prefix_bits(&address, prefix_length, ip_version)?;

        addresses.push(AssignedAddress {
            request_id,
            ip_version,
            address,
            prefix_length,
        });
    }
    Ok(AddressAssign { addresses })
}

/// Encode an ADDRESS_REQUEST payload (not including the capsule TLV header).
pub fn encode_address_request(request: &AddressRequest, buf: &mut BytesMut) {
    for addr in &request.addresses {
        varint::encode(addr.request_id, buf);
        buf.put_u8(addr.ip_version as u8);
        encode_ip_addr(&addr.address, buf);
        buf.put_u8(addr.prefix_length);
    }
}

/// Decode an ADDRESS_REQUEST payload.
pub fn decode_address_request(buf: &mut Bytes) -> Result<AddressRequest, Error> {
    let mut addresses = Vec::new();
    while buf.has_remaining() {
        let request_id = varint::decode(buf)?;
        if request_id == 0 {
            return Err(Error::ProtocolViolation(
                "ADDRESS_REQUEST request_id must be non-zero".into(),
            ));
        }
        let ip_version = IpVersion::from_u8(buf_get_u8(buf)?)
            .ok_or_else(|| Error::MalformedCapsule {
                capsule_type: 0x02,
                detail: "invalid IP version".into(),
            })?;
        let address = decode_ip_addr(ip_version, buf)?;
        let prefix_length = buf_get_u8(buf)?;

        if prefix_length > ip_version.max_prefix_len() {
            return Err(Error::MalformedCapsule {
                capsule_type: 0x02,
                detail: format!(
                    "prefix length {prefix_length} exceeds max {} for {:?}",
                    ip_version.max_prefix_len(),
                    ip_version
                ),
            });
        }

        addresses.push(RequestedAddress {
            request_id,
            ip_version,
            address,
            prefix_length,
        });
    }

    if addresses.is_empty() {
        return Err(Error::ProtocolViolation(
            "ADDRESS_REQUEST must contain at least one entry".into(),
        ));
    }

    Ok(AddressRequest { addresses })
}

fn encode_ip_addr(addr: &IpAddr, buf: &mut BytesMut) {
    match addr {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
}

fn decode_ip_addr(version: IpVersion, buf: &mut Bytes) -> Result<IpAddr, Error> {
    let len = version.addr_len();
    if buf.remaining() < len {
        return Err(Error::UnexpectedEof);
    }
    match version {
        IpVersion::V4 => {
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        IpVersion::V6 => {
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
    }
}

fn buf_get_u8(buf: &mut Bytes) -> Result<u8, Error> {
    if !buf.has_remaining() {
        return Err(Error::UnexpectedEof);
    }
    Ok(buf.get_u8())
}

fn validate_prefix_bits(addr: &IpAddr, prefix_length: u8, version: IpVersion) -> Result<(), Error> {
    let max = version.max_prefix_len();
    if prefix_length >= max {
        return Ok(()); // full address, no bits to check
    }
    let host_bits = (max - prefix_length) as u32;
    let has_lower_bits = match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(*v4);
            let mask = (1u32 << host_bits) - 1;
            bits & mask != 0
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(*v6);
            let mask = (1u128 << host_bits) - 1;
            bits & mask != 0
        }
    };
    if has_lower_bits {
        return Err(Error::MalformedCapsule {
            capsule_type: 0x01,
            detail: format!(
                "address {addr} has non-zero bits below prefix length {prefix_length}"
            ),
        });
    }
    Ok(())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test address_capsules`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/capsule/address.rs connect-ip/tests/address_capsules.rs
git commit -m "feat: implement ADDRESS_ASSIGN and ADDRESS_REQUEST capsules (RFC 9484 §4.7.1-2)"
```

---

### Task 5: ROUTE_ADVERTISEMENT Capsule (RFC 9484 §4.7.3)

**Files:**
- Modify: `connect-ip/src/capsule/route.rs`
- Create: `connect-ip/tests/route_capsules.rs`

- [ ] **Step 1: Write the failing tests**

`connect-ip/tests/route_capsules.rs`:
```rust
use bytes::{Bytes, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use connect_ip::capsule::route::{
    RouteAdvertisement, IpAddressRange,
    encode_route_advertisement, decode_route_advertisement,
};
use connect_ip::types::IpVersion;

#[test]
fn roundtrip_single_ipv4_range() {
    let routes = RouteAdvertisement {
        ranges: vec![IpAddressRange {
            ip_version: IpVersion::V4,
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
            ip_protocol: 0, // all protocols
        }],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();

    assert_eq!(decoded.ranges.len(), 1);
    assert_eq!(decoded.ranges[0].start, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
    assert_eq!(decoded.ranges[0].end, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)));
    assert_eq!(decoded.ranges[0].ip_protocol, 0);
}

#[test]
fn roundtrip_multiple_ranges_sorted() {
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 255)),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V6,
                start: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                end: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0xFFFF)),
                ip_protocol: 0,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();
    assert_eq!(decoded.ranges.len(), 3);
}

#[test]
fn decode_unsorted_ranges_is_error() {
    // Build a valid-looking buffer but with ranges out of order
    // IPv6 before IPv4 — violates sort requirement
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V6,
                start: IpAddr::V6(Ipv6Addr::LOCALHOST),
                end: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::LOCALHOST),
                end: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ip_protocol: 0,
            },
        ],
    };

    // Encode without sorting (raw encode for testing)
    let mut buf = BytesMut::new();
    encode_route_advertisement_unchecked(&routes, &mut buf);
    let result = decode_route_advertisement(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn decode_overlapping_ranges_is_error() {
    // Two ranges with the same version/protocol that overlap
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200)),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), // overlaps with previous end
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement_unchecked(&routes, &mut buf);
    let result = decode_route_advertisement(&mut buf.freeze());
    assert!(result.is_err());
}

#[test]
fn roundtrip_empty_routes() {
    let routes = RouteAdvertisement { ranges: vec![] };
    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();
    assert!(decoded.ranges.is_empty());
}

#[test]
fn encode_sorts_ranges() {
    // Provide ranges out of order — encoder should sort them
    let routes = RouteAdvertisement {
        ranges: vec![
            IpAddressRange {
                ip_version: IpVersion::V6,
                start: IpAddr::V6(Ipv6Addr::LOCALHOST),
                end: IpAddr::V6(Ipv6Addr::LOCALHOST),
                ip_protocol: 0,
            },
            IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
                ip_protocol: 0,
            },
        ],
    };

    let mut buf = BytesMut::new();
    encode_route_advertisement(&routes, &mut buf);
    let decoded = decode_route_advertisement(&mut buf.freeze()).unwrap();
    // After sorting: IPv4 comes before IPv6
    assert_eq!(decoded.ranges[0].ip_version, IpVersion::V4);
    assert_eq!(decoded.ranges[1].ip_version, IpVersion::V6);
}

// Helper: encode without sorting for negative test cases
fn encode_route_advertisement_unchecked(routes: &RouteAdvertisement, buf: &mut BytesMut) {
    use bytes::BufMut;
    use connect_ip::capsule::route::encode_ip_address_range;
    for range in &routes.ranges {
        encode_ip_address_range(range, buf);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test route_capsules`
Expected: FAIL

- [ ] **Step 3: Implement route capsule types**

`connect-ip/src/capsule/route.rs`:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::IpAddr;

use crate::error::Error;
use crate::types::IpVersion;

/// ROUTE_ADVERTISEMENT capsule payload (RFC 9484 §4.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub ranges: Vec<IpAddressRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressRange {
    pub ip_version: IpVersion,
    pub start: IpAddr,
    pub end: IpAddr,
    pub ip_protocol: u8,
}

/// Encode a ROUTE_ADVERTISEMENT payload. Sorts ranges per RFC ordering requirements.
pub fn encode_route_advertisement(routes: &RouteAdvertisement, buf: &mut BytesMut) {
    let mut sorted = routes.ranges.clone();
    sorted.sort_by(|a, b| {
        let va = a.ip_version as u8;
        let vb = b.ip_version as u8;
        va.cmp(&vb)
            .then(a.ip_protocol.cmp(&b.ip_protocol))
            .then(cmp_ip_addr(&a.start, &b.start))
    });

    for range in &sorted {
        encode_ip_address_range(range, buf);
    }
}

/// Encode a single IP address range entry. Public for test helpers.
pub fn encode_ip_address_range(range: &IpAddressRange, buf: &mut BytesMut) {
    buf.put_u8(range.ip_version as u8);
    encode_ip_addr(&range.start, buf);
    encode_ip_addr(&range.end, buf);
    buf.put_u8(range.ip_protocol);
}

/// Decode a ROUTE_ADVERTISEMENT payload. Validates sorting and non-overlap per RFC.
pub fn decode_route_advertisement(buf: &mut Bytes) -> Result<RouteAdvertisement, Error> {
    let mut ranges = Vec::new();

    while buf.has_remaining() {
        let ip_version = IpVersion::from_u8(buf_get_u8(buf)?)
            .ok_or_else(|| Error::MalformedCapsule {
                capsule_type: 0x03,
                detail: "invalid IP version".into(),
            })?;
        let start = decode_ip_addr(ip_version, buf)?;
        let end = decode_ip_addr(ip_version, buf)?;
        let ip_protocol = buf_get_u8(buf)?;

        // Validate start <= end
        if cmp_ip_addr(&start, &end) == std::cmp::Ordering::Greater {
            return Err(Error::ProtocolViolation(
                "ROUTE_ADVERTISEMENT range start > end".into(),
            ));
        }

        let range = IpAddressRange { ip_version, start, end, ip_protocol };

        // Validate ordering against previous range
        if let Some(prev) = ranges.last() {
            validate_range_order(prev, &range)?;
        }

        ranges.push(range);
    }

    Ok(RouteAdvertisement { ranges })
}

fn validate_range_order(prev: &IpAddressRange, curr: &IpAddressRange) -> Result<(), Error> {
    let pv = prev.ip_version as u8;
    let cv = curr.ip_version as u8;

    if pv > cv {
        return Err(Error::ProtocolViolation(
            "ROUTE_ADVERTISEMENT ranges not sorted by IP version".into(),
        ));
    }

    if pv == cv {
        if prev.ip_protocol > curr.ip_protocol {
            return Err(Error::ProtocolViolation(
                "ROUTE_ADVERTISEMENT ranges not sorted by IP protocol".into(),
            ));
        }

        if prev.ip_protocol == curr.ip_protocol {
            // End of prev must be strictly less than start of curr (no overlap)
            if cmp_ip_addr(&prev.end, &curr.start) != std::cmp::Ordering::Less {
                return Err(Error::ProtocolViolation(
                    "ROUTE_ADVERTISEMENT ranges overlap".into(),
                ));
            }
        }
    }

    Ok(())
}

fn cmp_ip_addr(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets().cmp(&b.octets()),
        // Mixed types shouldn't occur in a single range, but handle gracefully
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

fn encode_ip_addr(addr: &IpAddr, buf: &mut BytesMut) {
    match addr {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
}

fn decode_ip_addr(version: IpVersion, buf: &mut Bytes) -> Result<IpAddr, Error> {
    let len = version.addr_len();
    if buf.remaining() < len {
        return Err(Error::UnexpectedEof);
    }
    match version {
        IpVersion::V4 => {
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V4(octets.into()))
        }
        IpVersion::V6 => {
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V6(octets.into()))
        }
    }
}

fn buf_get_u8(buf: &mut Bytes) -> Result<u8, Error> {
    if !buf.has_remaining() {
        return Err(Error::UnexpectedEof);
    }
    Ok(buf.get_u8())
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test route_capsules`
Expected: all 6 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/capsule/route.rs connect-ip/tests/route_capsules.rs
git commit -m "feat: implement ROUTE_ADVERTISEMENT capsule (RFC 9484 §4.7.3)"
```

---

### Task 6: IP Datagram Framing (RFC 9484 §6)

Wraps h3-datagram to add the Context ID prefix. This is the layer that sends/receives IP packets as HTTP datagrams.

**Files:**
- Modify: `connect-ip/src/datagram.rs`
- Create: `connect-ip/tests/datagram_framing.rs`

- [ ] **Step 1: Write the failing tests**

`connect-ip/tests/datagram_framing.rs`:
```rust
use bytes::{Bytes, BytesMut};
use connect_ip::datagram::{encode_ip_datagram, decode_ip_datagram};

#[test]
fn roundtrip_ipv4_packet() {
    // Minimal IPv4 header (version nibble = 4)
    let mut packet = vec![0x45u8; 20]; // version=4, IHL=5
    packet[0] = 0x45;

    let mut buf = BytesMut::new();
    encode_ip_datagram(&packet, &mut buf);

    let (context_id, payload) = decode_ip_datagram(&mut buf.freeze()).unwrap();
    assert_eq!(context_id, 0); // Context ID 0 = IP packet
    assert_eq!(payload.as_ref(), packet.as_slice());
}

#[test]
fn roundtrip_ipv6_packet() {
    // Minimal IPv6 header (version nibble = 6)
    let mut packet = vec![0u8; 40];
    packet[0] = 0x60; // version=6

    let mut buf = BytesMut::new();
    encode_ip_datagram(&packet, &mut buf);

    let (context_id, payload) = decode_ip_datagram(&mut buf.freeze()).unwrap();
    assert_eq!(context_id, 0);
    assert_eq!(payload.as_ref(), packet.as_slice());
}

#[test]
fn context_id_zero_is_one_byte() {
    let packet = vec![0x45u8; 20];
    let mut buf = BytesMut::new();
    encode_ip_datagram(&packet, &mut buf);
    // Context ID 0 encodes as single varint byte (0x00), so total = 1 + packet.len()
    assert_eq!(buf.len(), 1 + packet.len());
}

#[test]
fn decode_non_zero_context_id() {
    // Manually encode a datagram with context ID 5
    let mut buf = BytesMut::new();
    connect_ip::varint::encode(5, &mut buf);
    buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

    let (context_id, payload) = decode_ip_datagram(&mut buf.freeze()).unwrap();
    assert_eq!(context_id, 5);
    assert_eq!(payload.as_ref(), &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn decode_empty_is_error() {
    let result = decode_ip_datagram(&mut Bytes::new());
    assert!(result.is_err());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test datagram_framing`
Expected: FAIL

- [ ] **Step 3: Implement datagram framing**

`connect-ip/src/datagram.rs`:
```rust
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::Error;
use crate::varint;

/// Context ID for IP packets (RFC 9484 §6).
pub const CONTEXT_ID_IP_PACKET: u64 = 0;

/// Encode an IP packet as an HTTP Datagram payload with Context ID 0.
///
/// Format: Context ID (varint) || IP Packet
pub fn encode_ip_datagram(ip_packet: &[u8], buf: &mut BytesMut) {
    varint::encode(CONTEXT_ID_IP_PACKET, buf);
    buf.put_slice(ip_packet);
}

/// Decode an HTTP Datagram payload into (Context ID, payload).
///
/// For Context ID 0, payload is a full IP packet.
/// For other Context IDs, payload is extension data.
pub fn decode_ip_datagram(buf: &mut Bytes) -> Result<(u64, Bytes), Error> {
    if !buf.has_remaining() {
        return Err(Error::UnexpectedEof);
    }

    let context_id = varint::decode(buf)?;
    let payload = buf.split_to(buf.remaining());
    Ok((context_id, payload))
}

/// Calculate the overhead added by datagram framing (Context ID varint).
///
/// For Context ID 0, this is 1 byte.
pub fn framing_overhead(context_id: u64) -> usize {
    varint::encoded_len(context_id)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test datagram_framing`
Expected: all 5 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/datagram.rs connect-ip/tests/datagram_framing.rs
git commit -m "feat: implement IP datagram framing with Context ID (RFC 9484 §6)"
```

---

### Task 7: Test Helpers (shared infrastructure for integration tests)

Before building session/client/proxy, we need shared test infrastructure for creating QUIC endpoints with self-signed certs, enabling datagrams and Extended CONNECT.

**Files:**
- Create: `connect-ip/tests/helpers/mod.rs`

- [ ] **Step 1: Create test helpers**

`connect-ip/tests/helpers/mod.rs`:
```rust
use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// Generate a self-signed certificate for testing.
pub fn generate_test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert);
    (vec![cert_der], key.into())
}

/// Create a quinn server endpoint on localhost with datagrams enabled.
pub fn make_server_endpoint(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> (quinn::Endpoint, SocketAddr) {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    server_config.transport_config(transport);

    let endpoint = quinn::Endpoint::server(
        server_config,
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();

    let addr = endpoint.local_addr().unwrap();
    (endpoint, addr)
}

/// Create a quinn client endpoint that trusts the given server cert.
pub fn make_client_endpoint(
    server_certs: &[CertificateDer<'static>],
) -> quinn::Endpoint {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let mut roots = rustls::RootCertStore::empty();
    for cert in server_certs {
        roots.add(cert.clone()).unwrap();
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client_config =
        quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap()));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}
```

- [ ] **Step 2: Verify helpers compile**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test loopback -- --list 2>&1 | head -5`
Expected: compiles (may show "0 tests" since loopback.rs is still a stub)

- [ ] **Step 3: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/tests/helpers/
git commit -m "feat: add test helpers for QUIC endpoint setup with self-signed certs"
```

---

### Task 8: ConnectIpSession

The core session type shared between client and proxy. It wraps the h3 request stream and datagram sender/reader, exposing methods to send/receive IP packets and exchange capsules.

**Files:**
- Modify: `connect-ip/src/session.rs`

- [ ] **Step 1: Implement ConnectIpSession**

`connect-ip/src/session.rs`:
```rust
use bytes::{Buf, Bytes, BytesMut};
use h3::quic;
use h3_datagram::datagram_handler::{DatagramReader, DatagramSender, HandleDatagramsExt};
use h3_datagram::quic_traits::{DatagramConnectionExt, RecvDatagram, SendDatagram};

use crate::capsule::address::{
    AddressAssign, AddressRequest, AssignedAddress, RequestedAddress,
    decode_address_assign, decode_address_request,
    encode_address_assign, encode_address_request,
};
use crate::capsule::codec::{decode_capsule, encode_capsule, RawCapsule};
use crate::capsule::capsule_type;
use crate::capsule::route::{
    IpAddressRange, RouteAdvertisement,
    decode_route_advertisement, encode_route_advertisement,
};
use crate::datagram;
use crate::error::Error;

/// An established CONNECT-IP session.
///
/// Created by either `ConnectIpClient::connect()` or `ConnectIpRequest::accept()`.
/// Provides methods to send/receive IP packets and exchange capsules.
pub struct ConnectIpSession<S, H, R>
where
    S: quic::BidiStream<Bytes>,
    H: SendDatagram<Bytes>,
    R: RecvDatagram,
{
    /// The HTTP request stream — used for capsule I/O.
    stream: h3::server::RequestStream<S, Bytes>,
    /// Datagram sender scoped to this session's stream ID.
    dg_sender: DatagramSender<H, Bytes>,
    /// Datagram reader.
    dg_reader: DatagramReader<R>,
}

impl<S, H, R> ConnectIpSession<S, H, R>
where
    S: quic::BidiStream<Bytes>,
    S::SendStream: quic::SendStream<Bytes>,
    S::RecvStream: quic::RecvStream,
    H: SendDatagram<Bytes>,
    R: RecvDatagram,
{
    /// Create a new session from the established stream and datagram handles.
    pub(crate) fn new(
        stream: h3::server::RequestStream<S, Bytes>,
        dg_sender: DatagramSender<H, Bytes>,
        dg_reader: DatagramReader<R>,
    ) -> Self {
        Self { stream, dg_sender, dg_reader }
    }

    /// Send an IP packet through the tunnel via HTTP Datagram.
    pub fn send_ip_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut buf = BytesMut::with_capacity(1 + packet.len());
        datagram::encode_ip_datagram(packet, &mut buf);
        self.dg_sender
            .send_datagram(buf.freeze())
            .map_err(|e| Error::DatagramSend(format!("{e:?}")))?;
        Ok(())
    }

    /// Receive the next IP packet from the tunnel.
    ///
    /// Blocks until a datagram with Context ID 0 arrives.
    /// Datagrams with non-zero Context IDs are silently dropped.
    pub async fn recv_ip_packet(&mut self) -> Result<Bytes, Error> {
        loop {
            let dg = self.dg_reader.read_datagram().await
                .map_err(|e| Error::H3Stream(e))?;
            let mut payload = dg.into_payload();
            let (context_id, ip_packet) = datagram::decode_ip_datagram(&mut payload)?;
            if context_id == datagram::CONTEXT_ID_IP_PACKET {
                return Ok(ip_packet);
            }
            // Non-zero context IDs: drop silently per RFC 9484
        }
    }

    /// Send an ADDRESS_REQUEST capsule and wait for ADDRESS_ASSIGN response.
    pub async fn request_addresses(
        &mut self,
        requests: Vec<RequestedAddress>,
    ) -> Result<Vec<AssignedAddress>, Error> {
        let request = AddressRequest { addresses: requests };
        let mut payload = BytesMut::new();
        encode_address_request(&request, &mut payload);
        self.send_capsule(capsule_type::ADDRESS_REQUEST, payload.freeze()).await?;

        // Wait for ADDRESS_ASSIGN response
        loop {
            let capsule = self.recv_capsule().await?;
            if capsule.capsule_type == capsule_type::ADDRESS_ASSIGN {
                let mut data = capsule.payload;
                let assign = decode_address_assign(&mut data)?;
                return Ok(assign.addresses);
            }
            // Other capsule types: skip (could be ROUTE_ADVERTISEMENT, etc.)
        }
    }

    /// Send an ADDRESS_ASSIGN capsule to the peer.
    pub async fn assign_addresses(
        &mut self,
        addresses: Vec<AssignedAddress>,
    ) -> Result<(), Error> {
        let assign = AddressAssign { addresses };
        let mut payload = BytesMut::new();
        encode_address_assign(&assign, &mut payload);
        self.send_capsule(capsule_type::ADDRESS_ASSIGN, payload.freeze()).await
    }

    /// Send a ROUTE_ADVERTISEMENT capsule to the peer.
    pub async fn advertise_routes(
        &mut self,
        ranges: Vec<IpAddressRange>,
    ) -> Result<(), Error> {
        let routes = RouteAdvertisement { ranges };
        let mut payload = BytesMut::new();
        encode_route_advertisement(&routes, &mut payload);
        self.send_capsule(capsule_type::ROUTE_ADVERTISEMENT, payload.freeze()).await
    }

    /// Receive the next ROUTE_ADVERTISEMENT capsule from the peer.
    pub async fn recv_routes(&mut self) -> Result<Vec<IpAddressRange>, Error> {
        loop {
            let capsule = self.recv_capsule().await?;
            if capsule.capsule_type == capsule_type::ROUTE_ADVERTISEMENT {
                let mut data = capsule.payload;
                let routes = decode_route_advertisement(&mut data)?;
                return Ok(routes.ranges);
            }
        }
    }

    /// Get the effective tunnel MTU.
    ///
    /// This is the maximum IP packet size that can fit in a single QUIC DATAGRAM,
    /// accounting for HTTP/3 framing and Context ID overhead.
    pub fn tunnel_mtu(&self) -> Option<usize> {
        // TODO: Access the underlying quinn connection's max_datagram_size
        // and subtract framing overhead. For now, return a conservative value.
        // This will be refined when we have access to the quinn Connection.
        None
    }

    async fn send_capsule(&mut self, capsule_type: u64, payload: Bytes) -> Result<(), Error> {
        let capsule = RawCapsule { capsule_type, payload };
        let mut buf = BytesMut::new();
        encode_capsule(&capsule, &mut buf);
        self.stream.send_data(buf.freeze()).await?;
        Ok(())
    }

    async fn recv_capsule(&mut self) -> Result<RawCapsule, Error> {
        // Read data from the stream until we have a complete capsule
        let data = self.stream.recv_data().await?
            .ok_or(Error::SessionClosed)?;
        let mut bytes = Bytes::copy_from_slice(data.chunk());
        decode_capsule(&mut bytes)?
            .ok_or(Error::SessionClosed)
    }
}
```

Note: The generic types are complex because h3 is heavily generic over the QUIC backend. The actual types get resolved when used with h3-quinn. The `recv_capsule` implementation is simplified — a production version would need to handle partial reads and buffer across multiple `recv_data` calls. We'll refine this in integration testing.

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo check`
Expected: compiles (the h3-datagram `Datagram` type may need `into_payload()` or similar — adjust based on actual API)

Note: h3-datagram's `Datagram` struct may expose payload differently. Check the actual field/method name and adjust `recv_ip_packet`. The datagram has a `stream_id` and `payload` — access the payload via the public field or method. If the API differs, update accordingly.

- [ ] **Step 3: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/session.rs
git commit -m "feat: implement ConnectIpSession with IP packet and capsule I/O"
```

---

### Task 9: ConnectIpProxy (server/responder side)

Accepts incoming CONNECT-IP requests on an h3 server connection and creates sessions.

**Files:**
- Modify: `connect-ip/src/proxy.rs`

- [ ] **Step 1: Implement ConnectIpProxy and ConnectIpRequest**

`connect-ip/src/proxy.rs`:
```rust
use bytes::Bytes;
use h3::ext::Protocol;
use h3::quic;
use h3::server::RequestStream;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_datagram::quic_traits::DatagramConnectionExt;
use http::{Method, Response, StatusCode};

use crate::error::Error;
use crate::session::ConnectIpSession;

/// Accepts incoming CONNECT-IP requests from an h3 server connection.
pub struct ConnectIpProxy;

impl ConnectIpProxy {
    /// Accept the next CONNECT-IP request from the h3 server connection.
    ///
    /// This loops over incoming requests, rejecting non-CONNECT-IP requests with 400,
    /// until a valid CONNECT-IP request arrives.
    pub async fn accept<C, B>(
        conn: &mut h3::server::Connection<C, B>,
    ) -> Result<Option<ConnectIpRequest<C, B>>, Error>
    where
        C: quic::Connection<B> + DatagramConnectionExt<B>,
        B: bytes::Buf,
    {
        while let Some(resolver) = conn.accept().await? {
            let (request, stream) = resolver.resolve_request().await?;

            let is_connect_ip = request.method() == Method::CONNECT
                && request
                    .extensions()
                    .get::<Protocol>()
                    .map_or(false, |p| p == &Protocol::CONNECT_IP);

            if !is_connect_ip {
                // Not a CONNECT-IP request — reject
                let mut stream = stream;
                let resp = Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(())
                    .unwrap();
                let _ = stream.send_response(resp).await;
                continue;
            }

            // Extract target and ipproto from the URI path
            let path = request.uri().path().to_string();
            let (target, ip_protocol) = parse_connect_ip_path(&path);

            return Ok(Some(ConnectIpRequest {
                target,
                ip_protocol,
                stream,
            }));
        }

        // Connection closed
        Ok(None)
    }
}

/// A pending CONNECT-IP request that can be accepted or rejected.
pub struct ConnectIpRequest<C, B>
where
    C: quic::Connection<B>,
    B: bytes::Buf,
{
    pub target: String,
    pub ip_protocol: String,
    stream: RequestStream<C::BidiStream, B>,
}

impl<C, B> ConnectIpRequest<C, B>
where
    C: quic::Connection<B> + DatagramConnectionExt<B>,
    h3::server::Connection<C, B>: HandleDatagramsExt<C, B>,
    B: bytes::Buf,
{
    /// Accept the request and create a CONNECT-IP session.
    ///
    /// `conn` is the h3 server connection, needed to access the datagram sender/reader.
    pub async fn accept_with_conn(
        mut self,
        conn: &h3::server::Connection<C, B>,
    ) -> Result<
        ConnectIpSession<
            C::BidiStream,
            <C as DatagramConnectionExt<B>>::SendDatagramHandler,
            <C as DatagramConnectionExt<B>>::RecvDatagramHandler,
        >,
        Error,
    > {
        // Send 200 OK
        let resp = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .unwrap();
        self.stream.send_response(resp).await?;

        let stream_id = self.stream.send_id();
        let dg_sender = conn.get_datagram_sender(stream_id);
        let dg_reader = conn.get_datagram_reader();

        Ok(ConnectIpSession::new(self.stream, dg_sender, dg_reader))
    }

    /// Reject the request with an HTTP error status.
    pub async fn reject(mut self, status: StatusCode) -> Result<(), Error> {
        let resp = Response::builder().status(status).body(()).unwrap();
        self.stream.send_response(resp).await?;
        Ok(())
    }
}

/// Parse the CONNECT-IP URI path to extract target and ipproto.
///
/// Expected format: `/.well-known/masque/ip/{target}/{ipproto}/`
/// Returns (target, ipproto) as raw strings. "*" for wildcards.
fn parse_connect_ip_path(path: &str) -> (String, String) {
    let segments: Vec<&str> = path
        .trim_matches('/')
        .split('/')
        .collect();

    // Expected: [".well-known", "masque", "ip", target, ipproto]
    if segments.len() >= 5
        && segments[0] == ".well-known"
        && segments[1] == "masque"
        && segments[2] == "ip"
    {
        let target = urlencoding_decode(segments[3]);
        let ipproto = urlencoding_decode(segments[4]);
        return (target, ipproto);
    }

    // Fallback: return wildcards
    ("*".into(), "*".into())
}

/// Simple percent-decoding for URI template variables.
fn urlencoding_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            if let (Some(h), Some(l)) = (chars.next(), chars.next()) {
                if let Ok(byte) = u8::from_str_radix(
                    &format!("{}{}", h as char, l as char),
                    16,
                ) {
                    result.push(byte as char);
                    continue;
                }
            }
        }
        result.push(b as char);
    }
    result
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo check`
Expected: compiles. There may be trait bound issues with h3-datagram generics — if `HandleDatagramsExt` is not implemented as expected, adjust the bounds. The key patterns to match come from h3-webtransport's session code.

- [ ] **Step 3: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/proxy.rs
git commit -m "feat: implement ConnectIpProxy for accepting CONNECT-IP requests"
```

---

### Task 10: ConnectIpClient (initiator side)

**Files:**
- Modify: `connect-ip/src/client.rs`

- [ ] **Step 1: Implement ConnectIpClient**

`connect-ip/src/client.rs`:
```rust
use std::net::SocketAddr;

use bytes::Bytes;
use h3::ext::Protocol;
use h3::quic;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use h3_datagram::quic_traits::DatagramConnectionExt;
use http::{Method, Request, StatusCode};

use crate::error::Error;
use crate::session::ConnectIpSession;

/// Client for initiating CONNECT-IP connections to a proxy.
pub struct ConnectIpClient;

impl ConnectIpClient {
    /// Connect to a CONNECT-IP proxy and establish a tunnel session.
    ///
    /// `target` is the scope of the tunnel: a hostname, IP prefix, or "*" for wildcard.
    /// `ip_protocol` is the IP protocol scope: a number 0-255 or "*" for all.
    pub async fn connect<C, O>(
        quic_conn: C,
        target: &str,
        ip_protocol: &str,
    ) -> Result<
        (
            ConnectIpSession<
                <O as quic::OpenStreams<Bytes>>::BidiStream,
                <C as DatagramConnectionExt<Bytes>>::SendDatagramHandler,
                <C as DatagramConnectionExt<Bytes>>::RecvDatagramHandler,
            >,
            h3::client::Connection<C, Bytes>,
        ),
        Error,
    >
    where
        C: quic::Connection<Bytes, OpenStreams = O> + DatagramConnectionExt<Bytes>,
        O: quic::OpenStreams<Bytes>,
        h3::client::Connection<C, Bytes>: HandleDatagramsExt<C, Bytes>,
    {
        // Build h3 client connection
        let (mut driver, mut send_request) = h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, _, Bytes>(quic_conn)
            .await?;

        // Build the Extended CONNECT request
        let path = format!(
            "/.well-known/masque/ip/{}/{}/",
            percent_encode(target),
            percent_encode(ip_protocol),
        );

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://proxy{path}"))
            .extension(Protocol::CONNECT_IP)
            .body(())
            .map_err(|e| Error::ProtocolViolation(format!("failed to build request: {e}")))?;

        let mut stream = send_request.send_request(req).await?;

        // Read the response
        let resp = stream.recv_response().await?;

        if !resp.status().is_success() {
            return Err(Error::ProtocolViolation(format!(
                "proxy rejected CONNECT-IP request: {}",
                resp.status()
            )));
        }

        // Set up datagram sender/reader
        let stream_id = stream.send_id();
        let dg_sender = driver.get_datagram_sender(stream_id);
        let dg_reader = driver.get_datagram_reader();

        let session = ConnectIpSession::new(stream, dg_sender, dg_reader);
        Ok((session, driver))
    }
}

/// Percent-encode a target or ipproto value for the URI template.
fn percent_encode(s: &str) -> String {
    if s == "*" {
        return "*".into();
    }
    // Encode colons (IPv6), slashes (prefix notation)
    s.replace(':', "%3A").replace('/', "%2F")
}
```

Note: The `ConnectIpSession` generic parameters use the client-side `RequestStream` which has the same shape as server-side. The `stream` returned by `send_request` is `RequestStream<BidiStream, Bytes>`. The session type in `session.rs` uses `h3::server::RequestStream` — we may need to make session generic over the stream type, or use `h3::client::RequestStream` separately. This will be resolved during compilation in Step 2. The key issue is that `h3::server::RequestStream` and the stream from `send_request` should be structurally compatible (both wrap a `BidiStream`). If they're not, we'll create a trait abstraction or use the client stream type directly.

- [ ] **Step 2: Verify it compiles and fix type issues**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo check`
Expected: may need adjustments to `ConnectIpSession` generics to work with both client and server stream types. Fix any compilation errors. The h3 crate's generics are complex — follow compiler guidance.

- [ ] **Step 3: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/src/client.rs connect-ip/src/session.rs
git commit -m "feat: implement ConnectIpClient for initiating CONNECT-IP connections"
```

---

### Task 11: Loopback Integration Test

The critical test: client connects to proxy over localhost, exchanges capsules, and sends IP packets bidirectionally.

**Files:**
- Modify: `connect-ip/tests/loopback.rs`

- [ ] **Step 1: Write the integration test**

`connect-ip/tests/loopback.rs`:
```rust
mod helpers;

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use connect_ip::capsule::address::{AssignedAddress, RequestedAddress};
use connect_ip::capsule::route::IpAddressRange;
use connect_ip::client::ConnectIpClient;
use connect_ip::proxy::ConnectIpProxy;
use connect_ip::types::IpVersion;

#[tokio::test]
async fn client_connects_to_proxy() {
    let (certs, key) = helpers::generate_test_certs();
    let (server_endpoint, server_addr) = helpers::make_server_endpoint(certs.clone(), key);
    let client_endpoint = helpers::make_client_endpoint(&certs);

    // Spawn proxy
    let proxy_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        assert_eq!(request.target, "*");
        assert_eq!(request.ip_protocol, "*");

        let mut session = request.accept_with_conn(&conn).await.unwrap();

        // Proxy receives an IP packet from client
        let packet = session.recv_ip_packet().await.unwrap();
        assert_eq!(packet.as_ref(), &[0x45u8; 20]);

        // Proxy sends an IP packet back
        session.send_ip_packet(&[0x60u8; 40]).unwrap();
    });

    // Client
    let quic_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let (mut session, driver) = ConnectIpClient::connect(h3_conn, "*", "*")
        .await
        .unwrap();

    // Drive the h3 connection in background
    tokio::spawn(async move {
        let mut driver = driver;
        let _ = driver.wait_idle().await;
    });

    // Client sends an IP packet
    session.send_ip_packet(&[0x45u8; 20]).unwrap();

    // Client receives an IP packet
    let packet = session.recv_ip_packet().await.unwrap();
    assert_eq!(packet.as_ref(), &[0x60u8; 40]);

    proxy_handle.await.unwrap();
}

#[tokio::test]
async fn address_negotiation_flow() {
    let (certs, key) = helpers::generate_test_certs();
    let (server_endpoint, server_addr) = helpers::make_server_endpoint(certs.clone(), key);
    let client_endpoint = helpers::make_client_endpoint(&certs);

    let proxy_handle = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let quic_conn = incoming.await.unwrap();
        let h3_conn = h3_quinn::Connection::new(quic_conn);

        let mut conn = h3::server::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build(h3_conn)
            .await
            .unwrap();

        let request = ConnectIpProxy::accept(&mut conn).await.unwrap().unwrap();
        let mut session = request.accept_with_conn(&conn).await.unwrap();

        // Proxy receives address request from client (via capsule on the stream)
        // For this test, proxy assigns addresses and advertises routes
        session
            .assign_addresses(vec![AssignedAddress {
                request_id: 1,
                ip_version: IpVersion::V4,
                address: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
                prefix_length: 32,
            }])
            .await
            .unwrap();

        session
            .advertise_routes(vec![IpAddressRange {
                ip_version: IpVersion::V4,
                start: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 255)),
                ip_protocol: 0,
            }])
            .await
            .unwrap();
    });

    let quic_conn = client_endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let (mut session, driver) = ConnectIpClient::connect(h3_conn, "*", "*")
        .await
        .unwrap();

    tokio::spawn(async move {
        let mut driver = driver;
        let _ = driver.wait_idle().await;
    });

    // Client requests an address
    let assigned = session
        .request_addresses(vec![RequestedAddress {
            request_id: 1,
            ip_version: IpVersion::V4,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_length: 32,
        }])
        .await
        .unwrap();

    assert_eq!(assigned.len(), 1);
    assert_eq!(assigned[0].address, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)));

    // Client receives routes
    let routes = session.recv_routes().await.unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].start, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)));

    proxy_handle.await.unwrap();
}
```

- [ ] **Step 2: Run the test**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test --test loopback -- --nocapture`
Expected: This will likely have compilation errors first — resolve them. Then the test should pass. The most likely issues are:
1. h3-datagram trait bounds not matching — adjust generics
2. `RequestStream` type mismatch between client and server — may need to make `ConnectIpSession` accept either
3. `Datagram` payload access method name

Fix issues iteratively until both tests pass.

- [ ] **Step 3: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/tests/loopback.rs
git commit -m "test: add loopback integration test for client <-> proxy IP tunneling"
```

---

### Task 12: Fuzz Targets

**Files:**
- Create: `connect-ip/fuzz/Cargo.toml`
- Create: `connect-ip/fuzz/fuzz_targets/fuzz_capsule.rs`
- Create: `connect-ip/fuzz/fuzz_targets/fuzz_datagram.rs`

- [ ] **Step 1: Create fuzz Cargo.toml**

`connect-ip/fuzz/Cargo.toml`:
```toml
[package]
name = "connect-ip-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
bytes = "1"
connect-ip = { path = ".." }

[[bin]]
name = "fuzz_capsule"
path = "fuzz_targets/fuzz_capsule.rs"
doc = false

[[bin]]
name = "fuzz_datagram"
path = "fuzz_targets/fuzz_datagram.rs"
doc = false
```

- [ ] **Step 2: Create fuzz_capsule target**

`connect-ip/fuzz/fuzz_targets/fuzz_capsule.rs`:
```rust
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);

    // Fuzz the raw capsule decoder — must never panic
    while buf.has_remaining() {
        use bytes::Buf;
        match connect_ip::capsule::codec::decode_capsule(&mut buf) {
            Ok(Some(capsule)) => {
                // Try to decode the payload as each known capsule type
                let mut payload = capsule.payload.clone();
                let _ = connect_ip::capsule::address::decode_address_assign(&mut payload);

                let mut payload = capsule.payload.clone();
                let _ = connect_ip::capsule::address::decode_address_request(&mut payload);

                let mut payload = capsule.payload;
                let _ = connect_ip::capsule::route::decode_route_advertisement(&mut payload);
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
});
```

- [ ] **Step 3: Create fuzz_datagram target**

`connect-ip/fuzz/fuzz_targets/fuzz_datagram.rs`:
```rust
#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = Bytes::copy_from_slice(data);

    // Fuzz the datagram decoder — must never panic
    let _ = connect_ip::datagram::decode_ip_datagram(&mut buf);
});
```

- [ ] **Step 4: Verify fuzz targets compile**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo +nightly fuzz build 2>&1 | tail -5`
Expected: builds successfully (requires nightly toolchain and `cargo-fuzz` installed)

If nightly is not available, just verify the fuzz crate compiles:
Run: `cd /home/haoye/Source/ipowt/connect-ip/fuzz && cargo check`

- [ ] **Step 5: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/fuzz/
git commit -m "feat: add fuzz targets for capsule and datagram parsers"
```

---

### Task 13: Benchmark

**Files:**
- Create: `connect-ip/benches/throughput.rs`

- [ ] **Step 1: Create throughput benchmark**

`connect-ip/benches/throughput.rs`:
```rust
use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use connect_ip::capsule::codec::{encode_capsule, decode_capsule, RawCapsule};
use connect_ip::datagram::{encode_ip_datagram, decode_ip_datagram};
use connect_ip::varint;

fn bench_varint(c: &mut Criterion) {
    let mut group = c.benchmark_group("varint");

    group.bench_function("encode_1byte", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(8);
            varint::encode(42, &mut buf);
        })
    });

    group.bench_function("encode_8byte", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(8);
            varint::encode(4_000_000_000u64, &mut buf);
        })
    });

    group.bench_function("decode_1byte", |b| {
        let data = Bytes::from_static(&[0x2A]);
        b.iter(|| {
            let mut buf = data.clone();
            varint::decode(&mut buf).unwrap();
        })
    });

    group.finish();
}

fn bench_capsule_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("capsule");

    let payload_1k = Bytes::from(vec![0xAAu8; 1024]);
    let capsule_1k = RawCapsule {
        capsule_type: 0x01,
        payload: payload_1k.clone(),
    };

    group.throughput(Throughput::Bytes(1024));

    group.bench_function("encode_1k", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1030);
            encode_capsule(&capsule_1k, &mut buf);
        })
    });

    group.bench_function("decode_1k", |b| {
        let mut encoded = BytesMut::new();
        encode_capsule(&capsule_1k, &mut encoded);
        let encoded = encoded.freeze();
        b.iter(|| {
            let mut buf = encoded.clone();
            decode_capsule(&mut buf).unwrap().unwrap();
        })
    });

    group.finish();
}

fn bench_datagram_framing(c: &mut Criterion) {
    let mut group = c.benchmark_group("datagram");

    // Typical IPv4 packet: 1400 bytes (MTU - headers)
    let packet = vec![0x45u8; 1400];
    group.throughput(Throughput::Bytes(1400));

    group.bench_function("encode_1400b", |b| {
        b.iter(|| {
            let mut buf = BytesMut::with_capacity(1401);
            encode_ip_datagram(&packet, &mut buf);
        })
    });

    group.bench_function("decode_1400b", |b| {
        let mut encoded = BytesMut::with_capacity(1401);
        encode_ip_datagram(&packet, &mut encoded);
        let encoded = encoded.freeze();
        b.iter(|| {
            let mut buf = encoded.clone();
            decode_ip_datagram(&mut buf).unwrap();
        })
    });

    group.finish();
}

criterion_group!(benches, bench_varint, bench_capsule_codec, bench_datagram_framing);
criterion_main!(benches);
```

- [ ] **Step 2: Verify benchmark compiles**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo bench --no-run`
Expected: compiles successfully

- [ ] **Step 3: Run benchmarks to establish baseline**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo bench`
Expected: benchmark results printed — save these as baseline numbers.

- [ ] **Step 4: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/benches/
git commit -m "feat: add throughput benchmarks for varint, capsule, and datagram codecs"
```

---

### Task 14: Examples

Minimal working examples that demonstrate the public API.

**Files:**
- Create: `connect-ip/examples/simple_proxy.rs`
- Create: `connect-ip/examples/simple_client.rs`

- [ ] **Step 1: Create simple_proxy example**

`connect-ip/examples/simple_proxy.rs`:
```rust
//! Minimal CONNECT-IP proxy that accepts one connection and echoes IP packets.
//!
//! Usage: cargo run --example simple_proxy

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use connect_ip::proxy::ConnectIpProxy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // Generate self-signed cert
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key: PrivateKeyDer = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into();
    let cert_der = CertificateDer::from(cert.cert);

    // Save cert for client to use
    std::fs::write("cert.der", cert_der.as_ref())?;
    println!("Certificate written to cert.der");

    // Configure QUIC with datagrams
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    server_config.transport_config(transport);

    let endpoint = quinn::Endpoint::server(server_config, bind_addr)?;
    println!("CONNECT-IP proxy listening on {bind_addr}");

    // Accept one connection
    let incoming = endpoint.accept().await.unwrap();
    let quic_conn = incoming.await?;
    println!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);
    let mut conn = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_conn)
        .await?;

    // Accept CONNECT-IP request
    if let Some(request) = ConnectIpProxy::accept(&mut conn).await? {
        println!(
            "CONNECT-IP request: target={}, ipproto={}",
            request.target, request.ip_protocol
        );

        let mut session = request.accept_with_conn(&conn).await?;
        println!("Session established — echoing IP packets");

        // Echo loop
        loop {
            match session.recv_ip_packet().await {
                Ok(packet) => {
                    println!("Received {} byte IP packet, echoing back", packet.len());
                    session.send_ip_packet(&packet)?;
                }
                Err(e) => {
                    println!("Session ended: {e}");
                    break;
                }
            }
        }
    }

    Ok(())
}
```

- [ ] **Step 2: Create simple_client example**

`connect-ip/examples/simple_client.rs`:
```rust
//! Minimal CONNECT-IP client that connects to the proxy and sends a test packet.
//!
//! Usage: cargo run --example simple_client
//!
//! Requires simple_proxy to be running and cert.der to exist.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use rustls::pki_types::CertificateDer;

use connect_ip::client::ConnectIpClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proxy_addr: SocketAddr = "127.0.0.1:4433".parse()?;

    // Load proxy certificate
    let cert_data = std::fs::read("cert.der")?;
    let cert = CertificateDer::from(cert_data);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;

    // Configure QUIC with datagrams
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(65535));
    transport.datagram_send_buffer_size(65535);
    let transport = Arc::new(transport);

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    client_config.transport_config(transport);

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);

    // Connect to proxy
    println!("Connecting to proxy at {proxy_addr}...");
    let quic_conn = endpoint.connect(proxy_addr, "localhost")?.await?;
    println!("QUIC connection established");

    let h3_conn = h3_quinn::Connection::new(quic_conn);

    let (mut session, driver) =
        ConnectIpClient::connect(h3_conn, "*", "*").await?;
    println!("CONNECT-IP session established");

    // Drive h3 connection in background
    tokio::spawn(async move {
        let mut driver = driver;
        let _ = driver.wait_idle().await;
    });

    // Send a fake IPv4 packet (20-byte header, all 0x45)
    let test_packet = vec![0x45u8; 20];
    session.send_ip_packet(&test_packet)?;
    println!("Sent {} byte test packet", test_packet.len());

    // Receive echo
    let echoed = session.recv_ip_packet().await?;
    println!("Received {} byte echo", echoed.len());
    assert_eq!(echoed.as_ref(), test_packet.as_slice());
    println!("Echo matches — tunnel working!");

    Ok(())
}
```

- [ ] **Step 3: Verify examples compile**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo build --examples`
Expected: compiles

- [ ] **Step 4: Commit**

```bash
cd /home/haoye/Source/ipowt
git add connect-ip/examples/
git commit -m "feat: add simple_proxy and simple_client examples"
```

---

### Task 15: API Refinement and Final Integration

Run all tests, fix any remaining issues, and ensure the full test suite passes.

**Files:**
- Potentially modify any file from previous tasks

- [ ] **Step 1: Run full test suite**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo test`
Expected: all unit tests and integration tests pass

- [ ] **Step 2: Run clippy**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo clippy -- -D warnings`
Expected: no warnings

- [ ] **Step 3: Run cargo doc**

Run: `cd /home/haoye/Source/ipowt/connect-ip && cargo doc --no-deps`
Expected: documentation builds cleanly

- [ ] **Step 4: Fix any issues found in steps 1-3**

Address clippy warnings, documentation issues, and any test failures. Iterate until all three commands pass cleanly.

- [ ] **Step 5: Final commit**

```bash
cd /home/haoye/Source/ipowt
git add -A
git commit -m "chore: polish connect-ip crate — clippy, docs, test fixes"
```
