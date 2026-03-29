# Plan: Make `connect-ip` Crate Production-Ready

## Context

Phase 1a of meshque — the `connect-ip` crate — has core datagram tunneling working (35 tests, client↔proxy loopback proven). But the design spec requires capsule I/O on sessions, MTU handling, and interop testing before the crate is production-ready.

## Current State

**Working:**
- Wire format: varint, capsule TLV encode/decode, datagram framing
- Capsule types: ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT (encode/decode only)
- Session: send/recv IP packets via HTTP datagrams
- Proxy: accept CONNECT-IP requests, create sessions
- Client: initiate CONNECT-IP connections
- Integration: client↔proxy loopback over localhost

**Missing (from design spec):**
1. Session capsule I/O — address negotiation, route exchange
2. MTU handling — query quinn for max datagram size, report tunnel MTU
3. Session close — graceful shutdown
4. Unknown capsule type handling — skip silently per RFC 9297
5. Streaming capsule decoder on HTTP request stream
6. Interop tests (connect-ip-go, optionally Cloudflare WARP)
7. Additional RFC conformance tests

## Architecture Challenge

The session currently only holds datagram handlers. To add capsule I/O, it needs the HTTP request stream. But server and client `RequestStream` are different types in h3.

**Solution:** The session will hold the stream as a type parameter. Server sessions use `h3::server::RequestStream<S, Bytes>`, client sessions use `h3::client::RequestStream<S, Bytes>`. Both have identical `send_data`/`recv_data`/`finish` methods. We use a trait `CapsuleStream` to abstract over both.

## Tasks

### Task A: CapsuleStream trait + session capsule I/O

**Files:** `src/session.rs`, `src/proxy.rs`, `src/client.rs`

1. Define a `CapsuleStream` trait with `send_data`, `recv_data`, `finish` methods
2. Implement for both `h3::server::RequestStream` and `h3::client::RequestStream`
3. Add the stream to `ConnectIpSession` as a type parameter
4. Implement session capsule methods:
   - `send_capsule(RawCapsule)` — encode + send_data
   - `recv_capsule() -> RawCapsule` — recv_data + decode
   - `send_address_assign(AddressAssign)`
   - `recv_address_assign() -> AddressAssign`
   - `send_address_request(AddressRequest)`
   - `recv_address_request() -> AddressRequest`
   - `send_route_advertisement(RouteAdvertisement)`
   - `recv_route_advertisement() -> RouteAdvertisement`
5. Higher-level:
   - `request_addresses(Vec<RequestedAddress>) -> Vec<AssignedAddress>` — send request + await assign response
   - `assign_addresses(Vec<AssignedAddress>)` — send assign capsule
   - `advertise_routes(Vec<IpAddressRange>)` — send route advertisement
   - `recv_routes() -> Vec<IpAddressRange>` — await route advertisement
6. Update proxy and client to pass the stream into the session
7. Unknown capsule types: skip silently in recv_capsule loop

### Task B: MTU handling

**Files:** `src/session.rs`, `src/datagram.rs`

1. Add `tunnel_mtu()` method to session that:
   - Queries the underlying QUIC connection for max datagram size
   - Subtracts HTTP/3 datagram framing overhead (quarter stream ID varint)
   - Subtracts Context ID overhead (1 byte for context ID 0)
   - Returns the effective max IP packet size
2. This requires access to the quinn Connection in the session.
   The h3-datagram `DatagramSender` wraps the quinn Connection, but doesn't expose max_datagram_size.
   Solution: Store the quinn Connection handle separately, or compute MTU at session creation time.

### Task C: Session close

**Files:** `src/session.rs`

1. Add `close()` method that:
   - Calls `finish()` on the request stream (sends FIN)
   - Drops datagram handlers
2. Add `Drop` impl for clean shutdown if not explicitly closed

### Task D: Additional RFC conformance tests

**Files:** `tests/address_negotiation.rs`, `tests/capsule_codec.rs` (add tests)

1. Address negotiation flow over loopback:
   - Client sends ADDRESS_REQUEST, proxy responds with ADDRESS_ASSIGN
   - Unsolicited ADDRESS_ASSIGN from proxy
   - ADDRESS_ASSIGN that removes previous addresses (empty list)
2. Route exchange flow over loopback:
   - Proxy sends ROUTE_ADVERTISEMENT, client receives
3. Unknown capsule type handling:
   - Send a capsule with type 0xFF, verify it's skipped silently
4. Capsule on closed stream:
   - Verify errors are handled gracefully
5. Malformed capsule in stream:
   - Feed truncated capsule via stream, verify stream abort

### Task E: Interop testing

**Files:** `tests/interop/go_proxy.rs`, `tests/interop/mod.rs`

1. Research connect-ip-go: find the repo, understand its API, determine how to run it
2. Write test that starts go proxy, connects with our Rust client
3. Write test that starts our Rust proxy, connects with go client
4. Gate behind `--features interop`
5. Cloudflare WARP interop: research feasibility, add if practical

### Task F: Final polish

1. Run clippy, fix warnings
2. Run all tests
3. Run benchmarks, verify they work
4. Verify fuzz targets compile
5. Update lib.rs re-exports if new public types added
6. Ensure cargo doc builds cleanly
