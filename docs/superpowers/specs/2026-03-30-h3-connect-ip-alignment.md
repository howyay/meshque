# meshque / connect-ip-rs / h3 Alignment Memo

## Purpose

Capture the intended boundary between upstream `h3`, our standalone `connect-ip-rs` crate, and the `meshque` application so future work stays aligned with Hyperium instead of duplicating or fighting it.

## Bottom Line

- `h3` is the HTTP/3 substrate.
- `connect-ip-rs` is the RFC 9484 (CONNECT-IP) implementation layer.
- `meshque` is the product/application layer.

This is the right split.

## What Upstream `h3` Currently Appears To Cover

Evidence from the upstream `hyperium/h3` repository:

- The repo describes itself as a generic async HTTP/3 implementation, with separate crates for `h3-quinn`, `h3-datagram`, and `h3-webtransport`.
- Issue `#164` (`CONNECT and tunnel support`) shows upstream is aware of generic CONNECT / tunnel support as an HTTP/3 concern.
- PR `#273` (`Added connect-ip (RFC9484) as a known HTTP/3 CONNECT protocol`) adds `Protocol::CONNECT_IP` support.
- PR `#282` (`Add extended CONNECT setting for client conn`) adds client Extended CONNECT support.
- PR `#280` (`Add datagram support for client`) expands client-side HTTP Datagram support.
- PR `#322` (`Correct behavior of standard CONNECT`) continues improving generic CONNECT behavior.
- Earlier datagram work was split into `h3-datagram` (for example PR `#199` and later release/publication work).

### Interpretation

Upstream `h3` is adding the primitives CONNECT-IP needs:

- generic Extended CONNECT handling
- generic HTTP Datagram support
- protocol tagging such as `Protocol::CONNECT_IP`

But that is not the same thing as a full RFC 9484 implementation.

## What `h3` Does **Not** Seem To Own

Based on the upstream repo shape and issue/PR history, `h3` does not appear to position itself as the place for:

- CONNECT-IP session semantics
- RFC 9484 capsule definitions and codecs
- ADDRESS_ASSIGN / ADDRESS_REQUEST / ROUTE_ADVERTISEMENT handling
- CONNECT-IP path/target/ip-protocol validation
- tunnel MTU rules and packet framing semantics specific to RFC 9484

That is consistent with issue `#164`, where generic tunnel support is discussed as an API concern while application-specific forwarding is expected to stay outside `h3`.

## What `connect-ip-rs` Owns

`connect-ip-rs` should remain the protocol library that builds RFC 9484 on top of `h3`.

Evidence in local code:

- `connect-ip/src/client.rs`
  - enables Extended CONNECT and datagrams
  - sets `Protocol::CONNECT_IP`
  - exposes `ConnectIpClient`
- `connect-ip/src/proxy.rs`
  - accepts and validates CONNECT-IP requests
  - exposes `ConnectIpProxy`
- `connect-ip/src/session.rs`
  - implements datagram send/recv for IP packets
  - implements capsule send/recv and session splitting
- `connect-ip/src/capsule/*`
  - implements RFC 9484 capsule types and codecs

### `connect-ip-rs` Responsibilities

- RFC 9484 request semantics
- capsule definitions and wire codec
- CONNECT-IP session abstraction
- IP packet framing over HTTP Datagrams
- MTU logic specific to CONNECT-IP
- interop at the MASQUE protocol layer

## What `meshque` Owns

`meshque` should remain the application/product layer.

Local evidence:

- `meshque/src/mesh.rs`
- `meshque/src/connection.rs`
- `meshque/src/tun_device.rs`
- signaling server and peer lifecycle code

### `meshque` Responsibilities

- TUN device setup
- peer identity and restart behavior
- signaling / discovery / endpoint exchange
- connection orchestration and reconnect behavior
- routing packets between TUN and CONNECT-IP tunnels
- product-specific UX / CLI / deployment concerns

## Current Alignment Assessment

The current project split is aligned with upstream `h3`.

We are not reimplementing generic HTTP/3 in `connect-ip-rs` or `meshque`.
We are using `h3`, `h3-quinn`, and `h3-datagram` as intended, while implementing the RFC 9484 layer above them.

That is healthy and should continue.

## Upstreaming Strategy

### Good candidates to upstream to `h3`

Only upstream changes that improve generic HTTP/3 or tunnel ergonomics:

- generic CONNECT API improvements
- generic datagram API improvements
- protocol enum / metadata support
- generic connection-lifecycle hooks needed by tunnel protocols
- generic stream/datagram ownership ergonomics

### Keep in `connect-ip-rs`

Do **not** try to upstream the RFC 9484 implementation itself into `h3`.
That includes:

- `ConnectIpClient` / `ConnectIpProxy`
- capsule types and codecs
- CONNECT-IP path rules
- route/address exchange semantics
- CONNECT-IP-specific MTU logic

### Keep in `meshque`

Do **not** try to upstream application behavior:

- TUN routing
- signaling server integration
- peer restart identity
- reconnect policy
- mesh topology logic

## Near-Term Actions

1. Keep using `h3` git main until a release includes the upstream CONNECT-IP-related primitives we rely on.
2. Periodically check upstream for release/tag notes that include:
   - `Protocol::CONNECT_IP`
   - Extended CONNECT client/server support improvements
   - datagram API changes
3. If `connect-ip-rs` hits friction due to generic `h3` limitations, upstream those generic improvements narrowly.
4. Avoid pushing MASQUE session semantics into `h3`; keep `connect-ip-rs` as the reusable RFC 9484 crate.

## Decision

Continue with the current architecture:

- `h3` as substrate
- `connect-ip-rs` as reusable CONNECT-IP/MASQUE protocol crate
- `meshque` as the VPN product

This keeps our work aligned with upstream while preserving a clean reusable boundary for RFC 9484 logic.
