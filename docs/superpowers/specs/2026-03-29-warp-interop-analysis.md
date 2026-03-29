# Cloudflare WARP MASQUE Interop Analysis

> Assessed 2026-03-29. Conclusion: defer to Phase 4. Not standard RFC 9484.

## Background

Cloudflare WARP uses a MASQUE-based tunnel (CONNECT-IP over HTTP/3) but with non-standard modifications. The open-source [Usque](https://github.com/Diniboy1123/usque) project reverse-engineered the protocol by decrypting QUIC traffic from the official client.

## Protocol Differences from RFC 9484

| Aspect | RFC 9484 | Cloudflare WARP |
|---|---|---|
| `:protocol` header | `connect-ip` | `cf-connect-ip` |
| Extended CONNECT | Server advertises via SETTINGS | Not advertised; client must skip the check |
| URI template | `/.well-known/masque/ip/{target}/{ipproto}/` | `https://cloudflareaccess.com/` (no path, no variables) |
| ROUTE_ADVERTISEMENT | Proxy sends routes to client | Not sent; client just starts sending packets |
| H3 datagram setting | Standard `SETTINGS_ENABLE_CONNECT_PROTOCOL` | Also sends deprecated `SETTINGS_H3_DATAGRAM_00 = 0x276` |
| Authentication | Out of scope for RFC | Client TLS certificate (ECDSA secp256r1) registered via Cloudflare API |

## Connection Flow

1. Register device via `https://api.cloudflareclient.com/v0a4471/reg` (creates WireGuard + MASQUE keys)
2. Generate ECDSA keypair, send public key to API with `tunnel_type: "masque"`
3. Generate self-signed certificate from the keypair
4. QUIC connect to `162.159.198.1:443` with:
   - SNI: `consumer-masque.cloudflareclient.com`
   - ALPN: `h3`
   - Client certificate from step 3
5. Send Extended CONNECT with `:protocol: cf-connect-ip` to `https://cloudflareaccess.com/`
6. Include `Capsule-Protocol: ?1` header
7. Receive 200 OK (with `Cf-Team` header containing team ID)
8. Start sending/receiving IP packets as datagrams with Context ID 0
9. No capsule exchange needed (no routes or addresses advertised by server)

## Why Not Test Now

- It's a **Cloudflare-specific dialect**, not standard RFC 9484
- Requires API registration + live network access to Cloudflare infrastructure
- Our connect-ip-go interop test already validates wire-format RFC compliance
- WARP compatibility is a **product feature** (meshque Phase 4), not a crate correctness test

## Implementation Notes for Phase 4

When we do implement WARP compatibility:

- Usque uses a **fork** of connect-ip-go: `github.com/Diniboy1123/connect-ip-go` (adds `cf-connect-ip` protocol support)
- The fork's changes are minimal — mainly the protocol string and skipping ExtendedConnect checks
- Our Rust crate would need:
  - Configurable `:protocol` value (default `connect-ip`, option for `cf-connect-ip`)
  - Configurable URI (not just the default template)
  - Skip ExtendedConnect requirement when connecting to WARP
  - ECDSA cert generation + Cloudflare API client
  - Pin to Cloudflare's server public key (custom `VerifyPeerCertificate`)

## References

- [Usque](https://github.com/Diniboy1123/usque) — open-source WARP MASQUE client (Go)
- [Usque RESEARCH.md](https://github.com/Diniboy1123/usque/blob/main/RESEARCH.md) — detailed reverse-engineering writeup
- [Diniboy1123/connect-ip-go](https://github.com/Diniboy1123/connect-ip-go) — forked connect-ip-go with `cf-connect-ip` support
