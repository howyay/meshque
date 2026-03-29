# meshque

A mesh VPN that tunnels IP traffic over MASQUE (CONNECT-IP / RFC 9484) on HTTP/3 port 443.

## Project Structure

- `connect-ip/` — Standalone Rust crate implementing RFC 9484 (CONNECT-IP) over HTTP/3
- `meshque/` — Peer binary (Phase 1b) — TUN + CONNECT-IP tunnel engine
- `signaling/` — Signaling server (Phase 1c) — TypeScript/Hono, platform-agnostic
- `docs/superpowers/specs/` — Design specs
- `docs/superpowers/plans/` — Implementation plans

## Build

### Rust (connect-ip + meshque)

Requires Rust toolchain. On NixOS, `cc` linker must be in PATH — use the `shell.nix` in `connect-ip/` or `nix-shell -p gcc`.

```bash
export PATH="/nix/store/kbw2j1vag664b3sj3rjwz9v53cqx87sb-gcc-wrapper-15.2.0/bin:$PATH"
cargo test --workspace  # runs all Rust tests
cargo build -p meshque  # build peer binary
```

### TypeScript (signaling)

```bash
cd signaling && pnpm install && pnpm test  # 28 tests
pnpm dev  # starts dev server on :8787
```

## Key Docs

- Roadmap: `docs/superpowers/specs/2026-03-27-meshque-roadmap.md`
- Phase 1a Spec (DONE): `docs/superpowers/specs/2026-03-27-connect-ip-crate-design.md`
- Phase 1a Plan (DONE): `docs/superpowers/plans/2026-03-28-connect-ip-crate.md`
- Phase 1b Spec (IN PROGRESS): `docs/superpowers/specs/2026-03-29-peer-binary-design.md`
- Phase 1b Untested: `docs/superpowers/specs/2026-03-29-phase1b-untested.md`
- Phase 1c Spec (DONE): `docs/superpowers/specs/2026-03-29-signaling-server-design.md`
- WARP Analysis: `docs/superpowers/specs/2026-03-29-warp-interop-analysis.md`

## Conventions

- Project folder is `ipowt` but the project name is **meshque** in all docs
- Rust for peer software, TypeScript for signaling server
- MASQUE CONNECT-IP (RFC 9484) as transport, not WebTransport


