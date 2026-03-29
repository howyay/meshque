# meshque

A mesh VPN that tunnels IP traffic over MASQUE (CONNECT-IP / RFC 9484) on HTTP/3 port 443.

## Project Structure

- `connect-ip/` — Standalone Rust crate implementing RFC 9484 (CONNECT-IP) over HTTP/3
- `docs/superpowers/specs/` — Design specs
- `docs/superpowers/plans/` — Implementation plans

## Build

Requires Rust toolchain. On NixOS, `cc` linker must be in PATH — use the `shell.nix` in `connect-ip/` or `nix-shell -p gcc`.

```bash
export PATH="/nix/store/kbw2j1vag664b3sj3rjwz9v53cqx87sb-gcc-wrapper-15.2.0/bin:$PATH"
cd connect-ip && cargo check
```

## Key Docs

- Roadmap: `docs/superpowers/specs/2026-03-27-meshque-roadmap.md`
- Phase 1a Spec: `docs/superpowers/specs/2026-03-27-connect-ip-crate-design.md`
- Implementation Plan: `docs/superpowers/plans/2026-03-28-connect-ip-crate.md`

## Conventions

- Project folder is `ipowt` but the project name is **meshque** in all docs
- Rust for peer software, TypeScript for signaling server
- MASQUE CONNECT-IP (RFC 9484) as transport, not WebTransport


