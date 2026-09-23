# AGENTS.md

Guide for coding agents working on lyrebird-rs, a Rust port of lyrebird (Tor's pluggable transport suite: obfs4, snowflake, webtunnel). Humans start at [`README.md`](README.md).

## Navigate with the maps

Read these before searching the tree:

- [`docs/FEATUREMAP.md`](docs/FEATUREMAP.md): feature → code → tests, plus recipes (add a transport, a bridge-line arg, a flag, a port/adapter, a deliberate difference).
- [`docs/CODEMAP.md`](docs/CODEMAP.md): the layers, the client/server/shutdown flows, and every file with what it owns and which upstream Go code it ports.
- [`README.md`](README.md): status, build, tests, and the table of deliberate differences from upstream.

If you add, move, rename or remove a file or a feature, update both maps in the same change.

## Architecture rules (hexagonal)

```
main.rs (composition root) ─► app (use cases) ─► ports ◄─ adapters
                                   │                ▲
                                   └─► domain ──────┘
shared/{domain,ports,adapters}     transports/<name>/{domain,ports,adapters}
```

1. `domain` and `ports` do no I/O: no `adapters::`, sockets, `std::fs`, `std::env`, `std::process`, stdio, `println!`, `tokio::signal`, rustls, str0m.
2. `app` uses ports only: no adapters, no direct I/O.
3. `shared` knows neither `app` nor any transport.
4. A transport never imports another transport or `app`.
5. Only `main.rs` picks adapters. Tests (in `#[cfg(test)]` modules at the end of a file, or in `tests/`) may use real adapters.

`tests/architecture.rs` enforces 1–4 on the source text. Keep `#[cfg(test)] mod tests` as the last item of a file; the check reads each file only up to that line.

## Commands

| Task | Command |
|---|---|
| Build | `cargo build --release` (binary: `target/release/lyrebird`) |
| Format / lint | `cargo fmt`, `cargo clippy --all-targets` (keep both clean) |
| Unit + recorded vectors | `cargo test --lib` |
| Layer rules | `cargo test --test architecture` |
| obfs4 through the binary | `cargo test --release --test interop` (slow in debug) |
| webtunnel through the binary | `cargo test --test webtunnel` |
| Everything local | `cargo test` |
| Arti end to end | `tools/arti-e2e/run.sh [obfs4\|snowflake\|webtunnel]` (Docker + network, minutes; run in the background) |

Before you finish: `cargo fmt --check && cargo clippy --all-targets && cargo test`.

## Conventions

- **Faithful port.** Behaviour, wire bytes, log and control lines follow lyrebird 0.8.1 and the pinned snowflake/webtunnel/goptlib versions (see README). A file ports one upstream file or package and says which in its header comment (`// Port of …`). Any intended divergence gets a test and a row in README's "Deliberate differences" table.
- **Bit-exactness.** obfs4 tables, DRBG streams, Go `math/rand` and Elligator2 must match Go byte for byte. `tests/vectors/*.json` were recorded once from the Go reference and are fixed data: do not regenerate or hand-edit them. There is no Go toolchain in this repo.
- **Log hygiene.** Use `shared::ports::log` only. Addresses go through `log::elide_addr`, errors through `log::elide_error`, library-style text through `log::print`/`log::scrubbed`. Never log a peer or bridge address unscrubbed. Messages to tor go through `TorControl` (`shared/domain/pt/control.rs`), never `println!`.
- **Errors.** A bad bridge line or a failed dial is an error for that connection, never a process exit or panic.
- **File headers.** Keep the copyright + `SPDX-License-Identifier` lines. Ported files keep upstream's license (BSD-2-Clause, BSD-3-Clause, MIT, CC0, GPL-3.0-or-later for `x25519ell2`); new files use the license of their neighbours. Upstream notices live in `LICENSE-UPSTREAM`.
- **Style.** Module docs (`//!`) say what the module owns in a sentence or two; comments explain *why* or name the upstream behaviour being matched. Match the surrounding code; no new dependencies without need.
- **Tests.** Unit tests sit next to the code. Test doubles implement the port traits in memory (`PipeDialer` in `transports/obfs4/domain/transport.rs`, `MemoryStore` in `transports/obfs4/domain/state.rs`, `TorControl::capture()`).
