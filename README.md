# lyrebird-rs

A Rust port of [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird), the Tor Project's pluggable transport (PT) suite. It builds a drop-in `lyrebird` binary that tor or [Arti](https://arti.torproject.org) can launch.

Reference version: `lyrebird-0.8.1` (`0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1`), with goptlib `v1.6.0` and snowflake `v2.11.0`.

## Status

| Transport | Client | Server | Verified against |
|---|---|---|---|
| obfs4 | ✅ | ✅ | Go lyrebird 0.8.1 (byte vectors + live binaries, iat-mode 0/1/2); Arti 2.6.0 bootstraps through Tor Browser's built-in obfs4 bridges |
| snowflake | ✅ | n/a upstream | Go broker/proxy/server v2.11.0 offline (throughput on par with Go, session survives a proxy restart); Arti 2.6.0 bootstraps through Tor Browser 15.0.23's built-in snowflake bridges |
| webtunnel | ⏳ | n/a upstream | — |
| meek_lite, obfs2, obfs3, scramblesuit | ⏳ | — | — |

Transports marked ⏳ are rejected with `CMETHOD-ERROR … no such transport is supported`, the same line lyrebird prints for unknown names.

## Build and run

| What | Command |
|---|---|
| Binary | `cargo build --release` → `target/release/lyrebird` |
| Container | `docker build -t lyrebird-rs .` |
| Flags | Same as upstream: `-enableLogging`, `-logLevel`, `-unsafeLogging`, `-obfs4-distBias`, `-version` |

Arti, managed transport:

```toml
[[bridges.transports]]
protocols = ["obfs4", "snowflake"]
path = "/usr/local/bin/lyrebird"
arguments = ["-enableLogging", "-logLevel", "INFO"]
run_on_startup = true
```

## Tests

| Suite | Command | Needs |
|---|---|---|
| Unit + Go golden vectors | `cargo test --lib` | — |
| Binary interop matrix (Rust/Go client × Rust/Go server × iat 0/1/2, wire shape) | `LYREBIRD_GO=/path/to/lyrebird cargo test --release --test interop` | Go lyrebird 0.8.1 (Go rows are skipped without it) |
| Arti end to end | `tools/arti-e2e/run.sh [obfs4\|snowflake]` (`-e PT_BIN=/usr/local/bin/lyrebird-go` for the Go baseline) | Docker, network access to Tor bridges |
| Offline snowflake network | `tools/snowflake-local/run.sh [lyrebird-rs\|lyrebird-go] [bytes] [sessions]` | Docker |
| Regenerate vectors | `tools/go-vectors/generate.sh` | Docker |

Golden vectors (`tests/vectors/`) come from the Go packages themselves: DRBG, Go `math/rand` streams, length tables, Elligator2, ntor, frames, and full handshake transcripts.

## Deliberate differences from lyrebird 0.8.1

| Area | Upstream | Here | Why |
|---|---|---|---|
| Paranoid mode (`iat-mode=2`) with a length table containing 0 | panics (`BUG: Write(), iat length was 0`); 170 of 5000 seeds are affected | resamples; falls back to MTU-sized writes after 64 zeros | crash fix |
| Client applies the bridge's PRNG seed | on the first `Read`, which blocks on the socket first, so the first burst uses the client's own table | as soon as the seed frame is buffered | follows the protocol's intent; no stalled frames |
| Buffered frames on read | read from the socket, then decode | decode what is buffered, then read | no complete frame waits for more network data |
| SIGINT with no active connections | waits for another event | exits | shutdown usability |
| `STATUS TYPE=version` | `IMPLEMENTATION="lyrebird"` | `IMPLEMENTATION="lyrebird-rs"` | honest reporting to tor/Arti |
| `-obfs4-distBias` tables | Go on arm64 fuses float ops (FMA), so its arm64 and amd64 builds disagree | matches amd64 Go | amd64 is the unfused reference |
| snowflake TLS to broker/CDN | Go `crypto/tls`, or uTLS with `utls-imitate` | rustls (webpki roots, no ALPN); `utls-imitate` is logged and ignored; `utls-nosni` still honoured when `utls-imitate` is set | no uTLS equivalent in Rust yet |
| snowflake WebRTC stack | pion (DTLS/SCTP/ICE fingerprints of pion) | str0m; host candidates are gathered but local ones are stripped from the offer | sans-IO Rust stack; wire fingerprints differ from pion |
| snowflake + outbound proxy (`TOR_PT_PROXY`, `proxy=`) | `TOR_PT_PROXY` is validated, then silently bypassed (the proxy URL is set on a copy of the config); `proxy=` relays WebRTC over SOCKS5 UDP | dial refused with an error | SOCKS5 UDP relaying not ported yet; never leak around a configured proxy |
| snowflake bad rendezvous config | `log.Fatal` (process exits) | dial error | one bad bridge line must not kill other transports |
| snowflake library log lines | written unscrubbed (answer SDPs include proxy IPs) | IP addresses scrubbed unless `-unsafeLogging` | log hygiene |
| SQS rendezvous | aws-sdk-go-v2 with the default HTTP client | built-in SigV4 JSON client (signatures match aws-sdk-go-v2) | no AWS SDK dependency |

## Layout

| Path | Upstream |
|---|---|
| `src/main.rs` | `cmd/lyrebird` |
| `src/pt/` | goptlib |
| `src/socks5.rs`, `src/proxy.rs`, `src/log.rs`, `src/termmon.rs` | `common/socks5`, `cmd/lyrebird/proxy_*`, `common/log`, `cmd/lyrebird/termmon*` |
| `src/common/` | `common/{csrand,drbg,ntor,probdist,replayfilter}`, `internal/x25519ell2`; `field.rs` and `gorand.rs` stand in for filippo.io/edwards25519 and Go `math/rand` |
| `src/transports/obfs4/` | `transports/obfs4` |
| `src/transports/snowflake/` | `transports/snowflake` + snowflake `client/lib`, `common/{amp,encapsulation,event,messages,nat,sqscreds,turbotunnel}`, kcp-go (`kcp.rs`, `kcp_session.rs`), smux (`smux.rs`), a STUN client (`stun.rs`) and str0m glue (`webrtc.rs`) |
| `src/common/httpc.rs` | the parts of Go `net/http` the HTTP-based transports use |

## License

GPL-3.0-or-later (see `LICENSE`), because upstream's `internal/x25519ell2` and `transports/meeklite` are GPLv3. The rest of lyrebird is BSD-2-Clause, goptlib is CC0, snowflake is BSD-3-Clause, and kcp-go and smux are MIT. Their notices are kept in `LICENSE-UPSTREAM` and in per-file headers.
