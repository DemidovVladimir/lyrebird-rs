# lyrebird-rs

A Rust port of [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird), the Tor Project's pluggable transport (PT) suite. It builds a drop-in `lyrebird` binary that tor or [Arti](https://arti.torproject.org) can launch.

Reference version: `lyrebird-0.8.1` (`0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1`), with goptlib `v1.6.0`, snowflake `v2.11.0` and webtunnel `aab00213ba56eca83c95e58bf713b005eb06983e` (the commit lyrebird pins).

## Status

| Transport | Client | Server | Verified against |
|---|---|---|---|
| obfs4 | ✅ | ✅ | Byte vectors recorded from lyrebird 0.8.1 (DRBG, length tables, Elligator2, ntor, frames, handshakes); Arti 2.6.0 bootstraps through Tor Browser's built-in obfs4 bridges |
| snowflake | ✅ | n/a upstream | Arti 2.6.0 bootstraps through Tor Browser 15.0.23's built-in snowflake bridges |
| webtunnel | ✅ | n/a upstream | Arti 2.6.0 bootstraps through the webtunnel bridges Moat hands to Tor Browser (`tools/arti-e2e/run.sh webtunnel`) |
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
protocols = ["obfs4", "snowflake", "webtunnel"]
path = "/usr/local/bin/lyrebird"
arguments = ["-enableLogging", "-logLevel", "INFO"]
run_on_startup = true
```

## Tests

| Suite | Command | Needs |
|---|---|---|
| Unit + recorded vectors | `cargo test --lib` | — |
| obfs4 through the binary (as client and as server, iat-mode 0/1/2, paranoid-mode recovery, wire shape follows the bridge's length table) | `cargo test --release --test interop` | — |
| webtunnel through the binary (pt-spec env + SOCKS args, in-process HTTP upgrade server, errors reported to tor) | `cargo test --test webtunnel` | — |
| Arti end to end | `tools/arti-e2e/run.sh [obfs4\|snowflake\|webtunnel]` | Docker, network access to Tor bridges |

The vectors in `tests/vectors/` were recorded once from lyrebird 0.8.1's own packages (DRBG, Go `math/rand` streams, length tables, Elligator2, ntor, frames, full handshake transcripts) and are kept as fixed test data.

Tor Browser's bundle has no built-in webtunnel bridges; `tools/arti-e2e/bridges.sh webtunnel` takes the lines Moat's circumvention defaults hand to Tor Browser instead.

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
| webtunnel TLS | uTLS by default (`hellorandomizednoalpn`), Go `crypto/tls` for `utls=none` | rustls (webpki roots, TLS 1.2+, no ALPN); the `utls=` name is still validated, so unknown names fail as upstream, but no fingerprint is imitated; `cert-domain=*` (chain check without a name check) is refused | no uTLS equivalent in Rust yet |
| webtunnel `utls=None` (any case but lowercase `none`) | nil-pointer panic (only lowercase `none` skips uTLS) | treated as `none` | crash fix |
| webtunnel `servername=` of only whitespace | panic (`Intn(0)` on the trimmed, empty list) | the empty name is used, so TLS fails with the no-server-name error and plain `http` proceeds | crash fix |
| webtunnel server names that are not valid DNS names or IP literals | sent verbatim as SNI | dial error | rustls needs a well-formed name |
| webtunnel `url=` parsing | Go `net/url`: host case, trailing dot and `..` segments kept as written; an IPv6 host is dialed unbracketed, which Go rejects | the `url` crate: host lower-cased and IDNA-encoded, `..` resolved, IPv6 host bracketed | one URL parser for every transport |
| webtunnel bytes after the `101` head | dropped with the `bufio.Reader` | kept as tunnel data | nothing lost (tor speaks first, so it rarely matters) |
| webtunnel dial errors | PT `LOG` line and lyrebird.log carry the bridge host and resolved IP | address scrubbed unless `-unsafeLogging`; the status line of an unrecognized reply is logged at DEBUG | log hygiene, and a 502 from the bridge's reverse proxy is otherwise invisible |

## Layout

| Path | Upstream |
|---|---|
| `src/main.rs` | `cmd/lyrebird` |
| `src/pt/` | goptlib |
| `src/socks5.rs`, `src/proxy.rs`, `src/log.rs`, `src/termmon.rs` | `common/socks5`, `cmd/lyrebird/proxy_*`, `common/log`, `cmd/lyrebird/termmon*` |
| `src/common/` | `common/{csrand,drbg,ntor,probdist,replayfilter}`, `internal/x25519ell2`; `field.rs` and `gorand.rs` stand in for filippo.io/edwards25519 and Go `math/rand` |
| `src/transports/obfs4/` | `transports/obfs4` |
| `src/transports/snowflake/` | `transports/snowflake` + snowflake `client/lib`, `common/{amp,encapsulation,event,messages,nat,sqscreds,turbotunnel}`, kcp-go (`kcp.rs`, `kcp_session.rs`), smux (`smux.rs`), a STUN client (`stun.rs`) and str0m glue (`webrtc.rs`) |
| `src/transports/webtunnel/` | `transports/webtunnel` + webtunnel `transport/{httpupgrade,tls}`, `common/certiChainHashCalc` |
| `src/common/httpc.rs` | the parts of Go `net/http` the HTTP-based transports use |

## License

GPL-3.0-or-later (see `LICENSE`), because upstream's `internal/x25519ell2` and `transports/meeklite` are GPLv3. The rest of lyrebird is BSD-2-Clause, goptlib is CC0, snowflake is BSD-3-Clause, and webtunnel, kcp-go and smux are MIT. Their notices are kept in `LICENSE-UPSTREAM` and in per-file headers.
