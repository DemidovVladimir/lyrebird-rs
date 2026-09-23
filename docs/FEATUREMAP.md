# Feature map

For each feature: where it lives, where its tests live, and where to go to add or change something. Paths are relative to `src/` unless they start with `tests/`, `tools/` or `docs/`. For the file-by-file map, see [`CODEMAP.md`](CODEMAP.md).

## Process and pt-spec (tor ↔ lyrebird)

| Feature | Code | Tests | Notes |
|---|---|---|---|
| Command-line flags (`-enableLogging`, `-logLevel`, `-unsafeLogging`, `-obfs4-distBias`, `-version`) | `shared/adapters/cli.rs` (parse, `USAGE`), `main.rs` (use) | `cli.rs` unit tests | Go `flag` syntax. A new flag goes into `Flags` and `USAGE`, then into `main.rs` → `Settings` or a transport constructor. |
| Managed-mode env (`TOR_PT_MANAGED_TRANSPORT_VER`, `TOR_PT_CLIENT_TRANSPORTS`, `TOR_PT_SERVER_*`, `TOR_PT_ORPORT`, `TOR_PT_EXTENDED_SERVER_PORT`, `TOR_PT_AUTH_COOKIE_FILE`, `TOR_PT_STATE_LOCATION`, `TOR_PT_EXIT_ON_STDIN_CLOSE`) | `shared/domain/pt/managed.rs` via the `Env` port | `managed.rs` unit tests | Errors go to tor (`ENV-ERROR` etc.) as they are found. |
| Control lines to tor (`VERSION`, `CMETHOD`, `SMETHOD`, `PROXY DONE`, `STATUS TYPE=version`, `LOG`, `*-ERROR`) | `shared/domain/pt/control.rs` (`TorControl`), written by `shared/adapters/stdout.rs` | `control.rs` unit tests; capture lines with `TorControl::capture()` | Every new line type is a `TorControl` method. |
| Transport args (bridge line → SOCKS user/pass → `Args`; server options) | `shared/domain/pt/args.rs`, `shared/adapters/socks5.rs::parse_client_parameters` | `args.rs`, `socks5.rs` unit tests | |
| Outbound proxy `TOR_PT_PROXY` (http, socks4a, socks5) | rules: `shared/domain/proxy.rs`; dialers: `shared/adapters/proxy.rs`; choice: `app/client.rs::setup` → `Network::dialer` | `proxy.rs` (both) unit tests | snowflake refuses a proxy; see its section. |
| SOCKS5 server for tor | `shared/adapters/socks5.rs`, port `shared/ports/socks.rs` (reply codes) | unit tests in both | CONNECT only. |
| Client mode | `app/client.rs` | `tests/interop.rs`, `tests/webtunnel.rs` | Error → SOCKS reply code mapping lives in `handle`. |
| Server mode, Extended ORPort | `app/server.rs`, `shared/adapters/extorport.rs` | `extorport.rs` unit tests, `tests/interop.rs` | Only obfs4 has a server. |
| Relaying | `app/relay.rs` | `relay.rs` unit test | 32 KiB buffer, no half-close propagation. |
| Shutdown (SIGINT waits for connections, SIGTERM / stdin close / parent death exit) | `shared/adapters/signals.rs` → `shared/ports/signals.rs` → `app/termmon.rs` | `termmon.rs` unit tests | |
| Logging, levels, address scrubbing | policy: `shared/ports/log.rs`; scrubber: `shared/domain/scrub.rs`; file: `shared/adapters/fs.rs` | unit tests in each | Always log through `log::*`. Wrap addresses with `log::elide_addr`, errors with `log::elide_error`, library text with `log::scrubbed`/`log::print`. |
| Version reporting | `lib.rs::VERSION`, `app/client.rs` / `app/server.rs` (`report_version("lyrebird-rs", …)`), `main.rs` (`-version`) | — | |

## obfs4 (`transports/obfs4/`, client + server)

| Feature | Code | Tests |
|---|---|---|
| Bridge-line args (`cert=` or `node-id=` + `public-key=`, `iat-mode=`) | `domain/client.rs::parse_args`, arg names in `domain/transport.rs` | `domain/transport.rs` tests |
| Server args (`node-id`, `private-key`, `drbg-seed`, `iat-mode` from `TOR_PT_SERVER_TRANSPORT_OPTIONS`) and first-run identity | `domain/state.rs::server_state_from_args` | `state.rs` tests (`MemoryStore`) |
| Identity files `obfs4_state.json`, `obfs4_bridgeline.txt` | `adapters/fs_state_store.rs` behind `ports/state_store.rs` | `fs_state_store.rs` tests |
| ntor + Elligator2 handshake | `domain/handshake.rs`, `shared/domain/crypto/{ntor,x25519ell2,field}.rs` | vectors `ntor.json`, `x25519ell2.json`, `obfs4_handshake.json` |
| Replay protection, probe-resistant close delay | `domain/server.rs`, `shared/domain/crypto/replayfilter.rs`, close delay in `domain/transport.rs` | `replayfilter.rs`, `server.rs` paths via `transport.rs` tests |
| Frames and packets | `domain/framing.rs`, `domain/packet.rs` | vector `framing.json` |
| Length obfuscation, PRNG seed frame, IAT (iat-mode 1) and paranoid mode (iat-mode 2) | `domain/conn.rs`, tables in `shared/domain/crypto/{probdist,drbg,gorand}.rs` | vectors `probdist.json`, `drbg.json`; `tests/interop.rs` |
| `-obfs4-distBias` (biased tables) | `main.rs` → `obfs4::Transport::new(_, biased)` → `probdist.rs` | `probdist.json` |

## snowflake (`transports/snowflake/`, client only)

| Feature | Code | Tests |
|---|---|---|
| Bridge-line args (`url`, `front`/`fronts`, `ampcache`, `sqsqueue`, `sqscreds`, `ice`, `max`, `fingerprint`, `utls-nosni`, `utls-imitate`, `proxy`) | `domain/config.rs::parse_client_args` | `config.rs` tests |
| Rendezvous choice (`sqsqueue` alone, else `ampcache` + `url`, else `url`) and poll encoding | `domain/broker.rs` (`BrokerChannel`, poll JSON) | `broker.rs` tests |
| HTTP rendezvous with domain fronting | `adapters/rendezvous.rs::HttpRendezvous` over `shared/adapters/httpc.rs` | `rendezvous.rs` tests |
| AMP cache rendezvous | `adapters/rendezvous.rs::AmpCacheRendezvous`, `adapters/amp.rs` | `amp.rs` tests |
| SQS rendezvous (SigV4) | `adapters/sqs.rs` | `sqs.rs` tests |
| WebRTC peers (str0m) and ICE/STUN servers | `adapters/webrtc.rs` behind `ports/webrtc.rs`; `ice=` parsing in `domain/config.rs` | `webrtc.rs` tests |
| NAT type detection and policy | `adapters/stun.rs::StunNatProbe` behind `ports/nat_probe.rs`; `domain/nat.rs` | `stun.rs`, `nat.rs` tests |
| Peer pool (`max`), peer lifecycle and timeouts | `domain/client.rs`, `domain/peer.rs`, timeouts in `domain/transport.rs` | — (end to end via `tools/arti-e2e/run.sh snowflake`) |
| Turbo Tunnel: encapsulation → KCP → smux | `domain/{encapsulation,turbotunnel,kcp,kcp_session,smux}.rs` | unit tests in each |
| Status events as tor `LOG` lines | `domain/events.rs` | `events.rs` tests |
| Outbound proxy refusal | `domain/transport.rs` (uses `Dialer::is_direct`), `domain/config.rs` (`proxy=`) | `config.rs` tests |

## webtunnel (`transports/webtunnel/`, client only)

| Feature | Code | Tests |
|---|---|---|
| Bridge-line args (`url`, `addr`, `servername`, `sni-imitation`, `utls`, `cert`, `cert-domain`) | `domain/config.rs::parse_client_args` | `config.rs` tests |
| SNI rotation over a `servername=` list | `domain/servername.rs` | `servername.rs` tests |
| TLS policy (which name to verify, pinning, refusals) | `domain/config.rs::tls_checks`; enforced by `adapters/rustls.rs` behind `ports/tls.rs` | `config.rs`, `rustls.rs` tests |
| HTTP upgrade (`GET` + `Upgrade: websocket` → `101`) | `domain/upgrade.rs`, message format in `shared/domain/http.rs` | `upgrade.rs`, `http.rs` tests |
| Dial, errors reported to tor (`LOG`, scrubbed) | `domain/transport.rs` | `transport.rs` tests, `tests/webtunnel.rs` |

## Not ported yet

`meek_lite`, `obfs2`, `obfs3`, `scramblesuit`: tor gets `CMETHOD-ERROR … no such transport is supported` from `app/client.rs` because nothing is registered under those names. SOCKS5 UDP relaying for snowflake `proxy=` is also missing.

## Recipes

### Add a transport

1. Create `src/transports/<name>/{mod.rs, domain/mod.rs, ports/mod.rs, adapters/mod.rs}` (all three layers, even if one is empty); add `pub mod <name>;` to `src/transports/mod.rs`.
2. In `domain/transport.rs`, implement `shared::ports::transport::Transport` and a `ClientFactory` (and a `ServerFactory` if there is a server side). Re-export `Transport` from `<name>/mod.rs`.
3. Put anything that touches the network, TLS or files behind a trait in `<name>/ports/`, implemented in `<name>/adapters/`. Use `shared` ports (`Dialer`, `ByteStream`, `TorControl`, `log`) where they fit.
4. Register it in `main.rs` inside the `Registry::new(vec![...])` list, wiring its adapters.
5. Add tests (unit tests in the files; a binary-level test in `tests/` like `tests/webtunnel.rs`), update the status table and the upstream mapping in `README.md`, and add a section here and in `CODEMAP.md`.
6. `tests/architecture.rs` picks up the new directory by itself.

### Add a bridge-line argument

Parse it in the transport's `domain/config.rs` (obfs4: `domain/client.rs`, names in `domain/transport.rs`), carry it in the client config, use it in `domain/transport.rs`. If it needs new I/O, extend the transport's port and adapter. Add a parse test next to the existing ones.

### Add a flag

`shared/adapters/cli.rs` (`Flags`, parser, `USAGE`) → `main.rs` → `app::Settings` or a transport constructor. Update the flag row in `README.md`.

### Add a port / swap an adapter

Trait in `ports/` (shared or per transport), no I/O there. Implementation in `adapters/`. Wire it in `main.rs` (shared: `app::Ports`; snowflake: `snowflake::Ports`; obfs4/webtunnel: constructor arg). For tests, implement the trait in the test module with in-memory pipes (see `PipeDialer` in `obfs4/domain/transport.rs`, `MemoryStore` in `obfs4/domain/state.rs`).

### Deviate from upstream on purpose

Implement it, add a test, and add a row to "Deliberate differences from lyrebird 0.8.1" in `README.md` (area, upstream, here, why).
