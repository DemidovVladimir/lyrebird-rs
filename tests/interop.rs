//! Black-box obfs4 checks over the real pluggable-transport interface
//! (pt-spec env + SOCKS5 args + an echo "ORPort"): the binary as client and
//! as server, one row per iat-mode, plus the wire shape of client writes.

use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use lyrebird::common::drbg::Seed;
use lyrebird::common::probdist::WeightedDist;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

const RUST: &str = env!("CARGO_BIN_EXE_lyrebird");
/// Upstream paranoid mode panics when this seed's length table yields 0.
const ZERO_LENGTH_SEED: &str = "fc4fbde4dda7d90ca00f8ab981a8c0976e5f049a7ca66d7d";
struct Pt {
    _child: Child,
    state: tempfile::TempDir,
}

impl Pt {
    fn log(&self) -> String {
        std::fs::read_to_string(self.state.path().join("lyrebird.log")).unwrap_or_default()
    }
}

async fn launch(envs: &[(&str, String)], kind: &str) -> (Pt, String) {
    let bin = RUST;
    let state = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(bin);
    cmd.args(["-enableLogging", "-logLevel", "DEBUG", "-unsafeLogging"])
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_STATE_LOCATION", state.path())
        .env_remove("TOR_PT_CLIENT_TRANSPORTS")
        .env_remove("TOR_PT_SERVER_TRANSPORTS")
        .env_remove("TOR_PT_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {bin}: {e}"));
    let mut err_lines = BufReader::new(child.stderr.take().unwrap()).lines();
    tokio::spawn(async move {
        while let Ok(Some(l)) = err_lines.next_line().await {
            eprintln!("{l}");
        }
    });
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let want = format!("{kind}METHOD obfs4 ");
    let line = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(l) = lines.next_line().await.unwrap() {
            if l.starts_with(&want) {
                return l;
            }
            assert!(!l.contains("-ERROR"), "{bin}: {l}");
        }
        panic!("{bin} exited before {want}");
    })
    .await
    .expect("PT startup timed out");
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    (
        Pt {
            _child: child,
            state,
        },
        line,
    )
}

async fn spawn_echo() -> SocketAddr {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = ln.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

/// Bridge identity with a chosen drbg-seed (so the length table is fixed).
fn server_opts(iat: u8, seed: &str) -> String {
    format!(
        "obfs4:iat-mode={iat};obfs4:node-id={};obfs4:private-key={};obfs4:drbg-seed={seed}",
        "5a".repeat(20),
        "4b".repeat(32)
    )
}

/// A deterministic seed whose length table cannot yield 0, so the matrix
/// rows exercise the normal padding path (the zero case has its own test).
fn zero_free_seed() -> String {
    (1u8..)
        .map(|i| Seed([i; 24]))
        .find(|s| !WeightedDist::new(s, 0, 1448, false).contains(0))
        .unwrap()
        .hex()
}

struct Server {
    pt: Pt,
    addr: SocketAddr,
    cert: String,
}

async fn start_server(iat: u8, seed: &str) -> Server {
    let echo = spawn_echo().await;
    let (pt, line) = launch(
        &[
            ("TOR_PT_SERVER_TRANSPORTS", "obfs4".into()),
            ("TOR_PT_SERVER_BINDADDR", "obfs4-127.0.0.1:0".into()),
            ("TOR_PT_ORPORT", echo.to_string()),
            ("TOR_PT_SERVER_TRANSPORT_OPTIONS", server_opts(iat, seed)),
        ],
        "S",
    )
    .await;
    // SMETHOD obfs4 127.0.0.1:PORT ARGS:cert=...,iat-mode=N
    let mut parts = line.split_whitespace();
    let addr = parts.nth(2).unwrap().parse().unwrap();
    let args = parts.find_map(|p| p.strip_prefix("ARGS:")).unwrap();
    let cert = args
        .split(',')
        .find_map(|kv| kv.strip_prefix("cert="))
        .unwrap()
        .to_string();
    assert!(args.contains(&format!("iat-mode={iat}")), "{line}");
    Server { pt, addr, cert }
}

async fn start_client() -> (Pt, SocketAddr) {
    let (pt, line) = launch(&[("TOR_PT_CLIENT_TRANSPORTS", "obfs4".into())], "C").await;
    let proxy = line.split_whitespace().nth(3).unwrap().parse().unwrap();
    (pt, proxy)
}

async fn socks_connect(
    proxy: SocketAddr,
    target: SocketAddr,
    args: &str,
) -> Result<TcpStream, String> {
    let SocketAddr::V4(target) = target else {
        panic!("ipv4 only")
    };
    let mut s = TcpStream::connect(proxy).await.map_err(|e| e.to_string())?;
    let io = |e: std::io::Error| e.to_string();
    s.write_all(&[5, 1, 2]).await.map_err(io)?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.map_err(io)?;
    assert_eq!(r, [5, 2]);
    let mut auth = vec![1, args.len() as u8];
    auth.extend_from_slice(args.as_bytes());
    auth.extend_from_slice(&[1, 0]);
    s.write_all(&auth).await.map_err(io)?;
    s.read_exact(&mut r).await.map_err(io)?;
    if r[1] != 0 {
        return Err(format!("socks auth rejected {r:?}"));
    }
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&target.ip().octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut rep = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut rep))
        .await
        .map_err(|_| "socks connect timed out".to_string())?
        .map_err(io)?;
    if rep[1] != 0 {
        return Err(format!("socks connect failed: reply {}", rep[1]));
    }
    Ok(s)
}

fn pattern(len: usize, salt: u32) -> Vec<u8> {
    (0..len as u32)
        .map(|i| (i.wrapping_mul(2654435761).wrapping_add(salt) >> 13) as u8)
        .collect()
}

/// Sends `payload` while reading the echo; stalls are reported with progress.
async fn roundtrip(stream: TcpStream, payload: &[u8]) -> Result<(), String> {
    let (mut r, mut w) = stream.into_split();
    let mut got = vec![0u8; payload.len()];
    let read = async {
        let mut n = 0;
        while n < got.len() {
            match r.read(&mut got[n..]).await {
                Ok(0) => return Err(format!("EOF after {n}/{}", got.len())),
                Ok(k) => n += k,
                Err(e) => return Err(format!("{e} after {n}/{}", got.len())),
            }
        }
        Ok(())
    };
    let write = async { w.write_all(payload).await.map_err(|e| e.to_string()) };
    tokio::time::timeout(Duration::from_secs(60), async {
        let (a, b) = tokio::join!(write, read);
        a.and(b)
    })
    .await
    .map_err(|_| format!("stalled on {} bytes", payload.len()))??;
    if got != payload {
        return Err("echo mismatch".into());
    }
    Ok(())
}

async fn run_row(iat: u8, seed: &str, sessions: usize) -> Result<(), String> {
    let server = start_server(iat, seed).await;
    let (client, proxy) = start_client().await;
    let args = format!("cert={};iat-mode={iat}", server.cert);
    let result: Result<(), String> = async {
        for i in 0..sessions {
            let conn = socks_connect(proxy, server.addr, &args)
                .await
                .map_err(|e| format!("session {i}: {e}"))?;
            let len = 1 + (i * 7919) % 4096;
            roundtrip(conn, &pattern(len, i as u32))
                .await
                .map_err(|e| format!("session {i}: {e}"))?;
        }
        let bulk = if iat == 0 { 1 << 20 } else { 256 << 10 };
        for rep in 0..3 {
            let conn = socks_connect(proxy, server.addr, &args)
                .await
                .map_err(|e| format!("bulk {rep}: {e}"))?;
            roundtrip(conn, &pattern(bulk, rep))
                .await
                .map_err(|e| format!("bulk {rep}: {e}"))?;
        }
        Ok(())
    }
    .await;
    result.map_err(|e| {
        format!(
            "{e}\n--- client log ---\n{}\n--- server log ---\n{}",
            tail(&client.log()),
            tail(&server.pt.log())
        )
    })
}

fn tail(log: &str) -> String {
    let lines: Vec<&str> = log
        .lines()
        .filter(|l| !l.ends_with("new connection"))
        .collect();
    lines[lines.len().saturating_sub(8)..].join("\n")
}

async fn matrix() {
    let seed = zero_free_seed();
    let mut failures = Vec::new();
    for iat in 0..=2u8 {
        if let Err(e) = run_row(iat, &seed, 50).await {
            failures.push(format!("iat-mode={iat}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_and_server_matrix() {
    matrix().await;
}

/// lyrebird 0.8.1 panics in paranoid mode when the length table yields 0;
/// the port resamples instead.
#[tokio::test(flavor = "multi_thread")]
async fn paranoid_mode_survives_zero_length_table() {
    let bad = Seed::from_hex(ZERO_LENGTH_SEED).unwrap();
    assert!(WeightedDist::new(&bad, 0, 1448, false).contains(0));
    run_row(2, ZERO_LENGTH_SEED, 30).await.unwrap();
}

/// Wire length of one 514-byte cell write after obfs4 burst padding to `target`.
fn padded_cell_len(target: usize) -> usize {
    const FRAME: usize = 514 + 3 + 18;
    const SEGMENT: usize = 1448;
    const HEADER: usize = 21;
    let pad = if target >= FRAME {
        target - FRAME
    } else {
        SEGMENT - FRAME + target
    };
    match pad {
        0 => FRAME,
        p if p > HEADER => FRAME + p,
        p => FRAME + SEGMENT + HEADER + p,
    }
}

/// Client->server segment sizes for 40 cell-sized writes through a tap.
/// Uses its own server: the session only ends once the server side closes.
async fn cell_write_sizes(seed: &str) -> Vec<usize> {
    let server = start_server(0, seed).await;
    let (_client, proxy) = start_client().await;
    let tap = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tap_addr = tap.local_addr().unwrap();
    let upstream = server.addr;
    let recorder = tokio::spawn(async move {
        let (down, _) = tap.accept().await.unwrap();
        let up = TcpStream::connect(upstream).await.unwrap();
        let (mut dr, mut dw) = down.into_split();
        let (mut ur, mut uw) = up.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut ur, &mut dw).await;
        });
        let mut sizes = Vec::new();
        let mut buf = vec![0u8; 65536];
        while let Ok(n) = dr.read(&mut buf).await {
            if n == 0 || uw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            sizes.push(n);
        }
        sizes
    });

    let args = format!("cert={};iat-mode=0", server.cert);
    let conn = socks_connect(proxy, tap_addr, &args).await.unwrap();
    let (mut r, mut w) = conn.into_split();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 514 * 40];
        r.read_exact(&mut buf).await.unwrap();
        r
    });
    for i in 0..40 {
        w.write_all(&pattern(514, i)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let r = reader.await.unwrap();
    drop((r, w, server));
    let sizes = recorder.await.unwrap();
    // The first read is the handshake.
    sizes[1..].to_vec()
}

/// obfs4 pads every burst to a length drawn from the bridge's table (sent
/// in the PRNG seed packet). The client must only produce the sizes that
/// table predicts, and must not send constant-size records.
#[tokio::test(flavor = "multi_thread")]
async fn wire_shape_follows_bridge_length_table() {
    let (seed, table) = (1u8..)
        .map(|i| Seed([i.wrapping_mul(29); 24]))
        .map(|s| (s, WeightedDist::new(&s, 0, 1448, false)))
        .find(|(_, t)| !t.contains(0) && (8..=40).contains(&t.support().len()))
        .unwrap();
    let expected: std::collections::BTreeSet<usize> =
        table.support().into_iter().map(padded_cell_len).collect();
    // The bridge's seed is applied as soon as it arrives, so every segment
    // must come from the bridge's table.
    let sizes = cell_write_sizes(&seed.hex()).await;
    let seen: std::collections::BTreeSet<usize> = sizes.iter().copied().collect();
    eprintln!(
        "{} distinct of {} possible: {seen:?}",
        seen.len(),
        expected.len()
    );
    assert_eq!(sizes.len(), 40, "one segment per write expected: {sizes:?}");
    assert!(
        seen.is_subset(&expected),
        "sizes {seen:?} not in {expected:?}"
    );
    assert!(seen.len() >= 3, "too uniform: {sizes:?}");
}
