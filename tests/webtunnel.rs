//! Black-box webtunnel checks over the real pluggable-transport interface
//! (pt-spec env + SOCKS5 args) against an in-process HTTP upgrade server
//! that echoes the tunnel. TLS (pins, name checks) is covered by the
//! module's own tests.

use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};

const RUST: &str = env!("CARGO_BIN_EXE_lyrebird");
const UPGRADE_OK: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";

struct Pt {
    _child: Child,
    _state: tempfile::TempDir,
    stdout: Arc<Mutex<Vec<String>>>,
    proxy: SocketAddr,
}

impl Pt {
    fn stdout_lines(&self) -> Vec<String> {
        self.stdout.lock().unwrap().clone()
    }

    async fn wait_for_line(&self, needle: &str) -> String {
        for _ in 0..100 {
            if let Some(l) = self.stdout_lines().into_iter().find(|l| l.contains(needle)) {
                return l;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "no stdout line containing {needle:?}: {:?}",
            self.stdout_lines()
        );
    }
}

/// Launches the binary as a webtunnel client and returns its SOCKS address.
async fn launch(extra_flags: &[&str]) -> Pt {
    let state = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(RUST);
    cmd.args(["-enableLogging", "-logLevel", "DEBUG"])
        .args(extra_flags)
        .env("TOR_PT_MANAGED_TRANSPORT_VER", "1")
        .env("TOR_PT_STATE_LOCATION", state.path())
        .env("TOR_PT_CLIENT_TRANSPORTS", "webtunnel")
        .env_remove("TOR_PT_SERVER_TRANSPORTS")
        .env_remove("TOR_PT_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    let mut child = cmd.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let proxy = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(l) = lines.next_line().await.unwrap() {
            stdout.lock().unwrap().push(l.clone());
            if let Some(rest) = l.strip_prefix("CMETHOD webtunnel socks5 ") {
                return rest.parse::<SocketAddr>().unwrap();
            }
            assert!(!l.contains("-ERROR"), "{l}");
        }
        panic!("exited before CMETHOD");
    })
    .await
    .expect("PT startup timed out");
    let sink = stdout.clone();
    tokio::spawn(async move {
        while let Ok(Some(l)) = lines.next_line().await {
            sink.lock().unwrap().push(l);
        }
    });
    Pt {
        _child: child,
        _state: state,
        stdout,
        proxy,
    }
}

/// Reads one HTTP request head from `s`.
async fn read_request(s: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut tmp).await.unwrap();
        assert!(n > 0, "client closed before sending a request");
        buf.extend_from_slice(&tmp[..n]);
    }
    String::from_utf8(buf).unwrap()
}

/// A plain upgrade server: records request heads, replies `reply`, echoes.
async fn upgrade_server(reply: &'static [u8]) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = ln.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let head = read_request(&mut s).await;
                seen.lock().unwrap().push(head);
                s.write_all(reply).await.unwrap();
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, requests)
}

/// SOCKS5 CONNECT through the PT with pt-spec args; returns the reply code.
async fn socks_connect(proxy: SocketAddr, args: &str) -> Result<TcpStream, u8> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 2]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 2]);
    let bytes = args.as_bytes();
    let (user, pass) = if bytes.len() > 255 {
        bytes.split_at(255)
    } else {
        (bytes, &[0u8][..])
    };
    let mut auth = vec![1, user.len() as u8];
    auth.extend_from_slice(user);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    s.write_all(&auth).await.unwrap();
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0, "SOCKS auth (args) rejected");
    // The target is ignored by webtunnel: use an unroutable one.
    let req = [5, 1, 0, 1, 192, 0, 2, 3, 0, 1];
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(30), s.read_exact(&mut rep))
        .await
        .expect("socks reply timed out")
        .unwrap();
    if rep[1] != 0 {
        return Err(rep[1]);
    }
    Ok(s)
}

async fn echo_check(mut s: TcpStream, len: usize) {
    let payload: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
    let (mut r, mut w) = s.split();
    let write = async { w.write_all(&payload).await.unwrap() };
    let read = async {
        let mut got = vec![0u8; len];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) =
        tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(write, read) })
            .await
            .expect("echo stalled");
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_upgrade_through_the_binary() {
    let (server, requests) = upgrade_server(UPGRADE_OK).await;
    let pt = launch(&["-unsafeLogging"]).await;
    let args = format!("url=http://bridge.test/secret;addr={server}");
    for i in 0..3 {
        let s = socks_connect(pt.proxy, &args).await.unwrap();
        echo_check(s, 1 + i * 50_000).await;
    }
    let heads = requests.lock().unwrap().clone();
    assert_eq!(heads.len(), 3);
    for head in &heads {
        assert_eq!(
            head,
            "GET /secret HTTP/1.1\r\nHost: bridge.test\r\nUser-Agent: Go-http-client/1.1\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        );
    }
    let sni = pt.wait_for_line("Using TLS SNI").await;
    assert_eq!(
        sni,
        "LOG SEVERITY=notice MESSAGE=\"Using TLS SNI: bridge.test\""
    );
    // The URL's own host:port is dialed when there is no addr=.
    let args = format!("url=http://{server}/via-url");
    let s = socks_connect(pt.proxy, &args).await.unwrap();
    echo_check(s, 1000).await;
    let head = requests.lock().unwrap().last().unwrap().clone();
    assert!(
        head.starts_with(&format!(
            "GET /via-url HTTP/1.1\r\nHost: {}\r\n",
            server.ip()
        )),
        "{head}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_are_reported_to_tor() {
    let (bad, _) = upgrade_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let pt = launch(&[]).await;
    // A non-101 reply: SOCKS general failure and a PT LOG line for tor.
    let args = format!("url=http://bridge.test/secret;addr={bad}");
    assert_eq!(socks_connect(pt.proxy, &args).await.err(), Some(1));
    let line = pt.wait_for_line("Error dialing").await;
    assert_eq!(
        line,
        "LOG SEVERITY=error MESSAGE=\"Error dialing: unrecognized reply\""
    );
    // Bad args: refused at the SOCKS layer, logged for tor.
    assert_eq!(
        socks_connect(pt.proxy, "url=ftp://bridge.test/")
            .await
            .err(),
        Some(1)
    );
    let line = pt.wait_for_line("Error parsing args").await;
    assert_eq!(
        line,
        "LOG SEVERITY=error MESSAGE=\"Error parsing args: url parse error: unknown scheme\""
    );
    // Connection refused: the address is scrubbed without -unsafeLogging.
    let args = "url=http://bridge.test/secret;addr=127.0.0.1:1";
    assert_eq!(socks_connect(pt.proxy, args).await.err(), Some(1));
    let line = pt.wait_for_line("error dialing").await;
    assert_eq!(
        line,
        "LOG SEVERITY=error MESSAGE=\"Error dialing: error dialing [scrubbed]:1: connection refused\""
    );
    let sni = pt.wait_for_line("Using TLS SNI").await;
    assert_eq!(
        sni,
        "LOG SEVERITY=notice MESSAGE=\"Using TLS SNI: bridge.test\""
    );
}
