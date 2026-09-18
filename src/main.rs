// Copyright (c) 2014-2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of lyrebird cmd/lyrebird.

//! `lyrebird`: a Tor managed pluggable transport (client or server, chosen
//! from the environment tor/Arti sets).

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use lyrebird::transports::{self, ClientFactory, Conn, DialError, ServerFactory};
use lyrebird::{log, proxy, pt, socks5, termmon, VERSION};

const LOG_FILE: &str = "lyrebird.log";
const SOCKS_ADDR: &str = "127.0.0.1:0";

struct Flags {
    show_version: bool,
    log_level: String,
    enable_logging: bool,
    unsafe_logging: bool,
    dist_bias: bool,
}

const USAGE: &str = "Usage of lyrebird:
  -enableLogging
    \tLog to TOR_PT_STATE_LOCATION/lyrebird.log
  -logLevel string
    \tLog level (ERROR/WARN/INFO/DEBUG) (default \"ERROR\")
  -obfs4-distBias
    \tEnable obfs4 using ScrambleSuit style table generation
  -unsafeLogging
    \tDisable the address scrubber
  -version
    \tPrint version and exit";

fn parse_bool(name: &str, v: &str) -> Result<bool, String> {
    match v {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Ok(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Ok(false),
        _ => Err(format!(
            "invalid boolean value {v:?} for -{name}: parse error"
        )),
    }
}

/// Go `flag` package syntax: `-name`, `--name`, `-name=value`, `-name value`.
fn parse_flags(args: &[String]) -> Result<Flags, String> {
    let mut f = Flags {
        show_version: false,
        log_level: "ERROR".into(),
        enable_logging: false,
        unsafe_logging: false,
        dist_bias: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--" || !arg.starts_with('-') || arg == "-" {
            break;
        }
        let body = arg.trim_start_matches('-');
        if arg.len() - body.len() > 2 || body.is_empty() || body.starts_with('=') {
            return Err(format!("bad flag syntax: {arg}"));
        }
        let (name, value) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (body, None),
        };
        match name {
            "version" | "enableLogging" | "unsafeLogging" | "obfs4-distBias" => {
                let v = match &value {
                    Some(v) => parse_bool(name, v)?,
                    None => true,
                };
                match name {
                    "version" => f.show_version = v,
                    "enableLogging" => f.enable_logging = v,
                    "unsafeLogging" => f.unsafe_logging = v,
                    _ => f.dist_bias = v,
                }
            }
            "logLevel" => {
                f.log_level = match value {
                    Some(v) => v,
                    None => {
                        i += 1;
                        args.get(i)
                            .cloned()
                            .ok_or_else(|| format!("flag needs an argument: -{name}"))?
                    }
                };
            }
            "h" | "help" => return Err(String::new()),
            _ => return Err(format!("flag provided but not defined: -{name}")),
        }
        i += 1;
    }
    Ok(f)
}

/// Go's `log.Fatal`: timestamped line on stderr, exit status 1.
fn fatal(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("{} {msg}", chrono::Local::now().format("%Y/%m/%d %H:%M:%S"));
    ExitCode::from(1)
}

fn exec_name() -> String {
    std::env::args()
        .next()
        .and_then(|a| {
            std::path::Path::new(&a)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "lyrebird".into())
}

/// lyrebird's `ptIsClient`.
fn is_client() -> Result<bool, String> {
    let client = std::env::var("TOR_PT_CLIENT_TRANSPORTS").unwrap_or_default();
    let server = std::env::var("TOR_PT_SERVER_TRANSPORTS").unwrap_or_default();
    match (client.is_empty(), server.is_empty()) {
        (false, false) => {
            pt::env_error("TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set");
            Err("TOR_PT_[CLIENT,SERVER]_TRANSPORTS both set".into())
        }
        (false, true) => Ok(true),
        (true, false) => Ok(false),
        (true, true) => Err("not launched as a managed transport".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flags = match parse_flags(&args) {
        Ok(f) => f,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("{e}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(if e.is_empty() { 0 } else { 2 });
        }
    };
    if flags.show_version {
        println!("lyrebird-rs {VERSION}");
        return ExitCode::SUCCESS;
    }
    let exec = exec_name();
    if let Err(e) = log::set_log_level(&flags.log_level) {
        return fatal(format!("[ERROR]: {exec} - failed to set log level: {e}"));
    }
    lyrebird::transports::obfs4::BIASED_DIST
        .store(flags.dist_bias, std::sync::atomic::Ordering::Relaxed);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return fatal(format!("[ERROR]: {exec} - failed to start runtime: {e}")),
    };
    let code = runtime.block_on(run(flags, exec));
    // Don't wait on connection tasks or blocking reads at exit.
    runtime.shutdown_background();
    code
}

async fn run(flags: Flags, exec: String) -> ExitCode {
    let term = termmon::TermMonitor::start();

    let Ok(client) = is_client() else {
        return fatal(format!(
            "[ERROR]: {exec} - must be run as a managed transport"
        ));
    };
    let state_dir = match pt::make_state_dir() {
        Ok(d) => d,
        Err(e) => return fatal(format!("[ERROR]: {exec} - No state directory: {e}")),
    };
    if log::init(
        flags.enable_logging,
        &state_dir.join(LOG_FILE),
        flags.unsafe_logging,
    )
    .is_err()
    {
        return fatal(format!("[ERROR]: {exec} - failed to initialize logging"));
    }
    log::notice(&format!("{VERSION} - launched"));

    let setup = if client {
        log::info(&format!("{exec} - initializing client transport listeners"));
        client_setup(&state_dir, &term).await
    } else {
        log::info(&format!("{exec} - initializing server transport listeners"));
        server_setup(&state_dir, &term).await
    };
    let listeners = match setup {
        Ok(l) => l,
        Err(code) => return code,
    };
    if listeners.is_empty() {
        // Go's os.Exit(-1).
        return ExitCode::from(255);
    }

    log::info(&format!("{exec} - accepting connections"));
    if term.wait(false).await != termmon::Signal::Term {
        for l in &listeners {
            l.abort();
        }
        term.wait(true).await;
    }
    log::notice(&format!("{exec} - terminated"));
    ExitCode::SUCCESS
}

async fn client_setup(
    state_dir: &std::path::Path,
    term: &termmon::TermMonitor,
) -> Result<Vec<JoinHandle<()>>, ExitCode> {
    let info = pt::client_setup().map_err(fatal)?;
    pt::report_version("lyrebird-rs", VERSION);
    let dialer = match proxy::from_env() {
        Ok(None) => proxy::Dialer::Direct,
        Ok(Some((_, d))) => {
            pt::proxy_done();
            d
        }
        Err(e) => return Err(fatal(e)),
    };
    let dialer = Arc::new(dialer);

    let mut listeners = Vec::new();
    for name in &info.method_names {
        let Some(t) = transports::get(name) else {
            pt::cmethod_error(name, "no such transport is supported");
            continue;
        };
        let Ok(f) = t.client_factory(state_dir) else {
            pt::cmethod_error(name, "failed to get ClientFactory");
            continue;
        };
        f.on_event(Arc::new(|msg| pt::log(pt::LogSeverity::Notice, &msg)));
        let ln = match TcpListener::bind(SOCKS_ADDR).await {
            Ok(l) => l,
            Err(e) => {
                pt::cmethod_error(name, &e.to_string());
                continue;
            }
        };
        let addr = ln.local_addr().expect("bound listener has an address");
        let task = tokio::spawn(client_accept_loop(f, ln, dialer.clone(), term.clone()));
        pt::cmethod(name, socks5::VERSION_STRING, &addr);
        log::info(&format!("{name} - registered listener: {addr}"));
        listeners.push(task);
    }
    pt::cmethods_done();
    Ok(listeners)
}

async fn client_accept_loop(
    f: Arc<dyn ClientFactory>,
    ln: TcpListener,
    dialer: Arc<proxy::Dialer>,
    term: termmon::TermMonitor,
) {
    loop {
        match ln.accept().await {
            Ok((conn, _)) => {
                let (f, dialer, term) = (f.clone(), dialer.clone(), term.clone());
                tokio::spawn(async move {
                    let _guard = term.handler();
                    client_handler(f, conn, &dialer).await;
                });
            }
            Err(e) if is_temporary(&e) => continue,
            Err(_) => return,
        }
    }
}

fn is_temporary(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | Interrupted | WouldBlock
    ) || e.raw_os_error().is_some_and(|n| n == 24 || n == 23) // EMFILE / ENFILE
}

async fn client_handler(f: Arc<dyn ClientFactory>, conn: TcpStream, dialer: &proxy::Dialer) {
    let name = f.transport_name();
    let mut req = match socks5::handshake(conn).await {
        Ok(r) => r,
        Err(e) => {
            log::error(&format!("{name} - client failed socks handshake: {e}"));
            return;
        }
    };
    let addr_str = log::elide_addr(&req.target);
    let args = match f.parse_args(&req.args) {
        Ok(a) => a,
        Err(e) => {
            log::error(&format!("{name}({addr_str}) - invalid arguments: {e}"));
            let _ = req.reply(socks5::ReplyCode::GeneralFailure).await;
            return;
        }
    };
    let remote = match f.dial(&req.target, dialer, args).await {
        Ok(c) => c,
        Err(e) => {
            let (text, code) = match &e {
                DialError::Io(io) => (log::elide_error(io), socks5::error_to_reply_code(io)),
                DialError::Other(o) => (
                    log::elide_error(o.as_ref()),
                    socks5::ReplyCode::GeneralFailure,
                ),
            };
            log::error(&format!(
                "{name}({addr_str}) - outgoing connection failed: {text}"
            ));
            let _ = req.reply(code).await;
            return;
        }
    };
    if let Err(e) = req.reply(socks5::ReplyCode::Succeeded).await {
        log::error(&format!(
            "{name}({addr_str}) - SOCKS reply failed: {}",
            log::elide_error(&e)
        ));
        return;
    }
    match copy_loop(Conn::from_tcp(req.into_stream()), remote).await {
        Ok(()) => log::info(&format!("{name}({addr_str}) - closed connection")),
        Err(e) => log::warn(&format!(
            "{name}({addr_str}) - closed connection: {}",
            log::elide_error(&e)
        )),
    }
}

async fn server_setup(
    state_dir: &std::path::Path,
    term: &termmon::TermMonitor,
) -> Result<Vec<JoinHandle<()>>, ExitCode> {
    let info = Arc::new(pt::server_setup().map_err(fatal)?);
    pt::report_version("lyrebird-rs", VERSION);

    let mut listeners = Vec::new();
    for bindaddr in &info.bindaddrs {
        let name = &bindaddr.method_name;
        let Some(t) = transports::get(name) else {
            pt::smethod_error(name, "no such transport is supported");
            continue;
        };
        let f = match t.server_factory(state_dir, &bindaddr.options) {
            Ok(f) => f,
            Err(e) => {
                pt::smethod_error(name, &e.to_string());
                continue;
            }
        };
        // 0.0.0.0 means "all addresses", as with Go's nil-IP listener.
        let mut addr = bindaddr.addr;
        if addr.ip() == std::net::Ipv4Addr::UNSPECIFIED {
            addr = SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), addr.port());
        }
        let ln = match bind_server(addr).await {
            Ok(l) => l,
            Err(e) => {
                pt::smethod_error(name, &e.to_string());
                continue;
            }
        };
        let local = ln.local_addr().expect("bound listener has an address");
        let task = tokio::spawn(server_accept_loop(
            f.clone(),
            ln,
            info.clone(),
            term.clone(),
        ));
        pt::smethod_args(name, &local, f.args().as_ref());
        log::info(&format!(
            "{name} - registered listener: {}",
            log::elide_addr(&local.to_string())
        ));
        listeners.push(task);
    }
    pt::smethods_done();
    Ok(listeners)
}

/// Dual-stack wildcard binds fall back to IPv4 where IPv6 is unavailable.
async fn bind_server(addr: SocketAddr) -> std::io::Result<TcpListener> {
    match TcpListener::bind(addr).await {
        Err(e) if addr.ip() == std::net::Ipv6Addr::UNSPECIFIED => {
            let v4 = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), addr.port());
            TcpListener::bind(v4).await.map_err(|_| e)
        }
        other => other,
    }
}

async fn server_accept_loop(
    f: Arc<dyn ServerFactory>,
    ln: TcpListener,
    info: Arc<pt::ServerInfo>,
    term: termmon::TermMonitor,
) {
    loop {
        match ln.accept().await {
            Ok((conn, peer)) => {
                let (f, info, term) = (f.clone(), info.clone(), term.clone());
                tokio::spawn(async move {
                    let _guard = term.handler();
                    server_handler(f, conn, peer, &info).await;
                });
            }
            Err(e) if is_temporary(&e) => continue,
            Err(_) => return,
        }
    }
}

async fn server_handler(
    f: Arc<dyn ServerFactory>,
    conn: TcpStream,
    peer: SocketAddr,
    info: &pt::ServerInfo,
) {
    let name = f.transport_name();
    let addr_str = log::elide_addr(&peer.to_string());
    log::info(&format!("{name}({addr_str}) - new connection"));
    let remote = match f.wrap(conn).await {
        Ok(c) => c,
        Err(e) => {
            log::warn(&format!(
                "{name}({addr_str}) - handshake failed: {}",
                log::elide_error(e.as_ref())
            ));
            return;
        }
    };
    let or_conn = match pt::extorport::dial_or(info, &peer, name).await {
        Ok(c) => c,
        Err(e) => {
            log::error(&format!(
                "{name}({addr_str}) - failed to connect to ORPort: {}",
                log::elide_error(&e)
            ));
            return;
        }
    };
    match copy_loop(Conn::from_tcp(or_conn), remote).await {
        Ok(()) => log::info(&format!("{name}({addr_str}) - closed connection")),
        Err(e) => log::warn(&format!(
            "{name}({addr_str}) - closed connection: {}",
            log::elide_error(&e)
        )),
    }
}

/// Upstream copies with io.Copy's 32 KiB buffer.
const COPY_BUFFER: usize = 32 * 1024;

async fn copy(
    from: &mut dyn transports::ReadHalf,
    to: &mut dyn transports::WriteHalf,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; COPY_BUFFER];
    loop {
        let n = from.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n]).await?;
    }
}

/// Both directions run until they end on their own (no half-close is
/// propagated), then both connections close — as upstream's copyLoop and
/// the deferred Close() calls (for a TLS transport, the close_notify).
async fn copy_loop(a: Conn, b: Conn) -> std::io::Result<()> {
    let Conn {
        reader: mut ar,
        writer: mut aw,
    } = a;
    let Conn {
        reader: mut br,
        writer: mut bw,
    } = b;
    let (r1, r2) = tokio::join!(
        copy(ar.as_mut(), bw.as_mut()),
        copy(br.as_mut(), aw.as_mut())
    );
    for w in [aw.as_mut(), bw.as_mut()] {
        let _ = tokio::time::timeout(Duration::from_secs(1), w.shutdown()).await;
    }
    r1.and(r2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn go_flag_syntax() {
        let f = parse_flags(&v(&[
            "-enableLogging",
            "--logLevel",
            "DEBUG",
            "-unsafeLogging=false",
        ]))
        .unwrap();
        assert!(f.enable_logging);
        assert_eq!(f.log_level, "DEBUG");
        assert!(!f.unsafe_logging);
        let f = parse_flags(&v(&["-logLevel=INFO", "-obfs4-distBias"])).unwrap();
        assert_eq!(f.log_level, "INFO");
        assert!(f.dist_bias);
        assert!(parse_flags(&v(&["-nope"])).is_err());
        assert!(parse_flags(&v(&["-logLevel"])).is_err());
        assert!(parse_flags(&v(&["---version"])).is_err());
        assert!(parse_flags(&v(&["-version=maybe"])).is_err());
        // Parsing stops at the first non-flag argument.
        assert!(parse_flags(&v(&["positional", "-nope"])).is_ok());
    }
}
