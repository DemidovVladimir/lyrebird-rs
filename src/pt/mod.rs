// Port of goptlib pt.go (CC0) — the Tor pluggable transport spec, v1.

//! Managed-transport environment handling and the stdout control protocol
//! (`VERSION`, `CMETHOD`, `SMETHOD`, `STATUS`, `LOG`, `PROXY`).

pub mod args;
pub mod extorport;

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;

pub use args::Args;

static STDOUT: Mutex<()> = Mutex::new(());

/// Error already reported on stdout (as `ENV-ERROR` etc.) where applicable.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PtError(pub String);

fn keyword_is_safe(k: &str) -> bool {
    k.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn arg_is_safe(a: &str) -> bool {
    a.bytes().all(|b| b < 0x80 && b != 0 && b != b'\n')
}

fn format_line(keyword: &str, args: &[&str]) -> String {
    assert!(
        keyword_is_safe(keyword),
        "keyword {keyword:?} contains forbidden bytes"
    );
    let mut line = keyword.to_string();
    for a in args {
        assert!(arg_is_safe(a), "arg {a:?} contains forbidden bytes");
        line.push(' ');
        line.push_str(a);
    }
    line
}

/// Writes one control line to stdout and flushes.
pub fn line(keyword: &str, args: &[&str]) {
    let text = format_line(keyword, args);
    let _guard = STDOUT.lock().unwrap_or_else(|e| e.into_inner());
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
    let _ = out.flush();
}

fn do_error(keyword: &str, args: &[&str]) -> PtError {
    line(keyword, args);
    PtError(format_line(keyword, args))
}

pub fn env_error(msg: &str) -> PtError {
    do_error("ENV-ERROR", &[msg])
}

pub fn version_error(msg: &str) -> PtError {
    do_error("VERSION-ERROR", &[msg])
}

pub fn cmethod_error(method: &str, msg: &str) -> PtError {
    do_error("CMETHOD-ERROR", &[method, msg])
}

pub fn smethod_error(method: &str, msg: &str) -> PtError {
    do_error("SMETHOD-ERROR", &[method, msg])
}

pub fn proxy_error(msg: &str) -> PtError {
    do_error("PROXY-ERROR", &[msg])
}

pub fn cmethod(name: &str, socks: &str, addr: &SocketAddr) {
    line("CMETHOD", &[name, socks, &addr.to_string()]);
}

pub fn cmethods_done() {
    line("CMETHODS", &["DONE"]);
}

pub fn smethod_args(name: &str, addr: &SocketAddr, args: Option<&Args>) {
    let encoded = format!("ARGS:{}", args::encode_smethod_args(args));
    line("SMETHOD", &[name, &addr.to_string(), &encoded]);
}

pub fn smethods_done() {
    line("SMETHODS", &["DONE"]);
}

pub fn proxy_done() {
    line("PROXY", &["DONE"]);
}

pub fn report_version(implementation: &str, version: &str) {
    let imp = format!("IMPLEMENTATION={}", encode_cstring(implementation));
    let ver = format!("VERSION={}", encode_cstring(version));
    line("STATUS", &["TYPE=version", &imp, &ver]);
}

#[derive(Clone, Copy)]
pub enum LogSeverity {
    Error,
    Warning,
    Notice,
    Info,
    Debug,
}

pub fn log(severity: LogSeverity, message: &str) {
    let sev = match severity {
        LogSeverity::Error => "error",
        LogSeverity::Warning => "warning",
        LogSeverity::Notice => "notice",
        LogSeverity::Info => "info",
        LogSeverity::Debug => "debug",
    };
    let sev = format!("SEVERITY={sev}");
    let msg = format!("MESSAGE={}", encode_cstring(message));
    line("LOG", &[&sev, &msg]);
}

/// C-style quoted string with octal escapes (pt-spec §3.3.4).
pub fn encode_cstring(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.bytes() {
        if c == 32 || c == 33 || (35..=91).contains(&c) || (93..=126).contains(&c) {
            out.push(c as char);
        } else {
            out.push_str(&format!("\\{c:03o}"));
        }
    }
    out.push('"');
    out
}

fn getenv(key: &str) -> String {
    std::env::var(key).unwrap_or_default()
}

fn getenv_required(key: &str) -> Result<String, PtError> {
    let v = getenv(key);
    if v.is_empty() {
        return Err(env_error(&format!("no {key} environment variable")));
    }
    Ok(v)
}

fn get_managed_transport_ver() -> Result<String, PtError> {
    const TRANSPORT_VERSION: &str = "1";
    let offered = getenv_required("TOR_PT_MANAGED_TRANSPORT_VER")?;
    if offered.split(',').any(|v| v == TRANSPORT_VERSION) {
        Ok(TRANSPORT_VERSION.to_string())
    } else {
        Err(version_error("no-version"))
    }
}

/// `TOR_PT_STATE_LOCATION`, created with mode 0700.
pub fn make_state_dir() -> Result<PathBuf, PtError> {
    let dir = PathBuf::from(getenv_required("TOR_PT_STATE_LOCATION")?);
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(&dir)
        .map_err(|e| PtError(format!("mkdir {}: {e}", dir.display())))?;
    Ok(dir)
}

pub struct ClientInfo {
    pub method_names: Vec<String>,
}

/// Version negotiation and `TOR_PT_CLIENT_TRANSPORTS`. `TOR_PT_PROXY` is
/// validated by `proxy::from_env` (lyrebird's stricter check).
pub fn client_setup() -> Result<ClientInfo, PtError> {
    let ver = get_managed_transport_ver()?;
    line("VERSION", &[&ver]);
    let transports = getenv_required("TOR_PT_CLIENT_TRANSPORTS")?;
    Ok(ClientInfo {
        method_names: transports.split(',').map(str::to_string).collect(),
    })
}

#[derive(Clone, Debug)]
pub struct Bindaddr {
    pub method_name: String,
    pub addr: SocketAddr,
    pub options: Args,
}

pub struct ServerInfo {
    pub bindaddrs: Vec<Bindaddr>,
    pub or_addr: Option<SocketAddr>,
    pub extended_or_addr: Option<SocketAddr>,
    pub auth_cookie_path: String,
}

/// Go `net.SplitHostPort`.
pub fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    let err = |why: &str| Err(format!("address {hostport}: {why}"));
    let Some(i) = hostport.rfind(':') else {
        return err("missing port in address");
    };
    let (host, j, k);
    if hostport.starts_with('[') {
        let Some(end) = hostport.find(']') else {
            return err("missing ']' in address");
        };
        if end + 1 == hostport.len() {
            return err("missing port in address");
        } else if end + 1 != i {
            if hostport.as_bytes()[end + 1] == b':' {
                return err("too many colons in address");
            }
            return err("missing port in address");
        }
        host = &hostport[1..end];
        j = 1;
        k = end + 1;
    } else {
        host = &hostport[..i];
        if host.contains(':') {
            return err("too many colons in address");
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains('[') {
        return err("unexpected '[' in address");
    }
    if hostport[k..].contains(']') {
        return err("unexpected ']' in address");
    }
    Ok((host.to_string(), hostport[i + 1..].to_string()))
}

/// IP:port only (no names), accepting unbracketed IPv6 like goptlib.
pub fn resolve_addr(addr: &str) -> Result<SocketAddr, String> {
    let (ip, port) = match split_host_port(addr) {
        Ok(hp) => hp,
        Err(e) => {
            let parts: Vec<&str> = addr.split(':').collect();
            if parts.len() <= 2 {
                return Err(e);
            }
            let bracketed = format!(
                "[{}]:{}",
                parts[..parts.len() - 1].join(":"),
                parts[parts.len() - 1]
            );
            split_host_port(&bracketed)?
        }
    };
    if ip.is_empty() {
        return Err(format!("address string {addr:?} lacks a host part"));
    }
    if port.is_empty() {
        return Err(format!("address string {addr:?} lacks a port part"));
    }
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| format!("not an IP string: {ip:?}"))?;
    let port: u16 = port.parse().map_err(|e| format!("{e}"))?;
    Ok(SocketAddr::new(ip, port))
}

fn get_server_bindaddrs() -> Result<Vec<Bindaddr>, PtError> {
    let raw_opts = getenv("TOR_PT_SERVER_TRANSPORT_OPTIONS");
    let opts = args::parse_server_transport_options(&raw_opts).map_err(|e| {
        env_error(&format!(
            "TOR_PT_SERVER_TRANSPORT_OPTIONS: {raw_opts:?}: {e}"
        ))
    })?;
    let bind = getenv_required("TOR_PT_SERVER_BINDADDR")?;
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for spec in bind.split(',') {
        let Some((name, addr)) = spec.split_once('-') else {
            return Err(env_error(&format!(
                "TOR_PT_SERVER_BINDADDR: {spec:?}: doesn't contain \"-\""
            )));
        };
        if !seen.insert(name.to_string()) {
            return Err(env_error(&format!(
                "TOR_PT_SERVER_BINDADDR: {spec:?}: duplicate method name {name:?}"
            )));
        }
        let addr = resolve_addr(addr)
            .map_err(|e| env_error(&format!("TOR_PT_SERVER_BINDADDR: {spec:?}: {e}")))?;
        result.push(Bindaddr {
            method_name: name.to_string(),
            addr,
            options: opts.get(name).cloned().unwrap_or_default(),
        });
    }
    let transports = getenv_required("TOR_PT_SERVER_TRANSPORTS")?;
    let wanted: Vec<&str> = transports.split(',').collect();
    result.retain(|b| wanted.contains(&b.method_name.as_str()));
    Ok(result)
}

pub fn server_setup() -> Result<ServerInfo, PtError> {
    let ver = get_managed_transport_ver()?;
    line("VERSION", &[&ver]);
    let bindaddrs = get_server_bindaddrs()?;

    let or_port = getenv("TOR_PT_ORPORT");
    let or_addr =
        if or_port.is_empty() {
            None
        } else {
            Some(resolve_addr(&or_port).map_err(|e| {
                env_error(&format!("cannot resolve TOR_PT_ORPORT {or_port:?}: {e}"))
            })?)
        };

    let auth_cookie_path = getenv("TOR_PT_AUTH_COOKIE_FILE");
    let ext = getenv("TOR_PT_EXTENDED_SERVER_PORT");
    let extended_or_addr = if ext.is_empty() {
        None
    } else {
        if auth_cookie_path.is_empty() {
            return Err(env_error(
                "need TOR_PT_AUTH_COOKIE_FILE environment variable with TOR_PT_EXTENDED_SERVER_PORT",
            ));
        }
        Some(resolve_addr(&ext).map_err(|e| {
            env_error(&format!(
                "cannot resolve TOR_PT_EXTENDED_SERVER_PORT {ext:?}: {e}"
            ))
        })?)
    };
    if or_addr.is_none() && extended_or_addr.is_none() {
        return Err(env_error(
            "need TOR_PT_ORPORT or TOR_PT_EXTENDED_SERVER_PORT environment variable",
        ));
    }
    Ok(ServerInfo {
        bindaddrs,
        or_addr,
        extended_or_addr,
        auth_cookie_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_matches_go() {
        assert_eq!(
            split_host_port("1.2.3.4:80").unwrap(),
            ("1.2.3.4".into(), "80".into())
        );
        assert_eq!(
            split_host_port("[::1]:80").unwrap(),
            ("::1".into(), "80".into())
        );
        assert_eq!(split_host_port(":80").unwrap(), ("".into(), "80".into()));
        assert!(split_host_port("1.2.3.4").is_err());
        assert!(split_host_port("::1:80").is_err());
        assert!(split_host_port("[::1]").is_err());
        assert!(split_host_port("[::1]x:80").is_err());
    }

    #[test]
    fn resolve_addr_matches_goptlib() {
        assert_eq!(
            resolve_addr("127.0.0.1:9000").unwrap().to_string(),
            "127.0.0.1:9000"
        );
        assert_eq!(
            resolve_addr("[::1]:9000").unwrap().to_string(),
            "[::1]:9000"
        );
        // Unbracketed IPv6 is accepted by goptlib.
        assert_eq!(resolve_addr("::1:9000").unwrap().to_string(), "[::1]:9000");
        assert!(resolve_addr("localhost:9000").is_err());
        assert!(resolve_addr(":9000").is_err());
        assert!(resolve_addr("1.2.3.4:").is_err());
        assert!(resolve_addr("1.2.3.4:70000").is_err());
    }

    #[test]
    fn cstring_escapes() {
        assert_eq!(encode_cstring("lyrebird"), "\"lyrebird\"");
        assert_eq!(encode_cstring("a\"b\\c\n"), "\"a\\042b\\134c\\012\"");
    }
}
