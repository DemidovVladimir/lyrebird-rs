// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird cmd/lyrebird/{pt_extras,proxy_http,proxy_socks4}.go and
// the golang.org/x/net/proxy SOCKS5 dialer it uses.

//! Outbound dialers: direct, or via `TOR_PT_PROXY` (http, socks4a, socks5).

use std::io;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::pt::{self, split_host_port};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dialer {
    Direct,
    Http {
        host_port: String,
        auth: Option<(String, String)>,
    },
    Socks4a {
        host_port: String,
        user: String,
    },
    Socks5 {
        host_port: String,
        auth: Option<(String, String)>,
    },
}

/// A parsed proxy URI, keeping the authority exactly as written.
#[derive(Debug)]
pub struct ProxySpec {
    pub scheme: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub host_port: String,
    has_path: bool,
    has_query: bool,
    has_fragment: bool,
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Splits `scheme://[user[:pass]@]host:port[/path][?q][#f]` without applying
/// scheme default ports (Go's url.URL keeps `Host` verbatim).
pub fn parse_proxy_uri(raw: &str) -> Result<ProxySpec, String> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| "proxy URI is relative, must be absolute".to_string())?;
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return Err(format!("invalid scheme {scheme:?}"));
    }
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(auth_end);
    let (userinfo, host_port) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    let (username, password) = match userinfo {
        None => (None, None),
        Some(ui) => match ui.split_once(':') {
            Some((u, p)) => (Some(percent_decode(u)), Some(percent_decode(p))),
            None => (Some(percent_decode(ui)), None),
        },
    };
    let path_end = tail.find(['?', '#']).unwrap_or(tail.len());
    let query_part = &tail[path_end..];
    Ok(ProxySpec {
        scheme: scheme.to_ascii_lowercase(),
        username,
        password,
        host_port: host_port.to_string(),
        has_path: path_end > 0,
        has_query: query_part.starts_with('?') && query_part.len() > 1,
        has_fragment: query_part.contains('#') && !query_part.ends_with('#'),
    })
}

/// lyrebird's `ptGetProxy`. Emits `PROXY-ERROR` on rejection; the caller
/// emits `PROXY DONE` on success. Snowflake's UDP-association probe is done
/// by the snowflake transport itself.
pub fn from_env() -> Result<Option<(ProxySpec, Dialer)>, pt::PtError> {
    let raw = std::env::var("TOR_PT_PROXY").unwrap_or_default();
    if raw.is_empty() {
        return Ok(None);
    }
    let spec = parse_proxy_uri(&raw)
        .map_err(|e| pt::proxy_error(&format!("failed to parse proxy config: {e}")))?;
    if spec.has_path {
        return Err(pt::proxy_error("proxy URI has a path defined"));
    }
    if spec.has_query {
        return Err(pt::proxy_error("proxy URI has a query defined"));
    }
    if spec.has_fragment {
        return Err(pt::proxy_error("proxy URI has a fragment defined"));
    }
    let dialer = match spec.scheme.as_str() {
        "http" => Dialer::Http {
            host_port: spec.host_port.clone(),
            auth: spec
                .username
                .clone()
                .map(|u| (u, spec.password.clone().unwrap_or_default())),
        },
        "socks4a" => {
            if spec.password.is_some() {
                return Err(pt::proxy_error(
                    "proxy URI specified SOCKS4a and a password",
                ));
            }
            Dialer::Socks4a {
                host_port: spec.host_port.clone(),
                user: spec.username.clone().unwrap_or_default(),
            }
        }
        "socks5" => {
            let auth = match (&spec.username, &spec.password) {
                (None, _) => None,
                (Some(u), p) => {
                    if u.is_empty() || u.len() > 255 {
                        return Err(pt::proxy_error(
                            "proxy URI specified a invalid SOCKS5 username",
                        ));
                    }
                    match p {
                        Some(p) if !p.is_empty() && p.len() <= 255 => Some((u.clone(), p.clone())),
                        _ => {
                            return Err(pt::proxy_error(
                                "proxy URI specified a invalid SOCKS5 password",
                            ))
                        }
                    }
                }
            };
            Dialer::Socks5 {
                host_port: spec.host_port.clone(),
                auth,
            }
        }
        other => {
            return Err(pt::proxy_error(&format!(
                "proxy URI has invalid scheme: {other}"
            )))
        }
    };
    if let Err(e) = resolve_ip_port(&spec.host_port) {
        return Err(pt::proxy_error(&format!("proxy URI has invalid host: {e}")));
    }
    Ok(Some((spec, dialer)))
}

/// lyrebird `resolveAddrStr`: literal IP and numeric port.
fn resolve_ip_port(addr: &str) -> Result<std::net::SocketAddr, String> {
    let (ip, port) = split_host_port(addr)?;
    if ip.is_empty() {
        return Err(format!("address string {addr:?} lacks a host part"));
    }
    if port.is_empty() {
        return Err(format!("address string {addr:?} lacks a port part"));
    }
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| format!("not an IP string: {ip:?}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("not a Port string: {port:?}"))?;
    Ok(std::net::SocketAddr::new(ip, port))
}

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

impl Dialer {
    pub async fn dial(&self, addr: &str) -> io::Result<TcpStream> {
        match self {
            Dialer::Direct => TcpStream::connect(addr).await,
            Dialer::Http { host_port, auth } => http_connect(host_port, auth.as_ref(), addr).await,
            Dialer::Socks4a { host_port, user } => socks4_connect(host_port, user, addr).await,
            Dialer::Socks5 { host_port, auth } => {
                socks5_connect(host_port, auth.as_ref(), addr).await
            }
        }
    }
}

async fn http_connect(
    proxy: &str,
    auth: Option<&(String, String)>,
    addr: &str,
) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    let mut req = format!("CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n");
    if let Some((u, p)) = auth {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    // Read the response head byte by byte so no tunnel data is consumed.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err(other("proxy error: response header too long"));
        }
        head.push(s.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&head);
    let status_line = text.lines().next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let _proto = parts.next();
    let code = parts.next().unwrap_or_default();
    if code != "200" {
        let status = status_line.split_once(' ').map_or("", |x| x.1);
        return Err(other(format!("proxy error: {status}")));
    }
    Ok(s)
}

async fn socks4_connect(proxy: &str, user: &str, addr: &str) -> io::Result<TcpStream> {
    let (ip, port) = split_host_port(addr).map_err(other)?;
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| other("failed to parse destination IP"))?;
    let std::net::IpAddr::V4(ip4) = ip else {
        return Err(other("destination address is not IPv4"));
    };
    let port: u16 = port.parse().map_err(|e| other(format!("{e}")))?;
    let mut s = TcpStream::connect(proxy).await?;
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&port.to_be_bytes());
    req.extend_from_slice(&ip4.octets());
    req.extend_from_slice(user.as_bytes());
    req.push(0);
    s.write_all(&req).await?;
    let mut resp = [0u8; 8];
    s.read_exact(&mut resp).await?;
    if resp[0] != 0x00 {
        return Err(other("proxy returned invalid SOCKS4 version"));
    }
    if resp[1] != 0x5a {
        let why = match resp[1] {
            0x5b => "request rejected or failed".to_string(),
            0x5c => "request rejected because SOCKS server cannot connect to identd on the client"
                .to_string(),
            0x5d => {
                "request rejected because the client program and identd report different user-ids"
                    .to_string()
            }
            c => format!("unknown failure code {c:x}"),
        };
        return Err(other(format!("proxy error: {why}")));
    }
    Ok(s)
}

async fn socks5_connect(
    proxy: &str,
    auth: Option<&(String, String)>,
    addr: &str,
) -> io::Result<TcpStream> {
    let (host, port) = split_host_port(addr).map_err(other)?;
    let port: u16 = port
        .parse()
        .map_err(|_| other("proxy: failed to parse port number"))?;
    let mut s = TcpStream::connect(proxy).await?;
    socks5_client_handshake(&mut s, auth, &host, port, 0x01).await?;
    Ok(s)
}

/// SOCKS5 client negotiation; returns the bound address reply body.
pub async fn socks5_client_handshake(
    s: &mut TcpStream,
    auth: Option<&(String, String)>,
    host: &str,
    port: u16,
    cmd: u8,
) -> io::Result<std::net::SocketAddr> {
    let greeting: &[u8] = if auth.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    s.write_all(greeting).await?;
    let mut resp = [0u8; 2];
    s.read_exact(&mut resp).await?;
    if resp[0] != 5 {
        return Err(other(format!(
            "proxy: unexpected protocol version {}",
            resp[0]
        )));
    }
    match resp[1] {
        0 => {}
        2 => {
            let (u, p) =
                auth.ok_or_else(|| other("proxy: no acceptable authentication methods"))?;
            let mut req = vec![1, u.len() as u8];
            req.extend_from_slice(u.as_bytes());
            req.push(p.len() as u8);
            req.extend_from_slice(p.as_bytes());
            s.write_all(&req).await?;
            s.read_exact(&mut resp).await?;
            if resp[1] != 0 {
                return Err(other("proxy: username/password authentication failed"));
            }
        }
        _ => return Err(other("proxy: no acceptable authentication methods")),
    }

    let mut req = vec![5, cmd, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(other(format!(
                    "proxy: destination host name too long: {host}"
                )));
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(other(format!(
            "proxy: unexpected protocol version {}",
            head[0]
        )));
    }
    if head[1] != 0 {
        return Err(other(format!("proxy: {}", socks5_reply_text(head[1]))));
    }
    let ip: std::net::IpAddr = match head[3] {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            b.into()
        }
        4 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            b.into()
        }
        3 => {
            let n = s.read_u8().await? as usize;
            let mut b = vec![0u8; n];
            s.read_exact(&mut b).await?;
            std::net::Ipv4Addr::UNSPECIFIED.into()
        }
        t => return Err(other(format!("proxy: unknown address type {t}"))),
    };
    let bport = s.read_u16().await?;
    Ok(std::net::SocketAddr::new(ip, bport))
}

fn socks5_reply_text(code: u8) -> String {
    match code {
        1 => "general SOCKS server failure".into(),
        2 => "connection not allowed by ruleset".into(),
        3 => "network unreachable".into(),
        4 => "host unreachable".into(),
        5 => "connection refused".into(),
        6 => "TTL expired".into(),
        7 => "command not supported".into(),
        8 => "address type not supported".into(),
        c => format!("unknown code: {c}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uris_like_go() {
        let s = parse_proxy_uri("socks5://us%3Aer:p%40ss@127.0.0.1:1080").unwrap();
        assert_eq!(s.scheme, "socks5");
        assert_eq!(s.username.as_deref(), Some("us:er"));
        assert_eq!(s.password.as_deref(), Some("p@ss"));
        assert_eq!(s.host_port, "127.0.0.1:1080");
        let h = parse_proxy_uri("http://[::1]:80").unwrap();
        assert_eq!(h.host_port, "[::1]:80");
        assert!(!h.has_path);
        assert!(parse_proxy_uri("http://1.2.3.4:80/x").unwrap().has_path);
        assert!(parse_proxy_uri("http://1.2.3.4:80?a=b").unwrap().has_query);
        assert!(parse_proxy_uri("1.2.3.4:80").is_err());
    }

    #[test]
    fn resolve_requires_literal_ip() {
        assert!(resolve_ip_port("127.0.0.1:1080").is_ok());
        assert!(resolve_ip_port("proxy.example:1080").is_err());
        assert!(resolve_ip_port("127.0.0.1").is_err());
    }

    #[tokio::test]
    async fn http_connect_tunnels() {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut c, _) = ln.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(c.read_u8().await.unwrap());
            }
            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nX")
                .await
                .unwrap();
            String::from_utf8(head).unwrap()
        });
        let d = Dialer::Http {
            host_port: addr,
            auth: Some(("u".into(), "p".into())),
        };
        let mut s = d.dial("192.0.2.1:443").await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), b'X');
        let head = server.await.unwrap();
        assert!(head.starts_with("CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n"));
        assert!(head.contains("Proxy-Authorization: Basic dTpw\r\n"));
    }
}
