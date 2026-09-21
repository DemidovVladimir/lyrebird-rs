// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird cmd/lyrebird/{proxy_http,proxy_socks4}.go and the
// golang.org/x/net/proxy SOCKS5 dialer it uses.

//! Outbound dialers through `TOR_PT_PROXY` (http, socks4a, socks5).

use std::io;

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::shared::domain::proxy::ProxyConfig;
use crate::shared::domain::pt::split_host_port;
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::stream::{BoxFuture, BoxStream};

/// Connects through the configured proxy.
pub struct ProxyDialer(ProxyConfig);

impl ProxyDialer {
    pub fn new(config: ProxyConfig) -> ProxyDialer {
        ProxyDialer(config)
    }
}

impl Dialer for ProxyDialer {
    fn dial<'a>(&'a self, addr: &'a str) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let tunnel = match &self.0 {
                ProxyConfig::Http { host_port, auth } => {
                    http_connect(host_port, auth.as_ref(), addr).await?
                }
                ProxyConfig::Socks4a { host_port, user } => {
                    socks4_connect(host_port, user, addr).await?
                }
                ProxyConfig::Socks5 { host_port, auth } => {
                    socks5_connect(host_port, auth.as_ref(), addr).await?
                }
            };
            Ok(Box::new(tunnel) as BoxStream)
        })
    }

    fn is_direct(&self) -> bool {
        false
    }
}

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
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
        let d = ProxyDialer::new(ProxyConfig::Http {
            host_port: addr,
            auth: Some(("u".into(), "p".into())),
        });
        let mut s = d.dial("192.0.2.1:443").await.unwrap();
        assert_eq!(s.read_u8().await.unwrap(), b'X');
        let head = server.await.unwrap();
        assert!(head.starts_with("CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\n"));
        assert!(head.contains("Proxy-Authorization: Basic dTpw\r\n"));
    }
}
