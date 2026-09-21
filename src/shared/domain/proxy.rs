// Copyright (c) 2014, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird cmd/lyrebird/pt_extras.go (ptGetProxy).

//! The outbound proxy tor asks for (`TOR_PT_PROXY`): URI parsing and
//! lyrebird's validation rules.

use crate::shared::domain::pt::{split_host_port, PtError, TorControl};
use crate::shared::ports::env::Env;

/// A validated outbound proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyConfig {
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
pub fn from_env(env: &dyn Env, tor: &TorControl) -> Result<Option<ProxyConfig>, PtError> {
    let raw = env.var("TOR_PT_PROXY");
    if raw.is_empty() {
        return Ok(None);
    }
    let spec = parse_proxy_uri(&raw)
        .map_err(|e| tor.proxy_error(&format!("failed to parse proxy config: {e}")))?;
    if spec.has_path {
        return Err(tor.proxy_error("proxy URI has a path defined"));
    }
    if spec.has_query {
        return Err(tor.proxy_error("proxy URI has a query defined"));
    }
    if spec.has_fragment {
        return Err(tor.proxy_error("proxy URI has a fragment defined"));
    }
    let config = match spec.scheme.as_str() {
        "http" => ProxyConfig::Http {
            host_port: spec.host_port.clone(),
            auth: spec
                .username
                .clone()
                .map(|u| (u, spec.password.clone().unwrap_or_default())),
        },
        "socks4a" => {
            if spec.password.is_some() {
                return Err(tor.proxy_error("proxy URI specified SOCKS4a and a password"));
            }
            ProxyConfig::Socks4a {
                host_port: spec.host_port.clone(),
                user: spec.username.clone().unwrap_or_default(),
            }
        }
        "socks5" => {
            let auth = match (&spec.username, &spec.password) {
                (None, _) => None,
                (Some(u), p) => {
                    if u.is_empty() || u.len() > 255 {
                        return Err(
                            tor.proxy_error("proxy URI specified a invalid SOCKS5 username")
                        );
                    }
                    match p {
                        Some(p) if !p.is_empty() && p.len() <= 255 => Some((u.clone(), p.clone())),
                        _ => {
                            return Err(
                                tor.proxy_error("proxy URI specified a invalid SOCKS5 password")
                            )
                        }
                    }
                }
            };
            ProxyConfig::Socks5 {
                host_port: spec.host_port.clone(),
                auth,
            }
        }
        other => return Err(tor.proxy_error(&format!("proxy URI has invalid scheme: {other}"))),
    };
    if let Err(e) = resolve_ip_port(&spec.host_port) {
        return Err(tor.proxy_error(&format!("proxy URI has invalid host: {e}")));
    }
    Ok(Some(config))
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

    struct OneVar(&'static str);

    impl Env for OneVar {
        fn var(&self, key: &str) -> String {
            match key {
                "TOR_PT_PROXY" => self.0.to_string(),
                _ => String::new(),
            }
        }
    }

    #[test]
    fn validates_like_lyrebird() {
        let (tor, lines) = TorControl::capture();
        assert_eq!(from_env(&OneVar(""), &tor).unwrap(), None);
        assert_eq!(
            from_env(&OneVar("socks5://u:p@127.0.0.1:1080"), &tor).unwrap(),
            Some(ProxyConfig::Socks5 {
                host_port: "127.0.0.1:1080".into(),
                auth: Some(("u".into(), "p".into())),
            })
        );
        assert!(from_env(&OneVar("socks4a://u:p@127.0.0.1:1080"), &tor).is_err());
        assert!(from_env(&OneVar("http://proxy.example:3128"), &tor).is_err());
        assert_eq!(
            *lines.lock().unwrap(),
            [
                "PROXY-ERROR proxy URI specified SOCKS4a and a password",
                "PROXY-ERROR proxy URI has invalid host: not an IP string: \"proxy.example\""
            ]
        );
    }
}
