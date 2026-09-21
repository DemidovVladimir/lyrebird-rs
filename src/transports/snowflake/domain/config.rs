// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of lyrebird transports/snowflake (ParseArgs) and snowflake/v2
// client/lib (ClientConfig, parseIceServers).

//! Bridge-line arguments and ICE server lists.

use super::broker::BrokerConfig;
use crate::shared::domain::proxy::parse_proxy_uri;
use crate::shared::domain::pt::Args;
use crate::shared::ports::log;

/// snowflake `ClientConfig`.
#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    pub broker: BrokerConfig,
    pub ice_addresses: Vec<String>,
    pub max: i64,
}

fn split_list(s: &str) -> Vec<String> {
    s.trim().split(',').map(str::to_string).collect()
}

/// lyrebird's snowflake `ParseArgs`.
pub fn parse_client_args(args: &Args) -> Result<ClientConfig, String> {
    let mut c = ClientConfig::default();
    if let Some(v) = args.get("ampcache") {
        c.broker.amp_cache_url = v.into();
    }
    if let Some(v) = args.get("sqsqueue") {
        c.broker.sqs_queue_url = v.into();
    }
    if let Some(v) = args.get("sqscreds") {
        c.broker.sqs_creds = v.into();
    }
    if let Some(v) = args.get("fronts") {
        if !v.is_empty() {
            c.broker.front_domains = split_list(v);
        }
    } else if let Some(v) = args.get("front") {
        c.broker.front_domains = split_list(v);
    }
    if let Some(v) = args.get("ice") {
        c.ice_addresses = split_list(v);
    }
    if let Some(v) = args.get("max") {
        c.max = v
            .parse()
            .map_err(|_| format!("Invalid SOCKS arg: max={v}"))?;
    }
    if let Some(v) = args.get("url") {
        c.broker.broker_url = v.into();
    }
    if let Some(v) = args.get("utls-nosni") {
        c.broker.utls_remove_sni = matches!(v.to_ascii_lowercase().as_str(), "true" | "yes");
    }
    if let Some(v) = args.get("utls-imitate") {
        c.broker.utls_client_id = v.into();
    }
    if let Some(v) = args.get("fingerprint") {
        c.broker.bridge_fingerprint = v.into();
    }
    if let Some(v) = args.get("proxy") {
        let spec = parse_proxy_uri(v).map_err(|_| format!("Invalid SOCKS arg: proxy={v}"))?;
        if spec.scheme != "socks5" {
            return Err("proxy is not supported: unsupported proxy type".into());
        }
        // Upstream relays WebRTC through SOCKS5 UDP ASSOCIATE; not ported yet.
        return Err(
            "proxy is not supported: SOCKS5 UDP relaying is not implemented in lyrebird-rs".into(),
        );
    }
    Ok(c)
}

/// pion `ice.ParseURL` for `stun:` URLs, re-serialized as `stun:host:port`.
fn parse_stun_url(address: &str) -> Result<String, String> {
    let rest = address.strip_prefix("stun:").ok_or("unknown scheme type")?;
    if rest.contains(['?', '/', '#']) {
        return Err("queries not supported in stun address".into());
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, tail) = v6.split_once(']').ok_or("missing ']' in address")?;
        match tail {
            "" => (h, None),
            t => (h, Some(t.strip_prefix(':').ok_or("invalid port")?)),
        }
    } else {
        match rest.rsplit_once(':') {
            Some((h, _)) if h.contains(':') => return Err("too many colons in address".into()),
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    let port: u16 = match port {
        None => 3478,
        Some(p) => p.parse().map_err(|_| "invalid port".to_string())?,
    };
    Ok(if host.contains(':') {
        format!("stun:[{host}]:{port}")
    } else {
        format!("stun:{host}:{port}")
    })
}

/// snowflake `parseIceServers`: keeps valid `stun:` servers only.
pub fn parse_ice_servers(addresses: &[String]) -> Vec<String> {
    let mut servers = Vec::new();
    for address in addresses {
        let address = address.trim();
        let scheme = address.split_once(':').map(|(s, _)| s.to_ascii_lowercase());
        if scheme.as_deref() != Some("stun") {
            log::print(&format!(
                "Warning: Only stun: (STUN over UDP) servers are supported currently, skipping {address}"
            ));
            continue;
        }
        match parse_stun_url(address) {
            Ok(s) => servers.push(s),
            Err(e) => log::print(&format!(
                "Warning: Parsing ICE server {address} resulted in error: {e}, skipping"
            )),
        }
    }
    servers
}

pub fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = crate::shared::domain::crypto::csrand::intn(i as i64 + 1) as usize;
        v.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> Args {
        let mut a = Args::new();
        for (k, v) in pairs {
            a.add(k, v);
        }
        a
    }

    #[test]
    fn parses_lyrebird_args() {
        let c = parse_client_args(&args(&[
            ("url", "https://1098762253.rsc.cdn77.org/"),
            ("fronts", "www.cdn77.com,www.phpmyadmin.net"),
            ("front", "ignored.example"),
            (
                "ice",
                " stun:stun.antisip.com:3478,stun:stun.epygi.com:3478 ",
            ),
            ("utls-imitate", "hellorandomizedalpn"),
            ("utls-nosni", "YES"),
            ("fingerprint", "2B280B23E1107BB62ABFC40DDCC8824814F80A72"),
            ("max", "3"),
        ]))
        .unwrap();
        assert_eq!(c.broker.broker_url, "https://1098762253.rsc.cdn77.org/");
        assert_eq!(
            c.broker.front_domains,
            ["www.cdn77.com", "www.phpmyadmin.net"]
        );
        assert_eq!(
            c.ice_addresses,
            ["stun:stun.antisip.com:3478", "stun:stun.epygi.com:3478"]
        );
        assert_eq!(c.broker.utls_client_id, "hellorandomizedalpn");
        assert!(c.broker.utls_remove_sni);
        assert_eq!(
            c.broker.bridge_fingerprint,
            "2B280B23E1107BB62ABFC40DDCC8824814F80A72"
        );
        assert_eq!(c.max, 3);

        let c =
            parse_client_args(&args(&[("fronts", ""), ("front", "a.example,b.example")])).unwrap();
        assert!(c.broker.front_domains.is_empty());
        let c = parse_client_args(&args(&[("front", "a.example,b.example")])).unwrap();
        assert_eq!(c.broker.front_domains, ["a.example", "b.example"]);
        assert_eq!(
            parse_client_args(&args(&[("max", "x")])).unwrap_err(),
            "Invalid SOCKS arg: max=x"
        );
        assert!(parse_client_args(&args(&[("proxy", "http://127.0.0.1:1")]))
            .unwrap_err()
            .contains("unsupported proxy type"));
        assert!(parse_client_args(&args(&[("proxy", "socks5://127.0.0.1:1")])).is_err());
    }

    #[test]
    fn parses_ice_servers_like_pion() {
        let input: Vec<String> = [
            "stun:stun.l.google.com:19302",
            " stun:stun.example ",
            "stun:[2001:db8::1]:3479",
            "stun:[2001:db8::2]",
            "turn:turn.example:3478",
            "stuns:stun.example:5349",
            "stun:host:notaport",
            "stun::3478",
            "stun:host:3478?transport=udp",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            parse_ice_servers(&input),
            [
                "stun:stun.l.google.com:19302",
                "stun:stun.example:3478",
                "stun:[2001:db8::1]:3479",
                "stun:[2001:db8::2]:3478",
            ]
        );
    }

    #[test]
    fn shuffles_every_element() {
        let mut v: Vec<u32> = (0..32).collect();
        shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort();
        assert_eq!(sorted, (0..32).collect::<Vec<_>>());
    }
}
