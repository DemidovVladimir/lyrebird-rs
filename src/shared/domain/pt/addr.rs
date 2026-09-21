// Port of goptlib pt.go (CC0) and Go's net.SplitHostPort.

//! `host:port` parsing with Go's rules.

use std::net::{IpAddr, SocketAddr};

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
}
