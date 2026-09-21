// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/webtunnel/{client.go,utls.go} and
// common/utlsutil.

//! Bridge-line arguments, and the TLS checks they ask for.

use crate::transports::webtunnel::ports::tls::Verify;

/// lyrebird's default `utls=` fingerprint.
pub const DEFAULT_UTLS: &str = "hellorandomizednoalpn";
/// Go `crypto/tls` with an empty `ServerName`.
pub const ERR_TLS_NO_NAME: &str =
    "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config";
/// uTLS's version of the same check.
pub const ERR_UTLS_NO_NAME: &str = "tls: at least one of ServerName, InsecureSkipVerify or InsecureServerNameToVerify must be specified in the tls.Config";

/// The uTLS ClientHello names lyrebird accepts (`common/utlsutil`);
/// `hellogolang` maps to nil upstream and is rejected there too.
pub const UTLS_NAMES: &[&str] = &[
    "hellorandomized",
    "hellorandomizedalpn",
    "hellorandomizednoalpn",
    "hellofirefox_auto",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellofirefox_63",
    "hellofirefox_65",
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellochrome_auto",
    "hellochrome_58",
    "hellochrome_62",
    "hellochrome_70",
    "hellochrome_72",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "helloios_auto",
    "helloios_11_1",
    "helloios_12_1",
    "helloios_13",
    "helloios_14",
    "helloandroid_11",
    "helloedge_auto",
    "helloedge_85",
    "helloedge_106",
    "hellosafari_auto",
    "hellosafari_16_0",
    "hello360_auto",
    "hello360_7_5",
    "hello360_11_0",
    "helloqq_auto",
    "helloqq_11_1",
];

/// `utlsutil.ParseClientHelloID`: `None` for "none" (Go's own TLS), the
/// lower-cased name for a known fingerprint ("" is Chrome auto).
pub fn parse_client_hello_id(s: &str) -> Result<Option<String>, String> {
    let s = s.to_lowercase();
    match s.as_str() {
        "none" => Ok(None),
        "" => Ok(Some("hellochrome_auto".into())),
        _ if UTLS_NAMES.contains(&s.as_str()) => Ok(Some(s)),
        _ => Err(format!("invalid ClientHelloID: '{s}'")),
    }
}

/// lyrebird's `clientConfig`, one per SOCKS connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientConfig {
    /// `host:port` to dial (the URL's, unless `addr=`).
    pub remote_address: String,
    /// Request path without its leading slash.
    pub path: String,
    /// `"tls"` for https URLs, empty otherwise.
    pub tls_kind: String,
    /// The `servername=` spec (a name or a list) sent as SNI.
    pub tls_server_name: String,
    /// The `Host:` header.
    pub http_host: String,
    /// `utls=`; empty means Go's own TLS, i.e. `utls=none`.
    pub utls_fingerprint: String,
    /// Verify the certificate against this name instead of the SNI
    /// (`sni-imitation=`, `cert-domain=`); uTLS mode only.
    pub utls_insecure_server_name_to_verify: String,
    /// `cert=`: base64 SHA-256 chain hash; when set, nothing else about
    /// the certificate is checked.
    pub pinned_certificate_chain_hash: String,
}

/// lyrebird's `clientFactory.parseArgs`.
pub fn parse_client_args(args: &crate::shared::domain::pt::Args) -> Result<ClientConfig, String> {
    let mut c = ClientConfig::default();
    if let Some(url_str) = args.get("url") {
        let url = url::Url::parse(url_str).map_err(|e| format!("url parse error: {e}"))?;
        let default_port = match url.scheme() {
            "https" => {
                c.tls_kind = "tls".into();
                443
            }
            "http" => 80,
            _ => return Err("url parse error: unknown scheme".into()),
        };
        // Go's url.Hostname: no brackets around an IPv6 literal.
        let hostname = url.host_str().unwrap_or("").trim_matches(['[', ']']);
        c.path = url.path().strip_prefix('/').unwrap_or(url.path()).into();
        c.tls_server_name = hostname.into();
        c.http_host = hostname.into();
        let port = url.port().unwrap_or(default_port);
        // Upstream concatenates hostname:port, undialable for IPv6.
        c.remote_address = if hostname.contains(':') {
            format!("[{hostname}]:{port}")
        } else {
            format!("{hostname}:{port}")
        };
        if let Some(addr) = args.get("addr") {
            c.remote_address = addr.into();
        }
    }
    if let Some(v) = args.get("sni-imitation") {
        c.tls_server_name = v.into();
        c.utls_insecure_server_name_to_verify = c.http_host.clone();
    }
    if let Some(v) = args.get("servername") {
        c.tls_server_name = v.into();
    }
    c.utls_fingerprint = match args.get("utls") {
        None | Some("") => DEFAULT_UTLS.into(),
        Some("none") => String::new(),
        Some(v) => v.into(),
    };
    if let Some(v) = args.get("cert") {
        c.pinned_certificate_chain_hash = v.into();
    }
    if let Some(v) = args.get("cert-domain") {
        c.utls_insecure_server_name_to_verify = v.into();
    }
    Ok(c)
}

/// The certificate check and SNI for one dial (upstream's `tls.Config` /
/// `uTLSConfig` construction, which happens before any I/O). `None` sends
/// no SNI.
pub fn tls_checks(
    config: &ClientConfig,
    server_name: &str,
) -> Result<(Verify, Option<String>), String> {
    use base64::Engine as _;
    let mut pins = Vec::new();
    if !config.pinned_certificate_chain_hash.is_empty() {
        let pin = base64::engine::general_purpose::STANDARD
            .decode(&config.pinned_certificate_chain_hash)
            .map_err(|e| format!("failed to decode approved certificate chain hash : {e}"))?;
        pins.push(pin);
    }
    // Upstream takes the uTLS path for any non-empty fingerprint; a name
    // that parses to "none" there dereferences nil.
    let utls = match config.utls_fingerprint.as_str() {
        "" => None,
        name => parse_client_hello_id(name)?,
    };
    if let Some(name) = &utls {
        crate::shared::ports::log::print(&format!(
            "uTLS fingerprint {name:?} is not supported; using rustls"
        ));
    }
    // The verify name only exists on the uTLS path.
    let verify_name = config.utls_insecure_server_name_to_verify.as_str();
    let verify = if !pins.is_empty() {
        Verify::Pins(pins)
    } else if utls.is_some() && verify_name == "*" {
        return Err("cert-domain=* (chain check without a name check) is not supported".into());
    } else if utls.is_some() && !verify_name.is_empty() {
        Verify::Name(verify_name.to_string())
    } else {
        Verify::ServerName
    };
    if server_name.is_empty() {
        if verify == Verify::ServerName {
            return Err(if utls.is_some() {
                ERR_UTLS_NO_NAME.into()
            } else {
                ERR_TLS_NO_NAME.into()
            });
        }
        // Nothing to verify the name against, or a pin: no SNI, as Go
        // sends none for an empty ServerName.
        return Ok((verify, None));
    }
    Ok((verify, Some(server_name.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::domain::pt::Args;

    fn args(pairs: &[(&str, &str)]) -> Args {
        let mut a = Args::new();
        for (k, v) in pairs {
            a.add(k, v);
        }
        a
    }

    #[test]
    fn parses_bridge_line_args() {
        let c = parse_client_args(&args(&[
            (
                "url",
                "https://d3pyjtpvxs6z0u.cloudfront.net/Exei6xoh1aev8fiethee",
            ),
            ("ver", "0.0.2"),
        ]))
        .unwrap();
        assert_eq!(
            c,
            ClientConfig {
                remote_address: "d3pyjtpvxs6z0u.cloudfront.net:443".into(),
                path: "Exei6xoh1aev8fiethee".into(),
                tls_kind: "tls".into(),
                tls_server_name: "d3pyjtpvxs6z0u.cloudfront.net".into(),
                http_host: "d3pyjtpvxs6z0u.cloudfront.net".into(),
                utls_fingerprint: DEFAULT_UTLS.into(),
                ..Default::default()
            }
        );
        let c = parse_client_args(&args(&[
            ("url", "http://example.com:8080/p"),
            ("addr", "192.0.2.1:80"),
            ("sni-imitation", "www.cloudflare.com"),
            ("servername", "a.test, b.test"),
            ("utls", "none"),
            ("cert", "AAAA"),
            ("cert-domain", "verify.test"),
        ]))
        .unwrap();
        assert_eq!(
            c,
            ClientConfig {
                remote_address: "192.0.2.1:80".into(),
                path: "p".into(),
                tls_kind: String::new(),
                tls_server_name: "a.test, b.test".into(),
                http_host: "example.com".into(),
                utls_fingerprint: String::new(),
                utls_insecure_server_name_to_verify: "verify.test".into(),
                pinned_certificate_chain_hash: "AAAA".into(),
            }
        );
        let c = parse_client_args(&args(&[("url", "https://[2001:db8::1]:8443")])).unwrap();
        assert_eq!(
            (c.remote_address.as_str(), c.path.as_str()),
            ("[2001:db8::1]:8443", "")
        );
        assert_eq!(c.http_host, "2001:db8::1");
        assert_eq!(
            parse_client_args(&args(&[])).unwrap().utls_fingerprint,
            DEFAULT_UTLS
        );
        assert_eq!(
            parse_client_args(&args(&[("url", "ftp://x/")])).unwrap_err(),
            "url parse error: unknown scheme"
        );
        assert!(parse_client_args(&args(&[("url", "https://h:abc/p")]))
            .unwrap_err()
            .starts_with("url parse error: "));
    }

    #[test]
    fn client_hello_ids() {
        assert_eq!(parse_client_hello_id("NONE").unwrap(), None);
        assert_eq!(
            parse_client_hello_id("HelloChrome_Auto")
                .unwrap()
                .as_deref(),
            Some("hellochrome_auto")
        );
        assert_eq!(
            parse_client_hello_id("hellogolang").unwrap_err(),
            "invalid ClientHelloID: 'hellogolang'"
        );
    }

    #[test]
    fn tls_checks_follow_the_bridge_line() {
        let c = |extra: &[(&str, &str)]| {
            let mut all = vec![("url", "https://bridge.test/p")];
            all.extend_from_slice(extra);
            parse_client_args(&args(&all)).unwrap()
        };
        assert_eq!(
            tls_checks(&c(&[]), "bridge.test").unwrap(),
            (Verify::ServerName, Some("bridge.test".into()))
        );
        assert_eq!(
            tls_checks(&c(&[("sni-imitation", "x.test")]), "x.test").unwrap(),
            (Verify::Name("bridge.test".into()), Some("x.test".into()))
        );
        // cert-domain only applies on the uTLS path.
        assert_eq!(
            tls_checks(&c(&[("cert-domain", "v.test"), ("utls", "none")]), "a").unwrap(),
            (Verify::ServerName, Some("a".into()))
        );
        assert_eq!(
            tls_checks(&c(&[("cert", "AQI=")]), "").unwrap(),
            (Verify::Pins(vec![vec![1, 2]]), None)
        );
        assert_eq!(tls_checks(&c(&[]), "").unwrap_err(), ERR_UTLS_NO_NAME);
        assert_eq!(
            tls_checks(&c(&[("utls", "none")]), "").unwrap_err(),
            ERR_TLS_NO_NAME
        );
        assert!(tls_checks(&c(&[("cert-domain", "*")]), "a").is_err());
    }
}
