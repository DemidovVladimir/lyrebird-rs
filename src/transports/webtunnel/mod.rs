// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird transports/webtunnel/{webtunnel.go,client.go,utls.go}.

//! WebTunnel (HTTPT): Tor carried by a web server's HTTP upgrade. Client
//! only, as upstream; the bridge side is the separate `webtunnel` project.
//!
//! A dial ignores the SOCKS target. It connects to the bridge URL's host
//! (or `addr=`), does TLS for `https` with the URL host (or `servername=`,
//! `sni-imitation=`) as SNI, sends `GET <path>` with the upgrade headers
//! and, after `101 Switching Protocols`, hands the raw stream to tor.

pub mod httpupgrade;
pub mod servername;
pub mod tls;

use std::io;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::common::httpc::{Connection, Stream};
use crate::log;
use crate::proxy::Dialer;
use crate::pt::{self, Args, LogSeverity};
use crate::transports::{self, BoxError, BoxFuture, ClientArgs, Conn, DialError, Plain, ReadHalf};

pub const TRANSPORT_NAME: &str = "webtunnel";
/// lyrebird's default `utls=` fingerprint.
pub const DEFAULT_UTLS: &str = "hellorandomizednoalpn";
/// Go `crypto/tls` with an empty `ServerName`.
const ERR_TLS_NO_NAME: &str =
    "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config";
/// uTLS's version of the same check.
const ERR_UTLS_NO_NAME: &str = "tls: at least one of ServerName, InsecureSkipVerify or InsecureServerNameToVerify must be specified in the tls.Config";

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

pub struct Transport;

impl transports::Transport for Transport {
    fn name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn client_factory(
        &self,
        _state_dir: &Path,
    ) -> Result<Arc<dyn transports::ClientFactory>, BoxError> {
        Ok(Arc::new(ClientFactory::new()))
    }

    fn server_factory(
        &self,
        _state_dir: &Path,
        _args: &Args,
    ) -> Result<Arc<dyn transports::ServerFactory>, BoxError> {
        Err("unimplemented".into())
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
pub fn parse_client_args(args: &Args) -> Result<ClientConfig, String> {
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

/// `msg` with addresses scrubbed unless `-unsafeLogging` (upstream logs
/// the bridge host and its resolved address as-is).
fn scrubbed(msg: &str) -> String {
    if log::unsafe_logging() {
        msg.to_string()
    } else {
        log::scrub(msg)
    }
}

/// PT `LOG` line for tor.
fn pt_log(severity: LogSeverity, msg: &str) {
    pt::log(severity, &scrubbed(msg));
}

pub struct ClientFactory {
    generators: servername::Holder,
    tls: tls::Tls,
}

impl Default for ClientFactory {
    fn default() -> ClientFactory {
        ClientFactory::new()
    }
}

impl ClientFactory {
    pub fn new() -> ClientFactory {
        ClientFactory::with_tls(tls::Tls::new())
    }

    /// A factory trusting a different root store (tests).
    pub fn with_tls(tls: tls::Tls) -> ClientFactory {
        ClientFactory {
            generators: servername::Holder::default(),
            tls,
        }
    }

    /// The TLS config and SNI for one dial (upstream's `tls.Config` /
    /// `uTLSConfig` construction, which happens before any I/O).
    fn tls_config(
        &self,
        config: &ClientConfig,
        server_name: &str,
    ) -> Result<(Arc<rustls::ClientConfig>, ServerName<'static>), String> {
        let mut pins = Vec::new();
        if !config.pinned_certificate_chain_hash.is_empty() {
            let pin = base64::engine::general_purpose::STANDARD
                .decode(&config.pinned_certificate_chain_hash)
                .map_err(|e| format!("failed to decode approved certificate chain hash : {e}"))?;
            pins.push(pin);
        }
        // Upstream takes the uTLS path for any non-empty fingerprint; a
        // name that parses to "none" there dereferences nil.
        let utls = match config.utls_fingerprint.as_str() {
            "" => None,
            name => parse_client_hello_id(name)?,
        };
        if let Some(name) = &utls {
            log::print(&format!(
                "uTLS fingerprint {name:?} is not supported; using rustls"
            ));
        }
        // The verify name only exists on the uTLS path.
        let verify_name = config.utls_insecure_server_name_to_verify.as_str();
        let verify = if !pins.is_empty() {
            tls::Verify::Pins(pins)
        } else if utls.is_some() && verify_name == "*" {
            return Err("cert-domain=* (chain check without a name check) is not supported".into());
        } else if utls.is_some() && !verify_name.is_empty() {
            tls::Verify::Name(tls::server_name(verify_name)?)
        } else {
            tls::Verify::ServerName
        };
        let (name, send_sni) = if server_name.is_empty() {
            if matches!(verify, tls::Verify::ServerName) {
                return Err(if utls.is_some() {
                    ERR_UTLS_NO_NAME.into()
                } else {
                    ERR_TLS_NO_NAME.into()
                });
            }
            // Nothing to verify the name against, or a pin: no SNI, as Go
            // sends none for an empty ServerName.
            (
                ServerName::try_from("no-sni.invalid").expect("valid"),
                false,
            )
        } else {
            (tls::server_name(server_name)?, true)
        };
        Ok((self.tls.config(verify, send_sni), name))
    }

    async fn dial_impl(&self, config: ClientConfig, dialer: &Dialer) -> Result<Conn, String> {
        let tcp = dialer.dial(&config.remote_address).await.map_err(|e| {
            format!(
                "error dialing {}: {}",
                log::elide_addr(&config.remote_address),
                log::elide_error(&e)
            )
        })?;

        let mut server_name = String::new();
        let mut generator = None;
        if !config.tls_server_name.is_empty() {
            let g = self
                .generators
                .get(config.tls_server_name.trim())
                .map_err(|e| format!("error getting server name generator: {e}"))?;
            server_name = g.generate();
            generator = Some(g);
        }
        pt_log(
            LogSeverity::Notice,
            &format!("Using TLS SNI: {server_name}"),
        );

        let tls = if config.tls_kind == "tls" {
            Some(self.tls_config(&config, &server_name)?)
        } else {
            None
        };
        // From here on a failure means the current server name did not
        // work (upstream: the TLS handshake runs inside the upgrade).
        let upgraded = async {
            let stream = match tls {
                Some((cfg, name)) => {
                    let tls = tokio_rustls::TlsConnector::from(cfg)
                        .connect(name, tcp)
                        .await
                        .map_err(|e| {
                            // rustls wraps a verifier's own error text;
                            // upstream returns the pin mismatch as-is.
                            let text = e.to_string();
                            match text.strip_prefix("unexpected error: ") {
                                Some(inner) if inner == tls::ERR_PIN_MISMATCH => inner.to_string(),
                                _ => text,
                            }
                        })?;
                    Stream::Tls(Box::new(tls))
                }
                None => Stream::Plain(tcp),
            };
            httpupgrade::client(stream, &config.path, &config.http_host).await
        }
        .await;
        match upgraded {
            Ok(conn) => Ok(assemble(conn)),
            Err(e) => {
                if let Some(g) = generator {
                    g.reroll_if_unchanged(&server_name);
                }
                Err(e)
            }
        }
    }
}

impl transports::ClientFactory for ClientFactory {
    fn transport_name(&self) -> &'static str {
        TRANSPORT_NAME
    }

    fn parse_args(&self, args: &Args) -> Result<ClientArgs, BoxError> {
        match parse_client_args(args) {
            Ok(c) => Ok(Box::new(c)),
            Err(e) => {
                pt_log(LogSeverity::Error, &format!("Error parsing args: {e}"));
                Err(scrubbed(&e).into())
            }
        }
    }

    fn dial<'a>(
        &'a self,
        _target: &'a str,
        dialer: &'a Dialer,
        args: ClientArgs,
    ) -> BoxFuture<'a, Result<Conn, DialError>> {
        Box::pin(async move {
            let config = args
                .downcast::<ClientConfig>()
                .map_err(|_| DialError::Other("invalid argument type for args".into()))?;
            match self.dial_impl(*config, dialer).await {
                Ok(conn) => Ok(conn),
                Err(e) => {
                    pt_log(LogSeverity::Error, &format!("Error dialing: {e}"));
                    Err(DialError::Other(scrubbed(&e).into()))
                }
            }
        })
    }
}

/// The tunnel: the upgraded stream, preceded by whatever arrived with the
/// reply head.
fn assemble(conn: Connection) -> Conn {
    let prefix = conn.rbuf;
    match conn.stream {
        Stream::Plain(tcp) => {
            let (r, w) = tcp.into_split();
            Conn {
                reader: Box::new(Prefixed::new(prefix, r)),
                writer: Box::new(Plain(w)),
            }
        }
        Stream::Tls(tls) => {
            let (r, w) = tokio::io::split(*tls);
            Conn {
                reader: Box::new(Prefixed::new(prefix, r)),
                writer: Box::new(Plain(w)),
            }
        }
    }
}

struct Prefixed<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> Prefixed<R> {
    fn new(prefix: Vec<u8>, inner: R) -> Prefixed<R> {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<R: AsyncRead + Unpin + Send> ReadHalf for Prefixed<R> {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> BoxFuture<'a, io::Result<usize>> {
        Box::pin(async move {
            if self.pos < self.prefix.len() {
                let n = buf.len().min(self.prefix.len() - self.pos);
                buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            self.inner.read(buf).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::ClientFactory as _;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    pub(super) fn args(pairs: &[(&str, &str)]) -> Args {
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

    pub(super) const UPGRADE_OK: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n";

    /// A plain upgrade server: answers `reply` to any request, then echoes.
    pub(super) async fn upgrade_server(reply: &'static [u8]) -> String {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = ln.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    s.write_all(reply).await.unwrap();
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    pub(super) async fn dial(
        f: &ClientFactory,
        url: &str,
        addr: &str,
        extra: &[(&str, &str)],
    ) -> Result<Conn, String> {
        let mut all = vec![("url", url), ("addr", addr)];
        all.extend_from_slice(extra);
        let parsed = f.parse_args(&args(&all)).unwrap();
        f.dial("192.0.2.3:1", &Dialer::Direct, parsed)
            .await
            .map_err(|e| e.to_string())
    }

    pub(super) async fn echo_check(mut conn: Conn, expect_prefix: &[u8]) {
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 13 % 251) as u8).collect();
        conn.writer.write_all(&payload).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while got.len() < expect_prefix.len() + payload.len() {
            let n = conn.reader.read(&mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, [expect_prefix, &payload].concat());
        conn.writer.shutdown().await.unwrap();
        assert_eq!(conn.reader.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn plain_upgrade_round_trip() {
        // Bytes after the head belong to the tunnel and must not be lost.
        let addr = upgrade_server(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\nearly",
        )
        .await;
        let f = ClientFactory::new();
        let conn = dial(&f, "http://bridge.test/secret", &addr, &[])
            .await
            .unwrap();
        echo_check(conn, b"early").await;
    }

    #[tokio::test]
    async fn failures_reroll_only_after_the_dial() {
        let bad = upgrade_server(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        let f = ClientFactory::new();
        let spec = "a.test,b.test,c.test";
        let before = f.generators.get(spec).unwrap().generate();
        let err = dial(
            &f,
            "http://bridge.test/secret",
            &bad,
            &[("servername", spec)],
        )
        .await
        .err()
        .expect("dial must fail");
        assert_eq!(err, "unrecognized reply");
        let after = f.generators.get(spec).unwrap().generate();
        assert_ne!(before, after, "the failed name is rotated out");
        // A refused TCP connection does not touch the generator.
        let err = dial(
            &f,
            "http://bridge.test/secret",
            "127.0.0.1:1",
            &[("servername", spec)],
        )
        .await
        .err()
        .expect("dial must fail");
        assert!(err.starts_with("error dialing "), "{err}");
        assert_eq!(f.generators.get(spec).unwrap().generate(), after);
    }

    #[tokio::test]
    async fn config_errors_happen_before_tls() {
        let addr = upgrade_server(UPGRADE_OK).await;
        let f = ClientFactory::new();
        let err = |extra: &'static [(&'static str, &'static str)]| {
            let (f, addr) = (&f, &addr);
            async move {
                dial(f, "https://bridge.test/secret", addr, extra)
                    .await
                    .err()
                    .expect("dial must fail")
            }
        };
        assert_eq!(
            err(&[("utls", "nonsense")]).await,
            "invalid ClientHelloID: 'nonsense'"
        );
        assert!(err(&[("cert", "not base64!")])
            .await
            .starts_with("failed to decode approved certificate chain hash : "));
        assert_eq!(err(&[("servername", "")]).await, ERR_UTLS_NO_NAME);
        assert_eq!(
            err(&[("servername", ""), ("utls", "none")]).await,
            ERR_TLS_NO_NAME
        );
        assert_eq!(
            err(&[("servername", " , ")]).await,
            "error getting server name generator: invalid servername spec"
        );
    }

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    /// A fresh CA and a leaf for `webtunnel.test` and 127.0.0.1: the root
    /// store, the chain and key the server uses, the chain's pin, and a
    /// pin that must not match.
    fn test_pki() -> (
        rustls::RootCertStore,
        Vec<CertificateDer<'static>>,
        PrivateKeyDer<'static>,
        String,
        String,
    ) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![
            "webtunnel.test".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
        let b64 = |h: Vec<u8>| base64::engine::general_purpose::STANDARD.encode(h);
        let pin = b64(tls::chain_hash(&[leaf.der(), ca.der()]));
        let wrong = b64(tls::chain_hash(&[ca.der()]));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (
            roots,
            vec![leaf.der().clone(), ca.der().clone()],
            key,
            pin,
            wrong,
        )
    }

    /// A TLS upgrade server presenting `chain`; answers 101 and echoes.
    async fn tls_upgrade_server(
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> String {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = ln.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    tls.write_all(UPGRADE_OK).await.unwrap();
                    let (mut r, mut w) = tokio::io::split(tls);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tls_pins_and_names() {
        let (roots, chain, key, pin, wrong) = test_pki();
        let addr = tls_upgrade_server(chain, key).await;
        let url = "https://webtunnel.test/secret";
        // The CA is unknown to the default roots: only a pin gets through,
        // and a pin skips the name check as well.
        let f = ClientFactory::new();
        let err = dial(&f, url, &addr, &[]).await.err().expect("unknown CA");
        assert!(err.contains("invalid peer certificate"), "{err}");
        echo_check(dial(&f, url, &addr, &[("cert", &pin)]).await.unwrap(), b"").await;
        let odd_name = [("cert", pin.as_str()), ("servername", "other.test")];
        echo_check(dial(&f, url, &addr, &odd_name).await.unwrap(), b"").await;
        let err = dial(&f, url, &addr, &[("cert", &wrong)])
            .await
            .err()
            .expect("wrong pin");
        assert!(err.contains(tls::ERR_PIN_MISMATCH), "{err}");

        // With the CA trusted: SNI, imitated SNI and cert-domain rules.
        let f = ClientFactory::with_tls(tls::Tls::with_roots(roots));
        let accepted: [&[(&str, &str)]; 6] = [
            &[],
            &[("utls", "none")],
            &[("sni-imitation", "other.test")],
            &[
                ("servername", "other.test"),
                ("cert-domain", "webtunnel.test"),
            ],
            &[("servername", ""), ("cert-domain", "webtunnel.test")],
            &[("servername", "127.0.0.1")],
        ];
        for extra in accepted {
            let conn = dial(&f, url, &addr, extra)
                .await
                .unwrap_or_else(|e| panic!("{extra:?}: {e}"));
            echo_check(conn, b"").await;
        }
        let refused: [&[(&str, &str)]; 4] = [
            &[("servername", "other.test")],
            // cert-domain only applies on the uTLS path.
            &[("sni-imitation", "other.test"), ("utls", "none")],
            &[("servername", "other.test"), ("cert-domain", "nope.test")],
            &[("servername", "127.0.0.2")],
        ];
        for extra in refused {
            let err = dial(&f, url, &addr, extra)
                .await
                .err()
                .unwrap_or_else(|| panic!("{extra:?} must be refused"));
            assert!(err.contains("invalid peer certificate"), "{extra:?}: {err}");
        }
    }
}
