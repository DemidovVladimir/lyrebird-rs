// Copyright (c) 2022 The Tor Project
// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: MIT AND BSD-2-Clause
//
// Port of webtunnel transport/tls/tls.go and common/certiChainHashCalc/pin.go
// (MIT; the latter from v2ray-core, MIT) and of lyrebird
// transports/webtunnel/utls.go (BSD-2-Clause), on rustls.

//! The `TlsConnector` port on rustls: Mozilla roots, TLS 1.2+, no ALPN
//! (uTLS's `hellorandomizednoalpn` sends none either). The chain is
//! verified against the SNI, against another name (`sni-imitation`,
//! `cert-domain`), or only against a pinned chain hash (`cert=`), as
//! upstream.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::shared::ports::{BoxFuture, BoxStream};
use crate::transports::webtunnel::ports::tls::{TlsConnector, TlsHandshake, Verify};

pub const ERR_PIN_MISMATCH: &str = "pinned certificate chain hash not matched";

/// `certiChainHashCalc.GenerateCertChainHash`: fold SHA-256 over the DER
/// chain as sent (leaf first). Empty for an empty chain.
pub fn chain_hash(certs: &[&[u8]]) -> Vec<u8> {
    let mut hash: Option<[u8; 32]> = None;
    for cert in certs {
        let out: [u8; 32] = Sha256::digest(cert).into();
        hash = Some(match hash {
            None => out,
            Some(prev) => Sha256::digest([prev.as_slice(), &out].concat()).into(),
        });
    }
    hash.map(|h| h.to_vec()).unwrap_or_default()
}

/// Shared verifier state; one per transport.
pub struct RustlsConnector {
    provider: Arc<CryptoProvider>,
    webpki: Arc<WebPkiServerVerifier>,
}

impl Default for RustlsConnector {
    fn default() -> RustlsConnector {
        RustlsConnector::new()
    }
}

impl RustlsConnector {
    /// Verifies against the Mozilla root store (Go uses the system's).
    pub fn new() -> RustlsConnector {
        RustlsConnector::with_roots(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    pub fn with_roots(roots: rustls::RootCertStore) -> RustlsConnector {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("root store is valid");
        RustlsConnector { provider, webpki }
    }

    /// A client config for one connection. `send_sni` false leaves the SNI
    /// extension out (Go sends none for an empty `ServerName`).
    fn config(&self, verify: Checked, send_sni: bool) -> Arc<rustls::ClientConfig> {
        let verifier: Arc<dyn ServerCertVerifier> = match verify {
            Checked::ServerName => self.webpki.clone(),
            Checked::Name(name) => Arc::new(NameVerifier {
                inner: self.webpki.clone(),
                name,
            }),
            Checked::Pins(pins) => Arc::new(PinVerifier {
                pins,
                provider: self.provider.clone(),
            }),
        };
        let mut cfg = rustls::ClientConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("ring supports TLS 1.2 and 1.3")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        cfg.enable_sni = send_sni;
        Arc::new(cfg)
    }
}

/// `Verify` with the name checked by rustls.
enum Checked {
    ServerName,
    Name(ServerName<'static>),
    Pins(Vec<Vec<u8>>),
}

impl TlsConnector for RustlsConnector {
    fn prepare(&self, verify: Verify, sni: Option<&str>) -> Result<Box<dyn TlsHandshake>, String> {
        let verify = match verify {
            Verify::ServerName => Checked::ServerName,
            Verify::Name(name) => Checked::Name(server_name(&name)?),
            Verify::Pins(pins) => Checked::Pins(pins),
        };
        let (name, send_sni) = match sni {
            // rustls needs some name; it is neither sent nor checked.
            None => (
                ServerName::try_from("no-sni.invalid").expect("valid"),
                false,
            ),
            Some(sni) => (server_name(sni)?, true),
        };
        Ok(Box::new(Handshake {
            config: self.config(verify, send_sni),
            name,
        }))
    }
}

struct Handshake {
    config: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
}

impl TlsHandshake for Handshake {
    fn connect(
        self: Box<Self>,
        stream: BoxStream,
    ) -> BoxFuture<'static, Result<BoxStream, String>> {
        Box::pin(async move {
            let tls = tokio_rustls::TlsConnector::from(self.config)
                .connect(self.name, stream)
                .await
                .map_err(|e| {
                    // rustls wraps a verifier's own error text; upstream
                    // returns the pin mismatch as-is.
                    let text = e.to_string();
                    match text.strip_prefix("unexpected error: ") {
                        Some(inner) if inner == ERR_PIN_MISMATCH => inner.to_string(),
                        _ => text,
                    }
                })?;
            Ok(Box::new(tls) as BoxStream)
        })
    }
}

/// Verifies the chain against a fixed name, whatever the SNI was.
#[derive(Debug)]
struct NameVerifier {
    inner: Arc<WebPkiServerVerifier>,
    name: ServerName<'static>,
}

impl ServerCertVerifier for NameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, &self.name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Accepts a chain if and only if its hash is one of the pins; nothing
/// else about the chain is checked (upstream sets `InsecureSkipVerify`).
#[derive(Debug)]
struct PinVerifier {
    pins: Vec<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain: Vec<&[u8]> = vec![end_entity.as_ref()];
        chain.extend(intermediates.iter().map(|c| c.as_ref()));
        let hash = chain_hash(&chain);
        // hmac.Equal: constant time, false for differing lengths.
        let matched = self.pins.iter().fold(false, |acc, pin| {
            acc | (pin.len() == hash.len() && bool::from(pin.ct_eq(&hash)))
        });
        if matched {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(ERR_PIN_MISMATCH.into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS server name from a bridge-line host: brackets and trailing dots
/// are dropped; an IP literal gets no SNI (Go does the same).
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let name = host.trim_matches(['[', ']']).trim_end_matches('.');
    ServerName::try_from(name.to_string()).map_err(|e| format!("invalid server name {name:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::webtunnel::domain::transport::tests::{
        dial, echo_check, factory, UPGRADE_OK,
    };
    use base64::Engine as _;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn folds_chain_hash_like_go() {
        assert!(chain_hash(&[]).is_empty());
        let a: [u8; 32] = Sha256::digest(b"a").into();
        assert_eq!(chain_hash(&[b"a"]), a);
        let b: [u8; 32] = Sha256::digest(b"b").into();
        let ab: [u8; 32] = Sha256::digest([a.as_slice(), &b].concat()).into();
        assert_eq!(chain_hash(&[b"a", b"b"]), ab);
        assert_ne!(chain_hash(&[b"b", b"a"]), ab);
    }

    #[test]
    fn server_names() {
        assert!(matches!(
            server_name("example.com.").unwrap(),
            ServerName::DnsName(_)
        ));
        assert!(matches!(
            server_name("[2001:db8::1]").unwrap(),
            ServerName::IpAddress(_)
        ));
        assert!(server_name("").is_err());
    }

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
        let pin = b64(chain_hash(&[leaf.der(), ca.der()]));
        let wrong = b64(chain_hash(&[ca.der()]));
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
        let f = factory(RustlsConnector::new());
        let err = dial(&f, url, &addr, &[]).await.err().expect("unknown CA");
        assert!(err.contains("invalid peer certificate"), "{err}");
        echo_check(dial(&f, url, &addr, &[("cert", &pin)]).await.unwrap(), b"").await;
        let odd_name = [("cert", pin.as_str()), ("servername", "other.test")];
        echo_check(dial(&f, url, &addr, &odd_name).await.unwrap(), b"").await;
        let err = dial(&f, url, &addr, &[("cert", &wrong)])
            .await
            .err()
            .expect("wrong pin");
        assert!(err.contains(ERR_PIN_MISMATCH), "{err}");

        // With the CA trusted: SNI, imitated SNI and cert-domain rules.
        let f = factory(RustlsConnector::with_roots(roots));
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
