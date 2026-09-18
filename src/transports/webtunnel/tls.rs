// Copyright (c) 2022 The Tor Project
// Copyright (c) 2023, The Tor Project
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: MIT AND BSD-2-Clause
//
// Port of webtunnel transport/tls/tls.go and common/certiChainHashCalc/pin.go
// (MIT; the latter from v2ray-core, MIT) and of lyrebird
// transports/webtunnel/utls.go (BSD-2-Clause), on rustls.

//! TLS for webtunnel: Mozilla roots, TLS 1.2+, no ALPN (uTLS's
//! `hellorandomizednoalpn` sends none either). The chain is verified
//! against the SNI, against another name (`sni-imitation`, `cert-domain`),
//! or only against a pinned chain hash (`cert=`), as upstream.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

/// How the server's certificate chain is checked.
pub enum Verify {
    /// Against the name sent as SNI (Go `crypto/tls` with `ServerName`).
    ServerName,
    /// Against `name` instead of the SNI (uTLS `InsecureServerNameToVerify`).
    Name(ServerName<'static>),
    /// Only against pinned chain hashes, no chain validation at all
    /// (`InsecureSkipVerify` plus `VerifyPeerCertificate`).
    Pins(Vec<Vec<u8>>),
}

/// Shared verifier state; one per client factory.
pub struct Tls {
    provider: Arc<CryptoProvider>,
    webpki: Arc<WebPkiServerVerifier>,
}

impl Default for Tls {
    fn default() -> Tls {
        Tls::new()
    }
}

impl Tls {
    /// Verifies against the Mozilla root store (Go uses the system's).
    pub fn new() -> Tls {
        Tls::with_roots(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    }

    pub fn with_roots(roots: rustls::RootCertStore) -> Tls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .expect("root store is valid");
        Tls { provider, webpki }
    }

    /// A client config for one connection. `send_sni` false leaves the SNI
    /// extension out (Go sends none for an empty `ServerName`).
    pub fn config(&self, verify: Verify, send_sni: bool) -> Arc<rustls::ClientConfig> {
        let verifier: Arc<dyn ServerCertVerifier> = match verify {
            Verify::ServerName => self.webpki.clone(),
            Verify::Name(name) => Arc::new(NameVerifier {
                inner: self.webpki.clone(),
                name,
            }),
            Verify::Pins(pins) => Arc::new(PinVerifier {
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
}
