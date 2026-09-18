// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 client/lib/rendezvous*.go and the client half of
// common/messages.

//! Broker rendezvous: trade our SDP offer for a proxy's SDP answer.

use std::io;
use std::sync::Mutex;
use std::time::Duration;

use super::nat::NAT_UNKNOWN;
use super::{amp, sqs};
use crate::common::httpc::{self, Client, Request};
use crate::log;
use crate::proxy::Dialer;
use crate::transports::BoxFuture;

pub const CLIENT_VERSION: &str = "1.0";
pub const DEFAULT_BRIDGE_FINGERPRINT: &str = "2B280B23E1107BB62ABFC40DDCC8824814F80A72";
const BROKER_ERROR_UNEXPECTED: &str = "Unexpected error, no answer.";
const RENDEZVOUS_ERROR_MSG: &str =
    "One of SQS, AmpCache, or Domain Fronting rendezvous methods must be used.";
/// Maximum number of bytes read from an HTTP response.
const READ_LIMIT: usize = 100_000;
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// JSON string the way Go's `encoding/json` writes it (HTML-safe escapes).
pub fn go_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `preparePollRequest`: version line + ClientPollRequest JSON, whose
/// `offer` is itself a JSON-serialized SessionDescription.
pub fn encode_poll_request(offer_sdp: &str, nat: &str, fingerprint: &str) -> Vec<u8> {
    let fingerprint = if fingerprint.is_empty() {
        DEFAULT_BRIDGE_FINGERPRINT
    } else {
        fingerprint
    };
    let offer = format!(
        "{{\"type\":\"offer\",\"sdp\":{}}}",
        go_json_string(offer_sdp)
    );
    format!(
        "{CLIENT_VERSION}\n{{\"offer\":{},\"nat\":{},\"fingerprint\":{}}}",
        go_json_string(&offer),
        go_json_string(nat),
        go_json_string(fingerprint)
    )
    .into_bytes()
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// `DecodeClientPollResponse` + `DeserializeSessionDescription`: the answer SDP.
pub fn decode_poll_response(data: &[u8]) -> io::Result<String> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        answer: String,
        #[serde(default)]
        error: String,
    }
    let resp: Resp = serde_json::from_slice(data).map_err(|e| invalid(e.to_string()))?;
    if resp.error.is_empty() && resp.answer.is_empty() {
        return Err(invalid("received empty broker response"));
    }
    if !resp.error.is_empty() {
        return Err(io::Error::other(resp.error));
    }
    let desc: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&resp.answer).map_err(|e| invalid(e.to_string()))?;
    let kind = desc
        .get("type")
        .ok_or_else(|| invalid("cannot deserialize SessionDescription without type field"))?;
    let sdp = desc
        .get("sdp")
        .ok_or_else(|| invalid("cannot deserialize SessionDescription without sdp field"))?;
    match kind.as_str() {
        Some("answer") => {}
        Some("offer" | "pranswer" | "rollback") => {
            return Err(invalid("broker returned a non-answer SessionDescription"))
        }
        _ => return Err(invalid("Unknown SDP type")),
    }
    sdp.as_str()
        .map(str::to_string)
        .ok_or_else(|| invalid("cannot deserialize SessionDescription: sdp is not a string"))
}

/// A way of carrying an encoded poll request to the broker and back.
pub trait Rendezvous: Send + Sync {
    fn exchange<'a>(&'a self, req: &'a [u8]) -> BoxFuture<'a, io::Result<Vec<u8>>>;
}

/// Replaces `url`'s host (and port) with a randomly chosen front domain.
fn apply_front(url: &mut url::Url, fronts: &[String]) -> io::Result<()> {
    if fronts.is_empty() {
        return Ok(());
    }
    let front = &fronts[crate::common::csrand::intn(fronts.len() as i64) as usize];
    log::print(&format!("Front URL:   {front}"));
    let parsed = url::Url::parse(&format!("{}://{front}/", url.scheme())).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid front domain: {e}"),
        )
    })?;
    url.set_host(parsed.host_str())
        .and_then(|_| {
            url.set_port(parsed.port())
                .map_err(|_| url::ParseError::InvalidPort)
        })
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid front domain: {e}"),
            )
        })
}

fn request_target(url: &url::Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    }
}

pub struct HttpRendezvous {
    broker: url::Url,
    fronts: Vec<String>,
    client: Client,
}

impl Rendezvous for HttpRendezvous {
    fn exchange<'a>(&'a self, req: &'a [u8]) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(async move {
            log::print("Negotiating via HTTP rendezvous...");
            log::print(&format!(
                "Target URL:  {}",
                httpc::host_header(&self.broker)
            ));
            let mut url = self
                .broker
                .join("client")
                .map_err(|e| invalid(e.to_string()))?;
            let host = httpc::host_header(&url);
            apply_front(&mut url, &self.fronts)?;
            let request = Request {
                method: "POST",
                target: &request_target(&url),
                host: &host,
                headers: vec![],
                body: Some(req),
                gzip: true,
            };
            let resp = self.client.round_trip(&url, &request, READ_LIMIT).await?;
            log::print(&format!(
                "HTTP rendezvous response: {}",
                resp.head.status_text
            ));
            if resp.head.status != 200 {
                return Err(io::Error::other(BROKER_ERROR_UNEXPECTED));
            }
            if resp.truncated {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            Ok(resp.body)
        })
    }
}

pub struct AmpCacheRendezvous {
    broker: url::Url,
    cache: Option<url::Url>,
    fronts: Vec<String>,
    client: Client,
}

impl Rendezvous for AmpCacheRendezvous {
    fn exchange<'a>(&'a self, req: &'a [u8]) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(async move {
            log::print("Negotiating via AMP cache rendezvous...");
            log::print(&format!("Broker URL: {}", self.broker));
            log::print(&format!(
                "AMP cache URL: {}",
                self.cache
                    .as_ref()
                    .map_or("<nil>".to_string(), |c| c.to_string())
            ));
            let mut url = self
                .broker
                .join(&format!("amp/client/{}", amp::encode_path(req)))
                .map_err(|e| invalid(e.to_string()))?;
            if let Some(cache) = &self.cache {
                url = amp::cache_url(&url, cache, "c").map_err(io::Error::other)?;
            }
            let host = httpc::host_header(&url);
            apply_front(&mut url, &self.fronts)?;
            let request = Request {
                method: "GET",
                target: &request_target(&url),
                host: &host,
                headers: vec![],
                body: None,
                gzip: true,
            };
            let resp = self
                .client
                .round_trip(&url, &request, READ_LIMIT + 1)
                .await?;
            log::print(&format!(
                "AMP cache rendezvous response: {}",
                resp.head.status_text
            ));
            if resp.head.status != 200 || resp.head.header("Location").is_some() {
                return Err(io::Error::other(BROKER_ERROR_UNEXPECTED));
            }
            if resp.body.len() > READ_LIMIT {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            amp::armor_decode(&resp.body)
        })
    }
}

pub struct SqsRendezvous {
    queue: String,
    client: sqs::SqsClient,
}

impl Rendezvous for SqsRendezvous {
    fn exchange<'a>(&'a self, req: &'a [u8]) -> BoxFuture<'a, io::Result<Vec<u8>>> {
        Box::pin(sqs::exchange(&self.client, &self.queue, req))
    }
}

/// The rendezvous-related part of snowflake's `ClientConfig`.
#[derive(Clone, Debug, Default)]
pub struct BrokerConfig {
    pub broker_url: String,
    pub amp_cache_url: String,
    pub sqs_queue_url: String,
    pub sqs_creds: String,
    pub front_domains: Vec<String>,
    pub keep_local_addresses: bool,
    pub utls_client_id: String,
    pub utls_remove_sni: bool,
    pub bridge_fingerprint: String,
}

pub struct BrokerChannel {
    rendezvous: Box<dyn Rendezvous>,
    pub keep_local_addresses: bool,
    nat_type: Mutex<String>,
    bridge_fingerprint: String,
}

fn parse_url(s: &str) -> Result<url::Url, String> {
    url::Url::parse(s).map_err(|e| format!("parse {s:?}: {e}"))
}

impl BrokerChannel {
    /// `newBrokerChannelFromConfig`. Upstream exits the process on a bad
    /// rendezvous selection; this returns the error instead.
    pub fn new(config: &BrokerConfig, dialer: Dialer) -> Result<BrokerChannel, String> {
        log::print(&format!(
            "Rendezvous using Broker at: {}",
            config.broker_url
        ));
        if !config.front_domains.is_empty() {
            log::print(&format!(
                "Domain fronting using a randomly selected domain from: [{}]",
                config.front_domains.join(" ")
            ));
        }
        // No uTLS: rustls sends its own ClientHello. SNI removal only
        // applied to uTLS connections upstream, so it does here too.
        if !config.utls_client_id.is_empty() {
            log::print(&format!(
                "uTLS imitation {:?} is not supported; using rustls",
                config.utls_client_id
            ));
        }
        let send_sni = !config.utls_remove_sni || config.utls_client_id.is_empty();
        let client = || {
            Client::new(
                dialer.clone(),
                httpc::tls_config(send_sni),
                Some(RESPONSE_HEADER_TIMEOUT),
            )
        };

        let rendezvous: Box<dyn Rendezvous> = if !config.sqs_queue_url.is_empty() {
            if !config.amp_cache_url.is_empty() || !config.broker_url.is_empty() {
                return Err(format!(
                    "Multiple rendezvous methods specified. {RENDEZVOUS_ERROR_MSG}"
                ));
            }
            if config.sqs_creds.is_empty() {
                return Err("sqscreds must be specified to use SQS rendezvous method.".into());
            }
            log::print(&format!("Through SQS queue at: {}", config.sqs_queue_url));
            let queue = parse_url(&config.sqs_queue_url)?;
            let creds = sqs::creds_from_base64(&config.sqs_creds)?;
            let region = queue.host_str().and_then(sqs::region_from_host).ok_or(
                "Could not extract AWS region from SQS URL. Ensure that the SQS Queue URL provided is valid.",
            )?;
            log::print(&format!("Queue URL:  {}", config.sqs_queue_url));
            Box::new(SqsRendezvous {
                queue: queue.to_string(),
                client: sqs::SqsClient::new(region, creds, dialer.clone()),
            })
        } else if !config.amp_cache_url.is_empty() && !config.broker_url.is_empty() {
            log::print(&format!("Through AMP cache at: {}", config.amp_cache_url));
            Box::new(AmpCacheRendezvous {
                broker: parse_url(&config.broker_url)?,
                cache: Some(parse_url(&config.amp_cache_url)?),
                fronts: config.front_domains.clone(),
                client: client(),
            })
        } else if !config.broker_url.is_empty() {
            Box::new(HttpRendezvous {
                broker: parse_url(&config.broker_url)?,
                fronts: config.front_domains.clone(),
                client: client(),
            })
        } else {
            return Err(format!(
                "No rendezvous method was specified. {RENDEZVOUS_ERROR_MSG}"
            ));
        };

        Ok(BrokerChannel {
            rendezvous,
            keep_local_addresses: config.keep_local_addresses,
            nat_type: Mutex::new(NAT_UNKNOWN.to_string()),
            bridge_fingerprint: config.bridge_fingerprint.clone(),
        })
    }

    #[cfg(test)]
    pub fn with_rendezvous(rendezvous: Box<dyn Rendezvous>) -> BrokerChannel {
        BrokerChannel {
            rendezvous,
            keep_local_addresses: false,
            nat_type: Mutex::new(NAT_UNKNOWN.to_string()),
            bridge_fingerprint: String::new(),
        }
    }

    /// Sends our offer; returns the proxy's answer SDP.
    pub async fn negotiate(&self, offer_sdp: &str, nat_to_send: &str) -> io::Result<String> {
        let req = encode_poll_request(offer_sdp, nat_to_send, &self.bridge_fingerprint);
        let resp = self.rendezvous.exchange(&req).await?;
        log::print(&format!(
            "Received answer: {}",
            String::from_utf8_lossy(&resp)
        ));
        decode_poll_response(&resp)
    }

    pub fn set_nat_type(&self, nat: &str) {
        *self.nat_type.lock().unwrap() = nat.to_string();
        log::print(&format!("NAT Type: {nat}"));
    }

    pub fn nat_type(&self) -> String {
        self.nat_type.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn encodes_poll_request_like_go() {
        let req = encode_poll_request("v=0\r\na=x<y>&z\r\n", "unrestricted", "");
        assert_eq!(
            String::from_utf8(req).unwrap(),
            "1.0\n{\"offer\":\"{\\\"type\\\":\\\"offer\\\",\\\"sdp\\\":\\\"v=0\\\\r\\\\na=x\\\\u003cy\\\\u003e\\\\u0026z\\\\r\\\\n\\\"}\",\
             \"nat\":\"unrestricted\",\"fingerprint\":\"2B280B23E1107BB62ABFC40DDCC8824814F80A72\"}"
        );
    }

    #[test]
    fn decodes_poll_responses() {
        let ok = br#"{"answer":"{\"type\":\"answer\",\"sdp\":\"v=0\\r\\n\"}"}"#;
        assert_eq!(decode_poll_response(ok).unwrap(), "v=0\r\n");
        let err = decode_poll_response(br#"{"error":"no snowflake proxies currently available"}"#)
            .unwrap_err();
        assert_eq!(err.to_string(), "no snowflake proxies currently available");
        let err = decode_poll_response(b"{}").unwrap_err();
        assert_eq!(err.to_string(), "received empty broker response");
        assert!(decode_poll_response(br#"{"answer":"{\"sdp\":\"x\"}"}"#).is_err());
        assert!(
            decode_poll_response(br#"{"answer":"{\"type\":\"offer\",\"sdp\":\"x\"}"}"#).is_err()
        );
        assert!(decode_poll_response(b"not json").is_err());
    }

    #[test]
    fn rejects_bad_rendezvous_selection() {
        let mut c = BrokerConfig {
            sqs_queue_url: "https://sqs.us-east-1.amazonaws.com/1/q".into(),
            broker_url: "https://b/".into(),
            ..Default::default()
        };
        assert!(BrokerChannel::new(&c, Dialer::Direct)
            .err()
            .unwrap()
            .starts_with("Multiple"));
        c.broker_url.clear();
        assert!(BrokerChannel::new(&c, Dialer::Direct)
            .err()
            .unwrap()
            .starts_with("sqscreds"));
        assert!(BrokerChannel::new(&BrokerConfig::default(), Dialer::Direct)
            .err()
            .unwrap()
            .starts_with("No rendezvous"));
        c.sqs_queue_url = "https://queue.example.com/1/q".into();
        c.sqs_creds = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "{}");
        assert!(BrokerChannel::new(&c, Dialer::Direct)
            .err()
            .unwrap()
            .starts_with("Could not extract"));
    }

    /// One-request HTTP server; returns what it received.
    async fn broker(response: String) -> (String, tokio::task::JoinHandle<String>) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let h = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got);
                if let Some(i) = text.find("\r\n\r\n") {
                    let cl = text[..i]
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .map_or(0, |v| v.parse::<usize>().unwrap());
                    if got.len() >= i + 4 + cl {
                        break;
                    }
                }
            }
            s.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(got).unwrap()
        });
        (addr, h)
    }

    fn http_ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn http_rendezvous_with_front() {
        let answer = r#"{"answer":"{\"type\":\"answer\",\"sdp\":\"ANSWER\"}"}"#;
        let (addr, server) = broker(http_ok(answer)).await;
        let port = addr.rsplit_once(':').unwrap().1;
        let config = BrokerConfig {
            broker_url: format!("http://broker.invalid:{port}/sub/"),
            front_domains: vec![addr.clone()],
            ..Default::default()
        };
        let bc = BrokerChannel::new(&config, Dialer::Direct).unwrap();
        assert_eq!(bc.negotiate("OFFER", "restricted").await.unwrap(), "ANSWER");
        let req = server.await.unwrap();
        assert!(req.starts_with(&format!(
            "POST /sub/client HTTP/1.1\r\nHost: broker.invalid:{port}\r\nUser-Agent: Go-http-client/1.1\r\nContent-Length: "
        )), "{req}");
        assert!(req.contains("\r\nAccept-Encoding: gzip\r\n\r\n1.0\n{\"offer\":"));
        assert!(req.ends_with(
            ",\"nat\":\"restricted\",\"fingerprint\":\"2B280B23E1107BB62ABFC40DDCC8824814F80A72\"}"
        ));
    }

    #[tokio::test]
    async fn http_rendezvous_rejects_non_200() {
        let (addr, server) =
            broker("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".into()).await;
        let config = BrokerConfig {
            broker_url: format!("http://{addr}/"),
            ..Default::default()
        };
        let bc = BrokerChannel::new(&config, Dialer::Direct).unwrap();
        let err = bc.negotiate("OFFER", "unknown").await.unwrap_err();
        assert_eq!(err.to_string(), BROKER_ERROR_UNEXPECTED);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn amp_rendezvous_decodes_armor() {
        let answer = r#"{"answer":"{\"type\":\"answer\",\"sdp\":\"AMP\"}"}"#;
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, answer);
        let html = format!(
            "<!doctype html>\n<html amp><body>\n<pre>\n0{}\n</pre>\n<pre>{}</pre></body></html>",
            &b64[..10],
            &b64[10..]
        );
        let (addr, server) = broker(http_ok(&html)).await;
        let port = addr.rsplit_once(':').unwrap().1;
        // The cache host is `<prefix>.<cache host>`; front to the real address.
        let r = AmpCacheRendezvous {
            broker: parse_url("https://snowflake-broker.example/").unwrap(),
            cache: Some(parse_url(&format!("http://localhost:{port}/")).unwrap()),
            fronts: vec![addr.clone()],
            client: Client::new(Dialer::Direct, httpc::tls_config(true), None),
        };
        let bc = BrokerChannel::with_rendezvous(Box::new(r));
        assert_eq!(bc.negotiate("OFFER", "unknown").await.unwrap(), "AMP");
        let req = server.await.unwrap();
        let first = req.lines().next().unwrap();
        assert!(
            first.starts_with("GET /c/s/snowflake-broker.example/amp/client/0"),
            "{first}"
        );
        assert!(
            req.contains(&format!(
                "\r\nHost: snowflake--broker-example.localhost:{port}\r\n"
            )),
            "{req}"
        );
    }
}
