// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 client/lib/rendezvous_{http,ampcache,sqs}.go (the
// transports; the method selection is in the domain's broker).

//! The rendezvous channels: HTTP POST (optionally domain-fronted), the AMP
//! cache, and SQS, all over the shared HTTP client.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use super::amp;
use super::sqs::{self, SqsClient, SqsRendezvous};
use crate::shared::adapters::httpc::{self, Client};
use crate::shared::domain::http::{host_header, Request};
use crate::shared::ports::dialer::Dialer;
use crate::shared::ports::log;
use crate::shared::ports::BoxFuture;
use crate::transports::snowflake::ports::rendezvous::{Rendezvous, RendezvousFactory};

const BROKER_ERROR_UNEXPECTED: &str = "Unexpected error, no answer.";
/// Maximum number of bytes read from an HTTP response.
const READ_LIMIT: usize = 100_000;
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

fn parse_url(s: &str) -> Result<url::Url, String> {
    url::Url::parse(s).map_err(|e| format!("parse {s:?}: {e}"))
}

/// Builds rendezvous channels whose connections go through `dialer`.
pub struct RendezvousClients {
    dialer: Arc<dyn Dialer>,
}

impl RendezvousClients {
    pub fn new(dialer: Arc<dyn Dialer>) -> RendezvousClients {
        RendezvousClients { dialer }
    }

    fn client(&self, send_sni: bool) -> Client {
        Client::new(
            self.dialer.clone(),
            httpc::tls_config(send_sni),
            Some(RESPONSE_HEADER_TIMEOUT),
        )
    }
}

impl RendezvousFactory for RendezvousClients {
    fn http(
        &self,
        broker_url: &str,
        fronts: &[String],
        send_sni: bool,
    ) -> Result<Box<dyn Rendezvous>, String> {
        Ok(Box::new(HttpRendezvous {
            broker: parse_url(broker_url)?,
            fronts: fronts.to_vec(),
            client: self.client(send_sni),
        }))
    }

    fn amp_cache(
        &self,
        broker_url: &str,
        cache_url: &str,
        fronts: &[String],
        send_sni: bool,
    ) -> Result<Box<dyn Rendezvous>, String> {
        log::print(&format!("Through AMP cache at: {cache_url}"));
        Ok(Box::new(AmpCacheRendezvous {
            broker: parse_url(broker_url)?,
            cache: Some(parse_url(cache_url)?),
            fronts: fronts.to_vec(),
            client: self.client(send_sni),
        }))
    }

    fn sqs(&self, queue_url: &str, creds: &str) -> Result<Box<dyn Rendezvous>, String> {
        log::print(&format!("Through SQS queue at: {queue_url}"));
        let queue = parse_url(queue_url)?;
        let creds = sqs::creds_from_base64(creds)?;
        let region = queue.host_str().and_then(sqs::region_from_host).ok_or(
            "Could not extract AWS region from SQS URL. Ensure that the SQS Queue URL provided is valid.",
        )?;
        log::print(&format!("Queue URL:  {queue_url}"));
        Ok(Box::new(SqsRendezvous {
            queue: queue.to_string(),
            client: SqsClient::new(region, creds, self.dialer.clone()),
        }))
    }
}

/// Replaces `url`'s host (and port) with a randomly chosen front domain.
fn apply_front(url: &mut url::Url, fronts: &[String]) -> io::Result<()> {
    if fronts.is_empty() {
        return Ok(());
    }
    let front = &fronts[crate::shared::domain::crypto::csrand::intn(fronts.len() as i64) as usize];
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
            log::print(&format!("Target URL:  {}", host_header(&self.broker)));
            let mut url = self
                .broker
                .join("client")
                .map_err(|e| invalid(e.to_string()))?;
            let host = host_header(&url);
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
            let host = host_header(&url);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::adapters::tcp::DirectDialer;
    use crate::transports::snowflake::domain::broker::{BrokerChannel, BrokerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn clients() -> RendezvousClients {
        RendezvousClients::new(Arc::new(DirectDialer))
    }

    #[test]
    fn sqs_needs_a_region() {
        let c = BrokerConfig {
            sqs_queue_url: "https://queue.example.com/1/q".into(),
            sqs_creds: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "{}"),
            ..Default::default()
        };
        assert!(BrokerChannel::new(&c, &clients())
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
        let bc = BrokerChannel::new(&config, &clients()).unwrap();
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
        let bc = BrokerChannel::new(&config, &clients()).unwrap();
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
            client: Client::new(Arc::new(DirectDialer), httpc::tls_config(true), None),
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
