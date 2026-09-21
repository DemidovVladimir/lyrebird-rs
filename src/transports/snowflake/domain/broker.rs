// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// Port of snowflake/v2 client/lib/rendezvous.go and the client half of
// common/messages.

//! Broker rendezvous: trade our SDP offer for a proxy's SDP answer, over
//! whichever channel the bridge line picks.

use std::io;
use std::sync::Mutex;

use super::nat::NAT_UNKNOWN;
use crate::shared::ports::log;
use crate::transports::snowflake::ports::rendezvous::{Rendezvous, RendezvousFactory};

pub const CLIENT_VERSION: &str = "1.0";
pub const DEFAULT_BRIDGE_FINGERPRINT: &str = "2B280B23E1107BB62ABFC40DDCC8824814F80A72";
const RENDEZVOUS_ERROR_MSG: &str =
    "One of SQS, AmpCache, or Domain Fronting rendezvous methods must be used.";

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

impl BrokerChannel {
    /// `newBrokerChannelFromConfig`: picks the rendezvous method. Upstream
    /// exits the process on a bad selection; this returns the error instead.
    pub fn new(
        config: &BrokerConfig,
        factory: &dyn RendezvousFactory,
    ) -> Result<BrokerChannel, String> {
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

        let rendezvous = if !config.sqs_queue_url.is_empty() {
            if !config.amp_cache_url.is_empty() || !config.broker_url.is_empty() {
                return Err(format!(
                    "Multiple rendezvous methods specified. {RENDEZVOUS_ERROR_MSG}"
                ));
            }
            if config.sqs_creds.is_empty() {
                return Err("sqscreds must be specified to use SQS rendezvous method.".into());
            }
            factory.sqs(&config.sqs_queue_url, &config.sqs_creds)?
        } else if !config.amp_cache_url.is_empty() && !config.broker_url.is_empty() {
            factory.amp_cache(
                &config.broker_url,
                &config.amp_cache_url,
                &config.front_domains,
                send_sni,
            )?
        } else if !config.broker_url.is_empty() {
            factory.http(&config.broker_url, &config.front_domains, send_sni)?
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

    /// Records which method was built; `sqs` fails like a bad region.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    struct Nowhere;

    impl Rendezvous for Nowhere {
        fn exchange<'a>(
            &'a self,
            _req: &'a [u8],
        ) -> crate::shared::ports::BoxFuture<'a, io::Result<Vec<u8>>> {
            Box::pin(async { Err(io::ErrorKind::NotConnected.into()) })
        }
    }

    impl RendezvousFactory for Recorder {
        fn http(
            &self,
            url: &str,
            fronts: &[String],
            sni: bool,
        ) -> Result<Box<dyn Rendezvous>, String> {
            self.0
                .lock()
                .unwrap()
                .push(format!("http {url} {fronts:?} {sni}"));
            Ok(Box::new(Nowhere))
        }

        fn amp_cache(
            &self,
            url: &str,
            cache: &str,
            fronts: &[String],
            sni: bool,
        ) -> Result<Box<dyn Rendezvous>, String> {
            self.0
                .lock()
                .unwrap()
                .push(format!("amp {url} {cache} {fronts:?} {sni}"));
            Ok(Box::new(Nowhere))
        }

        fn sqs(&self, url: &str, _creds: &str) -> Result<Box<dyn Rendezvous>, String> {
            self.0.lock().unwrap().push(format!("sqs {url}"));
            Err("bad queue".into())
        }
    }

    #[test]
    fn rejects_bad_rendezvous_selection() {
        let f = Recorder::default();
        let mut c = BrokerConfig {
            sqs_queue_url: "https://sqs.us-east-1.amazonaws.com/1/q".into(),
            broker_url: "https://b/".into(),
            ..Default::default()
        };
        assert!(BrokerChannel::new(&c, &f)
            .err()
            .unwrap()
            .starts_with("Multiple"));
        c.broker_url.clear();
        assert!(BrokerChannel::new(&c, &f)
            .err()
            .unwrap()
            .starts_with("sqscreds"));
        assert!(BrokerChannel::new(&BrokerConfig::default(), &f)
            .err()
            .unwrap()
            .starts_with("No rendezvous"));
        c.sqs_creds = "e30=".into();
        assert_eq!(BrokerChannel::new(&c, &f).err().unwrap(), "bad queue");
        assert_eq!(
            *f.0.lock().unwrap(),
            ["sqs https://sqs.us-east-1.amazonaws.com/1/q"]
        );
    }

    #[test]
    fn picks_amp_then_http() {
        let f = Recorder::default();
        let mut c = BrokerConfig {
            broker_url: "https://b/".into(),
            amp_cache_url: "https://cdn.ampproject.org/".into(),
            front_domains: vec!["f.example".into()],
            utls_client_id: "hellorandomizedalpn".into(),
            utls_remove_sni: true,
            ..Default::default()
        };
        BrokerChannel::new(&c, &f).unwrap();
        c.amp_cache_url.clear();
        c.utls_client_id.clear();
        BrokerChannel::new(&c, &f).unwrap();
        assert_eq!(
            *f.0.lock().unwrap(),
            [
                "amp https://b/ https://cdn.ampproject.org/ [\"f.example\"] false",
                "http https://b/ [\"f.example\"] true"
            ]
        );
    }
}
