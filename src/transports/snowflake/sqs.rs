// Copyright (c) 2016 Serene Han, Arlo Breault (snowflake, BSD-3-Clause)
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// The three Amazon SQS calls snowflake's SQS rendezvous makes through
// aws-sdk-go-v2 (AWS JSON 1.0 protocol, SigV4), plus common/sqscreds.

//! Minimal Amazon SQS client.

use std::io;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::common::httpc::{self, Client, Request};
use crate::log;
use crate::proxy::Dialer;

const SERVICE: &str = "sqs";
const MAX_ATTEMPTS: u32 = 3;
const USER_AGENT: &str = "aws-sdk-go-v2/1.36.1 ua/2.1 os/linux lang/go#1.23.6 md/GOOS#linux md/GOARCH#amd64 api/sqs#1.37.14";
const BODY_LIMIT: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Creds {
    pub access_key_id: String,
    pub secret_key: String,
}

/// `sqscreds.AwsCredsFromBase64`.
pub fn creds_from_base64(s: &str) -> Result<Creds, String> {
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(rename = "aws-access-key-id", default)]
        id: String,
        #[serde(rename = "aws-secret-key", default)]
        secret: String,
    }
    let data = STANDARD
        .decode(s)
        .map_err(|e| format!("illegal base64 data: {e}"))?;
    let raw: Raw = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    Ok(Creds {
        access_key_id: raw.id,
        secret_key: raw.secret,
    })
}

/// Region from an SQS queue host (`sqs.<region>.amazonaws.com`).
pub fn region_from_host(host: &str) -> Option<&str> {
    let region = host.strip_prefix("sqs.")?.strip_suffix(".amazonaws.com")?;
    let ok = !region.is_empty()
        && region
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    ok.then_some(region)
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// SigV4 `Authorization` value. `headers` are (lowercase name, value), all
/// signed; `amz_date` is `YYYYMMDDTHHMMSSZ`.
#[allow(clippy::too_many_arguments)]
pub fn sigv4_authorization(
    creds: &Creds,
    region: &str,
    service: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: &[u8],
    amz_date: &str,
) -> String {
    let mut headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_ascii_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    headers.sort();
    let canonical_headers: String = headers.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{method}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{}",
        hex::encode(Sha256::digest(body))
    );
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key_id
    )
}

fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    crate::common::csrand::bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

pub struct SqsClient {
    http: Client,
    endpoint: url::Url,
    region: String,
    creds: Creds,
}

impl SqsClient {
    pub fn new(region: &str, creds: Creds, dialer: Dialer) -> SqsClient {
        let endpoint =
            url::Url::parse(&format!("https://sqs.{region}.amazonaws.com/")).expect("valid region");
        SqsClient {
            http: Client::new(
                dialer,
                httpc::tls_config(true),
                Some(Duration::from_secs(60)),
            ),
            endpoint,
            region: region.to_string(),
            creds,
        }
    }

    async fn call(&self, op: &str, input: Value) -> io::Result<Value> {
        let body = serde_json::to_vec(&input).map_err(io::Error::other)?;
        let host = httpc::host_header(&self.endpoint);
        let invocation = uuid_v4();
        let mut attempt = 1;
        loop {
            let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
            let mut headers = vec![
                ("Amz-Sdk-Invocation-Id".to_string(), invocation.clone()),
                (
                    "Amz-Sdk-Request".to_string(),
                    format!("attempt={attempt}; max={MAX_ATTEMPTS}"),
                ),
                (
                    "Content-Type".to_string(),
                    "application/x-amz-json-1.0".to_string(),
                ),
                ("X-Amz-Date".to_string(), amz_date.clone()),
                ("X-Amz-Target".to_string(), format!("AmazonSQS.{op}")),
            ];
            let mut signed = headers.clone();
            signed.push(("Content-Length".into(), body.len().to_string()));
            signed.push(("Host".into(), host.clone()));
            let auth = sigv4_authorization(
                &self.creds,
                &self.region,
                SERVICE,
                "POST",
                "/",
                "",
                &signed,
                &body,
                &amz_date,
            );
            headers.push(("Authorization".to_string(), auth));
            headers.push(("User-Agent".to_string(), USER_AGENT.to_string()));
            let req = Request {
                method: "POST",
                target: "/",
                host: &host,
                headers,
                body: Some(&body),
                gzip: true,
            };
            let retryable = match self.http.round_trip(&self.endpoint, &req, BODY_LIMIT).await {
                Ok(resp) if resp.head.status == 200 => {
                    return serde_json::from_slice(&resp.body).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("operation error SQS: {op}, {e}"),
                        )
                    });
                }
                Ok(resp) => {
                    let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
                    let kind = v["__type"].as_str().unwrap_or("UnknownError");
                    let kind = kind.rsplit('#').next().unwrap_or(kind).to_string();
                    let msg = v["message"]
                        .as_str()
                        .or(v["Message"].as_str())
                        .unwrap_or("")
                        .to_string();
                    let request_id = resp
                        .head
                        .header("x-amzn-RequestId")
                        .unwrap_or("")
                        .to_string();
                    let err = io::Error::other(format!(
                        "operation error SQS: {op}, https response error StatusCode: {}, RequestID: {request_id}, {kind}: {msg}",
                        resp.head.status
                    ));
                    let throttled = kind.contains("Throttl") || kind == "RequestThrottled";
                    (resp.head.status >= 500 || throttled, err)
                }
                Err(e) => (
                    true,
                    io::Error::new(e.kind(), format!("operation error SQS: {op}, {e}")),
                ),
            };
            let (retry, err) = retryable;
            if !retry || attempt >= MAX_ATTEMPTS {
                return Err(err);
            }
            let cap = Duration::from_secs(20).min(Duration::from_secs(1 << (attempt - 1)));
            tokio::time::sleep(cap.mul_f64(crate::common::csrand::float64())).await;
            attempt += 1;
        }
    }

    pub async fn send_message(
        &self,
        queue_url: &str,
        body: &str,
        client_id: &str,
    ) -> io::Result<()> {
        let input = json!({
            "MessageAttributes": {"ClientID": {"DataType": "String", "StringValue": client_id}},
            "MessageBody": body,
            "QueueUrl": queue_url,
        });
        self.call("SendMessage", input).await.map(|_| ())
    }

    pub async fn get_queue_url(&self, name: &str) -> io::Result<String> {
        let out = self.call("GetQueueUrl", json!({"QueueName": name})).await?;
        Ok(out["QueueUrl"].as_str().unwrap_or_default().to_string())
    }

    /// First message body, or `None` if the long poll returned nothing.
    pub async fn receive_message(
        &self,
        queue_url: &str,
        wait_secs: u32,
    ) -> io::Result<Option<String>> {
        let input = json!({
            "MaxNumberOfMessages": 1,
            "QueueUrl": queue_url,
            "WaitTimeSeconds": wait_secs,
        });
        let out = self.call("ReceiveMessage", input).await?;
        Ok(out["Messages"]
            .as_array()
            .and_then(|m| m.first())
            .map(|m| m["Body"].as_str().unwrap_or_default().to_string()))
    }
}

/// snowflake `sqsRendezvous.Exchange`.
pub async fn exchange(client: &SqsClient, queue_url: &str, req: &[u8]) -> io::Result<Vec<u8>> {
    const TIMEOUT: Duration = Duration::from_secs(1);
    const RETRIES: u32 = 5;
    log::print("Negotiating via SQS Queue rendezvous...");
    let mut id = [0u8; 8];
    crate::common::csrand::bytes(&mut id);
    let client_id = hex::encode(id);
    log::print(&format!("SQS Client ID for rendezvous: {client_id}"));
    let body = String::from_utf8_lossy(req);
    client.send_message(queue_url, &body, &client_id).await?;
    tokio::time::sleep(TIMEOUT).await;

    let mut response_queue = Err(io::Error::other("no attempts"));
    for i in 0..RETRIES {
        response_queue = client
            .get_queue_url(&format!("snowflake-client-{client_id}"))
            .await;
        match &response_queue {
            Ok(_) => break,
            Err(e) => {
                log::print(&e.to_string());
                log::print(&format!(
                    "Attempt {} of {RETRIES} to retrieve URL of response SQS queue failed.",
                    i + 1
                ));
                tokio::time::sleep(TIMEOUT).await;
            }
        }
    }
    let response_queue = response_queue?;

    for i in 0..RETRIES {
        match client.receive_message(&response_queue, 20).await? {
            Some(answer) => return Ok(answer.into_bytes()),
            None => {
                log::print(&format!(
                    "Attempt {} of {RETRIES} to receive message from response SQS queue failed. No message found in queue.",
                    i + 1
                ));
                tokio::time::sleep(TIMEOUT.mul_f64(i as f64 / 2.0 + 1.0)).await;
            }
        }
    }
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_matches_aws_sdk_go_v2() {
        // Oracle: aws-sdk-go-v2 v1.36.1 `v4.Signer.SignHTTP` on the same
        // request (the signer snowflake's SQS rendezvous uses).
        let creds = Creds {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLE".into(),
        };
        let body = br#"{"QueueName":"snowflake-client-0123456789abcdef"}"#;
        let h = |k: &str, v: &str| (k.to_string(), v.to_string());
        let headers = vec![
            h(
                "Amz-Sdk-Invocation-Id",
                "0b7c4b0e-5d2a-4c1e-9f55-7c1f0c2d3e4f",
            ),
            h("Amz-Sdk-Request", "attempt=1; max=3"),
            h("Content-Type", "application/x-amz-json-1.0"),
            h("X-Amz-Date", "20260917T010203Z"),
            h("X-Amz-Target", "AmazonSQS.GetQueueUrl"),
            h("Content-Length", &body.len().to_string()),
            h("Host", "sqs.us-east-1.amazonaws.com"),
        ];
        let auth = sigv4_authorization(
            &creds,
            "us-east-1",
            "sqs",
            "POST",
            "/",
            "",
            &headers,
            body,
            "20260917T010203Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260917/us-east-1/sqs/aws4_request, \
             SignedHeaders=amz-sdk-invocation-id;amz-sdk-request;content-length;content-type;host;x-amz-date;x-amz-target, \
             Signature=678c362d2f7a4e36cb8d6fffa417fbc6625b93f45f208e545c1c8cee221e1618"
        );
    }

    #[test]
    fn parses_creds_and_region() {
        let b64 = STANDARD.encode(r#"{"aws-access-key-id":"AKID","aws-secret-key":"SECRET"}"#);
        assert_eq!(
            creds_from_base64(&b64).unwrap(),
            Creds {
                access_key_id: "AKID".into(),
                secret_key: "SECRET".into()
            }
        );
        assert!(creds_from_base64("!!").is_err());
        assert_eq!(
            region_from_host("sqs.us-east-1.amazonaws.com"),
            Some("us-east-1")
        );
        assert_eq!(region_from_host("sqs..amazonaws.com"), None);
        assert_eq!(region_from_host("sqs.us-east-1.example.com"), None);
        let id = uuid_v4();
        assert_eq!((id.len(), &id[14..15]), (36, "4"));
    }
}
