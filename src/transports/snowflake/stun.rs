// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// STUN (RFC 8489) binding client covering what snowflake needs from
// pion/stun: server-reflexive candidate gathering and the RFC 5780 mapping
// test in snowflake/v2 common/nat.

//! Minimal STUN binding client.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_OTHER_ADDRESS: u16 = 0x802C;

pub type TxId = [u8; 12];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BindingResponse {
    pub mapped: Option<SocketAddr>,
    pub other: Option<SocketAddr>,
}

pub fn binding_request() -> (TxId, Vec<u8>) {
    let mut txid = [0u8; 12];
    crate::common::csrand::bytes(&mut txid);
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&MAGIC.to_be_bytes());
    msg.extend_from_slice(&txid);
    (txid, msg)
}

fn parse_address(value: &[u8], xor: Option<&TxId>) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor.is_some() {
        port ^= (MAGIC >> 16) as u16;
    }
    let ip = match (family, value.len()) {
        (1, 8) => {
            let mut b: [u8; 4] = value[4..8].try_into().ok()?;
            if xor.is_some() {
                for (x, m) in b.iter_mut().zip(MAGIC.to_be_bytes()) {
                    *x ^= m;
                }
            }
            IpAddr::V4(Ipv4Addr::from(b))
        }
        (2, 20) => {
            let mut b: [u8; 16] = value[4..20].try_into().ok()?;
            if let Some(txid) = xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&MAGIC.to_be_bytes());
                key[4..].copy_from_slice(txid);
                for (x, k) in b.iter_mut().zip(key) {
                    *x ^= k;
                }
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// Parses a binding success response; returns its transaction id.
pub fn parse_response(msg: &[u8]) -> Option<(TxId, BindingResponse)> {
    if msg.len() < 20 || msg[0] & 0xc0 != 0 {
        return None;
    }
    let mtype = u16::from_be_bytes([msg[0], msg[1]]);
    let len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    if mtype != BINDING_SUCCESS
        || u32::from_be_bytes(msg[4..8].try_into().unwrap()) != MAGIC
        || msg.len() < 20 + len
    {
        return None;
    }
    let txid: TxId = msg[8..20].try_into().unwrap();
    let mut resp = BindingResponse::default();
    let mut xor_mapped = None;
    let mut attrs = &msg[20..20 + len];
    while attrs.len() >= 4 {
        let atype = u16::from_be_bytes([attrs[0], attrs[1]]);
        let alen = u16::from_be_bytes([attrs[2], attrs[3]]) as usize;
        if attrs.len() < 4 + alen {
            break;
        }
        let value = &attrs[4..4 + alen];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => xor_mapped = parse_address(value, Some(&txid)),
            ATTR_MAPPED_ADDRESS => resp.mapped = resp.mapped.or(parse_address(value, None)),
            ATTR_OTHER_ADDRESS => resp.other = parse_address(value, None),
            _ => {}
        }
        let padded = (alen + 3) & !3;
        attrs = &attrs[(4 + padded).min(attrs.len())..];
    }
    if xor_mapped.is_some() {
        resp.mapped = xor_mapped;
    }
    Some((txid, resp))
}

/// Sends a binding request to each server from `socket` and collects the
/// responses that arrive before `timeout` (requests are retransmitted).
pub async fn bind_all(
    socket: &UdpSocket,
    servers: &[SocketAddr],
    timeout: Duration,
) -> Vec<(SocketAddr, BindingResponse)> {
    let mut pending: HashMap<TxId, (SocketAddr, Vec<u8>)> = HashMap::new();
    for &server in servers {
        let (txid, msg) = binding_request();
        let _ = socket.send_to(&msg, server).await;
        pending.insert(txid, (server, msg));
    }
    let deadline = Instant::now() + timeout;
    let mut retransmit = Instant::now() + Duration::from_millis(500);
    let mut out = Vec::new();
    let mut buf = [0u8; 1500];
    while !pending.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if now >= retransmit {
            for (server, msg) in pending.values() {
                let _ = socket.send_to(msg, *server).await;
            }
            retransmit = now + Duration::from_millis(1000);
        }
        let wait = deadline.min(retransmit) - now;
        match tokio::time::timeout(wait, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => {
                if let Some((txid, resp)) = parse_response(&buf[..n]) {
                    if let Some((server, _)) = pending.remove(&txid) {
                        out.push((server, resp));
                    }
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }
    out
}

/// One request/response on a fresh socket (10 s timeout, as upstream).
async fn round_trip(socket: &UdpSocket, server: SocketAddr) -> io::Result<BindingResponse> {
    bind_all(socket, &[server], Duration::from_secs(10))
        .await
        .pop()
        .map(|(_, r)| r)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "timed out waiting for response"))
}

/// RFC 5780 mapping test (snowflake `isRestrictedMapping`): the NAT is
/// "restricted" if the mapped address changes with the destination.
pub async fn is_restricted_mapping(server: &str) -> io::Result<bool> {
    let primary = tokio::net::lookup_host(server)
        .await?
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no IPv4 address"))?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let first = round_trip(&socket, primary).await?;
    let mapped1 = first
        .mapped
        .ok_or_else(|| io::Error::other("Error retrieving XOR-MAPPED-ADDRESS resonse"))?;
    let other = first
        .other
        .ok_or_else(|| io::Error::other("NAT discovery feature not supported"))?;
    let second = round_trip(&socket, other).await?;
    let mapped2 = second
        .mapped
        .ok_or_else(|| io::Error::other("Error retrieving XOR-MAPPED-ADDRESS resonse"))?;
    Ok(mapped1 != mapped2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(txid: &TxId, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            body.resize((body.len() + 3) & !3, 0);
        }
        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC.to_be_bytes());
        msg.extend_from_slice(txid);
        msg.extend(body);
        msg
    }

    #[test]
    fn parses_rfc5769_ipv4_xor_mapped() {
        // RFC 5769 §2.2 sample response (IPv4, 192.0.2.1:32853).
        let txid: TxId = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let xor = vec![0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response(&txid, &[(ATTR_XOR_MAPPED_ADDRESS, xor)]);
        let (id, r) = parse_response(&msg).unwrap();
        assert_eq!(id, txid);
        assert_eq!(r.mapped, Some("192.0.2.1:32853".parse().unwrap()));
    }

    #[test]
    fn parses_rfc5769_ipv6_xor_mapped_and_other() {
        // RFC 5769 §2.3 sample (IPv6, [2001:db8:1234:5678:11:2233:4455:6677]:32853).
        let txid: TxId = [
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
        ];
        let xor = vec![
            0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25,
            0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        ];
        let other = vec![0x00, 0x01, 0x0d, 0x96, 203, 0, 113, 9];
        let msg = response(
            &txid,
            &[(ATTR_XOR_MAPPED_ADDRESS, xor), (ATTR_OTHER_ADDRESS, other)],
        );
        let (_, r) = parse_response(&msg).unwrap();
        assert_eq!(
            r.mapped,
            Some(
                "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
                    .parse()
                    .unwrap()
            )
        );
        assert_eq!(r.other, Some("203.0.113.9:3478".parse().unwrap()));
    }

    #[test]
    fn rejects_non_success() {
        let (_, req) = binding_request();
        assert!(parse_response(&req).is_none());
        assert_eq!(req.len(), 20);
    }

    #[tokio::test]
    async fn binds_against_local_server() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, from) = server.recv_from(&mut buf).await.unwrap();
                let txid: TxId = buf[8..20].try_into().unwrap();
                assert_eq!(n, 20);
                let port = from.port() ^ (MAGIC >> 16) as u16;
                let IpAddr::V4(ip) = from.ip() else {
                    unreachable!()
                };
                let mut v = vec![0, 1];
                v.extend_from_slice(&port.to_be_bytes());
                for (b, m) in ip.octets().iter().zip(MAGIC.to_be_bytes()) {
                    v.push(b ^ m);
                }
                server
                    .send_to(&response(&txid, &[(ATTR_XOR_MAPPED_ADDRESS, v)]), from)
                    .await
                    .unwrap();
            }
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let got = bind_all(&client, &[addr], Duration::from_secs(2)).await;
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1.mapped, Some(client.local_addr().unwrap()));
    }
}
