// Copyright (c) 2015, Yawning Angel <yawning at torproject dot org>
// Copyright (c) 2026 lyrebird-rs contributors
// SPDX-License-Identifier: BSD-2-Clause
//
// Port of lyrebird common/socks5.

//! The minimal SOCKS5 server tor talks to: CONNECT only, with per-connection
//! transport arguments carried in the RFC 1929 username/password.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

use crate::pt::Args;

const VERSION: u8 = 0x05;
const RSV: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xff;
const RFC1929_VER: u8 = 0x01;
const RFC1929_SUCCESS: u8 = 0x00;
const RFC1929_FAIL: u8 = 0x01;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReplyCode {
    Succeeded = 0,
    GeneralFailure = 1,
    ConnectionNotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressNotSupported = 8,
}

pub const VERSION_STRING: &str = "socks5";

/// Maps a dial error to a reply code the way upstream maps `syscall.Errno`s.
pub fn error_to_reply_code(e: &io::Error) -> ReplyCode {
    if e.raw_os_error().is_none() {
        return ReplyCode::GeneralFailure;
    }
    match e.kind() {
        io::ErrorKind::AddrNotAvailable => ReplyCode::AddressNotSupported,
        io::ErrorKind::TimedOut => ReplyCode::TtlExpired,
        io::ErrorKind::NetworkUnreachable => ReplyCode::NetworkUnreachable,
        io::ErrorKind::HostUnreachable => ReplyCode::HostUnreachable,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
            ReplyCode::ConnectionRefused
        }
        _ => ReplyCode::GeneralFailure,
    }
}

pub struct Request {
    pub target: String,
    pub args: Args,
    conn: TcpStream,
}

fn proto_err(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

struct Session {
    rd: BufReader<TcpStream>,
}

impl Session {
    async fn byte(&mut self) -> io::Result<u8> {
        self.rd.read_u8().await
    }

    async fn verify(&mut self, what: &str, expected: u8) -> io::Result<()> {
        let v = self.byte().await?;
        if v != expected {
            return Err(proto_err(format!(
                "message field '{what}' was 0x{v:02x} (expected 0x{expected:02x})"
            )));
        }
        Ok(())
    }

    async fn full(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.rd.read_exact(&mut buf).await?;
        Ok(buf)
    }

    /// Sends `data`; like upstream, it is an error for the client to have
    /// pipelined anything past the current message.
    async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.rd.get_mut().write_all(data).await?;
        self.check_no_trailing()
    }

    fn check_no_trailing(&self) -> io::Result<()> {
        let n = self.rd.buffer().len();
        if n > 0 {
            return Err(proto_err(format!(
                "read buffer has {n} bytes of trailing data"
            )));
        }
        Ok(())
    }

    async fn reply(&mut self, code: ReplyCode) -> io::Result<()> {
        self.send(&reply_bytes(code)).await
    }

    async fn negotiate_auth(&mut self) -> io::Result<u8> {
        self.verify("version", VERSION).await?;
        let n = self.byte().await?;
        let methods = self.full(n as usize).await?;
        let method = if methods.contains(&AUTH_USERPASS) {
            AUTH_USERPASS
        } else if methods.contains(&AUTH_NONE) {
            AUTH_NONE
        } else {
            AUTH_NO_ACCEPTABLE
        };
        self.send(&[VERSION, method]).await?;
        Ok(method)
    }

    async fn auth_rfc1929(&mut self) -> io::Result<Args> {
        match self.read_rfc1929().await {
            Ok(args) => {
                self.rd
                    .get_mut()
                    .write_all(&[RFC1929_VER, RFC1929_SUCCESS])
                    .await?;
                Ok(args)
            }
            Err(e) => {
                let _ = self.send(&[RFC1929_VER, RFC1929_FAIL]).await;
                Err(e)
            }
        }
    }

    async fn read_rfc1929(&mut self) -> io::Result<Args> {
        self.verify("auth version", RFC1929_VER).await?;
        let ulen = self.byte().await?;
        if ulen < 1 {
            return Err(proto_err("username with 0 length"));
        }
        let uname = self.full(ulen as usize).await?;
        let plen = self.byte().await?;
        if plen < 1 {
            return Err(proto_err("password with 0 length"));
        }
        let passwd = self.full(plen as usize).await?;
        // Args longer than 255 bytes spill into the password; a lone NUL
        // password means "no continuation".
        let mut arg_str = uname;
        if !(plen == 1 && passwd[0] == 0x00) {
            arg_str.extend_from_slice(&passwd);
        }
        parse_client_parameters(&arg_str).map_err(proto_err)
    }

    async fn read_command(&mut self) -> io::Result<String> {
        match self.read_command_inner().await {
            Ok(t) => {
                self.check_no_trailing()?;
                Ok(t)
            }
            Err((code, e)) => {
                let _ = self.reply(code).await;
                Err(e)
            }
        }
    }

    async fn read_command_inner(&mut self) -> Result<String, (ReplyCode, io::Error)> {
        let general = |e| (ReplyCode::GeneralFailure, e);
        self.verify("version", VERSION).await.map_err(general)?;
        self.verify("command", CMD_CONNECT)
            .await
            .map_err(|e| (ReplyCode::CommandNotSupported, e))?;
        self.verify("reserved", RSV).await.map_err(general)?;
        let atyp = self.byte().await.map_err(general)?;
        let host = match atyp {
            ATYP_IPV4 => {
                let b = self.full(4).await.map_err(general)?;
                Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string()
            }
            ATYP_DOMAIN => {
                let n = self.byte().await.map_err(general)?;
                if n == 0 {
                    return Err(general(proto_err("domain name with 0 length")));
                }
                let b = self.full(n as usize).await.map_err(general)?;
                String::from_utf8(b).map_err(|e| general(proto_err(e.to_string())))?
            }
            ATYP_IPV6 => {
                let b: [u8; 16] = self.full(16).await.map_err(general)?.try_into().unwrap();
                let ip = Ipv6Addr::from(b);
                // Go prints IPv4-mapped addresses in dotted form.
                match ip.to_ipv4_mapped() {
                    Some(v4) => format!("[{v4}]"),
                    None => format!("[{ip}]"),
                }
            }
            other => {
                return Err((
                    ReplyCode::AddressNotSupported,
                    proto_err(format!("unsupported address type 0x{other:02x}")),
                ))
            }
        };
        let port = self.full(2).await.map_err(general)?;
        Ok(format!("{host}:{}", u16::from_be_bytes([port[0], port[1]])))
    }
}

fn reply_bytes(code: ReplyCode) -> [u8; 10] {
    [VERSION, code as u8, RSV, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// Runs the server side of the SOCKS5 handshake (5 s deadline).
pub async fn handshake(conn: TcpStream) -> io::Result<Request> {
    let work = async move {
        let mut s = Session {
            rd: BufReader::with_capacity(4096, conn),
        };
        let method = s.negotiate_auth().await?;
        let args = match method {
            AUTH_NONE => Args::new(),
            AUTH_USERPASS => s.auth_rfc1929().await?,
            AUTH_NO_ACCEPTABLE => return Err(proto_err("no acceptable authentication methods")),
            m => {
                return Err(proto_err(format!(
                    "negotiated unsupported method 0x{m:02x}"
                )))
            }
        };
        s.check_no_trailing()?;
        let target = s.read_command().await?;
        Ok(Request {
            target,
            args,
            conn: s.rd.into_inner(),
        })
    };
    tokio::time::timeout(REQUEST_TIMEOUT, work)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))?
}

impl Request {
    pub async fn reply(&mut self, code: ReplyCode) -> io::Result<()> {
        self.conn.write_all(&reply_bytes(code)).await
    }

    pub fn into_stream(self) -> TcpStream {
        self.conn
    }
}

/// lyrebird's own SOCKS arg parser (stricter than goptlib's).
pub fn parse_client_parameters(arg_str: &[u8]) -> Result<Args, String> {
    let mut args = Args::new();
    if arg_str.is_empty() {
        return Ok(args);
    }
    let text = |b: &[u8]| String::from_utf8(b.to_vec()).map_err(|e| e.to_string());
    let mut key: Option<String> = None;
    let mut acc: Vec<u8> = Vec::new();
    let mut prev_is_escape = false;
    for (idx, &ch) in arg_str.iter().enumerate() {
        match ch {
            b'\\' => {
                prev_is_escape = !prev_is_escape;
                if prev_is_escape {
                    continue;
                }
            }
            b'=' if !prev_is_escape => {
                if key.is_none() {
                    if acc.is_empty() {
                        return Err(format!("unexpected '=' at {idx}"));
                    }
                    key = Some(text(&acc)?);
                    acc.clear();
                    continue;
                }
                // A second '=' belongs to the value.
            }
            b';' if !prev_is_escape => {
                let Some(k) = key.take().filter(|_| idx != arg_str.len() - 1) else {
                    return Err(format!("unexpected ';' at {idx}"));
                };
                args.add(&k, &text(&acc)?);
                acc.clear();
                continue;
            }
            b'=' | b';' => {}
            _ => {
                if prev_is_escape {
                    return Err(format!("unexpected '\\' at {}", idx - 1));
                }
            }
        }
        prev_is_escape = false;
        acc.push(ch);
    }
    if prev_is_escape {
        return Err("underminated escape character".into());
    }
    let Some(k) = key else {
        return Err("final key with no value".into());
    };
    args.add(&k, &text(&acc)?);
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn arg_parsing_matches_lyrebird() {
        let a = parse_client_parameters(b"cert=abc;iat-mode=0").unwrap();
        assert_eq!(a.get("cert"), Some("abc"));
        assert_eq!(a.get("iat-mode"), Some("0"));
        let a = parse_client_parameters(br"k=a\;b\\c=d").unwrap();
        assert_eq!(a.get("k"), Some(r"a;b\c=d"));
        assert!(parse_client_parameters(b"=v").is_err());
        assert!(parse_client_parameters(b"k=v;").is_err());
        assert!(parse_client_parameters(b";k=v").is_err());
        assert!(parse_client_parameters(b"novalue").is_err());
        assert!(parse_client_parameters(br"k=\x").is_err());
        assert!(parse_client_parameters(br"k=v\").is_err());
        let multi = parse_client_parameters(b"url=https://x/?a=b;fronts=a,b").unwrap();
        assert_eq!(multi.get("url"), Some("https://x/?a=b"));
        assert_eq!(multi.get("fronts"), Some("a,b"));
    }

    #[tokio::test]
    async fn full_handshake_with_args() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[5, 1, 2]).await.unwrap();
            let mut r = [0u8; 2];
            c.read_exact(&mut r).await.unwrap();
            assert_eq!(r, [5, 2]);
            let user = b"cert=AAAA;iat-mode=1";
            let mut auth = vec![1, user.len() as u8];
            auth.extend_from_slice(user);
            auth.extend_from_slice(&[1, 0]);
            c.write_all(&auth).await.unwrap();
            c.read_exact(&mut r).await.unwrap();
            assert_eq!(r, [1, 0]);
            c.write_all(&[5, 1, 0, 1, 192, 0, 2, 1, 0x01, 0xbb])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            c.read_exact(&mut rep).await.unwrap();
            rep
        });
        let (conn, _) = ln.accept().await.unwrap();
        let mut req = handshake(conn).await.unwrap();
        assert_eq!(req.target, "192.0.2.1:443");
        assert_eq!(req.args.get("cert"), Some("AAAA"));
        assert_eq!(req.args.get("iat-mode"), Some("1"));
        req.reply(ReplyCode::Succeeded).await.unwrap();
        assert_eq!(client.await.unwrap(), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn pipelined_greeting_is_rejected() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            // Greeting and CONNECT in one write: upstream refuses this.
            c.write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut buf = Vec::new();
            let _ = c.read_to_end(&mut buf).await;
        });
        let (conn, _) = ln.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = handshake(conn).await.err().expect("must fail");
        assert!(err.to_string().contains("trailing data"), "{err}");
        client.await.unwrap();
    }

    #[tokio::test]
    async fn bind_command_gets_not_supported() {
        let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = ln.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut c = TcpStream::connect(addr).await.unwrap();
            c.write_all(&[5, 1, 0]).await.unwrap();
            let mut r = [0u8; 2];
            c.read_exact(&mut r).await.unwrap();
            c.write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            c.read_exact(&mut rep).await.unwrap();
            rep[1]
        });
        let (conn, _) = ln.accept().await.unwrap();
        assert!(handshake(conn).await.is_err());
        assert_eq!(client.await.unwrap(), ReplyCode::CommandNotSupported as u8);
    }

    #[test]
    fn reply_codes() {
        let refused = io::Error::from_raw_os_error(libc_econnrefused());
        assert_eq!(error_to_reply_code(&refused), ReplyCode::ConnectionRefused);
        let custom = io::Error::new(io::ErrorKind::ConnectionRefused, "not an errno");
        assert_eq!(error_to_reply_code(&custom), ReplyCode::GeneralFailure);
    }

    fn libc_econnrefused() -> i32 {
        if cfg!(target_os = "linux") {
            111
        } else {
            61
        }
    }
}
