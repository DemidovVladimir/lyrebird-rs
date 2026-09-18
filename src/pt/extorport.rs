// Port of goptlib's Extended ORPort client (CC0).

//! Connects a server-side transport to tor's (Extended) ORPort.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::ServerInfo;
use crate::common::csrand;

const CMD_DONE: u16 = 0x0000;
const CMD_USERADDR: u16 = 0x0001;
const CMD_TRANSPORT: u16 = 0x0002;
const CMD_OKAY: u16 = 0x1000;
const CMD_DENY: u16 = 0x1001;
const AUTH_COOKIE_HEADER: &[u8; 32] = b"! Extended ORPort Auth Cookie !\x0a";

fn other(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

pub fn read_auth_cookie(data: &[u8]) -> io::Result<[u8; 32]> {
    if data.len() < 64 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    if data.len() > 64 {
        return Err(other("file is longer than 64 bytes"));
    }
    if !bool::from(data[..32].ct_eq(AUTH_COOKIE_HEADER)) {
        return Err(other("missing auth cookie header"));
    }
    Ok(data[32..].try_into().unwrap())
}

fn ext_hash(cookie: &[u8], label: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(cookie).expect("any key length");
    mac.update(label);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().into()
}

async fn authenticate(s: &mut TcpStream, cookie_path: &str) -> io::Result<()> {
    let mut offered = [false; 256];
    let mut count = 0;
    loop {
        if count >= 256 {
            return Err(other("read 256 auth types without seeing \\x00"));
        }
        let b = s.read_u8().await?;
        if b == 0 {
            break;
        }
        offered[b as usize] = true;
        count += 1;
    }
    if !offered[1] {
        return Err(other("server didn't offer auth type 1"));
    }
    s.write_all(&[1]).await?;

    let mut client_nonce = [0u8; 32];
    csrand::bytes(&mut client_nonce);
    s.write_all(&client_nonce).await?;
    let mut server_hash = [0u8; 32];
    let mut server_nonce = [0u8; 32];
    s.read_exact(&mut server_hash).await?;
    s.read_exact(&mut server_nonce).await?;

    let data = std::fs::read(cookie_path).map_err(|e| {
        other(format!(
            "error reading TOR_PT_AUTH_COOKIE_FILE {cookie_path:?}: {e}"
        ))
    })?;
    let cookie = read_auth_cookie(&data).map_err(|e| {
        other(format!(
            "error reading TOR_PT_AUTH_COOKIE_FILE {cookie_path:?}: {e}"
        ))
    })?;
    let expected = ext_hash(
        &cookie,
        b"ExtORPort authentication server-to-client hash",
        &client_nonce,
        &server_nonce,
    );
    if !bool::from(expected.ct_eq(&server_hash)) {
        return Err(other("mismatch in server hash"));
    }
    let client_hash = ext_hash(
        &cookie,
        b"ExtORPort authentication client-to-server hash",
        &client_nonce,
        &server_nonce,
    );
    s.write_all(&client_hash).await?;
    if s.read_u8().await? != 1 {
        return Err(other("server rejected authentication"));
    }
    Ok(())
}

async fn send_command(s: &mut TcpStream, cmd: u16, body: &[u8]) -> io::Result<()> {
    if body.len() > 65535 {
        return Err(other(format!(
            "body length {} exceeds maximum of 65535",
            body.len()
        )));
    }
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.extend_from_slice(&cmd.to_be_bytes());
    msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
    msg.extend_from_slice(body);
    s.write_all(&msg).await
}

async fn set_metadata(s: &mut TcpStream, addr: &str, method: &str) -> io::Result<()> {
    if !addr.is_empty() {
        send_command(s, CMD_USERADDR, addr.as_bytes()).await?;
    }
    if !method.is_empty() {
        send_command(s, CMD_TRANSPORT, method.as_bytes()).await?;
    }
    send_command(s, CMD_DONE, &[]).await?;
    let cmd = s.read_u16().await?;
    let len = s.read_u16().await?;
    let mut body = vec![0u8; len as usize];
    s.read_exact(&mut body).await?;
    match cmd {
        CMD_OKAY => Ok(()),
        CMD_DENY => Err(other("server returned DENY after our USERADDR and DONE")),
        c => Err(other(format!(
            "server returned unknown command 0x{c:04x} after our USERADDR and DONE"
        ))),
    }
}

/// Dials the ORPort (plain) or Extended ORPort (with auth and metadata).
/// `peer` is the client address reported via USERADDR.
pub async fn dial_or(info: &ServerInfo, peer: &SocketAddr, method: &str) -> io::Result<TcpStream> {
    let ext = match info.extended_or_addr {
        Some(a) if !info.auth_cookie_path.is_empty() => a,
        _ => {
            let or = info.or_addr.ok_or_else(|| other("no ORPort configured"))?;
            return TcpStream::connect(or).await;
        }
    };
    let mut s = TcpStream::connect(ext).await?;
    let setup = async {
        authenticate(&mut s, &info.auth_cookie_path).await?;
        set_metadata(&mut s, &peer.to_string(), method).await
    };
    tokio::time::timeout(Duration::from_secs(5), setup)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_parsing() {
        let mut data = AUTH_COOKIE_HEADER.to_vec();
        data.extend_from_slice(&[5u8; 32]);
        assert_eq!(read_auth_cookie(&data).unwrap(), [5u8; 32]);
        data.push(0);
        assert!(read_auth_cookie(&data).is_err());
        let mut bad = vec![0u8; 64];
        bad[32] = 1;
        assert!(read_auth_cookie(&bad).is_err());
        assert!(read_auth_cookie(&[0u8; 10]).is_err());
    }

    #[tokio::test]
    async fn authenticates_against_fake_tor() {
        let dir = std::env::temp_dir().join(format!("lyrebird-extor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cookie_path = dir.join("cookie");
        let cookie = [0x42u8; 32];
        let mut file = AUTH_COOKIE_HEADER.to_vec();
        file.extend_from_slice(&cookie);
        std::fs::write(&cookie_path, &file).unwrap();

        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ext = ln.local_addr().unwrap();
        let tor = tokio::spawn(async move {
            let (mut s, _) = ln.accept().await.unwrap();
            s.write_all(&[3, 1, 0]).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), 1);
            let mut cn = [0u8; 32];
            s.read_exact(&mut cn).await.unwrap();
            let sn = [9u8; 32];
            let sh = ext_hash(
                &cookie,
                b"ExtORPort authentication server-to-client hash",
                &cn,
                &sn,
            );
            s.write_all(&sh).await.unwrap();
            s.write_all(&sn).await.unwrap();
            let mut ch = [0u8; 32];
            s.read_exact(&mut ch).await.unwrap();
            let want = ext_hash(
                &cookie,
                b"ExtORPort authentication client-to-server hash",
                &cn,
                &sn,
            );
            assert_eq!(ch, want);
            s.write_all(&[1]).await.unwrap();
            let mut cmds = Vec::new();
            loop {
                let cmd = s.read_u16().await.unwrap();
                let len = s.read_u16().await.unwrap();
                let mut body = vec![0u8; len as usize];
                s.read_exact(&mut body).await.unwrap();
                cmds.push((cmd, String::from_utf8(body).unwrap()));
                if cmd == CMD_DONE {
                    break;
                }
            }
            s.write_all(&[0x10, 0x00, 0, 0]).await.unwrap();
            cmds
        });

        let info = ServerInfo {
            bindaddrs: vec![],
            or_addr: None,
            extended_or_addr: Some(ext),
            auth_cookie_path: cookie_path.to_string_lossy().into_owned(),
        };
        let peer: SocketAddr = "203.0.113.7:4444".parse().unwrap();
        dial_or(&info, &peer, "obfs4").await.unwrap();
        let cmds = tor.await.unwrap();
        assert_eq!(
            cmds,
            vec![
                (CMD_USERADDR, "203.0.113.7:4444".to_string()),
                (CMD_TRANSPORT, "obfs4".to_string()),
                (CMD_DONE, String::new()),
            ]
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
