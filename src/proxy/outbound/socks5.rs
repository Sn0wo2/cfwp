use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_socks::{io::Compat, tcp::Socks5Stream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use worker::{Error, Result, Socket};

use super::ProxyCredential;

pub(super) async fn handshake(
    socket: &mut Socket,
    proxy: &ProxyCredential,
    target: IpAddr,
    port: u16,
) -> Result<()> {
    if !proxy.username.as_deref().is_some_and(str::is_empty)
        && !proxy.password.as_deref().is_some_and(str::is_empty)
    {
        if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
            Socks5Stream::connect_with_password_and_socket(
                Compat::new(socket.compat()),
                SocketAddr::new(target, port),
                username,
                password,
            )
            .await
        } else {
            Socks5Stream::connect_with_socket(
                Compat::new(socket.compat()),
                SocketAddr::new(target, port),
            )
            .await
        }
        .map_err(|error| Error::RustError(error.to_string()))?;
        return Ok(());
    }
    socket
        .write_all(if proxy.username.is_some() && proxy.password.is_some() {
            &[0x05, 0x02, 0x00, 0x02]
        } else {
            &[0x05, 0x01, 0x00]
        })
        .await?;

    let mut response = [0_u8; 2];
    socket.read_exact(&mut response).await?;
    if response[0] != 0x05 {
        return Err(Error::RustError("invalid tunnel version".into()));
    }
    if response[1] == 0x02 {
        if proxy.username.is_none() || proxy.password.is_none() {
            return Err(Error::RustError("unsupported credential mode".into()));
        }
        let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
        let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(Error::RustError("credential payload too long".into()));
        }
        let mut auth = Vec::with_capacity(3 + username.len() + password.len());
        auth.push(0x01);
        auth.push(username.len() as u8);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        socket.write_all(&auth).await?;
        socket.read_exact(&mut response).await?;
        if response != [0x01, 0x00] {
            return Err(Error::RustError("credential check failed".into()));
        }
    } else if response[1] != 0x00 {
        return Err(Error::RustError("unsupported credential mode".into()));
    }

    let mut connect_request = vec![0x05, 0x01, 0x00];
    match target {
        IpAddr::V4(ipv4) => {
            connect_request.push(0x01);
            connect_request.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            connect_request.push(0x04);
            connect_request.extend_from_slice(&ipv6.octets());
        }
    }
    connect_request.extend_from_slice(&port.to_be_bytes());
    socket.write_all(&connect_request).await?;

    let mut header = [0_u8; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 0x05 || header[2] != 0x00 {
        return Err(Error::RustError("invalid SOCKS5 reply".into()));
    }
    if header[1] != 0x00 {
        return Err(Error::RustError(format!(
            "route setup failed: {}",
            header[1]
        )));
    }
    let address_len = match header[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0_u8; 1];
            socket.read_exact(&mut len).await?;
            len[0] as usize
        }
        0x04 => 16,
        _ => return Err(Error::RustError("invalid bind address".into())),
    };
    socket.read_exact(&mut vec![0_u8; address_len + 2]).await?;
    Ok(())
}
