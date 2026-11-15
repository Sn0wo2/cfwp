use std::net::{IpAddr, SocketAddr};

use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::{Error, Result, Socket};

use super::ProxyCredential;

pub(super) async fn handshake(
    socket: &mut Socket,
    proxy: &ProxyCredential,
    target: IpAddr,
    port: u16,
) -> Result<()> {
    let authority = SocketAddr::new(target, port);
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: cfwp\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
        ));
    }
    request.push_str("\r\n");
    socket.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() < 8192 {
        let read = socket.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    if !matches!(parsed.parse(&response), Ok(httparse::Status::Complete(_)))
        || !parsed.code.is_some_and(|code| (200..300).contains(&code))
    {
        return Err(Error::RustError("invalid HTTP proxy handshake".into()));
    }
    Ok(())
}
