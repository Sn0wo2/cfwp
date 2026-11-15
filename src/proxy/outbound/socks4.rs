use std::net::{IpAddr, SocketAddr};

use tokio_socks::{io::Compat, tcp::Socks4Stream};
use tokio_util::compat::TokioAsyncReadCompatExt;
use worker::{Error, Result, Socket};

use super::ProxyCredential;

pub(super) async fn handshake(
    socket: &mut Socket,
    proxy: &ProxyCredential,
    target: IpAddr,
    port: u16,
) -> Result<()> {
    let IpAddr::V4(ipv4) = target else {
        return Err(Error::RustError("SOCKS4 requires an IPv4 target".into()));
    };
    if let Some(username) = proxy.username.as_deref().filter(|value| !value.is_empty()) {
        Socks4Stream::connect_with_userid_and_socket(
            Compat::new(socket.compat()),
            SocketAddr::from((ipv4, port)),
            username,
        )
        .await
    } else {
        Socks4Stream::connect_with_socket(
            Compat::new(socket.compat()),
            SocketAddr::from((ipv4, port)),
        )
        .await
    }
    .map_err(|error| Error::RustError(error.to_string()))?;

    Ok(())
}
