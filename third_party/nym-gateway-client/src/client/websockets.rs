#[cfg(not(target_arch = "wasm32"))]
use crate::client::GatewayListeners;
use crate::error::GatewayClientError;

use nym_http_api_client::HickoryDnsResolver;
#[cfg(unix)]
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::Response;
use url::{Host, Url};

use std::net::SocketAddr;

// ENCLAVE PATCH (third_party/PATCHES.md): the gateway connection can be
// dialled by the caller (through Tor, `docs/09-transport.md` §1) instead of
// by a local DNS lookup and TCP connect. Process-wide: an Enclave process
// runs one mixnet client.

/// Opens a stream to a gateway's host and port by the caller's own means.
pub type StreamConnector = std::sync::Arc<
    dyn Fn(
            String,
            u16,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = std::io::Result<TcpStream>> + Send>,
        > + Send
        + Sync,
>;

static STREAM_CONNECTOR: std::sync::RwLock<Option<StreamConnector>> =
    std::sync::RwLock::new(None);

/// Dial every gateway connection with `connector` from now on (`None`:
/// the usual DNS lookup and TCP connect).
pub fn set_stream_connector(connector: Option<StreamConnector>) {
    if let Ok(mut c) = STREAM_CONNECTOR.write() {
        *c = connector;
    }
}

fn stream_connector() -> Option<StreamConnector> {
    STREAM_CONNECTOR.read().ok().and_then(|c| c.clone())
}

/// The WebSocket over a stream the caller's connector opened: no local DNS
/// lookup, and TLS (for `wss://`) still checks the gateway's hostname.
async fn connect_async_via_connector(
    connector: StreamConnector,
    endpoint: &str,
    #[cfg(unix)] connection_fd_callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    let uri =
        Url::parse(endpoint).map_err(|_| GatewayClientError::InvalidUrl(endpoint.to_owned()))?;
    let port: u16 = uri.port_or_known_default().unwrap_or(443);
    let host = uri
        .host_str()
        .ok_or(GatewayClientError::InvalidUrl(endpoint.to_owned()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let stream = connector(host, port).await.map_err(|err| {
        GatewayClientError::NetworkConnectionFailed {
            address: endpoint.to_owned(),
            source: Box::new(tungstenite::Error::from(err)),
        }
    })?;
    #[cfg(unix)]
    if let Some(callback) = connection_fd_callback.as_ref() {
        callback.as_ref()(stream.as_raw_fd());
    }
    tokio_tungstenite::client_async_tls(endpoint, stream)
        .await
        .map_err(|error| GatewayClientError::NetworkConnectionFailed {
            address: endpoint.to_owned(),
            source: Box::new(error),
        })
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn connect_async_with_hickory(
    endpoint: &str,
    #[cfg(unix)] connection_fd_callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    use tokio::net::TcpSocket;

    let resolver = HickoryDnsResolver::default();
    let uri =
        Url::parse(endpoint).map_err(|_| GatewayClientError::InvalidUrl(endpoint.to_owned()))?;
    let port: u16 = uri.port_or_known_default().unwrap_or(443);

    let host = uri
        .host()
        .ok_or(GatewayClientError::InvalidUrl(endpoint.to_owned()))?;

    // Get address for tcp connection, if a domain is provided use our preferred resolver rather than
    // the default std resolve
    let sock_addrs: Vec<SocketAddr> = match host {
        Host::Ipv4(addr) => vec![SocketAddr::new(addr.into(), port)],
        Host::Ipv6(addr) => vec![SocketAddr::new(addr.into(), port)],
        Host::Domain(domain) => {
            // Do a DNS lookup for the domain using our custom DNS resolver
            resolver
                .resolve_str(domain)
                .await?
                .map(|a| SocketAddr::new(a, port))
                .collect()
        }
    };

    let mut stream = Err(GatewayClientError::NoEndpointForConnection {
        address: endpoint.to_owned(),
    });
    for sock_addr in sock_addrs {
        let socket = if sock_addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|err| GatewayClientError::NetworkConnectionFailed {
            address: endpoint.to_owned(),
            source: Box::new(tungstenite::Error::from(err)),
        })?;

        #[cfg(unix)]
        if let Some(callback) = connection_fd_callback.as_ref() {
            callback.as_ref()(socket.as_raw_fd());
        }

        match socket.connect(sock_addr).await {
            Ok(s) => {
                stream = Ok(s);
                break;
            }
            Err(err) => {
                stream = Err(GatewayClientError::NetworkConnectionFailed {
                    address: endpoint.to_owned(),
                    source: Box::new(tungstenite::Error::from(err)),
                });
                continue;
            }
        }
    }

    tokio_tungstenite::client_async_tls(endpoint, stream?)
        .await
        .map_err(|error| GatewayClientError::NetworkConnectionFailed {
            address: endpoint.to_owned(),
            source: Box::new(error),
        })
}

async fn connect_async_inner(
    endpoint: &str,
    use_hickory_dns_resolver: bool,
    #[cfg(unix)] connection_fd_callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    // ENCLAVE PATCH: the caller's connector, when set, dials every gateway.
    if let Some(connector) = stream_connector() {
        return connect_async_via_connector(
            connector,
            endpoint,
            #[cfg(unix)]
            connection_fd_callback,
        )
        .await;
    }
    if use_hickory_dns_resolver {
        connect_async_with_hickory(
            endpoint,
            #[cfg(unix)]
            connection_fd_callback.clone(),
        )
        .await
    } else {
        let (stream, response) = tokio_tungstenite::connect_async(endpoint).await?;
        #[cfg(unix)]
        if let (Some(callback), Some(fd)) = (
            connection_fd_callback.as_ref(),
            crate::socket_state::ws_fd(&stream),
        ) {
            callback.as_ref()(fd);
        }

        Ok((stream, response))
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn connect_async_with_fallback(
    endpoints: &GatewayListeners,
    use_hickory_dns_resolver: bool,
    #[cfg(unix)] connection_fd_callback: Option<Arc<dyn Fn(RawFd) + Send + Sync>>,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, Response), GatewayClientError> {
    match connect_async_inner(
        endpoints.primary.as_ref(),
        use_hickory_dns_resolver,
        #[cfg(unix)]
        connection_fd_callback.clone(),
    )
    .await
    {
        Ok(inner) => Ok(inner),
        Err(e) => {
            if let Some(fallback) = &endpoints.fallback {
                tracing::warn!(
                    "Main endpoint failed {} : {e}, trying fallback : {fallback}",
                    endpoints.primary
                );
                connect_async_inner(
                    fallback.as_ref(),
                    use_hickory_dns_resolver,
                    #[cfg(unix)]
                    connection_fd_callback,
                )
                .await
            } else {
                Err(e)
            }
        }
    }
}
