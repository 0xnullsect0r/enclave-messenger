//! Tor for the mixnet client (`docs/09-transport.md` §1): a SOCKS5 server
//! on a loopback port that dials only through Tor, so the Nym entry gateway
//! sees a Tor exit instead of the device's address.
//!
//! nym-sdk can't link arti into the same process (they need different
//! SQLite versions), so `enclave-tord` runs next to `enclave-nymd`, which
//! dials its gateway through it (our nym-gateway-client patch,
//! `third_party/PATCHES.md`). The port answers only a client that knows the
//! secret netd gave both of them (RFC 1929 user/password), and only
//! `CONNECT`: no `BIND`, no UDP.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod socks;

#[cfg(feature = "tor")]
pub mod obfs4pt;

#[cfg(feature = "launch")]
pub mod launch;

pub use socks::{Dialer, serve};

/// The SOCKS5 user name; the password is the per-run secret.
pub const USER: &str = "enclave";

/// Dials through Tor.
#[cfg(feature = "tor")]
pub struct ArtiDialer(pub std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>);

#[cfg(feature = "tor")]
mod arti {
    use super::ArtiDialer;
    use crate::socks::{Dialer, Stream};

    impl ArtiDialer {
        /// Bootstrap a Tor client keeping its state and cache under `dir`,
        /// through `bridges` (bridge lines; obfs4 only) if any are given:
        /// obfs4 runs in this process ([`crate::obfs4pt`]).
        pub async fn bootstrap(dir: &std::path::Path, bridges: &[String]) -> std::io::Result<Self> {
            let mut b = arti_client::config::TorClientConfigBuilder::from_directories(
                dir.join("state"),
                dir.join("cache"),
            );
            if !bridges.is_empty() {
                let pt = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let addr = pt.local_addr()?;
                tokio::spawn(crate::obfs4pt::serve(pt));
                for line in bridges {
                    if !line.starts_with("obfs4 ") {
                        return Err(std::io::Error::other(format!(
                            "only obfs4 bridges are supported: {line}"
                        )));
                    }
                    let bridge: arti_client::config::BridgeConfigBuilder =
                        line.parse().map_err(std::io::Error::other)?;
                    b.bridges().bridges().push(bridge);
                }
                let mut t = arti_client::config::pt::TransportConfigBuilder::default();
                t.protocols(vec!["obfs4".parse().map_err(std::io::Error::other)?])
                    .proxy_addr(addr);
                b.bridges().transports().push(t);
            }
            let cfg = b.build().map_err(std::io::Error::other)?;
            let client = arti_client::TorClient::create_bootstrapped(cfg)
                .await
                .map_err(std::io::Error::other)?;
            Ok(Self(client))
        }
    }

    #[async_trait::async_trait]
    impl Dialer for ArtiDialer {
        async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn Stream>> {
            let s = self
                .0
                .connect((host, port))
                .await
                .map_err(std::io::Error::other)?;
            Ok(Box::new(s))
        }
    }
}

/// Dials directly: tests and the local mixnet only (`dev-direct`).
#[cfg(any(test, feature = "dev-direct"))]
pub struct DirectDialer;

#[cfg(any(test, feature = "dev-direct"))]
#[async_trait::async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn socks::Stream>> {
        Ok(Box::new(
            tokio::net::TcpStream::connect((host, port)).await?,
        ))
    }
}
