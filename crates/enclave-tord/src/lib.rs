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
        /// Bootstrap a Tor client keeping its state and cache under `dir`.
        pub async fn bootstrap(dir: &std::path::Path) -> std::io::Result<Self> {
            let cfg = arti_client::config::TorClientConfigBuilder::from_directories(
                dir.join("state"),
                dir.join("cache"),
            )
            .build()
            .map_err(std::io::Error::other)?;
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
