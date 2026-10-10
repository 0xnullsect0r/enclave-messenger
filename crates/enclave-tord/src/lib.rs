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

pub mod managed;

#[cfg(feature = "launch")]
pub mod launch;

pub use socks::{Dialer, serve};

/// The SOCKS5 user name; the password is the per-run secret.
pub const USER: &str = "enclave";

/// Install the TLS provider arti's connections to the Tor network use (it
/// takes rustls's process-wide one, and a build may enable none or two).
#[cfg(feature = "tor")]
pub fn install_tls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Dials through Tor.
#[cfg(feature = "tor")]
pub struct ArtiDialer(pub std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>);

#[cfg(feature = "tor")]
mod arti {
    use super::ArtiDialer;
    use crate::socks::{Dialer, Stream};

    impl ArtiDialer {
        /// Bootstrap a Tor client keeping its state and cache under `dir`,
        /// through `bridges` (bridge lines) if any are given: obfs4 runs in
        /// this process ([`crate::obfs4pt`]), Snowflake and WebTunnel
        /// through the SOCKS5 ports in `managed` ([`crate::managed`]).
        pub async fn bootstrap(
            dir: &std::path::Path,
            bridges: &[String],
            managed: &[(String, std::net::SocketAddr)],
        ) -> std::io::Result<Self> {
            use arti_client::config::pt::TransportConfigBuilder;
            let mut b = arti_client::config::TorClientConfigBuilder::from_directories(
                dir.join("state"),
                dir.join("cache"),
            );
            let mut obfs4 = false;
            for line in bridges {
                let kind = line.split_whitespace().next().unwrap_or_default();
                match kind {
                    "obfs4" => obfs4 = true,
                    k if managed.iter().any(|(n, _)| n == k) => {}
                    _ => {
                        return Err(std::io::Error::other(format!(
                            "no transport for this bridge: {line}"
                        )));
                    }
                }
                let bridge: arti_client::config::BridgeConfigBuilder =
                    line.parse().map_err(std::io::Error::other)?;
                b.bridges().bridges().push(bridge);
            }
            let name = |n: &str| n.parse().map_err(std::io::Error::other);
            if obfs4 {
                let pt = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let addr = pt.local_addr()?;
                tokio::spawn(crate::obfs4pt::serve(pt));
                let mut t = TransportConfigBuilder::default();
                t.protocols(vec![name("obfs4")?]).proxy_addr(addr);
                b.bridges().transports().push(t);
            }
            for (n, addr) in managed {
                let mut t = TransportConfigBuilder::default();
                t.protocols(vec![name(n)?]).proxy_addr(*addr);
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

/// In a `dev-direct` build this string is in the binary; release builds
/// must not contain it (CI checks with `strings`).
#[cfg(feature = "dev-direct")]
pub const DEV_DIRECT_MARKER: &str = "ENCLAVE-DEV-DIRECT-ENABLED";

/// Dials directly: tests and the local mixnet only (`dev-direct`).
#[cfg(any(test, feature = "dev-direct"))]
pub struct DirectDialer;

#[cfg(any(test, feature = "dev-direct"))]
#[async_trait::async_trait]
impl Dialer for DirectDialer {
    async fn dial(&self, host: &str, port: u16) -> std::io::Result<Box<dyn socks::Stream>> {
        #[cfg(feature = "dev-direct")]
        std::hint::black_box(DEV_DIRECT_MARKER);
        Ok(Box::new(
            tokio::net::TcpStream::connect((host, port)).await?,
        ))
    }
}
