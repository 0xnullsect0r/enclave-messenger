//! The nym-sdk mixnet driver (`enclave_nym::MixnetDriver`,
//! `docs/09-transport.md` §1).
//!
//! Configuration, per [`Role`]:
//! - **Ingress** (a server's Nym client): a persistent identity (its
//!   address is in the server's descriptor) kept in a directory. It never
//!   asks a sender for more reply blocks: every request brings what its
//!   reply needs.
//! - **Client** (a device): an ephemeral identity. Nym's own Poisson stream
//!   of real packets is off, because Enclave's scheduler already sends at a
//!   fixed rate (`enclave_net::shaped`); loop cover runs every 10 seconds
//!   (`docs/completion-plan.md` N1).
//!
//! Every message gets a fresh sender tag (our patch to nym-client-core,
//! `third_party/PATCHES.md`) and, when it expects an answer, enough single-use
//! reply blocks for all of it ([`surbs_for`]). Another patch counts what is
//! still in flight, so [`MixnetDriver::flush`] can wait for it before the
//! process exits.

pub mod credentials;

use enclave_nym::{Incoming, MixnetDriver, NymError, Pacing, ReplyTag, Result};
use nym_sdk::mixnet::{
    AnonymousSenderTag, IncludedSurbs, MixnetClientBuilder, MixnetClientSender,
    MixnetMessageSender, Recipient, StoragePaths,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

/// Reply blocks for an answer of `len` bytes, with one to spare: the
/// regular packets nym-sphinx splits such a reply into (each reply packet
/// carries a 2 KiB Sphinx payload less its acknowledgement, key digest and
/// fragment header). Too few would make the ingress ask the device for
/// more, which it can't answer (every message has a fresh sender tag).
pub fn surbs_for(len: usize) -> u32 {
    use nym_sphinx::anonymous_replies::requests::ReplyMessage;
    use nym_sphinx::message::NymMessage;
    use nym_sphinx::params::PacketSize;
    let m = NymMessage::new_reply(ReplyMessage::new_data_message(vec![0; len]));
    u32::try_from(m.required_packets(PacketSize::RegularPacket) + 1).unwrap_or(u32::MAX)
}

/// Sphinx packets a poll takes going up, with the reply blocks for its
/// answer (measured by `examples/localnet_roundtrip.rs`).
pub const POLL_PACKETS: u32 = 5;
/// Sphinx packets a unit sent one way takes (measured likewise).
pub const UNIT_PACKETS: u32 = 11;

/// Packet slots per tick beyond the unit and the poll: room for self-loop
/// probes (0.1 a tick on average), retransmissions, reply-block top-ups
/// and timer drift, so the paced queue empties every tick, and a backlog
/// (after a bulk burst, say) drains in a few ticks instead of standing.
/// Measured on the local mixnet (`examples/localnet_ticks.rs`): one spare
/// slot left a standing queue of 40 packets.
pub const SPARE_PACKETS: u32 = 4;

/// The gap between real packets for `pacing`: a tick's unit and poll leave
/// evenly across the tick (with [`SPARE_PACKETS`] slots to spare), and a
/// bulk transfer at the bulk cap.
pub fn packet_gap(pacing: &Pacing) -> Duration {
    if pacing.bulk {
        Duration::from_secs(1) / Pacing::BULK_PACKETS_PER_SEC
    } else {
        pacing.tick / (UNIT_PACKETS + POLL_PACKETS + SPARE_PACKETS)
    }
}

/// Dial every gateway connection through the SOCKS5 proxy at `proxy`
/// (`enclave-tord`: Tor) with `secret`, so the entry gateway never sees this
/// device's address (`docs/09-transport.md` §1). Process-wide; call before
/// connecting.
pub fn dial_gateways_through(proxy: std::net::SocketAddr, secret: String) {
    let secret = std::sync::Arc::new(secret);
    let connector: nym_gateway_client::client::StreamConnector =
        std::sync::Arc::new(move |host: String, port: u16| {
            let secret = std::sync::Arc::clone(&secret);
            Box::pin(async move { enclave_tord::socks::connect(proxy, &secret, &host, port).await })
        });
    nym_gateway_client::client::set_stream_connector(Some(connector));
}

/// Which side of Enclave this client is.
#[derive(Clone, Debug)]
pub enum Role {
    /// A stack's ingress, keeping its identity in `dir`.
    Ingress {
        /// Where nym-sdk keeps keys and gateway registration.
        dir: PathBuf,
    },
    /// A device.
    Client,
}

/// Connection options.
#[derive(Clone, Debug)]
pub struct Options {
    /// Ingress or client.
    pub role: Role,
    /// Ask for this gateway (identity key), or let nym-sdk choose.
    pub gateway: Option<String>,
    /// Which mixnet ([`Network::from_env`] for `--env`).
    pub network: Network,
    /// zk-nym ticketbooks to spend, [`enclave_nym::Held`] encoded (a
    /// device's, from [`credentials::buy`]). With any, a device's client
    /// runs in credentials mode on Nym's networks, importing what is left of
    /// each in order; a local mixnet doesn't check.
    pub tickets: Vec<Vec<u8>>,
}

/// Which mixnet to join.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// Nym's mainnet.
    Mainnet,
    /// Network details from `NYM_*` variables (the sandbox), as nym-sdk
    /// reads them.
    Env,
    /// A local mixnet (`ci/nym-localnet`): its fixed topology from a file
    /// and the one nym-api call a client makes (key-rotation information)
    /// answered at `nym_api`.
    Local {
        /// `NymTopology` JSON.
        topology: PathBuf,
        /// Base URL of the nym-api stand-in.
        nym_api: String,
    },
}

impl Network {
    /// For `--env`: a local mixnet if `ENCLAVE_NYM_TOPOLOGY` names a
    /// topology file (with `ENCLAVE_NYM_API`, default
    /// `http://nym-api:8000/`), else the `NYM_*` variables. Without
    /// `--env`, mainnet.
    pub fn from_env(env: bool) -> Self {
        if !env {
            return Network::Mainnet;
        }
        match std::env::var_os("ENCLAVE_NYM_TOPOLOGY") {
            Some(t) => Network::Local {
                topology: t.into(),
                nym_api: std::env::var("ENCLAVE_NYM_API")
                    .unwrap_or_else(|_| "http://nym-api:8000/".into()),
            },
            None => Network::Env,
        }
    }
}

fn client_error(e: impl std::fmt::Display) -> NymError {
    NymError::Client(e.to_string())
}

/// A connected nym-sdk client.
pub struct NymDriver {
    opts: Options,
    /// The client sending now: its sender and address.
    current: std::sync::RwLock<(MixnetClientSender, String)>,
    tx: mpsc::UnboundedSender<Incoming>,
    rx: Mutex<mpsc::UnboundedReceiver<Incoming>>,
    /// Readers of every client still alive (the current one, and one
    /// replaced by a gateway switch until its replies have had time).
    readers: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    switching: Mutex<()>,
    /// Ticketbooks bought while connected: spent from the next client
    /// (a gateway switch).
    bought: std::sync::Mutex<Vec<Vec<u8>>>,
    /// HTTP through Tor, made when first needed.
    fetcher: std::sync::OnceLock<credentials::Fetcher>,
}

/// How long a client replaced by a gateway switch keeps receiving.
const RETIRE_AFTER: Duration = Duration::from_secs(90);

fn gateway_of(address: &str) -> Option<&str> {
    address.split_once('@').map(|(_, g)| g)
}

/// Build and connect a nym-sdk client for `opts`.
async fn build(opts: &Options) -> Result<nym_sdk::mixnet::MixnetClient> {
    let mut debug = nym_sdk::DebugConfig::default();
    debug.traffic.disable_main_poisson_packet_distribution = true;
    debug.stats_reporting.enabled = false;
    if matches!(opts.role, Role::Client) {
        debug.cover_traffic.loop_cover_traffic_average_delay = Duration::from_secs(10);
    }
    if matches!(opts.role, Role::Ingress { .. }) {
        // Every request carries all the reply blocks its reply needs, so
        // the ingress never asks for more and keeps none in reserve for
        // asking (nym-sdk holds back 10 by default, which would leave a
        // reply short).
        debug.reply_surbs.maximum_reply_surbs_rerequests = 0;
        debug.reply_surbs.minimum_reply_surb_storage_threshold = 0;
        debug.reply_surbs.minimum_reply_surb_threshold_buffer = 0;
    }
    let (network, topology) = match &opts.network {
        Network::Mainnet => (nym_sdk::NymNetworkDetails::default(), None),
        Network::Env => (nym_sdk::NymNetworkDetails::new_from_env(), None),
        Network::Local { topology, nym_api } => {
            let api = url::Url::parse(nym_api).map_err(client_error)?;
            let provider =
                nym_topology::provider_trait::HardcodedTopologyProvider::new_from_file(topology)
                    .map_err(|e| client_error(format!("{}: {e}", topology.display())))?;
            (
                nym_sdk::NymNetworkDetails::new_mainnet().with_nym_api_urls(vec![api]),
                Some(provider),
            )
        }
    };
    match &opts.role {
        Role::Ingress { dir } => {
            let paths = StoragePaths::new_from_dir(dir).map_err(client_error)?;
            // The reply-block store takes its thresholds when it is
            // made, so from our configuration, not the defaults.
            let storage = paths
                .initialise_persistent_storage(&debug)
                .await
                .map_err(client_error)?;
            let mut b = MixnetClientBuilder::new_with_storage(storage)
                .network_details(network)
                .debug_config(debug);
            if let Some(g) = &opts.gateway {
                b = b.request_gateway(g.clone());
            }
            if let Some(p) = topology {
                b = b.custom_topology_provider(Box::new(p));
            }
            b.build()
                .map_err(client_error)?
                .connect_to_mixnet()
                .await
                .map_err(client_error)
        }
        Role::Client => {
            let paid = !opts.tickets.is_empty() && !matches!(opts.network, Network::Local { .. });
            let mut b = MixnetClientBuilder::new_ephemeral()
                .network_details(network)
                .debug_config(debug)
                .credentials_mode(paid);
            if let Some(g) = &opts.gateway {
                b = b.request_gateway(g.clone());
            }
            if let Some(p) = topology {
                b = b.custom_topology_provider(Box::new(p));
            }
            let client = b.build().map_err(client_error)?;
            if paid {
                for t in &opts.tickets {
                    credentials::import(&client, &enclave_nym::Held::decode(t)?).await?;
                }
            }
            client.connect_to_mixnet().await.map_err(client_error)
        }
    }
}

/// Start forwarding what `client` receives to `tx`; its sender and
/// address.
fn attach(
    mut client: nym_sdk::mixnet::MixnetClient,
    tx: mpsc::UnboundedSender<Incoming>,
) -> (MixnetClientSender, String, tokio::task::JoinHandle<()>) {
    let address = client.nym_address().to_string();
    let sender = client.split_sender();
    let reader = tokio::spawn(async move {
        while let Some(msgs) = client.wait_for_messages().await {
            for m in msgs {
                let incoming = Incoming {
                    data: m.message,
                    reply: m.sender_tag.map(|t| ReplyTag(t.to_bytes())),
                };
                if tx.send(incoming).is_err() {
                    return;
                }
            }
        }
    });
    (sender, address, reader)
}

impl NymDriver {
    /// Connect to the mixnet.
    pub async fn connect(opts: Options) -> Result<Self> {
        let client = build(&opts).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        let (sender, address, reader) = attach(client, tx.clone());
        Ok(Self {
            opts,
            current: std::sync::RwLock::new((sender, address)),
            tx,
            rx: Mutex::new(rx),
            readers: std::sync::Mutex::new(vec![reader]),
            switching: Mutex::new(()),
            bought: std::sync::Mutex::new(Vec::new()),
            fetcher: std::sync::OnceLock::new(),
        })
    }

    fn fetcher(&self) -> Result<&credentials::Fetcher> {
        if let Some(f) = self.fetcher.get() {
            return Ok(f);
        }
        let f = credentials::Fetcher::new()?;
        Ok(self.fetcher.get_or_init(|| f))
    }

    fn sender(&self) -> Result<MixnetClientSender> {
        self.current
            .read()
            .map(|c| c.0.clone())
            .map_err(|_| NymError::Closed)
    }
}

impl Drop for NymDriver {
    fn drop(&mut self) {
        if let Ok(readers) = self.readers.lock() {
            for r in readers.iter() {
                r.abort();
            }
        }
    }
}

#[async_trait::async_trait]
impl MixnetDriver for NymDriver {
    fn address(&self) -> String {
        self.current.read().map(|c| c.1.clone()).unwrap_or_default()
    }

    async fn send(&self, to: &str, data: Vec<u8>, reply_len: usize) -> Result<()> {
        let recipient =
            Recipient::try_from_base58_string(to).map_err(|_| NymError::UnknownRecipient)?;
        let surbs = if reply_len == 0 {
            IncludedSurbs::none()
        } else {
            IncludedSurbs::new(surbs_for(reply_len))
        };
        let sender = self.sender()?;
        nym_client_core::enclave::note_submitted();
        sender
            .send_message(recipient, data, surbs)
            .await
            .inspect_err(|_| nym_client_core::enclave::note_unsubmitted())
            .map_err(client_error)
    }

    async fn reply(&self, tag: ReplyTag, data: Vec<u8>) -> Result<()> {
        let sender = self.sender()?;
        nym_client_core::enclave::note_submitted();
        sender
            .send_reply(AnonymousSenderTag::from_bytes(tag.0), data)
            .await
            .inspect_err(|_| nym_client_core::enclave::note_unsubmitted())
            .map_err(client_error)
    }

    async fn recv(&self) -> Option<Incoming> {
        self.rx.lock().await.recv().await
    }

    /// A device moves to another gateway with a fresh ephemeral client
    /// (RT-02). The old client keeps receiving for [`RETIRE_AFTER`], so
    /// replies already on their way still arrive. An ingress keeps its
    /// gateway (its address is published).
    async fn switch_gateway(&self) -> Result<String> {
        if !matches!(self.opts.role, Role::Client) {
            return Err(NymError::Client("an ingress keeps its gateway".into()));
        }
        let _one = self.switching.lock().await;
        let old = self.address();
        let old_gateway = gateway_of(&old).map(str::to_string);
        let mut opts = Options {
            gateway: None,
            ..self.opts.clone()
        };
        // What this process started with, as far as it has spent, then
        // what it bought since.
        let mut held: Vec<enclave_nym::Held> = opts
            .tickets
            .iter()
            .filter_map(|t| enclave_nym::Held::decode(t).ok())
            .collect();
        if let Ok(b) = self.bought.lock() {
            held.extend(b.iter().filter_map(|t| enclave_nym::Held::decode(t).ok()));
        }
        opts.tickets = enclave_nym::advance(&held, nym_gateway_client::client::tickets_spent())
            .iter()
            .map(enclave_nym::Held::encode)
            .collect();
        // nym-sdk picks a gateway uniformly at random: with two to choose
        // from, eight tries all landing on the old one is 1 in 256.
        for _ in 0..8 {
            let client = build(&opts).await?;
            let address = client.nym_address().to_string();
            let Some(gateway) = gateway_of(&address).map(str::to_string) else {
                continue;
            };
            if Some(&gateway) == old_gateway.as_ref() {
                drop(client);
                continue;
            }
            let (sender, address, reader) = attach(client, self.tx.clone());
            if let Ok(mut c) = self.current.write() {
                *c = (sender, address);
            }
            let retired = {
                let Ok(mut readers) = self.readers.lock() else {
                    return Err(NymError::Closed);
                };
                let retired: Vec<_> = readers.drain(..).collect();
                readers.push(reader);
                retired
            };
            tokio::spawn(async move {
                tokio::time::sleep(RETIRE_AFTER).await;
                for r in retired {
                    r.abort();
                }
            });
            return Ok(gateway);
        }
        Err(NymError::Client("no other gateway found".into()))
    }

    fn set_pacing(&self, pacing: Pacing) {
        nym_client_core::enclave::set_packet_gap(packet_gap(&pacing));
        nym_client_core::enclave::set_loop_cover_delay(pacing.loop_cover);
    }

    async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        self.fetcher()?.fetch(method, url, body).await
    }

    async fn tickets_spent(&self) -> Result<u64> {
        Ok(nym_gateway_client::client::tickets_spent())
    }

    async fn buy_tickets(&self, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
        let book = credentials::buy(self.fetcher()?, gate, token).await?;
        if let Ok(mut b) = self.bought.lock() {
            b.push(book.clone());
        }
        Ok(book)
    }

    async fn flush(&self, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            if nym_client_core::enclave::outstanding() == 0 {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_unit_gets_enough_reply_blocks() {
        // A reply packet carries ≈1.6 KB: a 16,406 B reply is 11 packets,
        // plus one spare.
        let n = surbs_for(enclave_nym::frame::REPLY_LEN);
        assert_eq!(n, 12, "{n}");
        assert_eq!(surbs_for(1), 2);
    }

    #[test]
    fn a_tick_is_paced_evenly_and_bulk_at_the_cap() {
        let mut p = Pacing {
            tick: Duration::from_secs(3),
            bulk: false,
            loop_cover: Duration::from_secs(15),
            probe: Duration::from_secs(30),
        };
        // 16 packets up per tick and 4 spare slots: one every 3 s / 20
        // = 150 ms in Foreground, the last 2.25 s into the tick.
        assert_eq!(packet_gap(&p), Duration::from_millis(150));
        p.bulk = true;
        assert_eq!(packet_gap(&p), Duration::from_millis(25));
    }
}
