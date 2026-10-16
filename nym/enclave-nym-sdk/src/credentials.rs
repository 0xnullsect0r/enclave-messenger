//! zk-nym ticketbooks bought through the foundation's credential gate
//! (`enclave-credgate`, `docs/09-transport.md` §7).
//!
//! The device makes its own ecash key pair and withdrawal request, sends
//! the request with one Privacy Pass token to the gate, and gets back the
//! signers' blinded shares; it unblinds them with the signers' partial keys
//! and aggregates them itself, so neither the gate nor the proxy ever sees
//! its ecash secret. The result is kept as an [`ImportableTicketBook`]
//! (the ticketbook plus the master key and global signatures a client
//! needs to spend it), serialized: what the vault stores and hands back to
//! nymd at every start ([`import`]).
//!
//! HTTP goes through [`Fetcher`]: the Enclave TLS profile, and the SOCKS5
//! proxy netd gives nymd in its environment (Tor), so the gate never sees
//! the device's address.

use crate::client_error;
use enclave_nym::{NymError, Result};
use nym_credential_proxy_requests::api::v1::ticketbook::models::{
    PartialVerificationKeysResponse, TicketbookRequest, TicketbookWalletSharesResponse,
    WithdrawalRequestBs58Wrapper,
};
use nym_credentials::ecash::bandwidth::serialiser::VersionedSerialise;
use nym_credentials::{
    AggregatedCoinIndicesSignatures, AggregatedExpirationDateSignatures, EpochVerificationKey,
    ImportableTicketBook, IssuanceTicketBook, IssuedTicketBook,
};
use nym_credentials_interface::{
    Base58, BlindedSignature, TicketType, VerificationKeyAuth, generate_keypair_user,
};

/// The serialization revision of the stored [`ImportableTicketBook`].
const REVISION: u8 = <ImportableTicketBook as VersionedSerialise>::CURRENT_SERIALISATION_REVISION;

/// Extra roots for a local mixnet's tests: a PEM file.
pub const TEST_CA_VAR: &str = "ENCLAVE_NYM_TEST_CA";

/// HTTP for the credential gate: Enclave TLS, through the environment's
/// proxy (`ALL_PROXY`, set by netd to tord's SOCKS5 port).
pub struct Fetcher {
    http: reqwest::Client,
}

impl Fetcher {
    /// A client trusting the web PKI roots.
    pub fn new() -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots)
    }

    /// The client for `network`: the web PKI roots, and on a local mixnet
    /// also those in the PEM file [`TEST_CA_VAR`] names (the test stacks'
    /// own CA; never on Nym's networks).
    pub fn for_network(network: &crate::Network) -> Result<Self> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if cfg!(feature = "dev-networks")
            && matches!(network, crate::Network::Local { .. })
            && let Some(path) = std::env::var_os(TEST_CA_VAR)
        {
            for c in CertificateDer::pem_file_iter(&path).map_err(client_error)? {
                roots.add(c.map_err(client_error)?).map_err(client_error)?;
            }
        }
        Self::with_roots(roots)
    }

    /// A client trusting `roots` (tests and the local stacks' own CA).
    pub fn with_roots(roots: rustls::RootCertStore) -> Result<Self> {
        let tls = enclave_tls::client_config(roots).map_err(client_error)?;
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(client_error)?;
        Ok(Self { http })
    }

    /// `method` `url` with `body`: the status and the answer.
    pub async fn fetch(&self, method: &str, url: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(client_error)?;
        // `…#bytes=A-B`: a range of the file (a fragment never goes on the
        // wire; this one becomes the Range header), so a large download
        // comes in pieces a pipe frame holds.
        let (url, range) = match url.split_once("#bytes=") {
            Some((u, r))
                if r.split_once('-')
                    .is_some_and(|(a, b)| a.parse::<u64>().is_ok() && b.parse::<u64>().is_ok()) =>
            {
                (u, Some(format!("bytes={r}")))
            }
            _ => (url, None),
        };
        let mut req = self.http.request(method, url);
        if let Some(r) = range {
            req = req.header("range", r);
        } else {
            req = req
                .header("content-type", "application/octet-stream")
                .body(body);
        }
        let res = req.send().await.map_err(client_error)?;
        let status = res.status().as_u16();
        let bytes = res.bytes().await.map_err(client_error)?;
        Ok((status, bytes.to_vec()))
    }
}

fn ok(status: u16, what: &str) -> Result<()> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(NymError::Client(format!(
            "credential gate: {what} answered {status}"
        )))
    }
}

/// Buy one ticketbook from the gate at `gate` (`https://host`) with one
/// Privacy Pass `token` (`enclave-tokens`' `Token` encoding): a
/// [`enclave_nym::Held`] (nothing spent yet) around the serialized
/// [`ImportableTicketBook`], encoded.
pub async fn buy(fetch: &Fetcher, gate: &str, token: &[u8]) -> Result<Vec<u8>> {
    let gate = gate.trim_end_matches('/');
    let (status, keys) = fetch
        .fetch(
            "GET",
            &format!("{gate}/credgate/v1/partial-keys"),
            Vec::new(),
        )
        .await?;
    ok(status, "partial-keys")?;
    let keys: PartialVerificationKeysResponse =
        serde_json::from_slice(&keys).map_err(client_error)?;

    let (issuance, request) = withdrawal()?;
    let mut body = token.to_vec();
    body.extend_from_slice(&serde_json::to_vec(&request.0).map_err(client_error)?);
    let (status, shares) = fetch
        .fetch("POST", &format!("{gate}/credgate/v1/ticketbook"), body)
        .await?;
    ok(status, "ticketbook")?;
    let shares: TicketbookWalletSharesResponse =
        serde_json::from_slice(&shares).map_err(client_error)?;
    let book = finish(issuance, request.1, &keys, shares)?;
    let total = decode(&book)?.0.ticketbook.params_total_tickets();
    Ok(enclave_nym::Held {
        total: u32::try_from(total).map_err(client_error)?,
        spent: 0,
        book,
    }
    .encode())
}

/// A fresh ecash key pair and withdrawal request for a mixnet-entry
/// ticketbook, as the proxy wants it.
fn withdrawal() -> Result<(
    IssuanceTicketBook,
    (TicketbookRequest, nym_credentials::CredentialSigningData),
)> {
    let mut rng = rand_core_06::OsRng;
    let signing_key = nym_crypto::asymmetric::ed25519::PrivateKey::new(&mut rng);
    let issuance = IssuanceTicketBook::new_with_keypair(
        0,
        generate_keypair_user(),
        signing_key,
        TicketType::V1MixnetEntry,
        nym_ecash_time::ecash_default_expiration_date(),
    );
    let signing = issuance.prepare_for_signing();
    let request = TicketbookRequest {
        withdrawal_request: WithdrawalRequestBs58Wrapper(signing.withdrawal_request.clone()),
        ecash_pubkey: signing.ecash_pub_key,
        expiration_date: signing.expiration_date,
        ticketbook_type: signing.ticketbook_type,
        is_freepass_request: false,
    };
    Ok((issuance, (request, signing)))
}

/// Unblind every share with its signer's partial key, aggregate under the
/// master key, and package the ticketbook with the global signatures.
fn finish(
    issuance: IssuanceTicketBook,
    signing: nym_credentials::CredentialSigningData,
    keys: &PartialVerificationKeysResponse,
    shares: TicketbookWalletSharesResponse,
) -> Result<Vec<u8>> {
    let master = shares
        .master_verification_key
        .as_ref()
        .ok_or_else(|| NymError::Client("no master verification key in the answer".into()))?;
    let master_key =
        VerificationKeyAuth::try_from_bs58(&master.bs58_encoded_key).map_err(client_error)?;
    let mut partials = Vec::with_capacity(shares.shares.len());
    for share in &shares.shares {
        let Some(key) = keys.keys.iter().find(|k| k.node_index == share.node_index) else {
            continue;
        };
        let vk = VerificationKeyAuth::try_from_bs58(&key.bs58_encoded_key).map_err(client_error)?;
        let blinded =
            BlindedSignature::try_from_bs58(&share.bs58_encoded_share).map_err(client_error)?;
        partials.push(
            issuance
                .unblind_signature(&vk, &signing, blinded, share.node_index)
                .map_err(client_error)?,
        );
    }
    let wallet = issuance
        .aggregate_signature_shares(&master_key, &partials, signing)
        .map_err(client_error)?;
    let issued: IssuedTicketBook = issuance.into_issued_ticketbook(wallet, shares.epoch_id);
    let importable = ImportableTicketBook::from(issued)
        .with_master_verification_key(&EpochVerificationKey {
            epoch_id: master.epoch_id,
            key: master_key,
        })
        .with_maybe_coin_index_signatures(
            &shares
                .aggregated_coin_index_signatures
                .map(|s| s.signatures as AggregatedCoinIndicesSignatures),
        )
        .with_maybe_expiration_date_signatures(
            &shares
                .aggregated_expiration_date_signatures
                .map(|s| s.signatures as AggregatedExpirationDateSignatures),
        );
    Ok(importable.finalize_export().data)
}

/// The parts of a stored ticketbook, ready to import into a client.
pub struct Decoded(nym_credentials::DecodedImportableTicketBook);

/// Read a stored ticketbook (what [`buy`] returned).
pub fn decode(bytes: &[u8]) -> Result<Decoded> {
    let importable = ImportableTicketBook::try_unpack(bytes, REVISION).map_err(client_error)?;
    Ok(Decoded(importable.try_unpack_full().map_err(client_error)?))
}

/// The ticket store of a device's (ephemeral) client: kept from before it
/// connects, so books bought later go into the running client too.
pub type TicketStore = nym_credential_storage::ephemeral_storage::EphemeralStorage;

/// Import what is left of a held ticketbook into a device's ticket store.
/// The store spends books in the order they were imported.
pub async fn import(store: &TicketStore, held: &enclave_nym::Held) -> Result<()> {
    use nym_credential_storage::storage::Storage;
    if held.left() == 0 {
        return Ok(());
    }
    let ticketbook = decode(&held.book)?;
    let d = &ticketbook.0;
    if let Some(k) = &d.master_verification_key {
        store
            .insert_master_verification_key(k)
            .await
            .map_err(client_error)?;
    }
    if let Some(s) = &d.coin_index_signatures {
        store
            .insert_coin_index_signatures(s)
            .await
            .map_err(client_error)?;
    }
    if let Some(s) = &d.expiration_date_signatures {
        store
            .insert_expiration_date_signatures(s)
            .await
            .map_err(client_error)?;
    }
    if held.spent == 0 {
        store.insert_issued_ticketbook(&d.ticketbook).await
    } else {
        store
            .insert_partial_issued_ticketbook(&d.ticketbook, held.spent, held.total - 1)
            .await
    }
    .map_err(client_error)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use nym_credential_proxy_requests::api::v1::ticketbook::models::{
        MasterVerificationKeyResponse, PartialVerificationKey, WalletShare,
    };
    use nym_ecash_time::EcashTime;

    /// The device side of a purchase against signers made here: three
    /// signers (threshold two) blind-sign the device's withdrawal request,
    /// one is missing from the answer, and the device unblinds the rest,
    /// aggregates them, and stores a ticketbook it can read back.
    #[test]
    fn shares_from_signers_become_a_ticketbook() {
        let signers = nym_compact_ecash::ttp_keygen(2, 3).unwrap();
        let (issuance, (request, signing)) = withdrawal().unwrap();
        // What the proxy is sent survives JSON.
        let json = serde_json::to_vec(&request).unwrap();
        let _: TicketbookRequest = serde_json::from_slice(&json).unwrap();

        let keys = PartialVerificationKeysResponse {
            epoch_id: 4,
            keys: signers
                .iter()
                .enumerate()
                .map(|(i, s)| PartialVerificationKey {
                    node_index: i as u64 + 1,
                    bs58_encoded_key: s.verification_key().to_bs58(),
                })
                .collect(),
        };
        let shares: Vec<WalletShare> = signers
            .iter()
            .enumerate()
            .take(2)
            .map(|(i, s)| {
                let blinded = nym_compact_ecash::issue(
                    s.secret_key(),
                    signing.ecash_pub_key,
                    &signing.withdrawal_request,
                    signing.expiration_date.ecash_unix_timestamp(),
                    signing.ticketbook_type.encode(),
                )
                .unwrap();
                WalletShare {
                    node_index: i as u64 + 1,
                    bs58_encoded_share: blinded.to_bs58(),
                }
            })
            .collect();
        let vks: Vec<_> = signers.iter().map(|s| s.verification_key()).collect();
        let master =
            nym_compact_ecash::aggregate_verification_keys(&vks, Some(&[1, 2, 3])).unwrap();
        let answer = TicketbookWalletSharesResponse {
            epoch_id: 4,
            shares,
            master_verification_key: Some(MasterVerificationKeyResponse {
                epoch_id: 4,
                bs58_encoded_key: master.to_bs58(),
            }),
            aggregated_coin_index_signatures: None,
            aggregated_expiration_date_signatures: None,
        };
        let stored = finish(issuance, signing, &keys, answer).unwrap();
        let back = decode(&stored).unwrap();
        assert_eq!(back.0.ticketbook.epoch_id(), 4);
        assert!(back.0.master_verification_key.is_some());
        assert!(decode(&stored[..stored.len() / 2]).is_err());

        // Imported into a client's store, partly spent: what is left counts
        // (what an operator's top-up reads).
        let total = u32::try_from(back.0.ticketbook.params_total_tickets()).unwrap();
        let store = TicketStore::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            import(
                &store,
                &enclave_nym::Held {
                    total,
                    spent: 10,
                    book: stored,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                crate::funding::tickets_left(&store).await.unwrap(),
                u64::from(total - 10)
            );
        });
    }
}
