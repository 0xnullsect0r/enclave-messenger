//! The foundation's federation registrar (RFC 0012). The parts that
//! decide, kept apart from the serving so tests can drive them directly:
//!
//! - [`Application::parse`]: an application as a new stack's `apply`
//!   sends it — `u32 len ‖ ServerDescriptor ‖ u32 len ‖
//!   WitnessDescriptor (0 = none) ‖ 32 B proof of work`.
//! - [`Application::check`]: everything an application must survive —
//!   both descriptors self-signed and in their validity window, the proof
//!   of work (`api::pow_context_join`), and the descriptor the stack
//!   actually serves over its own front equal to the one it applied with.
//! - [`rebuild`]: the next list — every listed server re-fetched over its
//!   front and verified against the identity it had (a server may change
//!   anything except who it is), the approved applications added, the
//!   foundation's static relays, push relays and credential gates from
//!   the spec, one sequence number up, doubly signed.
//! - [`push`]: the signed list to every listed stack's
//!   `/federation/list`, where the server's own verification takes it.

use enclave_crypto::rng::HedgedRng;
use enclave_federation::{
    FoundationKey, ListedServer, ServerDescriptor, ServerList, WitnessDescriptor,
};
use std::time::Duration;

/// An application, parsed off the wire.
pub struct Application {
    /// The stack's own descriptor for itself.
    pub descriptor: ServerDescriptor,
    /// Its witness's descriptor, when it wrote one for the front to serve.
    pub witness: Option<WitnessDescriptor>,
}

/// Longest application accepted.
pub const MAX_APPLICATION: usize = 1 << 20;

impl Application {
    /// Parse the wire form (`enclave-server apply`): `u32 len ‖
    /// ServerDescriptor ‖ u32 len ‖ WitnessDescriptor (0 = none) ‖ 32 B
    /// proof of work`. The proof comes back for [`check`].
    pub fn parse(body: &[u8]) -> Result<(Self, [u8; 32]), String> {
        let take = |rest: &mut &[u8]| -> Result<Vec<u8>, String> {
            let n = rest
                .get(..4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
                .ok_or("application: short length")?;
            let b = rest
                .get(4..4 + n)
                .ok_or("application: short body")?
                .to_vec();
            *rest = &rest[4 + n..];
            Ok(b)
        };
        let mut rest = body;
        if body.len() > MAX_APPLICATION {
            return Err("application: too large".into());
        }
        let descriptor = ServerDescriptor::decode(&take(&mut rest)?)
            .map_err(|e| format!("application: descriptor: {e}"))?;
        let witness = take(&mut rest)?;
        let witness = if witness.is_empty() {
            None
        } else {
            Some(
                WitnessDescriptor::decode(&witness)
                    .map_err(|e| format!("application: witness: {e}"))?,
            )
        };
        let proof = rest
            .get(..32)
            .ok_or("application: no proof of work")?
            .try_into()
            .unwrap();
        Ok((
            Self {
                descriptor,
                witness,
            },
            proof,
        ))
    }

    /// Everything an application must survive. `served` is what the
    /// stack's front answered when the registrar fetched
    /// `https://<domain>/.well-known/enclave` itself: it must equal the
    /// descriptor applied with, so the domain, the certificate and the
    /// front all work, from the outside, now. Returns the server's id.
    pub fn check(
        &self,
        proof: &[u8; 32],
        effort: u32,
        now: u64,
        served: &[u8],
    ) -> Result<[u8; 16], String> {
        self.descriptor
            .verify(now)
            .map_err(|e| format!("descriptor: {e}"))?;
        if let Some(w) = &self.witness {
            w.verify(now).map_err(|e| format!("witness: {e}"))?;
        }
        let id = self.descriptor.id();
        let day = now / 86_400;
        if !enclave_tokens::verify(
            &enclave_rpc::api::pow_context_join(&id, day),
            effort,
            &enclave_tokens::PowProof(*proof),
        ) {
            return Err("proof of work".into());
        }
        let encoded = self.descriptor.encode();
        if served != encoded {
            return Err("the front serves a different descriptor".into());
        }
        Ok(id)
    }

    /// The list entries the application contributes: the server, and its
    /// witness (answered at its own front, `/witness/v1`).
    pub fn entries(&self) -> (ListedServer, Option<enclave_federation::ListedWitness>) {
        let d = &self.descriptor;
        let server = ListedServer {
            identity: d.identity.clone(),
            domain: d.domain.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            nym_address: d.nym_address.clone(),
            onion: d.onion.clone(),
            weight: 1,
            kt: d.kt.clone(),
        };
        let witness = self
            .witness
            .as_ref()
            .map(|w| enclave_federation::ListedWitness {
                key: w.key.clone(),
                operator: w.operator.clone(),
                family: w.family.clone(),
                url: format!("https://{}/witness/v1", d.domain),
            });
        (server, witness)
    }
}

/// The foundation's static infrastructure, from the spec file: the parts
/// of the list that don't come from stacks (the registrar's own spec, in
/// the same shape `enclave-admin server-list build` takes for them).
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Static {
    /// Cosignature threshold.
    pub witness_threshold: u8,
    /// Days a list stays valid.
    pub valid_days: u64,
    /// Witnesses (files of signed descriptors).
    pub witness: Vec<String>,
    /// Call relays.
    pub relay: Vec<String>,
    /// Push relays (`nym_address`, `onion`, `keys` file of concatenated
    /// `u32 epoch ‖ X448 ‖ ML-KEM-1024`).
    pub push: Vec<PushSpec>,
    /// Credential gates.
    pub credgate: Vec<GateSpec>,
}

/// A push relay in the spec.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushSpec {
    /// Nym address (empty when it isn't on the mixnet).
    pub nym_address: String,
    /// Onion service.
    pub onion: String,
    /// The key file.
    pub keys: String,
}

/// A credential gate in the spec.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateSpec {
    /// Where it answers.
    pub url: String,
    /// Its issuer name.
    pub issuer_name: String,
    /// The key file (`EPOCH HEX` lines).
    pub keys: String,
}

/// The next list: `previous` re-verified against `served` (each listed
/// server's live descriptor, by domain — identity and domain must
/// continue), the applications added, the static infrastructure assembled,
/// one sequence number up, doubly signed under the foundation key.
pub fn rebuild(
    previous: &ServerList,
    served: &std::collections::HashMap<String, Vec<u8>>,
    applications: &[Application],
    statik: &Static,
    now: u64,
    key: &FoundationKey,
    rng: &mut HedgedRng,
) -> Result<Vec<u8>, String> {
    if statik.valid_days == 0 || statik.valid_days > 90 {
        return Err("valid_days must be 1 to 90".into());
    }
    let mut servers = Vec::new();
    let mut witnesses = Vec::new();
    // The stacks already listed: re-verified through their fronts.
    for s in &previous.servers {
        let Some(live) = served.get(&s.domain) else {
            return Err(format!("{}: the front didn't answer", s.domain));
        };
        let d = ServerDescriptor::decode(live)
            .map_err(|e| format!("{}: {e}", s.domain))
            .and_then(|d| {
                d.verify(now)
                    .map_err(|e| format!("{}: {e}", s.domain))
                    .map(|()| d)
            })?;
        if d.id() != s.id() {
            return Err(format!(
                "{}: serves {} now, was {} — a server may change anything but who it is",
                s.domain,
                hex(&d.id()),
                hex(&s.id())
            ));
        }
        servers.push(ListedServer {
            identity: d.identity.clone(),
            domain: d.domain.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            nym_address: d.nym_address.clone(),
            onion: d.onion.clone(),
            weight: s.weight,
            kt: d.kt.clone(),
        });
        if let Some(kt) = &d.kt {
            let _ = kt; // carried in the server entry
        }
    }
    // The applications, in arrival order.
    for a in applications {
        let (server, witness) = a.entries();
        if servers
            .iter()
            .any(|s| s.id() == server.id() || s.domain.eq_ignore_ascii_case(&server.domain))
        {
            continue; // already listed (or applied twice)
        }
        servers.push(server);
        if let Some(w) = witness {
            witnesses.push(w);
        }
    }
    let base = previous.servers.is_empty() && applications.is_empty();
    if base {
        return Err("a list needs at least one server".into());
    }
    // The static witnesses, relays, push relays and gates.
    let dir_w =
        |p: &str| -> Result<Vec<u8>, String> { std::fs::read(p).map_err(|e| format!("{p}: {e}")) };
    for w in &statik.witness {
        let b = dir_w(w)?;
        let d = WitnessDescriptor::decode(&b)
            .map_err(|e| format!("{w}: {e}"))?
            .verify(now)
            .map_err(|e| format!("{w}: {e}"))
            .map(|()| WitnessDescriptor::decode(&b).unwrap())?;
        witnesses.push(enclave_federation::ListedWitness {
            key: d.key.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            url: d.url.clone(),
        });
    }
    let threshold = statik.witness_threshold.max(1);
    if usize::from(threshold) > witnesses.len() {
        return Err(format!(
            "witness_threshold {threshold} but only {} witnesses",
            witnesses.len()
        ));
    }
    let mut relays = Vec::new();
    for r in &statik.relay {
        let b = dir_w(r)?;
        let d = enclave_federation::RelayDescriptor::decode(&b)
            .map_err(|e| format!("{r}: {e}"))?
            .verify(now)
            .map_err(|e| format!("{r}: {e}"))
            .map(|()| enclave_federation::RelayDescriptor::decode(&b).unwrap())?;
        relays.push(enclave_federation::ListedRelay {
            identity: d.identity.clone(),
            operator: d.operator.clone(),
            family: d.family.clone(),
            addr: d.addr.clone(),
            link_key: d.link_key,
        });
    }
    let mut push = Vec::new();
    for x in &statik.push {
        let b = dir_w(&x.keys)?;
        if b.is_empty() || b.len() % 148 != 0 {
            return Err(format!("{}: not a push-relay key file", x.keys));
        }
        push.push(enclave_federation::PushRelayEntry {
            nym_address: x.nym_address.clone(),
            onion: x.onion.clone(),
            keys: b.chunks(148).map(<[u8]>::to_vec).collect(),
        });
    }
    let mut credgates = Vec::new();
    for g in &statik.credgate {
        let text = std::fs::read_to_string(&g.keys).map_err(|e| format!("{}: {e}", g.keys))?;
        let mut keys = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (e, k) = line
                .split_once(' ')
                .ok_or(format!("{}: each line is EPOCH HEX", g.keys))?;
            let epoch: u32 = e.parse().map_err(|_| format!("{}: {e}", g.keys))?;
            let mut key = [0u8; 49];
            hex_into(k, &mut key).map_err(|e| format!("{}: {e}", g.keys))?;
            keys.push((epoch, key));
        }
        credgates.push(enclave_federation::CredGateEntry {
            url: g.url.clone(),
            issuer_name: g.issuer_name.clone(),
            keys,
        });
    }
    let list = ServerList {
        seq: previous.seq + 1,
        issued: now,
        expires: now + statik.valid_days * 86_400,
        witness_threshold: threshold,
        servers,
        witnesses,
        relays,
        push,
        credgates,
    };
    list.sign(key, rng).map_err(|e| format!("signing: {e}"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_into(s: &str, out: &mut [u8]) -> Result<(), String> {
    if s.len() != out.len() * 2 {
        return Err("wrong length".into());
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| "not hex".to_string())?;
    }
    Ok(())
}

/// Push a signed list to every listed stack's federation API. Returns
/// each domain with what came of it.
pub async fn push(list: &[u8], domains: &[String]) -> Vec<(String, Result<u16, String>)> {
    let mut out = Vec::new();
    for d in domains {
        let url = format!("https://{d}/federation/list");
        out.push((
            d.clone(),
            post_https(&url, list, Duration::from_secs(30))
                .await
                .map(|(s, _)| s),
        ));
    }
    out
}

/// POST `body` to `url` under the Enclave TLS profile with the public
/// roots. The status and answer body.
pub async fn post_https(
    url: &str,
    body: &[u8],
    within: Duration,
) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = enclave_tls::client_config(roots).map_err(|e| e.to_string())?;
    tls.alpn_protocols.clear();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Full<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let req = hyper::Request::post(url)
        .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
        .body(http_body_util::Full::new(bytes::Bytes::copy_from_slice(
            body,
        )))
        .map_err(|e| e.to_string())?;
    let res = tokio::time::timeout(within, client.request(req))
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {e}"))?;
    let status = res.status().as_u16();
    let answer = res
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, answer.to_vec()))
}

/// GET the same way (a stack's descriptor, the registrar's parameters).
pub async fn get_https(url: &str, within: Duration) -> Result<(u16, Vec<u8>), String> {
    use http_body_util::BodyExt;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls = enclave_tls::client_config(roots).map_err(|e| e.to_string())?;
    tls.alpn_protocols.clear();
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .build();
    let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
    let req = hyper::Request::get(url)
        .body(http_body_util::Empty::new())
        .map_err(|e| e.to_string())?;
    let res = tokio::time::timeout(within, client.request(req))
        .await
        .map_err(|_| format!("{url}: timed out"))?
        .map_err(|e| format!("{url}: {e}"))?;
    let status = res.status().as_u16();
    let answer = res
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, answer.to_vec()))
}

/// The proof-of-work solve, for the `apply` test path and parity with
/// `enclave-server apply`.
pub fn solve_join(server: &[u8; 16], day: u64, effort: u32) -> Result<[u8; 32], String> {
    let mut rng = HedgedRng::new().map_err(|e| e.to_string())?;
    enclave_tokens::solve(
        &enclave_rpc::api::pow_context_join(server, day),
        effort,
        &mut rng,
    )
    .map(|p| p.0)
    .map_err(|e| e.to_string())
}
