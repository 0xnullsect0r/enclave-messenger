# Formal models

Symbolic (Dolev–Yao) models in ProVerif. Each query is preceded by the result it must give, as `(* expect: true *)`, `(* expect: false *)` or, for an equivalence that must fail (ProVerif then reports it "cannot be proved"), `(* expect: unproved *)`, and `cargo xtask proverif` checks every result in every model against those notes (CI builds the pinned ProVerif 2.05 release, job `proverif`; locally, set `PROVERIF` to the binary). An `expect: false` query is a deliberate sanity check: it shows the model can find the attack that the design is meant to prevent, so the matching `true` result means something.

| Model | What it shows | Result |
|---|---|---|
| `proverif/eqxdh.pv` | EQXDH (`docs/04-eqxdh.md`): the session key is secret in both directions; Bob accepts only keys Alice derived for him, and Alice accepts only the reply key Bob derived for her, each once (injective agreement) | 4 queries hold |
| `proverif/eqxdh_fs.pv` | Forward secrecy: after the sessions, every long-term key and the signed prekeys leak (one-time prekeys were deleted); what was sent stays secret | 2 queries hold |
| `proverif/eqxdh_quantum.pv` | PLAN D12's "all KEMs broken" lemma: the attacker takes discrete logs and opens every ML-KEM and McEliece ciphertext. A session whose PSK came from an in-person scan stays secret; the same session without a PSK does not | secret with PSK; attack found without |
| `proverif/eqxdh_downgrade.pv` | Downgrade resistance (RT-07): the mode byte (three KEMs or two, PSK or not) travels in the clear, but EnclaveCombine binds it, so Bob never accepts a mode Alice didn't choose. The KEM and DH secrets are abstracted to one shared secret | holds; a weakened instance without the binding is attacked |
| `proverif/invite_psk.pv` | Invite-link PSK (`docs/03-identity.md` §9.2) against the same quantum attacker, which also runs the server and sees every request-inbox capability the link derives: a session from a link sent privately stays secret (the PSK and capability labels are separate); from a link posted publicly it does not. Authentication against this attacker is not queried (ProVerif did not finish it in 25 minutes) | secret with a private link; attack found with a public one |
| `proverif/lockstep_pcs.pv` | Lockstep post-compromise security (`docs/05-ratchet.md`): after the root key leaks to a quantum attacker, one round trip it sees but does not alter heals the session through the ML-KEM step; an X448-only step does not | heals with ML-KEM; attack found with X448 alone |
| `proverif/group_macs.pv` | Group MAC vectors (`docs/07-groups.md` §3): a compromised member, holding the group's epoch keys, can't make another member accept a message as coming from a third | holds; the sanity query finds the member sending as themselves |
| `proverif/eqxdh_deniable.pv` | Deniability off the record, as an observational equivalence: a judge holding all of Bob's secrets can't tell Alice's real first message from one Bob made alone | equivalent |
| `proverif/eqxdh_on_record.pv` | Sanity for the above: with Alice's signature (On the record) the judge tells them apart | not provable, as it must be |
| `proverif/tokens_unlinkable.pv` | Write tokens from the shared pool (`09-transport.md` §3.3): the server, seeing the registration batch and the burned tokens, can't tell two writes by one contact from one write each by two | equivalent |
| `proverif/tokens_batches_link.pv` | Sanity: with a batch per contact, it can | not provable, as it must be |


## Tamarin

The same discipline in Tamarin (`formal/tamarin/`): each lemma is preceded by `/* expect: verified */` or `/* expect: falsified */`, and `cargo xtask tamarin` proves every model and checks every lemma by name; a model whose wellformedness checks warn fails too. CI runs it with the pinned Tamarin 1.10.0 release and Ubuntu's Maude (job `tamarin`); locally, set `TAMARIN` to the binary. Each model has sanity lemmas (`exists-trace`) showing the attack its main lemma rules out is found when the defence is removed, and that the protocol runs at all.

| Model | What it shows | Result |
|---|---|---|
| `tamarin/eqxdh_quantum.spthy` | PLAN D12's "all KEMs broken, optical exchange not recorded" lemma: every private key, exponent and KEM secret is the attacker's; a session with a PSK from an in-person scan stays secret | holds; broken without a PSK |
| `tamarin/braid.spthy` | The braid: a session that started on two KEMs is secure after the McEliece step, against an attacker that breaks X448 and ML-KEM | holds; the two-KEM key is broken before it |
| `tamarin/lockstep.spthy` | Lockstep post-compromise security against a quantum attacker: after the root key leaks, one ML-KEM step it sees but doesn't alter heals the session | heals; an X448-only step doesn't |
| `tamarin/wrap_table.spthy` | The direct envelope's wrap table (5 slots reduced to 2): the body key is secret unless a recipient's session key leaks; a device accepts only a body the sender sealed, even when the other recipient is compromised and knows the body key (each slot binds the sealed body) | holds; the other recipient does learn body keys |
| `tamarin/groups.spthy` | Groups, bounded to three members with Carol corrupt: Bob takes a message as Alice's only if she sent it (MAC vectors), although Carol can seal to the group; after Carol is removed, the next epoch key stays secret from her | holds |
| `tamarin/linking.spthy` | Device linking: the primary adds only a device key the person's own new device made, and sends the account secrets only to it, against a network attacker that can photograph the QR or show the primary a QR of its own | holds; without the phrase check the attacker's QR links its device |
| `tamarin/pending_root.spthy` | The pending-root window: with stolen recovery words, a contact still takes only manifests the person started, while the person has a device that looks within the 72 hours (the wait is that assumption) | holds; with every device lost, stolen words win |
| `tamarin/root_migration.spthy` | Changing the recovery words: a contact moves to a new root only if the person migrated on one of their devices (the record must arrive in a session from a listed device), with or without the old root's signature | holds; following a record on signatures alone is attacked |
| `tamarin/tokens.spthy` | Privacy Pass tokens: every accepted token was issued, and none is accepted twice | holds; without the spent set a token is spent twice |

## What the models abstract

- **Primitives are ideal.** KEMs open only with the secret key, KMAC256 is a random oracle, EnclaveSeal is authenticated encryption, X448 is Diffie–Hellman with the usual exponent equation. Computational proofs of EnclaveCombine and EnclaveSeal (CryptoVerif or EasyCrypt) are separate work and not done.
- **Prekey signatures** are replaced by an authenticated public channel for Bob's keys; the composite and SLH-DSA signatures on them are not modelled.
- **Identity sealing** in EQXDH stage 1 hides who initiates; ProVerif's secrecy queries don't express that property, so the model omits it.
- **The ratchet** is reduced to one post-compromise step, not the full Lockstep state machine, its skipped keys or its counters. Replay protection is not modelled anywhere.
- **Group rekeys** (the exporter broadcast) and the state hash chain are not modelled; `group_macs.pv` covers message authentication only.
- **Deniability** is modelled for the first message only (`eqxdh_deniable.pv`); later ratchet messages are sealed under keys both parties hold, the same argument.

The models are written from the specification and checked by hand against the code; nothing extracts them from the Rust source, so they can drift. A change to EQXDH, the ratchet's PQ step or group authentication must update the matching model.

Tamarin abstractions, beyond those above: blinding is left out of the token model (it gives unlinkability, an equivalence property, not unforgeability); the group model has three members and one removal; the pending-root model reads the 72-hour wait as "a device the person still has looks before any contact's wait ends"; the linking model reduces the four phrases to an exact comparison.
