# SIGNER.md — out-of-process signer for deposits-node

`deposits-signer` is a separate process that holds the operator/identity seed and answers BIP-340 / ECDSA / ECDH requests over a Unix socket. The daemon never sees the seed once `deposits-signer` is provisioned with it — it talks to the signer via a small RPC, gets back signatures and ECDH shared secrets, and constructs the rest itself.

This doc covers what the signer is, how to operate it, the wire it speaks, and what's wired vs. still pending. For the original design rationale + phasing, see [PLAN-remote-signer.md](PLAN-remote-signer.md).

---

## 1. Why this exists

A deposits-node that holds the operator secret on its own filesystem has two failure modes:

- **Process compromise.** Anyone who pops the daemon can exfiltrate the seed and become the operator: forge ledger updates, drain reserves, etc. The protocol's slashing only kicks in for *protocol-violating* behaviour the quorum can prove, not for "operator's seed escaped."
- **Hot-spare race.** Two daemons sharing the same operator seed will sign at the same `seq` and produce a self-equivocation, which *is* slashable. There's no way for the daemons to coordinate via the seed alone.

`deposits-signer` is the structural answer:

- **Compromise reduction.** Seed lives only inside the signer. Daemon process compromise leaks the *Nostr* key (event signing, NIP-04 ECDH) — annoying but not slashable. The operator/protocol key — the one slashing depends on — stays inside the signer.
- **Anti-equivocation.** The signer maintains a `(ledger_id, role) → max_seq` store and refuses to sign a regression. Hot-spare daemons can race all they want; the signer's policy ensures only one of their seq values gets through.

The signer is purely an implementation concern — there's no protocol change. Receivers verify a `BIP-340` signature against the operator's pubkey from the ledger; whether that signature was produced inside the daemon or via RPC to a separate process is invisible.

---

## 2. Architecture

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│ deposits-node (no seed)     │         │ deposits-signer              │
│                             │         │                              │
│  Signer trait               │ ─────►  │  Holds: operator seed        │
│   ├ LocalSigner (legacy)    │ socket  │         transport keypair    │
│   └ RemoteSigner ───────────┼────────►│         allowlist (node pks) │
│                             │         │         seq policy store     │
│  --signer-pubkey <pk>       │         │                              │
│  --signer-socket <path>     │         │  RPC: bip340_sign, ecdsa,    │
│                             │         │       ecdh, pubkey,          │
│                             │         │       issue_nostr_secret     │
└─────────────────────────────┘         └──────────────────────────────┘
```

**Crates:**

| Crate | Role |
|---|---|
| `deposits-signer-api` | The `Signer` trait, `SigRole` / `SigPurpose` types, wire message shapes, `LocalSigner` reference impl. Both ends depend on this. |
| `deposits-signer` | The binary. Holds the seed, listens on a Unix socket, dispatches sign requests, enforces anti-equivocation policy. |
| `deposits-node` | The daemon. Implements `RemoteSigner` (a `Signer` impl that talks to `deposits-signer`). Routes every operator-protocol sign through `Arc<dyn Signer>`. |

---

## 3. Trust model and key derivation

Two keys live behind the signer, derived from the same seed at distinct BIP-32 paths:

| Key | Path | Use |
|---|---|---|
| Operator / protocol | `m/86'/0'/0'/0/0` | Operator signature on every ledger update, cosignatures, invoice cosignatures, attestations. **Never leaves the signer.** |
| Nostr identity | `m/85'/0'/0'/0/0` | Nostr event signing, NIP-04 / NIP-44 ECDH, gift-wrap seals. **Issued to the daemon at startup** via `SignOp::IssueNostrSecret`; daemon holds it locally. |

The two prime paths (`86'` vs `85'`) are deliberately distinct so a leaked key is unambiguously identifiable as one or the other.

**Compromise scenarios:**

- *Daemon process compromise.* Attacker gets the Nostr key. They can sign fake events from the daemon's Nostr pubkey and decrypt past inbound NIP-04 DMs to it. They cannot produce protocol-level signatures (operator_signature on a ledger update, cosignatures, invoice cosignatures, attestations). Slashing-equivalent fraud is structurally unavailable.
- *Signer process compromise.* Catastrophic — attacker has the operator seed. Same blast radius as today's pre-signer architecture. Mitigations: separate host, hardened OS, restricted egress.
- *Transport socket compromise.* The mutual-pinned-keys handshake means an attacker who taps the socket can read in-flight requests but cannot impersonate either side. A daemon talking to a fake signer will fail the `expected_signer_pubkey` check on `HelloAck` and refuse to proceed.

---

## 4. Wire (daemon ↔ signer)

JSON over a Unix socket, length-prefixed `[u32 BE][body]` framing, capped at 1 MiB per frame. Defined in [`deposits-signer-api/src/wire.rs`](deposits-signer-api/src/wire.rs).

**Handshake:**

```
daemon                                             signer
  |  Hello { node_pubkey, nonce_a, version }    --►|
  |                                              | (allowlist check)
  | ◄-- HelloAck { signer_pubkey, nonce_b,       |
  |                sig_signer over                |
  |                sha256("deposits-signer/       |
  |                       hello-ack/v1"           |
  |                       || nonce_a              |
  |                       || node_pubkey)) }      |
  | (verify against pinned --signer-pubkey)      |
  | Auth { sig_node over                          |
  |        sha256("deposits-signer/             --►|
  |               auth/v1" || nonce_b ||          |
  |               signer_pubkey) }                |
  |                                              | (verify; handshake done)
```

The exact tag strings (`deposits-signer/hello-ack/v1`, `deposits-signer/auth/v1`) are exported as `HELLO_ACK_TAG` / `AUTH_TAG` from [`deposits-signer-api/src/wire.rs`](deposits-signer-api/src/wire.rs); both ends consume the same constants so no chance of drift.

Both signatures are BIP-340 against the respective transport pubkeys. Nonces are fresh per connection. Pinning is mutual — the signer's allowlist names the daemon transport pubkey, and the daemon's `--signer-pubkey` flag names the signer's transport pubkey. No TOFU; both ends are configured by the operator.

**Per-call requests** (post-handshake):

```rust
SignRequest { id, ctx: SignContext, op: SignOp }
```

Where `SignOp` is one of:

| Op | Returns | Notes |
|---|---|---|
| `Bip340 { digest: [u8;32] }` | 64-byte sig | The hot-path operator-update / cosign-update signing op. Anti-equivocation policy gates this. |
| `Ecdsa { sighash: [u8;32] }` | 64-byte compact sig | For the legacy P2WSH single-sig path. |
| `Ecdh { peer: PublicKey }` | 32-byte SHA-256-hashed shared secret | For NIP-44; not used for NIP-04 (which goes through the daemon-held Nostr key). |
| `PubkeyQuery` | `{ pubkey, xonly }` | Cached on connect; the daemon answers `pubkey()` / `xonly_pubkey()` synchronously thereafter. |
| `IssueNostrSecret` | 32-byte secret | Sibling-derived Nostr identity key, issued once at daemon startup. |

`SignContext` carries `SigRole` (NoLedger / OperatorUpdate / CosignUpdate) + `SigPurpose` (Bip340Untagged / InvoiceCosign / NostrEvent / Attestation / DepositGuarantee / Payment / PaymentAuthorization / DepositOffer / Withdrawal / OnchainSighash). The signer logs every request with its context for audit.

**No AEAD on the wire.** v1 runs over a Unix socket where filesystem permissions plus the mutual-pinned-keys handshake do the access control. Adding ChaCha20-Poly1305 sealing is a future-phase concern when the transport goes remote (hole-punched UDP/QUIC). The wire types are designed to fit inside sealed frames once that lands.

---

## 5. Anti-equivocation policy

State: a JSON file at `<data-dir>/anti_equivocation.json` (atomic-ish writes via tmp + rename). Two maps:

| Map | Key | Value |
|---|---|---|
| `operator` | `ledger_id (hex)` | max seq the signer has ever signed as operator on this ledger |
| `cosigner` | `operator_ledger_id (hex)` | max seq the signer has ever cosigned for this operator's ledger |

The two are tracked independently — a signer that's signed as operator at seq=5 on ledger A doesn't gate cosigning at seq=1 on the same ledger A. Different protocol roles, conceivably different keys later.

**Policy:** every `Bip340` request whose `SignContext.role` is `OperatorUpdate` or `CosignUpdate` runs through `SeqPolicy::check_and_record` before the signer dispatches. If `seq <= max`, the request is refused with `SignErrorKind::PolicyRefused`. On accept, the new max is persisted before returning the signature.

**Refused requests don't advance state.** A failed sign at seq=N leaves max at its prior value, so a legitimate seq=N+1 still goes through.

`NoLedger` requests pass through unconditionally — those are invoice cosigns, attestations, deposit offers, etc., not bound to a sequence.

ECDSA / ECDH / PubkeyQuery / IssueNostrSecret aren't policy-gated.

---

## 6. Operating the signer

```bash
# 1. Initialize a data directory + transport keypair, optionally with a seed.
deposits-signer init --data-dir /var/lib/dsigner --seed-file /run/seed
# → prints: signer transport pubkey: <hex>

# 2. Start the daemon. It will print its own transport pubkey.
deposits-node run --signer-pubkey <signer_hex> \
                  --signer-socket /run/dsigner.sock \
                  ...
# → prints: node transport pubkey: <node_hex>

# 3. Allowlist that node pubkey on the signer.
deposits-signer trust add --data-dir /var/lib/dsigner <node_hex>

# 4. Restart the daemon (or wait for reconnect — it'll succeed now).
deposits-signer run --data-dir /var/lib/dsigner --socket /run/dsigner.sock
```

**Subcommand cheat sheet:**

```
init        --data-dir <p> [--seed-file <p>]
              Generate transport keypair, optionally install seed.
              Refuses if the data dir is already initialized.

pubkey      --data-dir <p>
              Print the signer's transport pubkey.

import-seed --data-dir <p> --seed-file <p>
              Install or replace the operator seed (32 bytes hex).

trust add   --data-dir <p> <node_pubkey_hex>
              Allowlist a node transport pubkey.

trust list  --data-dir <p>
              Show currently allowed node pubkeys.

run         --data-dir <p> --socket <p>
              Start the signer.
```

**Data directory layout:**

```
/var/lib/dsigner/
├── transport_secret        — 32-byte hex, 0600
├── transport_pubkey        — 33-byte compressed hex, 0644
├── seed                    — 32-byte hex, 0600
├── allowlist               — newline-separated 33-byte hex node pubkeys, 0644
└── anti_equivocation.json  — JSON `{ operator: {...}, cosigner: {...} }`, 0644
```

All files are plain text and inspectable. The signer enforces 0600 on `transport_secret` and `seed` at write time.

---

## 7. Wiring a daemon

The daemon side is `RemoteSigner` in [`deposits-node/src/remote_signer.rs`](deposits-node/src/remote_signer.rs). It bridges the synchronous `Signer` trait to the async wire by owning a single-thread tokio runtime; each trait call does a `block_on` on a serialized RPC. Connection mutex serializes in-flight requests; `id` correlation matches responses to requests.

```rust
let remote = RemoteSigner::connect(
    &socket_path,
    node_transport_secret,
    expected_signer_pubkey,
)?;
// `remote: impl Signer` — pass it where `Arc<dyn Signer>` is expected.
```

`pubkey()` and `xonly_pubkey()` answer synchronously after `connect()` (cached via the post-handshake `PubkeyQuery`). Every other op makes one round-trip.

**Current limit:** the daemon's startup (`Node::new` → `DepositsHandler::new`) still takes a `SecretKey` and constructs a `LocalSigner` internally. Wiring it to use a `RemoteSigner` instead requires the daemon's CLI to grow `--signer-pubkey` / `--signer-socket` flags and skip the seed-load. End-to-end "real daemon talking to a real signer" is the natural follow-up commit; the e2e tests in [`deposits-node/tests/remote_signer_e2e.rs`](deposits-node/tests/remote_signer_e2e.rs) exercise the `RemoteSigner` directly today.

A second blocker: the wallet (BDK) constructs its descriptor from the seed and uses internal key knowledge for PSBT signing. To run the daemon entirely without the seed, BDK needs a watch-only descriptor + per-input external sighash signing. See `PLAN-remote-signer.md` §Phase-3 finish state cluster 4.

---

## 8. The Nostr-key issuance

A daemon talking to a remote signer needs *some* way to do Nostr-layer ops (event signing, NIP-04 ECDH for inbound DMs). Two options were on the table:

1. Extend the `Signer` trait with `shared_secret_point` for raw-X ECDH so NIP-04 goes through the signer.
2. Have the signer issue a separate "Nostr identity" secret to the daemon at startup; daemon holds it locally for all Nostr-layer ops.

We took option 2. NIP-04's symmetric key derivation uses the *raw X coordinate* of the ECDH shared point, not the SHA-256-hashed value `bitcoin::secp256k1::ecdh::SharedSecret` returns; making the wire-side variant correctly match would mean a new method per NIP. Option 2 sidesteps that entirely — the daemon does the same `nip04::encrypt(secret, peer, plaintext)` it always did, but `secret` is now the issued Nostr key, not the operator key.

**Trade-off:** the daemon's Nostr-publisher pubkey is no longer the operator's protocol pubkey. Wallets need to learn that:

- Advertisements (Kind 39100) are *published* under the Nostr pubkey.
- The advertisement's *content* names the operator's protocol pubkey (used to verify `operator_signature` on inner ledger updates).
- DMs from depositors (Kind 20101) are encrypted to the Nostr pubkey (the event author).
- Trust assertions about "this is operator X" verify the inner protocol signature, not the outer Nostr event signature.

This is a small wallet-side update, not a DEP. Tracked as a depositor-facing follow-up.

---

## 9. Implementation status

**Done:**

- `deposits-signer-api`: trait, types, wire, `LocalSigner`, `LocalSigner::with_nostr_secret`. 13 unit + 4 serde tests.
- `deposits-signer`: binary, handshake server, framing, anti-equivocation policy, init/trust/run subcommands. 16 unit + 3 in-process handshake tests including a wire-level seq-regression refusal test.
- `deposits-node`: `RemoteSigner` client + 5 e2e tests with a real spawned signer process. Operator-protocol signing throughout the daemon flows through `Arc<dyn Signer>`.
- Anti-equivocation: persistent state, atomic writes, refused-request-doesn't-poison-state semantics.
- Sibling Nostr secret issuance: signer derives at `m/85'/0'/0'/0/0`, daemon takes it via `SignOp::IssueNostrSecret`, `Nostr` layer constructed against it. `DepositsHandler.secret_key` field removed.

**Not yet wired (future commits):**

- **`Node::new` taking `Arc<dyn Signer>` directly.** Currently the daemon construction takes a `SecretKey` and builds a `LocalSigner` internally. Adding `--signer-pubkey` + `--signer-socket` CLI flags + a constructor variant that connects a `RemoteSigner` is a straightforward follow-up. Today's e2e tests exercise `RemoteSigner` against a real signer process, but the real daemon doesn't yet drive that path.
- **Wallet (BDK) descriptor split.** `wallet.rs` still derives the operator key from the seed for BDK. Migrating to a watch-only descriptor with per-input external sighash signing is its own architectural work (~200-400 LoC of BDK glue). Until it lands, the daemon's host still needs the seed at startup for the wallet path; the operator/protocol signing is already remote-signer-ready.
- **Hole-punched transport.** Same wire protocol, network framing instead of Unix socket. AEAD sealing of post-handshake frames lands at the same time.
- **Hot-spare daemon coordination.** Multiple daemons sharing one signer: leader election layer on the daemon side. Anti-equivocation on the signer is the safety net that makes the configuration viable; coordination keeps it from being noisy.
- **Wallet-side advertisement protocol update.** Depositor-facing change: parse `operator_pubkey` from advertisement content, encrypt DMs to the event's `pubkey` (Nostr key), verify `operator_signature` against `operator_pubkey`. Out of scope for the signer crates; lands in `deposits-wallet` / `deposits-tools/wallet/` / `deposits-web/wallet/`.
- **`KeyPath` / depositor-key extension on the trait.** `admin.rs` lock/fulfill sigs and `node_cli/{lightning,withdraw}.rs` flows currently derive depositor keys via the daemon's master seed. Migrating them through the signer needs a `Signer::bip340_sign_at(KeyPath, ...)` extension; documented in `PLAN-remote-signer.md` §Open follow-ups.

---

## 10. Code map

| Concern | Path |
|---|---|
| Trait, role/purpose taxonomy, error type | `deposits-signer-api/src/lib.rs` |
| `LocalSigner` reference impl | `deposits-signer-api/src/local.rs` |
| Wire types, handshake digests, framing shapes | `deposits-signer-api/src/wire.rs` |
| Binary entrypoint + subcommand dispatch | `deposits-signer/src/main.rs` |
| Data dir, key derivation | `deposits-signer/src/data.rs` |
| Length-prefixed JSON framing | `deposits-signer/src/framing.rs` |
| Server-side handshake + dispatch loop | `deposits-signer/src/server.rs` |
| Anti-equivocation policy + persistence | `deposits-signer/src/policy.rs` |
| RemoteSigner client | `deposits-node/src/remote_signer.rs` |
| End-to-end test (spawn signer, drive client) | `deposits-node/tests/remote_signer_e2e.rs` |
| In-process handshake test | `deposits-signer/tests/handshake_inproc.rs` |

---

## 11. Useful one-liners

```bash
# Sanity: print the transport pubkeys at both ends.
deposits-signer pubkey --data-dir /var/lib/dsigner

# What's currently allowlisted?
deposits-signer trust list --data-dir /var/lib/dsigner

# What seqs has the signer signed?  (Plain JSON; readable.)
cat /var/lib/dsigner/anti_equivocation.json | jq

# Edit the allowlist by hand (one pubkey per line). Restart the signer
# afterward — the allowlist is loaded once at `run` startup (see
# server.rs::ServerCtx). `trust add` does the same edit + you skip the restart
# until next time you cycle.
$EDITOR /var/lib/dsigner/allowlist

# Tail the signer with handshake/dispatch logging.
RUST_LOG=deposits_signer=info deposits-signer run \
    --data-dir /var/lib/dsigner --socket /run/dsigner.sock
```
