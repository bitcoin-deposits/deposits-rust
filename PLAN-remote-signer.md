# PLAN — remote signer for deposits-node

A new component, `deposits-signer`, holds the seed. The daemon never sees the seed — it gets a socket path and a pubkey and does its work over RPC.

This is purely an implementation concern: the protocol can't tell that a signature came from a remote process, only that BIP-340 verifies. No DEP changes, no wire-format changes.

The motivating scenarios:
- **Seed off the daemon's host.** A compromised `deposits-node` can't exfiltrate the seed.
- **Seq-monotonicity policy.** A compromised daemon can't trick the signer into signing two updates at the same `seq` — the kind of self-equivocation that would be slashable.
- **Hot-spare nodes (later).** Two daemons sharing one signer; the signer's policy keeps them from racing into self-equivocation. Coordination on the daemon side is a separate problem.
- **Hardware-isolated signer (later).** Same wire protocol, the signer process moves onto an HSM-adjacent host.

Out of scope for this work: threshold signing, FROST, multi-sig over the operator key. Those are protocol-level changes (a different DEP); they're a strictly larger lift.

---

## Design decisions (locked)

- **Thin PSBT path.** The signer BIP-340-signs sighashes; the daemon constructs PSBTs with a watch-only descriptor via BDK. Wallet logic stays where it is. The signer's job is "compute these signatures," not "manage UTXOs."
- **Anti-equivocation policy in v1.** A small `(ledger_id, max_seq_signed)` store on the signer, refusing regressions. Without this, the signer is a refactor without a security upside; with it, a compromised daemon can't get forks signed.
- **Socket-only transport.** Unix socket on a local path. Eventually a hole-punched UDP/QUIC transport can replace the socket; the wire protocol above the framing doesn't change. TLS is rejected.
- **Two transport keypairs, both sides explicit-pinned.** The signer has its own transport key (independent of the deposits seed); the daemon has its own. No TOFU. Operator runs both, knows both pubkeys, configures each end.
- **One signer pubkey on the daemon, allowlist of node pubkeys on the signer.** Asymmetric on purpose: one signer can serve many nodes (hot-spare or shared infra); a node trusts exactly one signer. Multi-signer failover is YAGNI for v1.

---

## Architecture

```
┌─────────────────────────────┐         ┌──────────────────────────────┐
│ deposits-node (no seed)     │         │ deposits-signer              │
│                             │         │                              │
│  Signer trait               │ ─────►  │  Holds: deposits seed        │
│   ├ LocalSigner (legacy)    │ socket  │         transport keypair    │
│   └ RemoteSigner ───────────┼────────►│         allowlist (node pks) │
│                             │         │         seq policy store     │
│  --signer-pubkey <pk>       │         │                              │
│  --signer-socket <path>     │         │  RPC: bip340_sign, ecdh,     │
│                             │         │       psbt_sign, etc.        │
└─────────────────────────────┘         └──────────────────────────────┘
```

**Crates:**
- `deposits-signer-api` — the `Signer` trait, `KeyPath` enum, RPC types, wire framing. No I/O. Both ends depend on this.
- `deposits-signer` — the binary. Holds the seed. Implements the server side.
- `deposits-node` — gains a `RemoteSigner` impl. Existing inline `secp.sign_schnorr(...)` calls are routed through `&dyn Signer`.

`LocalSigner` lives in `deposits-signer-api` (or a feature-flagged module) so daemon tests don't need to spin up the signer binary. `LocalSigner` reads the seed from `--seed-file` and keeps the existing behaviour bit-for-bit.

---

## Wire / auth

**Framing.** Length-prefixed CBOR (or msgpack — pick one) frames over the socket. JSON is fine for v1 if we want trivially-debuggable wire dumps; perf isn't a concern at this rate.

**Handshake (mutual challenge-response):**

1. Daemon connects to socket. Sends `Hello { node_pubkey, nonce_a }`.
2. Signer checks `node_pubkey` is in allowlist. Sends `HelloAck { signer_pubkey, nonce_b, sig_signer = sign(transport_key, nonce_a || node_pubkey) }`.
3. Daemon verifies `sig_signer` against the configured signer pubkey. Sends `Auth { sig_node = sign(transport_key, nonce_b || signer_pubkey) }`.
4. Signer verifies `sig_node`. Both sides derive a session key via X25519 ECDH on the two transport pubkeys (with the nonces mixed in for forward secrecy across reconnects).
5. All subsequent frames are AEAD-sealed with the session key.

About 80 LoC of crypto plus protocol enum types. No Noise framework dependency, no rustls. Uses the existing secp256k1 + a small AEAD (chacha20poly1305 already a transitive dep; otherwise add it).

**Why not just trust the socket's filesystem permissions?** They're enough for "is this process allowed to talk." They're not enough for the hot-spare future where the same wire protocol runs over a network transport. Keeping cryptographic auth from day one means the network case is "just change the framing"; not redoing the security model.

---

## Init / pinning UX

```
$ deposits-signer init --data-dir /var/lib/dsigner --seed-file /run/seed
generated transport keypair
signer transport pubkey: dsig1qrz...

$ deposits-signer run --data-dir /var/lib/dsigner --socket /run/dsigner.sock
deposits-signer listening on /run/dsigner.sock

$ deposits-node run \
    --signer-pubkey dsig1qrz... \
    --signer-socket /run/dsigner.sock \
    --network bitcoin --name alice ...
node transport pubkey: dnode1abc...
ERROR: signer rejected connection (node not in allowlist)

$ deposits-signer trust add dnode1abc...
allowlisted dnode1abc...

# restart node — it now connects.
```

Both pubkeys are bech32-encoded (HRP `dsig` for signer, `dnode` for node) so they're copy-paste-friendly and visually distinct.

---

## `Signer` trait shape

```rust
pub enum KeyPath {
    NostrIdentity,
    Operator,
    Cosigner { ledger_id: LedgerId },
    Wallet { account: u32 },
}

pub enum SigTag {
    Bip340Untagged,                  // raw BIP-340 over a 32-byte digest
    InvoiceCosign,                   // tagged hash "invoice_cosign_signing_message"
    Attestation,                     // DEP-04 subkey attestation
    // Add new domain separators here; signer applies the tagged hash so
    // the daemon can't reuse a sig from one domain in another.
}

pub trait Signer: Send + Sync {
    fn xonly_pubkey(&self, path: &KeyPath) -> Result<XOnlyPublicKey>;

    fn bip340_sign(
        &self,
        path: &KeyPath,
        tag: SigTag,
        // For Untagged: payload must be exactly 32 bytes.
        // For tagged variants: payload is the pre-tagged input, signer applies the tag.
        payload: &[u8],
        // Operator/Cosigner signs go through the seq-policy gate.
        // None for non-ledger contexts (e.g. invoice cosign).
        seq_context: Option<SeqContext>,
    ) -> Result<[u8; 64]>;

    fn ecdh(&self, path: &KeyPath, peer: &XOnlyPublicKey) -> Result<[u8; 32]>;

    // Sign Taproot inputs in the PSBT for the given wallet account. The
    // signer's BDK descriptor is private-key-aware; the daemon's is watch-only.
    fn psbt_sign(&self, account: u32, psbt: Psbt) -> Result<Psbt>;
}

pub struct SeqContext {
    pub ledger_id: LedgerId,
    pub seq: u64,
    // For cosign-side requests: the cosigner's own ledger head they're committing to.
    pub member_ledger_hash: Option<[u8; 32]>,
}
```

The `SeqContext` is what the anti-equivocation policy keys off. For operator-context signs, the signer enforces `seq > last_seq_signed[ledger_id]` and persists. For cosigner-context signs, it enforces `seq > last_seq_signed_as_cosigner[ledger_id]` *and* refuses to backdate `member_ledger_hash` (cosigner can't sign committing to an old chain head if a newer one has already been signed against).

NIP-04/NIP-44 stay in the daemon — they're symmetric crypto on top of `ecdh`. The signer only does the asymmetric step.

---

## Anti-equivocation policy details

Stored on the signer:
- `operator_seq[ledger_id] -> u64` (last seq we signed as operator)
- `cosigner_seq[ledger_id] -> u64` (last seq we signed as cosigner)
- `cosigner_head[ledger_id] -> [u8; 32]` (last `member_ledger_hash` we committed to when cosigning)

Backed by sled (smallest dep) or sqlite (more familiar). v1: sled.

**Policy:**
- Reject `bip340_sign` with `seq_context: Some(ctx)` when `path = Operator` if `ctx.seq <= operator_seq[ctx.ledger_id]`.
- Reject `bip340_sign` with `seq_context: Some(ctx)` when `path = Cosigner` if `ctx.seq <= cosigner_seq[ctx.ledger_id]`.
- Reject `bip340_sign` with `path = Cosigner` if `ctx.member_ledger_hash` is older than `cosigner_head[that_ledger]` (where "older" is determined by the signer fetching its own ledger head from the relay; alternatively, pin "monotonic counter on member ledger" in the same store).
- On accept: persist before returning the signature.

The "older than" check on `member_ledger_hash` is the harder one — the signer needs to either subscribe to its own ledger relay (gives it a real-time view of its head) or trust the daemon-supplied head and just enforce monotonicity per-ledger. v1: the latter, with a TODO to upgrade. A racing spare can't get a regression past the seq check anyway.

---

## Phasing

| Phase | Scope | Lands as |
|---|---|---|
| 1 | Audit signing call sites; categorize by KeyPath role; identify daemon vs CLI/recovery flows | doc / commits with no behaviour change |
| 2 | Define `Signer` trait + `LocalSigner` in `deposits-signer-api`; one PR | `deposits-signer-api` crate |
| 3 | Refactor daemon-path call sites to use the trait | one PR per cluster (`request_handlers`, `ledger_actor`, `nostr`, `wallet`) |
| 4 | `deposits-signer` binary + handshake + RPC server | new crate + binary |
| 5 | `RemoteSigner` client + integration test (signer over tmpdir socket; existing protocol tests pass) | `deposits-node` PR |
| 6 | Anti-equivocation policy + persistent store + tests for racing-spare scenario | `deposits-signer` PR |
| 7 | Init / trust-add UX, daemon CLI flags, doc | `deposits-tools` PR |

`node_cli/recovery.rs`, `node_cli/danger.rs`, `node_cli/reserves.rs` are operator-local one-shot flows — they reload the seed from `--seed-file` for the duration of the command. Routing them through the signer is *possible* (and probably worth doing in a phase 8) but blocks nothing for v1; they're explicitly out of scope.

---

---

## Phase 1 audit findings

72 signing-relevant call sites across 21 files. Categorized below.

### Existing abstraction worth building on

`deposits-core/src/message_validation.rs` already defines a `HandlerContext` trait with `sign_message(content: &[u8]) -> Option<[u8; 64]>` and `sign_schnorr(sighash: &[u8; 32]) -> Option<[u8; 64]>` methods — default impls fetch via `our_secret_key()`. This is the hook point; the daemon's `DepositsHandler` impls `HandlerContext` at `handler.rs:1577`. Phase 3 refactor is mostly: the daemon's `HandlerContext` impl routes through a `Signer` instead of returning the raw secret key, and `our_secret_key` becomes optional / phased out.

### Daemon-path call sites (phase 3 refactor scope)

| File | Calls | Role | Notes |
|---|---|---|---|
| `deposits-node/src/handler.rs:1364, 1591` | 1 sign + 1 secret-key getter | Operator | Cosignature on update; `our_secret_key()` returns the seed today |
| `deposits-node/src/node/ledger_actor.rs:569-570` | 1 keypair build + sign | Operator | `staged.update.operator_signature = secp.sign_schnorr(&msg, &keypair)` — primary operator-update sign path |
| `deposits-node/src/node/request_handlers/quorum.rs:285, 553` | 2 | Operator + Cosigner | Quorum begin / add member sign paths |
| `deposits-node/src/node/request_handlers/invoice.rs:239, 791` | 2 | Operator (tagged: invoice cosign) | Use `SigTag::InvoiceCosign` |
| `deposits-node/src/node/request_handlers/cosign.rs` | several | Cosigner | Cosign request response — biggest seq-policy beneficiary |
| `deposits-node/src/node/request_handlers/admin.rs:279, 284` | 2 | Operator | Lock + fulfill sigs |
| `deposits-node/src/node/request_handlers/custody.rs` | several | Operator | Custody flow |
| `deposits-node/src/node/dispute.rs` | several | Operator + Cosigner | Dispute-side signs |
| `deposits-node/src/node/init.rs` | 1+ | Operator | Init-time signs |
| `deposits-node/src/node/ledger_queries.rs` | 1+ | Operator | Query-side sign |
| `deposits-node/src/nostr.rs` (~12 sites) | nip04::encrypt/decrypt + 1 event sign at :4425 | NostrIdentity (ECDH + sign) | `self.keys.secret_key()` for NIP-04, `self.secret_key` for event sign |
| `deposits-node/src/wallet.rs:1134` | 1 sign_ecdsa | Wallet | **Legacy P2WSH single-sig** — needs ECDSA-sighash signer method, not just BIP-340 |
| `deposits-node/src/wallet.rs:806, 933, 1281, 1549` | 4 BDK wallet.sign(psbt) | Wallet | BDK Taproot signing — needs descriptor split (watch-only on daemon, key-aware on signer) |
| `deposits-node/src/wallet.rs:1776` | 1 keypair build + sign | Wallet | One-off Taproot sign outside BDK |

### deposits-core helpers (phase 2 trait + phase 3 caller updates)

| File | Functions | Action |
|---|---|---|
| `deposits-core/src/signing.rs` | `create_deposit_guarantee_signature`, `create_payment_signature`, `create_payment_authorization_signature`, `create_deposit_offer_signature`, `create_withdrawal_signature` | Each takes `&SecretKey`. Refactor: split each into a payload-builder (returns the bytes to sign + the tag) and let callers use `signer.bip340_sign_tagged(...)`. Add `SigTag` variants for each domain |
| `deposits-core/src/message_validation.rs` | `HandlerContext::sign_message`, `sign_schnorr`, `our_secret_key` | Replace default impls; add a `signer: Arc<dyn Signer>` accessor; the two sign methods route through it. Eventually delete `our_secret_key` |
| `deposits-core/src/descriptor.rs:249` | Test-only sign | Leave as-is (test) |

### Out of scope for v1 (operator-local one-shot CLI flows)

| File | Sites | Why deferred |
|---|---|---|
| `deposits-node/src/node_cli/recovery.rs` | ~14 | Operator runs interactively with `--seed-file`; reload seed for the duration of the command. Routing through signer is a phase-8 mechanical refactor |
| `deposits-node/src/node_cli/danger.rs` | ~7 | Same — danger commands reload seed |
| `deposits-node/src/node_cli/reserves.rs` | 1 | Same |

### Not daemon code (separate concern)

| File | Sites | Notes |
|---|---|---|
| `deposits-node/src/bin/htlc-agent.rs` | 1 | Standalone tool, ad-hoc keypair |
| `deposits-node/src/bin/transfer-simulator.rs` | 1 | Standalone tool |
| `deposits-node/src/bin/nostr-bench.rs` | 1 | Bench harness |

### Phase-3 finish state (post-implementation)

5 of 7 clusters fully migrated, 2 with documented blockers requiring
trait extensions:

  - **Cluster 1 (handler.rs / ledger_actor.rs)** — done.
  - **Cluster 2 (dispute / init / ledger_queries)** — done.
  - **Cluster 1.5 (request_handlers/*)** — done. admin.rs's lock/fulfill
    sigs deferred (depositor-key derivation, see follow-ups).
  - **Cluster 5 (deposits-core/signing.rs)** — done for the daemon-path
    `create_deposit_offer_signature` site; the other helpers
    (`create_payment_signature`, `create_withdrawal_signature`,
    `create_deposit_guarantee_signature`, etc.) are called from
    depositor-side flows in `node_cli/{lightning,withdraw}.rs` that
    derive depositor keys via the daemon's master seed. Splitting their
    digests out is mechanical but lands with the keypath-Signer extension.

  - **Cluster 4 (wallet.rs)** — partially done.
    - The two manual sign sites (`build_rotation_to_taproot` legacy P2WSH
      ECDSA, `sign_custody_transfer_sighash` Tapscript script-spend) are
      migrated to take `&dyn Signer` and route through
      `signer.ecdsa_sign_sighash` / `signer.bip340_sign`.
    - The four BDK `wallet.sign(&mut psbt)` sites (806, 933, 1281, 1549)
      remain. **Blocker:** BDK 1.0's `Wallet::sign` finds the secret key
      via the descriptor's xprv. To migrate, the daemon needs a watch-only
      descriptor variant + per-input sighash extraction, with each
      sighash routed through the Signer. ~200-400 LoC of BDK glue;
      separable from the rest of the work.

  - **Cluster 3 (nostr.rs)** — documented blocker, no migration yet.
    - **Event signing** (`sign_with_keys(&self.keys)`, ~30 sites) can be
      replaced by computing the event id, calling `signer.bip340_sign`,
      and using `UnsignedEvent::add_signature(sig)` — straightforward.
      Or by implementing `nostr_sdk::NostrSigner` on a delegate.
    - **NIP-04 encrypt/decrypt** (`nip04::encrypt(self.keys.secret_key(),
      peer, ...)`, ~12 sites) is the **load-bearing blocker**. NIP-04
      derives its symmetric key by taking the *raw X coordinate* of the
      ECDH shared point (`ecdh::shared_secret_point` followed by
      truncation to 32 bytes) — **not** the SHA-256-hashed
      `SharedSecret` value our `Signer::ecdh` currently returns. They
      are different bytes; using the wrong one produces unreadable
      ciphertext.
    - **Path forward:** add a new trait method
      `Signer::shared_secret_point(peer) -> [u8; 32]` returning the raw
      X coord, alongside the existing `ecdh()`. LocalSigner implements
      it via `bitcoin::secp256k1::ecdh::shared_secret_point`; RemoteSigner
      adds a new `SignOp::SharedPoint` variant on the wire; `deposits-signer`
      dispatches it. Once that lands, the NIP-04 sites migrate
      mechanically and `nostr.rs` can drop the `Keys::new(secret_key)`
      construction. (NIP-44 uses a different scheme — HKDF over the
      compressed point — and would need its own method or a unified
      `shared_point_compressed`. NIP-44 is feature-gated; optional v2.)

### Trait-shape refinements from the audit

1. **Add `ecdsa_sign_sighash`** to the `Signer` trait. The legacy P2WSH path in `wallet.rs:1134` needs ECDSA, not BIP-340. Single call site, but it's on the daemon hot path and we can't pretend it isn't there.
2. **`HandlerContext` is the right insertion point** — already wires `sign_message` / `sign_schnorr` through the daemon. The `Signer` trait becomes a field on the daemon's `HandlerContext` impl; legacy `our_secret_key()` returns `None` once the migration is complete.
3. **`SigTag` enum gets concrete variants now**: `Bip340Untagged`, `InvoiceCosign`, `DepositGuarantee`, `Payment`, `PaymentAuthorization`, `DepositOffer`, `Withdrawal`. The signing.rs functions become payload-builders + tag pairs; signer applies the domain hash. Rules out daemon reusing a payment sig as a withdrawal sig.
4. **PSBT shape confirmed thin**: BDK descriptors are wallet-internal, but the legacy P2WSH ECDSA already uses the raw `sign_ecdsa(sighash, &operator_secret)` pattern. The watch-only-descriptor + remote-sighash-sign path matches both. We migrate to a watch-only `bdk_wallet::Wallet` on the daemon that calls `signer.bip340_sign(KeyPath::Wallet { account }, ...)` or `signer.ecdsa_sign_sighash(...)` per input.

---

## Open follow-ups (not v1)

- **`member_ledger_hash` freshness on the signer.** Have the signer subscribe to its own ledger relay and refuse cosignature requests committing to a head it doesn't recognize as current.
- **Node identity ≠ operator identity.** Today the daemon uses the operator's seed-derived key for *everything* on Nostr — outer event signatures, ECDH for NIP-04/44, gift-wrap seals. Of these, only inbound NIP-04 decrypt (clients encrypting Kind 20101 to the operator npub) and the inner `operator_signature` / cosignatures / invoice cosigns *require* the operator key. Outer event sigs and outbound encrypts are convention. A future protocol annex (DEP-04-shaped operator→node-host delegation) would let the daemon sign Nostr outers with its own per-host key and only call the Signer for the genuinely operator-bound ops. Cuts ~80% of Signer round-trips on a busy daemon. Worth doing once RemoteSigner load is real; not before.

- **Hole-punched transport.** Same RPC, different framing. libp2p / NAT traversal is the heavy lift, the wire above it is unchanged.
- **Hot-spare daemon coordination.** Leader election layer between hot-spare nodes; the signer's seq policy is the safety net, but you don't want to rely on it for steady-state correctness.
- **Threshold signing.** Different shape entirely; would need a DEP because slashing semantics change. Out of scope here.
- **HSM / hardware signer.** Run `deposits-signer` on an air-gapped host with the wire transport replaced by a hardware path. v1's clean abstraction makes this a swap, not a redesign.
- **LDK remote signer.** Separate keys, separate infra, LDK upstream supports it. Wire after `deposits-signer` is solid.
- **`node_cli/*` flows through the signer.** Recovery and danger commands currently reload the seed directly; routing them through the signer is mechanical but blocks nothing.

- **Trait extension for derivation-path key selection.** The current `Signer` trait wraps a single key (the operator/identity key). `admin.rs`'s lock/fulfill sigs and `node_cli/{lightning,withdraw}.rs` flows derive *depositor* keys via `derive_deposit_key_at(index)` to act on behalf of internal deposits the daemon owns. These should go through the same Signer — the daemon holds the master seed, the signer holds the master seed in v1 — but the trait needs to grow a derivation path parameter. Cleanest shape is to add a `KeyPath` (or `KeySelector`) enum and a `bip340_sign_at(path, ctx, digest)` method (or thread the path through `SignContext`). LocalSigner extends to take an `Xpriv` and derive on demand; RemoteSigner sends the path over the wire. This unblocks routing every signing call site, including admin and node_cli, through the same plumbing.
