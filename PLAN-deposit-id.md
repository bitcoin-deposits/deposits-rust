# PLAN — `deposit_pubkey` → `deposit_id` cut + descriptor-aware receive witness

## Why

Every Nostr-request shape that names a deposit currently uses `deposit_pubkey`
(33-byte compressed hex) as the identifier. That bakes in the assumption that
every deposit's spendability is `pk(<single key>)`. Three knock-on problems:

1. **Identity by recompute, not lookup.** Daemon handlers do
   `compute_deposit_id(format!("pk({})", deposit_pubkey_hex))` to derive the id.
   For a `multi(2, ...)` deposit opened earlier with a different descriptor,
   the recomputed id won't match the registry entry — invoices/withdrawals/
   transfers silently miss the deposit.

2. **Receive-sig is single-Schnorr.** When `receive_requires_sig` is set, the
   daemon decodes a single hex pubkey and runs `verify_schnorr` against one
   signature. For a multisig deposit there's no single key to verify against;
   the policy is whatever the descriptor says.

3. **lnurl URLs leak the pubkey.** `pubkey@<ledger>.<domain>` exposes 33 bytes
   of public material every time someone hands out their LN address.
   `deposit_id` is a 16-byte hash of the descriptor — strictly less leaky.

`DepositOpen` on the on-chain TLV codec already carries `descriptor: String` +
`deposit_id`, no `deposit_pubkey`. The protocol itself is fine. The problem is
the Nostr-request layer between wallets/lnurl and the operator daemon, plus
the wallet's `deposits.json`-on-disk schema. Both still treat the pubkey as
the canonical identifier.

The descriptor-verification machinery exists too:
`deposits_core::descriptor::verify_witness(descriptor, witness, msg)` — pk()
fast path + miniscript fallback. The receive-sig sites just don't call it.

## End state

- **Identifier is `deposit_id` everywhere.** Every Nostr request that names an
  existing deposit sends `deposit_id` (32 hex chars). Every response that
  echoes the deposit emits `deposit_id` + `descriptor`, never `deposit_pubkey`.

- **Create-time uses `descriptor` directly.** `deposit_open` and `make_offer`
  accept a `descriptor: String` (free-form miniscript). Daemon computes
  `deposit_id` from descriptor at create time and stores both. No
  `format!("pk({}, ..."` in the daemon.

- **Receive-sig is `receive_witness: DescriptorWitness`.** The witness is a
  `{ stack: [hex, ...] }` shape (existing protocol type). Verification calls
  `deposits_core::descriptor::verify_witness(deposit.descriptor, &witness,
  &padded_deposit_id)` — descriptor-aware, supports `pk()`, `multi()`, and
  any miniscript the existing fallback handles.

- **lnurl URL: `<deposit_id>@<ledger_bech32>.<domain>`.** Gateway URL routes
  use `:deposit_id`, forwarded to the operator's `make_invoice` as
  `deposit_id`.

- **Wallet's `deposits.json`** keyed by `deposit_id` with `descriptor` as the
  spendability source-of-truth. Local key material moves to a separate
  `local_keys` substructure that's a wallet-implementation detail (only
  meaningful for `pk()` deposits the wallet generated itself, or for
  multisig deposits where the wallet holds one of the keys).

- **`replay-ledger`'s defunct TLV-24 entry** (no codec path emits it) deleted.

**Hard cut.** No legacy `deposit_pubkey` fallback. We're getting close to
external users; this is the last clean window.

## Sub-plan: scope

### Wave 1 — daemon-side (deposits-node)

#### 1a. Helper

Add `parse_deposit_id_param(request) -> Result<DepositId, String>` to
`deposits-node/src/node/request_handlers/deposits.rs`. Used by every
existing-deposit handler.

#### 1b. Handler-by-handler conversion

Every handler reading `request.params.get("deposit_pubkey")` becomes a
`deposit_id` reader, looking up `ledger.state.deposits.get(&deposit_id)` to
get the deposit's `descriptor` when needed for witness verification. Drop
all `format!("pk({})", deposit_pubkey)` synthesis.

| Handler | File:line | Wire change |
|---|---|---|
| `process_deposit_open_request` | `deposits.rs:154` | Param: `deposit_pubkey` → `descriptor` (operator computes id from it). Response: `deposit_id` + `descriptor`. |
| `process_make_offer_request` | `deposits.rs:417` | Param: `deposit_pubkey` → `descriptor` (deposit doesn't exist yet at offer time, so we need the descriptor to compute id and to populate `DepositOffer.descriptor`). |
| `process_offer_status_request` | `deposits.rs:744` | Optional fallback param `deposit_pubkey` → just `deposit_id`. |
| `process_balance_query_request` | `deposits.rs:871` | `deposit_pubkey` → `deposit_id`. Response emits `deposit_id` + `descriptor`. |
| `process_deposit_credit_request` | `deposits.rs:1003` | `deposit_pubkey` → `deposit_id`. |
| `process_make_invoice_request` | `invoice.rs:26` | `deposit_pubkey` → `deposit_id`. `receive_signature` → `receive_witness`. Response: `deposit_id`. |
| `process_pay_invoice_request` | `invoice.rs:384` | Same pattern as make_invoice. |
| `process_withdraw_request` | `transfer.rs:31` | Drop `deposit_pubkey`; already takes `deposit_id`. The `signature` field becomes `witness: DescriptorWitness` — `lock_withdrawal` already takes `DescriptorWitness`, just push it from the wire instead of synthesizing it. |

#### 1c. `node_cli/admin.rs:223` (admin buffer-fill flow)

`admin buffer fill <index>` resolves the buffer's deposit_pubkey from the
local `buffer_indices.json` registry, then sends `make_invoice` to the
daemon. Wave 2 territory really, but lives in node_cli; flag it for parity
with Wave 1.

#### 1d. `htlc-agent.rs:646`

Same shape — reads `deposit_pubkey` out of a deposit-offer response.
After Wave 1 it should read `deposit_id` from the response.

#### 1e. `transfer-simulator.rs` (3 sites)

Synthetic test bin that writes `"deposit_pubkey": info.pubkey_hex` into
synthesized requests. Migrate when we update the rest of the senders.

#### 1f. `create_deposit_offer` and `lock_withdrawal` helper signatures

`create_deposit_offer` currently takes `deposit_pubkey: PublicKey` only to
recompute id. Should take `descriptor: &str` and compute id from it (offer
needs to populate `DepositOffer.descriptor` anyway).

`lock_withdrawal` already takes `deposit_id: DepositId` + `DescriptorWitness`
— no change, just wire it from the request directly.

#### 1g. `receive_requires_sig` flow generalization

Three sites verify a `receive_signature` (single Schnorr) today:
`make_offer` (`deposits.rs:553`), `make_invoice` (`invoice.rs:43`), and
arguably wherever else the flag gates. Each:

```rust
// New shape:
let witness: DescriptorWitness = serde_json::from_value(
    request.params.get("receive_witness")
        .ok_or("Deposit requires receive_witness")?.clone()
)?;
let mut msg = [0u8; 32];
msg[..16].copy_from_slice(&deposit_id);
deposits_core::descriptor::verify_witness(
    &deposit.descriptor, &witness, &msg
).map_err(|e| format!("Invalid receive_witness: {}", e))?;
```

The padded-id-as-message convention stays the same as today.

For `make_offer` of a *new* deposit (no registry entry yet), the descriptor
is the one in the request (since the deposit doesn't exist yet) — same
`verify_witness` call, just sourced from the request param instead of
`deposit.descriptor`.

### Wave 2 — clients

| Crate / file | Sites | Change |
|---|---|---|
| `deposits-wallet/src/wallet_cli/deposit.rs` | ~10 | Senders: submit `descriptor` at open / `deposit_id` everywhere else. Storage: `deposits.json` keyed by `deposit_id` with `descriptor`; `pubkey` field renamed `local_pubkey` and only stored for wallet-owned `pk()` deposits. |
| `deposits-wallet/src/wallet_cli/payments.rs` | ~5 | Same. |
| `deposits-wallet/src/wallet_cli/swap.rs` | 1 | Reads pubkey from local deposits.json — adapt to new schema. |
| `deposits-node/src/node_cli/{deposit,admin,lightning,withdraw,nostr_commands}.rs` | ~10 | CLI senders mirror wallet senders. |
| `deposits-lnurl/src/bin/deposits-lnurl.rs` | ~5 | URL path `:deposit_id` (already named), forwarded as `deposit_id` (currently labeled `deposit_pubkey`). Doc comment updated. |
| `deposits-tools/docker/wallet-cli.sh` | 1 (`lnurl` subcommand) | Print `<deposit_id>@<ledger>.<domain>`. (Already drafted in this session, was reverted as part of atomic-cut hygiene.) |
| `deposits-tools/bin/setup-lnurl.sh`, `test-lightning-deposits.sh`, `setup-htlc-agent.sh`, `test-quorum.sh` | scripts | Send `deposit_id` / `descriptor`. |
| `deposits-web/wallet/index.html` + `tlv-catalog.js` | several | Web wallet's `make_invoice`, `deposit_open`, etc. requests rewritten. |

### Wave 3 — tests + cleanup

| File | Change |
|---|---|
| `deposits-test/tests/{invoice_cosign,cross_ledger_route,lnurl_zap}.rs`, `deposits-test/src/regtest.rs` | Fixtures + helpers send `deposit_id` + `descriptor`. |
| `deposits-tools/tests/{invoice_tracking_test,nip17_gift_wrap_test}.rs` | Fixtures. |
| `deposits-node/tests/gift_wrap_test.rs` | Hard-coded JSON `{"deposit_pubkey": "02abc..."}` → `{"deposit_id": "...", ...}`. |
| `deposits-tools/src/bin/replay-ledger.rs` | Drop `24 => ("deposit_pubkey", Enc::Pubkey)` line — no codec path emits TLV-24. |
| **New regression test** | Open a `multi(2, pk(A), pk(B), pk(C))` deposit. `make_invoice` with a 2-of-3 `receive_witness` succeeds. With only 1 sig, fails with "Invalid receive_witness". Validates the descriptor-aware path end-to-end. |

## Sub-plan: ordering

Wave 1 → Wave 2 → Wave 3, all landed together. Each wave individually leaves
either daemon ↔ wallet or test fixtures inconsistent, so the sequence is
mostly an organizational aid, not a step-by-step deploy plan. **No legacy
fallback** at any wave boundary — this is a hard cut.

End-of-PR validation:

1. `cargo test -p deposits-node --lib` (25 lib tests)
2. `cargo test -p deposits-signer-api --lib` (23 lib tests)
3. `cargo test -p deposits-node --test remote_signer_e2e` (12 e2e tests)
4. `cargo test -p deposits-node --test gift_wrap_test`
5. `cargo test -p deposits-test --test invoice_cosign`
6. `cargo test -p deposits-test --test lnurl_zap`
7. **New** `cargo test -p deposits-test --test multi_descriptor_deposit` (regression)
8. `bash bin/setup.sh 3` → activate cluster → wallet `open`/`offer`/`invoice`/`withdraw` end-to-end smoke
9. lnurl smoke: gateway resolves `<deposit_id>@<ledger>.<domain>` → invoice payable

## Sub-plan: estimated diff size

Rough estimate:

- Wave 1: ~12 files, ~600-800 LoC changed (mostly handler bodies)
- Wave 2: ~15 files, ~400-600 LoC changed
- Wave 3: ~8 files, ~200-300 LoC changed (mostly fixture renames)
- New multi-descriptor test: ~150-200 LoC

Total: ~30-35 files, ~1500-2000 LoC. One PR, one cluster smoke at the end.

## Open questions

1. **Wallet-storage schema migration.** Existing `deposits.json` files in the
   field have `"pubkey": "..."` at the root. After the cut, the schema
   changes. Options:
   - Migrate on load (read either shape, write the new one).
   - Hard cut (clear `deposits.json` on first load of a new wallet binary).
   - We're pre-1.0; hard cut is fine for this iteration.

2. **`receive_witness` for non-`pk()`/`multi()` descriptors.** The existing
   `verify_witness` falls back to a miniscript interpreter. That should
   handle most reasonable miniscripts, but exotic ones (preimage hashlocks,
   `after`/`older` timelocks combined with keys) may not have a clean
   "off-chain witness" interpretation. For this PR: defer to whatever
   `verify_witness` decides. Add an explicit "policy not supported for
   off-chain consent" error for descriptors the verifier can't satisfy
   off-chain.

3. **`DepositOffer` wire shape on Nostr.** Already carries `descriptor`, so
   no change to the offer payload itself — only to the `make_offer` request
   that creates it.

4. **TLV-24 in replay-ledger:** confirmed dead by codec audit — no
   `LedgerOperation` variant emits or reads field 24. Safe to delete.
