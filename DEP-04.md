# DEP-04: Peer Messaging

## Abstract

This document specifies the Nostr-based peer messaging protocol. All communication between wallets and operators, and between operators, uses Nostr events with specific Kind numbers, tags, and content formats.

## Relay Architecture

The protocol uses two types of relays:

- **Operator relays**: handle ephemeral request/response traffic. Each operator monitors one or more relays for incoming requests.
- **Ledger relay**: stores durable events (ledger updates, disputes, fraud proofs). Any relay that retains Kind 9100 events can serve as a ledger relay.

Wallets connect to both: operator relays for requests, ledger relays for reading history and advertisements.

## Event Kinds

### Ledger Protocol (operator ↔ wallet, operator ↔ operator)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 9100 | Ledger Update | Durable | deposits-node | Signed ledger update (base64 TLV, see DEP-02) |
| 9101 | Fraud Proof | Durable | deposits-node | Fraud proof broadcast (JSON, see DEP-06) |
| 9103 | Dispute | Durable | deposits-node | Custody dispute notification (JSON) |
| 9104 | Recovery Agreement | Durable | deposits-node | Quorum member recovery agreement (JSON) |
| 9106 | Custody Lottery Reveal | Durable | deposits-node | Disputant's preimage reveal during the on-chain lottery (JSON, see DEP-06 §Phase 3) |
| 20101 | Request | Ephemeral | deposits-node, wallet | Wallet-to-operator request (JSON) |
| 20102 | Response | Ephemeral | deposits-node | Operator-to-wallet response (JSON) |

### Discovery and Pricing (operator → relay → wallet)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 39100 | Advertisement | Replaceable | deposits-node | Operator terms, fees, reserves (JSON, NIP-33, `d`=ledger ID) |
| 39101 | Price Oracle | Replaceable | deposits-node | BTC/USD price (JSON, NIP-33, `d`=`btcusd`) |
| 39102 | Courier Advertisement | Replaceable | deposits-node | Cross-ledger routing capacity and fees (JSON, NIP-33, see DEP-13) |
| 39104 | Bridge Advertisement | Replaceable | any deposit holder with an LN node | Lightning ↔ ledger bridging capacity and fees (JSON, NIP-33, see DEP-10) |

### Identity Verification (wallet ↔ lightning-verifier ↔ operator)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 25500 | Verify Request | Ephemeral | wallet | Wallet-to-verifier verification request (JSON) |
| 25501 | Verify Response | Ephemeral | lightning-verifier | Verifier-to-wallet response: invoice, challenge, or result (JSON) |
| 55502 | Domain Attestation | Durable | lightning-verifier | Published attestation linking npub to lightning address (JSON) |

### Wallet Infrastructure (wallet → relay → wallet)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 10301 | Subkey Management | Replaceable | *reserved* | Subkey attestation/revocation list (JSON) |
| 30078 | Wallet State | Replaceable | wallet | NIP-04 encrypted state backup to self (NIP-78, `d`=`deposits-wallet/state`) |

## Event Tags

| Tag | Usage | Description |
|---|---|---|
| `d` | Kind 9100 | Ledger ID prefix (16 hex chars, truncated for relay filtering). |
| `d` | Kind 39100 | Ledger ID (64 hex chars). Enables NIP-33 replacement. |
| `seq` | Kind 9100 | Sequence number (for relay-side ordering) |
| `prev` | Kind 9100 | Previous chain hash (hex) |
| `hash` | Kind 9100 | Current hash (hex) |
| `t` | Kind 9100 | Operation discriminant number (for relay-side filtering) |
| `i` | Kind 9100 | Affected deposit IDs (for per-deposit filtering) |
| `l` | Kind 20101, 20102 | Ledger ID (for relay-side request routing) |
| `action` | Kind 20101 | Request action name |
| `d` | Kind 39102 | Courier pubkey (hex). Enables NIP-33 replacement per courier. |
| `service` | Kind 39102 | Service type (e.g., `htlc_routing`) |
| `n` | Kind 39102 | Network name |
| `p` | Kind 20101 | Courier pubkey (for courier-addressed requests, see DEP-13) |
| `p` | Kind 9101 | Accused operator pubkey |
| `l` | Kind 9106 | Ledger ID (hex) — disputed ledger this reveal applies to |
| `member` | Kind 9106 | Revealing disputant's pubkey (hex) |
| `d` | Kind 30078 | App namespace (`deposits-wallet/state`). Enables NIP-78 replacement. |
| `p` | Kind 25500 | Verifier pubkey (hex) |
| `e` | Kind 25501 | Request event ID (for response matching) |
| `p` | Kind 55502 | Verified user pubkey (hex) |

## Request/Response Protocol

Wallets send ephemeral Kind 20101 events to operator relays. The content is JSON with an `action` field and operation-specific parameters. The operator processes the request and responds with a Kind 20102 event tagged with the request's event ID.

### Request Actions

| Action | Description | See |
|---|---|---|
| deposit_open | Open a new deposit | DEP-08 |
| make_offer | Create on-chain funding offer | DEP-10 |
| make_invoice | Create lightning invoice | DEP-10 |
| pay_invoice | Pay lightning invoice from deposit | DEP-10 |
| withdraw | On-chain withdrawal | DEP-10 |
| transfer_lock | Lock funds for transfer | DEP-09 |
| transfer_complete | Complete a transfer | DEP-09 |
| balance_query | Query deposit balance | DEP-08 |
| cosign_update | Request co-signature on update | DEP-02 |
| cosign_offer | Request co-signature on offer | DEP-10 |
| cosign_invoice | Request co-signature on invoice | DEP-10 |
| partner_add | Add quorum member | DEP-05 |
| partner_join | Record quorum join | DEP-05 |
| request_route | Request cross-ledger route from courier | DEP-13 |
| confiscation_sign | Request co-signature on a confiscation TX (dispute) | DEP-06 |
| forfeit_sweep_sign | Request co-signature on a forfeit-sweep TX (arm-and-reveal forfeiture) | DEP-06 |
| issue_hold_invoice | Ask a bridge for a hold invoice against a wallet-supplied hash | DEP-10 |
| quote_invoice | Ask a bridge for a per-invoice pay quote | DEP-10 |

### Response Format

```json
{
  "success": true,
  "result": { ... },
  "error": null
}
```

## Advertisements (Kind 39100)

Operators publish NIP-33 replaceable events advertising their terms. The `d` tag is the ledger_id, ensuring only the latest advertisement per ledger is retained. Content includes:

- `operator_pubkey` — the operator's protocol-level secp256k1 pubkey (33-byte compressed hex). This is the trust anchor: slashing, ledger updates' `operator_signature`, and on-chain custody all flow from this identity. Wallets MUST verify the advertisement's outer Nostr event signature against this key.
- `delegate_pubkey` — *(optional, since 2026-05)* the daemon's per-host **delegate Nostr key** (33-byte compressed hex). When non-empty, this is the pubkey wallets address Nostr-layer messaging to (NIP-04 DM recipient, Kind 9100 event author). The operator's protocol-level key never leaves the signer; the delegate handles everything else. Empty (`""`) on advertisements published by daemons that haven't been moved off the "operator key for everything" model — wallets MUST then fall back to `operator_pubkey` for messaging. See §Operator → Delegate Delegation below.
- Reserves amount (the deposit-capacity portion of the on-chain UTXO)
- Collateral amount (the security-bond portion; mirrors `collateral_amount_msats` from the ledger's most recent `LedgerOpen` / `QuorumBegin`)
- Fee schedules (periodic and transfer)
- Deposit limits (min/max)
- Access-control flags (whether `deposit_open` requires an attestation; allowed lightning-address domains)
- Relay URL
- Operator's observed Bitcoin chain tip at publish time (informational; clients that need a fresh tip SHOULD prefer the Kind 39101 price-oracle stream — see §Price Oracle below)
- `guarantees` — *(optional)* a machine-readable guarantee matrix that wallets route on. See §Guarantee Matrix below.
- `capabilities` — *(optional)* the operator's advertised DEP-16 capability set. See §Capabilities below.

Earlier drafts also carried `total_obligations` and `available_headroom`. Both were dropped — the operator can trivially inflate them with self-paid Lightning invoices, so they're not reliable trust signals. Wallets that need capacity information should either discover a courier already holding funds on this ledger, or trust the protocol invariant `reserves ≥ obligations` enforced by the quorum's co-signers.

Wallets discover operators by fetching Kind 39100 events from ledger relays.

### Guarantee Matrix

A guarantee matrix is a list of `(regime, amount-range, shape, honesty, time-profile)` rows. Wallets pick the row that matches the operation they're about to perform and route accordingly: an "online receive" path may demand `settlement_atomic`, falling back to `deterrence` only when nothing stronger is offered for the amount.

```jsonc
"guarantees": [
  {
    "regime": "transfer_internal",
    "min_msats": 0,
    "max_msats": 18446744073709551615,
    "shape": "settlement_atomic",
    "honesty": "operator_and_quorum",
    "time_profile": { "happy_path_blocks": 1, "worst_case_blocks": 6 }
  },
  {
    "regime": "invoice_receive",
    "min_msats": 0,
    "max_msats": 18446744073709551615,
    "shape": "deterrence",
    "honesty": "operator_and_quorum_and_ln",
    "time_profile": { "happy_path_blocks": 1, "worst_case_blocks": 720 }
  }
]
```

**Canonical regime names** (controlled vocabulary, open-ended for forward compatibility):

| Regime | Meaning |
|---|---|
| `onchain_credit` | Wallet sends bitcoin on-chain; operator credits the deposit after confirmations. |
| `onchain_withdraw` | Wallet asks the operator to broadcast a withdrawal to a wallet-controlled address. |
| `invoice_receive` | Wallet receives a Lightning payment via the HTLC-bridge model (DEP-10 §Receive). The wallet picks any bridge offering this service (the operator itself, or any third-party deposit holder with an LN node), generates the preimage, hands the bridge only the hash. The bridge issues a hold invoice; the on-ledger `TransferLock` is structurally bound to the upstream HTLC. Always `shape: settlement_atomic`, `honesty: bridge_only` — the bridge cannot claim upstream without the preimage appearing in a cosigned ledger record. The operator advertising this row asserts that their ledger supports the bridge mechanic (when-supplied BOLT-11 aux verification in the cosignature flow — DEP-10 §"Bridge cosigner rules"); it does NOT mean the operator itself is the bridge. |
| `invoice_receive_legacy_deterrence` | Wallet receives a Lightning payment via the operator-held-preimage path (DEP-10 §"Offline receive"): operator's LN node holds the preimage and commits `InvoiceCredit` unilaterally. `shape: deterrence`, `honesty: operator_only`. Provided for offline-receive use cases (LNURL gateways, permanent-cold-storage deposits) where the wallet cannot come online during the HTLC window. Wallets seeking the atomic path MUST refuse operators that only advertise this row. |
| `invoice_pay` | Wallet pays a Lightning invoice via a bridge (DEP-10 §Pay). The wallet locks the (invoice amount + bridge service fee) to the bridge's deposit via a standard `TransferLock`; the bridge pays the invoice via LDK and `TransferCompletes` revealing the preimage. `shape: settlement_atomic` for the locking step; actual payment outcome still subject to LN reachability (lock times out and refunds if the bridge fails to route). Bridges set their own service fees per invoice or per published schedule; this DEP-04 row asserts the operator's ledger supports the bridge mechanic, not that the operator itself runs a bridge. |
| `transfer_internal` | Transfer between two deposits on the same ledger. |
| `transfer_courier` | Cross-ledger transfer via an HTLC/PTLC courier. |

**Shape** is one of:

- `settlement_atomic` — a quorum cosignature is required before the operator's commit; the credit and the receipt are tied together in a single signed update. Fraud requires a quorum collusion.
- `deterrence` — the operator commits unilaterally and the wallet's recourse is the fraud proof; uncredited-payment evidence triggers slashing post-hoc. One confirmed theft costs the operator their entire collateral, so the upside of stealing a single payment is bounded by what the payment alone produced.
- `advisory` — no protocol-level enforcement; reputation only. Used for operations the protocol doesn't otherwise gate (e.g. routing-policy choices on outbound Lightning payments).

**Honesty** is one of `operator_only`, `operator_and_quorum`, `operator_and_quorum_and_ln`, `operator_and_courier`, `bridge_only`. The `bridge_only` value (used by the HTLC-bridge `invoice_receive` row) means the only party whose honesty matters is the bridge the wallet selected — and even the bridge cannot steal, only refuse service, since its upstream claim is gated on the wallet's on-ledger reveal.

**Time profile** carries `happy_path_blocks` (expected wait under normal conditions) and `worst_case_blocks` (bounded wait under the degraded conditions this regime tolerates).

**Defaults and forward compatibility.** Operators MAY publish multiple rows for the same regime over disjoint amount ranges (e.g., `settlement_atomic` up to 1 BTC, `deterrence` above). Wallets MUST treat absence of the `guarantees` field as *"no commitment"* rather than *"no protection"* — older daemons published advertisements before this field existed. A wallet that doesn't recognize a regime name SHOULD skip the row and continue rather than abort. Adding new regime names is a non-breaking codec change.

**Trust path.** The matrix is signed by the operator's Nostr event signature, so a wallet who trusts `operator_pubkey` for the advertisement trusts the matrix. The matrix is a *promise*, not a *proof* — the protocol-level guarantees come from the deposit script, the quorum, and the slashing economics. A misadvertised matrix that an operator then fails to honor is itself a reputational signal but not directly slashable.

### Capabilities

The `capabilities` field projects the operator's DEP-16 capability set (see DEP-16 §capability) to three flat lists, so wallets can filter operators by the descriptor primitives they implement without reaching for the calculus directly.

```jsonc
"capabilities": {
  "obligations":  ["pk", "pk_h", "pk_any", "pk_threshold", "hashlock", "pointlock", "attest"],
  "state_preds":  ["older", "after", "amount_at_most", "destination_is", "balance_at_least", ...],
  "value_fns":    ["add", "sub", "mul", "div", "min", "max", "pct", "bps", "deposit_balance", ...]
}
```

Names use the canonical lowercase spec spelling — `pk_threshold` for the n-of-m signature obligation, `pointlock` for the PTLC primitive, `hashlock` for the four-hash HTLC obligation. Wallets compare with `contains`.

**Default semantics.** An empty `capabilities` (or its absence) means *"operator did not publish capabilities"*. Wallets MUST then assume only the protocol-mandated minimum (`pk`, `pk_h`, `hashlock`, `older`, `after`), in line with `CapabilitySet::minimum()` in the calculus. Wallets that need an extended primitive — most notably `pointlock` for PTLC courier routes (DEP-13 §"Courier PTLC pattern") — MUST verify the capability is advertised by every operator on the route before constructing descriptors that use it. Operators that don't advertise the capability refuse such descriptors at admission, so probing without checking burns capital on doomed locks.

**Trust path.** Same as `guarantees`: the operator's Nostr event signature attests the capability list. A misadvertised capability that the operator then rejects at admission is a wallet-side error that recovers gracefully (the wallet falls back to HTLC, or picks a different operator); the protocol-level safety isn't at risk.

## Operator → Delegate Delegation

A two-key model separates the operator's *protocol-level identity* from the daemon's *Nostr-layer identity*.

**The operator key** (`operator_pubkey`) is the trust anchor. It signs:
- The advertisement's outer Nostr event signature (Kind 39100)
- The `operator_signature` inside every `SignedLedgerUpdate` (Kind 9100 content)
- Cosignatures on other operators' ledgers (when this operator is a quorum member)
- Invoice cosignatures (the operator's half of a co-signed BOLT11 attestation)
- DEP-04 subkey attestations

In a deployment running `deposits-signer` (out-of-process signer holding the operator seed), this key never leaves the signer. The daemon talks to the signer over a local Unix socket and receives BIP-340 signatures back over the wire.

**The delegate key** (`delegate_pubkey`) is the daemon's per-host Nostr identity. It signs:
- Kind 9100 ledger update events (outer Nostr event signature only — the inner `operator_signature` is still signed by the operator key)
- All Nostr-layer DM envelopes (NIP-04 / NIP-44 encrypt + decrypt; the daemon decrypts inbound DMs to its delegate npub)
- Gift-wrap envelopes (Kind 1059 outer)

The delegate key is held in process by the daemon and persisted under the daemon's data directory. Compromise of the daemon's host leaks the delegate key but **not** the operator key — slashing-equivalent fraud is structurally unavailable to an attacker who has only the delegate.

### Wallet trust path

A wallet acquires `operator_pubkey` out-of-band (e.g. configured manually, discovered via a public listing). To interact with that operator:

1. Fetch the advertisement: `kind=39100, author=operator_pubkey`. Verify outer event sig against `operator_pubkey`.
2. Read `delegate_pubkey` from advertisement content. If empty, treat `operator_pubkey` as the delegate (legacy fallback).
3. For ledger updates: subscribe to `kind=9100, #l=<ledger_id>` and verify two layers — the outer Nostr event sig against `delegate_pubkey`, and the inner `operator_signature` against `operator_pubkey` (from the ledger's `LedgerOpen`). The operator-protocol verification is what protects the deposit; the outer is just transport authenticity.
4. For NIP-04/44 DMs: encrypt to `delegate_pubkey`. Decrypt inbound DMs from the operator with `delegate_pubkey` as the sender.

### Why this isn't NIP-26 / DEP-04 subkey attestation

NIP-26 delegated event signing and the existing DEP-04 subkey-attestation pattern (Kind 10301) are *wallet-side* mechanisms — a user delegates from a long-lived account key to ephemeral subkeys. The operator → delegate split here is *operator-side* and uses the advertisement itself as the delegation document: the operator's signature on the advertisement carries the delegate pubkey in the content, so the trust path is "wallet trusts operator → operator endorses delegate." A separate Kind 10301 attestation event would be redundant.

### Backwards compatibility

Older wallets that don't read `delegate_pubkey` will treat the advertisement's event author as the operator's messaging identity. This works as long as the daemon's `self.keys` is the operator key (operator-key-for-everything mode). Once the daemon switches to delegate-key-for-Nostr (this commit's follow-up), the advertisement still authors as `operator_pubkey` (signed by signer), but Kind 9100 events author as `delegate_pubkey`. Older wallets filtering Kind 9100 by `author=operator_pubkey` will miss them and need to follow the delegation. Operators rolling forward should publish a transition advertisement with both keys' addresses available before flipping.

## Bridge Advertisements (Kind 39104)

Lightning ↔ ledger bridges advertise via NIP-33 replaceable events on the ledger relay, mirroring the courier advertisement pattern (Kind 39102). The `d` tag is the bridge's pubkey, enabling per-bridge replacement.

```json
{
  "bridge_pubkey": "<hex>",
  "network": "bitcoin",
  "ledgers": [
    {
      "ledger_id": "<64 hex>",
      "deposit_id": "<32 hex>",
      "balance_msats": 500000000,
      "lock_type": ["htlc", "ptlc"],
      "receive": {
        "fee_fixed_msats": 100,
        "fee_rate_bps": 30,
        "min_amount_msats": 10000,
        "max_amount_msats": 100000000,
        "hold_window_blocks": 120
      },
      "pay": {
        "fee_fixed_msats": 200,
        "fee_rate_bps": 50,
        "quote_endpoint": "<optional Nostr DM action>"
      }
    }
  ]
}
```

- `ledgers` — one entry per ledger the bridge can service. The bridge holds a deposit on each.
- `receive` — pricing for inbound bridging on that ledger (wallet receives via bridge's BOLT-11 → bridge's TransferLock). `fee_*` is the bridge's service margin, captured via the BOLT-11 spread; published as a flat schedule for amounts in `[min_amount_msats, max_amount_msats]`. `hold_window_blocks` is the bridge's typical hold window — how long the wallet has to reveal the preimage on-ledger before the parked HTLCs (and the bridge's TransferLock) time out. Set by the bridge's LN implementation (DEP-10 §"Hold windows": LND/CLN bridges ~120+, LDK bridges ~18); wallets MUST pick a bridge whose window comfortably exceeds their expected reveal latency.
- `pay` — pricing for outbound bridging on that ledger (wallet TransferLocks to bridge → bridge pays the BOLT-11). `fee_*` is the bridge's published baseline. If the bridge prefers per-invoice quoting (because routing variance is high), `quote_endpoint` names a Nostr-DM action wallets can hit to request a fresh quote per BOLT-11 — analogous to `request_route` for couriers (DEP-13).
- `lock_type` — `htlc` always; `ptlc` only when both the bridge's deposit operator and the wallet's operator advertise the `pointlock` capability in Kind 39100. Wallets that need PTLC privacy MUST verify the capability on both ledgers before selecting a `ptlc`-advertising bridge.

The protocol does NOT enforce that a bridge's published `receive`/`pay` schedule is honored — bridges are peer services, not protocol-attested ones. A bridge that publishes one price and quotes another loses business, but the wallet's only protocol-level recourse is the timeout-and-refund failure mode of any unanswered `TransferLock`. Wallets SHOULD prefer bridges with consistent published schedules over those that always per-invoice-quote (lower trust friction), and SHOULD aggregate reputation signals across multiple bridges per ledger.

The cosigning quorum's role on bridge ops is structural (standard TransferLock conformance always; timeout-ordering and completion-script binding when the submitter attaches the BOLT-11 as aux data in the cosignature request — see DEP-10 §"Bridge cosigner rules") — they do NOT verify the bridge's published prices against the lock, since prices are market-set and not part of the protocol fee surface.

### Bridge request envelopes

Bridges are addressed the same way couriers are: Kind 20101 requests with a `p` tag carrying the bridge's pubkey, answered by Kind 20102 tagged with the request event ID. Two actions:

**`issue_hold_invoice`** (wallet → bridge, receive direction — DEP-10 §Receive step 1):

```json
{
  "ledger_id": "<64 hex>",
  "deposit_id": "<32 hex>",          // wallet's deposit to credit
  "amount_msats": 250000,            // X — what the wallet wants to receive
  "lock_type": "htlc",               // or "ptlc"
  "payment_hash": "<64 hex>"         // H = sha256(r); wallet keeps r
}
```

For `lock_type: "ptlc"`, `payment_point` (66 hex, compressed) replaces `payment_hash`. Response:

```json
{
  "success": true,
  "result": {
    "bolt11": "<invoice for X + service_fee + transfer_fee>",
    "service_fee_msats": 1300,
    "transfer_fee_msats": 600,
    "hold_window_blocks": 120        // measured/typical; informational
  }
}
```

The wallet checks the amount math against the bridge's advertised schedule before handing the BOLT-11 to the payer. The bridge MUST refuse hashes it has seen before (re-using `H` across invoices would let an old on-ledger reveal settle a new HTLC).

**`quote_invoice`** (wallet → bridge, pay direction — DEP-10 §Pay step 1):

```json
{
  "ledger_id": "<64 hex>",
  "bolt11": "<the external invoice the wallet wants paid>"
}
```

Response:

```json
{
  "success": true,
  "result": {
    "bridge_deposit_id": "<32 hex>",   // lock destination
    "service_fee_msats": 2100,          // bridge margin incl. expected routing
    "quote_expiry_secs": 120,
    "min_lock_window_blocks": 18        // bridge ignores locks with shorter T_ledger
  }
}
```

The quote is advisory (the bridge's signature is not on it — see DEP-10 §Pay: the bridge's risk is its own routing exposure, and a wallet that locks a different total simply won't be served). Carrying the BOLT-11 in the request is what later lets the bridge recognize the lock: it indexes pending quotes by the invoice's payment hash and matches the arriving `TransferLock.completion_script` against it.

## Price Oracle (Kind 39101)

Operators publish a NIP-33 replaceable event (`d`=`btcusd`, kind `39101`) carrying the BTC/USD spot price and the publisher's observed chain tip:

```json
{
  "pair": "BTCUSD",
  "price": 67234.50,
  "block_height": 901234,
  "timestamp": 1746547200
}
```

- `pair` — currency pair. Reserved for future expansion; only `BTCUSD` is currently published.
- `price` — BTC/USD spot price the operator observed (operators MAY source this from any oracle of their choice; clients SHOULD aggregate across operators rather than trust a single publisher).
- `block_height` — *(since 2026-05)* the publishing operator's observed Bitcoin chain tip at the moment of publication. `0` means the publisher didn't include one (older daemons). Wallets ignore `0` and pick the highest non-zero value across all observed publishers.
- `timestamp` — the operator's wall clock at publish (UNIX seconds). Non-load-bearing — Nostr's `created_at` is the canonical event time.

The chain-tip piggyback lets light clients (browser wallets, gateways, explorers) learn the current Bitcoin height without running a node or polling an external block explorer. It is *not* a consensus-critical feed — clients use it for liveness checks (quorum-freshness, lock-timeout sanity) where being a few blocks stale is harmless. Anything that needs a tamper-evident height (e.g. fraud-proof verification) MUST anchor against an actual block hash, not this field.

Wallets sample multiple recent events (typical limit: 5–10) and use the highest `block_height` seen, breaking ties by `created_at`. A single bad publisher cannot drag the tip backwards because `block_height` only ratchets up.

## Wallet Pre-Open Quorum-Freshness Check

A deposit opened against an operator whose quorum has lapsed is unrecoverable through the normal cosign path — the operator can no longer assemble a majority cosignature, and the wallet has no protocol-level recourse short of dispute. Wallets MUST therefore refuse to open new deposits on an operator whose quorum has expired, and SHOULD warn when expiry is imminent.

The check uses two pieces of data already on the wire — no new operator-published field is required:

1. **Quorum expiry block** — the `quorum_expiry` field (TLV type 86, see DEP-02 §TLV Field Tags) of the most recent `QuorumBegin` (op discriminant 12, see DEP-02 §LedgerOperation discriminants) in the target ledger's Kind 9100 stream. If the ledger has no `QuorumBegin` on record, the operator hasn't activated a quorum yet and the wallet MUST refuse: there is no cosign path at all.

2. **Chain tip** — the highest `block_height` observed on a recent Kind 39101 price-oracle event (see §Price Oracle above).

Decision rule:

| Condition | Wallet action |
|---|---|
| no `QuorumBegin` on the ledger | refuse to open |
| `tip ≥ quorum_expiry` | refuse to open (operator's quorum is past the expiry block) |
| `quorum_expiry - tip < 144` blocks | warn but allow (≈ 1 day of headroom remaining) |
| `quorum_expiry - tip ≥ 144` blocks | proceed |
| `tip == 0` (no price feed observed) | skip the chain-tip half of the check; the QuorumBegin presence check still applies |

Both inputs are fetched independently of the operator's own Kind 39100 advertisement. The advertisement's `current_block` and `quorum_state` fields are operator-self-reported and replaceable — they remain in the ad for at-a-glance debugging but wallets MUST NOT use them for the freshness gate. The Kind 9100 `QuorumBegin` is co-signed by a quorum majority and the Kind 39101 tip is corroborated across the publishing operator set, so neither can be unilaterally forged stale-true by a single operator.

Explorer UIs that surface "quorum status" badges SHOULD use the same derivation so the operator's self-reported `quorum_state` cannot mask an actually-expired quorum.

## Wallet Identity and NIP-07

Wallets derive a Nostr keypair from their BIP-39 seed at derivation path `m/84'/0'/0'/0/0`. This key signs requests (Kind 20101) and verification events (Kind 25500).

Alternatively, wallets MAY delegate identity to a NIP-07 browser extension (`window.nostr`). When NIP-07 mode is active:

- Verification requests (Kind 25500) are signed by the extension
- The wallet key is retained for deposit operations (Kind 20101), which require the derived key
- Subkey attestation (Kind 10301) is disabled, since the wallet does not control the signing key
- The extension's relay list (`window.nostr.getRelays()`) is used for state sync

The choice between wallet key and NIP-07 is stored in wallet state and can be toggled in settings.

## Wallet State Sync (Kind 30078)

Wallets persist operational state (deposits, relays, key index) to Nostr relays using NIP-78 application-specific data events. The `d` tag is `deposits-wallet/state`, making it a parameterized replaceable event — only the latest version is retained.

Content is NIP-04 encrypted to the wallet's own pubkey (encrypt-to-self). In NIP-07 mode, `window.nostr.nip04.encrypt` is used; otherwise, the wallet implements NIP-04 directly (ECDH shared secret + AES-256-CBC).

The encrypted payload contains:

```json
{
  "network": "bitcoin",
  "relays": ["ws://..."],
  "ledgerRelay": "wss://...",
  "deposits": [...],
  "keyIndex": 3,
  "useNip07": false
}
```

The seed and mnemonic are never included — they are the key itself.

State is synced to both operator relays and identity relays (from NIP-07) with a 5-second debounce after local saves. On wallet import, state is restored from relays automatically.

## Domain Attestation (Kind 55502)

An external verification service publishes Kind 55502 events attesting that a Nostr pubkey controls a specific lightning address. The operator queries for these events during deposit access control (see DEP-08).

```json
{
  "npub": "npub1...",
  "lightning_address": "user@domain.com",
  "verified_at": "2026-01-15T12:00:00+00:00",
  "method": "nip05"
}
```

The event is authored by the verifier and tagged `#p` with the verified pubkey. Verification methods:

- **`nip05`**: The domain's `.well-known/nostr.json` maps the user to this pubkey. Free.
- **`challenge`**: The verifier paid random amounts to the lightning address and the user reported them correctly. Requires payment.

The verifier communicates with wallets via Kind 25500 (request) and Kind 25501 (response) ephemeral events. The wallet sends a verification request; the verifier responds with an invoice, challenge, or attestation result.

## Subkey Attestation (Kind 10301)

A root keypair signs attestations authorizing independent subkeys to act on its behalf. The attestation message is `SHA256("nostr301:<hex-subkey-pubkey>")`, signed with BIP-340 Schnorr.

Events signed by a subkey include:
- `["v", "<hex-account-pubkey>"]` — the account this subkey acts for
- `["va", "<hex-attestation-signature>"]` — proof of authorization

Kind 10301 (replaceable) manages the subkey set:

```json
{
  "inbox_keys": ["<hex-subkey1>", "<hex-subkey2>"],
  "revoked_subkeys": ["<hex-subkey3>"]
}
```

Revocation is a policy check — the attestation signature remains cryptographically valid, but verifiers MUST check the Kind 10301 event for revocations before trusting a subkey.

## Relay Tag Truncation

Kind 9100 events use a truncated 16-character prefix of the ledger ID in the `d` tag for relay-side filtering efficiency. The full 64-character ledger ID is encoded in the TLV content (tag 2, LEDGER_ID). Wallets and operators MUST use the full ledger ID from TLV when constructing requests — not the truncated tag value.

Kind 20101 request events carry the full ledger ID in the `l` tag.

## Offline Operation

Wallets need no persistent connections. They can go offline indefinitely and catch up by fetching Kind 9100 events from any relay that has them. The hash chain provides integrity verification — a wallet replays events and validates the chain regardless of when they were fetched.

## Related DEPs

- [DEP-02](DEP-02.md): Ledger update wire format (Kind 9100 content)
- [DEP-06](DEP-06.md): Fraud proof broadcast format (Kind 9101 content)
- [DEP-12](DEP-12.md): Certified delivery (Kind 20101 wallet → member request, durable record via DeliveryEmbed on Kind 9100)

## References

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) -- Nostr event structure
- [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md) -- Encrypted direct messages
- [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) -- Browser extension signing (`window.nostr`)
- [NIP-33](https://github.com/nostr-protocol/nips/blob/master/33.md) -- Parameterized replaceable events
- [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) -- Application-specific data
