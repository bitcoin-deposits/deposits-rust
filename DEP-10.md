# DEP-10: Payment Channels

## Abstract

This document specifies how deposits receive and send funds through on-chain transactions and lightning payments. Operators create funding offers and invoices on behalf of deposits; these are co-signed by a quorum member and retained by the wallet as evidence.

## On-chain Funding

### Offers

An operator creates a funding offer for a deposit: a bitcoin address where funds can be sent, with a deadline block and amount range. After quorum establishment, offers are co-signed by a quorum member using BIP-340 tagged hashing:

    tag = SHA256("deposits/offer_cosign")
    data = ledger_id || offer_id || operator_x_only || len(address) || address || deadline_block_le32
    digest = SHA256(tag || tag || data || member_ledger_hash)

The wallet retains the offer, cosignature, and co-signer pubkey as evidence. If the operator does not credit the deposit after sufficient confirmations, this evidence is used to construct a fraud proof (see DEP-06).

### Credit (disc 35)

When the operator confirms a deposit to the funding address, they append `OnchainCredit` with the txid, vout, amount, and funding address.

### Withdrawal

A wallet requests withdrawal by providing a destination address, amount, and witness satisfying the deposit's descriptor. The operator:

1. Appends `OnchainLock` with withdrawal_id, amount, destination, and fee
2. Constructs and broadcasts the bitcoin transaction
3. On confirmation: appends `OnchainFulfill` with the txid
4. On failure: appends `OnchainFail` (releases the locked `amount + miner_fee` and charges the deposit's fixed transfer fee — see DEP-07 §"Fee on Failure")

## Lightning

The operator's Lightning node is an LN↔ledger bridge. Two directions:

- **Receive** (§Receive below). A BOLT-11 hold invoice with a wallet-chosen payment hash is paid by some external sender; the operator's commitment is structurally bound to the wallet revealing the preimage on-ledger. Atomic by construction — no trust delta, no separate authorization signature.
- **Pay** (§Pay below). A wallet hands the operator an external BOLT-11 and a signed quote committing the wallet to the operator's worst-case routing-fee exposure. The operator either pays within the quote or fails the lock; routing variance is bounded by the quote, not absorbed silently.

Both directions reuse existing on-ledger primitives — `TransferLock`/`TransferComplete` for receive, `InvoiceLock`/`InvoiceFulfill`/`InvoiceFail` for pay — without inventing a new operation type. The atomic property of receive comes from the cross-domain HTLC, not from a new field on `InvoiceCredit`.

### Receive

The flow is a standard cross-domain HTLC with the deposits ledger as the final hop of the Lightning route.

1. **Invoice issuance.** Wallet generates a 32-byte preimage `r` locally, computes `H = sha256(r)`, sends `H` (and the desired receive amount `X`) to the operator over the existing peer-messaging channel. Operator's LN node issues a BOLT-11 *hold invoice* with `payment_hash = H` and amount `X + bridge_fee` (see DEP-07 §"Lightning bridge fees"). The cosigned invoice record goes on the ledger as it does today. **Only the wallet knows `r`**; operator and payer know only `H`.
2. **HTLC arrival.** Payer routes a Lightning payment to the operator's node with `payment_hash = H`, amount `X + bridge_fee`, CLTV expiry `T_ln`. The operator's node **holds** the HTLC — it cannot settle without `r`. The upstream funds are parked, claimable by no one.
3. **Hash-locked credit.** Operator appends `TransferLock` from its self-deposit on the same ledger to the wallet's deposit, with:
    - `amount = X`
    - `fee = 0` (source is the operator's own deposit; self-pay is a no-op — bridge fee is the implicit `X + bridge_fee − X = bridge_fee` delta retained on the upstream LN claim)
    - `completion_script = "sha256(H_hex)"`
    - `timeout_height = T_ledger` where `T_ledger + Δ < T_ln`
   Quorum cosigners verify the timeout-ordering constraint against the invoice's CLTV (see §"Bridge cosigner rules" below) — this is a hard conformance check, not advisory.
4. **Claim.** Wallet observes the cosigned `TransferLock` on the relay, verifies the timeout margin and the script, appends `TransferComplete` with a script witness revealing `r`. Cosigned, applied; balance credited to the wallet's deposit. The preimage is now public on the relay, inside a quorum-attested record.
5. **Upstream settlement.** Operator's daemon scrapes `r` off its own Kind 9100 stream, hands it to its LN node, settles the inbound HTLC, claims `X + bridge_fee`. The `Δ` margin guarantees the operator has time to do so even if the wallet revealed `r` at the last block of `T_ledger` — same CLTV-delta discipline as any LN routing hop.

**Why this is atomic.** The operator's only path to the upstream money runs through a cosigned, claimable credit existing on the ledger first. The operator cannot collect upstream without `r` being public, and `r` cannot become public except through a quorum-cosigned credit to the wallet's deposit. The order of operations is enforced by the hash, not by deterrence. The wallet's recourse for theft is structural ("they can't claim without crediting me") rather than evidentiary ("they claimed but didn't credit, here's the preimage"). The `Uncredited Lightning` fraud proof remains in the codec for legacy ledger states, but the new flow doesn't produce them.

**PTLC variant.** Substitute `r` with a scalar `s` and `H` with `P = G·s`; the BOLT-11 becomes a PTLC-style hold (subject to LN-side PTLC availability — separate spec), and the on-ledger lock becomes `pointlock(P)`. Same flow, no on-ledger relay leak of `r` correlatable with the LN leg. The descriptor calculus already supports `pointlock(P)` (DEP-16 §capability, DEP-13 §"Courier PTLC pattern"); the wire path is identical.

### Pay

A wallet hands the operator an external BOLT-11 to pay. The operator's exposure to LN routing-fee variance is bounded by an operator-signed quote that the wallet commits to at lock time.

1. **Quote negotiation.** Wallet sends a `quote_invoice` peer message with the BOLT-11 string and the deposit it wants to debit. Operator's daemon decodes the invoice, runs a routing probe via LDK, and responds with a signed quote (see §"Quote wire format" below):

       (invoice_amount, max_routing_fee_msats, operator_margin_msats,
        quote_total_msats, quote_expiry_block, operator_signature)

   where `quote_total_msats = invoice_amount + max_routing_fee_msats + operator_margin_msats` and `operator_margin_msats >= operator's published outbound margin floor` from the Kind 39100 ad. The signature is BIP-340 over the tagged digest of the tuple. `quote_expiry_block` is a near-future ledger height (default ~6 blocks) bounding the quote's validity — the operator's routing-graph view drifts continuously, so the quote can't be open-ended.
2. **Lock.** Wallet either accepts the quote and emits `InvoiceLock` with the new fields:

        InvoiceLock {
          deposit_id, amount: quote_total_msats, payment_id, sequence_number,
          nonce, expiry, witness,
          quote_signature: [u8; 64],   // operator's signed quote
          quote_expiry: u32,            // echoed from the quote
        }

   or walks away — the quote was a peer message, no on-ledger commitment until the lock.
3. **Cosigner check.** Quorum cosigners verify:
    - `quote_signature` is a valid BIP-340 signature by the operator's key over the tagged digest of `(invoice_amount, max_routing_fee_msats, operator_margin_msats, quote_total_msats, quote_expiry)`.
    - `current_ledger_tip < quote_expiry`.
    - `amount == quote_total_msats` (no widening attack).
    - `operator_margin_msats >= operator's published outbound margin floor` (operator can't undercut their own advertised floor mid-quote).
   Without these, the operator could lift the quote arbitrarily after the wallet committed, or sign a forged margin under-cutting their published schedule.
4. **Execute.** Operator's daemon hands the BOLT-11 to LDK with `max_total_routing_fee_msats = max_routing_fee_msats` from the quote.
    - **Success.** LDK returns the preimage. Operator appends `InvoiceFulfill` with the preimage. The locked `quote_total_msats` is consumed; the wallet's deposit is debited by exactly that amount. Operator retains `quote_total_msats − invoice_amount − actual_routing_fee_msats` as net revenue — their advertised margin plus any unused routing buffer.
    - **Failure / cap exceeded.** LDK reports no route fits under the cap, or the payment times out. Operator appends `InvoiceFail` with a reason code. Locked funds return to the wallet's deposit per DEP-07 §"Fee on Failure" — the deposit recovers `quote_total_msats` minus the `TransferFeeSchedule.fixed_msats` per-op floor, which the operator collects regardless of outcome.
    - **Quote expired.** If `current_tip >= quote_expiry` when the operator tries to execute, the operator MUST `InvoiceFail` without attempting — committing to a stale quote means committing to outdated routing assumptions, which is what the expiry exists to prevent.

### Self-Pay

When the payer and payee are deposits on the same operator, the operator MAY settle internally without routing through Lightning. The operator credits and debits the respective deposits directly via a single `TransferComplete` against an internally-issued `TransferLock`, avoiding routing fees and failure modes. The quote dance is skipped — fees fall back to the operator's published intra-ledger `TransferFeeSchedule` (DEP-07).

### Bridge cosigner rules

For BOTH receive and pay, the cosigning quorum enforces structural invariants that the operator cannot bypass:

**Receive (TransferLock-as-bridge):**

- The cosigner MUST resolve the BOLT-11 invoice this lock corresponds to. Mechanism: every BOLT-11 the operator issues for the HTLC-bridge path is first cosigned on-ledger via the existing invoice-cosignature flow (§Invoices above), which leaves a cosigned record keyed by `payment_hash` (or `payment_point` for PTLC). The TransferLock's `completion_script = sha256(H)` (resp. `pointlock(P)`) names this record; the cosigner looks it up and reads the BOLT-11 amount from there. A `TransferLock` whose completion-script hash/point doesn't match any cosigned invoice record is non-conforming and cosigners refuse.
- `TransferLock.timeout_height + Δ ≤ BOLT-11.cltv_expiry_block`, where Δ is the cosigner's local minimum margin (default 144 blocks, MUST be at least the operator's `timeout_margin_blocks` declared on the ledger).
- `TransferLock.amount + TransferLock.fee == BOLT-11.amount` AND `TransferLock.fee == invoice_receive_bridge_fee(TransferLock.amount)` per the operator's published `invoice_receive_fee_*` schedule on Kind 39100 (DEP-07 §"Lightning Bridge Fees"). The bridge_fee rides on `TransferLock.fee` so it flows into `fees_accumulated` and quorum members get their cut on bridge revenue (DEP-05 compensation).
- `TransferLock.completion_script` is `sha256(H_hex)` or `pointlock(P_hex)` matching the cosigned invoice record.
- The source deposit MUST be one of the operator's declared self-deposits on this ledger.

**Pay (InvoiceLock with quote):**

- The four signature/expiry/amount/margin checks listed in §Pay step 3.

A `TransferLock` or `InvoiceLock` that fails these checks is non-conforming; cosigners refuse to sign, and the operator cannot commit. This is the structural difference from the legacy InvoiceCredit-based receive — bridge atomicity is enforced cryptographically at cosig time, not via post-hoc fraud proofs.

### Quote wire format

`quote_invoice` and `quote_response` are Nostr DM messages between wallet and operator. The exact Nostr kinds and message envelope are specified in DEP-04. The signed digest of the quote tuple is:

    tag    = SHA256("deposits/invoice_quote")
    data   = ledger_id || deposit_id || payment_hash ||
             invoice_amount_msat_le64 || max_routing_fee_msat_le64 ||
             operator_margin_msat_le64 || quote_total_msat_le64 ||
             quote_expiry_le32
    digest = SHA256(tag || tag || data)

The operator signs `digest` with its protocol-level secp256k1 key (the same key that signs Kind 39100 ads — wallets and cosigners already trust this key for fee schedules). `payment_hash` is included so a quote can't be replayed across different invoices.

### Offline receive

The HTLC-bridge model requires the wallet to come online and reveal `r` within the BOLT-11's CLTV window. For wallets that are permanently offline (LNURL gateways, scheduled-payout addresses), three options:

1. **Hot-key proxy.** A dedicated agent holds the preimage chain for the wallet's deposit and reveals on demand. Structurally equivalent to how LNURL servers operate today on any LN node — the proxy IS the receiving "LN node" from the network's perspective; the deposits ledger is just the final settlement layer.
2. **Legacy deterrence path.** Operators MAY continue offering the InvoiceCredit-based deterrence receive for ledgers and use cases that need it. The wire format (`InvoiceCredit` discriminant 30) remains valid and the `Uncredited Lightning` fraud proof remains the recourse, exactly as in earlier protocol versions. Operators MUST advertise this regime separately in Kind 39100 — see DEP-04 §"Guarantee Matrix" — so wallets that don't use it can refuse operators that only offer it (and vice versa for offline-only deposits).
3. **Watchtower.** A future spec for a third-party agent that holds preimages and reveals them on agreed schedules, with its own slashable bond for failure-to-reveal. Out of scope here.

Wallets SHOULD prefer the HTLC-bridge model when they can be online during receive windows. The deterrence path is for the LNURL-shaped operational reality, not for security-sensitive amounts.

## Evidence Retention

Wallets retain co-signed offers and (legacy-deterrence-mode) invoices until the corresponding credit appears on the ledger or the deadline expires. Without this evidence, fraud cannot be proven for the paths that rely on evidence:

- **On-chain**: if the offer's deadline block passes with sufficient confirmations but no credit, the wallet constructs a fraud proof autonomously (see DEP-06).
- **Lightning, HTLC-bridge mode**: no evidence retention required. The bridge is atomic by construction — if the operator received an upstream HTLC matching a wallet-held preimage and the on-ledger `TransferLock` never appeared, the operator's upstream HTLC simply times out and the payer is refunded. There's nothing to prove because there's no theft path.
- **Lightning, legacy deterrence mode**: the wallet retains the co-signed invoice. If a payer provides the preimage proving payment, and no `InvoiceCredit` appears on the ledger, the wallet constructs an `Uncredited Lightning` fraud proof with the preimage as evidence.

## Lightning Trust Boundaries

Two distinct trust regimes, depending on which Lightning path a deposit uses:

**HTLC-bridge (default, receive and pay).** No on-ledger trust boundary. Receive is atomic by construction (§Receive above); pay is bounded by the operator-signed quote (§Pay above). The operator's LN node is still a Lightning peer that can fail in Lightning-typical ways (forwarding failures, channel force-closes, fee-bump races) — those failure modes affect *whether* a payment routes, not whether the operator can steal it.

**Legacy deterrence (receive only, opt-in).** The original trust boundary still applies for this path: the operator's lightning node knows whether the preimage was received, but the wallet does not, and the wallet's recourse is the `Uncredited Lightning` fraud proof which depends on the payer surfacing the preimage. Operators offering this path SHOULD declare it explicitly in their guarantee matrix; wallets that route through it SHOULD apply the same hygiene that earlier protocol versions assumed:

- limit outstanding uncredited invoices per operator
- prefer on-chain funding or HTLC-bridge receive for amounts exceeding their risk tolerance
- for high-value legacy invoices, arrange for the payer to share proof-of-payment out-of-band

## Obligation Limits

Creating offers and invoices increases the ledger's potential obligations. The operator must not create offers or invoices that would push total obligations above the least of:

1. The reserves amount (from LedgerOpen/QuorumBegin)
2. The collateral amount declared on LedgerOpen/QuorumBegin (`collateral_amount`)

See DEP-05 for details.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (Invoice/Onchain operation fields, including `InvoiceLock.quote_signature` / `quote_expiry`)
- [DEP-04](DEP-04.md): Peer messaging (`quote_invoice` / `quote_response`), guarantee matrix rows for `invoice_receive` / `invoice_pay`
- [DEP-05](DEP-05.md): Quorum and collateral (obligation limits, cosigning requirements, bridge cosigner rules)
- [DEP-06](DEP-06.md): Fraud proofs (uncredited on-chain payment, `Uncredited Lightning` for legacy-deterrence-mode receive only)
- [DEP-07](DEP-07.md): Fee schedules (bridge fees for receive direction, outbound margin floor)
- [DEP-08](DEP-08.md): Deposits (descriptor witnesses, `receive_requires_sig` — still relevant for the legacy deterrence path)
- [DEP-13](DEP-13.md): Couriers (HTLC/PTLC patterns; the Lightning bridge is the same pattern with one leg on BOLT-11 instead of a sister ledger)
- [DEP-16](DEP-16.md): Descriptor calculus (`pointlock` capability gates the PTLC variant of the bridge)
