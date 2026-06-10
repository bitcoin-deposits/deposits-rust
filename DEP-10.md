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

Lightning connectivity is a peer-provided bridging service, not an operator privilege. Any deposit holder with a Lightning node can run a bridge: a deposit on the ledger plus the LN-side infrastructure to receive or pay BOLT-11 invoices. The on-ledger primitives — `TransferLock`/`TransferComplete` — are exactly the same as for intra-ledger transfers and cross-ledger courier hops. The cross-domain HTLC pattern stays the same; only one leg lives on BOLT-11 instead of on another deposit.

This separates two distinct fees:

- The **ledger transfer fee** (`TransferFeeSchedule` from DEP-07) is paid by the bridge to `fees_accumulated` on every `TransferLock`, like any other transfer. Quorum members get their cosigning compensation through this channel regardless of who runs the bridge.
- The **bridge service fee** is the bridge's own margin, captured externally via the difference between the BOLT-11 amount and the on-ledger transfer amount. It never touches the ledger's fee surface — it's market-priced, the bridge sets it competitively, and a wallet picks the bridge it likes. The operator may run a bridge from a self-deposit (and many will, since they already have LN infrastructure), but they're competing on price with anyone else holding a deposit on the ledger.

Bridges advertise themselves on Nostr the same way couriers do (DEP-04 §"Bridge Advertisements" — see also DEP-13). The operator-LN-sidecar with `InvoiceCredit`-based deterrence stays as the legacy fallback for permanently-offline wallets that cannot reveal preimages within HTLC windows — see §Offline receive below.

### Receive

The flow is a standard cross-domain HTLC with the deposits ledger as the final hop of the Lightning route. The "bridge" below is whichever deposit holder the wallet chose; nothing about the protocol distinguishes operator-run bridges from third-party bridges.

1. **Invoice issuance.** Wallet generates a 32-byte preimage `r` locally, computes `H = sha256(r)`, sends `H` (and the desired receive amount `X`) to the bridge over the existing peer-messaging channel. Bridge's LN node issues a BOLT-11 *hold invoice* with `payment_hash = H` and amount `X + service_fee + transfer_fee`, where `service_fee` is the bridge's own margin and `transfer_fee` is what the bridge will pay to the operator on the upcoming on-ledger `TransferLock`. The cosigned invoice record (the existing invoice-cosignature flow) goes on the ledger so cosigners can resolve `H` to the BOLT-11 amount at lock time. **Only the wallet knows `r`**; bridge and payer know only `H`.
2. **HTLC arrival.** Payer routes a Lightning payment to the bridge's node with `payment_hash = H`, amount `X + service_fee + transfer_fee`, CLTV expiry `T_ln`. The bridge's node **holds** the HTLC — it cannot settle without `r`. The upstream funds are parked, claimable by no one.
3. **Hash-locked credit.** Bridge appends `TransferLock` from its own deposit to the wallet's deposit, with:
    - `amount = X`
    - `fee = transfer_fee` — the standard `TransferFeeSchedule` cost paid to `fees_accumulated`
    - `completion_script = "sha256(H_hex)"`
    - `timeout_height = T_ledger` where `T_ledger + Δ < T_ln`
   Quorum cosigners verify the timeout-ordering constraint against the invoice's CLTV and the standard `TransferLock` conformance rules (see §"Bridge cosigner rules" below).
4. **Claim.** Wallet observes the cosigned `TransferLock` on the relay, verifies the timeout margin and the script, appends `TransferComplete` with a script witness revealing `r`. Cosigned, applied; balance credited to the wallet's deposit (`X`). The preimage is now public on the relay, inside a quorum-attested record.
5. **Upstream settlement.** Bridge's daemon scrapes `r` off its own Kind 9100 stream, hands it to its LN node, settles the inbound HTLC, claims `X + service_fee + transfer_fee`. The `Δ` margin guarantees the bridge has time to do so even if the wallet revealed `r` at the last block of `T_ledger` — same CLTV-delta discipline as any LN routing hop. The bridge has now exchanged its on-ledger deposit balance of `X + transfer_fee` (debited from its deposit at TransferLock time) for `X + service_fee + transfer_fee` on Lightning, netting `service_fee` minus its LN-side routing costs.

**Why this is atomic.** The bridge's only path to the upstream money runs through a cosigned, claimable credit existing on the ledger first. The bridge cannot collect upstream without `r` being public, and `r` cannot become public except through a quorum-cosigned credit to the wallet's deposit. The order of operations is enforced by the hash, not by deterrence. The wallet's recourse for theft is structural ("the bridge can't claim without crediting me") rather than evidentiary ("they claimed but didn't credit, here's the preimage"). The `Uncredited Lightning` fraud proof remains in the codec for legacy InvoiceCredit-based receives but the bridge flow doesn't produce them.

**PTLC variant.** Substitute `r` with a scalar `s` and `H` with `P = G·s`; the BOLT-11 becomes a PTLC-style hold (subject to LN-side PTLC availability — separate spec), and the on-ledger lock becomes `pointlock(P)`. Same flow, no on-ledger relay leak of `r` correlatable with the LN leg. The descriptor calculus supports `pointlock(P)` today (DEP-16 §capability, DEP-13 §"Courier PTLC pattern"); operators advertise the capability per DEP-04's capability set, and wallets filter bridges by whether both the bridge's operator and the wallet's operator advertise it.

### Pay

A wallet hands a bridge an external BOLT-11 to pay. The bridge takes on the LN routing-fee variance as its own business risk — that's why bridges quote service fees per-invoice (or publish ledger-wide schedules) rather than absorbing routing costs silently.

1. **Bridge selection and quote.** Wallet inspects bridge advertisements (DEP-04 §"Bridge Advertisements") and either (a) computes the cost from a bridge's published schedule, or (b) sends a `quote_invoice` peer message with the BOLT-11 and asks for a per-invoice quote. The bridge responds with a price (`service_fee` for this particular invoice — covers its expected routing cost plus its margin). The wallet picks a bridge and proceeds.
2. **Lock.** Wallet emits a standard `TransferLock` from its own deposit to the bridge's deposit:
    - `amount = invoice_amount + service_fee`
    - `fee = transfer_fee` — the standard `TransferFeeSchedule` cost
    - `completion_script = "sha256(H_hex)"` where `H` is the BOLT-11's `payment_hash`
    - `timeout_height = T_ledger` where `T_ledger + Δ < BOLT-11.cltv_expiry_block`
   No new fields. The wallet's authorization signature satisfies the wallet's deposit descriptor (standard TransferLock witness).
3. **Pay and reveal.** Bridge's daemon hands the BOLT-11 to LDK with whatever routing-fee cap the bridge chose to give itself. On success, LDK returns the preimage `r`. The bridge appends `TransferComplete` with the script witness revealing `r`. The lock resolves; the bridge's deposit receives `invoice_amount + service_fee` (less `transfer_fee` which goes to `fees_accumulated`). The bridge's net: `service_fee − actual_routing_fee_msats` retained on the deposit ledger side.
4. **Failure paths.**
    - **No route fits.** Bridge gives up before revealing, never produces a TransferComplete. The lock times out at `T_ledger`; wallet's deposit recovers `amount` (minus `transfer_fee_failed` per DEP-07 §"Fee on Failure", which the operator collects regardless). Bridge ate the routing-probe work for no margin and SHOULD be priced out of future routes.
    - **Bridge griefs.** Bridge reveals a preimage that doesn't match `H` (impossible to satisfy the `sha256(H)` lock), or accepts the lock and never attempts the payment. Same outcome as "no route fits" — lock times out, wallet recovers, bridge wasted its own deposit liquidity and reputation. Repeated grief is the bridge's market exit.

The wallet's commitment is the locked `amount`; the bridge's risk is its own routing exposure. There's no on-ledger quote signature, no operator-mediated cosigner rule for the spread — the bridge sets a price, the wallet either accepts it or picks a different bridge.

### Self-Pay

When the payer and payee are deposits on the same operator, no bridge is needed: the operator (or the wallet, or anyone) can issue a TransferLock between the two deposits directly. Lightning is bypassed entirely. Fees fall back to the operator's published intra-ledger `TransferFeeSchedule` (DEP-07).

### Bridge cosigner rules

For BOTH receive and pay, the cosigning quorum enforces the cross-domain HTLC discipline. These are conformance checks on the `TransferLock`, not new operations:

- **Standard TransferLock conformance.** Source has sufficient balance, `fee` matches the deposit's `TransferFeeSchedule`, witness satisfies the source descriptor, nonce/expiry valid. These rules apply to every TransferLock, bridge or not.
- **Correlated BOLT-11 lookup.** The cosigner MUST resolve the BOLT-11 invoice this lock corresponds to. For receive, the bridge issued the BOLT-11 and has the existing invoice-cosignature record on the ledger keyed by `payment_hash` (or `payment_point` for PTLC). For pay, the wallet supplies the BOLT-11 in the lock request; the cosigner decodes it. Either way, the cosigner reads the BOLT-11's `cltv_expiry_block` and `amount` to enforce the timing and (for receive) bound the on-ledger lock amount.
- **Timeout-ordering rule.** `TransferLock.timeout_height + Δ ≤ BOLT-11.cltv_expiry_block`, where Δ is the cosigner's local minimum margin (default 144 blocks, MUST be at least the operator's `timeout_margin_blocks` declared on the ledger). Without this margin, the bridge can't safely reveal-and-claim on the LN side before the upstream HTLC times out.
- **Completion-script binding.** `TransferLock.completion_script` is `sha256(H_hex)` or `pointlock(P_hex)` where `H` (resp. `P`) matches the BOLT-11's `payment_hash` (resp. `payment_point`). A mismatch is non-conforming.
- **Receive-side amount bound.** For receive locks, `TransferLock.amount + TransferLock.fee ≤ BOLT-11.amount`. The bridge MAY retain a spread (the service fee), but cannot overpay the wallet from the BOLT-11 — that's only enforceable on the upper bound. Underpaying (locking less than the BOLT-11 entitles) is the bridge's prerogative since the BOLT-11 itself was the price-quote.

A `TransferLock` that fails these checks is non-conforming; cosigners refuse to sign and the bridge cannot commit. The HTLC-bridge atomicity is enforced cryptographically at cosig time via the standard `TransferLock` rules plus the BOLT-11 correlation check, not via post-hoc fraud proofs.

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

**HTLC-bridge (default, receive and pay).** No on-ledger trust boundary. Receive is atomic by construction (§Receive above); pay is bounded by the bridge's own routing risk — the wallet's commitment is the locked amount, the bridge sets its service fee high enough to cover expected routing variance (§Pay above). The bridge's LN node is still a Lightning peer that can fail in Lightning-typical ways (forwarding failures, channel force-closes, fee-bump races) — those failure modes affect *whether* a payment routes, not whether the bridge can steal it.

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

- [DEP-02](DEP-02.md): Wire format (Invoice/Onchain operation fields). No new fields for the bridge — both directions reuse standard `TransferLock`/`TransferComplete`.
- [DEP-04](DEP-04.md): Peer messaging (bridge advertisements, optional `quote_invoice` for per-invoice pricing), guarantee matrix rows for `invoice_receive` / `invoice_pay` / `invoice_receive_legacy_deterrence`
- [DEP-05](DEP-05.md): Quorum and collateral (obligation limits, cosigning requirements, bridge cosigner rules)
- [DEP-06](DEP-06.md): Fraud proofs (uncredited on-chain payment, `Uncredited Lightning` for legacy-deterrence-mode receive only)
- [DEP-07](DEP-07.md): Fee schedules (standard `TransferFeeSchedule` applies to bridge `TransferLock` ops; bridge service fees are market-priced and out of scope)
- [DEP-08](DEP-08.md): Deposits (descriptor witnesses, `receive_requires_sig` — still relevant for the legacy deterrence path)
- [DEP-13](DEP-13.md): Couriers (HTLC/PTLC patterns; the Lightning bridge is the same pattern with one leg on BOLT-11 instead of a sister ledger)
- [DEP-16](DEP-16.md): Descriptor calculus (`pointlock` capability gates the PTLC variant of the bridge)
