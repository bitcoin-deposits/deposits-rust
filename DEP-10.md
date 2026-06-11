# DEP-10: Payment Channels

## Abstract

This document specifies how deposits receive and send funds through on-chain transactions and lightning payments. On-chain funding offers are operator-created and quorum-cosigned. Lightning connectivity is a peer-provided bridging service: any deposit holder with a Lightning node can bridge BOLT-11 payments to and from the ledger using standard transfer locks, atomically and without trust. A legacy operator-mediated receive path remains for permanently-offline wallets.

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

1. **Invoice issuance.** Wallet generates a 32-byte preimage `r` locally, computes `H = sha256(r)`, sends `H` (and the desired receive amount `X`) to the bridge over the existing peer-messaging channel (`issue_hold_invoice` — DEP-04). Bridge's LN node issues a BOLT-11 *hold invoice* with `payment_hash = H` and amount `X + service_fee + transfer_fee`, where `service_fee` is the bridge's own margin and `transfer_fee` is what the bridge will pay on the upcoming on-ledger `TransferLock`. The bridge returns the BOLT-11 to the wallet, which checks the amount math before handing it to the payer. **Only the wallet knows `r`**; bridge and payer know only `H`.
2. **HTLC arrival.** Payer routes a Lightning payment to the bridge's node with `payment_hash = H`, amount `X + service_fee + transfer_fee`, CLTV expiry `T_ln`. The bridge's node **holds** the HTLC — it cannot settle without `r`. The upstream funds are parked, claimable by no one.
3. **Hash-locked credit.** Once the HTLC is parked, the bridge reads the held HTLC's actual CLTV expiry from its LN node (the **measured hold window** — see §"Hold windows" below) and appends `TransferLock` from its own deposit to the wallet's deposit, with:
    - `amount = X`
    - `fee = transfer_fee` — the standard `TransferFeeSchedule` cost paid to `fees_accumulated`
    - `completion_script = "sha256(H_hex)"`
    - `timeout_height = T_ledger = htlc_expiry_height − Δ`, where `htlc_expiry_height` is the earliest CLTV among the held HTLCs and Δ is the bridge's scrape-reveal-and-settle margin (default 6 blocks)
   The bridge attaches the BOLT-11 and the observed `htlc_expiry_height` as auxiliary data in the cosignature request, so cosigners can verify the timeout ordering on its behalf alongside the standard `TransferLock` conformance rules (see §"Bridge cosigner rules" below).
4. **Claim.** Wallet observes the cosigned `TransferLock` on the relay, verifies the timeout margin and the script, appends `TransferComplete` with a script witness revealing `r`. Cosigned, applied; balance credited to the wallet's deposit (`X`). The preimage is now public on the relay, inside a quorum-attested record.
5. **Upstream settlement.** Bridge's daemon scrapes `r` off its own Kind 9100 stream, hands it to its LN node, settles the inbound HTLC, claims `X + service_fee + transfer_fee`. The `Δ` margin guarantees the bridge has time to do so even if the wallet revealed `r` at the last block of `T_ledger` — same CLTV-delta discipline as any LN routing hop. The bridge has now exchanged its on-ledger deposit balance of `X + transfer_fee` (debited from its deposit at TransferLock time) for `X + service_fee + transfer_fee` on Lightning, netting `service_fee` minus its LN-side routing costs.

**Why this is atomic.** The bridge's only path to the upstream money runs through a cosigned, claimable credit existing on the ledger first. The bridge cannot collect upstream without `r` being public, and `r` cannot become public except through a quorum-cosigned credit to the wallet's deposit. The order of operations is enforced by the hash, not by deterrence. The wallet's recourse for theft is structural ("the bridge can't claim without crediting me") rather than evidentiary ("they claimed but didn't credit, here's the preimage"). The `Uncredited Lightning` fraud proof remains in the codec for legacy InvoiceCredit-based receives but the bridge flow doesn't produce them.

**PTLC variant.** Substitute `r` with a scalar `s` and `H` with `P = G·s`; the BOLT-11 becomes a PTLC-style hold (subject to LN-side PTLC availability — separate spec), and the on-ledger lock becomes `pointlock(P)`. Same flow, no on-ledger relay leak of `r` correlatable with the LN leg. The descriptor calculus supports `pointlock(P)` today (DEP-16 §capability, DEP-13 §"Courier PTLC pattern"); operators advertise the capability per DEP-04's capability set, and wallets filter bridges by whether both the bridge's operator and the wallet's operator advertise it.

### Hold windows

The hold window — how long parked HTLCs stay claimable, and therefore how long the wallet has to reveal `r` on-ledger — is set by the LN side, not by the bridge or the ledger. The bridge MUST treat it as **measured, not assumed**: read the held HTLC's actual CLTV expiry after acceptance and derive `T_ledger` from it. Live-measured windows across the implementations the reference backends drive (regtest, defaults):

| Bridge's LN node | Typical window (blocks) | Window configurable? |
|---|---|---|
| LND (`invoicesrpc`) | ~125 | Yes — `AddHoldInvoice.cltv_expiry` |
| CLN + BoltzExchange/hold | ~124 | Via the plugin's gRPC interface only |
| LDK (ldk-node `receive_for_hash`) | **~18** | No — fixed `min_final_cltv_expiry_delta` (24) minus LDK's internal fail-back buffer (6) |

Consequences:

- **The wallet's reveal window is short** — minutes to hours, not days. An LDK-backed bridge gives roughly 18 blocks (~3 hours). This is acceptable *because the HTLC-bridge premise is an online receive*: the wallet initiated the flow and is waiting to reveal. Permanently-offline receive stays on the legacy path (§"Offline receive").
- **Bridges SHOULD advertise their typical hold window** (`receive.hold_window_blocks` in the Kind 39104 ad — DEP-04) so wallets can pick a bridge whose window matches their reveal latency. A wallet on a slow connection should prefer an LND/CLN bridge over an LDK one.
- **Δ is small.** The bridge's margin between `T_ledger` and the HTLC expiry only needs to cover scraping `r` off the relay and submitting the LN-side settle — single-digit blocks. Default 6. It is NOT the courier's 144-block `timeout_margin_blocks`: a courier sets both legs' timeouts and pays for safety with wall-clock; a bridge inherits LN's hold physics, and a 144-block margin would leave a negative lock window on every measured backend.

### Pay

A wallet hands a bridge an external BOLT-11 to pay. The bridge takes on the LN routing-fee variance as its own business risk — that's why bridges quote service fees per-invoice (or publish ledger-wide schedules) rather than absorbing routing costs silently.

1. **Bridge selection and quote.** Wallet inspects bridge advertisements (DEP-04 §"Bridge Advertisements") and either (a) computes the cost from a bridge's published schedule, or (b) sends a `quote_invoice` peer message with the BOLT-11 and asks for a per-invoice quote. The bridge responds with a price (`service_fee` for this particular invoice — covers its expected routing cost plus its margin). The wallet picks a bridge and proceeds.
2. **Lock.** Wallet emits a standard `TransferLock` from its own deposit to the bridge's deposit:
    - `amount = invoice_amount + service_fee`
    - `fee = transfer_fee` — the standard `TransferFeeSchedule` cost
    - `completion_script = "sha256(H_hex)"` where `H` is the BOLT-11's `payment_hash`
    - `timeout_height = T_ledger`, chosen by the wallet to give the bridge a reasonable pay-and-claim window (bridges advertise their minimum window in the Kind 39104 ad; a bridge SHOULD ignore locks whose window is shorter). Note the asymmetry with receive: there is **no** cross-domain CLTV-ordering constraint here. A BOLT-11's `min_final_cltv_expiry` is a relative final-hop delta and its expiry is a wall-clock timestamp — neither maps onto a ledger-height bound. If the bridge pays the payee but fails to claim before `T_ledger`, the wallet is refunded AND the payee was paid; the loss is entirely the bridge's, and the bridge protects itself by refusing short windows and claiming promptly.
   No new fields. The wallet's authorization signature satisfies the wallet's deposit descriptor (standard TransferLock witness).
3. **Pay and reveal.** Bridge's daemon hands the BOLT-11 to LDK with whatever routing-fee cap the bridge chose to give itself. On success, LDK returns the preimage `r`. The bridge appends `TransferComplete` with the script witness revealing `r`. The lock resolves; the bridge's deposit receives `invoice_amount + service_fee` (less `transfer_fee` which goes to `fees_accumulated`). The bridge's net: `service_fee − actual_routing_fee_msats` retained on the deposit ledger side.
4. **Failure paths.**
    - **No route fits.** Bridge gives up before revealing, never produces a TransferComplete. The lock times out at `T_ledger` and resolves via `TransferFail`; per DEP-07 §"Fee on Failure" the wallet's deposit recovers `amount` plus the proportional fee portion, with only the fixed portion (`fixed_msats`) staying with the operator. The bridge ate the routing-probe work for no margin; wallets SHOULD deprioritize bridges with high failure rates.
    - **Bridge griefs.** Bridge reveals a preimage that doesn't match `H` (impossible to satisfy the `sha256(H)` lock), or accepts the lock and never attempts the payment. Same outcome as "no route fits" — lock times out, wallet recovers, bridge wasted its own deposit liquidity and reputation. Repeated grief is the bridge's market exit.

The wallet's commitment is the locked `amount`; the bridge's risk is its own routing exposure. There's no on-ledger quote signature, no operator-mediated cosigner rule for the spread — the bridge sets a price, the wallet either accepts it or picks a different bridge.

### Self-Pay

When the payer and payee are deposits on the same operator, no bridge is needed: the operator (or the wallet, or anyone) can issue a TransferLock between the two deposits directly. Lightning is bypassed entirely. Fees fall back to the operator's published intra-ledger `TransferFeeSchedule` (DEP-07).

### Bridge cosigner rules

A bridge `TransferLock` is, on the wire, indistinguishable from any other hash-locked transfer — courier hops (DEP-13) use the same `sha256(H)` completion scripts. Cosigners therefore CANNOT require a correlated BOLT-11 for every hash-locked transfer; the bridge checks below apply only when the lock's submitter supplies the BOLT-11.

**Mandatory for every TransferLock (bridge or not):**

- **Standard TransferLock conformance.** Source has sufficient balance, `fee` matches the deposit's `TransferFeeSchedule`, witness satisfies the source descriptor, nonce/expiry valid.

**When-supplied BOLT-11 checks.** The lock's submitter MAY attach the corresponding BOLT-11 string as auxiliary data in the cosignature-request envelope (DEP-04 — it is NOT a field on the ledger operation; the wire format is unchanged). When present, cosigners decode it and enforce:

- **Completion-script binding.** `TransferLock.completion_script` is `sha256(H_hex)` or `pointlock(P_hex)` where `H` (resp. `P`) matches the BOLT-11's `payment_hash` (resp. `payment_point`). A mismatch is non-conforming.
- **Timeout-ordering rule (receive only).** `TransferLock.timeout_height + Δ ≤` the inbound HTLC's CLTV height as stated in the aux data, where Δ is the cosigner's local minimum margin (default 6 blocks — see §"Hold windows" for why this is NOT the courier's 144-block margin). The cosigner additionally sanity-checks the stated HTLC expiry against the BOLT-11's `min_final_cltv_expiry` + current tip (the floor the payer's HTLC must clear); a stated expiry below that floor is non-conforming aux data.
- **Receive-side amount bound.** `TransferLock.amount + TransferLock.fee ≤ BOLT-11.amount`. The bridge MAY retain a spread (the service fee), but a lock exceeding what the BOLT-11 pays the bridge is a self-inflicted loss the cosigner flags.

**Who these rules protect.** Walk the receive flow: every check above protects the *bridge from its own mistakes*, not the wallet. The wallet's safety is structural — it does not reveal `r` until a cosigned `TransferLock` paying it `X` exists on the relay, and if the lock is missing, mis-scripted, or mis-timed, the wallet stays silent, both sides time out, and the payer is refunded. This is why when-supplied enforcement is sound: a bridge that skips the aux data only endangers its own funds. Bridges SHOULD always supply it; cosigner enforcement converts bridge-side bugs into refused locks instead of lost liquidity.

For pay, the same logic holds in mirror: the wallet chose `T_ledger` and verified the BOLT-11's `payment_hash` itself before locking, so it needs no cosigner help; a bridge that accepts a short-window lock or pays a mismatched invoice loses its own money.

### Offline receive

The HTLC-bridge model requires the wallet to come online and reveal `r` within the BOLT-11's CLTV window. For wallets that are permanently offline (LNURL gateways, scheduled-payout addresses), three options:

1. **Hot-key proxy.** A dedicated agent holds the preimage chain for the wallet's deposit and reveals on demand. Structurally equivalent to how LNURL servers operate today on any LN node — the proxy IS the receiving "LN node" from the network's perspective; the deposits ledger is just the final settlement layer.
2. **Legacy deterrence path.** Operators MAY continue offering the InvoiceCredit-based deterrence receive for ledgers and use cases that need it. The wire format (`InvoiceCredit` discriminant 30) remains valid and the `Uncredited Lightning` fraud proof remains the recourse, exactly as in earlier protocol versions. Operators MUST advertise this regime separately in Kind 39100 — see DEP-04 §"Guarantee Matrix" — so wallets that don't use it can refuse operators that only offer it (and vice versa for offline-only deposits).

   On this path the operator creates the BOLT-11 through their own LN node (holding the preimage), and the invoice is co-signed by a quorum member as evidence of the operator's commitment to credit on payment:

       tag = SHA256("deposits/invoice_cosign")
       data = ledger_id || payment_hash || deposit_id || amount_msat_le64
       digest = SHA256(tag || tag || data || member_ledger_hash)

   The wallet retains the invoice, cosignature, and co-signer pubkey; if a payer later proves payment (provides the preimage) and no `InvoiceCredit` appears, this evidence backs the fraud proof (DEP-06). When the operator's LN node receives payment, they append `InvoiceCredit` with the payment_hash, deposit_id, amount, invoice_id, and sequence_number.
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

Creating offers and (legacy-path) invoices increases the ledger's potential obligations. The operator must not create offers or invoices that would push total obligations above the least of:

1. The reserves amount (from LedgerOpen/QuorumBegin)
2. The collateral amount declared on LedgerOpen/QuorumBegin (`collateral_amount`)

See DEP-05 for details.

**HTLC-bridge receive creates no new obligations.** A bridge receive moves existing ledger balance from the bridge's deposit to the wallet's — total deposits are unchanged, so the reserves invariant is untouched by bridge volume. New value enters the ledger only through `OnchainCredit` and the legacy `InvoiceCredit` path. A bridge replenishes its on-ledger balance the same way couriers manage liquidity: on-chain funding, buying balance from other deposits, or running flow in both directions and letting pay-side inflows offset receive-side outflows.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (Invoice/Onchain operation fields). No new fields for the bridge — both directions reuse standard `TransferLock`/`TransferComplete`.
- [DEP-04](DEP-04.md): Peer messaging (bridge advertisements, optional `quote_invoice` for per-invoice pricing), guarantee matrix rows for `invoice_receive` / `invoice_pay` / `invoice_receive_legacy_deterrence`
- [DEP-05](DEP-05.md): Quorum and collateral (obligation limits, cosigning requirements, bridge cosigner rules)
- [DEP-06](DEP-06.md): Fraud proofs (uncredited on-chain payment, `Uncredited Lightning` for legacy-deterrence-mode receive only)
- [DEP-07](DEP-07.md): Fee schedules (standard `TransferFeeSchedule` applies to bridge `TransferLock` ops; bridge service fees are market-priced and out of scope)
- [DEP-08](DEP-08.md): Deposits (descriptor witnesses, `receive_requires_sig` — still relevant for the legacy deterrence path)
- [DEP-13](DEP-13.md): Couriers (HTLC/PTLC patterns; the Lightning bridge is the same pattern with one leg on BOLT-11 instead of a sister ledger)
- [DEP-16](DEP-16.md): Descriptor calculus (`pointlock` capability gates the PTLC variant of the bridge)
