# Chapter 9: Payment Channels

> **Audience**: wallet users, integrators, operators
> **Prereqs**: chapters 3 (Lightning section), 6, 8
> **DEPs**: DEP-10

The chapter title is a bit of a tease. "Payment Channels" in DEP-10 does not mean a deposits-protocol equivalent of Lightning channels — there are no off-chain HTLC trees between deposits and operators, no commitment transactions, no force-close path. What DEP-10 specifies is the *bridging surface* between a deposits ledger and the outside payment world: the operations a wallet uses to send Bitcoin out of a deposit and pull Bitcoin into one, primarily through Lightning, with on-chain transactions covered as the matching bookend.

The mental model from [Chapter 2](02-mental-model.md) holds: a deposit is a stable account on a ledger, balances are tracked in millisatoshis, and the operator owns an on-chain UTXO that anchors the whole thing. Lightning bridging is the operator saying "I will route my Lightning node's liquidity on your deposit's behalf, and the ledger will keep accounting honest." The wallet is not running a Lightning node. The deposit does not have a Lightning channel. The operator's Lightning node is the one and only LN endpoint that the protocol talks about, and the trust boundary that comes with it is the central thing this chapter has to teach.

## What problem this solves

A custody-scaling protocol that cannot send and receive Lightning is not a custody-scaling protocol; it is an on-chain wallet with extra steps. The whole point of holding a deposit instead of a hot wallet is that the deposit can act like a balance — you receive payments while offline, you spend without paying mining fees per spend, and the operator absorbs the routing and liquidity headaches you would otherwise have to manage yourself.

The challenge is that Lightning is, fundamentally, a system of mutual obligations between two channel counterparties, and the deposit holder is not a counterparty to any of those channels. The operator's LN node is. So when "the deposit" pays an invoice, what actually happens is: the operator's LN node pays it, and the ledger records that the deposit has been debited the corresponding amount. When "the deposit" receives, the operator's LN node receives, and the ledger records that the deposit has been credited.

The protocol's job is to make that recording cryptographically committed, observable to the wallet, and — to whatever extent is technically possible — fraud-detectable. DEP-10 lays out the operations and a brief but unflinching account of where fraud detection runs out.

## The setup

An operator who offers Lightning runs a Lightning node alongside the deposits daemon. The reference implementation supports LDK via a sidecar (`deposits-node/src/ldk_cli.rs` is the thin client that talks to it), but the protocol does not bind to LDK specifically — any node that can create BOLT-11 invoices and pay BOLT-11 invoices works. The LN node is the operator's. Its channel graph, its peers, its liquidity decisions, its fee policies — all of those are out-of-protocol.

Wallets do not run a Lightning node. They do not maintain channels. They do not need to be online when payments arrive. From the wallet's perspective, Lightning bridging is one or two requests over Nostr to the operator, plus eventually a `Kind:9100` ledger update committing the credit or debit. Same flow shape as deposits and transfers from [Chapter 8](08-deposits-and-transfers.md).

The four ledger operations that drive the Lightning surface are:

- `InvoiceCredit` (discriminant 30) — the operator's LN node received a payment for a deposit; credit it.
- `InvoiceLock` (31) — lock funds against a BOLT-11 invoice the deposit is going to pay.
- `InvoiceFail` (32) — the locked payment failed; release the funds, charge the failure fee.
- `InvoiceFulfill` (33) — the locked payment succeeded; debit the deposit, surface the preimage.

The on-chain analogues are `OnchainCredit` / `OnchainLock` / `OnchainFail` / `OnchainFulfill`. We touch on those at the end; their main treatment is in [Chapter 5](05-onchain-transactions.md).

Defined in `deposits-protocol/src/messages/types.rs`. Validated in `deposits-core/src/message_handlers/`. Driven from `deposits-node/src/node/request_handlers/invoice.rs`.

## Receiving a payment

Bob has a deposit on Alice's ledger. Someone — let us say Carol, who happens to be Bob's friend and is not a depositor on this ledger or any other deposits ledger — wants to send Bob 5,000 sats. From Carol's side this is just a Lightning payment to a BOLT-11 invoice. From Bob's side it is a deposit credit. From Alice's side it is two pieces of work: her LN node has to receive the payment, and her ledger has to be updated to credit Bob.

The flow:

1. Bob's wallet sends a `make_invoice` request to Alice over Nostr. The request specifies the deposit pubkey, the amount in sats, and an optional description. Wire shape: `Kind:20100` request event tagged with Alice's npub and the ledger ID; payload is JSON.

2. Alice's daemon receives the request (`process_make_invoice_request`). It checks that the deposit exists, validates the receive-signature if `receive_requires_sig` is set on the deposit, and verifies that creating a 5,000-sat obligation does not push the ledger over its [collateral obligation limits](07-quorum-and-collateral.md). If anything fails, Alice responds with an error and nothing else happens.

3. Alice asks her LN node (via `ldk_cli`) to create a BOLT-11 invoice for 5,000,000 msat. The LN node returns an invoice string and a payment hash.

4. Alice records a `PendingInvoice` in her in-memory map: `payment_hash → (ledger_id, deposit_id, amount, invoice string)`. This is what tells the daemon which deposit to credit when the payment lands.

5. If the ledger is post-rotation (its quorum has been activated — see [Chapter 7](07-quorum-and-collateral.md)), Alice fans out a `cosign_invoice` request to her quorum members. A member co-signs by computing the BIP-340 tagged hash from DEP-10:

   ```
   tag    = SHA256("deposits/invoice_cosign")
   data   = ledger_id || payment_hash || deposit_id || amount_msat_le64
   digest = SHA256(tag || tag || data || member_ledger_hash)
   ```

   and signing it with their operator key. The cosignature, the member's pubkey, and the member's `member_ledger_hash` (the content hash of the most recent update on the member's *own* ledger, used to bind this attestation to a specific point in the member's history) come back to Alice.

6. Alice replies to Bob's wallet with the invoice string, payment hash, deposit info, the cosigner's pubkey, the member's ledger hash, and the cosignature. **This response is the evidence package Bob's wallet retains.**

7. Bob's wallet hands the BOLT-11 invoice to Carol. The handoff happens entirely outside the protocol — text message, QR code, email, whatever Bob and Carol normally use.

8. Carol pays the invoice from her own LN wallet. Her LN wallet does not speak deposits-protocol. To it, this is just another Lightning payment. The payment routes through the network, eventually reaches Alice's LN node, and Alice's LN node releases the preimage to settle the HTLC.

9. Alice's daemon, on its next polling cycle, notices that the previously-pending invoice has been paid. It commits a `LedgerOperation::InvoiceCredit { payment_hash, deposit_id, amount, invoice_id, sequence_number }` to the ledger. Quorum members co-sign the update (they validate that this `payment_hash` was previously announced via a co-signed invoice and that the credit amount matches). Alice broadcasts the signed update on `Kind:9100`.

10. Bob's wallet, the next time it syncs, sees `InvoiceCredit` on his ledger and updates the local balance. The 5,000 sats are now spendable from Bob's deposit.

The cosignature in step 5 is doing the load-bearing work that makes step 9 fraud-provable. Without it, Alice could deny ever issuing the invoice. With it, Bob holds a signed promise from a quorum member that Alice committed to crediting `deposit_id` with `amount` msat upon receipt of `payment_hash`. If Alice's LN node receives the payment but Alice never commits the credit, that signed promise plus a copy of the preimage (which the payer can produce, since they paid the invoice themselves) becomes a fraud proof.

The full fraud-proof construction is the subject of [Chapter 11](11-fraud-proofs.md). What matters here is the wallet-side responsibility: **retain the cosigned invoice until the credit appears on the ledger**, because without it the wallet cannot prove that an obligation existed.

## Sending a payment

Bob wants to pay Eve a Lightning invoice for 7,500 sats. Eve, like Carol, is just somebody on the wider Lightning network. She's not a depositor here.

The flow looks symmetric to the receive case but works differently underneath:

1. Bob's wallet constructs a `pay_invoice` request: deposit pubkey, the BOLT-11 invoice string, the payment hash, the amount in msat, and a Schnorr signature over `(deposit_id, payment_hash, amount_msat)` that proves Bob authorizes the spend. Sent as `Kind:20100` to Alice.

2. Alice's daemon (`process_pay_invoice_request`) parses the invoice, verifies that the client-supplied payment hash and amount match the BOLT-11 fields, verifies Bob's authorization signature, and confirms that Bob's deposit has at least the requested amount in available balance.

3. Alice constructs `LedgerOperation::InvoiceLock { deposit_id, amount, payment_id, sequence_number, witness }` where `witness` carries Bob's authorization signature. The lock is committed via the standard staged-commit / cosign path: members validate, co-sign, the operator broadcasts. From this moment forward, `amount` is `locked` in Bob's deposit balance, not available, but also not yet debited.

4. Alice tells her LN node to pay the invoice. The LN node attempts to route the payment.

5a. **Success path.** The LN node finds a route, the HTLCs settle, the LN node receives the preimage. Alice commits `LedgerOperation::InvoiceFulfill { deposit_id, amount, payment_id, sequence_number, witness, preimage }`. The `apply` function collapses the lock — Bob's locked balance drops by `amount`, his total balance drops by the same amount, the deposit is debited net. The preimage is recorded in the operation, which means anybody auditing the chain can later prove the payment was actually delivered.

5b. **Failure path.** The LN node tries every route it knows and fails — no liquidity, no path, deadline exceeded, whatever. Alice commits `LedgerOperation::InvoiceFail { deposit_id, amount, payment_id, sequence_number }`. The lock is released: Bob's locked balance drops by `amount`, total balance is unchanged at the level of the locked-out funds, but the deposit is charged a fixed transfer-fee for the failure (see [Chapter 10](10-fees-and-time.md)). Bob's wallet, on next sync, sees the lock open and close in the same direction without a net debit — modulo the failure fee.

The asymmetry between fulfill and fail matters. `InvoiceFulfill` carries the preimage; `InvoiceFail` does not. That's not an oversight — there is no preimage in a failed payment, by definition, because the receiver never released it. The presence of a preimage on the ledger is precisely what tells an auditor "this payment was actually delivered." A pattern where Alice always commits `InvoiceFulfill` without a real preimage would be a non-conforming chain: members would refuse to co-sign because they cannot validate the preimage against the locked payment hash (the preimage's SHA-256 must equal `payment_id`). A pattern where Alice commits `InvoiceFail` for payments that actually succeeded is a different and harder-to-detect attack — and it's the symmetric concern of the receive-side fraud, addressed below.

## Internal settle

Now consider the case where Bob is paying *another deposit on the same ledger*. Maybe Bob is paying Frank, who also has a deposit on Alice's ledger. The natural way this could work — Bob pays an invoice, it routes through the LN network, eventually back to Alice's own LN node, settles, Alice credits Frank — does work, but it's wasteful. Lightning routing fees apply, routing failures are possible, and the actual money never has to leave the Lightning node's books.

DEP-10 §"Self-Pay" gives the operator latitude to settle internally. The implementation in `process_pay_invoice_request` checks whether the payment hash is in `pending_invoices` (meaning: this is an invoice that Alice herself created, ergo for one of her own deposits). If so, instead of asking the LN node to pay, Alice commits two extra operations atomically:

- `InvoiceFulfill` for Bob's outgoing payment (debits Bob's deposit).
- `InvoiceCredit` for Frank's incoming payment (credits Frank's deposit).

The `preimage` field on the fulfill is set to all zeros for self-pay, since no Lightning HTLC ever existed. Members validate the operation by accepting that `payment_id` matches a pending invoice on this ledger.

Same accounting outcome as the routed case: Bob debited, Frank credited, ledger conformance preserved. No routing fees, no routing failures, no need to convince the wider network to find a path. The only thing the wallets see, on sync, is two ledger updates that net out to a transfer.

The implementation also detects "cross-node self-pay" — the case where Bob and Frank are on different ledgers but those ledgers' operators share a Lightning node (a common arrangement in cluster deployments). LDK reports `already initiated` when asked to pay an invoice it already issued; the daemon recognizes that and lets the background `auto_complete_outbound_payments` task settle the payment when LDK finishes.

## The Lightning fraud-proof story

Here is where the trust boundary becomes explicit. DEP-10 §"Lightning Trust Boundary" puts it bluntly:

> Lightning invoice fraud is not autonomously provable. The operator's lightning node is a trust boundary that the protocol cannot fully bridge — the operator knows whether the preimage was received, but the wallet does not.

The asymmetry: when Bob's wallet asks Alice for an invoice, Alice promises (via her own signature on the resulting ledger update structure, plus the cosignature from the quorum member) that any payment to that BOLT-11 invoice will be credited to Bob's deposit. The promise is on the ledger. But the trigger for the promise — "Alice's LN node received the payment" — happens entirely inside Alice's infrastructure. Nostr cannot observe it. Bitcoin Core cannot observe it. The protocol, sitting where it does, cannot prove that Alice received unless someone external comes forward with evidence.

That someone is the payer. Whoever paid the invoice has the preimage — Lightning's settlement protocol guarantees they do, that's what makes the HTLC release. The preimage's SHA-256 is the payment hash; it's a 32-byte cryptographic certificate that the payment was settled on the LN side. If the payer ever shares that preimage with anybody, the recipient can construct a fraud proof:

- The cosigned invoice (from step 6 above) proves Alice committed to crediting `deposit_id` with `amount` if `payment_hash` was paid.
- The preimage proves `payment_hash` was paid.
- The absence of an `InvoiceCredit` for that `payment_hash` on Alice's ledger, after the deadline window, proves Alice did not credit.

That triple, packaged together, is the fraud-proof shape DEP-06 specifies. We get to the full construction in [Chapter 11](11-fraud-proofs.md). What this chapter has to convey is the deterrence story: Alice has the *technical* ability to skim payments — she could let her LN node receive a payment and then "forget" to commit the `InvoiceCredit`. What she does not have is the ability to do this without risk. Any payer who shares the preimage exposes her. The whitepaper's framing: stealing a single payment of *N* sats vs. losing the entire collateral if caught. With the reference 40/60 split, an operator running a 4 BTC reserves UTXO has 6 BTC in collateral. Even at *N* = the full reserves capacity, the steal-once expected value is negative as long as the probability of a payer ever sharing a preimage exceeds reserves/(reserves + collateral) — and that ratio is at most 40%, often much less. The whitepaper's claim is that this probability is overwhelmingly higher than 40% in practice, because preimages leak: payers share them with friends, payment processors retain them in logs, automated services publish them on monitoring channels, and so on.

DEP-10 lists the wallet-side mitigations: limit outstanding uncredited invoices per operator (so the steal-once horizon is bounded), prefer on-chain funding for amounts exceeding wallet risk tolerance (because on-chain credit is autonomously fraud-provable — confirmed funding goes to a known address with a known deadline block, no third-party preimage required), and for high-value invoices, arrange out-of-band proof-of-payment with the payer.

## Onchain lock path

The on-chain analogue is shorter to describe because it works the same way structurally. A wallet requests a withdrawal — destination address, amount, fee, and a witness satisfying the deposit's descriptor. The operator commits `OnchainLock` with the withdrawal_id, amount, destination, and fee, then constructs the Bitcoin transaction, broadcasts, and waits for confirmation:

- On confirmation, the operator commits `OnchainFulfill` with the txid. The lock collapses, the deposit is debited.
- On failure (the broadcast doesn't confirm in the deadline window, or the transaction can't be assembled), the operator commits `OnchainFail`. The lock releases the `amount + miner_fee`, and the deposit is charged the fixed transfer-fee for failures.

Critically, the on-chain *receive* side has a different structure (offers, not invoices) that DEP-10 §"On-chain Funding" specifies and [Chapter 5](05-onchain-transactions.md) walks through. The fraud story on receive is also stronger: an operator cannot deny seeing an on-chain payment, because Bitcoin is autonomously observable. That's the protocol's preferred path for high-value funding — no preimage-leakage assumption required.

For sends, the cooperative-exit path is the on-chain analogue of the Lightning path. Same accounting shape, same lock-fulfill-fail state machine. Mining fees replace routing fees as the variable cost.

## Wallet-side responsibilities

Three duties for a wallet that uses Lightning bridging seriously:

**Retain cosigned invoices.** The cosigned invoice is the only evidence that an obligation existed. The wallet's local store should keep the invoice string, the payment hash, the cosigner pubkey, the member ledger hash, the cosignature, and the deposit info — keyed by payment hash — until the matching `InvoiceCredit` is observed on the ledger or the deadline expires. Lose the cosignature, lose the ability to prove fraud.

**Verify the cosignature on receipt.** When the operator returns a `make_invoice` response with cosign fields, recompute the BIP-340 tagged hash and call `verify_schnorr` against the cosigner's pubkey. The cosigner pubkey itself should be checked against the ledger's known quorum (an operator who returns a cosignature from a key not in the quorum is misbehaving). The wallet's verification logic mirrors what fraud-proof verifiers will run on the same data — same hash, same key, same library.

**Poll for credit updates.** The wallet should subscribe to its operators' `Kind:9100` events and apply each `SignedLedgerUpdate` to a local replica of ledger state. When `InvoiceCredit` arrives matching a retained invoice, the wallet can drop the retention. Polling cadence is a wallet-policy decision; the protocol does not require any particular interval, but unusual lag (a deadline approaching with no credit) is the signal to escalate.

The send side has a complementary duty: the wallet should track outstanding `InvoiceLock` operations and flag operators that consistently produce `InvoiceFail` for payments that succeeded (this is detectable when the wallet has out-of-band confirmation that the receiver did get paid). That detection feeds into [Chapter 11](11-fraud-proofs.md)'s fraud-proof construction for "uncredited Lightning payment" reused on the send side as "falsely-failed Lightning payment."

## A worked example

Bob holds a deposit on Alice's ledger. The deposit has 12,000 sats balance, 0 sats locked. Bob wants Carol — an external party with a regular Lightning wallet — to send him 5,000 sats.

```
1. Bob's wallet → Alice (Nostr Kind:20100, "make_invoice"):
   {
     "ledger_id": "0xabc...def",
     "deposit_pubkey": "0x02bob...",
     "amount_sats": 5000,
     "description": "coffee owed"
   }

2. Alice's daemon:
   - validates deposit_pubkey resolves to deposit_id "0xb0b1..."
   - verifies obligation limits (5,000,000 msat fits under reserves)
   - calls ldk_cli.create_invoice(5_000_000, "coffee owed")
   - LDK returns: invoice="lnbc50u1p...", payment_hash="0x4d2a..."
   - records pending: payment_hash → (ledger, deposit_id, 5_000_000, invoice)
   - sends cosign_invoice to quorum member Mallory
   - Mallory computes the tagged hash, signs, returns:
     {
       "cosign_signature": "0x1f8c...",
       "cosigner_pubkey":  "0x02mall...",
       "cosigner_ledger_hash": "0xdead..."
     }

3. Alice → Bob's wallet (Nostr Kind:20101 response):
   {
     "invoice":          "lnbc50u1p...",
     "deposit_id":       "0xb0b1...",
     "payment_hash":     "0x4d2a...",
     "cosign_signature": "0x1f8c...",
     "cosigner_pubkey":  "0x02mall...",
     "cosigner_ledger_hash": "0xdead..."
   }

4. Bob's wallet:
   - verifies invoice's payment_hash matches the response field
   - recomputes the cosign tagged hash and Schnorr-verifies it
   - stores the cosigned invoice in its retention store
   - hands "lnbc50u1p..." to Carol via SMS

5. Carol pays "lnbc50u1p..." from her LN wallet. Routing happens.

6. Alice's LN node settles the payment, receives the preimage.

7. Alice's daemon (next poll cycle):
   - matches payment_hash to the pending invoice
   - commits InvoiceCredit {
       payment_hash: 0x4d2a...,
       deposit_id:   0xb0b1...,
       amount:       5_000_000,
       invoice_id:   "lnbc50u1p...",
       sequence_number: <next>
     }
   - quorum members validate and co-sign
   - broadcasts SignedLedgerUpdate as Kind:9100

8. Bob's wallet (next sync):
   - decodes the Kind:9100 event
   - applies InvoiceCredit, deposit balance becomes 17,000 sats
   - drops the retained invoice for payment_hash 0x4d2a...
```

If step 7 had not happened — Alice received but did not commit — Bob's wallet would have noticed the deadline approaching with the invoice still retained. At that point, with Carol's preimage in hand (Carol can produce it from her LN wallet's logs), Bob's wallet has the materials to construct the fraud proof. The cosigned invoice supplies the obligation; the preimage supplies the trigger; the missing `InvoiceCredit` supplies the breach. [Chapter 11](11-fraud-proofs.md) covers how that proof is packaged and what happens next.

## What stays in your head

- Lightning bridging is the operator's LN node acting on the deposit's behalf. Wallets do not run Lightning. The trust boundary is the operator's node.
- Receive: wallet asks for an invoice, operator and one quorum member co-sign the obligation, payer pays the invoice out-of-band, operator commits `InvoiceCredit` on receipt.
- Send: wallet authorizes spending, operator commits `InvoiceLock`, LN node attempts payment, success → `InvoiceFulfill` (with preimage), failure → `InvoiceFail` (with failure fee).
- Self-pay: same operator settles internally, two extra operations, no LN routing.
- The Lightning fraud-proof story relies on a payer ever sharing the preimage. Steal-once economics make it irrational, but the autonomy is weaker than on-chain.
- Wallets must retain cosigned invoices until the matching credit lands or the deadline expires. Without retention there is no fraud proof.
- On-chain has the same lock-fulfill-fail shape on the send side, plus a stronger autonomous fraud story on the receive side via offers (Chapter 5).

## Where this leads

[Chapter 10](10-fees-and-time.md) covers the fee schedule that hangs off every deposit and the time-obligation parameters that put deadlines on every operation in this chapter — failure fees, response windows, deadline blocks, fee assessment cadence. The fraud-proof construction for uncredited Lightning, alluded to throughout this chapter, is in [Chapter 11](11-fraud-proofs.md).
