# Chapter 16: Couriers

> **Audience**: wallet users, integrators (especially payment processors), developers
> **Prereqs**: chapters 3 (HTLCs), 8, 9
> **DEPs**: DEP-13

A deposit lives on exactly one ledger. The accounting that makes a deposit possible — the operator's reserves UTXO, the quorum that co-signs, the conformance rules — are all per-ledger. There is no protocol-level "send N sats from Alice's deposit on Ledger A to Bob's deposit on Ledger B." The two ledgers do not share a state machine and have no reason to trust each other's updates.

This is a deliberate consequence of the protocol's shape. Each ledger is its own custody arrangement; making them interchangeable would compromise the slashing model. But it is also a real practical problem: a wallet on Ledger A wants to push value to a deposit on Ledger B, and the protocol owes them an answer.

The answer is *couriers*. A courier is a third party — usually an automated service — that holds deposits on multiple ledgers and atomically swaps value between them for a fee. The mechanism is a hash-time-locked contract, the same primitive Lightning routing uses. The protocol gives couriers exactly one piece of dedicated machinery: a `TransferLock` operation whose completion can be gated on a hash preimage. Everything else — discovery, pricing, liquidity management — is out-of-protocol policy that runs in the courier's own software.

## What problem this solves

Deposits are per-ledger, operators are per-ledger, slashing is per-ledger. The fact that multiple ledgers exist on the same Bitcoin network is a deployment fact, not a protocol fact. A wallet with deposits on Ledger A, B, and C has three separate custody relationships with three separate operators under three separate quorums.

But users think "I want to pay this person." If the recipient deposits on a ledger the sender does not, the options are:

1. Withdraw to on-chain, then have the recipient deposit. Slow (102-block confirmation depth, see [Chapter 5](05-onchain-transactions.md)) and burns mining fees on both ends. For small payments, unusably expensive.

2. Pay through Lightning, via the sender's operator's LN node. Works if the amount fits a Lightning route, but it forces the recipient to surface a Lightning invoice — meaning *their* operator has to be online for the payment to land — which is a stronger uptime condition than a deposit.

3. Use a courier: an intermediary that already has deposits on both A and B. The sender locks to the courier on A under a hash; the courier places a matching lock on B; the recipient reveals the preimage on B to claim; the courier uses the same preimage on A to claim. Atomic, no on-chain footprint, no Lightning route to find.

The courier pattern is option 3. It is not a panacea — it requires a willing courier with liquidity on both sides — but in steady state it makes the per-ledger custody model look like a single payment surface to the user, the way Lightning's channel graph makes the per-channel model look like one.

## The HTLC primitive

The piece of machinery the protocol gives couriers is `TransferLock` with a `completion_script` (`deposits-protocol/src/messages/types.rs`). A `TransferLock` reserves an amount from a source deposit and earmarks it for a destination deposit on the same ledger. The earmark is conditional: the destination only gets the funds if it can produce a witness satisfying `completion_script` before `timeout_height`. Past the deadline, the funds return to the source via `TransferFail`.

Two ways to satisfy the script. The first is a wallet-key signature, used by the one-shot transfers in [Chapter 8](08-deposits-and-transfers.md). The second — the one couriers depend on — is a hash preimage. The script `sha256(<32-byte hash>)` is satisfied by a witness whose stack contains the 32-byte preimage `r` such that `SHA256(r)` equals the hash. The htlc-agent reference implementation recognizes only this script form (`extract_hash_from_script` in `deposits-node/src/bin/htlc-agent.rs`); other shapes are not routable.

A courier holds deposits on two or more ledgers. To move value from Ledger A to Ledger B, it places one HTLC on A (the wallet locks to the courier's deposit) and a matching HTLC on B (the courier locks to the wallet's destination deposit). Same hash on both sides. Whichever side reveals the preimage first leaks it; the other side claims with it. The hash binds the two halves; the timeouts make the dance safe.

## The dance

Here is the canonical four-step flow, with the actors named and the operations labeled. The wallet has a deposit on Ledger A and a deposit on Ledger B (the destination deposit can belong to a different identity — a wallet sending to a friend — but for the protocol it just has to be a known deposit ID on B). The courier holds deposits on both ledgers.

1. **Wallet generates a preimage.** The wallet picks a random 32-byte `r`, computes `H = SHA256(r)`, and keeps `r` private. `H` is what will appear on the wire on both ledgers.

2. **Wallet asks the courier for a route.** The wallet sends a `request_route` request to the courier over Nostr (`Kind:20101` with `action=request_route`, addressed by `#p` to the courier's npub). The payload tells the courier the source ledger, the destination ledger, the destination deposit ID, the amount, and the hash `H`. The courier responds (`Kind:20102`) with the deposit ID it controls on the source ledger (where the wallet should lock to), the total fee, and the forward amount the courier promises to lock on the destination ledger. The courier also stashes the route in its `pending_routes` table keyed by `H`, so when an inbound lock with that hash arrives it knows where to forward.

3. **Wallet locks on Ledger A (the inbound side).** The wallet issues a `TransferLock` on A: source = wallet's deposit on A, destination = courier's deposit on A (from the route response), amount = the full transfer amount, completion script = `sha256(H)`, timeout height = current block + a generous safety margin. DEP-13's reference value is 288 blocks (~2 days); the operator's quorum policy may cap it lower (`max_transfer_timeout_blocks`). The operator on A signs and broadcasts. Money is now reserved on A, claimable by anyone who can produce `r` before the timeout.

4. **Courier locks on Ledger B (the outbound side).** The courier's daemon is subscribed to ledger updates tagged with its deposit IDs (`#i` tag, see [Chapter 6](06-peer-messaging.md)). When it sees the inbound `TransferLock` from step 3, it looks up `H` in `pending_routes` to recover the destination, and issues its own `TransferLock` on B: source = courier's deposit on B, destination = wallet's deposit on B (from the pending route), amount = `forward_amount` (the inbound amount minus the full route fee), same `sha256(H)` script, **timeout height strictly earlier than the inbound timeout** (typically inbound − 144 blocks, which is the courier's `timeout_margin_blocks`).

5. **Wallet completes on B.** The wallet was monitoring B for any `TransferLock` targeting its deposit with hash `H`. When it sees one, it issues a `TransferComplete` on B with `r` in the witness stack. The operator on B applies it; the wallet's deposit on B is credited the forward amount. The preimage is now publicly visible on B's chain, in the witness of the `TransferComplete` update.

6. **Courier completes on A.** The courier's daemon is subscribed to `TransferComplete` events on B's ledger (filtered by `#d` for the ledger ID and `#t=71` for the operation discriminant). When it sees one whose witness contains a preimage matching one of its outstanding routes, it pulls `r` out of the witness and issues a `TransferComplete` on A using the same preimage. The operator on A applies it; the courier's deposit on A is credited the inbound amount. Done.

End state: wallet's deposit on A is debited the full amount, wallet's deposit on B credited `amount − fees`, courier's deposit on A credited the full amount, courier's deposit on B debited the forward amount. The courier earned `route_fee` minus the operator transfer fees on each side; the wallet lost `route_fee` worth of value; everything else moved cleanly.

The whole dance is six operations on the wire — one `TransferLock` and one `TransferComplete` per ledger, plus the route request and response — and takes as long as the slower of the two ledgers' commit pipelines, a few seconds in steady state.

## Timeout discipline is the whole game

The reason this works without trust is the inequality `T_B < T_A`:

- If the wallet never reveals `r`: B times out first, returning the courier's funds. Then A times out, returning the wallet's funds. Nobody loses.

- If the wallet reveals `r` at the last possible moment on B (just before T_B): the courier still has `T_A − T_B` blocks — the timeout margin — to observe the preimage on B and use it on A. A 144-block margin (~24 hours) is comfortable even for a briefly-offline courier.

- If `T_B ≥ T_A`: the wallet waits until *just after* T_A (the inbound side fails, wallet's funds return on A), then reveals `r` on B before T_B and claims the outbound side too. The courier loses the outbound lock without the matching inbound credit. This is the *only* way the courier can lose, and it depends entirely on the timeout ordering being inverted. The htlc-agent enforces `outbound_timeout = inbound_timeout − timeout_margin_blocks` when placing the outbound lock.

DEP-13's security note phrases this as the one thing a courier cannot get wrong. Everything else is recoverable.

The wallet has a milder symmetric concern. If it picks `T_A` too close to the current block height, the courier may not have time to place the outbound before the inbound expires — the wallet just sees a `TransferFail` on A and retries with a longer timeout. No loss, just a wasted round-trip. DEP-13 recommends `T_A ≥ 2 × timeout_margin_blocks`.

The operators on each side enforce timeouts (`auto-complete-transfers` and timeout-fail logic in `deposits-node/src/node/auto_tasks.rs`). They see only their own ledger and have no idea this is part of a cross-ledger swap; from their perspective it is a hash-locked transfer like any other.

## Discovery

A wallet that wants to pay a deposit on Ledger B from a deposit on Ledger A needs to find a courier that bridges the two. The mechanism is a Nostr advertisement.

Couriers publish `Kind:39102` events to a discovery relay (the "ledgers relay" — the durable one that retains advertisements; see [Chapter 6](06-peer-messaging.md)). The event is NIP-33 replaceable, keyed on the courier pubkey, so each courier has at most one current advertisement and updates supersede prior ones.

The advertisement payload is JSON listing every ledger the courier holds a deposit on, with per-ledger fields:

- `ledger_id` and `deposit_id`: the courier's deposit on that ledger, where wallets can lock to.
- `balance_msats`: the courier's available balance on that ledger. Wallets use this to size their requests; if the balance is too small to cover the route, there is no point asking.
- `fee_in_fixed_msats`, `fee_in_rate_bps`: the courier's margin for *receiving* on this ledger. Pure profit on the courier's side; receiving costs the courier nothing operationally.
- `fee_out_fixed_msats`, `fee_out_rate_bps`: the courier's price for *sending* from this ledger. This is the operator's transfer fee on this ledger plus a margin; sending costs the courier the operator's fee plus whatever margin the courier wants to keep.

Wallets fetch these advertisements (filter on `kind=39102` and the network tag), build a list of couriers that bridge the source and destination ledgers they care about, and pick one based on fees, available capacity, or any other policy the wallet's UX exposes. Multiple couriers may bridge the same pair, and DEP-13 explicitly intends for this to be a competitive market.

Discovery is one-shot. A wallet that knows it wants to pay a particular destination can fetch advertisements once, pick a courier, and proceed; it does not need to maintain a long-lived view of the courier landscape. Advertisements are republished by the courier on a timer (the htlc-agent does this every 30 minutes) so stale data ages out naturally.

## Pricing and rebalancing

The fee model is two-sided. A route from Ledger A to Ledger B passes through two courier deposits — inbound on A, outbound on B — and each side has its own fee:

```
route_fee = fee_out(A, amount) + fee_in(B, amount)
```

each term computed as `fixed_msats + amount_msats × rate_bps / 10000`. The wallet pays `amount`; the recipient on B gets `amount − route_fee`; the courier keeps `route_fee` minus the operator transfer fees it pays on each side.

`fee_in(B)` is the courier's margin for receiving on B. Claiming an inbound lock with the preimage costs the courier nothing on the wire, so this is pure margin. `fee_out(A)` is the price the courier charges to spend its own liquidity on the outbound side (note: the advertisement names `fee_out` per ledger, but in a route from A to B the courier actually sends from B; the wallet sums the *source* ledger's `fee_out` and the *destination* ledger's `fee_in` to get the total, mirroring how the htlc-agent computes it).

The interesting consequence is liquidity rebalancing. A courier flush on A but starved on B raises `fee_in` on A and lowers `fee_in` on B; A → B routes get cheaper, B → A routes get more expensive, and traffic shifts toward the direction that refills B. No explicit rebalancing transactions, no manual operator action — prices and balances find each other. Same idea as Lightning routing-node fee schedules.

Couriers also pass through operator transfer fees. If Operator B charges 0.1% per transfer, that lands in the courier's `fee_out(B)` automatically. The htlc-agent reads operator fees from the `Kind:39100` advertisements at startup and bakes them into its own outbound margin.

## Couriers are not first-class actors

Worth saying flatly: there is no `CourierOpen` or `CourierAdvertise` operation in the ledger state machine. Couriers do not appear in any quorum. The protocol does not know what a courier is.

What the protocol provides is the HTLC primitive (`TransferLock` with `sha256(H)`), the messaging plumbing (`Kind:20101/20102` request/response, the request-route action), and a Nostr event kind reserved for advertisements (`Kind:39102`). On top of those, anyone with deposits on multiple ledgers can run a courier — the htlc-agent binary in `deposits-node/src/bin/htlc-agent.rs` is one implementation, but there is no requirement to use it. A courier could be a single human with a wallet running the requests by hand. It would be slow, but it would work.

This shapes what couriers can and cannot do. They cannot censor based on deposit identity in a way that survives competition: if Carol-the-courier refuses to route Alice's payment, Alice can find a different courier. They cannot break atomicity: the HTLC primitive is enforced by the operators on each side, not by the courier. They cannot steal funds in steady state: timeouts protect both sides as long as the courier sets `T_B < T_A`.

What they can do is set whatever fees they want, refuse routes for whatever reason (DEP-13 does not require them to accept any particular request), go offline (in which case routes return to wallets via timeout), and exit the market entirely. None of this is a protocol concern. A courier is a market role; the market sorts it out.

## A worked example

Concrete numbers. Alice has a deposit on Ledger A with 100,000 sats. Bob has a deposit on Ledger B. Alice wants to send 10,000 sats to Bob. (Bob is a different identity; his deposit is on a different ledger; this is the case the courier exists for.)

Carol runs a courier bridging A and B. Her advertisement publishes flat per-leg fees: `fee_out(A) = 20 sats`, `fee_in(B) = 30 sats`. (In a real advertisement these are `fixed + rate_bps` formulas; for a 10,000-sat route at typical bps values they evaluate to roughly these numbers, so we will use the flat figures here.) Alice computes the route fee as 20 + 30 = 50 sats, forward amount 9,950 sats.

Step by step:

1. **Preimage**. Alice's wallet generates `r` (32 random bytes) and computes `H = SHA256(r)`. `H` is a 32-byte hash.

2. **Route request**. Alice sends Carol a `request_route` over Nostr: `{source_ledger: A, dest_ledger: B, dest_deposit_id: bob_on_B, amount_msats: 10_000_000, hash: H}`. Carol responds with `{courier_deposit_id: carol_on_A, fee_msats: 50_000, forward_amount_msats: 9_950_000}` and stores the route in her pending table keyed on `H`.

3. **Inbound lock on A**. Alice's wallet looks up the current block height on A — say block 800,000 — and issues `TransferLock(source=alice_on_A, destination=carol_on_A, amount=10_000_000, completion_script=sha256(H), timeout_height=800_288)`. Operator A signs and broadcasts. The 10,000-sat lock is now visible on A's chain.

4. **Outbound lock on B**. Carol's daemon sees the inbound lock (it was subscribed to events tagged with `carol_on_A`). It looks up `H` in pending routes, finds Alice's request, and issues on B: `TransferLock(source=carol_on_B, destination=bob_on_B, amount=9_950_000, completion_script=sha256(H), timeout_height=800_144)` (assuming B is at the same block height; in practice the timeout is computed from B's current height as `B_now + (T_A − T_B_margin)` where the margin is 144 blocks). Operator B signs and broadcasts. The 9,950-sat lock is now visible on B's chain, and from Bob's perspective there is a pending HTLC he can claim.

5. **Bob completes on B**. Alice tells Bob the preimage `r` (or, if Alice and Bob are the same identity with separate wallets, Alice's wallet on B sees the lock and claims it itself). Bob's wallet issues `TransferComplete(transfer_id, witness=[r])` on B. Operator B verifies `SHA256(r) == H`, applies the operation, credits Bob 9,950 sats. The preimage is now in plain view on B's chain in the witness of the `TransferComplete` update.

6. **Carol completes on A**. Carol's daemon was subscribed to `TransferComplete` events on B (filtering by `#t=71`). It sees the completion, extracts `r` from the witness, matches it against her outstanding routes by hash, and issues on A: `TransferComplete(transfer_id, witness=[r])`. Operator A verifies, applies, credits Carol 10,000 sats.

End state:

- `alice_on_A`: −10,000 sats. `carol_on_A`: +10,000 sats. Operator A took whatever its standard transfer fee is — say 0 sats fixed, included in Alice's lock — and recorded it.
- `carol_on_B`: −9,950 sats. `bob_on_B`: +9,950 sats. Operator B's transfer fee was paid by Carol on the outbound lock.
- Carol's net: +10,000 sats on A, −9,950 sats on B, minus operator B's transfer fee. If operator B charges 30 sats per transfer, Carol cleared 50 − 30 = 20 sats on this trip. (Her advertised `fee_out(B)` margin minus what she paid the operator is exactly her net margin per route on this leg.)
- Alice's net: −10,000 sats on A, +0 on B (the 9,950 sats went to Bob, not back to her).
- Bob's net: +9,950 sats.

The 50-sat fee was split between Carol's two-sided margin and Operator B's transfer fee. Operator A's transfer fee (paid by Alice when she placed the inbound lock) is separate — that is the standard intra-ledger transfer fee and would have been paid even if Alice were transferring to another deposit on A.

## Failure modes

Things that can go wrong, and what the protocol does about each.

- **Wallet times out without revealing.** Alice changes her mind, or her wallet crashes mid-flow, or she just walks away. T_B passes first; Operator B times out the outbound lock and returns 9,950 sats to Carol on B. T_A passes; Operator A times out the inbound lock and returns 10,000 sats to Alice on A. Nobody loses. The courier wasted some operational effort (a `TransferLock` and the eventual `TransferFail` on B) and paid Operator B's transfer fee for the round-trip; that is the cost of doing business.

- **Courier vanishes after the wallet revealed on B.** Alice claims on B, the preimage is on B's chain, Carol's daemon is offline and never sees it. T_A still has time; if Alice (or anyone — the preimage is public) wants to be helpful, she could complete on A herself with the preimage and credit Carol's deposit on A; this costs nothing and is occasionally what well-behaved wallets do as a courtesy. If nobody completes on A, T_A passes, Alice gets her 10,000 sats back on A, and Carol has a 9,950-sat loss on B with no offset. This is a courier-business loss, not a protocol failure. The wallet got value (Bob has the 9,950 sats); the courier ate the loss because it could not stay online long enough to claim. Carol's incentive is not to vanish.

- **Operator on either side fails during the swap.** If Operator A goes offline mid-swap, Alice's `TransferLock` may not get co-signed; this is detected as a stale operator and falls into the [delivery escalation](15-delivery-escalation.md) path — Alice can issue a `delivery_embed` request, escalate through the quorum, and trigger a [dispute](12-recovery-pipeline.md) if Operator A is genuinely censoring. Carol participates in the dispute as any other depositor on A: her deposit on A is just one more deposit, and the recovery lottery will move it to whoever takes over custody. Same on the B side. Couriers carry no special status in disputes.

- **Operator censors the courier mid-swap.** Same as above. The courier holds a deposit on the operator's ledger, and the deposit's spending request (`TransferLock`) being ignored triggers the escalation chapter's machinery just like any other censorship case. If censorship persists, the dispute pipeline recovers; the courier's deposit moves; the swap's locks time out via the regular `TransferFail` path.

- **Courier runs out of liquidity.** A wallet asks for a route Carol cannot fund. Carol responds with a failure to the route request; the wallet picks a different courier. No locks placed; no harm.

- **Operator's transfer fee changed between advertisement and lock.** The advertisement (Kind:39100 from the operator) is replaceable; the operator can publish a new schedule. If a courier's advertised `fee_out` was based on a stale operator fee, the courier may end up paying more than it expected, eating into its margin. This is a courier-policy issue, fixable by re-fetching the operator advertisement at route-request time. The htlc-agent does this on startup; busier deployments would do it per-route.

The HTLC primitive itself is robust against the most adversarial of these — atomicity is a property of the timeouts and the hash, not of any party behaving honestly. As long as both operators apply the conformance rules and broadcast, both halves of the swap settle consistently, regardless of what the courier or wallet does between steps.

## What stays in your head

- A courier is a third party that holds deposits on multiple ledgers and atomically swaps between them via HTLC. It is not a protocol primitive; the protocol just provides `TransferLock` with a hash-preimage `completion_script`, and the courier builds the rest.
- The dance is two `TransferLock`s and two `TransferComplete`s, plus a route request/response. The wallet generates the preimage; whichever side reveals first leaks it; the timeout ordering `T_outbound < T_inbound` ensures atomicity.
- Couriers advertise via `Kind:39102` events naming the ledgers they bridge, the per-direction fees, and their available capacity. Wallets compute route cost as `fee_out(source) + fee_in(destination)`.
- The two-sided fee model gives couriers a knob to rebalance liquidity without explicit rebalancing transactions: raise the fee on the side you want to discourage, lower the fee on the side you want to encourage.
- Failure cases are bounded: timeouts protect both wallet and courier in steady state, dispute pipelines apply if an operator misbehaves, and the only way a courier can be drained is by inverting the timeout order.

## Where this leads

The next chapter covers the [attestation service](17-attestation-service.md): a Web2-rooted identity layer that lets operators (and couriers, who are operators of multiple deposits) bind their pubkeys to verifiable real-world identifiers, so wallets browsing advertisements have something to anchor trust on beyond the pubkey itself.
