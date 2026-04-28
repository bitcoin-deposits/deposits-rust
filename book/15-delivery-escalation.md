# Chapter 15: Delivery Escalation

> **Audience**: wallet users, integrators, developers, operators
> **Prereqs**: chapters 6, 7, 11
> **DEPs**: DEP-12

A protocol that punishes operators for misbehavior is only as good as its ability to detect misbehavior. The fraud-proof machinery in [Chapter 11](11-fraud-proofs.md) handles the easy cases — the operator did something visibly wrong, and there's a signed update on the ledger to point at. The harder case is when the operator does *nothing*. They receive a request and ignore it. There is no signed update. There is no public record of the request even existing. The operator's defense is "I never saw it." Without an answer to that defense, censorship is undetectable, and an undetectable misbehavior is one the protocol cannot deter.

DEP-12 is the answer. It gives wallets a way to convert "the operator ignored me" into evidence that survives on the relay, hash-chains into the operator's own ledger via the cosignature path, and arms a fraud proof if the operator continues to refuse service. The mechanism is small — one new ledger operation, one extra request kind reusing the existing wallet-to-operator transport — but it closes the last gap in the operator-misbehavior surface. After this chapter, every category of operator misbehavior has a corresponding economic deterrent.

## What problem this solves

Recall the [trust assumption](02-mental-model.md#the-trust-assumption): the protocol assumes that at least one quorum member of any given ledger is honest. Every fraud-detection mechanism in the protocol is a way of giving that one honest member something it can act on. For visible misbehavior (a non-conforming update, an uncredited Lightning payment, a stale cosignature, an inactive quorum member), the visible artifact *is* the evidence — the member sees it on the relay, constructs a fraud proof, and broadcasts.

Refusal-to-serve has no visible artifact by default. A wallet sends a Nostr request to the operator. Nostr requests are ephemeral (`Kind:20101`); relays may forward them once and then drop them. There is no delivery receipt. There is no proof the operator's daemon ever subscribed to the relay where the request was published. There is no causal ordering of "request first, then no response." If a wallet later complains, the operator has every defense an adversary could ask for: "the relay didn't forward it," "I was offline that minute," "the request was malformed," "I never saw it." None of these defenses are testable without out-of-band cooperation from the operator.

The fraud-proof machinery would gladly slash an operator for refusing service if it could prove the request happened. It can't, because nothing on Nostr — by itself — anchors a wallet's request to a verifiable point in time on a chain the operator publicly owns. DEP-12 is the missing primitive: a way for the wallet to *cause* the request to be anchored on a chain that the operator can no longer disclaim awareness of.

## The escalation primitive

A wallet that has been ignored sends the request a second time, but to a different addressee. Instead of the operator, it sends to one of the operator's **quorum members**. The member is, by definition, an operator of *some other* ledger that has its own cosignature relationship with the original operator. The member receives the request, processes the wallet's payment commitment for embedding (a small fee for the disk space and broadcast), and appends a `DeliveryEmbed` operation to its **own** ledger. That operation contains, as a payload, the SHA-256 of the original wallet request together with the target ledger ID and the target operator pubkey.

That single act creates everything the protocol needs.

The member's ledger update goes out on `Kind:9100` like every other ledger update. Relays retain it, the wallet retains a pointer to its sequence number, and — most importantly — the member's chain now includes a hash chain entry that summarizes the request. The next time the original operator co-signs an update on the member's ledger (which they do periodically, because that's what cosignatures are: each operator co-signs the *member* ledgers they belong to), the cosignature data binds the operator's signature to a `member_ledger_hash` whose preimage transitively includes the embed. The operator cannot later claim ignorance: by their own signature, they have attested to a state that contains the request hash.

From there, the chain of consequences plays out:

- If the operator processes the original request and commits it to their ledger within the deadline (`service_response_blocks`, configured per-quorum at activation time), the embed becomes a benign annotation. The wallet got its service. The member got their fee. Nobody is harmed.

- If the operator refuses to act, the deadline expires, and now the embedding becomes the missing evidence in a fraud proof. The honest member already has the embed on their own ledger; they can construct a `NonConforming` proof against the operator (by absence: the operator should have committed an `InvoiceCredit`, `OnchainCredit`, `TransferLock`, or whatever the original request was, and didn't), present it to the operator's quorum, and trigger the [recovery pipeline](12-recovery-pipeline.md). The operator's collateral becomes the member's payoff for having stepped up.

The whitepaper's framing for this is exact: *the wallet's escalation is effectively a bounty.* The wallet pays a small fee to the member for the embedding; the member's potential upside is collateral confiscation on the operator's ledger. The wallet doesn't have to convince the member to care about the request — the member's incentive structure already aligns. They embed the hash, collect the fee, and watch.

## Wire mechanics

### The request

The wallet's escalation rides the same `Kind:20101` (`KIND_LEDGER_REQUEST`) Nostr event the wallet uses for every other operator interaction. The action string is `delivery_embed`. The `p`-tag is the member's pubkey, not the operator's. The request body is JSON with three fields:

```json
{
  "request_hash":     "<32-byte hex SHA256 of the original signed request payload>",
  "target_ledger_id": "<32-byte hex ledger ID where the request should be processed>",
  "target_operator":  "<33-byte hex compressed pubkey of the original operator>"
}
```

The outer `LedgerRequest.ledger_id` field selects which of the *member's* ledgers receives the embed (a member can run several). The wallet picks; the member's daemon either has that ledger or rejects the request.

### The handler

`process_delivery_embed_request` lives in `deposits-node/src/node/request_handlers/deposits.rs:1138`. It parses and validates the three params, resolves which of the member's loaded ledgers the embed should land on, and constructs:

```rust
LedgerOperation::DeliveryEmbed {
    request_hash,
    target_ledger_id,
    target_operator,
}
```

Then it calls `commit_operation` — the same code path every other operator-side commit takes. The actor stages, requests cosignatures from *its* quorum members, operator-signs, applies, persists, and broadcasts a `Kind:9100` update with the TLV-encoded operation. The handler returns the resulting `event_id`, the new `sequence`, and the post-commit `tip_hash` so the wallet has a precise pointer back into the member's chain.

The implementation today accepts the embed unconditionally — there's no payment validation in the handler. The DEP and the CLI both call this out as a known gap: a future iteration adds a `payment_commitment` parameter (typically a signed `TransferLock` from the wallet's deposit on the member's ledger, or an off-chain settlement against an existing balance there). The structural pieces are wired; the pricing layer is the last seam to close.

### The operation on the wire

`DeliveryEmbed` is discriminant 80 in the `LedgerOperation` enum (`deposits-protocol/src/messages/types.rs:491`). Its TLV payload is exactly three fields:

| TLV tag | Field             | Size | Meaning                                                  |
|---------|-------------------|------|----------------------------------------------------------|
| 0       | discriminant      | 1    | 80                                                       |
| 270     | request_hash      | 32   | SHA-256 of the original wallet-signed request payload    |
| 272     | target_ledger_id  | 32   | The operator's ledger ID — the chain that *should* respond |
| 274     | target_operator   | 33   | The original operator's compressed secp256k1 pubkey       |

State-transition-wise, `DeliveryEmbed` is a no-op: `LedgerState::apply` returns the next state unchanged (`deposits-protocol/src/types/ledger_state.rs:632`). The operation exists purely to anchor the request hash into a hash-chained, broadcast, retention-durable ledger position. That's the whole job.

### The wallet CLI

`deposits-wallet escalate` (`deposits-wallet/src/wallet_cli/escalate.rs`) is the user-facing path:

```
deposits-wallet escalate \
    --member-ledger <member_ledger_id_hex> \
    --request-hash <32-byte hex> \
    --target-ledger <operator_ledger_id_hex> \
    --target-operator <33-byte pubkey hex> \
    --relay <ws://...>
```

It validates the hex inputs locally (so the wallet doesn't pay a relay round-trip for a malformed request), opens a Nostr transport against the messaging relay, sends the `delivery_embed` request, and waits up to 30 seconds for a `Kind:20102` response. On success it prints the embed's event id, sequence, and tip hash. On failure it prints why.

### Reservation of Kind 9105/9106

Earlier drafts of DEP-12 reserved a dedicated Nostr kind for the escalation event. In the implementation that turned out to be unnecessary: a `DeliveryEmbed` is just another ledger operation, so it rides `Kind:9100` like every other ledger update. The relay retention rules, the broadcast pipeline, the conformance checks, the cosignature flow — everything reuses the existing wire format with no new code path. DEP-12's "Public Record" section makes this explicit: the embed *is* the canonical event to watch, and the kind it lands on is the same kind operators already publish on. Kind 9105/9106 ended up assigned to the custody-lottery reveal flow (`KIND_CUSTODY_LOTTERY_REVEAL = 9106` in `deposits-node/src/nostr.rs:106`), which is unrelated to delivery escalation.

## Why it works against an adversarial operator

A natural objection: *Nostr events have no real timestamp. The operator could claim the embedding came after their would-have-processed window and deny they ever had time to act.*

The objection assumes the operator can cleanly disentangle "time my daemon was running" from "time the embed appeared on my ledger." Under the protocol's actual trust assumption, they can't. Two reasons.

First, the relay timestamps are not the load-bearing primitive. The cosignature chain is. Once the embed is in the member's chain, every subsequent member-ledger update advances `member_ledger_hash` past the embed. The operator co-signs those member-ledger updates because the cosignature relationship is mutual — that's the whole point of being on each other's quorums. As soon as the operator signs *any* member-ledger update whose hash chain transitively includes the embed, they have committed (with their own key) to a state that contains the request. They cannot later say "I never saw the request" without simultaneously saying "my own signature is invalid."

Second, the `service_response_blocks` deadline is measured in *block height on the member's ledger*, not wall-clock time. The DEP says the clock starts at the `block_height` of the `DeliveryEmbed` update. Bitcoin block heights are public, monotone, and adversary-resistant in a way that Nostr timestamps are not. The deadline is a function of the chain state, not of any party's clock. If the operator argues the embed "came too late," what they're actually arguing is that the member's chain itself is dishonest — and the member's chain has its own quorum with its own slashing risk. The dispute would now run *two* fraud proofs in parallel, against both the operator and the member, and the operator's incentive to make that argument falls apart fast.

The protocol doesn't need a real timestamp. It needs causal ordering, and the cosignature-mediated entanglement of two ledgers gives that for free.

## Wallet UX: when to escalate, what to pay

A well-behaved wallet does not escalate immediately. The first request goes to the operator on their advertised relay. The operator should respond within a few seconds — request handlers in the daemon are fast paths, and even with a cosign round-trip the typical latency is well under 30 seconds. A wallet's first move on no-response is usually retry: republish the original request after 30–60 seconds in case the relay dropped it.

Escalation is the next step. The decision points are roughly:

- **Has the operator gone silent on every relay they advertise?** If they're up on one relay and down on another, the issue is relay routing, not censorship. Try the other relays first.

- **Is the wallet's request well-formed?** A request the operator legitimately can't process (bad signature, missing param, denied by access control) doesn't get answered with a thoughtful explanation today; the wallet sees a `Kind:20102` rejection or nothing. Escalation against a request the operator was right to reject is just expensive noise.

- **Is the request time-sensitive?** Lightning payments and on-chain credit operations have wall-clock consequences (HTLC deadlines, address watchers). For these, a 30-second escalation window is appropriate. For balance queries or speculative offers, the wallet can afford to wait longer.

The cost: the member sets the embed fee. DEP-12 §"Pricing" expects per-vbyte pricing advertised in the member's `Kind:39100` operator advertisement (the member is doing operator work, after all — they're broadcasting a co-signed update). The fee is small in absolute terms because the embed itself is small (one TLV-encoded operation, dozens of bytes). The fee is also intentionally small relative to the operator's per-operation fees: the embedding is a coordination cost, not a settlement payment, and the *real* economic structure here is the implicit promise of slashing if the operator persists in misbehaving.

Wallets can also escalate to **multiple members in parallel.** A request hash sent to three members produces three `DeliveryEmbed` operations on three different ledgers. The operator only has to be caught by one of them — and the operator can't block all of them without inconveniencing every quorum member they depend on. Multi-member escalation is a one-liner in the wallet (call `escalate` three times), and the cost is three small fees, not three multiplied by anything load-bearing.

## A worked example

Alice opened a deposit on Bob's ledger. She received an on-chain payment to her per-deposit address; the funding transaction has 102 confirmations; Bob's daemon should have committed an `OnchainCredit` long ago. Alice's wallet sends a `pay_attention` (informally: a credit-status query, or a follow-up on the open invoice/offer). Bob doesn't respond. Alice's wallet retries on the second of Bob's advertised relays. Still nothing. Alice's wallet decides Bob is censoring.

Bob's quorum has two other members: Carol and Dave. Alice's wallet picks Carol — Carol is closer in graph distance to Alice's trust anchors, per [Chapter 17](17-attestation-service.md) — and runs:

```
deposits-wallet escalate \
    --member-ledger <Carol's ledger id> \
    --request-hash <SHA256 of Alice's signed credit-claim payload> \
    --target-ledger <Bob's ledger id> \
    --target-operator <Bob's pubkey>
```

The wallet publishes a `Kind:20101` event tagged with Carol's npub, action `delivery_embed`, body containing the three fields. Carol's daemon receives it, parses it, looks up *Carol's own* ledger (Carol may have several; the wallet specified which), constructs `LedgerOperation::DeliveryEmbed { request_hash, target_ledger_id: <Bob's>, target_operator: <Bob's> }`, and calls `commit_operation`. Carol's actor stages, fans out cosignatures to *Carol's* quorum, signs, applies, broadcasts. The TLV-encoded `Kind:9100` event lands on the relay.

Two things happen next, in parallel:

1. Bob's daemon — which is subscribed to Carol's ledger feed because Bob is a quorum member of Carol's ledger — receives the embed event. Bob's daemon notices that this is a `DeliveryEmbed` operation targeting Bob himself. The good case: Bob processes the original credit, commits an `OnchainCredit` to his own ledger, and the embed becomes a paper trail nobody acts on. Alice gets her balance update, Carol got the embedding fee, Bob did the work he was supposed to do.

2. The bad case: Bob continues to ignore. Time passes. Carol periodically co-signs Bob's ledger updates as part of her normal quorum-member duties — and Bob, in turn, periodically co-signs Carol's. Each round of cosignatures from Bob on Carol's ledger advances Bob's signature chain to attest a state that contains the embed. After `service_response_blocks` go by with no `OnchainCredit` for Alice's deposit on Bob's ledger, the deadline elapses. Carol now has everything she needs to construct a `NonConforming` fraud proof: Alice's signed request (it was provided to Carol when Alice escalated), Carol's `DeliveryEmbed` update (on Carol's own ledger), and the causal link via Bob's cosignature on a post-embed Carol-ledger update. Carol broadcasts the fraud proof to Bob's quorum. The recovery pipeline ([Chapter 12](12-recovery-pipeline.md)) takes over from here.

The custody lottery resolves, somebody — quite possibly Carol herself, since she has the strongest evidence and the most motivation to win — takes over Bob's ledger. Bob's collateral is forfeited. Alice's deposit is intact; her balance update appears on her ledger as soon as the new operator gets to it.

The wallet's role ended at the escalation request. The cost to Alice was one small embedding fee. The cost to Bob, if he persisted in censoring, was his entire ledger and the bond backing it.

## What the protocol does not promise

A few honest limits on what escalation can accomplish.

- **Escalation does not produce instant resolution.** The fraud proof fires after `service_response_blocks` elapse, not at the moment of escalation. The deadline is part of the quorum's published policy ([Chapter 7](07-quorum-and-collateral.md)); typical values are in the dozens of blocks (hours, not minutes). For a wallet that needs an answer *right now*, escalation is a slower path than just routing through a different operator.

- **Escalation does not work if every member colludes.** If Bob, Carol, and Dave all decide to ignore Alice in concert, no `DeliveryEmbed` lands and there's no causal anchor to point at. This is the same fundamental failure mode the rest of the protocol shares: the trust assumption needs at least one honest member, and if that fails the protocol cannot save the deposit. What it can do is make the collusion expensive — every member who refuses to embed has their own ledger and their own bond, and a multi-ledger fraud proof against a colluding subset can become a network-wide event. DEP-12 §"Incentives" is direct about this: a wallet that gets refused by every member of a quorum has learned the quorum is unanimously uncooperative, and the rational response is to distribute funds elsewhere and publish the refusal to network health monitors.

- **Escalation does not authenticate the original request.** The member doesn't validate that Alice's underlying request was well-formed or merited a response — the embed is a hash, not a fully decoded operation. This is by design. Members are not in a position to second-guess the operator's request validation; their role is to anchor the existence of the request. Whether the request was legitimate is what `service_response_blocks` plus the recovery-pipeline fraud-proof verifier eventually decides.

- **Escalation does not move funds.** A `DeliveryEmbed` is a no-op at the state-machine level. It changes no balance, opens no deposit, locks no transfer. It is pure causal anchoring. The wallet's funds are still on the operator's ledger when the dust settles; what changes is who the operator is.

## Where this lands in the implementation

Three files end-to-end:

- `deposits-protocol/src/messages/types.rs:491` defines the `DeliveryEmbed` variant and its discriminant (80) plus the no-op `apply` semantics in `deposits-protocol/src/types/ledger_state.rs:632`.
- `deposits-node/src/node/request_handlers/deposits.rs:1138` is the member-side handler: parse → resolve ledger → commit → reply.
- `deposits-wallet/src/wallet_cli/escalate.rs` is the wallet-side CLI: validate args → publish `Kind:20101` request → wait for response → print result.

The integration test in `deposits-test/tests/delivery_embed.rs` exercises the full path on a fresh three-operator regtest cluster: discover op0 and op1, generate a synthetic 32-byte request hash, run `deposits-wallet escalate` with op0 as target and op1 as the embedding member, then poll op1's ledger JSONL for a `DeliveryEmbed` matching the wallet's hash. It confirms the wallet → member transport, the handler, the commit, and the persistence end-to-end. The test does not exercise the operator-side cosignature on op1's post-embed update or the eventual fraud-proof construction — those are covered separately in [Chapter 11](11-fraud-proofs.md)'s test suite.

## Where this leads

Delivery escalation is the *passive* path between ledgers — a wallet leverages an existing quorum-member relationship to anchor evidence. The active path between ledgers is the next chapter: [couriers](16-couriers.md), the wallet-shaped service that holds deposits on multiple ledgers and atomically swaps between them via hash-locked contracts. Together, escalation and couriering are the two ways a wallet's interests cross ledger boundaries — one for evidence, one for value.
