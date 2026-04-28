# Chapter 3: Background

> **Audience**: everyone (developers can skim)
> **Prereqs**: chapters 1, 2
> **DEPs**: none

The protocol assembles existing Bitcoin and Lightning primitives into a custody-scaling configuration. This chapter walks through the primitives the rest of the book assumes — Taproot, Schnorr, hash-locked contracts, Lightning channels, federations, Nostr — at the level a reader needs to follow Parts II and III. It is not a Bitcoin tutorial. If you don't already know what a UTXO is or how a 2-of-3 multisig works, this chapter won't help you; chase down a generic Bitcoin reference first and come back.

The bias here is deliberate. We cover the bits the protocol *actively uses*, with enough motivation that when [Chapter 5](05-onchain-transactions.md) says "the reserves UTXO is a Taproot output with a script tree containing N spend paths," the reader knows what each of those words means and roughly why each was chosen. We also cover one piece of contrast — federations — because "why not just run a federation?" is the obvious first question and deserves an answer up front.

## Taproot, briefly

Bitcoin's pre-Taproot output types — P2PKH, P2SH, P2WSH — exposed a tradeoff at signing time. A simple single-key spend was small and cheap. A complex multisig or scripted spend was visible to the world: the redeem script went on-chain in clear, the witness stack listed every signer, and the size of the output reflected the complexity of its spending conditions. Outputs that *might* be spent under exotic conditions — a 2-of-3 multisig with a one-month timeout fallback to a recovery key, say — paid for that complexity even when the cooperative path was used.

Taproot changes the shape. A Taproot output (P2TR) is, on the wire, a single 32-byte tweaked public key. The output script is one push of that key. The spending side has two options:

- **Key-path spend**. Produce a single Schnorr signature against the tweaked key. The witness is one signature. The chain sees exactly that — a Schnorr signature against a pubkey — and has no way to tell whether the spending parties were one person, a multisig, or a complex aggregate. As long as the parties who tweaked the key cooperate, the cheapest, smallest, most-private path is taken.

- **Script-path spend**. The tweaked key was constructed as `internal_key + tweak(merkle_root)` where the merkle root commits to a tree of *Tapscript* leaves. The spender reveals one leaf, satisfies the script that leaf describes, and provides a Merkle proof that the leaf is in the committed tree. The chain sees only the leaf that was used, never the others.

The cryptographic content of "this output can be spent under any of N conditions" is therefore split across two layers. The *expected* path — usually a cooperative aggregate signature — costs one Schnorr sig. The *fallback* paths — disputes, timeouts, emergency recovery — cost only when used, and only their own size, not the size of all the alternatives.

This is exactly the shape Bitcoin Deposits needs.

The reserves UTXO is a single Taproot output. The internal key is a MuSig-style aggregate of the operator and quorum members, so the cooperative path — rotating the UTXO, periodically restructuring the reserves — is a single Schnorr signature with no on-chain footprint of how many parties cooperated. The script tree contains the dispute-armed paths: confiscation by the recovery lottery winner, fallback timeouts, and a few other scripted contingencies described in [Chapter 5](05-onchain-transactions.md). In the happy case the chain never sees any of them. In the unhappy case the network reveals exactly the leaf it needs and nothing more.

A useful intuition: Taproot lets the protocol design as if every UTXO has a "honest-everyone-cooperates" path that is invisible and cheap, and an unbounded number of "things-have-gone-wrong" paths that you only pay for if you take them. The whole on-chain footprint of a normally-operating ledger is one cooperative Schnorr signature per rotation.

A second useful intuition: because the script-path spends each prove only that one leaf was in the tree, the script tree can be large and structurally rich without bloating any individual transaction. The protocol's recovery pipeline depends on this — there are several distinct script paths, each tied to a different stage of the dispute resolution, and they don't compete with each other for size.

## Schnorr signatures and MuSig

Schnorr signatures (BIP-340) replaced ECDSA for Taproot spends. Two properties of Schnorr matter for this protocol:

First, **linearity**. A Schnorr signature `(R, s)` against a public key `P` over message `m` satisfies `s·G = R + H(R || P || m) · P`. Because the verification equation is linear in the key and the nonce, signatures from multiple parties can be aggregated: if two signers each produce a signature against their respective keys for the same message, the resulting components can be combined into a single signature against the aggregated key. This is the basis of MuSig and the variants that followed.

Second, **batching**. Schnorr signatures verify in batches faster than they verify individually, which matters for nodes catching up on a busy chain or for software validating long reserves-rotation histories.

For this protocol, the MuSig story matters more than the verification speed story. The operator and quorum members hold partial keys; the aggregated key is what the on-chain UTXO is locked under. To cooperatively spend the UTXO — to rotate reserves, to settle a dispute via the cooperative path, to close a ledger — the parties run a MuSig signing protocol to produce a single Schnorr signature against the aggregated key. The chain sees one signature, learns nothing about how many partials went into it, and verifies the aggregated key directly.

A subtlety worth flagging: MuSig requires per-signing nonce coordination. Each signer commits to a nonce, broadcasts the commitment, then reveals the nonce, then signs. Reusing a nonce across two distinct messages reveals the secret key — this is not an obscure failure mode, it's the same nonce-reuse pitfall that haunted ECDSA in the early days, and it's worse here because partial-key aggregation means a single signer's slip can be exploited by the others. The implementation (and the protocol around it) takes nonce hygiene seriously; [Chapter 7](07-quorum-and-collateral.md) and [Chapter 13](13-custody-lottery.md) revisit this when the cosigning ceremony comes up in detail.

For everyday cosigning of *ledger updates* (as opposed to UTXO spends), the protocol does not actually need MuSig — each member's signature on each update is collected separately and verified separately. MuSig matters specifically for the on-chain spend paths. Off-chain, the cosignature scheme is "operator signs, members sign individually, ⌊Q/2⌋+1 of them are required, all signatures are stored alongside the update on the relay." That's simpler, easier to reason about for protocol-level concerns, and decouples the off-chain availability story from the on-chain signing cryptography. We'll see this distinction repeatedly.

## Hash-locked contracts (HTLCs)

A hash-locked contract is a payment that resolves on the disclosure of a preimage. The shape is universal:

```
Output funded by Alice, spendable two ways:

  PATH A (Bob claims):
    requires <signature by Bob> AND <preimage x such that H(x) = h>

  PATH B (Alice refunds):
    requires <signature by Alice> AND <block height >= T>
```

Alice is the payer, Bob is the receiver, `h` is a hash chosen by some upstream party, `T` is a refund timeout.

The contract's invariant: *if Bob claims the funds, the preimage `x` becomes publicly known* (because PATH A revealed it on-chain or in an off-chain message). Whoever was waiting for `x` upstream can now resolve their own contract. If Bob does *not* claim before `T`, Alice can refund, and the upstream contract remains unresolved (but also unfunded — neither party loses).

Chained HTLCs are how Lightning routes payments. A → B → C means A funds an HTLC to B, B funds an HTLC to C, both lock against the same `h`, and C reveals `x` when paid. C → B propagates the preimage backward; B → A propagates it backward; the route settles. Importantly, the timeouts decrease along the route: B's outbound contract to C must time out *before* A's inbound contract to B times out, so that if C disappears, B can refund their leg before A refunds the leg into B.

This same primitive shows up three times in the Bitcoin Deposits protocol:

1. **Lightning bridging**. When a wallet on a Deposits ledger receives a Lightning payment, the operator's Lightning node terminates the Lightning HTLC, learns the preimage, and credits the deposit. When a wallet *sends* Lightning, the operator funds an outbound Lightning HTLC, the receiver reveals the preimage on the Lightning network, and the operator debits the deposit. Either way, an HTLC is the bridge between the Lightning route and the Deposits ledger update. [Chapter 9](09-payment-channels.md) covers this in detail.

2. **Couriers**. A wallet on ledger A wanting to pay a deposit on ledger B asks a courier to bridge the value. The courier holds deposits on both ledgers. The wallet locks an `InvoiceLock` on A against hash `h`; the courier locks a corresponding `InvoiceLock` on B against the same `h`; the receiver on B reveals the preimage, the courier claims on A, and the value crosses. This is structurally identical to a Lightning hop, except the contracts are recorded as ledger operations rather than as Bitcoin transactions. [Chapter 16](16-couriers.md) walks through this.

3. **Recovery payouts**. Some recovery-pipeline branches use hash-locked structures to bind preimage knowledge to fund release. [Chapter 12](12-recovery-pipeline.md) covers the mechanics; the primitive is the same.

What makes the primitive useful is the *atomicity* it provides without trust. Neither party needs to be honest for the contract to resolve safely; what they need is to be online and motivated before their respective timeouts. A courier who goes silent after locking inbound on A but never locks outbound on B simply forfeits the trade — A's wallet refunds and tries another route. The timeout structure is the entirety of the safety argument.

## Lightning's channel model

Lightning is a network of bidirectional payment channels between Bitcoin nodes. Each channel is anchored by a single 2-of-2 multisig UTXO that both parties co-funded. Off-chain, the parties exchange signed *commitment transactions* that redistribute the channel balance — one for each new state. To make a payment, parties tear up the old commitment and sign a new one with the updated balance. To close cooperatively, they sign a settlement transaction that pays the current balances and broadcast it. To force-close, either party broadcasts the latest commitment they hold, and a delay window protects against publishing a stale commitment (the counterparty has time to publish a *justice* transaction that takes the whole channel as a penalty for the cheat attempt).

Routing across multiple channels uses the chained-HTLC mechanism we just walked through. Each hop is independent: the sender doesn't need a relationship with the receiver, only a path of channels in between.

What Lightning gets right: **off-chain throughput**, **near-instant settlement** along the route, **trustless atomicity** via HTLCs, **strong privacy** at the routing layer (onion-routed), and **unilateral exit** — at any moment either party can close the channel and recover their balance on-chain.

What Lightning struggles with, and what Bitcoin Deposits is shaped around:

- **Channel liquidity is asymmetric**. A new channel funded by Alice has all the capacity on her side. Alice can send up to the full channel size; she can receive nothing. To receive, she needs a counterparty to send first, or she needs to swap, or she needs a separate channel funded inbound. Channels do not "rebalance themselves." This is fine for power users running Lightning nodes; it is not fine for someone who wants a checking account that sometimes receives a payroll deposit and sometimes pays for groceries.

- **Receiving while offline is awkward**. Lightning HTLCs have timeouts; if the receiver isn't online to claim within the timeout, the payment refunds. There are watchtowers and async-receive proposals, but none of them are as clean as "the operator received it and you'll see it next time you sync."

- **On-chain footprint per user**. Every channel is at least one Bitcoin UTXO (and at peak operation, two — one open transaction and one close). For a network with billions of users, that's billions of UTXOs, and Bitcoin doesn't have room. Lightning at scale assumes most users are clients of routing nodes that own the channels, which transitively reintroduces a custody question.

- **Force-close cost**. Unilateral exit is real but not free; in a fee spike, force-closing a small channel can cost more than the channel's balance.

Bitcoin Deposits trades unilateral exit for shared custody by a quorum of operators with collateral on the line. Each ledger anchors many deposits to one UTXO. Receiving is asynchronous and offline-tolerant by construction. There is no per-user on-chain footprint until a wallet wants to actually exit the network. The cost is the loss of unilateral exit — the wallet depends on the recovery pipeline rather than on its own ability to broadcast a Bitcoin transaction. [Chapter 11](11-fraud-proofs.md) and [Chapter 12](12-recovery-pipeline.md) describe what fills that gap.

## Why federations don't quite work

The most obvious answer to "Lightning isn't quite right; what's next?" is: a federation. A fixed group of N entities co-signs a multisig that holds funds, runs an off-chain ledger of who owns what, and periodically settles to Bitcoin. Liquid is the canonical example, with a federation of about a dozen organizations co-signing peg-in/peg-out flows; various sidechain proposals follow the same template; RGB-on-Liquid layers asset issuance on top.

Federations are not bad. They are simply solving a different problem.

The trust assumption of a typical M-of-N federation is "fewer than N − M of the federation members are jointly compromised." For practical M and N (Liquid is roughly 11-of-15) this is a meaningful assumption, but it has three properties that don't fit the deposits use case:

- **Membership is fixed** at federation formation. Adding or removing a member is a federation-level event, not a per-user one. A federation can't grow to absorb new operator capacity the way a permissionless market can.

- **Members are reputational, not collateralized**. The cost of misbehavior is "your name is on a sign-off and your organization will be blamed." That is not nothing — established institutions don't take such hits lightly — but it is also not on-chain enforceable. There is no slashing pool; if a federation does steal, the recovery is legal, slow, and uncertain.

- **The user has no per-ledger choice**. There is one Liquid federation. If a user dislikes its membership composition, they don't switch to a different one and stay on the same network. They leave the network entirely.

Bitcoin Deposits inverts each of these. Membership is per-ledger, joinable on negotiation, with thousands of operators at maturity; misbehavior costs *collateral* posted on-chain in the same UTXO that backs the deposits, slashable by anyone who produces a fraud proof; users pick *their* operator and through that operator a *specific* quorum, and they evaluate the quorum on quantitative criteria — graph independence from their trusted set, attested identities, collateral ratios — rather than on a binary "trust the federation, yes or no."

Put differently, a federation is a single trust set that everyone shares; Bitcoin Deposits is a market of trust sets that users choose between. Both are valid designs; they just answer different questions.

## Nostr basics

Most off-chain protocol coordination — operator advertisements, ledger updates, fraud broadcasts, dispute messages — happens over Nostr. Nostr (NIP-01) is a thin event-broadcast protocol with three pieces:

- **Events** are JSON objects with a few mandatory fields: a 32-byte pubkey, a 64-byte signature over the event hash, a numeric `kind` indicating event type, an array of `tags` for indexing and addressing, a `content` field whose interpretation depends on the kind, and a creation timestamp. The signature is over a canonical serialization that includes all the other fields, so the event is self-authenticating.

- **Kinds** are integers that carve up the event space by purpose. Some kinds are *durable* — relays are expected to retain them indefinitely (or at least for a long retention window). Others are *ephemeral* — relays are not expected to retain them past delivery. The kind also determines whether an event replaces previous events from the same pubkey (replaceable kinds), is addressable by a tag tuple (parameterized replaceable kinds), or is purely append-only.

- **Relays** are servers that accept signed events from publishers and serve them to subscribers. Subscribers send filter queries — by pubkey, kind, tag, time range — and the relay pushes back matching events. Relays do not coordinate with each other; if a publisher wants reach, they publish to multiple relays. There is no global broadcast, no consensus, no canonical ordering.

For this protocol's purposes, the relevant facts are:

- Ledger updates are durable, append-only events keyed by a `d` tag containing the ledger ID. A reader who wants to replay a ledger end-to-end queries the relay for events from the operator's pubkey with the matching `d` tag.

- Operator advertisements (capacity, fees, attestations) are replaceable events; the latest version overrides earlier ones.

- Fraud broadcasts and dispute messages are durable but addressed by tag tuples that let quorum members and wallets locate them by ledger ID and dispute round.

- Some coordination messages — for example, cosignature requests during quorum signing — are ephemeral. The relay carries them long enough for delivery and forgets them.

- Wallets and operators do not assume the relay is honest. They assume signed events are valid and unsigned events are noise. A relay that refuses to serve a particular event is observable (the wallet asks; the answer is empty); a relay that silently drops events from a publisher is the publisher's problem to detect (typically by querying a second relay). Operators are expected to announce *which* relays they publish to, and wallets are expected to subscribe to enough of them that no single relay is a single point of failure.

Two implementation footnotes the rest of the book will rely on. First: events are content-addressed by their hash, so fraud proofs can refer to specific updates by hash without ambiguity. Second: the relay knows nothing about protocol semantics — it doesn't validate ledger conformance, it doesn't check signatures over the protocol's domain-specific payloads, it doesn't enforce sequence numbers. All of that is the receiver's job. The relay is a dumb pipe that filters by pubkey, kind, and tag, and signs nothing on its own behalf. This minimalism is why the protocol can change without the relay knowing: the wire format is between operators and wallets, with Nostr just carrying bytes.

## Where this leads

That covers the primitives the protocol leans on: Taproot for compact-when-cooperative on-chain anchoring, Schnorr/MuSig for aggregated signing, HTLCs for atomic off-chain bridging, and Nostr for durable broadcast. We also drew the contrast lines: Lightning gives you channels and unilateral exit but not asynchronous custody at scale; federations give you scale but not per-user choice or on-chain enforcement.

[Chapter 4](04-ledger-state.md) opens Part II by introducing the ledger state model — the operations that drive a ledger forward, the invariants those operations preserve, and the format of an individual signed update. From there the rest of Part II builds outward: on-chain transactions in [Chapter 5](05-onchain-transactions.md), the wire format on the relay in [Chapter 6](06-peer-messaging.md), quorum formation and collateral structure in [Chapter 7](07-quorum-and-collateral.md), and the user-facing operations — deposits, transfers, channel payments, fees — in [Chapters 8](08-deposits-and-transfers.md) through [10](10-fees-and-time.md).
