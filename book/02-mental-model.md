# Chapter 2: Mental Model

> **Audience**: everyone
> **Prereqs**: [Chapter 1](01-introduction.md)
> **DEPs**: none (introduces vocabulary used by all of them)

The protocol has six kinds of actor and three kinds of object. If you can keep these straight, the rest of the book will make sense.

## The actors

### Operator

An *operator* is the active custodian of one or more ledgers. They run the daemon (the `deposits-node` binary in this implementation), they hold the operator key that signs ledger updates, they keep a Lightning node alongside if they offer Lightning bridging, and they earn fees from every operation that crosses their ledgers.

Operators are not neutral. They are economically motivated parties — running this is a business — and the protocol is designed around the assumption that operators will optimize their own income. The honesty of any specific operator is not assumed; the *aggregate* honesty of the network is enforced by collateral.

An operator's identity, on a ledger, is whatever pubkey signed the most recent co-signed update on that ledger. This is important: the operator-identity is per-ledger and can change over time. After a custody transfer, the same human-or-organization may continue to be "the operator" colloquially, but the ledger's `parent_pubkey` (its programmatic operator) has been rotated to whoever the recovery lottery selected.

### Quorum member

A *quorum member* of ledger A is an operator of *some other ledger* who has agreed to co-sign A's updates. Membership is per-ledger — an operator can be a quorum member of dozens of other ledgers simultaneously, and every ledger's quorum is a separately-negotiated set.

Members do three things:

1. **Co-sign**: each new update on the ledger they're a member of needs a majority cosignature (⌊Q/2⌋+1 of Q members). Members validate the update against the rules — over-promising, fee underflows, sequence gaps, dispute-state violations — and refuse to sign if it would be non-conforming.

2. **Watch for fraud**: members run the same conformance checks every wallet does. If they observe non-conforming behavior on the ledger they're a member of, they are the natural party to assemble a fraud proof. They have direct access to the latest updates, they have economic skin in the game (their own collateral is on the line), and they have the upside of taking over a successful recovery.

3. **Participate in disputes**: when a fraud proof fires, members fork their continuation of the ledger from the last conforming update, race the custody lottery, and the winner inherits operator status. Their *own* ledgers are not touched by the dispute — only the disputed ledger.

Membership is lightweight. It does not require a separate capital deposit; the member's own ledger already has collateral. What it does require is being responsive enough to co-sign promptly (otherwise the operator can't make progress) and being honest in the cosigning role (otherwise the member's own collateral is slashable).

The whitepaper's phrasing is exact: members are "incentivized predators." They earn a small steady income from co-signing, and they stand to take over a much larger ledger if the operator falls. This asymmetry is what makes the network work without a neutral validator class.

### Wallet

A *wallet* is the depositor's client. It holds the keys that authorize spending from a deposit, it knows which ledgers it has deposits on, and it speaks Nostr to the relay where its operators broadcast.

Wallets do not need to be online. They can be offline for arbitrary stretches and catch up by replaying events from any relay that retains them. When a payment arrives — the operator credits the deposit and broadcasts the update — the wallet picks it up the next time it connects.

Wallets are also the primary fraud-proof producers in the customer-facing failure modes: a wallet that paid for a Lightning invoice and learned the preimage, an out-of-band party who got the same preimage from a confirmed payment, a wallet whose deposit was supposed to be credited and wasn't. The wallet assembles the proof, submits it to the operator's quorum members, and steps back.

In this book "wallet" almost always means the depositor's client (typically `deposits-wallet`). Operators and quorum members run different software (`deposits-node`); when those parties have wallet-shaped concerns — for example, the deposit a quorum member holds on the ledger they belong to — we'll say so explicitly.

### Courier

A *courier* is a wallet-shaped service that holds deposits on multiple ledgers and atomically swaps between them on behalf of users. If you have a deposit on ledger A and want to pay a deposit on ledger B, you don't need a direct relationship with B's operator — you find a courier who bridges A and B and pay them a fee to carry the value across.

Couriers settle via hash-locked contracts: same primitive Lightning uses for routing. The mechanics are the subject of [Chapter 16](16-couriers.md). What matters for the mental model is that couriers are an *economic role*, not a protocol primitive — anyone can run one, fees are visible on the relay, and routes are competitive.

### Attestation service

The *attestation service* is the protocol's lightest-touch concession to identity. It is a Web2 verification provider — domain ownership, Lightning address control, social platform handles — that issues signed attestations binding a real-world identifier to an operator's pubkey. Wallets and couriers use these attestations as one input to discovery: "is this operator who they claim to be?"

The protocol does not require attestations. Operators can run anonymously. But discovery markets — the Nostr-broadcast advertisements wallets use to find operators — work better when *some* operators are pseudonymously rooted in a verifiable identity, because that gives wallets something to start from. [Chapter 17](17-attestation-service.md) covers this.

### Relay

A *relay* is a Nostr server. The protocol uses Nostr because it gives wallets and operators a content-addressable, retention-tunable, multi-publisher event store with no centralized directory. Operators publish ledger updates, fraud broadcasts, and attestation announcements as Nostr events. Wallets subscribe to the relays their operators advertise on.

The choice of which relay to use is a deployment decision, not a protocol constraint. An operator might run their own relay; a wallet might subscribe to several. The protocol defines what events look like (kinds, tags, payloads); relays just store and serve them.

## The objects

### Ledger

A *ledger* is an append-only chain of signed updates owned by a single operator at a time. It is identified by a 32-byte hash derived from the operator key, the reserves address, and the genesis block height. New ledgers are created by their operators at will; closing them is also under operator control (with conformance constraints).

Each ledger has:

- A current operator (`parent_pubkey`).
- A reserves UTXO (the on-chain output backing it).
- A quorum (the set of member pubkeys who co-sign).
- A state machine driven by a typed enumeration of operations: `LedgerOpen`, `DepositOpen`, `InvoiceLock`, `TransferLock`, `FeeChange`, `DisputeEnter`, `DisputeAcquire`, and so on. [Chapter 4](04-ledger-state.md) catalogs these.
- A history (the JSONL chain of every update ever signed).

Ledgers are the unit of custody. A wallet's funds live on a specific ledger; an operator's reputation and collateral are per-ledger; disputes resolve per-ledger.

### Deposit

A *deposit* is a stable account on a ledger, identified by a deposit-pubkey. Each deposit has:

- A balance (in millisatoshis).
- A locked balance (funds in flight in pending transfers or invoices).
- A miniscript spending-condition that authorizes wallet-side withdrawals.
- A fee schedule (per-operation fees, per-block balance fees, fee-change governance parameters) negotiated at opening.

Deposits are opened with a `DepositOpen` operation that the operator signs. Funding flows in either via on-chain transactions to a per-deposit Bitcoin address, or via Lightning invoices the operator creates on the deposit's behalf. Spending flows out via transfers (intra-ledger), Lightning payments (operator routes through their LN node), or on-chain exits (operator signs a withdrawal transaction, members co-sign).

Deposits live on exactly one ledger. To move value across ledgers a wallet uses a courier (Chapter 16) or an on-chain exit followed by an on-chain entry on the destination ledger.

### UTXO (the operator's reserves)

The operator's UTXO is the on-chain anchor of the whole ledger. It is a single Taproot output — `P2TR` — controlled jointly by the quorum members. Its value is split, by accounting, into:

- **Reserves**: the deposit capacity. If reserves is 4 BTC, total deposit balances on the ledger cannot exceed 4 BTC.
- **Collateral**: the operator's security bond. Cannot back deposits. Forfeitable on misbehavior.

The split is negotiated at quorum formation. The reference deployment uses a 40/60 reserves/collateral ratio, meaning deposit capacity is 40% of the on-chain UTXO; the rest is the operator's at-risk bond.

The Taproot script tree contains spend paths for: cooperative reserves rotation (operator + quorum cosig), dispute-armed confiscation (the recovery lottery), and fallback timeout paths. Chapter 5 walks through the script tree in detail.

## The relationships

```
                    [Wallet]                           [Wallet]
                       |                                  |
                       | deposits on                      |
                       v                                  v
        +----------------------------+    +----------------------------+
        | Ledger A                   |    | Ledger B                   |
        | operator: Alice            |    | operator: Bob              |
        | reserves UTXO              |    | reserves UTXO              |
        |                            |    |                            |
        | deposits: D1, D2, D3...    |    | deposits: D7, D8, D9...    |
        +----------------------------+    +----------------------------+
              |       |       |                  |       |
        co-signed by                       co-signed by
              |       |       |                  |       |
              v       v       v                  v       v
        [Bob]  [Carol]  [Dave]              [Alice] [Carol]
              ^                                          ^
              | also operator of                         |
              | some other ledger                        |
              +------------------------------------------+
                  (collateral on Ledger Z, say)

                            |
                            | route between A and B
                            v
                       [Courier]
                       holds D2 on A
                       holds D8 on B
                       atomic swap A → B via HTLC
```

Things to notice in this picture:

- Alice is the operator of ledger A and a quorum member of ledger B. Bob is the inverse. Carol is a member of both. Each of them also has their own ledger somewhere with their own collateral; that's where their slashing risk lives if they cheat as a member.
- Quorum membership is asymmetric: Bob is in A's quorum, but A's operator (Alice) is not necessarily in B's quorum.
- The wallet doesn't pick its quorum. The wallet picks an *operator* (and therefore a ledger), and the operator's quorum is what it is. Wallets evaluate operators by inspecting their quorum's structure, collateral, attestations, and graph distance from the wallet's trusted anchors.
- A courier is just another wallet that happens to have deposits on multiple ledgers. There's no special protocol slot for couriers — they're a market role.

## The trust assumption

The protocol's central trust assumption, in one sentence: **the quorum of any given ledger contains at least one honest member.**

That's it. Not "the operator is honest." Not "the majority of the quorum is honest." Just: at least one member of the quorum is willing and able to act on a fraud proof.

If that holds, every misbehavior is detected and slashed. If that doesn't hold — if a ledger's entire quorum colludes with the operator to steal — the protocol cannot save the deposits on that ledger. What it can do is make the collusion expensive: every colluding member also has their own ledger with its own quorum, and a coordinated attack across them all requires compromising every one of those quorums simultaneously. With independent quorums and multiple ledgers per operator, the simulation results in the whitepaper put the network-wide compromise probability low enough to make 49%-coalition attacks unprofitable.

This is not a soft assumption. It is *the* assumption. It is the reason wallets are encouraged to spread funds across multiple ledgers from operators with independent quorums; it is why the attestation service and the ring-signature web-of-trust exist (so wallets can verify quorum independence rather than take it on faith); it is why fee schedules include enforcement of minimum operator profitability (so members aren't pushed by economics into colluding). Everything else in the protocol is engineering around this one trust statement.

## What stays in your head

If you remember nothing else from this chapter, remember this:

- A *ledger* is owned by one *operator* at a time, custodied by a *quorum* of other operators, anchored to one Bitcoin *UTXO* split into *reserves* (deposit capacity) and *collateral* (security bond).
- *Deposits* live on a ledger; *transfers* move value within a ledger; *couriers* move value across ledgers.
- The protocol does not assume operators are honest. It assumes at least one quorum member per ledger is honest. The collateral structure makes this assumption load-bearing for the whole network's integrity.
- *Wallets* are offline-tolerant clients that listen to *Nostr relays* for events from their operators. The relay is a transport, not a coordinator.

## Where this leads

The next chapter covers the Bitcoin and Lightning concepts the rest of the book assumes you know — Taproot, multisig, hash-locked contracts, Lightning's channel model — and explains why each of the obvious-looking custody-scaling solutions doesn't quite work. After that, Part II opens the protocol itself starting with the ledger state machine.
