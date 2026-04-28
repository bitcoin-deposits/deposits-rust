# Chapter 1: Introduction

> **Audience**: everyone
> **Prereqs**: none
> **DEPs**: none (this chapter prepares you to read them)

## The custody-scaling problem

Bitcoin is a settlement network. It works extraordinarily well for what it is — a global, neutral, censorship-resistant ledger of unspent transaction outputs — and extraordinarily poorly as a payment network for billions of people. Roughly seven transactions per second, ten-minute blocks, fees that rise during demand spikes. These are conscious tradeoffs: simplicity and decentralization were prioritized over throughput, and the result is a base layer that secures more value with less infrastructure than any payment system in history.

But people still want to pay each other. They want to receive their salary, settle a tab, tip a creator, pay a bill — and they want it to feel like cash, not like an international wire. The ecosystem has spent over a decade trying to bridge this gap, and the answers cluster into three uncomfortable categories:

1. **Custodial services.** Exchanges, banks, payment processors. They scale, they work, and they own your funds. If the custodian goes down, mismanages, or gets compromised, you lose. The history of custodial Bitcoin is a steady drumbeat of insolvency events.

2. **Lightning.** A clever payment-channel network on top of Bitcoin, where most payments happen off-chain between counterparties who eventually settle on-chain. Lightning is real and it works, but it has a particular shape: you need an open channel before you can pay, channel liquidity must be managed, receiving payments while offline is awkward, and a single channel close can cost more in on-chain fees than the channel ever moved. Lightning solves payment routing; it does not solve "I want a Bitcoin account I can use from a phone with no setup."

3. **Sidechains and rollups.** Federations of signers running their own ledger, periodically anchoring to Bitcoin. These solve scaling but reintroduce the trust problem: a federation that controls custody can collude, freeze withdrawals, or refuse service. The federation members are usually known entities running known software; the protocol does not enforce honest behavior, it relies on reputational and legal incentives.

There is a fourth pattern that has been imagined for years and never quite assembled: a network of operators who custody Bitcoin on behalf of users, but where the protocol — not reputation — keeps them honest. That is what Bitcoin Deposits is.

## What the protocol does

A *deposit* is a stable account, identified by a public key, held by an *operator* on a *ledger*. Wallets can fund a deposit by sending Bitcoin to a per-deposit address; they can spend from it by signing wallet-side authorizations the operator must honor; they can transfer to other deposits on the same ledger atomically; they can pay and receive Lightning invoices through the operator's Lightning node; and they can move funds to a different ledger via a *courier* that bridges the two with hash-locked contracts.

A *ledger* is an append-only chain of signed updates. Each update — a deposit opening, a transfer lock, a fee change, a dispute event — is signed by the operator, hash-chained to the previous update, and broadcast to a Nostr relay where it lives forever. Anyone can read a ledger end to end and verify it conforms to the protocol's rules.

The operator's funds, the deposits' funds, and a security bond all live in a single Bitcoin UTXO controlled by a *quorum* — a small group of other operators who co-sign every update. The UTXO is split into two halves by accounting: the *reserves* portion is what wallets can deposit against, and the *collateral* portion is the operator's bond. Co-signers refuse to sign updates that would let the operator over-promise against reserves or shrink the collateral.

If the operator misbehaves — signs a non-conforming update, refuses to credit a confirmed deposit, fails to deliver a paid Lightning invoice, ignores a wallet's request — anyone can produce a *fraud proof*: cryptographic evidence that the operator's chain contains an event that should not have been there, or that an event that should have been there is missing. A fraud proof, broadcast to the quorum, triggers a *recovery pipeline*: members of the quorum fork their own continuation of the ledger from the last conforming update, race to settle a *custody lottery* against the operator's UTXO, and the winner takes over as the new operator. The losing operator's collateral is forfeited. The deposits remain in place; their custodian has changed.

Wallets keep depositing, transferring, and receiving without manual intervention through the change in custody. Their UX is "the operator is the operator"; the protocol enforces that whoever is the operator at any given moment is honest enough to keep their collateral.

## What it deliberately doesn't do

Three explicit non-goals, called out in the [whitepaper](../WHITEPAPER.md):

- **No unilateral exit.** A Lightning channel lets you force-close on-chain. A deposits ledger does not. If the operator vanishes and the quorum fails to recover the ledger, the funds stay in the network until somebody does. Unilateral exit is replaced by a redundancy guarantee: as long as the network is alive, your funds are reachable through whichever quorum took over.

- **No privacy.** Verification requires transparency. Every ledger update is publicly auditable, addressable, signed. There is no shielded pool of deposits hiding in zero-knowledge math. Some privacy is recoverable at the wallet layer (deposits are key-controlled, addresses can rotate, ring signatures attest membership without revealing identity — see [Chapter 18](18-ring-signatures.md)) but the protocol surface is fundamentally public.

- **Intermittent availability.** A deposit is only as available as its operator. Operators go offline, get DDoS'd, run maintenance windows. Wallets are expected to spread funds across multiple ledgers from independent operators, exactly the way someone might keep multiple bank accounts at different institutions. The recovery pipeline preserves *funds*, not *uptime*.

These tradeoffs aren't accidental. They're the price of getting custody at scale without unilateral exit's on-chain footprint, without privacy's verification opacity, and without a federation's hand-wave about why anyone would behave.

## What it actually solves

The protocol's central contribution is not a new cryptographic primitive. It is a configuration of existing primitives — Taproot script paths, Schnorr signatures, hash-locked contracts, Nostr broadcast — into an economic structure where stealing costs more than it gains. The whitepaper's word for this is *economic deterrence*: the protocol does not prove operators won't misbehave, it makes misbehavior more expensive than the upside.

Concretely:

- An operator who skims a single Lightning payment exposes themselves to fraud-proof evidence (the payer can produce the preimage). One confirmed theft triggers loss of the ledger and forfeiture of the entire collateral. Stealing pays for one payment; getting caught loses millions.

- An operator running multiple ledgers with independent quorums faces a multiplicative problem: the same slashing evidence presented on one ledger triggers slashing on the others. Quorum independence — measurable by graph metrics like vertex-connectivity from a wallet's trusted set to the quorum's members — is a property the wallet can verify before depositing.

- A coalition of operators trying to exit en masse loses collateral on every one of their honest-quorum ledgers. Simulation shows that with a 40/60 reserves/collateral split and multiple ledgers per operator, this attack is unprofitable for coalitions controlling up to 49% of the network.

The fourth-category pattern — operators custodying funds, the protocol keeping them honest — works because the protocol is the slashing engine, not the validator. There is no on-chain consensus about whether an operator misbehaved. There is just a quorum of other operators with collateral at stake, watching for fraud proofs, ready to take the losing operator's reserves if the proofs arrive.

## How this book is organized

Five parts:

- **Part I (this part)** sets context: the problem, the actors, and enough Bitcoin and Lightning background to read the rest.
- **Part II** is the protocol core: the ledger state model, the on-chain transactions, the wire format on the relay, quorum formation, and the operations wallets actually perform — deposits, transfers, channel payments, fees.
- **Part III** is security: how fraud proofs are constructed, how the recovery pipeline executes when one fires, how the custody lottery resolves who takes over, and how the protocol defends against the one attack that can't be deterred at all (operator equivocation).
- **Part IV** is the privacy and identity layer: certified delivery escalation when an operator refuses to respond, courier-routed transfers between ledgers, the attestation service that bootstraps trust into discovery, and the ring-signature web-of-trust scheme that lets wallets verify operator identity without doxxing themselves.
- **Part V** is the implementation: a tour of the nine Rust crates that make up the reference implementation, what the daemon does on the inside (actor model, persistence, dispute drivers), how the wallet works, how the test infrastructure exercises the protocol, and what running this in production looks like.

The DEPs (`DEP-01.md` through `DEP-15.md` in the repository root) are the authoritative specifications. This book teaches; the DEPs specify. When the two disagree, the DEP is right.

## Where this leads

The next chapter introduces the cast of characters — operators, members, wallets, ledgers, deposits, couriers — and how they relate. Once you have the vocabulary, the rest of the book builds.
