# The Bitcoin Deposits Book

A guide to the Bitcoin Deposits protocol: how it works, why it works that way, and what it takes to build, run, or integrate with a deposits network.

This book is split into five parts. Each chapter is a standalone Markdown file. There is no rendering step — just `cat`, an editor, or a browser plugin. Cross-references are relative file links.

## Reading paths

The chapters are listed in topological order — earlier chapters introduce vocabulary that later chapters use. But not every reader needs every chapter. Pick a path:

### "I'm a wallet user / would-be depositor"

You want to understand what custody looks like before you trust funds to the network.

1. [Chapter 1: Introduction](01-introduction.md) — the problem and the proposed solution
2. [Chapter 2: Mental Model](02-mental-model.md) — the cast of characters
3. [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md) — what your funds are actually backed by
4. [Chapter 11: Fraud Proofs](11-fraud-proofs.md) — what the network promises if your operator cheats
5. [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md) — what happens when it does
6. [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md) — the basic operations you'll use
7. [Chapter 9: Payment Channels](09-payment-channels.md) — how Lightning bridges in and out

### "I'm an operator / want to run a node"

You want to run the daemon, advertise to wallets, and earn fees.

1. [Chapter 1: Introduction](01-introduction.md), [Chapter 2: Mental Model](02-mental-model.md)
2. [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md), [Chapter 5: On-Chain Transactions](05-onchain-transactions.md)
3. [Chapter 4: Ledger State Model](04-ledger-state.md), [Chapter 6: Peer Messaging](06-peer-messaging.md)
4. [Chapter 10: Fees and Time Obligations](10-fees-and-time.md)
5. [Chapter 11: Fraud Proofs](11-fraud-proofs.md), [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md), [Chapter 13: Custody Lottery](13-custody-lottery.md)
6. [Chapter 23: Operations and Mainnet](23-operations.md)

### "I'm an integrator / building a service on top"

You want to wire your application into the protocol — exchange, payment processor, custody service.

1. [Chapter 1: Introduction](01-introduction.md), [Chapter 2: Mental Model](02-mental-model.md)
2. [Chapter 4: Ledger State Model](04-ledger-state.md), [Chapter 6: Peer Messaging](06-peer-messaging.md)
3. [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md), [Chapter 9: Payment Channels](09-payment-channels.md)
4. [Chapter 16: Couriers](16-couriers.md) — cross-ledger routing
5. [Chapter 15: Delivery Escalation](15-delivery-escalation.md) — when an operator stops responding to you
6. [Chapter 17: Attestation Service](17-attestation-service.md) — the discovery layer
7. [Appendix B: Wire Format Reference](appendix-b-wire-format.md)

### "I'm a developer / want to contribute or fork"

You want to read the implementation alongside the protocol.

1. The whole protocol track (Chapters 1–18)
2. [Chapter 19: Architecture Tour](19-architecture-tour.md) — what each crate does
3. [Chapter 20: The Daemon](20-the-daemon.md) — the actor model and main loop
4. [Chapter 21: The Wallet](21-the-wallet.md)
5. [Chapter 22: Testing and Fuzzing](22-testing-and-fuzzing.md)

## Full table of contents

### Part I — Foundations
- [Chapter 1: Introduction](01-introduction.md)
- [Chapter 2: Mental Model](02-mental-model.md)
- [Chapter 3: Background](03-background.md)

### Part II — Protocol Core
- [Chapter 4: Ledger State Model](04-ledger-state.md)
- [Chapter 5: On-Chain Transactions](05-onchain-transactions.md)
- [Chapter 6: Peer Messaging](06-peer-messaging.md)
- [Chapter 7: Quorum and Collateral](07-quorum-and-collateral.md)
- [Chapter 8: Deposits and Transfers](08-deposits-and-transfers.md)
- [Chapter 9: Payment Channels](09-payment-channels.md)
- [Chapter 10: Fees and Time Obligations](10-fees-and-time.md)

### Part III — Security and Disputes
- [Chapter 11: Fraud Proofs](11-fraud-proofs.md)
- [Chapter 12: Recovery Pipeline](12-recovery-pipeline.md)
- [Chapter 13: Custody Lottery](13-custody-lottery.md)
- [Chapter 14: Equivocation Defense](14-equivocation-defense.md)

### Part IV — Privacy and Identity
- [Chapter 15: Delivery Escalation](15-delivery-escalation.md)
- [Chapter 16: Couriers](16-couriers.md)
- [Chapter 17: Attestation Service](17-attestation-service.md)
- [Chapter 18: Anonymous WoT Ring Signatures](18-ring-signatures.md)

### Part V — Implementation
- [Chapter 19: Architecture Tour](19-architecture-tour.md)
- [Chapter 20: The Daemon](20-the-daemon.md)
- [Chapter 21: The Wallet](21-the-wallet.md)
- [Chapter 22: Testing and Fuzzing](22-testing-and-fuzzing.md)
- [Chapter 23: Operations and Mainnet](23-operations.md)

### Appendices
- [Appendix A: Glossary](appendix-a-glossary.md)
- [Appendix B: Wire Format Reference](appendix-b-wire-format.md)
- [Appendix C: Error Codes and Conformance Violations](appendix-c-error-codes.md)
- [Appendix D: Configuration Reference](appendix-d-configuration.md)

## Source-of-truth documents

This book teaches and contextualizes. When precision matters, these are the authoritative documents, listed in roughly the order you'd want to read them:

- [WHITEPAPER.md](../WHITEPAPER.md) — the rationale
- [DEP-01](../DEP-01.md) through [DEP-15](../DEP-15.md) — the specifications
- [PROPOSAL.md](../PROPOSAL.md) — the collateral-in-UTXO model rationale
- [SECURITY.md](../SECURITY.md) — the threat model
- [CUSTODY_LOTTERY.md](../CUSTODY_LOTTERY.md) — the lottery design
- [RING-SIGNATURES.md](../RING-SIGNATURES.md) — the WoT scheme

If a chapter contradicts a DEP, the DEP wins and the chapter is wrong.

---

## Style guide for chapter authors

Each chapter starts with a header block:

```markdown
# Chapter N: Title

> **Audience**: wallet users / operators / integrators / developers (one or more)
> **Prereqs**: chapters X, Y (or "none" for foundational chapters)
> **DEPs**: DEP-NN, DEP-MM (the source-of-truth specs this chapter teaches)
```

After that, the body. Conventions:

- **Teach, don't restate.** DEPs are the spec. The book exists to give the reader a working mental model. Quote the DEP when wording is load-bearing; otherwise paraphrase, simplify, give examples.
- **Lead with motivation.** Each chapter opens with *what problem this part of the protocol solves* before getting into mechanics. Readers should never wonder why something exists.
- **Use concrete numbers.** Q≤8, 40/60 reserves/collateral split, 102-block confirmation depth — these grounding facts help readers anchor abstractions.
- **Show wire shapes when useful.** Example TLV layouts, example Nostr events, example state transitions. Don't enumerate every field — that's the appendix's job.
- **Cross-link generously.** Use relative links: `[the dispute pipeline](12-recovery-pipeline.md)`. Forward references are fine.
- **One voice per chapter.** Each chapter should read like one author wrote it. If a single agent is producing the chapter, that comes for free.
- **No emoji.** No callout boxes (`> 💡 NOTE:`). Plain prose, plain code blocks.
- **Length**: aim for 1500–4000 words per chapter. Foundational chapters can be shorter; reference-heavy chapters can be longer.
- **Code samples**: prefer pseudocode or shell snippets the reader can run. If you cite Rust, cite specific files like `deposits-core/src/ledger.rs:1107`.
- **Footnotes for tangents.** Don't break flow with parentheticals; if a point is worth making but breaks the line, put it in a footnote.
- **End with a "Where this leads" paragraph.** One or two sentences pointing to the next chapter or the chapter that builds on this one.

### What to avoid

- Re-explaining Bitcoin basics. Assume the reader knows UTXOs, signatures, multisig, basic Lightning. The Background chapter (Chapter 3) covers anything beyond that.
- Repeating DEP prose verbatim. If a DEP paragraph is exactly what you want to say, link to it instead.
- Vague claims. "More secure" → secure against what attacker, with what budget. "Fast" → numbers.
- Implementation details in protocol chapters. Part II (chapters 4–10) is wire-and-rules only; how the Rust code does it lives in Part V.
- Over-promising. The protocol has real tradeoffs (no unilateral exit, no privacy, intermittent availability). Name them.

### Conventions

- "Operator" = the active custodian of a ledger.
- "Member" = a quorum member of a ledger (an operator of *another* ledger who is co-signing this one).
- "Wallet" = the depositor's client.
- "Ledger" = an append-only chain of signed updates owned by a single operator.
- Amounts are in millisatoshis unless stated otherwise (consistent with the DEPs).
- Hex byte counts are written as "32 bytes" not "256 bits".
