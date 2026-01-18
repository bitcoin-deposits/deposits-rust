# Bitcoin Deposits: An Introduction

Bitcoin Deposits is a custodial wallet protocol built on Lightning. The operator holds funds but can't steal them—the protocol makes theft economically irrational and cryptographically provable.

## The Economics

For every sat of user deposits, the operator locks two sats of their own: 100% in reserves within the channel, and another 100% as collateral in other channels. Partners in those other channels can slash the operator's collateral if they misbehave elsewhere. Stealing 1 BTC costs 2+ BTC in slashed collateral, so the game theory points firmly toward honesty.

## The Cryptography

Every operation—deposits, payments, fees—produces a signed, hash-chained record. The operator signs each update, and each update includes the hash of its predecessor. Modify any historical entry and the chain breaks.

These signed updates don't stay between operator and partner. The operator broadcasts them to collateral partners in other channels, who validate independently. When a channel force-closes, voters evaluate the ledger against protocol rules. Conforming operators get their funds back. Non-conforming operators lose them to a time-locked recovery process that makes depositors whole.

## The Ledger

The ledger is a hash chain tracking deposits, payments, and fees. Both operator and partner maintain copies—the operator's is authoritative, the partner's is for validation. If the two diverge, signatures prove who lied.

To compute a balance, you replay the ledger from genesis. There's no index to corrupt, no shortcut to exploit.

## Reserves and Collateral

Reserves live in the commitment transaction, spendable only with partner cooperation. The protocol enforces a 1:1 ratio: 10 BTC in deposits requires 10 BTC in reserves. Partners won't sign commitments that violate this constraint.

Collateral addresses the next obvious problem: operator-partner collusion. The operator maintains excess reserves in other channels, and those partners attest to its existence. Cheat in one channel, get slashed in the others. The attestation web makes universal collusion impractical.

## Recovery

Force-closes trigger evaluation. After waiting six blocks for entropy, voters check the hash chain, verify signatures, and compare on-chain state to the signed record. Conforming operators return to normal operations. Non-conforming operators enter tiered recovery.

The tiers degrade over time. On day one, only a randomly-selected partner can claim—this prevents races. From day two, any three partners can claim together. By week two, any single partner suffices. Taproot script paths encode each tier's signature requirements, ensuring funds never lock permanently.

## User Experience

Users connect via Nostr Wallet Connect: encrypted messages through a relay to the operator's node. The UX is a standard wallet—check balance, receive, send—without channel management or an online requirement.

Operators run an LDK node with the protocol enabled. A CLI handles administration; the cryptographic machinery runs automatically.

## Limitations

Partners see transaction history—that's how validation works. Operator downtime stops new payments. Lightning routing failures still happen. Lost keys mean lost access.

## Alternatives

Fedimint requires federation consensus. Cashu uses bearer ecash. Both involve different trust models with their own tradeoffs. Bitcoin Deposits uses a single operator with multi-party accountability: simpler to deploy, secured by slashing.

Liquid and other sidechains need their own consensus mechanisms. Bitcoin Deposits runs entirely on Lightning and settles on Bitcoin.

---

For the full specification, see [deposits.md](deposits.md).
