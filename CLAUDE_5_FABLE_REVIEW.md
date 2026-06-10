Two very different questions — one is a punch list, one is a mirror. Punch list first, consolidated from everything that survived both sessions, in priority order:

**Ship-blockers (slashing-path correctness — bugs here are catastrophic in both directions):**
- **Lottery single-non-revealer gap.** Partial-reveal leaves exist only for N≥11; policy caps N at 7. The case your own spec calls dominant has no script path in any deployable configuration — one withholding loser collapses the lottery into the CSV-144 social-multisig cascade. Extend partial-reveal leaves down to N=3, and make non-revealers forfeit their slashing share so the abort option carries a price.
- **Preimage bounds-checking.** Mandate `OP_SIZE` range validation per preimage in the claim leaf, so a malformed commitment degrades to withholding (handled above) rather than poisoning the leaf for everyone.
- **DEP-16 conformance suite.** The term evaluator sits directly on the slashing path; a cross-implementation divergence is a false fraud proof. Canonical test vectors and a cost cap before anything else depends on it.

**Trust-model honesty (documentation, not code):**
- **Rewrite the whitepaper to match the spec.** The windfall incentive story is dead, "membership requires no separate capital" is false under replacement collateral, and the tier-table liveness clock — honest-majority-responsive-within-1008-blocks — appears nowhere. The spec is more defensible than the paper advertising it.
- **Publish the simulation.** Parameters, adversary model, and a correlated-compromise variant — because under agent operators, monoculture replaces the 49% coalition as the realistic worst case, and correlated-downtime measurement (free, from the public record) should enter the independence story.
- **The guarantee matrix, machine-readable, in Kind 39100.** Which sats, which guarantee, whose honesty, what time profile. Humans were never going to read it; your actual users will route on it.

**Upgrades (clear wins, no trust-model change):**
- PTLC completion locks — kills courier hash linkage, restores your Bitcoin-equivalence privacy claim, cheap because the ledger isn't script-bound.
- Tiered lightning receive — wire the settlement-atomic path through the InvoiceLock primitives you already have for online receive; deterrence stays for offline; wallets display the regime.
- Batched operations per update, bps-only fee norms. Constant factors, but big ones, and both un-tax exactly the behaviors agent commerce runs on.

