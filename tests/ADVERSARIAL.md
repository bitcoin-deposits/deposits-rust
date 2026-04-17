# Adversarial Testing Architecture

## Purpose

Systematically attempt to steal funds from the deposits protocol. Each attack
targets a specific security property. The output is not pass/fail but a
structured assessment: what invariant held (or broke), minimum adversary
capability, cost/extraction ratio, and whether the defense is protocol-level,
implementation-level, or wallet-policy.

## Output Structure

Every attack produces:

```
Attack: <name>
Invariant tested: <which property must hold to prevent this>
Adversary capability: <what the attacker controls>
Cost to attacker: <what they spend/risk>
Extraction: <what they gain if successful>
Result: BLOCKED at <layer> | EXPLOITABLE under <conditions>
Defense: protocol | implementation | wallet-policy
Scales: constant | linear | super-linear with network size
```

## Invariant Registry

Each test that fails records which invariant prevented the attack. This builds
the empirical security model — the actual properties the protocol depends on.

### Economic Invariants
- **E1**: reserves_amount >= sum(deposits.balance) at all times
- **E2**: collateral locked on member ledgers >= obligations they back
- **E3**: slashing extraction >= attacker's maximum possible theft
- **E4**: expected value of attack < 0 for rational adversary

### Cryptographic Invariants
- **C1**: operations with witnesses are only valid if witness satisfies descriptor
- **C2**: payment credits require unique payment_hash (no double-credit)
- **C3**: signatures are bound to specific (ledger_id, operation, context)
- **C4**: Taproot internal key is unspendable (NUMS point)
- **C5**: Taproot tree structure matches announced quorum composition

### State Machine Invariants
- **S1**: dispute state gates block all normal operations
- **S2**: hash chain is append-only, no forks without DisputeEnter
- **S3**: balance cannot go negative (available_balance checked before lock)
- **S4**: collateral locks are ratchet-only (amount and expiry only increase)

### Liveness Invariants
- **L1**: disputes resolve within bounded time
- **L2**: lottery completes even if participants withhold reveals
- **L3**: wallet can always force evidence onto the ledger (DeliveryEmbed)
- **L4**: relay censorship cannot suppress dispute detection

## Tier 1: Load-Bearing Informal Arguments

### 1.1 Sybil-with-Plausible-Topology
- **Target invariant**: Wallet discovery heuristics reject insufficient diversity
- **Attack**: Construct sybil cluster that passes wallet topology checks
- **Methodology**: Parameterize wallet heuristics (min cosign paths, diversity
  requirements), then search for minimum sybil cluster that passes
- **Key question**: What's the minimum cluster size/topology that's undetectable?
- **Implementation**: Graph-based simulation with configurable wallet policies

### 1.2 Near-Expiry Extraction
- **Target invariant**: E3 (slashing >= theft), E2 (collateral covers obligations)
- **Attack**: Time extraction to exploit window where collateral_lock < cascade_time
- **Formula**: extraction_window = min(remaining_collateral_lock, diameter × dispute_response_blocks)
- **Key question**: Is there a profitable window, and do wallets refuse deposits in it?
- **Implementation**: Time-parameterized simulation varying quorum_expiry and lock_until_block

### 1.3 Race-to-Slash Exploitation
- **Target invariant**: E4 (negative expected value)
- **Attack**: Induce premature or strategic slashing via fake fraud proofs
- **Key question**: Can an attacker trick honest members into slashing innocents?
- **Implementation**: Game-theoretic model with configurable defector behavior

### 1.4 Lightning-Layer Bounded Theft
- **Target invariant**: E3, E4
- **Attack**: Steal payments below wallet detection threshold, extract indefinitely
- **Key question**: What's the maximum sustainable theft rate?
- **Implementation**: Population simulation with varying wallet preimage-reporting

## Tier 2: Spec-Level Ambiguities

### 2.1 NUMS Point Not Mandated
- **Target invariant**: C4
- **Attack**: Operator picks internal key whose discrete log they know
- **Test**: Check that implementation uses BIP-341 NUMS, wallets verify it
- **Implementation**: Direct code inspection + test with non-NUMS internal key

### 2.2 Taproot Tree Not Verified by Wallets
- **Target invariant**: C5
- **Attack**: Extra leaf in Taproot tree granting operator solo spend
- **Test**: Construct tree with hidden leaf, verify wallet detects mismatch
- **Implementation**: Build TaprootReservesOutput with extra leaf, test verification

### 2.3 Cosigner Validation Scope
- **Target invariant**: S2 (no forks without dispute)
- **Attack**: Present abbreviated history to new quorum joiners, hiding equivocation
- **Test**: New member joins, receives partial history, check if they validate from genesis
- **Implementation**: Simulate QuorumJoin with truncated event store

### 2.4 Proof Hash Embedding Ambiguity
- **Target invariant**: C3 (signatures bound to context)
- **Attack**: Embed proof in non-canonical location that verifiers miss
- **Test**: Check if implementation accepts proofs from any field vs only canonical
- **Implementation**: Construct fraud proof with non-standard embedding

## Tier 3: Protocol-Level Games

### 3.1 Censorship-via-Quorum-Rotation
- **Target invariant**: L3 (wallet can force evidence)
- **Attack**: Operator rotates quorum to evade DeliveryEmbed
- **Key question**: Is rotation cheaper than embedding?
- **Implementation**: Cost model comparing rotation vs embed fees

### 3.2 Collateral Double-Counting
- **Target invariant**: E2
- **Attack**: Simultaneous non-conformance across multiple backed ledgers
- **Key question**: Does slashing math hold when multiple ledgers fail at once?
- **Implementation**: Multi-ledger simulation with concurrent disputes

### 3.3 Dispute-Lottery Griefing
- **Target invariant**: L1, L2
- **Attack**: Commit to lottery preimage, refuse to reveal
- **Key question**: Can dispute resolution be stalled indefinitely?
- **Implementation**: Simulate lottery with non-revealing participant, check timeouts

### 3.4 Entropy Block MEV
- **Target invariant**: E4
- **Attack**: Miner withholds block to manipulate lottery outcome
- **Key question**: At what deposit size does MEV become profitable?
- **Implementation**: Probabilistic model of mining advantage

## Tier 4: Integration and Ecosystem

### 4.1 Relay-Level Censorship
- **Target invariant**: L4
- **Test**: Suppress specific event kinds, verify degradation mode

### 4.2 Wallet State Exfiltration
- **Target invariant**: Privacy (not fund safety)
- **Test**: Correlate relay metadata to deanonymize users

### 4.3 Recovery Ambiguity
- **Target invariant**: Wallet correctness
- **Test**: Publish fake Kind 9100 events matching victim's derived pubkeys

### 4.4 Domain Attestation Verifier Compromise
- **Target invariant**: Access control trust root
- **Test**: Forge attestations with compromised verifier key

## Tier 5: Implementation Attacks

### 5.1 Signature Malleability
- **Target invariant**: C1, C3
- **Test**: Accept malleated signature encodings

### 5.2 Timing Attacks on Crypto
- **Target invariant**: C1 (key secrecy)
- **Test**: Timing oracle against signing operations

### 5.3 Integer Overflow in Fee Arithmetic
- **Target invariant**: S3 (balance non-negative)
- **Test**: balance=2^63-1, bps=10000, blocks=52560

### 5.4 Replay Across Ledgers
- **Target invariant**: C3
- **Test**: Cosigner attestation from ledger A replayed on ledger B

### 5.5 Descriptor Parsing Complexity
- **Target invariant**: C1
- **Test**: Pathological descriptors, deposit_id collisions (16-byte truncated SHA256)
