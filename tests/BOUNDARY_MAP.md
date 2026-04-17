# Security Boundary Map

Live artifact tracking the empirical security surface of the Bitcoin Deposits protocol.
Generated from adversarial testing — 87 in-process tests, 6 Docker tests, 20 attack vectors.

## Extraction Provenance

Every extraction number has one of three types:

- **(T)** Test topology bound — "this is what was sitting in the test." Scales with deployment, not a property of the attack. The real claim is a percentage of reserves.
- **(M)** Model bound — computed from attack parameters × window × rate. Independent of test size.
- **(E)** Empirical — measured from an actual successful attack run against live nodes.

## Findings

### Implementation (fix in code, gone forever)

| Finding | Extraction | Type | Attack |
|---------|-----------|------|--------|
| NUMS = operator key | 100% of reserves | (T) | Operator key-path spends Taproot reserves, bypassing all script paths. Internal key is tie-breaker pubkey, not BIP-341 NUMS. |

**Fix:** Require BIP-341 NUMS point `lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)` as internal key. Require wallets to verify on every QuorumBegin.

### Wallet-Policy (every wallet implementer must know this)

| Finding | Extraction | Type | Attack |
|---------|-----------|------|--------|
| Near-expiry window | 100% of reserves | (M) | Steal when `remaining_lock < diameter × dispute_response_blocks`. Cascade can't complete before collateral unlocks. |
| Lightning bounded theft | `theft_rate × payment_volume × operator_lifetime` | (M) | Steal payments below wallet detection threshold. Viable when >1% of wallets don't verify preimages. |
| Collateral < deposits | `total_deposits - total_collateral` | (M) | Protocol allows deposits to exceed collateral. If reserves stolen, collateral can't make depositors whole. |
| Deposit/collateral gap | Appears at 1.0× ratio | (M) | Same as above — the boundary is exactly when deposits cross collateral. |

**Wallet requirements:**
1. Refuse deposits when `quorum_expiry - current_height < diameter × dispute_response_blocks`
2. Verify preimages for every invoice payment
3. Check `total_collateral >= total_deposits` before opening deposits
4. Reconstruct Taproot tree from quorum members, reject address mismatches

### Node-Policy (every operator must get this right)

| Finding | Extraction | Type | Attack |
|---------|-----------|------|--------|
| Cross-ledger attestation replay | collateral amount | (T) | Attestation accepted on different ledger — quorum membership check passes, ledger binding is not enforced at protocol layer. |
| Verifier compromise | enables deposit opening | (T) | Single point of failure for attestation-based access control. |
| Cosigner abbreviated history | enables hidden forks | (T) | New quorum members must replay from genesis — protocol relies on node enforcement. |

**Operator requirements:**
1. Watchers must verify `collateral_ledger_id` matches expected member ledger
2. Protect attestation verifier signing key as critical infrastructure
3. Enforce full-chain validation for new quorum members

### Protocol (by design, documented tradeoffs)

| Finding | Extraction | Type | Notes |
|---------|-----------|------|-------|
| Public ledgers | metadata | (T) | Verification requires transparency. Not a bug. |
| Censorship via sybil quorum | enables other attacks | (M) | Composes with near-expiry and lightning theft. |
| Relay censorship residual | enables delay | (M) | All-relay censorship indistinguishable from operator silence. |

### Composition Attacks (not yet tested)

| Composition | Components | Expected extraction | Priority |
|-------------|-----------|-------------------|----------|
| Sybil + near-expiry | #6 + #2 | 100% of reserves | HIGH — tests the transitive-slashing argument |
| Sybil + lightning theft | #6 + #3 | theft_rate × volume | MEDIUM — censorship prevents dispute detection |
| Verifier + deposit flood | #7 + #5 | collateral gap | LOW — requires verifier compromise first |

## Invariant Registry (empirical)

These are the properties that actually held under adversarial testing — the empirical security model.

| ID | Invariant | Tested | Held |
|----|-----------|--------|------|
| E1 | reserves >= deposits | ✓ | Yes (conformance check) |
| E2 | collateral >= obligations | ✓ | **Partial** (deposits can exceed collateral) |
| E3 | slashing >= theft | ✓ | Yes (1.5× ratio at default params) |
| E4 | EV(attack) < 0 | ✓ | Yes (2.5× safety margin with 99% detection) |
| C1 | witness satisfies descriptor | ✓ | Yes (CoreWitnessVerifier) |
| C2 | unique payment_hash | ✓ | Yes (HashSet dedup) |
| C3 | signatures ledger-bound | ✓ | **Partial** (attestations not bound at protocol layer) |
| C4 | NUMS internal key | ✓ | **No** (operator key, not NUMS) |
| C5 | taproot tree matches quorum | ✓ | Yes (different quorum = different address) |
| S1 | dispute blocks normal ops | ✓ | Yes (state gate) |
| S2 | hash chain append-only | ✓ | Yes (unique hashes, chain links) |
| S3 | balance >= 0 | ✓ | Yes (available_balance check) |
| S4 | collateral ratchet-only | ✓ | Yes (reduce blocked) |
| L1 | bounded dispute resolution | ✓ | Yes (state machine has exits) |
| L2 | lottery completion | ✓ | Yes (protocol progresses despite non-reveal) |
| L3 | wallet embed capability | ✓ | **Partial** (sybil quorum blocks embed) |
| L4 | relay censorship resistance | ✓ | **Partial** (multi-relay mitigates, all-relay fails) |

3 invariants failed (C4, partial E2, partial C3). 4 held partially. 10 held fully.
