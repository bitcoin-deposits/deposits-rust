# Bitcoin Deposits: Implementation Specification

**Version**: 0.2 (draft)
**Status**: Work in progress

---

## Overview

Bitcoin Deposits is a Layer 3 protocol for trustless custody. Operators maintain transparent account ledgers backed by on-chain reserves. Quorum members hold pre-signed recovery transactions and monitor for dishonesty. Users get Lightning-speed payments without channel management, UTXOs, or liquidity concerns.

**Security model**: Successful theft requires collusion of 51% of network capital—the same threshold as Bitcoin itself, enforced by capital at risk rather than hashpower.

**Key tradeoff**: No unilateral exit to L1. Instead, guaranteed recovery via reassignment to honest operators.

---

## Core Concepts

### Deposit

A deposit is an account on an operator's ledger.

```
Deposit {
    pubkey: secp256k1 public key (identity)
    balance: u64 (millisatoshis)
    spend_script: Miniscript (authorization rules)
    receive_policy: bool (true = keysend allowed, false = invoice required)
}
```

- The pubkey is the deposit's identity across the network
- Spend script defines who can move funds (default: single sig)
- Receive policy gates whether signed invoices are required

### Operator

An operator maintains a transparent ledger and holds reserves.

```
Operator {
    pubkey: secp256k1 public key (identity)
    ledger: ordered list of transactions
    state_root: hash of current ledger state
    reserves: on-chain UTXOs backing the ledger
    quorum_members: set of operators holding recovery capability
}
```

**Operator obligations**:
- Only sign conforming ledger updates
- Maintain appropriately funded reserves output
- Credit wallet invoices when paid
- Publish state updates to nostr relay

### Quorum Member

A quorum member monitors an operator and holds recovery capability.

```
QuorumMember {
    pubkey: secp256k1 public key
    operator: pubkey of operator being monitored
    recovery_tx: pre-signed transaction to recover reserves
    own_ledger_size: u64 (must be >= operator's ledger / 2)
}
```

**Quorum member obligations**:
- Only co-sign conforming attestations
- Broadcast recovery tx on evidence of dishonesty
- Provide conforming vote for recovery proceedings

---

## Ledger Operations

### Transaction

```
Transaction {
    source: deposit pubkey
    destination: deposit pubkey | invoice
    amount: u64 (millisatoshis)
    fee: u64 (millisatoshis)
    memo: optional bytes
    signature: satisfies source deposit's spend_script
}
```

**Validation rules**:
1. Source deposit exists and has sufficient balance
2. Signature satisfies source deposit's spend_script
3. If destination is existing deposit: receive_policy is satisfied
4. If destination is invoice: invoice is valid and not expired
5. Fee meets operator's minimum

**Change guarantee**: Any transaction may create a change output back to a new deposit with identical spend_script and receive_policy. Operators MUST NOT refuse valid change outputs.

### Invoice

```
Invoice {
    destination: deposit pubkey
    amount: u64 (millisatoshis)
    payment_hash: sha256 (for cross-operator HTLCs)
    expiry: unix timestamp
    memo: optional bytes
    signature: from destination deposit key
}
```

Invoices carry all receive conditions. The deposit's receive_policy simply determines whether an invoice is required (false) or optional (true/keysend).

### State Update

```
StateUpdate {
    sequence: u64 (monotonically increasing)
    timestamp: unix timestamp
    previous_root: hash
    transactions: ordered list
    new_root: hash
    operator_signature: signature over all fields
}
```

Operators publish state updates to their nostr relay. Partners and anyone else can subscribe and validate.

---

## Spend Scripts

Spend scripts use Miniscript, the analyzable subset of Bitcoin Script.

### Common Patterns

**Single signature (default)**:
```
pk(deposit_pubkey)
```

**2-of-3 multisig**:
```
thresh(2, pk(A), pk(B), pk(C))
```

**Timelock recovery**:
```
or(pk(owner), and(pk(recovery), after(1000)))
```
Where `after(N)` refers to operator block height.

**HTLC (for cross-operator)**:
```
or(
    and(sha256(H), pk(receiver)),
    and(after(timeout), pk(sender))
)
```

### Operator Blocks

Operators produce blocks (state updates) with monotonically increasing sequence numbers. Timelocks reference these:

- `after(N)`: valid when operator block height >= N
- `older(N)`: valid when N blocks have passed since deposit creation

If an operator claims a block from the future, this is evidence of non-conformance.

---

## Reserves and Recovery

### Reserve Output Structure

Operator reserves sit in a standard P2WSH output:

```
OP_IF
    <operator_pubkey> CHECKSIG
    <timeout> CHECKLOCKTIMEVERIFY
OP_ELSE
    <N> <partner1_pubkey> ... <partnerN_pubkey> <N> CHECKMULTISIG
OP_ENDIF
```

- Operator can reclaim after timeout (normal refresh)
- Partners can spend via multisig (recovery)

### Recovery Transaction

Operators pre-sign recovery transactions and distribute to partners:

```
RecoveryTx {
    input: reserves UTXO (partner multisig path)
    output: recovery multisig address
    locktime: block A (CLTV - not valid before)
    signatures: operator's signature for the input
}
```

Partners hold this transaction. They only broadcast on evidence of dishonesty.

### Partner Set Changes

When partners join or leave:

1. Operator creates new recovery tx with updated partner set
2. New tx has earlier CLTV than old txs
3. Old txs remain valid but current partners can always act first
4. Periodically, operator refreshes to new UTXO (resets locktime space)

**Expiry enforcement**: If old partners broadcast an outdated recovery tx, their signatures prove collusion. Their own quorum members confiscate their funds.

### Recovery Process

When dishonesty is detected:

1. Partner broadcasts recovery tx
2. Funds land in recovery multisig
3. Partners vote on ledger validity
4. Valid: funds returned to operator with corrected state
5. Invalid: funds and ledger reassigned to honest operator

Voting is visible and auditable. Dishonest votes trigger confiscation from the voter's own collateral relationships.

---

## Cross-Operator Transfers

Transfers between operators use HTLCs on the deposit layer.

### Protocol

Alice (Operator A) pays Bob (Operator B):

1. Bob generates preimage P, gives hash H to Alice
2. Alice creates HTLC deposit on A: "Bob gets funds if reveals P before timeout"
3. A notifies B of pending HTLC
4. B credits Bob's deposit (conditional on P)
5. Bob reveals P to B
6. B reveals P to A
7. A resolves HTLC to complete transfer

### HTLC Deposit

```
Deposit {
    pubkey: htlc_id
    balance: amount
    spend_script: or(
        and(sha256(H), pk(receiver_operator)),
        and(after(timeout), pk(sender_operator))
    )
    receive_policy: false
}
```

This is just a normal deposit with an HTLC spend script. No special machinery required.

---

## Network Communication

### Nostr Integration

Operators run nostr relays. All communication uses nostr events.

**State updates**: Operator publishes to their relay
**Queries**: Wallets send requests (signed with deposit key)
**Discovery**: Broadcast "who has deposit X?"

### Wallet → Operator

```
Event {
    kind: 21000 (deposit request)
    pubkey: deposit pubkey
    content: encrypted request (optional, for privacy)
    tags: [
        ["p", operator_pubkey],
        ["request", base64(request)]
    ]
    sig: signature from deposit key
}
```

Request types:
- `transfer`: move funds
- `invoice`: create invoice
- `balance`: query balance
- `history`: query transaction history

### Deposit Discovery

When a wallet doesn't know its current operator:

```
Event {
    kind: 21001 (deposit discovery)
    content: deposit_pubkey
}
```

Current operator responds with proof of inclusion in their ledger.

### Giftwrap for Privacy

Wallets can wrap requests in NIP-59 giftwrap to obscure:
- Which deposit is making the request
- Balance queries
- Transaction metadata

The ledger is transparent, but query patterns can be private.

---

## Collateral Requirements

### Size Requirement

To be a quorum member for operator O, partner P must have:

```
P.ledger_total >= O.ledger_total / 2
```

This ensures partners have proportional skin in the game.

### Security Threshold

To steal from ledger L:
1. Corrupt majority of L's quorum members
2. Each partner has their own quorum members
3. Recursion continues until you need 51% of total network capital

The market determines acceptable:
- Collateral ratios
- Partner set sizes
- Timeout periods
- Fee structures

No protocol-level governance. Participants vote with capital.

---

## Implementation Phases

### Phase 1: Single Operator

- Transparent ledger with state updates
- On-chain reserves (single-sig + timelock)
- Basic wallet operations
- Nostr communication

### Phase 2: Quorum Members

- Multi-party reserve output
- Pre-signed recovery transactions
- Partner monitoring
- Recovery process

### Phase 3: Cross-Operator

- HTLC deposits
- Operator-to-operator settlement
- Deposit discovery across network

### Phase 4: Optimizations

- Lightning bridge for speed
- FROST for efficient multisig
- Privacy layers
- Advanced spend scripts

---

## Open Questions

1. **Optimal collateral ratios**: What ratios make the game theory work at different network sizes?

2. **Partner discovery**: How do new operators find partners? Reputation bootstrapping?

3. **Privacy layer**: Can we add privacy without breaking accountability? Selective disclosure?

4. **Governance**: How do protocol upgrades happen? Soft forks within the deposit network?

5. **Dust and rent**: Minimum balances? Ongoing fees for inactive deposits?

---

## Appendix: Conformance Rules

An operator is **conforming** if:

1. Every state update is validly signed
2. Every transaction in the ledger satisfies its spend script
3. The state root correctly hashes the ledger state
4. Reserves >= sum of all deposit balances
5. All credited invoices correspond to received payments
6. Block timestamps are monotonically increasing and not in the future

An operator is **non-conforming** if any of the above fail. Evidence of non-conformance triggers recovery.

A partner is **conforming** if:

1. They only attest to conforming operator states
2. They broadcast recovery on evidence of non-conformance
3. They vote honestly in recovery proceedings

A partner is **non-conforming** if they:

1. Attest to invalid state
2. Fail to act on clear non-conformance
3. Vote dishonestly (provable via signed contradictions)

Non-conforming partners lose their collateral via their own partners.