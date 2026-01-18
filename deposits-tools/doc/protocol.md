# Bitcoin Deposits Lightning Protocol Extension
## Technical Specification v1.0

### Abstract

Bitcoin Deposits is a Layer 3 protocol extension for the Lightning Network that enables trust-minimized custodial wallets through validated channel outputs called ReservesOutputs. The protocol allows operators to manage deposits on behalf of users while being constrained by cryptographic rules enforced at the Lightning channel level.

---

## 1. Protocol Overview

### 1.1 Architecture Layers

```
Layer 3: Bitcoin Deposits Protocol
- Deposit wallets controlled by user keys
- MuSig2 ledger addressing
- Cross-ledger auditing network

Layer 2: Lightning Network + ReservesOutput
- Channel commitment transactions
- Reserve validation rules
- Payment routing

Layer 1: Bitcoin Blockchain
- Final settlement
- UTXO model
```

### 1.2 Key Components

- **Reserves**: A separate channel output that holds reserves
- **Ledger**: MuSig2-addressed deposit container requiring operator-partner cooperation
- **Deposits**: User-controlled balances within the ledger
- **Cross-Auditing**: Network of channel partners monitoring ledger operations

---

## 2. ReservesOutput Specification

### 2.1 Channel Extension

The ReservesOutput extends Lightning channels with an additional validated output in commitment transactions.

**Feature Bit**: `option_reserves_output` (bit 42)

### 2.2 State Management

```javascript
Ledger {
  operatorKey: pubkey
  partnerKey: pubkey
  ledgerAddress: address  // MuSig2(operatorKey, partnerKey)
  deposits: Array<Deposit>
  reserves: ReservesOutput
}

ReservesOutput {
  channelId: bytes32
  amount: satoshis
  spendTo: pubkey
}

Deposit {
  pubkey: pubkey
  balance: satoshis
  invoices: Array<Invoice>  // Unexpired outstanding invoices
  fees: FeeStructure
  lastFeeAssessment: timestamp
}

Invoice {
  id: string
  amount: satoshis
  expires: timestamp
}

Fees {
  annualizedFixed: satoshis
  annualizedBps: float
  frequencyBlocks: int
}
```

### 2.3 Validation Rules

All operations must satisfy these constraints:

1. **Reserve Requirements**
   `reserves >= sum(all deposit balances) * 1.2 + max(outstanding invoice amounts)`

2. **Operation Prerequisites**
   - Deposits are always added with zero balance
   - Cannot remove deposit with non-zero balance or unexpired invoices
   - Cannot process outgoing payments exceeding deposit balance
   - Cannot cosign invoices without adequate reserves for new exposure

---

## IMPLEMENTATION UPDATE ✅

### Current Status (January 2025)

We have successfully implemented a complete Bitcoin Deposits protocol proof-of-concept with the following key architectural discoveries:

#### ✅ **Economic Model Validation**
- **Key Insight**: Deposits are **NEVER** artificially funded by protocol messages
- **Reality**: Deposits only increase from external Lightning invoice payments
- **Validation**: Alice cannot "give away money" - protocol prevents artificial funding
- **Economic Rationality**: Reserves added only when needed, removed when excess

#### ✅ **Real Protocol Implementation**
- **Message Types**: All 17 message types (0x1000-0x14FF) implemented with TLV encoding
- **State Machines**: Real economic enforcement, not scripted responses
- **Two-Node Testing**: Independent protocol instances with P2P message exchange
- **Economic Enforcement**: Both Alice and Bob validate reserve requirements independently

#### ✅ **Architecture Discovery**
- **ldk-server**: HTTP API wrapper (REST endpoints only)
- **ldk-node**: Real Lightning protocol implementation (where Bitcoin Deposits belongs)
- **CustomMessage**: The proper integration point for Lightning protocol extensions
- **Implementation Path**: Protocol logic goes in ldk-node, API exposure in ldk-server

#### ✅ **Test Coverage**
```
63/63 tests passing:
- 56 message/codec tests
- 4 protocol state tests
- 3 multi-node integration tests
```

#### 📊 **Key Files Implemented**
- `bitcoin_deposits_messages.rs` - Complete message definitions
- `bitcoin_deposits_protocol.rs` - Real economic state machine
- `bitcoin_deposits_codec.rs` - Lightning TLV encoding/decoding
- `bitcoin_deposits_integration_test.rs` - True two-node P2P testing
- `bitcoin_deposits_handler.rs` - Message handling framework

The implementation below serves as the **blueprint for migration to ldk-node**.

---

## 3. Message Protocol

### 3.1 Message Types

```
RESERVES MESSAGES
├── RESERVES_ADD            // Create initial reserves
├── RESERVES_REMOVE         // Remove reserves (closing)
├── RESERVES_UPDATE_OUTPUT  // Update reserves configuration
├── RESERVES_TO_RESERVES    // Add to reserves
└── RESERVES_TO_LOCAL       // Remove from reserves

LEDGER MESSAGES
├── LEDGER_ADD_DEPOSIT      // Create new deposit
├── LEDGER_REMOVE_DEPOSIT   // Remove empty deposit
├── LEDGER_UPDATE_DEPOSIT   // Update deposit configuration
├── LEDGER_LOCK_TRANSFER    // Lock for external transfer
├── LEDGER_FAIL_TRANSFER    // Unlock due to failed transfer
└── LEDGER_FULFILL_TRANSFER // Remove due to successful transfer

MAINTENANCE MESSAGES
├── MAINTENANCE_ASSESS_FEE  // Apply fees
└── MAINTENANCE_CHARGE_FEES // Collect fees

RECEIVING MESSAGES
├── RECEIVING_COSIGN_INVOICE // MuSig2 invoice
└── RECEIVING_CREDIT_PAYMENT // Credit deposit

SENDING MESSAGES
├── SENDING_LOCK_PAYMENT     // Lock for payment
├── SENDING_FAIL_PAYMENT     // Timeout refund
└── SENDING_FULFILL_PAYMENT  // Complete payment
```

### 3.2 Message Flow

1. **Ledger Creation**
   ```
   Operator -> Partner: RESERVES_ADD(0)
   [Both create MuSig2 ledger address]
   ```

2. **Reserve Management**
   ```
   Operator -> Partner: RESERVES_TO_RESERVES(amount)
   [Operator's channel balance decreases by amount]
   [Reserves increase by amount]
   ```

3. **Deposit Creation**
   ```
   Operator -> Partner: LEDGER_ADD_DEPOSIT(pubkey)
   [Creates deposit with 0 balance]
   [Sets as next target for invoice assignment]
   ```

4. **Invoice Generation and Cosigning**
   ```
   Operator -> Partner: RECEIVING_COSIGN_INVOICE(pendingInvoice)
   [Creates pendingInvoice, calculates required reserves]
   [Partner verifies reserve requirements]
   [Both sign with MuSig2]
   ```

5. **Invoice Payment**
   ```
   External -> Operator: Lightning payment
   [Increases operator's channel balance]
   [Operator moves invoice_amount * 1.2 to reserves]
   [Credits invoice_amount to assigned deposit]
   [Removes invoice from deposit's invoices array]
   ```

---

## 4. Ledger Operations

### 4.1 Ledger Address Creation

Ledgers use MuSig2 aggregated public keys:

```
ledger_address = MuSig2.KeyAgg(
    derive_key(operator_key, ledger_id),
    derive_key(partner_key, ledger_id)
)
```

### 4.2 Reserve Management

**Adding Reserves**:
- Operator moves funds from local channel balance to reserves

**Removing Reserves**:
- Automatically optimizes to exact required amount: `sum(deposits) * 1.2 + max(invoices)`
- Returns all excess to operator's channel balance in single operation

### 4.3 Payment Processing

**Outgoing Payments**:
1. User signs payment authorization
2. Operator locks deposit balance
3. Payment routes through Lightning
4. On success: balance deducted
5. On failure: balance refunded

**Incoming Payments**:
1. Operator generates invoice (creates pendingInvoice state)
2. Partner verifies reserve requirements for new exposure
3. Both parties cosign invoice (assigns to deposit via round-robin)
4. External node pays Lightning invoice
5. One of operator's channel balances increases with payment

6a. Operator moves (invoice_amount × 1.2) from channel to reserves
7a. Invoice amount credited to assigned deposit balance
8a. Invoice removed from deposit's outstanding invoices array

6b. Operator does not credit deposit balance
7b. Payer provides preimage to depositor
8b. Depositor provides preimage to channel partner
9b. With proof of payment and no credited deposit, partner force closes channel

---

## 5. Security Model

### 5.1 Trust Assumptions

The protocol is trust-minimized, not trustless:

- **Prevented**: Unilateral operator actions (MuSig2 requirement)
- **Detectable**: Payment theft (payment preimage evidence)
- **Enforceable**: Protocol violations (channel force close)
- **Economic**: Security deposits exceed potential gains

### 5.2 Attack Mitigation

**Payment Theft Prevention**:
- Invoices require partner cosignature
- Highwater mark tracks peak invoice exposure
- Evidence of non-credited payment triggers force close

**Collusion Prevention**:
- Multi-ledger architecture (4-6 ledgers per operator)
- Cross-auditing by other channel partners
- Security deposit forfeiture across all ledgers
- Network effects punish dishonesty

### 5.3 Recovery Process

**Force Close Scenario**:
1. Reserves + security deposits → multisig of all partners
2. Partners verify protocol compliance via audit logs
3. Compliant operator: funds returned
4. Non-compliant: security deposits forfeited, deposits recovered

---

## 6. Cross-Ledger Auditing

### 6.1 Network Structure

Recommended operator configuration:
- 4-6 ledgers with different channel partners
- Each partner audits operator's other ledgers
- Security deposit per ledger = 100% / (number of ledgers)

### 6.2 Audit Responsibilities

Channel partners monitor:
- Reserve compliance (120% deposits, 100% highwater)
- Payment processing integrity
- Invoice cosigning validity
- Cross-ledger consistency

### 6.3 Enforcement Mechanisms

- **Soft enforcement**: Reputation reporting
- **Hard enforcement**: Channel force closure
- **Network enforcement**: Cascading closures for violations

---

## Appendix A: Validation Pseudocode

```python
def validate_operation(state, operation):
    if operation.type == "ADD_DEPOSIT":
        # Deposits can be added with zero reserves since they start at zero balance
        assert operation.pubkey not in [d.pubkey for d in state.deposits]

    elif operation.type == "COSIGN_INVOICE":
        total_deposits = sum(d.balance for d in state.deposits)
        max_invoice = max([inv.amount for d in state.deposits for inv in d.invoices] + [0])
        if state.pendingInvoice:
            max_invoice = max(max_invoice, state.pendingInvoice.amount)
        required = total_deposits * 1.2 + max_invoice
        assert state.reserves >= required, f"Insufficient reserves: need {required}, have {state.reserves}"

    elif operation.type == "REMOVE_DEPOSIT":
        deposit = next(d for d in state.deposits if d.pubkey == operation.pubkey)
        assert deposit.balance == 0, "Non-zero balance"
        assert len(deposit.invoices) == 0, "Outstanding invoices"

    elif operation.type == "SEND_PAYMENT":
        deposit = next(d for d in state.deposits if d.pubkey == operation.pubkey)
        assert deposit.balance >= operation.amount, "Insufficient deposit balance"

    return True
```

## Appendix B: MuSig2 Ledger Creation

```python
def create_ledger_address(operator_key, partner_key, ledger_id):
    # Derive child keys
    op_ledger_key = derive_key(operator_key, ledger_id)
    pt_ledger_key = derive_key(partner_key, ledger_id)

    # MuSig2 key aggregation
    ledger_pubkey = musig2_key_agg([op_ledger_key, pt_ledger_key])

    # Create P2TR address
    ledger_address = p2tr_address(ledger_pubkey)

    return ledger_address
```
