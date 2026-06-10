# DEP-07: Fee Schedules

## Abstract

This document specifies the fee structures for Bitcoin Deposits: periodic custody fees, per-transfer fees, fee negotiation at deposit opening, and the fee change mechanism with block notice and change limits.

## Periodic Custody Fees (FeeStructure)

Custody fees are charged periodically against deposit balances:

- **annualized_msats**: fixed fee per year (msats), pro-rated for elapsed blocks
- **annualized_bps**: proportional fee rate (basis points per year), applied to the deposit balance
- **frequency_blocks**: collection period (blocks) -- how often `FeeCollect` is appended

Fee calculation for a collection period:

    fixed_portion = annualized_msats * blocks_elapsed / 52560
    proportional_portion = balance * annualized_bps * blocks_elapsed / (52560 * 10000)
    total_fee = fixed_portion + proportional_portion

All fee arithmetic uses integer division with floor rounding. Implementations MUST compute the multiplicative chain in at least u128 (or equivalent wide integer) before dividing — with realistic whale balances (~10¹⁶ msats), the product `balance * annualized_bps * blocks_elapsed` exceeds 2⁶⁴ long before the divisor rescues it, and silent u64 wrap would let the operator collect an arbitrary fraction of the intended fee. The final quotient fits in u64 for any sane input; implementations SHOULD saturate the downcast rather than wrap.

The operator appends `FeeCollect` (disc 50) with the computed fee, which is deducted from the deposit's balance and added to the ledger's `fees_accumulated` counter (see below).

## Per-Transfer Fees (TransferFeeSchedule)

Each transfer out of a deposit incurs a fee:

- **fixed_msats**: fixed fee per transfer (msats)
- **rate_bps**: proportional fee (basis points of the transfer amount)

Fee calculation:

    fee = fixed_msats + (amount_msats * rate_bps / 10000)

The same wide-integer requirement applies: `amount_msats * rate_bps` can overflow u64 for large amounts; implementations MUST widen to u128 and saturate the downcast.

The sender must provide the exact expected fee in the `TransferLock` request. The operator rejects mismatches.

### Why two components, not bps-only

External reviewers periodically propose collapsing fees to basis-points-only on the grounds that a flat per-op fee "taxes the behaviors agent commerce runs on." That framing is wrong, and the protocol explicitly rejects it.

Per-operation cost is real and *not* amount-proportional. Each ledger update costs the operator and its quorum:

- a cosignature round-trip (one network RTT per cosigner, signature CPU)
- validation work (decode, replay against state, conformance check)
- storage (the signed update lives forever on the operator's relay and propagates to peers)
- bandwidth (gossip to the durable relay, the messaging relay, and any subscribed wallets)

A 1-sat micropayment imposes the same per-op cost on the operator as a 1-BTC settlement; only the *risk* component scales with amount. Bps-only fees would force the operator to subsidize every small operation out of large-operation revenue — a model that's unstable under volume mix shifts and creates an obvious griefing surface (flood the operator with sub-dust transfers; the operator either rejects them or runs at a loss).

The right shape for both `FeeStructure` and `TransferFeeSchedule` is:

- **`fixed_msats` covers the per-op cost floor.** Operators should set it as low as their actual operational cost permits — measured in msats, comfortably under common micropayment values. A reasonable target is "the operator's marginal cost per operation, plus a small margin," not "what the market will bear." Wallets should distrust operators whose fixed components are large relative to their bps components.
- **`*_bps` covers the value-proportional risk-and-capital cost** — the operator's exposure scales with the amount under management or in flight, and bps captures that cleanly.

Both halves serve a structural purpose. Dropping the fixed component would require either subsidizing micropayments (operator unstable) or refusing them (defeats the use case). Keep both, keep `fixed_msats` low.

## Lightning Bridge Fees

The Lightning bridge (DEP-10 §Lightning) is the cross-domain HTLC connecting BOLT-11 payments to deposits-ledger TransferLocks/InvoiceLocks. Both directions have an operator-margin component and a Lightning-cost component, but the two compose differently and are advertised on separate schedules.

### Inbound (receive) — `InvoiceReceiveFeeSchedule`

The wallet asks for receive amount `X`. The operator publishes a BOLT-11 for `X + bridge_fee` and emits a `TransferLock` from its self-deposit with `amount = X` and `fee = bridge_fee`. The operator's self-deposit is debited by `X + bridge_fee`; the wallet's deposit receives `X`; `fees_accumulated` grows by `bridge_fee`. The operator's upstream LN claim collects the same `X + bridge_fee` from the payer, replenishing the self-deposit's outflow.

Crucially, the bridge_fee flows through `fees_accumulated` — not around it — so quorum-member compensation (DEP-05) applies to bridge revenue the same way it applies to intra-ledger transfer revenue. Operators who wanted to bypass quorum compensation would have to publish a special "bridge fees stay with operator" carve-out, which the protocol explicitly does not allow.

Schedule:

- **fixed_msats**: per-op cost floor for the bridge (cosig coordination, validation, BOLT-11 hold-invoice liquidity tied up for the CLTV window)
- **rate_bps**: proportional component covering operator capital cost and channel-rebalancing exposure

Fee calculation (operator quotes, wallet inspects the BOLT-11 before sharing with payer):

    bridge_fee = fixed_msats + (X * rate_bps / 10000)
    bolt11_amount = X + bridge_fee

Operators publish these on Kind 39100 as `invoice_receive_fee_fixed_msats` and `invoice_receive_fee_rate_bps`. Existing daemons that don't publish them advertise the legacy InvoiceCredit-based deterrence receive path only (DEP-10 §"Offline receive"), and wallets seeking HTLC-bridge receive MUST filter operators by the presence of these fields.

The Lightning routing fee on the inbound side is paid by the **payer's** node, not the operator's — the operator is the terminal hop, so there's no routing-fee variance to bound. The `invoice_receive_fee_*` schedule is the operator's full take.

**Self-deposit liquidity requirement.** The operator MUST maintain a self-deposit balance of at least `X + bridge_fee` per outstanding bridge receive. Without it the `TransferLock` would underflow and cosigners would refuse. Operators sizing self-deposit liquidity should follow the same drip/replenish patterns used for couriers (DEP-13).

### Outbound (pay) — `InvoicePayFeeSchedule` + per-payment quote

The outbound direction has two distinct cost components that the cosigning quorum can verify differently:

1. **Operator margin** — declared on Kind 39100 as `invoice_pay_fee_fixed_msats` + `invoice_pay_fee_rate_bps`. This is the operator's profit floor for taking on the routing job. Cosigners can verify the operator's signed quote includes at least this margin against the invoice amount.
2. **Max routing-fee buffer** — quoted per-payment by the operator at quote-negotiation time, based on the operator's LN graph view at that moment. Cosigners cannot independently probe LN routes; they accept whatever the operator signed in the quote because the operator's signature is the binding artifact, and the operator's risk is that LDK exceeds the cap and the payment fails (operator collects only the per-op `fixed_msats` per the Fee on Failure rule, eating the routing-probe work for no margin).

The quote dance is specified in DEP-10 §Pay. The cosigner conformance rule binds `InvoiceLock.amount` to the signed quote total; the wallet's commitment is exactly that amount.

Fee calculation (operator runs internally before responding to `quote_invoice`):

    operator_margin_msats   = invoice_pay_fee_fixed_msats + (invoice_amount * invoice_pay_fee_rate_bps / 10000)
    max_routing_fee_msats   = <LDK routing probe with safety multiplier, operator-chosen>
    quote_total_msats       = invoice_amount + operator_margin_msats + max_routing_fee_msats

Routing-fee variance the operator takes on is bounded by `max_routing_fee_msats`. On success they collect `operator_margin_msats + (max_routing_fee_msats − actual_routing_fee_msats)`. On failure they collect only the per-op `fixed_msats` floor from the deposit's `TransferFeeSchedule` per the Fee on Failure rule.

### Cosigner conformance rules

Each direction has rules the cosigning quorum verifies before signing:

**Inbound (TransferLock-as-bridge):**

- The cosigner checks `TransferLock.amount + TransferLock.fee == correlated BOLT-11.amount`, where the BOLT-11 is supplied by the wallet (or read off the cosigned invoice record).
- `TransferLock.fee == invoice_receive_bridge_fee(TransferLock.amount)` per the operator's published `invoice_receive_fee_*` schedule — the operator can't widen the fee mid-quote.
- `TransferLock.timeout_height + Δ ≤ BOLT-11.cltv_expiry_block` — see DEP-10 §"Bridge cosigner rules" for the Δ rules.
- The source deposit MUST be one of the operator's declared self-deposits on the same ledger (so the bridge_fee flows into `fees_accumulated` for quorum payout, not into an opaque operator pocket).

**Outbound (InvoiceLock with quote):**

- The cosigner verifies `quote_signature` against the operator's published key.
- `current_ledger_tip < quote_expiry`.
- `InvoiceLock.amount == quote_total_msats`.
- `operator_margin_msats >= invoice_pay_fee_fixed_msats + (invoice_amount * invoice_pay_fee_rate_bps / 10000)` — operator cannot undercut their advertised floor mid-quote.

A non-conforming lock fails cosigner verification; the operator cannot commit it. This is the structural enforcement that prevents the operator from silently widening either direction's fee.

## Fee on Failure

Lock-then-resolve operations (`TransferLock`/`Complete`/`Fail`, `InvoiceLock`/`Fulfill`/`Fail`, `OnchainLock`/`Fulfill`/`Fail`) charge a fee even when the resolution is a failure. Rationale: the operator did real work holding the lock and coordinating the attempt. On the failure path:

Lock-then-resolve operations (`TransferLock`/`Complete`/`Fail`, `InvoiceLock`/`Fulfill`/`Fail`, `OnchainLock`/`Fulfill`/`Fail`) charge a fee even when the resolution is a failure. Rationale: the operator did real work holding the lock and coordinating the attempt. On the failure path:

- The **proportional** portion of the fee is zero, since no `amount` was moved.
- The **fixed** portion (`fixed_msats` from the deposit's current `TransferFeeSchedule`) is charged to the deposit and credited to the operator's `fees_accumulated`.
- Any locked capacity is otherwise released. For `TransferFail` specifically, the source recovers `amount + proportional_portion` — only `fixed_msats` stays with the operator. For `InvoiceFail` and `OnchainFail`, the locked `amount` is released in full (those ops don't lock an operator fee upfront) and `fixed_msats` is debited from the deposit's balance.

Implementations MUST use saturating subtraction so that a deposit whose balance dipped below `fixed_msats` between lock and fail does not panic or underflow — in that edge case the operator collects only what the deposit can afford.

## Fee Accumulator

Every ledger carries a monotonically non-decreasing `fees_accumulated: u64` counter tracking the total msats of fee the operator has earned on that ledger. Contributions:

| Op | Amount added |
|---|---|
| `FeeCollect` | `amount` |
| `TransferComplete` | `pending.fee` (fixed + proportional; covers intra-ledger transfers AND inbound bridge receives — the bridge's `bridge_fee` rides on `TransferLock.fee` per §"Lightning Bridge Fees") |
| `TransferFail` | `source.transfer_fees.fixed_msats` |
| `InvoiceFulfill` (with quote) | `locked_amount - invoice_amount - actual_routing_fee_msats` (outbound bridge — operator's advertised margin plus any unused routing buffer; recorded by the operator and re-checked by replayers reading the LDK-reported routing fee from the operation) |
| `InvoiceFail` | `deposit.transfer_fees.fixed_msats` |
| `OnchainFail` | `deposit.transfer_fees.fixed_msats` |

`OnchainLock.fee_sats` is a **miner** fee and is NOT accumulated on success or failure. `OnchainFulfill` does not contribute today (no operator-fee model on the withdrawal-success path).

The legacy `InvoiceCredit` op (deterrence-mode receive — DEP-10 §"Offline receive") also doesn't contribute, since the operator's fee on that path is collected entirely outside the ledger via the spread between LN routing/margin and what they choose to credit. Operators offering this path SHOULD price it conservatively given the lack of cosigner-enforced fee transparency.

`fees_accumulated` is serde-defaulted so pre-accumulator ledgers load with 0, and it is the substrate a future payout operation will debit against when distributing quorum-member compensation (see DEP-05).

## Fee Negotiation

Fee schedules are negotiated at deposit opening (`DepositOpen`). The operator's advertisement (Kind 39100) publishes their minimum fees. The wallet proposes fees in the open request; the operator validates they meet the minimums.

Quorum members also set fee minimums at join time (see DEP-05). The operator cannot open deposits with fees below the strictest quorum member's minimums.

## Fee Changes

Fee parameters negotiated at deposit opening:

- **fee_change_after_blocks**: blocks after opening before any change is allowed
- **fee_change_notice_blocks**: blocks of notice before a change takes effect
- **fee_change_limit_bps**: maximum change per adjustment (basis points of current fee, e.g. 1000 = 10%)

### FeeChange (disc 22)

The operator announces new fees with an `effective_block`:

1. `current_block >= opened_at_block + fee_change_after_blocks` -- enough time since opening
2. `effective_block >= current_block + fee_change_notice_blocks` -- sufficient notice
3. Change in `annualized_bps` and `annualized_msats` must be within `fee_change_limit_bps` of current values

The change is stored as `pending_fee_change` on the deposit. When `FeeCollect` runs at or after `effective_block`, the new fees take effect.

A subsequent `FeeChange` replaces any pending change.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (FeeStructure, TransferFeeSchedule nested TLV, FeeChange/FeeCollect fields)
- [DEP-05](DEP-05.md): Quorum and collateral (fee limits negotiated by quorum members)
- [DEP-08](DEP-08.md): Deposits (fee schedule established at opening)
- [DEP-09](DEP-09.md): Transfers (transfer fee validation)
