# DEP-10: Payment Channels

## Abstract

This document specifies how deposits receive and send funds through on-chain transactions and lightning payments. Operators create funding offers and invoices on behalf of deposits; these are co-signed by a quorum member and retained by the wallet as evidence.

## On-chain Funding

### Offers

An operator creates a funding offer for a deposit: a bitcoin address where funds can be sent, with a deadline block and amount range. After quorum establishment, offers are co-signed by a quorum member using BIP-340 tagged hashing:

    tag = SHA256("deposits/offer_cosign")
    data = ledger_id || offer_id || operator_x_only || len(address) || address || deadline_block_le32
    digest = SHA256(tag || tag || data || member_ledger_hash)

The wallet retains the offer, cosignature, and co-signer pubkey as evidence. If the operator does not credit the deposit after sufficient confirmations, this evidence is used to construct a fraud proof (see DEP-06).

### Credit (disc 35)

When the operator confirms a deposit to the funding address, they append `OnchainCredit` with the txid, vout, amount, and funding address.

### Withdrawal

A wallet requests withdrawal by providing a destination address, amount, and witness satisfying the deposit's descriptor. The operator:

1. Appends `OnchainLock` with withdrawal_id, amount, destination, and fee
2. Constructs and broadcasts the bitcoin transaction
3. On confirmation: appends `OnchainFulfill` with the txid
4. On failure: appends `OnchainFail` (releases the locked `amount + miner_fee` and charges the deposit's fixed transfer fee — see DEP-07 §"Fee on Failure")

## Lightning

### Invoices

An operator creates a BOLT11 invoice through their lightning sidecar on behalf of a deposit. After quorum establishment, invoices are co-signed by a quorum member:

    tag = SHA256("deposits/invoice_cosign")
    data = ledger_id || payment_hash || deposit_id || amount_msat_le64
    digest = SHA256(tag || tag || data || member_ledger_hash)

The wallet retains the invoice, cosignature, and co-signer pubkey as evidence.

### Credit (disc 30)

When the operator's lightning node receives payment (obtains the preimage), they append `InvoiceCredit` with the payment_hash, deposit_id, amount, invoice_id, and sequence_number.

### Payment

A wallet requests payment of a BOLT11 invoice by providing the invoice, deposit pubkey, amount, and a witness. The operator:

1. Appends `InvoiceLock` with payment_hash, amount, payment_id, and deposit witness
2. Routes the payment through their lightning node
3. On success: appends `InvoiceFulfill` with the preimage
4. On failure: appends `InvoiceFail` (releases the locked `amount` and charges the deposit's fixed transfer fee — see DEP-07 §"Fee on Failure")

### Self-Pay

When the payer and payee are deposits on the same operator, the operator may settle internally without routing through lightning. The operator credits and debits the respective deposits directly, avoiding routing fees and failure modes.

## Evidence Retention

Wallets should retain co-signed offers and invoices until the corresponding credit appears on the ledger or the deadline expires. Without this evidence, fraud cannot be proven:

- **On-chain**: if the offer's deadline block passes with sufficient confirmations but no credit, the wallet constructs a fraud proof autonomously (see DEP-06)
- **Lightning**: the wallet retains the co-signed invoice. If a payer provides the preimage proving payment, and no credit appears, the wallet constructs a fraud proof with the preimage as evidence

Without evidence retention, the wallet cannot prove fraud.

## Lightning Trust Boundary

Lightning invoice fraud is not autonomously provable. The operator's lightning node is a trust boundary that the protocol cannot fully bridge — the operator knows whether the preimage was received, but the wallet does not. The on-chain fraud proof system provides autonomous provability; lightning relies on deterrence: any payer might provide the preimage to the wallet, and if they do, the operator faces dispute, reserves seizure, and collateral confiscation. The upside of stealing a single payment is bounded; the downside is existential.

Wallets should:

- limit outstanding uncredited invoices per operator
- prefer on-chain funding for amounts exceeding their risk tolerance
- for high-value invoices, arrange for the payer to share proof-of-payment out-of-band

## Obligation Limits

Creating offers and invoices increases the ledger's potential obligations. The operator must not create offers or invoices that would push total obligations above the least of:

1. The reserves amount (from LedgerOpen/QuorumBegin)
2. The collateral amount declared on LedgerOpen/QuorumBegin (`collateral_amount`)

See DEP-05 for details.

## Related DEPs

- [DEP-02](DEP-02.md): Wire format (Invoice/Onchain operation fields)
- [DEP-05](DEP-05.md): Quorum and collateral (obligation limits, cosigning requirements)
- [DEP-06](DEP-06.md): Fraud proofs (uncredited on-chain payment, uncredited lightning payment)
- [DEP-08](DEP-08.md): Deposits (descriptor witnesses, receive_requires_sig)
