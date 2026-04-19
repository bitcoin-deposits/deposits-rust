//! Tests for collateral deposits — removed after collateral model removal.
//! Collateral is now tracked at the UTXO level via collateral_amount on LedgerOpen/QuorumBegin.

#[test]
fn collateral_model_removed() {
    // CollateralLock, is_collateral on Deposit, and per-deposit collateral tracking
    // have been removed. Collateral is now a simple amount on the ledger state.
}
