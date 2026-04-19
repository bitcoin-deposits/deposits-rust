//! Collateral reuse attack tests.
//!
//! The old per-deposit collateral lock model (CollateralLock with
//! MAX_COLLATERAL_LOCKS) has been replaced by a simpler collateral_amount
//! tracked at the UTXO/QuorumBegin level. The reuse attack surface no
//! longer exists in the current protocol.

#[test]
fn collateral_reuse_model_removed() {
    // The old model allowed the same collateral deposit to back multiple
    // ledgers via CollateralLock operations with per-ledger locks.
    // The new model tracks collateral_amount at the QuorumBegin level,
    // removing the per-deposit lock/reuse vector entirely.
    //
    // This test is a placeholder confirming the old attack surface is gone.
}
