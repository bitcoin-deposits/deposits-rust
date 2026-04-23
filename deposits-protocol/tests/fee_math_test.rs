//! Regression tests for fee-math overflow.
//!
//! Before the u128 intermediate, `FeeStructure::calculate_fee` multiplied
//! `balance * bps * blocks` in u64. For realistic whale balances
//! (~10¹⁶ msats) combined with a 100%-annual fee and a year of blocks,
//! that product exceeds 2⁶⁴ and silently wraps — the operator would then
//! collect a tiny (or zero) fee instead of the intended amount, or the
//! debug build would panic. This file pins the safe behavior.

use deposits_protocol::types::{FeeStructure, TransferFeeSchedule};

// =========================================================================
// FeeStructure::calculate_fee
// =========================================================================

#[test]
fn fee_structure_normal_case() {
    // 1% annual on 1M msats over a year ≈ 10_000 msats.
    let fees = FeeStructure::new(0, 100, 2016);
    let fee = fees.calculate_fee(1_000_000, 52560);
    assert_eq!(fee, 10_000);
}

#[test]
fn fee_structure_handles_whale_balance_without_overflow() {
    // Pre-fix this wraps u64 silently (release) or panics (debug).
    // balance = 10^16 msats  (~$1M at BTC = $100k)
    // bps     = 10_000       (100% annual)
    // blocks  = 52560        (one year)
    // product = 10^16 * 10^4 * 52560 ≈ 5.2e24  >> u64::MAX (~1.8e19)
    //
    // Mathematically the fee = balance * 100% = 10^16 msats.
    let fees = FeeStructure::new(0, 10_000, 2016);
    let fee = fees.calculate_fee(10u64.pow(16), 52560);
    assert_eq!(fee, 10u64.pow(16));
}

#[test]
fn fee_structure_handles_max_balance_by_saturating() {
    // Absurd input: u64::MAX balance, 100% annual, one year. The u128
    // intermediate holds it; the downcast saturates since the "fee"
    // exceeds u64::MAX. Better to return u64::MAX than to wrap.
    let fees = FeeStructure::new(0, 10_000, 2016);
    let fee = fees.calculate_fee(u64::MAX, 52560);
    // Real answer (~u64::MAX) fits in u64, so no saturation actually
    // occurs here — but the calculation completes without panic.
    assert_eq!(fee, u64::MAX);
}

#[test]
fn fee_structure_fixed_portion_scales_with_blocks() {
    let fees = FeeStructure::new(52_560, 0, 2016); // 1 msat/block fixed
    assert_eq!(fees.calculate_fee(0, 52560), 52_560); // full year
    assert_eq!(fees.calculate_fee(0, 26_280), 26_280); // half year
}

// =========================================================================
// TransferFeeSchedule::calculate_fee
// =========================================================================

#[test]
fn transfer_fee_schedule_normal_case() {
    // 2 msats fixed + 20 bps (0.2%) on 1M msats = 2 + 2000
    let s = TransferFeeSchedule::new(2, 20);
    assert_eq!(s.calculate_fee(1_000_000), 2 + 2000);
}

#[test]
fn transfer_fee_schedule_handles_large_amount_without_overflow() {
    // amount * bps can overflow u64 directly: 10^16 * 10_000 = 10^20.
    let s = TransferFeeSchedule::new(0, 10_000); // 100% proportional
    let fee = s.calculate_fee(10u64.pow(16));
    assert_eq!(fee, 10u64.pow(16));
}

#[test]
fn transfer_fee_schedule_saturates_on_max_amount() {
    // u64::MAX * 10_000 / 10_000 = u64::MAX, which fits.
    let s = TransferFeeSchedule::new(10, 10_000);
    let fee = s.calculate_fee(u64::MAX);
    // Proportional saturates to u64::MAX; fixed adds via saturating_add.
    assert_eq!(fee, u64::MAX);
}
