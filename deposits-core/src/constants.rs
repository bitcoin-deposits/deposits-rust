//! Bitcoin Deposits Protocol Constants
//!
//! This module defines important constants used throughout the Bitcoin Deposits
//! protocol, including minimum amounts, timeouts, and validation thresholds.

/// Minimum amount for a reserves output in satoshis
///
/// This value is set to 660 satoshis, which is:
/// - Equal to the total anchor output value in Lightning (2 × 330 sats)
/// - Above the P2WSH dust limit (330 sats) with safety margin
/// - Sufficient to cover the cost of spending the complex reserves script
///
/// The reserves script is more complex than anchor outputs:
/// - 2-of-2 multisig with timelock fallback
/// - Larger witness data requirements
/// - Higher fee requirements for spending
///
/// This minimum ensures reserves outputs remain economically spendable
/// under various fee conditions while preventing dust outputs.
pub const MIN_RESERVES_OUTPUT_SATS: u64 = 660;

/// Maximum amount for a single reserves output in satoshis (10 BTC)
///
/// This prevents accidentally creating extremely large reserves outputs
/// and provides a reasonable upper bound for validation.
pub const MAX_RESERVES_OUTPUT_SATS: u64 = 1_000_000_000; // 10 BTC

/// Default emergency timeout for reserves outputs in blocks
///
/// This is the number of blocks after which either party can
/// unilaterally spend the reserves output if the counterparty
/// becomes unresponsive. Set to 1 day (144 blocks).
pub const DEFAULT_EMERGENCY_TIMEOUT_BLOCKS: u32 = 144;

/// Minimum emergency timeout for reserves outputs in blocks
///
/// Prevents setting timeouts that are too short and could lead
/// to accidental unilateral spending during normal operations.
pub const MIN_EMERGENCY_TIMEOUT_BLOCKS: u32 = 144; // 1 day minimum

/// Maximum emergency timeout for reserves outputs in blocks
///
/// Prevents setting timeouts that are unreasonably long.
/// Set to 30 days (4320 blocks).
pub const MAX_EMERGENCY_TIMEOUT_BLOCKS: u32 = 4320; // 30 days

/// Minimum custodial balance ratio for reserves (100%)
///
/// Reserves must be at least 100% of the total custodial balance.
/// The 100%+100% collateral model means: 100% in channel reserves + 100% collateral in other channels.
pub const MIN_RESERVES_RATIO_PERCENT: u8 = 100;

/// Bitcoin dust limit for P2WSH outputs (satoshis)
///
/// This is the standard Bitcoin Core dust threshold for
/// Pay-to-Witness-Script-Hash outputs. Reserves outputs
/// must be above this threshold plus a safety margin.
pub const P2WSH_DUST_LIMIT_SATS: u64 = 330;

/// Bitcoin dust limit for P2WPKH outputs (satoshis)
///
/// Standard dust threshold for Pay-to-Witness-PubKey-Hash outputs.
pub const P2WPKH_DUST_LIMIT_SATS: u64 = 294;

/// Fee rate floor for reserves output calculations (sat/vbyte)
///
/// Minimum fee rate used when calculating whether reserves outputs
/// are economically spendable. Set to 3 sat/vbyte (Bitcoin Core default).
pub const FEE_RATE_FLOOR_SAT_PER_VBYTE: u64 = 3;

/// Estimated weight of reserves output spending (virtual bytes)
///
/// This includes:
/// - Input weight: ~40 vbytes (outpoint + sequence)
/// - Witness weight: ~80 vbytes (signatures + script)
/// - Output weight: ~43 vbytes (P2WSH scriptPubKey)
/// Total: ~163 vbytes
pub const RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES: u64 = 163;

/// Estimated cost to spend reserves output at minimum fee rate
///
/// Calculated as: RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES × FEE_RATE_FLOOR_SAT_PER_VBYTE
/// = 163 × 3 = 489 satoshis
///
/// The minimum reserves output amount (660 sats) provides a safety margin
/// above this spending cost.
pub const ESTIMATED_RESERVES_SPENDING_COST_SATS: u64 =
    RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES * FEE_RATE_FLOOR_SAT_PER_VBYTE;

/// Collateral reporting period in blocks
///
/// CONSTRAINT: collateraldecrease doesn't happen in the same reporting period as collateralincrease
///
/// This prevents gaming where an operator could increase collateral to satisfy a constraint
/// check and then immediately decrease it. A full "reporting period" must elapse between
/// a collateral increase and any subsequent decrease.
///
/// Set to 144 blocks (~1 day), matching the emergency timeout.
pub const COLLATERAL_REPORTING_PERIOD_BLOCKS: u32 = 144;

/// Bitcoin Deposits Protocol Version
///
/// Current wire protocol version for Bitcoin Deposits messages.
/// Used in handshake and message validation.
pub const DEPOSITS_PROTOCOL_VERSION: u16 = 1;

// ============================================================================
// Handler Operational Constants
// ============================================================================

/// Reserves headroom to reduce frequency of ReservesIncrease/Decrease messages.
/// This is a flat amount added to required reserves to provide buffer.
/// Set to 0 to see exact reserves management without padding.
pub const RESERVES_HEADROOM_SATS: u64 = 0;

/// Calculate required reserves with headroom buffer.
/// Returns the target reserves amount that includes safety margin.
pub fn calculate_reserves_with_headroom(base_required: u64) -> u64 {
    base_required.saturating_add(RESERVES_HEADROOM_SATS)
}

/// Collateral headroom to reduce frequency of CollateralIncrease/Decrease messages.
/// This is a flat amount added to required collateral as a buffer.
/// Prevents constant adjustments when deposit balances fluctuate.
pub const COLLATERAL_HEADROOM_SATS: u64 = 1000; // 1000 sat buffer

/// Calculate required collateral with headroom buffer.
/// Returns the target collateral amount that includes safety margin.
pub fn calculate_collateral_with_headroom(base_required: u64) -> u64 {
    base_required.saturating_add(COLLATERAL_HEADROOM_SATS)
}

/// Maximum age (in seconds) for pending ACKs before they're considered stale
pub const STALE_ACK_THRESHOLD_SECS: u64 = 30;

/// Maximum age (in seconds) for pending broadcasts before retry
pub const STALE_BROADCAST_THRESHOLD_SECS: u64 = 5;

/// Delay (in seconds) before lazy sync commits uncommitted ACKed updates.
/// This allows rapid operations to coalesce into a single commitment.
/// After this period of quiet (no new operations), pending updates are committed.
pub const LAZY_SYNC_DELAY_SECS: u64 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimum_reserves_above_dust_limit() {
        assert!(MIN_RESERVES_OUTPUT_SATS > P2WSH_DUST_LIMIT_SATS);
        assert!(MIN_RESERVES_OUTPUT_SATS >= ESTIMATED_RESERVES_SPENDING_COST_SATS);
    }

    #[test]
    fn test_timeout_bounds() {
        assert!(MIN_EMERGENCY_TIMEOUT_BLOCKS <= DEFAULT_EMERGENCY_TIMEOUT_BLOCKS);
        assert!(DEFAULT_EMERGENCY_TIMEOUT_BLOCKS <= MAX_EMERGENCY_TIMEOUT_BLOCKS);
    }

    #[test]
    fn test_amount_bounds() {
        assert!(MIN_RESERVES_OUTPUT_SATS < MAX_RESERVES_OUTPUT_SATS);
        assert!(MIN_RESERVES_OUTPUT_SATS >= ESTIMATED_RESERVES_SPENDING_COST_SATS);
    }

    #[test]
    fn test_reserves_ratio() {
        assert!(MIN_RESERVES_RATIO_PERCENT >= 100);
        assert!(MIN_RESERVES_RATIO_PERCENT <= 200); // Reasonable upper bound
    }
}
