//! Bitcoin Deposits Protocol Constants

/// Minimum amount for a reserves output in satoshis
pub const MIN_RESERVES_OUTPUT_SATS: u64 = 660;

/// Maximum amount for a single reserves output in satoshis (10 BTC)
pub const MAX_RESERVES_OUTPUT_SATS: u64 = 1_000_000_000;

/// Default emergency timeout for reserves outputs in blocks (~1 day)
pub const DEFAULT_EMERGENCY_TIMEOUT_BLOCKS: u32 = 144;

/// Minimum emergency timeout for reserves outputs in blocks
pub const MIN_EMERGENCY_TIMEOUT_BLOCKS: u32 = 144;

/// Maximum emergency timeout for reserves outputs in blocks (~30 days)
pub const MAX_EMERGENCY_TIMEOUT_BLOCKS: u32 = 4320;

/// Minimum custodial balance ratio for reserves (100%)
pub const MIN_RESERVES_RATIO_PERCENT: u8 = 100;

/// Bitcoin dust limit for P2WSH outputs (satoshis)
pub const P2WSH_DUST_LIMIT_SATS: u64 = 330;

/// Bitcoin dust limit for P2WPKH outputs (satoshis)
pub const P2WPKH_DUST_LIMIT_SATS: u64 = 294;

/// Fee rate floor for reserves output calculations (sat/vbyte)
pub const FEE_RATE_FLOOR_SAT_PER_VBYTE: u64 = 3;

/// Estimated weight of reserves output spending (virtual bytes)
pub const RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES: u64 = 163;

/// Estimated cost to spend reserves output at minimum fee rate
pub const ESTIMATED_RESERVES_SPENDING_COST_SATS: u64 =
    RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES * FEE_RATE_FLOOR_SAT_PER_VBYTE;

/// Collateral reporting period in blocks (~1 day)
pub const COLLATERAL_REPORTING_PERIOD_BLOCKS: u32 = 144;

/// Bitcoin Deposits Protocol Version
pub const DEPOSITS_PROTOCOL_VERSION: u16 = 1;

/// Maximum number of disputants in a single custody dispute lottery.
///
/// Past this size the on-chain construction stops being the right tool —
/// witness sizes grow unwieldy, recovery quorums become impractical, and
/// bond ratios approach 1.0× of disputed value (see CUSTODY_LOTTERY.md
/// "Why N = 15 Is the Cap"). Builders refuse to construct lottery
/// scripts for N > MAX_DISPUTANTS; recovery_confiscate refuses to
/// proceed if it observes more DisputeArmed events than this cap.
pub const MAX_DISPUTANTS: usize = 15;

/// CSV block delay for the very-final timeout-recovery leaf.
///
/// After this many blocks (~8 weeks), a single quorum member can spend
/// the lottery output back to a fallback custodian. This is the escape
/// hatch for retry-depth exhaustion: if the dispute has cycled through
/// `⌊N/2⌋` failed lotteries (cascading defection-and-re-dispute), the
/// timeout-recovery leaf becomes spendable as a last resort. The long
/// CSV ensures it cannot be used to short-circuit a healthy dispute.
pub const TIMEOUT_RECOVERY_CSV_BLOCKS: u32 = 8064;
