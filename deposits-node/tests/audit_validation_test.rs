//! Sanity/coverage tests for the node-level audit validations.
//!
//! These replicate the validation logic from `Node` methods
//! (`check_collateral_obligation_limit`, `max_transfer_timeout_blocks`,
//! `max_descriptor_bytes`) as pure functions so we can test them without
//! instantiating a full `Node`.

// ---------------------------------------------------------------------------
// Replicated validation helpers
// ---------------------------------------------------------------------------

/// Three-term obligation limit check (mirrors `Node::check_collateral_obligation_limit`).
///
/// Returns `None` when the obligation is within all limits, or `Some(reason)` on rejection.
fn check_obligation_limit(
    reserves_amount: u64,
    total_collateral: u64,
    min_member_collateral: Option<u64>,
    current_obligations: u64,
    additional_msats: u64,
) -> Option<String> {
    let new_total = current_obligations.saturating_add(additional_msats);

    // Reserves limit
    if reserves_amount > 0 && new_total > reserves_amount {
        return Some(format!(
            "Would exceed reserves: {} + {} = {} > {}",
            current_obligations, additional_msats, new_total, reserves_amount
        ));
    }

    // Total collateral limit
    if total_collateral > 0 && new_total > total_collateral {
        return Some(format!(
            "Would exceed total_collateral: {} + {} = {} > {}",
            current_obligations, additional_msats, new_total, total_collateral
        ));
    }

    // 2x minimum member collateral limit
    if let Some(min_c) = min_member_collateral {
        let limit = min_c.saturating_mul(2);
        if new_total > limit {
            return Some(format!(
                "Would exceed 2x collateral: {} + {} = {} > {}",
                current_obligations, additional_msats, new_total, limit
            ));
        }
    }

    None
}

/// Transfer timeout validation (mirrors the check in `process_transfer_lock_request`).
///
/// `max_timeout` is the strictest (minimum) `max_transfer_timeout_blocks` across all
/// quorum members, defaulting to 1008 when no member sets it.
fn check_transfer_timeout(
    current_block: u32,
    timeout_height: u32,
    max_timeout: u32,
) -> Option<String> {
    if current_block > 0 && timeout_height > current_block.saturating_add(max_timeout) {
        return Some(format!(
            "timeout_height {} exceeds max: current_block {} + max_timeout {} = {}",
            timeout_height,
            current_block,
            max_timeout,
            current_block.saturating_add(max_timeout),
        ));
    }
    None
}

/// Descriptor size validation (mirrors the check in `process_make_offer_request`).
///
/// `max_bytes` is the strictest (minimum) `max_descriptor_bytes` across all quorum members.
fn check_descriptor_size(descriptor: &str, max_bytes: Option<u32>) -> Option<String> {
    if let Some(limit) = max_bytes {
        if descriptor.len() as u32 > limit {
            return Some(format!(
                "Descriptor size {} bytes exceeds quorum limit of {} bytes",
                descriptor.len(),
                limit,
            ));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Three-term obligation limit tests ----

    #[test]
    fn obligation_limit_rejects_when_total_collateral_is_binding() {
        // total_collateral = 500_000 is the tightest constraint
        let result = check_obligation_limit(
            1_000_000, // reserves
            500_000,   // total_collateral (binding)
            Some(400_000), // min_member_collateral -> 2x = 800_000
            400_000,   // current obligations
            200_000,   // additional (total = 600_000 > 500_000)
        );
        assert!(result.is_some(), "should reject: exceeds total_collateral");
        assert!(
            result.as_ref().unwrap().contains("total_collateral"),
            "reason should mention total_collateral, got: {}",
            result.unwrap()
        );
    }

    #[test]
    fn obligation_limit_rejects_when_2x_collateral_is_binding() {
        // 2x min_member_collateral = 600_000 is the tightest constraint
        let result = check_obligation_limit(
            1_000_000, // reserves
            900_000,   // total_collateral
            Some(300_000), // min_member_collateral -> 2x = 600_000 (binding)
            500_000,   // current obligations
            200_000,   // additional (total = 700_000 > 600_000)
        );
        assert!(result.is_some(), "should reject: exceeds 2x collateral");
        assert!(
            result.as_ref().unwrap().contains("2x collateral"),
            "reason should mention 2x collateral, got: {}",
            result.unwrap()
        );
    }

    #[test]
    fn obligation_limit_rejects_when_reserves_is_binding() {
        // reserves = 400_000 is the tightest constraint
        let result = check_obligation_limit(
            400_000,   // reserves (binding)
            900_000,   // total_collateral
            Some(400_000), // min_member_collateral -> 2x = 800_000
            300_000,   // current obligations
            200_000,   // additional (total = 500_000 > 400_000)
        );
        assert!(result.is_some(), "should reject: exceeds reserves");
        assert!(
            result.as_ref().unwrap().contains("reserves"),
            "reason should mention reserves, got: {}",
            result.unwrap()
        );
    }

    #[test]
    fn obligation_limit_accepts_when_all_limits_satisfied() {
        // total = 400_000, all limits >= 800_000
        let result = check_obligation_limit(
            1_000_000, // reserves
            900_000,   // total_collateral
            Some(400_000), // min_member_collateral -> 2x = 800_000
            300_000,   // current obligations
            100_000,   // additional (total = 400_000, under all limits)
        );
        assert!(result.is_none(), "should accept: under all limits");
    }

    // ---- Transfer timeout tests ----

    #[test]
    fn transfer_timeout_rejects_when_exceeds_max() {
        let current_block = 800_000u32;
        let max_timeout = 1008u32;
        let timeout_height = current_block + 1009;

        let result = check_transfer_timeout(current_block, timeout_height, max_timeout);
        assert!(result.is_some(), "should reject: 1009 > max 1008");
    }

    #[test]
    fn transfer_timeout_accepts_at_exact_max() {
        let current_block = 800_000u32;
        let max_timeout = 1008u32;
        let timeout_height = current_block + 1008;

        let result = check_transfer_timeout(current_block, timeout_height, max_timeout);
        assert!(result.is_none(), "should accept: exactly at max");
    }

    #[test]
    fn transfer_timeout_accepts_well_under_max() {
        let current_block = 800_000u32;
        let max_timeout = 1008u32;
        let timeout_height = current_block + 500;

        let result = check_transfer_timeout(current_block, timeout_height, max_timeout);
        assert!(result.is_none(), "should accept: well under max");
    }

    // ---- Descriptor size tests ----

    #[test]
    fn descriptor_size_accepts_under_limit() {
        // "pk(02<64 hex chars>)" = 3 + 2 + 64 + 1 = 70 bytes
        let descriptor = format!("pk(02{})", "ab".repeat(32));
        assert_eq!(descriptor.len(), 70);

        let result = check_descriptor_size(&descriptor, Some(100));
        assert!(result.is_none(), "should accept: 69 < 100");
    }

    #[test]
    fn descriptor_size_rejects_over_limit() {
        let descriptor = "x".repeat(101);

        let result = check_descriptor_size(&descriptor, Some(100));
        assert!(result.is_some(), "should reject: 101 > 100");
        assert!(
            result.as_ref().unwrap().contains("101"),
            "message should include actual size"
        );
    }

    #[test]
    fn descriptor_size_accepts_when_no_limit() {
        let descriptor = "x".repeat(10_000);

        let result = check_descriptor_size(&descriptor, None);
        assert!(result.is_none(), "should accept: no limit set");
    }
}
