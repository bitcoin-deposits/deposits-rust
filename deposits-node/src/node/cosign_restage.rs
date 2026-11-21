// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! RE-STAGING a cosign draft that has fallen behind the cosigners' window.
//!
//! A cosigner refuses a `block_height` more than 6 blocks below its own tip (DEP-02 §Block height
//! and hash; [`COSIGN_MAX_BLOCK_SKEW`]). Every cosign retry used to resend the identical draft, so
//! one dated outside that window was refused the same way every time. (Regtest 1121-101522: cl's
//! cld848 drafted seq 5 of `fbe37fad` at 35890; this crate's ref6 at 35897 refused it three times,
//! "block_height 35890 is more than 6 blocks from our height 35897", and a post-expiry rotation
//! never formed. The same shape is in this crate: the QuorumBegin retry in the actor-outbox
//! drainer, and `sign_and_broadcast`, resend one draft.)
//!
//! Re-dating is allowed because the draft is not signed by us. The ledger actor operator-signs
//! only after the cosignatures are in (DEP-02 §Operator: "The operator signs after collecting the
//! required majority of co-signatures"), and only a signed update is written ahead (DEP-02
//! implementer note: a node "MUST NOT sign a different update at a (ledger, sequence) it has
//! already signed"). DEP-05 §Cosign Rounds names the case: cosignatures kept for the old
//! `cosign_data` "are dead" once the operator signs a different update at that sequence, and are
//! never attached to other bytes. [`super::write_ahead::check_restampable`] checks the premise
//! instead of assuming it.

use super::request_handlers::cosign::COSIGN_MAX_BLOCK_SKEW;
use deposits_core::types::{CosignEntry, SignedLedgerUpdate};
use std::future::Future;
use std::time::Duration;

/// Blocks of headroom kept under the cosigners' window.
pub const RESTAMP_MARGIN: u32 = 2;

/// A draft whose `block_height` is more than this many blocks below our tip is re-staged before
/// it is asked for again (window − margin = 4).
pub const RESTAMP_LAG: u32 = COSIGN_MAX_BLOCK_SKEW - RESTAMP_MARGIN;

/// How many times one commit re-stages its draft before it gives up.
pub const MAX_RESTAGES: usize = 3;

/// How a cosign round for one draft failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosignFailure {
    /// The draft must be re-staged at our tip: its height has fallen more than [`RESTAMP_LAG`]
    /// behind, or a cosigner refused it as too old and our tip has moved past it.
    Stale {
        draft_height: u32,
        current_height: u32,
        reason: String,
    },
    /// A cosigner refused the draft's height as too old (one attempt's outcome; the round loop
    /// decides whether that makes the draft [`CosignFailure::Stale`]).
    StaleRefused(String),
    /// Anything else (timeout, too few members): re-staging would not help.
    Failed(String),
}

impl std::fmt::Display for CosignFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CosignFailure::Stale { draft_height, current_height, reason } => write!(
                f,
                "cosign draft at block_height {draft_height} is stale against our tip {current_height}: {reason}"
            ),
            CosignFailure::StaleRefused(m) => write!(f, "cosign refused as stale: {m}"),
            CosignFailure::Failed(m) => write!(f, "{m}"),
        }
    }
}

/// Whether a draft at `draft_height` must be re-staged before it is asked for again.
pub fn draft_is_stale(current_height: u32, draft_height: u32, refused_stale: bool) -> bool {
    let lag = current_height.saturating_sub(draft_height);
    lag > RESTAMP_LAG || (refused_stale && lag > 0)
}

/// A cosigner's refusal of a `block_height` too far BELOW its tip. This crate's cosigner says
/// "block_height H is more than 6 blocks from our height T" for both directions, so the two
/// heights are read back and compared; cl-deposits says "block_height H is more than 6 below our
/// tip T".
pub fn is_stale_refusal(error: &str) -> bool {
    fn num_after(s: &str, key: &str) -> Option<u64> {
        let at = s.find(key)? + key.len();
        let digits: String = s[at..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        digits.parse().ok()
    }
    if !error.contains("block_height") {
        return false;
    }
    if error.contains("below our tip") {
        return true;
    }
    if error.contains("blocks from our height") {
        if let (Some(h), Some(t)) = (
            num_after(error, "block_height"),
            num_after(error, "our height"),
        ) {
            return h < t;
        }
    }
    false
}

/// The `block_height` a v2 `cosign_data` signs (DEP-02: seq8 || ledger_id32 || height4 || …).
pub fn cosign_data_height(cosign_data: &[u8]) -> Option<u32> {
    let b = cosign_data.get(40..44)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One draft's cosign round, attempt by attempt. Before every attempt, and after a stale-height
/// refusal, it asks whether the draft must be re-staged ([`CosignFailure::Stale`]) rather than
/// resent. A QuorumBegin whose attempt timed out is asked again, up to 4 attempts `retry_pause`
/// apart (a member may still be gap-filling the staged-quorum history; the retry the drainer
/// always had).
pub async fn drive_cosign_round<H, A, Fut>(
    update: &SignedLedgerUpdate,
    is_quorum_begin: bool,
    current_height: H,
    mut attempt: A,
    retry_pause: Duration,
) -> Result<Vec<CosignEntry>, CosignFailure>
where
    H: Fn() -> u32,
    A: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<CosignEntry>, CosignFailure>>,
{
    let draft = update.block_height;
    let mut attempts = 0usize;
    loop {
        let cur = current_height();
        if draft_is_stale(cur, draft, false) {
            return Err(CosignFailure::Stale {
                draft_height: draft,
                current_height: cur,
                reason: format!("more than {RESTAMP_LAG} blocks behind"),
            });
        }
        let result = attempt().await;
        attempts += 1;
        match result {
            Ok(entries) => return Ok(entries),
            Err(CosignFailure::StaleRefused(reason)) => {
                let cur = current_height();
                return Err(if draft_is_stale(cur, draft, true) {
                    CosignFailure::Stale {
                        draft_height: draft,
                        current_height: cur,
                        reason,
                    }
                } else {
                    // Our own view has not moved past the draft: a draft re-staged here would carry
                    // the same height and be refused the same way.
                    CosignFailure::Failed(format!(
                        "{reason} (our tip {cur} has not moved past the draft; not re-staging)"
                    ))
                });
            }
            Err(CosignFailure::Failed(m))
                if is_quorum_begin && m.contains("Cosign timeout") && attempts < 4 =>
            {
                tracing::warn!(
                    "QuorumBegin seq={} cosign round {} timed out; retrying in {:?} (members may be gap-filling)",
                    update.sequence_number,
                    attempts,
                    retry_pause
                );
                tokio::time::sleep(retry_pause).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_and_the_margin() {
        assert_eq!(RESTAMP_LAG, 4);
        assert!(!draft_is_stale(35894, 35890, false));
        assert!(draft_is_stale(35895, 35890, false));
        assert!(draft_is_stale(35897, 35890, false));
        assert!(
            !draft_is_stale(35890, 35890, true),
            "our tip has not moved: re-staging cannot help"
        );
        assert!(draft_is_stale(35891, 35890, true));
        assert!(
            !draft_is_stale(35880, 35890, false),
            "a draft above our tip is not stale"
        );
    }

    #[test]
    fn stale_refusals_are_recognised_by_direction() {
        // ref6's own words, regtest 1121-101522.
        assert!(is_stale_refusal(
            "block_height 35890 is more than 6 blocks from our height 35897"
        ));
        // The same message for a draft ABOVE the cosigner: not stale, re-staging would not help.
        assert!(!is_stale_refusal(
            "block_height 35904 is more than 6 blocks from our height 35897"
        ));
        // cl-deposits' cosigner.
        assert!(is_stale_refusal(
            "node: block_height 35890 is more than 6 below our tip 35897"
        ));
        assert!(!is_stale_refusal(
            "node: block_height 35904 is more than 6 above our tip 35897"
        ));
        assert!(!is_stale_refusal("Seq mismatch: expected 5, got 4"));
        assert!(!is_stale_refusal(
            "member policy: we do not cosign a rotation past quorum_expiry"
        ));
    }
}
