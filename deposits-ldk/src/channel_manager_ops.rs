// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Channel Manager Operations - LDK Adapter
//!
//! This module re-exports the `ChannelManagerOps` trait and related types from deposits-core,
//! and provides conversion functions between deposits-core types and LDK types.

// Re-export the trait and types from deposits-core
pub use deposits_core::{
    ChannelManagerOps, ChannelDetails, NullChannelManager,
    CommitmentExtraOutput, ChannelId,
};

use lightning::ln::chan_utils::CommitmentExtraOutput as LdkCommitmentExtraOutput;
use lightning::ln::types::ChannelId as LdkChannelId;

// ============================================================================
// Conversion Functions: deposits-core -> LDK
// ============================================================================

/// Convert a deposits-core CommitmentExtraOutput to LDK's CommitmentExtraOutput
pub fn to_ldk_commitment_extra_output(output: &CommitmentExtraOutput) -> LdkCommitmentExtraOutput {
    LdkCommitmentExtraOutput {
        amount_satoshis: output.amount_satoshis,
        script_pubkey: output.script_pubkey.clone(),
    }
}

/// Convert a Vec of deposits-core CommitmentExtraOutput to LDK's CommitmentExtraOutput
pub fn to_ldk_commitment_extra_outputs(outputs: &[CommitmentExtraOutput]) -> Vec<LdkCommitmentExtraOutput> {
    outputs.iter().map(to_ldk_commitment_extra_output).collect()
}

/// Convert a deposits-core ChannelId to LDK's ChannelId
pub fn to_ldk_channel_id(id: &ChannelId) -> LdkChannelId {
    LdkChannelId::from_bytes(*id.as_bytes())
}

// ============================================================================
// Conversion Functions: LDK -> deposits-core
// ============================================================================

/// Convert LDK's CommitmentExtraOutput to deposits-core CommitmentExtraOutput
pub fn from_ldk_commitment_extra_output(output: &LdkCommitmentExtraOutput) -> CommitmentExtraOutput {
    CommitmentExtraOutput {
        amount_satoshis: output.amount_satoshis,
        script_pubkey: output.script_pubkey.clone(),
    }
}

/// Convert a Vec of LDK's CommitmentExtraOutput to deposits-core CommitmentExtraOutput
pub fn from_ldk_commitment_extra_outputs(outputs: &[LdkCommitmentExtraOutput]) -> Vec<CommitmentExtraOutput> {
    outputs.iter().map(from_ldk_commitment_extra_output).collect()
}

/// Convert LDK's ChannelId to deposits-core ChannelId
pub fn from_ldk_channel_id(id: &LdkChannelId) -> ChannelId {
    ChannelId::new(id.0)
}

// Note: We cannot implement From trait here due to Rust's orphan rules.
// The conversion functions above should be used instead:
// - to_ldk_commitment_extra_output / from_ldk_commitment_extra_output
// - to_ldk_channel_id / from_ldk_channel_id
