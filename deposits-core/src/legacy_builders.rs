// Copyright bitcoin-deposits contributors.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Frozen historical `TapscriptReservesBuilder` versions.
//!
//! Each submodule reproduces the on-chain script construction at a specific
//! point in the file's git history. They exist purely so the migration helper
//! in `deposits-tools/src/bin/sweep-all.rs` (`migrate-snapshot` subcommand)
//! can identify which version produced a given on-chain scriptPubKey and
//! materialise its tier leaves + control blocks back into the operator's
//! `taproot_reserves.json` snapshot.
//!
//! Why "frozen": once a version is in here, its behaviour MUST NEVER change.
//! Otherwise we'd silently lose access to vault outputs we previously
//! identified by their script bytes. Pinned-fixture tests assert this.

use crate::tapscript_reserves::VoterSet;
use bitcoin::{
    hashes::Hash,
    opcodes::all::*,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    script::Builder,
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Network, ScriptBuf,
};

/// Builder behaviour as of commit `b3d38acc` (2026-04-17, "Fix NUMS
/// vulnerability"). The relevant on-chain shape was current from that
/// commit through 2026-05-06 (i.e. up to and excluding `c075cc0f`,
/// which anchored tier CLTV to `quorum_expiry` and demoted the operator).
///
/// Key differences from later versions:
///   - Tier-0 leaf has NO CLTV (timelock_blocks = 0)
///   - Tier-1 leaf CLTV is the *relative* offset 1008, not anchored to
///     quorum_expiry (which would land it at quorum_expiry + 1008 in
///     later code)
///   - Default config has FOUR tiers (majority, minority, operator-only,
///     emergency)
///   - Internal key is the BIP-341 NUMS point: `lift_x(SHA256("TapTweak"))`
///     — same as current code
///   - Tier depth assignment: linear (i+1) for non-2-tier trees, both
///     at depth 1 for 2-tier trees. Differs from later balanced-tree
///     placement.
///   - Operator is NOT included in tier-0/1/2 keysets (NoTieBreaker /
///     RequiresTieBreaker bool drives this)
///   - Default ruleset is implicit (the field didn't exist yet);
///     `default_for_voter_count(n)` is the only configuration
pub mod v_2026_04_17 {
    use super::*;

    /// BIP-341 NUMS: `lift_x(SHA256("TapTweak"))`. Same bytes as current code.
    pub const NUMS_INTERNAL_KEY: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
        0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
        0xce, 0x80, 0x3a, 0xc0,
    ];

    /// A single tier in this version's config. Fields and meaning are
    /// frozen to the b3d38acc-era shape.
    #[derive(Clone, Debug)]
    pub struct ThresholdTier {
        pub threshold: usize,
        pub requires_tie_breaker: bool,
        pub timelock_blocks: u32,
    }

    /// The default 4-tier config from `b3d38acc` for `n >= 3` quorum
    /// members (i.e. excluding operator). Mirrors the inline construction
    /// in `ThresholdConfig::default_for_voter_count(n)` at that commit.
    /// `n` is the QUORUM_MEMBER count (not including the operator/
    /// tie-breaker).
    pub fn default_tiers(n: usize) -> Vec<ThresholdTier> {
        if n <= 2 {
            return vec![
                ThresholdTier {
                    threshold: 2,
                    requires_tie_breaker: false,
                    timelock_blocks: 0,
                },
                ThresholdTier {
                    threshold: 1,
                    requires_tie_breaker: true,
                    timelock_blocks: 2016,
                },
                ThresholdTier {
                    threshold: 1,
                    requires_tie_breaker: false,
                    timelock_blocks: 4032,
                },
            ];
        }
        let majority = (n / 2) + 1;
        let minority = (n / 3).max(1);
        vec![
            ThresholdTier {
                threshold: majority,
                requires_tie_breaker: false,
                timelock_blocks: 0,
            },
            ThresholdTier {
                threshold: minority,
                requires_tie_breaker: false,
                timelock_blocks: 1008,
            },
            ThresholdTier {
                threshold: 1,
                requires_tie_breaker: true,
                timelock_blocks: 2016,
            },
            ThresholdTier {
                threshold: 1,
                requires_tie_breaker: false,
                timelock_blocks: 4032,
            },
        ]
    }

    /// `<ledger_hash> OP_DROP OP_0` — provably unspendable but commits
    /// the ledger hash to the Taproot tree.
    fn build_commitment_leaf(ledger_hash: [u8; 32]) -> ScriptBuf {
        Builder::new()
            .push_slice(ledger_hash)
            .push_opcode(OP_DROP)
            .push_opcode(OP_PUSHBYTES_0)
            .into_script()
    }

    /// Build a tier leaf in the b3d38acc shape. Includes a relative-blocks
    /// `<n> OP_CLTV OP_DROP` prefix when `timelock_blocks > 0`.
    ///
    /// Note: bitcoin's OP_CLTV is BIP-65 *absolute* — at b3d38acc the
    /// argument was treated as a block height, not a relative offset.
    /// The resulting scripts read literally: "must reach block N before
    /// spending via this tier". For mainnet outputs created late-2026,
    /// `timelock_blocks=1008` is well below the current chain tip and
    /// thus already-satisfied.
    pub fn build_threshold_leaf(tier: &ThresholdTier, voter_set: &VoterSet) -> ScriptBuf {
        let mut builder = Builder::new();
        if tier.timelock_blocks > 0 {
            builder = builder
                .push_int(tier.timelock_blocks as i64)
                .push_opcode(OP_CLTV)
                .push_opcode(OP_DROP);
        }
        let sorted_keys = voter_set.sorted_x_only_pubkeys();
        if tier.threshold == 1 {
            if tier.requires_tie_breaker {
                let tb = voter_set
                    .tie_breaker()
                    .expect("tie-breaker required but not in voter set");
                builder = builder.push_x_only_key(&tb.x_only()).push_opcode(OP_CHECKSIG);
            } else {
                builder = builder
                    .push_x_only_key(&sorted_keys[0])
                    .push_opcode(OP_CHECKSIG);
            }
        } else {
            let keys_to_use = if tier.requires_tie_breaker {
                let tb = voter_set
                    .tie_breaker()
                    .expect("tie-breaker required but not in voter set");
                let mut keys = vec![tb.x_only()];
                for voter in voter_set.primary_voters() {
                    keys.push(voter.x_only());
                }
                keys.sort_by_key(|a| a.serialize());
                keys
            } else {
                sorted_keys.clone()
            };
            assert!(
                keys_to_use.len() >= tier.threshold,
                "Not enough keys for threshold"
            );
            builder = builder
                .push_x_only_key(&keys_to_use[0])
                .push_opcode(OP_CHECKSIG);
            for key in keys_to_use.iter().skip(1) {
                builder = builder.push_x_only_key(key).push_opcode(OP_CHECKSIGADD);
            }
            builder = builder
                .push_int(tier.threshold as i64)
                .push_opcode(OP_GREATERTHANOREQUAL);
        }
        builder.into_script()
    }

    /// Full build: spending tiers + commitment leaf in the b3d38acc tree
    /// layout. Returns (Address, TaprootSpendInfo, per-tier leaf scripts in
    /// order — so callers can derive control blocks via
    /// `spend_info.control_block((leaf_script, LeafVersion::TapScript))`).
    pub fn build(
        voter_set: &VoterSet,
        tiers: &[ThresholdTier],
        network: Network,
        ledger_hash: [u8; 32],
    ) -> Result<(Address, TaprootSpendInfo, Vec<ScriptBuf>), String> {
        let secp = Secp256k1::new();
        let leaves: Vec<ScriptBuf> = tiers
            .iter()
            .map(|t| build_threshold_leaf(t, voter_set))
            .collect();
        if leaves.is_empty() {
            return Err("no tiers".to_string());
        }
        let commitment_leaf = build_commitment_leaf(ledger_hash);
        let internal_key = XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY)
            .map_err(|e| format!("NUMS internal key invalid: {:?}", e))?;
        let mut builder = TaprootBuilder::new();
        let num_spending_leaves = leaves.len();
        let total_leaves = num_spending_leaves + 1;
        for (i, script) in leaves.iter().enumerate() {
            let depth = if total_leaves == 2 { 1 } else { (i + 1) as u8 };
            builder = builder
                .add_leaf(depth, script.clone())
                .map_err(|e| format!("add tier {} leaf: {:?}", i, e))?;
        }
        let commitment_depth = if total_leaves == 2 {
            1
        } else {
            num_spending_leaves as u8
        };
        builder = builder
            .add_leaf(commitment_depth, commitment_leaf)
            .map_err(|e| format!("add commitment leaf: {:?}", e))?;
        let spend_info = builder
            .finalize(&secp, internal_key)
            .map_err(|e| format!("finalize taproot: {:?}", e))?;
        let address = Address::p2tr(&secp, internal_key, spend_info.merkle_root(), network);
        Ok((address, spend_info, leaves))
    }

    /// Convenience: control block for tier i (0-indexed).
    pub fn control_block_for_tier(
        spend_info: &TaprootSpendInfo,
        leaves: &[ScriptBuf],
        tier_index: usize,
    ) -> Option<bitcoin::taproot::ControlBlock> {
        let leaf = leaves.get(tier_index)?.clone();
        spend_info.control_block(&(leaf, LeafVersion::TapScript))
    }
}

/// Pre-b3d38acc builder behaviour: same tier layout as v_2026_04_17 but with
/// the OPERATOR's x-only pubkey as the Taproot internal key (the NUMS
/// vulnerability that `b3d38acc` fixed). If the daemon was running this
/// version at tx-construction time but b3d38acc-era code at metadata-write
/// time, that explains the JSON-vs-on-chain address drift.
pub mod v_pre_2026_04_17 {
    use super::*;

    pub fn build_with_operator_internal_key(
        voter_set: &VoterSet,
        tiers: &[v_2026_04_17::ThresholdTier],
        network: Network,
        ledger_hash: [u8; 32],
    ) -> Result<(Address, TaprootSpendInfo, Vec<ScriptBuf>), String> {
        let secp = Secp256k1::new();
        let leaves: Vec<ScriptBuf> = tiers
            .iter()
            .map(|t| v_2026_04_17::build_threshold_leaf(t, voter_set))
            .collect();
        if leaves.is_empty() {
            return Err("no tiers".to_string());
        }
        // Commitment leaf (inline, since v_2026_04_17::build_commitment_leaf is private).
        let commitment_leaf = Builder::new()
            .push_slice(ledger_hash)
            .push_opcode(OP_DROP)
            .push_opcode(OP_PUSHBYTES_0)
            .into_script();
        // Pre-fix internal key: tie-breaker (operator) x-only pubkey.
        let internal_key = voter_set
            .tie_breaker()
            .map(|v| v.x_only())
            .unwrap_or_else(|| voter_set.sorted_x_only_pubkeys()[0]);
        let mut builder = TaprootBuilder::new();
        let num_spending_leaves = leaves.len();
        let total_leaves = num_spending_leaves + 1;
        for (i, script) in leaves.iter().enumerate() {
            let depth = if total_leaves == 2 { 1 } else { (i + 1) as u8 };
            builder = builder
                .add_leaf(depth, script.clone())
                .map_err(|e| format!("add leaf {}: {:?}", i, e))?;
        }
        let commitment_depth = if total_leaves == 2 {
            1
        } else {
            num_spending_leaves as u8
        };
        builder = builder
            .add_leaf(commitment_depth, commitment_leaf)
            .map_err(|e| format!("add commitment leaf: {:?}", e))?;
        let spend_info = builder
            .finalize(&secp, internal_key)
            .map_err(|e| format!("finalize: {:?}", e))?;
        let address = Address::p2tr(&secp, internal_key, spend_info.merkle_root(), network);
        Ok((address, spend_info, leaves))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::PublicKey;
    use std::str::FromStr;

    /// Pinned fixture: the b3d38acc builder run against a known input set
    /// produces a specific scriptPubKey. ANY change to v_2026_04_17 that
    /// moves this hash is a bug — the historical version must stay frozen.
    /// Inputs taken from the snowden snapshot in the 2026-04 deployment:
    /// operator=02b017e1…, three quorum members, expiry=948352, ledger_hash
    /// 7fc25d52…, network=mainnet.
    #[test]
    fn v_2026_04_17_pinned_snowden_fixture() {
        let operator = PublicKey::from_str(
            "02b017e1288da93b90d9ca139d9fdb3310c4ba65d451803875471c2b6d57a4520f",
        )
        .unwrap();
        let members: Vec<PublicKey> = [
            "0206c4db20bda97893e99f843b0acf6bd61624baa09c72536841a974230f1e4995",
            "036cba47c801a59c0792fd4a214ec6b37eb6f206a5be68a9d87064d5f89fd8a777",
            "02208787bb5c2d2428d4055d353d4656642be7ef6550a3240b2063b4c073d8ae1a",
        ]
        .into_iter()
        .map(|s| PublicKey::from_str(s).unwrap())
        .collect();
        let voter_set = VoterSet::new(operator, members.clone());
        let ledger_hash: [u8; 32] = hex::decode(
            "7fc25d5245e7003be4f1c4138fbf608bf0ecbb4eca7be4954529d42168473b76",
        )
        .unwrap()
        .try_into()
        .unwrap();
        // The daemon at b3d38acc called `default_for_voter_count(quorum_members.len() + 1)` —
        // including the operator in the count. So `n = members + 1`.
        let tiers = v_2026_04_17::default_tiers(members.len() + 1);

        let (address, _info, _leaves) =
            v_2026_04_17::build(&voter_set, &tiers, Network::Bitcoin, ledger_hash).expect("build");

        // This is the address the daemon WROTE to snowden's
        // `taproot_reserves.json` `.address` field — i.e. what the
        // metadata-writing path computed from these inputs. The
        // on-chain UTXO at the recorded outpoint is actually a
        // DIFFERENT address (`bc1pfq2e6y8c…`) — see commit message
        // for context. v_2026_04_17 only needs to reproduce the
        // metadata-path output for this test; the on-chain shape is
        // built by a different (still-unidentified) code path.
        assert_eq!(
            address.to_string(),
            "bc1pkc5gfg54sktcfjae4cgw29a7x7urcvvyavjc6vs052cu4eguyf2szsljdw",
            "v_2026_04_17 must reproduce snowden's metadata-path address — \
             if this moves, the historical builder has drifted and \
             stuck-fund identification breaks"
        );
    }
}


