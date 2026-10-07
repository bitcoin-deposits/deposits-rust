//! Tapscript Multisig Reserves Output
//!
//! Constructs Taproot outputs with threshold-based spending policies for reserves.
//! The script tree enables multiple spend paths with degrading thresholds over time.
//!
//! ## Spend Path Hierarchy
//!
//! 1. **Majority Immediate**: Tie-breaker + majority of other voters (no timelock)
//! 2. **Degraded Tier 1**: Reduced threshold after first timelock
//! 3. **Degraded Tier 2**: Further reduced threshold after second timelock
//! 4. **Emergency Recovery**: Single party after extended timelock
//!
//! ## Voter Roles
//!
//! - **Tie-breaker**: The channel partner (required for immediate spend)
//! - **Primary Voters**: Other channel partners in the network

use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use bitcoin::{
    secp256k1::{PublicKey, Secp256k1, XOnlyPublicKey},
    taproot::{LeafVersion, TaprootBuilder, TaprootSpendInfo},
    Address, Amount, Network, ScriptBuf, TxOut, Witness,
};
use serde::{Deserialize, Serialize};

use crate::error::{DepositsError, DepositsResult};

/// BIP-341 recommended NUMS (Nothing Up My Sleeve) point for Taproot internal keys.
///
/// This is `lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)`,
/// which has no known discrete log. Using this as the internal key makes key-path
/// spending impossible — all spends must use a Tapscript leaf.
///
/// Wallets MUST verify that reserves outputs use this exact point as their
/// internal key. Any other internal key allows the holder to key-path spend,
/// bypassing all quorum and timelock protections.
pub const TAPROOT_NUMS_POINT: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Verify that a Taproot reserves output uses the canonical NUMS internal key.
///
/// Returns `true` if the output's internal key matches `TAPROOT_NUMS_POINT`.
/// Wallets should call this on every QuorumBegin to reject reserves addresses
/// where the operator could key-path spend.
pub fn verify_nums_internal_key(output: &TaprootReservesOutput) -> bool {
    output.spend_info.internal_key().serialize() == TAPROOT_NUMS_POINT
}

/// A voter in the reserves multisig
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Voter {
    /// The voter's public key
    pub pubkey: PublicKey,
    /// Whether this voter is the tie-breaker (required for immediate spend)
    pub is_tie_breaker: bool,
}

impl Voter {
    pub fn new(pubkey: PublicKey, is_tie_breaker: bool) -> Self {
        Self {
            pubkey,
            is_tie_breaker,
        }
    }

    /// Convert to x-only pubkey for Tapscript
    pub fn x_only(&self) -> XOnlyPublicKey {
        self.pubkey.x_only_public_key().0
    }
}

/// Set of voters for a reserves output
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VoterSet {
    /// All voters (tie-breaker + primary voters)
    voters: Vec<Voter>,
}

impl VoterSet {
    /// Create a new voter set with a tie-breaker and additional voters
    pub fn new(tie_breaker: PublicKey, other_voters: Vec<PublicKey>) -> Self {
        let mut voters = vec![Voter::new(tie_breaker, true)];
        for pk in other_voters {
            voters.push(Voter::new(pk, false));
        }
        Self { voters }
    }

    /// Get the tie-breaker voter
    pub fn tie_breaker(&self) -> Option<&Voter> {
        self.voters.iter().find(|v| v.is_tie_breaker)
    }

    /// Get all non-tie-breaker voters
    pub fn primary_voters(&self) -> Vec<&Voter> {
        self.voters.iter().filter(|v| !v.is_tie_breaker).collect()
    }

    /// Total number of voters
    pub fn total_count(&self) -> usize {
        self.voters.len()
    }

    /// Number of primary (non-tie-breaker) voters
    pub fn primary_count(&self) -> usize {
        self.voters.iter().filter(|v| !v.is_tie_breaker).count()
    }

    /// Get sorted x-only pubkeys (deterministic ordering for script construction)
    pub fn sorted_x_only_pubkeys(&self) -> Vec<XOnlyPublicKey> {
        let mut keys: Vec<_> = self.voters.iter().map(|v| v.x_only()).collect();
        keys.sort_by_key(|a| a.serialize());
        keys
    }

    /// Get all voters as PublicKeys
    pub fn all_voters(&self) -> Vec<PublicKey> {
        self.voters.iter().map(|v| v.pubkey).collect()
    }
}

/// A threshold spending tier with optional timelock
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdTier {
    /// Number of signatures required
    pub threshold: usize,
    /// Whether tie-breaker signature is required
    pub requires_tie_breaker: bool,
    /// **Absolute** `OP_CLTV` target (block height) for this tier. `0`
    /// means no timelock — the tier is the immediate quorum-majority
    /// path routine rotations use. The Ruleset's tier-config factory
    /// is responsible for picking the right value (`quorum_expiry + offset`). The script builder treats this as
    /// the literal value to push before `OP_CLTV`.
    pub timelock_blocks: u32,
    /// Human-readable description
    pub description: String,
}

impl ThresholdTier {
    pub fn new(
        threshold: usize,
        requires_tie_breaker: bool,
        timelock_blocks: u32,
        description: &str,
    ) -> Self {
        Self {
            threshold,
            requires_tie_breaker,
            timelock_blocks,
            description: description.to_string(),
        }
    }

    /// Majority immediate: tie-breaker + majority of others, no timelock
    pub fn majority_immediate(voter_count: usize) -> Self {
        let majority = (voter_count / 2) + 1;
        Self::new(
            majority,
            true,
            0,
            "Majority immediate (tie-breaker required)",
        )
    }

    /// Degraded tier with reduced threshold after timelock
    pub fn degraded(threshold: usize, requires_tie_breaker: bool, timelock_blocks: u32) -> Self {
        let desc = if requires_tie_breaker {
            format!(
                "{}-of-n after {} blocks (tie-breaker required)",
                threshold, timelock_blocks
            )
        } else {
            format!("{}-of-n after {} blocks", threshold, timelock_blocks)
        };
        Self::new(threshold, requires_tie_breaker, timelock_blocks, &desc)
    }

    /// Emergency single-party recovery after extended timelock
    pub fn emergency_recovery(timelock_blocks: u32) -> Self {
        Self::new(
            1,
            false,
            timelock_blocks,
            &format!("Emergency recovery after {} blocks", timelock_blocks),
        )
    }
}

/// Configuration for reserves output thresholds
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// Ordered list of threshold tiers (most restrictive first)
    pub tiers: Vec<ThresholdTier>,
}

impl ThresholdConfig {
    /// Build a [`ThresholdConfig`] for `n` voters under the current
    /// ruleset, anchored at `quorum_expiry = 0` (tests and shape checks).
    ///
    /// Provided as a thin compatibility shim so existing call sites
    /// that haven't been ruleset-aware yet keep compiling. New code
    /// should call `crate::ruleset::lookup(name)` and run that
    /// ruleset's `tier_config_factory(n, quorum_expiry)` instead —
    /// this routes through the version the ledger committed to in
    /// its QuorumBegin.
    pub fn default_for_voter_count(n: usize) -> Self {
        (crate::ruleset::resolve_or_current(None).tier_config_factory)(n, 0)
    }

    /// Custom configuration
    pub fn custom(tiers: Vec<ThresholdTier>) -> Self {
        Self { tiers }
    }
}

/// Builder for Tapscript reserves outputs.
///
/// Takes a fully-resolved `ThresholdConfig` whose `timelock_blocks`
/// fields are already absolute `OP_CLTV` targets — the Ruleset's
/// tier-config factory bakes the right shape (legacy literal vs.
/// `quorum_expiry + offset`). The builder is otherwise ruleset-naive:
/// it just builds the script tree from whatever config it's handed.
pub struct TapscriptReservesBuilder {
    voter_set: VoterSet,
    config: ThresholdConfig,
    network: Network,
    /// Ledger hash committed to in the Taproot tree
    ledger_hash: [u8; 32],
}

impl TapscriptReservesBuilder {
    pub fn new(
        voter_set: VoterSet,
        config: ThresholdConfig,
        network: Network,
        ledger_hash: [u8; 32],
    ) -> Self {
        Self {
            voter_set,
            config,
            network,
            ledger_hash,
        }
    }

    /// Create with the current ruleset's tiers anchored at `quorum_expiry = 0`.
    /// For tests and script-shape checks only: a real vault must be built from
    /// its ledger's ruleset and quorum expiry.
    pub fn with_defaults(voter_set: VoterSet, network: Network, ledger_hash: [u8; 32]) -> Self {
        let config = ThresholdConfig::default_for_voter_count(voter_set.total_count());
        Self::new(voter_set, config, network, ledger_hash)
    }

    /// Build an unspendable commitment leaf that embeds the ledger hash
    /// Script format: <ledger_hash> OP_DROP OP_FALSE
    /// This is provably unspendable but commits the hash to the Taproot tree
    fn build_commitment_leaf(&self) -> ScriptBuf {
        Builder::new()
            .push_slice(self.ledger_hash)
            .push_opcode(OP_DROP)
            .push_opcode(OP_PUSHBYTES_0) // OP_FALSE is OP_0
            .into_script()
    }

    /// Build a Tapscript leaf for a threshold tier
    pub fn build_threshold_leaf(&self, tier: &ThresholdTier) -> DepositsResult<ScriptBuf> {
        let mut builder = Builder::new();

        // Add timelock if specified. `timelock_blocks` is the absolute
        // CLTV target — the Ruleset's tier-config factory baked it in
        // (legacy literal or `quorum_expiry + offset`).
        if tier.timelock_blocks > 0 {
            builder = builder
                .push_int(tier.timelock_blocks as i64)
                .push_opcode(OP_CLTV)
                .push_opcode(OP_DROP);
        }

        // Get sorted pubkeys for deterministic script construction
        let sorted_keys = self.voter_set.sorted_x_only_pubkeys();

        // Operator-alone special case: tie-breaker required AND
        // threshold == 1 means "ONLY the operator can spend." Emit a
        // single-key CHECKSIG of the tie-breaker (operator). This is
        // distinct from "any one voter" which uses the general
        // CHECKSIGADD path below.
        if tier.threshold == 1 && tier.requires_tie_breaker {
            let tb = self.voter_set.tie_breaker().ok_or_else(|| {
                DepositsError::InvalidState("Tie-breaker required but not found".to_string())
            })?;
            builder = builder
                .push_x_only_key(&tb.x_only())
                .push_opcode(OP_CHECKSIG);
            return Ok(builder.into_script());
        }

        // General CHECKSIGADD path. Used for every other tier — strict
        // majority, minority, "any one voter" (threshold=1 without
        // tie-breaker), etc. The witness shape is uniform: one sig (or
        // empty push) per voter in sorted order, plus the leaf+control_
        // block tail. This means rotation and confiscation can share
        // witness-assembly code across tiers without special-casing the
        // single-signer-from-the-quorum scenario.
        //
        // Pattern: <key1> CHECKSIG <key2> CHECKSIGADD … <threshold>
        // GREATERTHANOREQUAL

        let keys_to_use = if tier.requires_tie_breaker {
            // Must include tie-breaker, plus the primary voters
            let tb = self.voter_set.tie_breaker().ok_or_else(|| {
                DepositsError::InvalidState("Tie-breaker required but not found".to_string())
            })?;
            let mut keys = vec![tb.x_only()];
            for voter in self.voter_set.primary_voters() {
                keys.push(voter.x_only());
            }
            keys.sort_by_key(|a| a.serialize());
            keys
        } else {
            sorted_keys.clone()
        };

        if keys_to_use.len() < tier.threshold {
            return Err(DepositsError::InvalidState(format!(
                "Not enough keys ({}) for threshold ({})",
                keys_to_use.len(),
                tier.threshold
            )));
        }

        // First key uses CHECKSIG
        builder = builder
            .push_x_only_key(&keys_to_use[0])
            .push_opcode(OP_CHECKSIG);

        // Subsequent keys use CHECKSIGADD
        for key in keys_to_use.iter().skip(1) {
            builder = builder.push_x_only_key(key).push_opcode(OP_CHECKSIGADD);
        }

        // Check threshold (use >= so meeting OR exceeding threshold works)
        builder = builder
            .push_int(tier.threshold as i64)
            .push_opcode(OP_GREATERTHANOREQUAL);

        Ok(builder.into_script())
    }

    /// Build the complete Taproot output
    pub fn build(&self) -> DepositsResult<TaprootReservesOutput> {
        self.build_with_internal_key(None)
    }

    /// Build the Taproot output forcing a specific internal key.
    ///
    /// Defaults (`internal_key_override = None`) to the BIP-341 NUMS point.
    /// Use the tie-breaker's x-only pubkey when reconstructing a pre-NUMS-fix
    /// reserves UTXO (pre-`b3d38ac`) whose on-chain shape committed the
    /// operator's pubkey as the internal key. Production legacy ledgers that
    /// don't reconstruct under NUMS need this — see `validate-relay`'s
    /// scanning strategy.
    pub fn build_with_internal_key(
        &self,
        internal_key_override: Option<XOnlyPublicKey>,
    ) -> DepositsResult<TaprootReservesOutput> {
        let secp = Secp256k1::new();

        // Build script leaves for each tier
        let mut leaves: Vec<ScriptBuf> = Vec::new();
        for tier in self.config.tiers.iter() {
            let script = self.build_threshold_leaf(tier)?;
            leaves.push(script);
        }

        if leaves.is_empty() {
            return Err(DepositsError::InvalidState(
                "No threshold tiers configured".to_string(),
            ));
        }

        // Add the commitment leaf (embeds ledger hash, unspendable)
        let commitment_leaf = self.build_commitment_leaf();

        // Default: BIP-341 NUMS point — provably unspendable key path so
        // every spend must go through the Tapscript leaves (per b3d38ac).
        // Override: the tie-breaker x-only pubkey for reconstructing
        // legacy pre-NUMS-fix UTXOs that committed the operator's key as
        // the internal key.
        let internal_key = match internal_key_override {
            Some(k) => k,
            None => XOnlyPublicKey::from_slice(&[
                0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
                0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
                0xce, 0x80, 0x3a, 0xc0,
            ])
            .map_err(|_| DepositsError::InvalidState("Invalid NUMS point".to_string()))?,
        };

        // Build Taproot tree
        // Structure: spending tiers at shallow depths, commitment leaf at deepest
        let mut builder = TaprootBuilder::new();

        // Total leaves = spending tiers + commitment leaf
        let num_spending_leaves = leaves.len();
        let total_leaves = num_spending_leaves + 1;

        // Add spending leaves with depths calculated for optimal structure
        for (i, script) in leaves.iter().enumerate() {
            // Calculate depth: deeper for later (less preferred) tiers
            let depth = if total_leaves == 2 {
                1 // Binary tree: both at depth 1
            } else {
                (i + 1) as u8
            };

            builder = builder.add_leaf(depth, script.clone()).map_err(|e| {
                DepositsError::InvalidState(format!("Failed to add Tapscript leaf: {:?}", e))
            })?;
        }

        // Add commitment leaf at the deepest level (paired with last spending leaf)
        let commitment_depth = if total_leaves == 2 {
            1
        } else {
            num_spending_leaves as u8
        };
        builder = builder
            .add_leaf(commitment_depth, commitment_leaf)
            .map_err(|e| {
                DepositsError::InvalidState(format!("Failed to add commitment leaf: {:?}", e))
            })?;

        let spend_info = builder.finalize(&secp, internal_key).map_err(|e| {
            DepositsError::InvalidState(format!("Failed to finalize Taproot tree: {:?}", e))
        })?;

        // Create the output script (P2TR)
        let address = Address::p2tr(&secp, internal_key, spend_info.merkle_root(), self.network);

        Ok(TaprootReservesOutput {
            address,
            spend_info,
            voter_set: self.voter_set.clone(),
            config: self.config.clone(),
            network: self.network,
            ledger_hash: self.ledger_hash,
        })
    }
}

/// A complete Taproot reserves output ready for use in commitment transactions
#[derive(Clone, Debug)]
pub struct TaprootReservesOutput {
    /// The P2TR address for this reserves output
    pub address: Address,
    /// Taproot spend info (needed for spending)
    pub spend_info: TaprootSpendInfo,
    /// The voter set for this output
    pub voter_set: VoterSet,
    /// The threshold configuration (with absolute CLTV targets baked in)
    pub config: ThresholdConfig,
    /// The network this output is for
    pub network: Network,
    /// The ledger hash committed to in this output
    pub ledger_hash: [u8; 32],
}

impl TaprootReservesOutput {
    /// Get the script pubkey for use in TxOut
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }

    /// Create a TxOut with specified amount
    pub fn to_tx_out(&self, amount_sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: self.script_pubkey(),
        }
    }

    /// Get the internal key (for key-path spending)
    pub fn internal_key(&self) -> XOnlyPublicKey {
        self.spend_info.internal_key()
    }

    /// Get the merkle root of the script tree
    pub fn merkle_root(&self) -> Option<bitcoin::taproot::TapNodeHash> {
        self.spend_info.merkle_root()
    }

    /// Get the control block for a specific tier (needed for script-path spending)
    pub fn control_block_for_tier(
        &self,
        tier_index: usize,
    ) -> Option<bitcoin::taproot::ControlBlock> {
        if tier_index >= self.config.tiers.len() {
            return None;
        }

        // Rebuild the script for this tier to get control block
        let builder = TapscriptReservesBuilder::new(
            self.voter_set.clone(),
            self.config.clone(),
            self.network,
            self.ledger_hash,
        );

        let script = builder
            .build_threshold_leaf(&self.config.tiers[tier_index])
            .ok()?;
        self.spend_info
            .control_block(&(script, LeafVersion::TapScript))
    }

    /// Get the ledger hash committed to in this output
    pub fn ledger_hash(&self) -> [u8; 32] {
        self.ledger_hash
    }

    /// Verify that an on-chain script_pubkey matches this Taproot reserves output.
    ///
    /// Used by dispute and confiscation paths to confirm that an on-chain
    /// reserves output commits to the expected ledger state — the operator's
    /// claimed `ledger_hash` is part of the tapscript, so any mismatch here
    /// is provable evidence of non-conforming reserves.
    pub fn verify_script_pubkey(&self, on_chain_script: &ScriptBuf) -> bool {
        &self.script_pubkey() == on_chain_script
    }
}

/// Verify that an on-chain script_pubkey corresponds to a Taproot reserves output
/// with the given parameters. Returns true if the script matches.
///
/// 1. Reconstruct the expected Taproot address from the voter set, network,
///    and expected `ledger_hash`.
/// 2. Compare against the on-chain script. A match proves the reserves UTXO
///    commits to the supplied `ledger_hash` (since `ledger_hash` is mixed
///    into the tapscript leaf).
///
/// `ledger_hash` cannot be directly extracted from a P2TR `scriptPubkey`;
/// verification works by reconstruction and equality check.
pub fn verify_taproot_reserves(
    voter_set: VoterSet,
    network: bitcoin::Network,
    expected_ledger_hash: [u8; 32],
    on_chain_script: &ScriptBuf,
) -> bool {
    let builder = TapscriptReservesBuilder::with_defaults(voter_set, network, expected_ledger_hash);
    match builder.build() {
        Ok(output) => output.verify_script_pubkey(on_chain_script),
        Err(_) => false,
    }
}

/// Build a Taproot reserves script_pubkey for the given VoterSet.
///
/// This creates a P2TR output with tiered spending thresholds for reserves.
/// The VoterSet defines the voters for reserve spending:
/// - Tie-breaker: The channel partner (required for immediate spend)
/// - Other voters: Quorum members from other channels (if any)
///
/// # Arguments
/// * `voter_set` - The set of voters who can authorize reserve spends
/// * `ledger_hash` - The current ledger hash to embed in the Taproot tree
/// * `network` - Bitcoin network (mainnet, testnet, etc.)
///
/// # Returns
/// The script_pubkey for the P2TR reserves output
pub fn build_taproot_reserves_script(
    voter_set: VoterSet,
    ledger_hash: [u8; 32],
    network: bitcoin::Network,
) -> DepositsResult<ScriptBuf> {
    let builder = TapscriptReservesBuilder::with_defaults(voter_set, network, ledger_hash);
    let output = builder.build()?;
    Ok(output.script_pubkey())
}

/// Parameters for building a deterministic spend transaction
#[derive(Clone, Debug)]
pub struct SpendTxParams {
    /// The reserves UTXO outpoint (txid:vout as 36 bytes)
    pub reserves_outpoint: bitcoin::OutPoint,
    /// The amount in the reserves UTXO (satoshis)
    pub reserves_amount: u64,
    /// Destination script for the *change* (remainder after `splits` and fee).
    /// When `splits` is empty, this is the only output and receives
    /// `reserves_amount − fee`.
    pub destination_script: ScriptBuf,
    /// Additional fixed-amount outputs that come *before* the change output.
    /// Each entry is `(script_pubkey, amount_sats)`. The change output to
    /// `destination_script` is computed as
    /// `reserves_amount − sum(splits) − fee`. Empty by default for
    /// backward-compatible single-output behavior.
    #[doc(alias = "multi-output")]
    pub splits: Vec<(ScriptBuf, u64)>,
    /// Fee rate in sat/vbyte
    pub fee_rate_sat_vbyte: u64,
    /// nLockTime value for the spending TX. Must be `≥ quorum_expiry +
    /// tier_offset` for tiers gated by `OP_CLTV` to satisfy the script
    /// (see DEP-03 §"Spending Tiers"). Tier 0 (anytime majority) uses
    /// `0` since there's no CLTV — input sequence still opts into
    /// CLTV enforcement (see `Sequence::ENABLE_RBF_NO_LOCKTIME`).
    pub lock_time: u32,
}

/// A deterministic spend transaction builder for reserves outputs
pub struct ReservesSpendBuilder;

impl ReservesSpendBuilder {
    /// Build a deterministic spend transaction from reserves to destination
    ///
    /// The transaction is deterministic given the same parameters, enabling
    /// multiple parties to independently construct and sign the same tx.
    pub fn build_spend_transaction(
        params: &SpendTxParams,
        _reserves_script_pubkey: &ScriptBuf,
    ) -> DepositsResult<bitcoin::Transaction> {
        use bitcoin::{Sequence, Transaction, TxIn, TxOut, Witness};

        // Estimate tx size: Taproot script-path spend input (~135 vb) +
        // one ~43 vb output per emitted output (change + every split).
        // 135 vb is conservative for tier-0 majority of 3 (witness =
        // 2 sigs + 1 empty stack + ~104 byte script + ~97 byte control
        // block ≈ 333 wbytes / 4 ≈ 84 vbytes; plus 41 byte base input +
        // ~10 byte tx overhead).
        let output_count = (params.splits.len() + 1) as u64;
        let estimated_vbytes = 135 + 43 * output_count;
        let fee = estimated_vbytes * params.fee_rate_sat_vbyte;

        let splits_total: u64 = params.splits.iter().map(|(_, n)| *n).sum();
        let consumed = splits_total.saturating_add(fee);
        if consumed >= params.reserves_amount {
            return Err(DepositsError::InvalidState(format!(
                "splits ({} sats) + fee ({} sats) exceeds reserves ({} sats)",
                splits_total, fee, params.reserves_amount
            )));
        }
        let change_amount = params.reserves_amount - consumed;

        let mut outputs: Vec<TxOut> = params
            .splits
            .iter()
            .map(|(script, amount)| TxOut {
                value: Amount::from_sat(*amount),
                script_pubkey: script.clone(),
            })
            .collect();
        outputs.push(TxOut {
            value: Amount::from_sat(change_amount),
            script_pubkey: params.destination_script.clone(),
        });

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(params.lock_time),
            input: vec![TxIn {
                previous_output: params.reserves_outpoint,
                script_sig: ScriptBuf::new(), // Empty for Taproot
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // Filled in later with signatures
            }],
            output: outputs,
        };

        Ok(tx)
    }

    /// Compute the sighash for Taproot script-path spending (BIP-342)
    ///
    /// Returns the sighash that each voter should sign with their Schnorr key
    pub fn compute_sighash(
        tx: &bitcoin::Transaction,
        input_index: usize,
        reserves_amount: u64,
        reserves_script_pubkey: &ScriptBuf,
        leaf_script: &ScriptBuf,
    ) -> DepositsResult<bitcoin::TapSighash> {
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};

        let prevouts = vec![TxOut {
            value: Amount::from_sat(reserves_amount),
            script_pubkey: reserves_script_pubkey.clone(),
        }];

        let mut cache = SighashCache::new(tx);

        let sighash = cache
            .taproot_script_spend_signature_hash(
                input_index,
                &Prevouts::All(&prevouts),
                bitcoin::taproot::TapLeafHash::from_script(leaf_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .map_err(|e| {
                DepositsError::InvalidState(format!("Failed to compute sighash: {:?}", e))
            })?;

        Ok(sighash)
    }

    /// Create a witness for script-path spending with CHECKSIGADD
    ///
    /// Signatures must be in the same order as keys in the script (sorted by x-only pubkey).
    /// For missing signatures (non-participating voters), use an empty 64-byte signature.
    pub fn create_checksigadd_witness(
        signatures: &[Option<[u8; 64]>],
        leaf_script: &ScriptBuf,
        control_block: &bitcoin::taproot::ControlBlock,
    ) -> Witness {
        let mut witness = Witness::new();

        // For CHECKSIGADD, we push signatures in reverse order of keys
        // (stack order: first key's signature is checked last)
        for sig_opt in signatures.iter().rev() {
            match sig_opt {
                Some(sig) => {
                    // 64-byte Schnorr signature (no sighash type byte for Default)
                    witness.push(&sig[..]);
                }
                None => {
                    // Empty signature for non-participating voter
                    witness.push([]);
                }
            }
        }

        // Push the leaf script
        witness.push(leaf_script.as_bytes());

        // Push the control block
        witness.push(control_block.serialize());

        witness
    }

    /// Finalize a spend transaction with collected signatures
    ///
    /// Takes the unsigned transaction and the signatures collected from voters,
    /// creating the final signed transaction ready for broadcast.
    pub fn finalize_spend_transaction(
        mut tx: bitcoin::Transaction,
        signatures: &[Option<[u8; 64]>],
        leaf_script: &ScriptBuf,
        control_block: &bitcoin::taproot::ControlBlock,
    ) -> bitcoin::Transaction {
        tx.input[0].witness =
            Self::create_checksigadd_witness(signatures, leaf_script, control_block);
        tx
    }
}

// ============================================================================
// LOTTERY SCRIPT BUILDER
// ============================================================================

/// A participant in the custody lottery
#[derive(Clone, Debug)]
pub struct LotteryParticipant {
    /// The participant's public key (x-only for Taproot)
    pub pubkey: XOnlyPublicKey,
    /// HASH160 of their committed preimage
    pub commitment_hash: [u8; 20],
    /// Target address where they want funds sent if they win
    pub target_reserves: String,
}

impl LotteryParticipant {
    pub fn new(pubkey: XOnlyPublicKey, commitment_hash: [u8; 20], target_reserves: String) -> Self {
        Self {
            pubkey,
            commitment_hash,
            target_reserves,
        }
    }
}

/// Multiple of the estimated on-chain claim fee that the disputed value
/// must exceed for the lottery to be economically rational.
///
/// Below this floor the winner's net payout would be eroded by fees and
/// nobody has a reason to claim, leaving the output stuck.
pub const MIN_ECONOMIC_FEE_MULTIPLE: u64 = 5;

/// Default confiscation feerate (sat/vB) while no `reference_feerate_sat_vb` is recorded.
pub const CONFISCATION_DEFAULT_FEERATE_SAT_VB: u64 = 2;

/// DEP-03 §"Confiscation fee": `feerate × (120 + 30 × voters)` sats, where `voters`
/// counts the vault's voters (members and operator). A deterministic bound on the
/// confiscation's vsize at any tier, so every cosigner builds the same transaction.
pub fn confiscation_fee_sats(voters: usize, feerate_sat_vb: u64) -> u64 {
    feerate_sat_vb.saturating_mul(120 + 30 * voters as u64)
}

/// DEP-03 §"Rotation transaction": the deterministic vsize bound from its outputs,
/// `46 + 30 × voters + Σ (9 + len(spk)) + 68 × [splice-in]`.
pub fn rotation_vsize(voters: usize, output_spk_lens: &[usize], splice_in: bool) -> u64 {
    46 + 30 * voters as u64
        + output_spk_lens.iter().map(|l| 9 + *l as u64).sum::<u64>()
        + if splice_in { 68 } else { 0 }
}

/// The inputs DEP-03 §"Rotation transaction" fixes the rotation from.
#[derive(Clone, Debug)]
pub struct RotationTxParams {
    pub vault: bitcoin::OutPoint,
    pub vault_sats: u64,
    /// Keys of the vault being spent (members and operator).
    pub voters: usize,
    pub feerate_sat_vb: u64,
    /// The spending tier's CLTV (0 at Tier 0).
    pub lock_time: u32,
    pub new_vault_spk: ScriptBuf,
    pub splice_in: Option<(bitcoin::OutPoint, u64)>,
    /// Exit outputs in recorded order, then the migration output, as (spk, sats).
    pub extra_outputs: Vec<(ScriptBuf, u64)>,
}

/// The unsigned rotation (DEP-03 §"Rotation transaction"): version 2, nLockTime the
/// tier's CLTV, input 0 the vault and input 1 the splice-in (both `0xfffffffd`),
/// output 0 the new vault, then the exit and migration outputs. `None` if the new
/// vault would fall below 330 sats.
pub fn build_rotation_tx(p: &RotationTxParams) -> Option<bitcoin::Transaction> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, Sequence, TxIn, TxOut, Witness,
    };
    let mut input = vec![TxIn {
        previous_output: p.vault,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }];
    if let Some((outpoint, _)) = p.splice_in {
        input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }
    let mut lens = vec![p.new_vault_spk.len()];
    lens.extend(p.extra_outputs.iter().map(|(spk, _)| spk.len()));
    let fee =
        p.feerate_sat_vb
            .saturating_mul(rotation_vsize(p.voters, &lens, p.splice_in.is_some()));
    let paid_out: u64 = p.extra_outputs.iter().map(|(_, v)| *v).sum();
    let total = p.vault_sats + p.splice_in.map(|(_, v)| v).unwrap_or(0);
    let new_vault = total.checked_sub(paid_out)?.checked_sub(fee)?;
    if new_vault < 330 {
        return None;
    }
    let mut output = vec![TxOut {
        value: Amount::from_sat(new_vault),
        script_pubkey: p.new_vault_spk.clone(),
    }];
    output.extend(p.extra_outputs.iter().map(|(spk, v)| TxOut {
        value: Amount::from_sat(*v),
        script_pubkey: spk.clone(),
    }));
    Some(bitcoin::Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(p.lock_time),
        input,
        output,
    })
}

/// DEP-03 `claim_fee_floor` with no `reference_feerate_sat_vb` recorded: the lottery
/// claim's fee, and the padding every replacement-collateral declaration must cover.
pub const CLAIM_FEE_FLOOR_SATS: u64 = 5_000;

/// The unsigned lottery claim (DEP-03 §"Claim transaction"): input 0 the lottery
/// output (nSequence `LOTTERY_REVEAL_CSV_BLOCKS` for a revealer-subset leaf, else
/// `0xfffffffd`), input 1 the winner's declared replacement collateral at its declared
/// value (`0xfffffffd`), one output to the winner's target of the inputs less `fee`.
pub fn build_lottery_claim_tx(
    lottery: bitcoin::OutPoint,
    lottery_sats: u64,
    collateral: Option<(bitcoin::OutPoint, u64)>,
    destination: ScriptBuf,
    fee: u64,
    subset_leaf: bool,
) -> bitcoin::Transaction {
    use bitcoin::{Sequence, TxIn, Witness};
    let mut input = vec![TxIn {
        previous_output: lottery,
        script_sig: ScriptBuf::new(),
        sequence: if subset_leaf {
            Sequence::from_height(LOTTERY_REVEAL_CSV_BLOCKS as u16)
        } else {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        },
        witness: Witness::new(),
    }];
    let mut total = lottery_sats;
    if let Some((outpoint, sats)) = collateral {
        input.push(TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        total += sats;
    }
    bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input,
        output: vec![TxOut {
            value: Amount::from_sat(total.saturating_sub(fee)),
            script_pubkey: destination,
        }],
    }
}

/// Contributions are `LEN(preimage) - 16` in `1..=60`: uniform mod every
/// `m` in `1..=6` (60 = lcm(1..6)); for `m = 7` residues 1-4 occur 9/60 and
/// the rest 8/60 (DEP-06 §"Influence and bias").
pub const LOTTERY_CONTRIBUTION_RANGE: usize = 60;

/// Longest preimage a claim leaf accepts: 76 bytes, within the 80-byte
/// standard tapscript stack item.
pub const LOTTERY_MAX_PREIMAGE_LEN: usize = 16 + LOTTERY_CONTRIBUTION_RANGE;

/// The reveal deadline: revealer-subset claim leaves open this many blocks
/// after the confiscation confirms (DEP-06 Phase 3).
pub const LOTTERY_REVEAL_CSV_BLOCKS: u32 = 72;

/// Most participants a lottery output supports: the subset tree has
/// `2^k - 1` claim leaves.
pub const MAX_LOTTERY_PARTICIPANTS: usize = 7;

/// CSV block delay before an armer's slashing-share output can be
/// swept by the recovery quorum as forfeited (because the armer never
/// revealed their preimage). The armer keeps their slice by spending
/// the reveal-claim leaf within this window; after the window, others
/// can sweep. Matches the existing recovery long-tail floor of 144
/// blocks (~1 day) so the timing is consistent with the lottery's own
/// recovery cascade.
pub const ARMER_SHARE_SWEEP_CSV_BLOCKS: u32 = 144;

/// Per-regime bond ratio: the lower bound on `bond / disputed_value`
/// required to keep defection-and-eat-the-slash irrational.
///
/// Returns `(numerator, denominator)` so callers can do exact integer math
/// without floating point. The ratio is `(N-1)/N`, matching each disputant's
/// expected loss probability if they refuse to reveal.
pub fn bond_ratio_for_n(n: usize) -> (u64, u64) {
    let n = n.max(1) as u64;
    (n.saturating_sub(1), n)
}

/// Minimum bond a disputant must stake to keep defection irrational at
/// the current disputant count. Computed as `((N-1)/N) * disputed_value`,
/// rounded up so the operator pays the full required ratio.
pub fn min_bond_for_disputed_value(n: usize, disputed_value: u64) -> u64 {
    let (num, den) = bond_ratio_for_n(n);
    if den == 0 {
        return 0;
    }
    disputed_value.saturating_mul(num).div_ceil(den)
}

/// Refuse if the recovery long-tail couldn't be signed by the
/// non-disputing remainder of the quorum. `t_emergency` is the floor
/// threshold across the recovery leaves (typically `T-2` clamped to 1).
pub fn check_recovery_quorum_precondition(
    n_quorum: usize,
    n_disputants: usize,
    t_emergency: usize,
) -> DepositsResult<()> {
    let non_disputing = n_quorum.saturating_sub(n_disputants);
    if non_disputing < t_emergency {
        return Err(DepositsError::RecoveryQuorumUnreachable {
            n_quorum,
            n_disputants,
            t_emergency,
        });
    }
    Ok(())
}

/// Refuse if the disputed value is too small relative to the on-chain
/// claim fee for the lottery to make economic sense. The threshold is
/// `MIN_ECONOMIC_FEE_MULTIPLE × estimated_claim_fee`.
pub fn check_economic_precondition(
    disputed_value: u64,
    estimated_claim_fee: u64,
) -> DepositsResult<()> {
    let min_required = estimated_claim_fee.saturating_mul(MIN_ECONOMIC_FEE_MULTIPLE);
    if disputed_value < min_required {
        return Err(DepositsError::LotteryNotEconomical {
            disputed_value,
            min_required,
        });
    }
    Ok(())
}

/// Refuse if a disputant's bond is below the per-regime ratio. Belongs at
/// `DisputeArmed` ingest where each disputant's collateral is known.
pub fn check_bond_ratio_precondition(
    n: usize,
    bond: u64,
    disputed_value: u64,
) -> DepositsResult<()> {
    let required = min_bond_for_disputed_value(n, disputed_value);
    if bond < required {
        let (numerator, denominator) = bond_ratio_for_n(n);
        return Err(DepositsError::InsufficientBondRatio {
            n,
            actual: bond,
            required,
            numerator,
            denominator,
        });
    }
    Ok(())
}

/// Builder for lottery Tapscript outputs used in custody dispute resolution
/// (DEP-06 Phase 2).
///
/// Leaves, in tree order: the full-set claim (every preimage, winner =
/// `sum mod k`); one leaf per nonempty proper subset S of the participants,
/// behind CSV 72, in which a threshold of recovery voters attests S before
/// the draw over S (winner = `sum_S mod |S|`); then the recovery cascade.
/// A sole participant (`k = 1`) gets a plain signature leaf instead.
pub struct LotteryScriptBuilder {
    participants: Vec<LotteryParticipant>,
    network: Network,
    /// Quorum members (excluding disputed operator) for timeout recovery
    recovery_voters: Vec<XOnlyPublicKey>,
    /// Recovery threshold
    recovery_threshold: usize,
}

/// Nonempty proper subsets of `0..k`, by decreasing size, then in
/// lexicographic order (the order `combinations(range(k), m)` yields).
pub fn lottery_subset_indices(k: usize) -> Vec<Vec<usize>> {
    fn combos(start: usize, k: usize, m: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if m == 0 {
            out.push(cur.clone());
            return;
        }
        for i in start..=(k - m) {
            cur.push(i);
            combos(i + 1, k, m - 1, cur, out);
            cur.pop();
        }
    }
    let mut out = Vec::new();
    for m in (1..k).rev() {
        combos(0, k, m, &mut Vec::new(), &mut out);
    }
    out
}

/// The claim body for `members` in canonical order: verify each preimage
/// (hash, `17..=76` bytes), sum the contributions, and let only member
/// `sum mod m` spend.
pub fn build_claim_body(members: &[LotteryParticipant]) -> ScriptBuf {
    let m = members.len();
    let mut builder = Builder::new();
    for (i, p) in members.iter().enumerate() {
        builder = builder
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(p.commitment_hash)
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_SIZE)
            .push_opcode(OP_DUP)
            .push_int(17)
            .push_opcode(OP_GREATERTHANOREQUAL)
            .push_opcode(OP_VERIFY)
            .push_opcode(OP_DUP)
            .push_int(LOTTERY_MAX_PREIMAGE_LEN as i64)
            .push_opcode(OP_LESSTHANOREQUAL)
            .push_opcode(OP_VERIFY)
            .push_opcode(OP_SWAP)
            .push_opcode(OP_DROP)
            .push_int(16)
            .push_opcode(OP_SUB);
        if i + 1 < m {
            builder = builder.push_opcode(OP_TOALTSTACK);
        }
    }
    for _ in 1..m {
        builder = builder.push_opcode(OP_FROMALTSTACK).push_opcode(OP_ADD);
    }
    if m == 1 {
        return builder
            .push_opcode(OP_DROP)
            .push_x_only_key(&members[0].pubkey)
            .push_opcode(OP_CHECKSIG)
            .into_script();
    }
    // The sum is below 64m: six conditional subtractions of m*2^b reduce it
    // mod m (OP_MOD is OP_SUCCESS in tapscript).
    for b in (0..=5).rev() {
        let x = (m << b) as i64;
        builder = builder
            .push_opcode(OP_DUP)
            .push_int(x)
            .push_opcode(OP_GREATERTHANOREQUAL)
            .push_opcode(OP_IF)
            .push_int(x)
            .push_opcode(OP_SUB)
            .push_opcode(OP_ENDIF);
    }
    for (i, p) in members.iter().enumerate() {
        builder = builder
            .push_opcode(OP_DUP)
            .push_int(i as i64)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_DROP)
            .push_x_only_key(&p.pubkey)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE);
    }
    builder = builder.push_opcode(OP_DROP).push_opcode(OP_PUSHBYTES_0);
    for _ in 0..m {
        builder = builder.push_opcode(OP_ENDIF);
    }
    builder.into_script()
}

impl LotteryScriptBuilder {
    pub fn new(
        participants: Vec<LotteryParticipant>,
        recovery_voters: Vec<XOnlyPublicKey>,
        recovery_threshold: usize,
        network: Network,
    ) -> Self {
        Self {
            participants,
            recovery_voters,
            recovery_threshold,
            network,
        }
    }

    /// The full-set claim leaf. Witness (bottom to top):
    /// `<sig> <preimage_{k-1}> ... <preimage_0>`. A sole participant's leaf
    /// is a plain signature check (DEP-03: no draw, no preimage).
    pub fn build_lottery_script(&self) -> DepositsResult<ScriptBuf> {
        let k = self.participants.len();
        if k == 0 || k > MAX_LOTTERY_PARTICIPANTS {
            return Err(DepositsError::InvalidState(format!(
                "Lottery requires 1..={} participants (got {})",
                MAX_LOTTERY_PARTICIPANTS, k
            )));
        }
        if k == 1 {
            return Ok(Builder::new()
                .push_x_only_key(&self.participants[0].pubkey)
                .push_opcode(OP_CHECKSIG)
                .into_script());
        }
        Ok(build_claim_body(&self.participants))
    }

    /// The voters' attestation prefix of a subset leaf: CSV 72, then every
    /// recovery voter (sorted) in a CHECKSIGADD threshold, verified.
    fn build_attest_prefix(&self) -> DepositsResult<ScriptBuf> {
        if self.recovery_voters.len() < self.recovery_threshold || self.recovery_voters.is_empty() {
            return Err(DepositsError::InvalidState(format!(
                "Not enough recovery voters ({}) for threshold ({})",
                self.recovery_voters.len(),
                self.recovery_threshold
            )));
        }
        let mut sorted_keys = self.recovery_voters.clone();
        sorted_keys.sort_by_key(|a| a.serialize());
        let mut builder = Builder::new()
            .push_int(LOTTERY_REVEAL_CSV_BLOCKS as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_x_only_key(&sorted_keys[0])
            .push_opcode(OP_CHECKSIG);
        for key in sorted_keys.iter().skip(1) {
            builder = builder.push_x_only_key(key).push_opcode(OP_CHECKSIGADD);
        }
        Ok(builder
            .push_int(self.recovery_threshold as i64)
            .push_opcode(OP_GREATERTHANOREQUAL)
            .push_opcode(OP_VERIFY)
            .into_script())
    }

    /// `(indices, leaf)` for every nonempty proper subset of the
    /// participants, in tree order; empty for `k < 2`.
    pub fn build_subset_leaves(&self) -> DepositsResult<Vec<(Vec<usize>, ScriptBuf)>> {
        let k = self.participants.len();
        if k < 2 {
            return Ok(vec![]);
        }
        let prefix = self.build_attest_prefix()?;
        Ok(lottery_subset_indices(k)
            .into_iter()
            .map(|idx| {
                let members: Vec<LotteryParticipant> =
                    idx.iter().map(|&i| self.participants[i].clone()).collect();
                let mut bytes = prefix.clone().into_bytes();
                bytes.extend_from_slice(build_claim_body(&members).as_bytes());
                (idx, ScriptBuf::from(bytes))
            })
            .collect())
    }

    /// Build a recovery script for when revelation stalls.
    ///
    /// After CSV timeout, the quorum (minus disputed operator) can recover funds.
    pub fn build_recovery_script(&self, csv_blocks: u32) -> DepositsResult<ScriptBuf> {
        if self.recovery_voters.len() < self.recovery_threshold {
            return Err(DepositsError::InvalidState(format!(
                "Not enough recovery voters ({}) for threshold ({})",
                self.recovery_voters.len(),
                self.recovery_threshold
            )));
        }

        let mut builder = Builder::new();

        // Add CSV timelock
        builder = builder
            .push_int(csv_blocks as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);

        // Sort keys for deterministic script
        let mut sorted_keys = self.recovery_voters.clone();
        sorted_keys.sort_by_key(|a| a.serialize());

        // Multi-sig using CHECKSIGADD pattern
        if self.recovery_threshold == 1 {
            // Single-sig case
            builder = builder
                .push_x_only_key(&sorted_keys[0])
                .push_opcode(OP_CHECKSIG);
        } else {
            // First key uses CHECKSIG
            builder = builder
                .push_x_only_key(&sorted_keys[0])
                .push_opcode(OP_CHECKSIG);

            // Subsequent keys use CHECKSIGADD
            for key in sorted_keys.iter().skip(1) {
                builder = builder.push_x_only_key(key).push_opcode(OP_CHECKSIGADD);
            }

            // Check threshold
            builder = builder
                .push_int(self.recovery_threshold as i64)
                .push_opcode(OP_GREATERTHANOREQUAL);
        }

        Ok(builder.into_script())
    }

    /// Build the complete Taproot lottery output: the full-set leaf, the
    /// subset leaves, then the recovery cascade (CSV 144 / 1008 / 4032 with
    /// thresholds T / T-1 / T-2) and the CSV-8064 single-voter escape hatch.
    /// Depths follow the balanced layout (DEP-03).
    pub fn build(&self) -> DepositsResult<LotteryOutput> {
        let secp = Secp256k1::new();

        let lottery_script = self.build_lottery_script()?;
        let subset_scripts = self.build_subset_leaves()?;

        let recovery_specs = [
            (144u32, self.recovery_threshold), // ~1 day, T
            (1008, self.recovery_threshold.saturating_sub(1).max(1)), // ~1 week, T-1
            (4032, self.recovery_threshold.saturating_sub(2).max(1)), // ~4 weeks, T-2
            (crate::constants::TIMEOUT_RECOVERY_CSV_BLOCKS, 1usize), // ~8 weeks, threshold 1
        ];

        let mut leaves: Vec<ScriptBuf> =
            Vec::with_capacity(1 + subset_scripts.len() + recovery_specs.len());
        leaves.push(lottery_script.clone());
        leaves.extend(subset_scripts.iter().map(|(_, s)| s.clone()));
        for (csv, threshold) in recovery_specs {
            let builder = LotteryScriptBuilder::new(
                self.participants.clone(),
                self.recovery_voters.clone(),
                threshold,
                self.network,
            );
            leaves.push(builder.build_recovery_script(csv)?);
        }

        // Use NUMS point as internal key (unspendable key path)
        let nums_point = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .map_err(|_| DepositsError::InvalidState("Invalid NUMS point".to_string()))?;

        // For `m` leaves where `2^(d-1) < m <= 2^d`, `2*(m - 2^(d-1))` leaves
        // at depth `d` and the remaining `2^d - m` at depth `d-1`, deeper ones
        // first (the TaprootBuilder fills slots in call order).
        let m = leaves.len();
        let builder = if m == 1 {
            TaprootBuilder::new().add_leaf(0, leaves[0].clone())
        } else {
            let d_max = m.next_power_of_two().trailing_zeros() as u8;
            let (deep_count, shallow_depth, shallow_count) = if m.is_power_of_two() {
                (m, d_max, 0usize)
            } else {
                let d_min = d_max - 1;
                let deep = 2 * (m - (1 << d_min));
                let shallow = (1 << d_max) - m;
                (deep, d_min, shallow)
            };

            let mut bldr = TaprootBuilder::new();
            for s in &leaves[..deep_count] {
                bldr = bldr.add_leaf(d_max, s.clone()).map_err(|e| {
                    DepositsError::InvalidState(format!("Failed to add deep leaf: {:?}", e))
                })?;
            }
            for s in &leaves[deep_count..deep_count + shallow_count] {
                bldr = bldr.add_leaf(shallow_depth, s.clone()).map_err(|e| {
                    DepositsError::InvalidState(format!("Failed to add shallow leaf: {:?}", e))
                })?;
            }
            Ok(bldr)
        }
        .map_err(|e| DepositsError::InvalidState(format!("Failed to add leaf: {:?}", e)))?;

        let spend_info = builder.finalize(&secp, nums_point).map_err(|e| {
            DepositsError::InvalidState(format!("Failed to finalize Taproot tree: {:?}", e))
        })?;

        let address = Address::p2tr(&secp, nums_point, spend_info.merkle_root(), self.network);

        Ok(LotteryOutput {
            address,
            spend_info,
            participants: self.participants.clone(),
            lottery_script,
            subset_scripts,
            recovery_voters: self.recovery_voters.clone(),
            recovery_threshold: self.recovery_threshold,
            network: self.network,
        })
    }
}

/// A complete lottery Taproot output for custody dispute resolution
#[derive(Clone, Debug)]
pub struct LotteryOutput {
    /// The P2TR address for this lottery output
    pub address: Address,
    /// Taproot spend info (needed for spending)
    pub spend_info: TaprootSpendInfo,
    /// Lottery participants, in canonical order
    pub participants: Vec<LotteryParticipant>,
    /// The full-set claim script
    pub lottery_script: ScriptBuf,
    /// `(participant indices, leaf)` for every nonempty proper subset, in
    /// tree order. Empty for a sole participant.
    pub subset_scripts: Vec<(Vec<usize>, ScriptBuf)>,
    /// Recovery voters (quorum minus disputed operator)
    pub recovery_voters: Vec<XOnlyPublicKey>,
    /// Recovery threshold
    pub recovery_threshold: usize,
    /// Network
    pub network: Network,
}

impl LotteryOutput {
    /// Get the script pubkey for use in TxOut
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }

    /// Create a TxOut with specified amount
    pub fn to_tx_out(&self, amount_sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: self.script_pubkey(),
        }
    }

    /// Get the control block for the full-set claim script
    pub fn lottery_control_block(&self) -> Option<bitcoin::taproot::ControlBlock> {
        self.spend_info
            .control_block(&(self.lottery_script.clone(), LeafVersion::TapScript))
    }

    /// The claim leaf of the revealer subset `indices` (ascending participant
    /// indices), if it is a proper subset.
    pub fn subset_leaf(&self, indices: &[usize]) -> Option<&ScriptBuf> {
        self.subset_scripts
            .iter()
            .find(|(idx, _)| idx.as_slice() == indices)
            .map(|(_, s)| s)
    }

    /// Control block for the revealer subset `indices`.
    pub fn subset_control_block(
        &self,
        indices: &[usize],
    ) -> Option<bitcoin::taproot::ControlBlock> {
        let leaf = self.subset_leaf(indices)?.clone();
        self.spend_info
            .control_block(&(leaf, LeafVersion::TapScript))
    }

    /// The four recovery leaves in `(csv_blocks, threshold, script)` tuples,
    /// matching the order they were added in `LotteryScriptBuilder::build`:
    ///   - `(144,  T)`     ~1 day,  primary recovery
    ///   - `(1008, T-1)`   ~1 week
    ///   - `(4032, T-2)`   ~4 weeks
    ///   - `(8064, 1)`     ~8 weeks, the timeout-recovery escape hatch
    ///
    /// Honest voters spend these only into a re-arm round's lottery output
    /// (DEP-06 Phase 4), never to the accused operator.
    pub fn recovery_leaves(&self) -> Vec<(u32, usize, ScriptBuf)> {
        let specs: [(u32, usize); 4] = [
            (144, self.recovery_threshold),
            (1008, self.recovery_threshold.saturating_sub(1).max(1)),
            (4032, self.recovery_threshold.saturating_sub(2).max(1)),
            (crate::constants::TIMEOUT_RECOVERY_CSV_BLOCKS, 1usize),
        ];
        specs
            .iter()
            .filter_map(|(csv, threshold)| {
                let builder = LotteryScriptBuilder::new(
                    self.participants.clone(),
                    self.recovery_voters.clone(),
                    *threshold,
                    self.network,
                );
                builder
                    .build_recovery_script(*csv)
                    .ok()
                    .map(|script| (*csv, *threshold, script))
            })
            .collect()
    }

    /// Control block for a previously-obtained recovery leaf script (from
    /// `recovery_leaves`). Returns `None` if the script isn't in this
    /// output's Taproot tree (caller passed a stale or wrong script).
    pub fn recovery_control_block(
        &self,
        leaf_script: &ScriptBuf,
    ) -> Option<bitcoin::taproot::ControlBlock> {
        self.spend_info
            .control_block(&(leaf_script.clone(), LeafVersion::TapScript))
    }

    /// The x-only recovery voter keys in the sorted order the recovery and
    /// attestation scripts consume them. Index `i` of a `voter_signatures`
    /// argument corresponds to `recovery_voter_order()[i]`.
    pub fn recovery_voter_order(&self) -> Vec<XOnlyPublicKey> {
        let mut sorted = self.recovery_voters.clone();
        sorted.sort_by_key(|k| k.serialize());
        sorted
    }

    /// The winner's index among `preimages` (in member order): the sum of
    /// `LEN - 16` mod their count. Each preimage must be `17..=76` bytes.
    pub fn calculate_winner(preimages: &[Vec<u8>]) -> DepositsResult<usize> {
        let n = preimages.len();
        if n == 0 {
            return Err(DepositsError::InvalidState(
                "Need at least 1 preimage".to_string(),
            ));
        }
        let mut sum: usize = 0;
        for (i, preimage) in preimages.iter().enumerate() {
            let len = preimage.len();
            if !(17..=LOTTERY_MAX_PREIMAGE_LEN).contains(&len) {
                return Err(DepositsError::InvalidState(format!(
                    "Preimage {} has invalid length {} (must be 17..={})",
                    i, len, LOTTERY_MAX_PREIMAGE_LEN
                )));
            }
            sum += len - 16;
        }
        Ok(sum % n)
    }

    /// The winning participant index (into the full canonical order) of the
    /// draw over `indices`, given `preimages` parallel to `indices`.
    pub fn subset_winner(indices: &[usize], preimages: &[Vec<u8>]) -> DepositsResult<usize> {
        if indices.len() != preimages.len() {
            return Err(DepositsError::InvalidState(
                "subset and preimages differ in length".to_string(),
            ));
        }
        Ok(indices[Self::calculate_winner(preimages)?])
    }

    /// Derive a dispute-lottery preimage from a 256-bit seed, independent of
    /// how many arm: length `17 + (seed mod 60)`, bytes the first `length`
    /// bytes of `SHA256("deposits/lottery/preimage/v2" || seed || counter_le32)`
    /// for counter = 0, 1, ... The length (the contribution) is uniform over
    /// `1..=60` up to a `60 / 2^256` bias; at least 17 bytes keeps a
    /// second preimage of another length out of reach (~2^80 under HASH160).
    pub fn derive_lottery_preimage(seed: &[u8; 32]) -> Vec<u8> {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let mut residue: u64 = 0;
        for &byte in seed.iter() {
            residue = (residue * 256 + byte as u64) % (LOTTERY_CONTRIBUTION_RANGE as u64);
        }
        let length = 17 + residue as usize;
        let mut out = Vec::with_capacity(length);
        let mut counter: u32 = 0;
        while out.len() < length {
            let mut eng = sha256::Hash::engine();
            eng.input(b"deposits/lottery/preimage/v2");
            eng.input(seed);
            eng.input(&counter.to_le_bytes());
            let block = sha256::Hash::from_engine(eng).to_byte_array();
            let take = (length - out.len()).min(block.len());
            out.extend_from_slice(&block[..take]);
            counter += 1;
        }
        out
    }

    /// Witness for the full-set claim leaf:
    /// `[sig, preimage_{k-1}, ..., preimage_0, leaf, control]` (a sole
    /// participant's leaf takes only the signature).
    pub fn create_claim_witness(
        &self,
        winner_signature: &[u8; 64],
        preimages: &[Vec<u8>],
    ) -> DepositsResult<Witness> {
        if self.participants.len() > 1 && preimages.len() != self.participants.len() {
            return Err(DepositsError::InvalidState(format!(
                "Expected {} preimages, got {}",
                self.participants.len(),
                preimages.len()
            )));
        }
        let control_block = self
            .lottery_control_block()
            .ok_or_else(|| DepositsError::InvalidState("No control block".to_string()))?;
        let mut witness = Witness::new();
        witness.push(&winner_signature[..]);
        if self.participants.len() > 1 {
            for preimage in preimages.iter().rev() {
                witness.push(preimage);
            }
        }
        witness.push(self.lottery_script.as_bytes());
        witness.push(control_block.serialize());
        Ok(witness)
    }

    /// Witness for the revealer-subset leaf `indices`:
    /// `[sig, preimage_{s_{m-1}}, ..., preimage_{s_0}, vsig_{r-1}, ..., vsig_0,
    /// leaf, control]`. `preimages` parallel `indices`; `voter_signatures`
    /// parallel `recovery_voter_order()`, `None` pushing empty. The input's
    /// `nSequence` must be at least `LOTTERY_REVEAL_CSV_BLOCKS`.
    pub fn create_subset_claim_witness(
        &self,
        indices: &[usize],
        winner_signature: &[u8; 64],
        preimages: &[Vec<u8>],
        voter_signatures: &[Option<[u8; 64]>],
    ) -> DepositsResult<Witness> {
        if preimages.len() != indices.len() {
            return Err(DepositsError::InvalidState(format!(
                "Expected {} preimages for the subset, got {}",
                indices.len(),
                preimages.len()
            )));
        }
        if voter_signatures.len() != self.recovery_voters.len() {
            return Err(DepositsError::InvalidState(format!(
                "Expected {} voter signature slots, got {}",
                self.recovery_voters.len(),
                voter_signatures.len()
            )));
        }
        let leaf = self
            .subset_leaf(indices)
            .ok_or_else(|| {
                DepositsError::InvalidState(format!("No claim leaf for subset {:?}", indices))
            })?
            .clone();
        let control_block = self.subset_control_block(indices).ok_or_else(|| {
            DepositsError::InvalidState(format!("No control block for subset {:?}", indices))
        })?;
        let mut witness = Witness::new();
        witness.push(&winner_signature[..]);
        for preimage in preimages.iter().rev() {
            witness.push(preimage);
        }
        for sig in voter_signatures.iter().rev() {
            match sig {
                Some(s) => witness.push(&s[..]),
                None => witness.push([]),
            }
        }
        witness.push(leaf.as_bytes());
        witness.push(control_block.serialize());
        Ok(witness)
    }
}

// ============================================================================
// Armer share output (DEP-06 §"Arm-and-reveal forfeiture")
// ============================================================================
//
// Each armer in a punitive confiscation receives their slashed-value
// slice in a small per-armer Taproot output that gates the spend on
// the armer revealing the same preimage they committed to in their
// `DisputeArmed`. The output has two leaves:
//
//   Leaf 0 — reveal-claim: `OP_HASH160 <commitment_hash> OP_EQUALVERIFY
//            <armer_xonly> OP_CHECKSIG`. The armer spends by pushing
//            their preimage plus a Schnorr signature.
//
//   Leaf 1 — sweep: `<ARMER_SHARE_SWEEP_CSV_BLOCKS> OP_CSV OP_DROP`
//            followed by the standard CHECKSIGADD threshold pattern over
//            the recovery quorum. After the CSV delay, if the armer
//            never spent the reveal-claim leaf, the recovery quorum
//            sweeps the slice as forfeited.
//
// The output's value is `remainder / N_armers` (integer division; the
// residue is silently absorbed into the miner fee, same dust-handling
// convention the lottery's main confiscation TX uses). Non-armers get
// no slice at all — arming is the gate to a share, and revealing is
// the gate to keeping it.
//
// Operational notes:
//   - Both reveal-claim and sweep are tapscript spends; the internal
//     key is the standard NUMS point so the key path is unspendable.
//   - The recovery_voters set passed in is identical to the lottery's
//     recovery_voters ("quorum minus original_operator"), so each armer
//     remains in the set that can sweep their own slice — but they need
//     `recovery_threshold` cooperation to do so, which they're unlikely
//     to get if their non-reveal is what stranded the lottery.

/// A per-armer slashing-share output. Built once per armer at
/// confiscation time and embedded in the confiscation TX as a P2TR
/// output of value `remainder / N_armers`.
#[derive(Clone, Debug)]
pub struct ArmerShareOutput {
    /// P2TR address — what the confiscation TX pays into.
    pub address: Address,
    /// Taproot spend info — needed to construct either spend witness.
    pub spend_info: TaprootSpendInfo,
    /// The reveal-claim leaf script (Leaf 0).
    pub reveal_script: ScriptBuf,
    /// The recovery-sweep leaf script (Leaf 1).
    pub sweep_script: ScriptBuf,
}

impl ArmerShareOutput {
    /// `script_pubkey` for embedding in a `TxOut`.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address.script_pubkey()
    }

    /// Control block for the reveal-claim leaf.
    pub fn reveal_control_block(&self) -> Option<bitcoin::taproot::ControlBlock> {
        self.spend_info
            .control_block(&(self.reveal_script.clone(), LeafVersion::TapScript))
    }

    /// Control block for the sweep leaf.
    pub fn sweep_control_block(&self) -> Option<bitcoin::taproot::ControlBlock> {
        self.spend_info
            .control_block(&(self.sweep_script.clone(), LeafVersion::TapScript))
    }
}

/// Build the reveal-claim leaf for an armer's share output.
///
/// Script (executes against witness `[<armer_sig>, <preimage>]`, top of stack on the right):
///
/// ```text
/// OP_HASH160 <commitment_hash> OP_EQUALVERIFY
/// <armer_xonly> OP_CHECKSIG
/// ```
///
/// Stack walkthrough:
/// - witness pushes `armer_sig`, then `preimage` on top
/// - `OP_HASH160` hashes `preimage` → `<armer_sig> <hash>`
/// - `<commitment_hash> OP_EQUALVERIFY` checks the hash matches the
///   commitment from the armer's `DisputeArmed`, then drops both →
///   `<armer_sig>`
/// - `<armer_xonly> OP_CHECKSIG` consumes the sig and pushes the
///   verify result.
pub fn build_armer_reveal_leaf(
    commitment_hash: &[u8; 20],
    armer_xonly: &XOnlyPublicKey,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_HASH160)
        .push_slice(commitment_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(armer_xonly)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the recovery-sweep leaf for an armer's share output.
///
/// Mirrors `LotteryScriptBuilder::build_recovery_script` exactly so the
/// signing pattern (sorted keys, first key CHECKSIG, rest CHECKSIGADD,
/// final threshold check) is shared with the lottery's own recovery
/// long-tail. CSV is fixed at `ARMER_SHARE_SWEEP_CSV_BLOCKS`.
pub fn build_armer_sweep_leaf(
    recovery_voters: &[XOnlyPublicKey],
    recovery_threshold: usize,
) -> DepositsResult<ScriptBuf> {
    if recovery_voters.len() < recovery_threshold {
        return Err(DepositsError::InvalidState(format!(
            "Armer-share sweep: not enough recovery voters ({}) for threshold ({})",
            recovery_voters.len(),
            recovery_threshold
        )));
    }
    if recovery_threshold == 0 {
        return Err(DepositsError::InvalidState(
            "Armer-share sweep: recovery_threshold must be >= 1".to_string(),
        ));
    }

    let mut sorted_keys = recovery_voters.to_vec();
    sorted_keys.sort_by_key(|a| a.serialize());

    let mut builder = Builder::new()
        .push_int(ARMER_SHARE_SWEEP_CSV_BLOCKS as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP);

    if recovery_threshold == 1 {
        builder = builder
            .push_x_only_key(&sorted_keys[0])
            .push_opcode(OP_CHECKSIG);
    } else {
        builder = builder
            .push_x_only_key(&sorted_keys[0])
            .push_opcode(OP_CHECKSIG);
        for key in sorted_keys.iter().skip(1) {
            builder = builder.push_x_only_key(key).push_opcode(OP_CHECKSIGADD);
        }
        builder = builder
            .push_int(recovery_threshold as i64)
            .push_opcode(OP_GREATERTHANOREQUAL);
    }

    Ok(builder.into_script())
}

/// Build a per-armer slashing-share Taproot output. Used by the
/// punitive confiscation TX in place of a bare P2TR per cosigner — see
/// the module-level docstring above and DEP-06 §"Punitive split".
pub fn build_armer_share_output(
    armer_xonly: &XOnlyPublicKey,
    commitment_hash: &[u8; 20],
    recovery_voters: &[XOnlyPublicKey],
    recovery_threshold: usize,
    network: Network,
) -> DepositsResult<ArmerShareOutput> {
    let reveal_script = build_armer_reveal_leaf(commitment_hash, armer_xonly);
    let sweep_script = build_armer_sweep_leaf(recovery_voters, recovery_threshold)?;

    // NUMS internal key — same constant the LotteryScriptBuilder uses.
    let nums_point = XOnlyPublicKey::from_slice(&TAPROOT_NUMS_POINT)
        .map_err(|_| DepositsError::InvalidState("Invalid NUMS point".to_string()))?;

    // 2-leaf tree → depth 1 for both leaves.
    let builder = TaprootBuilder::new()
        .add_leaf(1, reveal_script.clone())
        .map_err(|e| {
            DepositsError::InvalidState(format!("Failed to add armer reveal leaf: {:?}", e))
        })?
        .add_leaf(1, sweep_script.clone())
        .map_err(|e| {
            DepositsError::InvalidState(format!("Failed to add armer sweep leaf: {:?}", e))
        })?;

    let secp = Secp256k1::new();
    let spend_info = builder.finalize(&secp, nums_point).map_err(|e| {
        DepositsError::InvalidState(format!("Failed to finalize armer-share tree: {:?}", e))
    })?;

    let address = Address::p2tr(&secp, nums_point, spend_info.merkle_root(), network);

    Ok(ArmerShareOutput {
        address,
        spend_info,
        reveal_script,
        sweep_script,
    })
}

/// Identify the revealer set from a lottery output's claim TX witness.
///
/// The full-set and revealer-subset claims expose every revealing
/// armer's preimage in the witness stack. Walk the stack,
/// HASH160 each item that could be a preimage, and match against the
/// known `armers` list (by commitment_hash). Return the matched armer
/// pubkeys, sorted by xonly bytes for determinism — every honest sweeper
/// constructing the same TX will agree byte-for-byte.
///
/// Items in the witness that aren't preimages (the winner's signature,
/// the leaf script, the control block) won't HASH160 to any commitment,
/// so they're silently skipped.
///
/// Used by `build_forfeit_sweep_tx`'s callers to compute the recipient list
/// per DEP-06 §"Sweep recipients: pro-rata to revealers".
pub fn revealers_from_claim_witness(
    claim_witness: &bitcoin::Witness,
    armers: &[(XOnlyPublicKey, [u8; 20])],
) -> Vec<XOnlyPublicKey> {
    use bitcoin::hashes::{hash160, Hash};

    let mut revealers: Vec<XOnlyPublicKey> = Vec::new();
    for item in claim_witness.iter() {
        // Preimages are 17..=76 bytes. Other items in that range (64-byte
        // signatures) hash to no commitment and are skipped below.
        if item.len() < 17 || item.len() > LOTTERY_MAX_PREIMAGE_LEN {
            continue;
        }
        let h = hash160::Hash::hash(item).to_byte_array();
        for (armer_pk, commit) in armers {
            if *commit == h && !revealers.contains(armer_pk) {
                revealers.push(*armer_pk);
            }
        }
    }
    revealers.sort_by_key(|k| k.serialize());
    revealers
}

/// Build the unsigned sweep TX that spends a forfeited armer-share output
/// pro-rata to the revealers, per DEP-06 §"Sweep recipients: pro-rata to
/// revealers".
///
/// The returned TX is unsigned — the caller is responsible for collecting
/// `recovery_threshold` BIP-340 signatures from the recovery-voter set,
/// building the CHECKSIGADD witness in the same shape `LotteryScriptBuilder::
/// build_recovery_script` produces, and broadcasting.
///
/// Layout:
/// - **One input**: the armer-share UTXO at `armer_share_outpoint`. `nSequence`
///   is set to `ARMER_SHARE_SWEEP_CSV_BLOCKS` so the sweep leaf's `OP_CSV`
///   passes; `nVersion` is 2 (required for BIP-68 relative-locktime semantics).
/// - **N outputs** for `N = revealers.len()` revealers: each gets
///   `(slice_value - fee) / N` to a P2TR keyed by `armer.pubkey` (the
///   `XOnlyPublicKey`). Recipients are sorted by xonly bytes for determinism.
/// - **Edge case `N == 0`**: an error. Nobody revealed, so the slice belongs to
///   the re-arm round (DEP-06 Phase 4), never to the accused operator.
pub fn build_forfeit_sweep_tx(
    armer_share_outpoint: bitcoin::OutPoint,
    slice_value_sats: u64,
    revealers: &[XOnlyPublicKey],
    fee_sats: u64,
    network: Network,
) -> DepositsResult<bitcoin::Transaction> {
    use bitcoin::{Amount, Sequence, Transaction, TxIn, TxOut, Witness};

    if fee_sats >= slice_value_sats {
        return Err(DepositsError::InvalidState(format!(
            "Sweep fee {} >= slice value {}; sweep is uneconomical",
            fee_sats, slice_value_sats
        )));
    }
    let spendable = slice_value_sats - fee_sats;

    let mut outs: Vec<TxOut> = Vec::new();
    let secp = Secp256k1::new();
    if revealers.is_empty() {
        return Err(DepositsError::InvalidState(
            "No revealers: the slice goes to the re-arm round (DEP-06), never the operator"
                .to_string(),
        ));
    }
    let n = revealers.len() as u64;
    let per_revealer = spendable / n;
    // Dust (spendable % n) is silently absorbed into the miner fee, same
    // convention the punitive-split confiscation TX uses.
    let mut sorted = revealers.to_vec();
    sorted.sort_by_key(|k| k.serialize());
    for r in &sorted {
        let addr = bitcoin::Address::p2tr(&secp, *r, None, network);
        outs.push(TxOut {
            value: Amount::from_sat(per_revealer),
            script_pubkey: addr.script_pubkey(),
        });
    }

    Ok(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: armer_share_outpoint,
            script_sig: bitcoin::ScriptBuf::new(),
            // Relative-locktime sequence: nSequence = CSV value satisfies the
            // sweep leaf's OP_CSV. Type bit 22 is clear (block-height), bits
            // 31-25 reserved, low bits carry the value.
            sequence: Sequence::from_height(ARMER_SHARE_SWEEP_CSV_BLOCKS as u16),
            witness: Witness::default(),
        }],
        output: outs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    fn generate_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut secret = [0u8; 32];
        secret[31] = seed;
        let sk = SecretKey::from_slice(&secret).unwrap();
        PublicKey::from_secret_key(&secp, &sk)
    }

    #[test]
    fn test_two_party_voter_set() {
        let tie_breaker = generate_test_pubkey(1);
        let voter2 = generate_test_pubkey(2);

        let voter_set = VoterSet::new(tie_breaker, vec![voter2]);

        assert_eq!(voter_set.total_count(), 2);
        assert_eq!(voter_set.primary_count(), 1);
        assert!(voter_set.tie_breaker().is_some());
    }

    #[test]
    fn test_multi_party_voter_set() {
        let tie_breaker = generate_test_pubkey(1);
        let others: Vec<_> = (2..=5).map(generate_test_pubkey).collect();

        let voter_set = VoterSet::new(tie_breaker, others);

        assert_eq!(voter_set.total_count(), 5);
        assert_eq!(voter_set.primary_count(), 4);
    }

    #[test]
    fn test_default_threshold_config_is_current_ruleset() {
        let config_2 = ThresholdConfig::default_for_voter_count(2);
        assert_eq!(config_2.tiers.len(), 3);
        assert_eq!(config_2.tiers[0].timelock_blocks, 0);
        assert_eq!(config_2.tiers[1].timelock_blocks, 720);
        assert_eq!(config_2.tiers[2].timelock_blocks, 8064);

        let config_7 = ThresholdConfig::default_for_voter_count(7);
        assert_eq!(config_7.tiers.len(), 4);
        assert_eq!(config_7.tiers[0].threshold, 4);
        assert_eq!(config_7.tiers[1].threshold, 3);
        assert_eq!(config_7.tiers[1].timelock_blocks, 720);
    }

    fn test_ledger_hash() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_build_taproot_output() {
        let tie_breaker = generate_test_pubkey(1);
        let others: Vec<_> = (2..=4).map(generate_test_pubkey).collect();
        let voter_set = VoterSet::new(tie_breaker, others);

        let builder = TapscriptReservesBuilder::with_defaults(
            voter_set,
            Network::Regtest,
            test_ledger_hash(),
        );
        let output = builder.build().expect("Should build successfully");

        // Verify we got a valid P2TR address
        assert!(output.script_pubkey().is_p2tr());

        // Verify merkle root exists (we have script paths)
        assert!(output.merkle_root().is_some());

        // Verify ledger hash is stored
        assert_eq!(output.ledger_hash(), test_ledger_hash());
    }

    #[test]
    fn test_tx_out_creation() {
        let tie_breaker = generate_test_pubkey(1);
        let voter_set = VoterSet::new(tie_breaker, vec![generate_test_pubkey(2)]);

        let builder = TapscriptReservesBuilder::with_defaults(
            voter_set,
            Network::Regtest,
            test_ledger_hash(),
        );
        let output = builder.build().expect("Should build successfully");

        let tx_out = output.to_tx_out(100_000);
        assert_eq!(tx_out.value.to_sat(), 100_000);
        assert!(tx_out.script_pubkey.is_p2tr());
    }

    #[test]
    fn test_different_ledger_hashes_produce_different_outputs() {
        let tie_breaker = generate_test_pubkey(1);
        let voter_set = VoterSet::new(tie_breaker, vec![generate_test_pubkey(2)]);

        let hash1 = [0x11; 32];
        let hash2 = [0x22; 32];

        let builder1 =
            TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, hash1);
        let builder2 = TapscriptReservesBuilder::with_defaults(voter_set, Network::Regtest, hash2);

        let output1 = builder1.build().expect("Should build");
        let output2 = builder2.build().expect("Should build");

        // Different ledger hashes should produce different merkle roots
        assert_ne!(output1.merkle_root(), output2.merkle_root());
        // And different addresses
        assert_ne!(output1.address, output2.address);
    }

    // ========================================================================
    // LOTTERY TESTS
    // ========================================================================

    fn generate_x_only_pubkey(seed: u8) -> XOnlyPublicKey {
        generate_test_pubkey(seed).x_only_public_key().0
    }

    fn test_commitment_hash(seed: u8) -> [u8; 20] {
        let mut hash = [0u8; 20];
        hash[0] = seed;
        hash
    }

    fn lottery_fixture(k: usize, voters: usize, threshold: usize) -> LotteryOutput {
        let participants: Vec<LotteryParticipant> = (1..=k as u8)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    format!("tb1p{}", i),
                )
            })
            .collect();
        let recovery: Vec<XOnlyPublicKey> = (0..voters as u8)
            .map(|i| generate_x_only_pubkey(100 + i))
            .collect();
        LotteryScriptBuilder::new(participants, recovery, threshold, Network::Signet)
            .build()
            .unwrap()
    }

    #[test]
    fn calculate_winner_is_sum_mod_count_over_17_to_76() {
        let p = |len: usize| vec![0u8; len];
        assert_eq!(
            LotteryOutput::calculate_winner(&[p(18), p(19), p(17)]).unwrap(),
            0
        );
        assert_eq!(
            LotteryOutput::calculate_winner(&[p(76), p(17)]).unwrap(),
            61 % 2
        );
        assert!(LotteryOutput::calculate_winner(&[p(16), p(17)]).is_err());
        assert!(LotteryOutput::calculate_winner(&[p(77), p(17)]).is_err());
        assert_eq!(LotteryOutput::calculate_winner(&[p(40)]).unwrap(), 0);
        assert_eq!(
            LotteryOutput::subset_winner(&[1, 3, 4], &[p(17), p(17), p(17)]).unwrap(),
            1
        );
    }

    #[test]
    fn derived_preimages_cover_all_sixty_lengths_deterministically() {
        use bitcoin::hashes::{sha256, Hash};
        let mut lengths = std::collections::BTreeSet::new();
        for i in 0u32..2000 {
            let seed = sha256::Hash::hash(&i.to_be_bytes()).to_byte_array();
            let p = LotteryOutput::derive_lottery_preimage(&seed);
            assert!((17..=LOTTERY_MAX_PREIMAGE_LEN).contains(&p.len()));
            assert_eq!(p, LotteryOutput::derive_lottery_preimage(&seed));
            lengths.insert(p.len());
        }
        assert_eq!(lengths.len(), LOTTERY_CONTRIBUTION_RANGE);
    }

    #[test]
    fn subset_indices_by_size_then_lexicographic() {
        assert_eq!(
            lottery_subset_indices(3),
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![1, 2],
                vec![0],
                vec![1],
                vec![2]
            ]
        );
        assert_eq!(lottery_subset_indices(7).len(), 126);
        assert!(lottery_subset_indices(1).is_empty());
    }

    #[test]
    fn lottery_has_full_set_every_proper_subset_and_four_recovery_leaves() {
        for k in 2..=MAX_LOTTERY_PARTICIPANTS {
            let out = lottery_fixture(k, 3, 2);
            assert_eq!(out.subset_scripts.len(), (1 << k) - 2, "k={}", k);
            assert!(out.lottery_control_block().is_some());
            for (idx, leaf) in &out.subset_scripts {
                assert!(out.subset_control_block(idx).is_some());
                // CSV 72 prefix, then the voters' CHECKSIGADD attestation.
                assert!(leaf.as_bytes().starts_with(&[0x01, 0x48, 0xb2, 0x75, 0x20]));
            }
            assert_eq!(out.recovery_leaves().len(), 4);
        }
        // k = 7: 131 leaves, depth 8, a 289-byte control block.
        let out = lottery_fixture(7, 7, 4);
        assert_eq!(
            out.lottery_control_block().unwrap().serialize().len(),
            33 + 32 * 8
        );
    }

    #[test]
    fn sole_participant_gets_a_plain_signature_leaf() {
        let out = lottery_fixture(1, 3, 2);
        assert!(out.subset_scripts.is_empty());
        assert_eq!(out.lottery_script.len(), 34);
    }

    #[test]
    fn too_many_participants_rejected() {
        let participants: Vec<LotteryParticipant> = (1..=8u8)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "t".into(),
                )
            })
            .collect();
        let b = LotteryScriptBuilder::new(
            participants,
            vec![generate_x_only_pubkey(100)],
            1,
            Network::Signet,
        );
        assert!(b.build().is_err());
    }

    #[test]
    fn test_bond_ratio_matches_design_table() {
        // Spot-check the (N-1)/N ratios from CUSTODY_LOTTERY.md's summary table.
        assert_eq!(bond_ratio_for_n(3), (2, 3));
        assert_eq!(bond_ratio_for_n(4), (3, 4));
        assert_eq!(bond_ratio_for_n(5), (4, 5));
        assert_eq!(bond_ratio_for_n(10), (9, 10));
        assert_eq!(bond_ratio_for_n(15), (14, 15));
    }

    #[test]
    fn test_min_bond_rounds_up() {
        // 2/3 of 100 = 66.67 → ceil = 67
        assert_eq!(min_bond_for_disputed_value(3, 100), 67);
        // 4/5 of 100 = 80 (exact)
        assert_eq!(min_bond_for_disputed_value(5, 100), 80);
        // 14/15 of 1_000_000 = 933_333.33 → 933_334
        assert_eq!(min_bond_for_disputed_value(15, 1_000_000), 933_334);
    }

    #[test]
    fn test_check_recovery_quorum_precondition_pass_and_fail() {
        // 5-member quorum, 2 disputants, T_emergency=2 → 3 non-disputing >= 2: ok
        assert!(check_recovery_quorum_precondition(5, 2, 2).is_ok());

        // Same quorum but 4 disputants → only 1 non-disputing < 2: reject
        let err = check_recovery_quorum_precondition(5, 4, 2).unwrap_err();
        match err {
            DepositsError::RecoveryQuorumUnreachable {
                n_quorum,
                n_disputants,
                t_emergency,
            } => {
                assert_eq!(n_quorum, 5);
                assert_eq!(n_disputants, 4);
                assert_eq!(t_emergency, 2);
            }
            _ => panic!("expected RecoveryQuorumUnreachable, got {:?}", err),
        }
    }

    #[test]
    fn test_check_economic_precondition_pass_and_fail() {
        // Fee 1000 sats, threshold 5000 sats. 10000 reserves: ok.
        assert!(check_economic_precondition(10_000, 1_000).is_ok());
        // Right at the boundary: 5000 reserves >= 5000 threshold: ok.
        assert!(check_economic_precondition(5_000, 1_000).is_ok());
        // Below threshold: reject.
        let err = check_economic_precondition(4_999, 1_000).unwrap_err();
        match err {
            DepositsError::LotteryNotEconomical {
                disputed_value,
                min_required,
            } => {
                assert_eq!(disputed_value, 4_999);
                assert_eq!(min_required, 5_000);
            }
            _ => panic!("expected LotteryNotEconomical, got {:?}", err),
        }
    }

    #[test]
    fn test_check_bond_ratio_precondition_pass_and_fail() {
        // N=5, disputed value 100, required = 80. Bond 80: pass.
        assert!(check_bond_ratio_precondition(5, 80, 100).is_ok());
        // Bond 79: reject.
        let err = check_bond_ratio_precondition(5, 79, 100).unwrap_err();
        match err {
            DepositsError::InsufficientBondRatio {
                n,
                actual,
                required,
                numerator,
                denominator,
            } => {
                assert_eq!(n, 5);
                assert_eq!(actual, 79);
                assert_eq!(required, 80);
                assert_eq!(numerator, 4);
                assert_eq!(denominator, 5);
            }
            _ => panic!("expected InsufficientBondRatio, got {:?}", err),
        }
    }

    #[test]
    fn test_forfeit_sweep_tx_satisfies_csv_and_pays_revealers_pro_rata() {
        // The armer-share sweep leaf opens with
        // `<ARMER_SHARE_SWEEP_CSV_BLOCKS> OP_CSV`, so the sweep TX's
        // input MUST carry nSequence = that height (block-height
        // relative locktime, BIP-68) and nVersion = 2, or the script
        // fails at OP_CSV. This pins both — a regression here makes
        // every forfeit sweep unbroadcastable.
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                    [0x11; 32],
                ),
            ),
            vout: 1,
        };
        let revealers = vec![
            generate_x_only_pubkey(21),
            generate_x_only_pubkey(22),
            generate_x_only_pubkey(23),
        ];
        let tx = build_forfeit_sweep_tx(outpoint, 30_000, &revealers, 500, Network::Regtest)
            .expect("sweep tx builds");

        assert_eq!(tx.version, bitcoin::transaction::Version::TWO);
        assert_eq!(tx.input.len(), 1);
        assert_eq!(
            tx.input[0].sequence,
            bitcoin::Sequence::from_height(ARMER_SHARE_SWEEP_CSV_BLOCKS as u16),
            "input nSequence must equal the sweep leaf's CSV height"
        );
        assert!(
            tx.input[0].sequence.is_relative_lock_time(),
            "sequence must enable BIP-68 relative locktime"
        );

        // Pro-rata: (30_000 - 500) / 3 each, residue → fee.
        assert_eq!(tx.output.len(), 3);
        for out in &tx.output {
            assert_eq!(out.value.to_sat(), 29_500 / 3);
        }

        // Determinism: same inputs with revealers passed in a different
        // order produce byte-identical TXs (outputs sorted by xonly key).
        let mut shuffled = revealers.clone();
        shuffled.reverse();
        let tx2 = build_forfeit_sweep_tx(outpoint, 30_000, &shuffled, 500, Network::Regtest)
            .expect("sweep tx builds");
        assert_eq!(
            bitcoin::consensus::encode::serialize(&tx),
            bitcoin::consensus::encode::serialize(&tx2),
            "sweep tx must be order-independent in its revealer input"
        );
    }

    #[test]
    fn test_forfeit_sweep_tx_zero_revealers_refused() {
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                    [0x22; 32],
                ),
            ),
            vout: 2,
        };
        assert!(build_forfeit_sweep_tx(outpoint, 30_000, &[], 500, Network::Regtest).is_err());
    }
}

/// Frozen-builder enforcement: a snapshot test against a canonical input
/// set. If the current `TapscriptReservesBuilder` produces a script that
/// doesn't match `EXPECTED_CURRENT_SCRIPT_HEX`, this test fails — and the
/// failure means a behaviour change that, if shipped, would silently
/// strand any on-chain UTXOs previously built by this code path.
///
/// The freeze-first protocol on failure is documented in
/// [`crate::legacy_builders`]. The short version: before updating the
/// expected hex below, copy the CURRENT behaviour into a new
/// `v_YYYY_MM_DD` submodule in `legacy_builders.rs` with its own pinned
/// fixture test, so future migrations can identify and spend UTXOs from
/// the old code path.
///
/// The canonical inputs mirror snowden's recorded snapshot, so the same
/// (operator, members, ledger_hash) feed both this test and the
/// `v_2026_04_17_pinned_snowden_fixture` test in `legacy_builders` —
/// the two together pin "old behaviour" and "current behaviour" side
/// by side.
#[cfg(test)]
mod frozen_builder_snapshot {
    use super::*;
    use bitcoin::Network;
    use std::str::FromStr;

    /// scriptPubKey hex produced by the current `TapscriptReservesBuilder`
    /// for the canonical input set below.
    ///
    /// **DO NOT update this constant in isolation.** If a code change moves
    /// this hash, the freeze-first protocol applies:
    ///
    ///   1. Identify the PRE-CHANGE script bytes (this constant's current
    ///      value, or `git show HEAD~1:deposits-core/src/tapscript_reserves.rs`).
    ///   2. In `deposits-core/src/legacy_builders.rs`, add a new submodule
    ///      `v_YYYY_MM_DD` (today's date) that REPRODUCES the pre-change
    ///      behaviour exactly. Use `v_2026_04_17` as a template.
    ///   3. Add a pinned-fixture test in `legacy_builders.rs` asserting the
    ///      new submodule produces the pre-change script.
    ///   4. ONLY THEN update this constant to the new behaviour.
    ///
    /// Skipping steps 1-3 means future on-chain UTXOs built by the old code
    /// become unspendable by `migrate-snapshot` / `legacy-recover`.
    // Updated 2026-06-01 with the build_threshold_leaf cleanup that
    // makes `threshold == 1 && !requires_tie_breaker` use CHECKSIGADD
    // over all voters instead of single-CHECKSIG of sorted_keys[0].
    // Per project owner: no v1 deployment exists, so the freeze-first
    // legacy_builders dance was skipped — there are no on-chain UTXOs
    // committed to the prior script shape.
    const EXPECTED_CURRENT_SCRIPT_HEX: &str =
        "51202da85682af56fd62b6fa106e30831a8dbfa05c74259bdca8e0cfad0242ff0e55";

    /// Cross-implementation vector (cl-deposits inspect/lottery-test.lisp pins the
    /// same hex): operator + 6 members (7 voters), `cltv-offset-v2` at
    /// quorum_expiry 800000, signet. Tier 1 is ceil(7/2) - 1 = 3 of 7.
    pub(crate) const CLTV_OFFSET_V2_SEVEN_VOTERS_HEX: &str =
        "51206e92587c6bcdf7bd653c242c1937224eac71bc486fe7c3b9fc6edb70b129dbeb";

    #[test]
    fn cltv_offset_v2_seven_voters_matches_pinned_vector() {
        let key = |i: u8| {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            PublicKey::from_secret_key(
                &secp,
                &bitcoin::secp256k1::SecretKey::from_slice(&[i; 32]).unwrap(),
            )
        };
        let members: Vec<PublicKey> = (2..=7).map(key).collect();
        let voter_set = VoterSet::new(key(1), members);
        let rs = crate::ruleset::lookup("cltv-offset-v2").unwrap();
        let config = (rs.tier_config_factory)(7, 800_000);
        assert_eq!(config.tiers[1].threshold, 3);
        let out = TapscriptReservesBuilder::new(voter_set, config, Network::Signet, [0x5a; 32])
            .build()
            .unwrap();
        let actual = hex::encode(out.script_pubkey().as_bytes());
        assert_eq!(actual, CLTV_OFFSET_V2_SEVEN_VOTERS_HEX);
    }

    #[test]
    fn current_builder_matches_pinned_snapshot() {
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
        let ledger_hash: [u8; 32] =
            hex::decode("7fc25d5245e7003be4f1c4138fbf608bf0ecbb4eca7be4954529d42168473b76")
                .unwrap()
                .try_into()
                .unwrap();
        // Pins the builder's script assembly, independent of any ruleset: the
        // tier table is fixed here (majority 3, minority 1 at 1008, operator at
        // 2016, emergency at 4032).
        let config = ThresholdConfig::custom(vec![
            ThresholdTier::new(3, false, 0, "3-of-4 quorum (immediate)"),
            ThresholdTier::new(1, false, 1008, "1-of-4 quorum (after 1008 blocks)"),
            ThresholdTier::new(1, true, 2016, "Operator only (after 2016 blocks)"),
            ThresholdTier::emergency_recovery(4032),
        ]);
        let builder =
            TapscriptReservesBuilder::new(voter_set, config, Network::Bitcoin, ledger_hash);
        let out = builder.build().expect("build current");
        let actual = hex::encode(out.script_pubkey().as_bytes());
        assert_eq!(
            actual, EXPECTED_CURRENT_SCRIPT_HEX,
            "\n\nTapscriptReservesBuilder output CHANGED for the canonical inputs.\n\
             \n\
             If this is intentional, follow the freeze-first protocol:\n\
             \n\
               1. cp v_2026_04_17 → v_<today> in deposits-core/src/legacy_builders.rs,\n\
                  reproducing the PRE-CHANGE behaviour exactly.\n\
               2. Add a pinned-fixture test in legacy_builders.rs.\n\
               3. Then update EXPECTED_CURRENT_SCRIPT_HEX above to: {}\n\
             \n\
             Skipping steps 1-2 means on-chain UTXOs built before this commit\n\
             become unspendable by migrate-snapshot / legacy-recover.\n",
            actual
        );
    }
}

#[cfg(test)]
mod sole_participant_tests {
    use super::*;

    fn xonly(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk)
            .x_only_public_key()
            .0
    }

    /// DEP-03: one eligible armer takes custody without a draw.
    #[test]
    fn a_sole_participant_claims_with_a_signature_alone() {
        let p = vec![LotteryParticipant::new(xonly(1), [1u8; 20], "tb1p1".into())];
        let out =
            LotteryScriptBuilder::new(p, vec![xonly(21), xonly(22), xonly(23)], 2, Network::Signet)
                .build()
                .unwrap();
        let mut expect = vec![0x20];
        expect.extend_from_slice(&xonly(1).serialize());
        expect.push(0xac);
        assert_eq!(out.lottery_script.as_bytes(), &expect[..]);
        assert!(out.subset_scripts.is_empty());
        assert_eq!(
            LotteryOutput::calculate_winner(&[vec![7u8; 25]]).unwrap(),
            0
        );
        let w = out
            .create_claim_witness(&[9u8; 64], &[vec![7u8; 25]])
            .unwrap();
        assert_eq!(w.len(), 3, "signature, leaf, control block: no preimage");
        assert_eq!(
            out.address.to_string(),
            "tb1p0fnnskqkq6ntxvgt6vyrnxp9spre03dwa7vtxjscedeaz8qtc7cqsqmjlp"
        );
    }
}
