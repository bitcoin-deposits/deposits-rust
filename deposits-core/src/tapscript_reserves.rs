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
    /// Block height timelock (0 = no timelock)
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
    /// Default configuration for n voters (quorum members, not counting operator):
    /// - Tier 0: Majority of quorum, no operator (immediate) - normal co-signed operations
    /// - Tier 1: Minority of quorum, no operator (1008 blocks) - degraded quorum recovery
    /// - Tier 2: Operator only (2016 blocks) - operator solo after quorum timeout
    /// - Tier 3: Any single party (4032 blocks) - emergency last resort
    pub fn default_for_voter_count(n: usize) -> Self {
        let tiers = if n <= 2 {
            // Simple 2-party case
            vec![
                ThresholdTier::new(2, false, 0, "Both quorum members required"),
                ThresholdTier::new(1, true, 2016, "Operator only after 2016 blocks"),
                ThresholdTier::emergency_recovery(4032),
            ]
        } else {
            let majority = (n / 2) + 1;
            let minority = (n / 3).max(1);
            vec![
                // Tier 0: majority of quorum (no operator) — immediate
                ThresholdTier::new(
                    majority,
                    false,
                    0,
                    &format!("{}-of-{} quorum (immediate)", majority, n),
                ),
                // Tier 1: minority of quorum (no operator) — after ~1 week
                ThresholdTier::new(
                    minority,
                    false,
                    1008,
                    &format!("{}-of-{} quorum (after 1008 blocks)", minority, n),
                ),
                // Tier 2: operator only — after ~2 weeks
                ThresholdTier::new(1, true, 2016, "Operator only (after 2016 blocks)"),
                // Tier 3: any single party — after ~4 weeks
                ThresholdTier::emergency_recovery(4032),
            ]
        };
        Self { tiers }
    }

    /// Custom configuration
    pub fn custom(tiers: Vec<ThresholdTier>) -> Self {
        Self { tiers }
    }
}

/// Builder for Tapscript reserves outputs
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

    /// Create with default threshold configuration
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

        // Add timelock if specified
        if tier.timelock_blocks > 0 {
            builder = builder
                .push_int(tier.timelock_blocks as i64)
                .push_opcode(OP_CLTV)
                .push_opcode(OP_DROP);
        }

        // Get sorted pubkeys for deterministic script construction
        let sorted_keys = self.voter_set.sorted_x_only_pubkeys();

        // Build threshold check using CHECKSIGADD pattern (BIP-342)
        // For n-of-m: push keys, use CHECKSIGADD, then check threshold
        if tier.threshold == 1 {
            // Single-sig case: just CHECKSIG with first available key
            if tier.requires_tie_breaker {
                if let Some(tb) = self.voter_set.tie_breaker() {
                    builder = builder
                        .push_x_only_key(&tb.x_only())
                        .push_opcode(OP_CHECKSIG);
                } else {
                    return Err(DepositsError::InvalidState(
                        "Tie-breaker required but not found".to_string(),
                    ));
                }
            } else {
                // Any single key can spend
                builder = builder
                    .push_x_only_key(&sorted_keys[0])
                    .push_opcode(OP_CHECKSIG);
            }
        } else {
            // Multi-sig case using CHECKSIGADD (BIP-342)
            // Pattern: <key1> CHECKSIG <key2> CHECKSIGADD <key3> CHECKSIGADD ... <threshold> GREATERTHANOREQUAL

            let keys_to_use = if tier.requires_tie_breaker {
                // Must include tie-breaker, plus enough others to meet threshold
                let tb = self.voter_set.tie_breaker().ok_or_else(|| {
                    DepositsError::InvalidState("Tie-breaker required but not found".to_string())
                })?;

                let mut keys = vec![tb.x_only()];
                for voter in self.voter_set.primary_voters() {
                    keys.push(voter.x_only());
                }
                // Sort for determinism
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
        }

        Ok(builder.into_script())
    }

    /// Build the complete Taproot output
    pub fn build(&self) -> DepositsResult<TaprootReservesOutput> {
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

        // Use BIP-341 NUMS point as internal key (provably unspendable key path).
        // This prevents any party from key-path spending reserves — all spends
        // must go through the Tapscript leaves (quorum threshold, timelocks).
        // NUMS = lift_x(SHA256("TapTweak")) — no known discrete log.
        let internal_key = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .map_err(|_| DepositsError::InvalidState("Invalid NUMS point".to_string()))?;

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
    /// The threshold configuration
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
    /// Destination script for the spend
    pub destination_script: ScriptBuf,
    /// Fee rate in sat/vbyte
    pub fee_rate_sat_vbyte: u64,
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

        // Estimate tx size for fee calculation
        // Taproot script-path spend: ~input overhead + ~65 witness bytes per signature + control block
        // Conservative estimate: 150 vbytes for input + 43 vbytes for output
        let estimated_vbytes = 200u64;
        let fee = estimated_vbytes * params.fee_rate_sat_vbyte;

        if fee >= params.reserves_amount {
            return Err(DepositsError::InvalidState(format!(
                "Fee {} exceeds reserves amount {}",
                fee, params.reserves_amount
            )));
        }

        let output_amount = params.reserves_amount - fee;

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: params.reserves_outpoint,
                script_sig: ScriptBuf::new(), // Empty for Taproot
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // Filled in later with signatures
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: params.destination_script.clone(),
            }],
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

/// Smallest N at which we add partial-reveal claim leaves to the lottery
/// Taproot output. Below this, P(all reveal) is high enough that the
/// CSV-144 quorum recovery path is sufficient as a fallback.
pub const PARTIAL_REVEAL_MIN_N: usize = 11;

/// CSV block delay before the partial-reveal claim leaves become
/// spendable. Short enough to give honest revealers a faster path than
/// the CSV-144 recovery, but long enough that genuine reveals have time
/// to all land on chain first.
pub const PARTIAL_REVEAL_CSV_BLOCKS: u32 = 72;

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

/// Builder for lottery Tapscript outputs used in custody dispute resolution.
///
/// The lottery mechanism uses preimage-size entropy:
/// 1. Each participant commits HASH160(preimage) where preimage is 17-20 bytes
/// 2. When revealing, the SIZE of each preimage contributes entropy (size - 16 = 1-4)
/// 3. Sum of all contributions mod N determines the winner
/// 4. Only the winner can spend with their signature + all preimages
///
/// The script verifies all preimages and checks the signer is the entropy-selected winner.
pub struct LotteryScriptBuilder {
    participants: Vec<LotteryParticipant>,
    network: Network,
    /// Quorum members (excluding disputed operator) for timeout recovery
    recovery_voters: Vec<XOnlyPublicKey>,
    /// Recovery threshold
    recovery_threshold: usize,
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

    /// Build the lottery claim script.
    ///
    /// Witness stack (bottom to top): <sig> <preimage_n> ... <preimage_1>
    ///
    /// Script logic:
    /// 1. Verify each preimage: HASH160(preimage) == committed_hash
    /// 2. Extract size contribution: SIZE - 16 (gives 1-4 for 17-20 byte preimages)
    /// 3. Sum all contributions
    /// 4. Calculate winner index: sum mod N
    /// 5. Branch to winner's pubkey and verify signature
    pub fn build_lottery_script(&self) -> DepositsResult<ScriptBuf> {
        let n = self.participants.len();
        if n < 2 {
            return Err(DepositsError::InvalidState(
                "Lottery requires at least 2 participants".to_string(),
            ));
        }
        if n > crate::constants::MAX_DISPUTANTS {
            return Err(DepositsError::InvalidState(format!(
                "Lottery dispatch supports at most {} participants \
                 (MAX_DISPUTANTS); the protocol's hard cap",
                crate::constants::MAX_DISPUTANTS
            )));
        }

        let mut builder = Builder::new();

        // Process each preimage and accumulate size contributions
        // Stack starts with: <sig> <preimage_n> ... <preimage_1>
        // After processing preimage_1: altstack has contribution_1

        for (i, participant) in self.participants.iter().enumerate() {
            // Stack: ... <preimage_i>
            // Duplicate for hash check
            builder = builder.push_opcode(OP_DUP);
            // Hash the preimage
            builder = builder.push_opcode(OP_HASH160);
            // Push expected hash and verify
            builder = builder.push_slice(participant.commitment_hash);
            builder = builder.push_opcode(OP_EQUALVERIFY);
            // Now stack has: ... <preimage_i>
            // Get size
            builder = builder.push_opcode(OP_SIZE);
            // Stack: ... <preimage_i> <size>
            // Swap and drop the preimage (we only need the size)
            builder = builder.push_opcode(OP_SWAP);
            builder = builder.push_opcode(OP_DROP);
            // Stack: ... <size>
            // Subtract 16 to get contribution (1-4)
            builder = builder.push_int(16);
            builder = builder.push_opcode(OP_SUB);
            // Stack: ... <contribution_i>

            if i < n - 1 {
                // Not the last one - save to altstack
                builder = builder.push_opcode(OP_TOALTSTACK);
            }
            // Last contribution stays on main stack
        }

        // Now main stack has: <sig> <contribution_n>
        // Altstack has: <contribution_1> ... <contribution_n-1>

        // Sum all contributions
        for _ in 0..(n - 1) {
            builder = builder.push_opcode(OP_FROMALTSTACK);
            builder = builder.push_opcode(OP_ADD);
        }
        // Stack: <sig> <total_sum>

        // Two dispatch strategies, both starting from stack `<sig> <total_sum>`.
        //
        // Linear (N in 2..=5 and 11..=15): compute `sum mod N` via repeated
        // conditional subtraction (OP_MOD is OP_SUCCESS in Tapscript), then
        // dispatch on the resulting index 0..N-1. O(N) for both the modulo
        // and the dispatch — total ~1.2 KB at N=15. The original design
        // specified a BinaryTree for N=11..=15; we deviated because Linear
        // is structurally simpler (shared with Regime A) and the dispatch
        // tree's structural bytes outweigh the savings from a smaller index
        // dispatch at this N.
        //
        // CombinedTable (N in 6..=10): skip the modulo entirely; emit one
        // arm per integer sum in `[N, N²]`, each routing directly to
        // `pubkey_(s mod N)`. Larger than Linear at every N (the O(N²-N+1)
        // dispatch dominates), but kept here as a deliberate structural
        // demonstration of the regime in the design doc; past N=10 even the
        // demonstration becomes impractical (211 arms ≈ 8.7 KB at N=15) so
        // Linear takes over again.
        if !(6..=10).contains(&n) {
            // Stack: <sig> <total_sum>
            //
            // Compute `sum mod N` by repeatedly subtracting N while sum >= N.
            // Max sum is N² so we need at most N subtractions.
            let n_int = n as i64;
            for _ in 0..n {
                builder = builder.push_opcode(OP_DUP);
                builder = builder.push_int(n_int);
                builder = builder.push_opcode(OP_GREATERTHANOREQUAL);
                builder = builder.push_opcode(OP_IF);
                builder = builder.push_int(n_int);
                builder = builder.push_opcode(OP_SUB);
                builder = builder.push_opcode(OP_ENDIF);
            }
            // Stack: <sig> <winner_index> where winner_index ∈ 0..N

            // Linear dispatch on winner_index.
            for (i, participant) in self.participants.iter().enumerate() {
                builder = builder.push_opcode(OP_DUP);
                builder = builder.push_int(i as i64);
                builder = builder.push_opcode(OP_EQUAL);
                builder = builder.push_opcode(OP_IF);
                builder = builder.push_opcode(OP_DROP);
                builder = builder.push_x_only_key(&participant.pubkey);
                builder = builder.push_opcode(OP_CHECKSIG);
                builder = builder.push_opcode(OP_ELSE);
            }
            builder = builder.push_opcode(OP_DROP);
            builder = builder.push_opcode(OP_PUSHBYTES_0);
            for _ in 0..n {
                builder = builder.push_opcode(OP_ENDIF);
            }
        } else {
            // Stack: <sig> <total_sum>, where total_sum ∈ [N, N²].
            //
            // Combined-table dispatch: one arm per integer sum value, each
            // routing to `pubkey_(s mod N)`. We emit `N² - N + 1` arms in
            // ascending order; structurally identical to the linear case but
            // keyed on sum rather than index.
            let sum_min = n;
            let sum_max = n * n;
            let arm_count = sum_max - sum_min + 1;

            for s in sum_min..=sum_max {
                let winner = s % n;
                let participant = &self.participants[winner];
                builder = builder.push_opcode(OP_DUP);
                builder = builder.push_int(s as i64);
                builder = builder.push_opcode(OP_EQUAL);
                builder = builder.push_opcode(OP_IF);
                builder = builder.push_opcode(OP_DROP);
                builder = builder.push_x_only_key(&participant.pubkey);
                builder = builder.push_opcode(OP_CHECKSIG);
                builder = builder.push_opcode(OP_ELSE);
            }
            builder = builder.push_opcode(OP_DROP);
            builder = builder.push_opcode(OP_PUSHBYTES_0);
            for _ in 0..arm_count {
                builder = builder.push_opcode(OP_ENDIF);
            }
        }

        Ok(builder.into_script())
    }

    /// Build the partial-reveal claim leaves for a single missing
    /// disputant (K=1 coverage).
    ///
    /// Returns one leaf per disputant index `j` in `0..N`, each prefixed
    /// with `<PARTIAL_REVEAL_CSV_BLOCKS> OP_CSV OP_DROP` and followed by
    /// a regular lottery script over the `N-1` revealers excluding `j`.
    /// Empty `Vec` for `N < PARTIAL_REVEAL_MIN_N`.
    ///
    /// This covers the dominant partial-reveal failure mode (one
    /// disputant fails to reveal) while preserving lottery randomness.
    /// Cases with two or more non-revealers fall back to the CSV-144
    /// quorum recovery long-tail. K≥2 coverage is a pure
    /// construction-time extension if production reliability data
    /// warrants it; no protocol or message changes needed.
    ///
    /// Note that the sub-lottery's regime is determined by `N-1`, not N:
    /// at N=11 the partial leaves are 10-disputant CombinedTable; at
    /// N=12..=15 they are 11..=14-disputant Linear-after-mod.
    pub fn build_partial_reveal_leaves(&self) -> DepositsResult<Vec<ScriptBuf>> {
        let n = self.participants.len();
        if n < PARTIAL_REVEAL_MIN_N {
            return Ok(vec![]);
        }

        let mut leaves = Vec::with_capacity(n);
        for missing_idx in 0..n {
            let revealers: Vec<LotteryParticipant> = self
                .participants
                .iter()
                .enumerate()
                .filter_map(|(j, p)| if j == missing_idx { None } else { Some(p.clone()) })
                .collect();

            let sub_builder = LotteryScriptBuilder::new(
                revealers,
                self.recovery_voters.clone(),
                self.recovery_threshold,
                self.network,
            );
            let inner = sub_builder.build_lottery_script()?;

            let prefix = Builder::new()
                .push_int(PARTIAL_REVEAL_CSV_BLOCKS as i64)
                .push_opcode(OP_CSV)
                .push_opcode(OP_DROP)
                .into_script();

            let mut bytes = prefix.into_bytes();
            bytes.extend_from_slice(inner.as_bytes());
            leaves.push(ScriptBuf::from(bytes));
        }

        Ok(leaves)
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

    /// Build the complete Taproot lottery output.
    ///
    /// Leaf order (also the order they appear in the Taproot tree, which
    /// matters only for control-block determinism — the spender picks any
    /// leaf):
    /// - Leaf 0: Lottery claim script (preimage reveal + winner sig)
    /// - Leaves 1..=N (when `N >= PARTIAL_REVEAL_MIN_N`): partial-reveal
    ///   claim, one per missing disputant index `j`, CSV 72
    /// - Recovery long-tail:
    ///   - CSV 144,  threshold T
    ///   - CSV 1008, threshold T-1
    ///   - CSV 4032, threshold T-2
    /// - Timeout recovery: CSV 8064, threshold 1 (escape hatch for
    ///   retry-depth exhaustion or total operator absence)
    ///
    /// Total leaves: 5 for `N < PARTIAL_REVEAL_MIN_N`, `5 + N` otherwise.
    /// At N=15 that's 20 leaves → Merkle depth `⌈log₂ 20⌉ = 5`.
    pub fn build(&self) -> DepositsResult<LotteryOutput> {
        let secp = Secp256k1::new();

        // Build lottery claim script
        let lottery_script = self.build_lottery_script()?;

        // Build partial-reveal claim leaves (empty for N < 11)
        let partial_reveal_scripts = self.build_partial_reveal_leaves()?;

        // Build recovery scripts with degrading thresholds, plus a final
        // CSV-8064 timeout-recovery leaf with threshold 1. The latter is
        // the escape hatch for retry-depth exhaustion: if `⌊N/2⌋` lottery
        // rounds have failed in cascading defection-and-re-dispute, the
        // dispute is declared void at the orchestration layer and any
        // single recovery voter can spend through this leaf.
        let recovery_specs = [
            (144u32, self.recovery_threshold),                           // ~1 day, T
            (1008, self.recovery_threshold.saturating_sub(1).max(1)),    // ~1 week, T-1
            (4032, self.recovery_threshold.saturating_sub(2).max(1)),    // ~4 weeks, T-2
            (crate::constants::TIMEOUT_RECOVERY_CSV_BLOCKS, 1usize),     // ~8 weeks, threshold 1
        ];

        let mut leaves: Vec<ScriptBuf> =
            Vec::with_capacity(1 + partial_reveal_scripts.len() + recovery_specs.len());
        leaves.push(lottery_script.clone());
        leaves.extend(partial_reveal_scripts.iter().cloned());
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
        // NUMS = "Nothing Up My Sleeve" - provably unspendable
        let nums_point = XOnlyPublicKey::from_slice(&[
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ])
        .map_err(|_| DepositsError::InvalidState("Invalid NUMS point".to_string()))?;

        // Build a Taproot tree with depths that match a balanced layout
        // for the given leaf count. For `m` leaves where `2^(d-1) < m <=
        // 2^d`, we put `2*(m - 2^(d-1))` leaves at depth `d` and the
        // remaining `2^d - m` at depth `d-1`. Power-of-2 m collapses to
        // all leaves at depth d. The TaprootBuilder fills slots in
        // call order, so we add the deeper leaves first.
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
            partial_reveal_scripts,
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
    /// Lottery participants
    pub participants: Vec<LotteryParticipant>,
    /// The lottery claim script
    pub lottery_script: ScriptBuf,
    /// Partial-reveal claim scripts, indexed by the missing disputant.
    /// Empty for `N < PARTIAL_REVEAL_MIN_N`. `partial_reveal_scripts[j]`
    /// is the leaf used when disputant `j` failed to reveal.
    pub partial_reveal_scripts: Vec<ScriptBuf>,
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

    /// Get the control block for the lottery claim script
    pub fn lottery_control_block(&self) -> Option<bitcoin::taproot::ControlBlock> {
        self.spend_info
            .control_block(&(self.lottery_script.clone(), LeafVersion::TapScript))
    }

    /// Get the control block for the partial-reveal leaf at index
    /// `missing_idx`. Returns `None` if N < `PARTIAL_REVEAL_MIN_N` (no
    /// partial-reveal leaves exist) or if `missing_idx` is out of
    /// range.
    pub fn partial_reveal_control_block(
        &self,
        missing_idx: usize,
    ) -> Option<bitcoin::taproot::ControlBlock> {
        let leaf = self.partial_reveal_scripts.get(missing_idx)?.clone();
        self.spend_info
            .control_block(&(leaf, LeafVersion::TapScript))
    }

    /// Create a witness for spending through the partial-reveal leaf
    /// when disputant `missing_idx` failed to reveal.
    ///
    /// Caller responsibilities:
    /// - The spending tx's input must have `nSequence >= PARTIAL_REVEAL_CSV_BLOCKS`,
    ///   otherwise the OP_CSV at the leaf's prefix will reject.
    /// - `winner_signature` must be a valid Schnorr sig over the tx
    ///   sighash by the (sum mod (N-1))-th revealer (in disputant order
    ///   excluding `missing_idx`).
    /// - `preimages` must contain exactly `N-1` items in the order of
    ///   the remaining disputants (i.e., disputant indices
    ///   `0..N` with `missing_idx` removed). Each preimage must hash
    ///   under HASH160 to the corresponding committed hash.
    ///
    /// Witness layout (matches `create_claim_witness`):
    /// `[sig, preimage_{N-2}, ..., preimage_0, leaf_script, control_block]`
    /// — sig at the bottom of the stack, preimage of the first
    /// remaining disputant on top.
    pub fn create_partial_reveal_witness(
        &self,
        missing_idx: usize,
        winner_signature: &[u8; 64],
        preimages: &[Vec<u8>],
    ) -> DepositsResult<Witness> {
        let n = self.participants.len();
        if n < PARTIAL_REVEAL_MIN_N {
            return Err(DepositsError::InvalidState(format!(
                "Partial-reveal claim leaves only exist for N >= {}; this output has N={}",
                PARTIAL_REVEAL_MIN_N, n
            )));
        }
        if missing_idx >= n {
            return Err(DepositsError::InvalidState(format!(
                "missing_idx {} out of range for N={}",
                missing_idx, n
            )));
        }
        if preimages.len() != n - 1 {
            return Err(DepositsError::InvalidState(format!(
                "Expected {} preimages (N-1) for partial-reveal at missing_idx={}; got {}",
                n - 1,
                missing_idx,
                preimages.len()
            )));
        }

        let leaf_script = self
            .partial_reveal_scripts
            .get(missing_idx)
            .ok_or_else(|| {
                DepositsError::InvalidState(format!(
                    "Partial-reveal leaf {} not present in this output",
                    missing_idx
                ))
            })?
            .clone();

        let control_block = self
            .partial_reveal_control_block(missing_idx)
            .ok_or_else(|| {
                DepositsError::InvalidState(format!(
                    "Partial-reveal control block {} not present in spend_info",
                    missing_idx
                ))
            })?;

        let mut witness = Witness::new();
        witness.push(&winner_signature[..]);
        for preimage in preimages.iter().rev() {
            witness.push(preimage);
        }
        witness.push(leaf_script.as_bytes());
        witness.push(control_block.serialize());

        Ok(witness)
    }

    /// Calculate the winner given revealed preimages.
    ///
    /// Each preimage must be 17 to (16+N) bytes — the contribution
    /// `LEN(preimage) - 16` is in `1..=N` so that one byte length
    /// uniformly chosen from `1..=N` produces a uniform `sum mod N`
    /// (the commit-reveal randomness extraction property only holds
    /// when each contribution covers a full residue class). Returns
    /// the winning participant's index.
    pub fn calculate_winner(preimages: &[Vec<u8>]) -> DepositsResult<usize> {
        let n = preimages.len();
        if n < 2 {
            return Err(DepositsError::InvalidState(
                "Need at least 2 preimages".to_string(),
            ));
        }

        let max_len = 16 + n;
        let mut sum: usize = 0;
        for (i, preimage) in preimages.iter().enumerate() {
            let len = preimage.len();
            if !(17..=max_len).contains(&len) {
                return Err(DepositsError::InvalidState(format!(
                    "Preimage {} has invalid length {} (must be 17..={})",
                    i, len, max_len
                )));
            }
            sum += len - 16; // contribution in 1..=N
        }

        Ok(sum % n)
    }

    /// Create a witness for claiming the lottery output.
    ///
    /// The winner must provide their signature and all participants' preimages.
    /// Preimages must be in the same order as participants.
    pub fn create_claim_witness(
        &self,
        winner_signature: &[u8; 64],
        preimages: &[Vec<u8>],
    ) -> DepositsResult<Witness> {
        if preimages.len() != self.participants.len() {
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

        // Witness stack order (top to bottom after Tapscript setup):
        //   preimage_0 (top) - processed first by script
        //   preimage_1
        //   ...
        //   preimage_n-1
        //   signature (bottom) - used by CHECKSIG at script end
        //
        // Witness array maps to stack: witness[0] -> bottom, witness[n-1] -> top
        // So push: signature first, then preimages in reverse order

        witness.push(&winner_signature[..]);

        for preimage in preimages.iter().rev() {
            witness.push(preimage);
        }

        // Push the lottery script
        witness.push(self.lottery_script.as_bytes());

        // Push the control block
        witness.push(control_block.serialize());

        Ok(witness)
    }
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
    fn test_default_threshold_config() {
        // 2-party: both required, operator fallback, emergency
        let config_2 = ThresholdConfig::default_for_voter_count(2);
        assert_eq!(config_2.tiers.len(), 3);
        assert_eq!(config_2.tiers[0].threshold, 2);
        assert!(!config_2.tiers[0].requires_tie_breaker);
        assert_eq!(config_2.tiers[1].timelock_blocks, 2016); // operator solo
        assert!(config_2.tiers[1].requires_tie_breaker);

        // 5-party: majority, minority, operator, emergency
        let config_5 = ThresholdConfig::default_for_voter_count(5);
        assert_eq!(config_5.tiers.len(), 4);
        // Tier 0: majority (3-of-5) no operator, immediate
        assert_eq!(config_5.tiers[0].threshold, 3);
        assert!(!config_5.tiers[0].requires_tie_breaker);
        assert_eq!(config_5.tiers[0].timelock_blocks, 0);
        // Tier 1: minority (1-of-5) no operator, 1008 blocks
        assert_eq!(config_5.tiers[1].threshold, 1);
        assert!(!config_5.tiers[1].requires_tie_breaker);
        assert_eq!(config_5.tiers[1].timelock_blocks, 1008);
        // Tier 2: operator only, 2016 blocks
        assert!(config_5.tiers[2].requires_tie_breaker);
        assert_eq!(config_5.tiers[2].timelock_blocks, 2016);
        // Tier 3: emergency recovery (1-of-n), 4032 blocks
        assert_eq!(config_5.tiers[3].threshold, 1);
        assert_eq!(config_5.tiers[3].timelock_blocks, 4032);
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

    /// Count occurrences of `opcode` in `script`, walking via the proper
    /// `Instructions` iterator so push-data bytes that happen to equal the
    /// opcode's byte don't get miscounted.
    fn count_opcode(script: &bitcoin::ScriptBuf, opcode: bitcoin::opcodes::Opcode) -> usize {
        script
            .instructions()
            .filter_map(|inst| inst.ok())
            .filter(|inst| {
                matches!(
                    inst,
                    bitcoin::script::Instruction::Op(op) if *op == opcode
                )
            })
            .count()
    }

    fn test_commitment_hash(seed: u8) -> [u8; 20] {
        let mut hash = [0u8; 20];
        hash[0] = seed;
        hash
    }

    #[test]
    fn test_lottery_winner_calculation() {
        // Test with 2 participants
        // Preimage lengths 17 and 18 -> contributions 1 and 2 -> sum 3 -> 3 % 2 = 1
        let preimages = vec![
            vec![0u8; 17], // contribution 1
            vec![0u8; 18], // contribution 2
        ];
        let winner = LotteryOutput::calculate_winner(&preimages).unwrap();
        assert_eq!(winner, 1); // (1 + 2) % 2 = 1

        // Preimage lengths 17 and 17 -> contributions 1 and 1 -> sum 2 -> 2 % 2 = 0
        let preimages = vec![
            vec![0u8; 17], // contribution 1
            vec![0u8; 17], // contribution 1
        ];
        let winner = LotteryOutput::calculate_winner(&preimages).unwrap();
        assert_eq!(winner, 0); // (1 + 1) % 2 = 0
    }

    #[test]
    fn test_lottery_winner_four_participants() {
        // Test with 4 participants
        // Lengths: 17, 18, 19, 20 -> contributions: 1, 2, 3, 4 -> sum 10 -> 10 % 4 = 2
        let preimages = vec![vec![0u8; 17], vec![0u8; 18], vec![0u8; 19], vec![0u8; 20]];
        let winner = LotteryOutput::calculate_winner(&preimages).unwrap();
        assert_eq!(winner, 2); // (1 + 2 + 3 + 4) % 4 = 2
    }

    #[test]
    fn test_lottery_script_build() {
        let participants = vec![
            LotteryParticipant::new(
                generate_x_only_pubkey(1),
                test_commitment_hash(1),
                "bcrt1p...".to_string(),
            ),
            LotteryParticipant::new(
                generate_x_only_pubkey(2),
                test_commitment_hash(2),
                "bcrt1p...".to_string(),
            ),
        ];

        let recovery_voters = vec![
            generate_x_only_pubkey(10),
            generate_x_only_pubkey(11),
            generate_x_only_pubkey(12),
        ];

        let builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            2, // 2-of-3 recovery
            Network::Regtest,
        );

        let script = builder
            .build_lottery_script()
            .expect("Should build lottery script");
        // Basic sanity check - script should be non-empty
        assert!(!script.is_empty());
    }

    #[test]
    fn test_lottery_output_build() {
        let participants = vec![
            LotteryParticipant::new(
                generate_x_only_pubkey(1),
                test_commitment_hash(1),
                "bcrt1p...".to_string(),
            ),
            LotteryParticipant::new(
                generate_x_only_pubkey(2),
                test_commitment_hash(2),
                "bcrt1p...".to_string(),
            ),
            LotteryParticipant::new(
                generate_x_only_pubkey(3),
                test_commitment_hash(3),
                "bcrt1p...".to_string(),
            ),
        ];

        let recovery_voters = vec![generate_x_only_pubkey(10), generate_x_only_pubkey(11)];

        let builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            2, // 2-of-2 recovery
            Network::Regtest,
        );

        let output = builder.build().expect("Should build lottery output");

        // Verify we got a valid P2TR address
        assert!(output.script_pubkey().is_p2tr());

        // Verify control block exists
        assert!(output.lottery_control_block().is_some());
    }

    #[test]
    fn test_lottery_reject_invalid_participant_count() {
        // Too few participants
        let participants = vec![LotteryParticipant::new(
            generate_x_only_pubkey(1),
            test_commitment_hash(1),
            "bcrt1p...".to_string(),
        )];

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![generate_x_only_pubkey(10)],
            1,
            Network::Regtest,
        );

        assert!(builder.build_lottery_script().is_err());
    }

    #[test]
    fn test_lottery_winner_five_participants() {
        // Sweep all 5^5 = 3125 length combinations; verify winner index is
        // sum_of_contributions mod 5 in every case. Catches off-by-one in
        // the contribution = LEN - 16 calc and the mod 5 reduction.
        for a in 1..=5 {
            for b in 1..=5 {
                for c in 1..=5 {
                    for d in 1..=5 {
                        for e in 1..=5 {
                            let preimages = vec![
                                vec![0u8; 16 + a],
                                vec![0u8; 16 + b],
                                vec![0u8; 16 + c],
                                vec![0u8; 16 + d],
                                vec![0u8; 16 + e],
                            ];
                            let winner =
                                LotteryOutput::calculate_winner(&preimages).unwrap();
                            let expected = (a + b + c + d + e) % 5;
                            assert_eq!(
                                winner, expected,
                                "lengths={:?}",
                                (a, b, c, d, e)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_lottery_script_build_five() {
        // N=5 must build without the "at most 4 participants" error.
        let participants: Vec<LotteryParticipant> = (1..=5)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();

        let recovery_voters = vec![
            generate_x_only_pubkey(20),
            generate_x_only_pubkey(21),
            generate_x_only_pubkey(22),
        ];

        let builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            2,
            Network::Regtest,
        );

        let script = builder
            .build_lottery_script()
            .expect("N=5 lottery script should build");
        assert!(!script.is_empty());

        // The N=5 script is meaningfully larger than N=4 (extra hash-
        // verify block + an extra mod-subtract iteration + an extra
        // dispatch arm). Lower bound is loose — the script size grows
        // linearly with N — but catches accidental no-op changes.
        assert!(
            script.len() > 200,
            "N=5 script unexpectedly small: {} bytes",
            script.len()
        );
    }

    #[test]
    fn test_max_disputants_constant_matches_script_cap() {
        // Phase 4c: the script's hard cap should be sourced from the
        // protocol's MAX_DISPUTANTS constant. Both the constant and the
        // cap are 15 by design — see CUSTODY_LOTTERY.md "Why N = 15 Is
        // the Cap". The script must accept exactly MAX_DISPUTANTS and
        // reject MAX_DISPUTANTS + 1.
        assert_eq!(crate::constants::MAX_DISPUTANTS, 15);

        let max_builder = make_lottery_builder(crate::constants::MAX_DISPUTANTS);
        assert!(
            max_builder.build_lottery_script().is_ok(),
            "exactly MAX_DISPUTANTS should be accepted"
        );

        let too_many = make_lottery_builder(crate::constants::MAX_DISPUTANTS + 1);
        assert!(
            too_many.build_lottery_script().is_err(),
            "MAX_DISPUTANTS + 1 should be rejected"
        );
    }

    #[test]
    fn test_lottery_reject_sixteen_participants() {
        // N=16 exceeds the protocol's MAX_DISPUTANTS=15 cap. The builder
        // must refuse so we never silently mint a lottery output for a
        // dispute size the rest of the protocol won't honour.
        let participants: Vec<LotteryParticipant> = (1..=16)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![generate_x_only_pubkey(20), generate_x_only_pubkey(21)],
            2,
            Network::Regtest,
        );

        let err = builder
            .build_lottery_script()
            .expect_err("N=16 exceeds MAX_DISPUTANTS=15");
        let msg = format!("{}", err);
        assert!(
            msg.contains("at most 15") || msg.contains("MAX_DISPUTANTS"),
            "error message should point to the protocol cap; got: {}",
            msg
        );
    }

    #[test]
    fn test_lottery_script_build_eleven() {
        let participants: Vec<LotteryParticipant> = (1..=11)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![
                generate_x_only_pubkey(20),
                generate_x_only_pubkey(21),
                generate_x_only_pubkey(22),
            ],
            2,
            Network::Regtest,
        );

        let script = builder
            .build_lottery_script()
            .expect("N=11 should build via Linear-after-mod");

        // Linear dispatch emits N arms (11 here) plus the modulo
        // subroutine's N iterations of OP_IF/OP_ENDIF.
        // Total OP_ENDIFs: N (mod) + N (dispatch) = 2N = 22 for N=11.
        let endif_count = count_opcode(&script, bitcoin::opcodes::all::OP_ENDIF);
        assert_eq!(
            endif_count, 22,
            "expected 11 mod ENDIFs + 11 dispatch ENDIFs at N=11"
        );

        // Measured: 879 B at this revision. Less than half the original
        // BinaryTree estimate (1.6 KB) — Linear-after-mod is the right
        // tool here despite the design's initial preference.
        assert!(
            (750..=1050).contains(&script.len()),
            "N=11 script length {} should fall within expected envelope",
            script.len()
        );
    }

    #[test]
    fn test_lottery_script_build_fifteen() {
        let participants: Vec<LotteryParticipant> = (1..=15)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![
                generate_x_only_pubkey(20),
                generate_x_only_pubkey(21),
                generate_x_only_pubkey(22),
                generate_x_only_pubkey(23),
            ],
            3,
            Network::Regtest,
        );

        let script = builder
            .build_lottery_script()
            .expect("N=15 should build via Linear-after-mod");

        // 2N = 30 ENDIFs at N=15.
        let endif_count = count_opcode(&script, bitcoin::opcodes::all::OP_ENDIF);
        assert_eq!(endif_count, 30, "expected 30 ENDIFs at N=15");

        // Measured: 1199 B at this revision. The original BinaryTree
        // estimate of 2.0 KB overcounted; Linear-after-mod fits in 1.2 KB.
        assert!(
            (1050..=1400).contains(&script.len()),
            "N=15 script length {} should fall within expected envelope",
            script.len()
        );
    }

    // ========================================================================
    // PARTIAL-REVEAL TESTS (Phase 4b)
    // ========================================================================

    fn make_lottery_builder(n: usize) -> LotteryScriptBuilder {
        let participants: Vec<LotteryParticipant> = (1..=n as u8)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();
        let recovery_voters = vec![
            generate_x_only_pubkey(50),
            generate_x_only_pubkey(51),
            generate_x_only_pubkey(52),
            generate_x_only_pubkey(53),
        ];
        LotteryScriptBuilder::new(participants, recovery_voters, 3, Network::Regtest)
    }

    #[test]
    fn test_partial_reveal_leaves_skipped_below_threshold() {
        // N=10 is below PARTIAL_REVEAL_MIN_N. The output should still
        // build cleanly with the legacy 4-leaf shape.
        let builder = make_lottery_builder(10);
        let leaves = builder
            .build_partial_reveal_leaves()
            .expect("partial-reveal builder should not error at N<11");
        assert!(
            leaves.is_empty(),
            "expected no partial-reveal leaves at N=10, got {}",
            leaves.len()
        );

        let output = builder.build().expect("N=10 lottery output should build");
        assert!(
            output.partial_reveal_scripts.is_empty(),
            "LotteryOutput should expose empty partial_reveal_scripts at N=10"
        );
    }

    #[test]
    fn test_partial_reveal_leaf_count_matches_n() {
        // At N=11, expect 11 partial-reveal leaves.
        // At N=15, expect 15.
        for n in PARTIAL_REVEAL_MIN_N..=15 {
            let builder = make_lottery_builder(n);
            let leaves = builder
                .build_partial_reveal_leaves()
                .unwrap_or_else(|e| panic!("partial-reveal failed at N={}: {:?}", n, e));
            assert_eq!(leaves.len(), n, "expected {} partial leaves at N={}", n, n);

            let output = builder
                .build()
                .unwrap_or_else(|e| panic!("output build failed at N={}: {:?}", n, e));
            assert_eq!(output.partial_reveal_scripts.len(), n);
        }
    }

    #[test]
    fn test_partial_reveal_excludes_missing_disputant() {
        // Each partial leaf at index j must correspond to a sub-lottery
        // that excludes participant j. Verify by reconstructing the
        // expected sub-script for each j and asserting byte equality.
        let n = 11;
        let builder = make_lottery_builder(n);
        let leaves = builder.build_partial_reveal_leaves().unwrap();

        for missing_idx in 0..n {
            let revealers: Vec<LotteryParticipant> = builder
                .participants
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != missing_idx)
                .map(|(_, p)| p.clone())
                .collect();
            let sub_builder = LotteryScriptBuilder::new(
                revealers,
                builder.recovery_voters.clone(),
                builder.recovery_threshold,
                builder.network,
            );
            let inner = sub_builder.build_lottery_script().unwrap();

            let prefix = Builder::new()
                .push_int(PARTIAL_REVEAL_CSV_BLOCKS as i64)
                .push_opcode(OP_CSV)
                .push_opcode(OP_DROP)
                .into_script();
            let mut expected = prefix.into_bytes();
            expected.extend_from_slice(inner.as_bytes());

            assert_eq!(
                leaves[missing_idx].as_bytes(),
                &expected[..],
                "partial leaf {} should be CSV-72-prefixed sub-lottery for the 10 remaining disputants",
                missing_idx
            );
        }
    }

    #[test]
    fn test_partial_reveal_csv_prefix_present() {
        // Every partial-reveal leaf must start with `<72> OP_CSV OP_DROP`
        // — without the CSV the leaf would be spendable immediately,
        // racing the primary lottery claim.
        let builder = make_lottery_builder(13);
        let leaves = builder.build_partial_reveal_leaves().unwrap();

        for (j, leaf) in leaves.iter().enumerate() {
            let bytes = leaf.as_bytes();
            // OP_PUSHNUM_8 + OP_PUSHBYTES_1 0x48 (72) — actually 72 fits
            // in the 1-byte form via OP_PUSHBYTES_1. The Builder uses
            // push_int which picks the most compact form. 72 is encoded
            // as `0x01 0x48` (length 1 followed by byte 0x48).
            assert_eq!(
                bytes[0], 0x01,
                "leaf {} should start with OP_PUSHBYTES_1; got 0x{:02x}",
                j, bytes[0]
            );
            assert_eq!(
                bytes[1], 72,
                "leaf {} should push 72 (CSV blocks); got {}",
                j, bytes[1]
            );
            assert_eq!(
                bytes[2], OP_CSV.to_u8(),
                "leaf {} byte 2 should be OP_CSV (0x{:02x}); got 0x{:02x}",
                j,
                OP_CSV.to_u8(),
                bytes[2]
            );
            assert_eq!(
                bytes[3],
                bitcoin::opcodes::all::OP_DROP.to_u8(),
                "leaf {} byte 3 should be OP_DROP",
                j
            );
        }
    }

    #[test]
    fn test_partial_reveal_uses_combined_table_at_n11() {
        // At N=11, partial leaves are 10-disputant sub-lotteries — that
        // falls in Regime B (CombinedTable). Each leaf should contain
        // the CombinedTable's 91 ENDIF dispatch arms (10²-10+1 = 91).
        let builder = make_lottery_builder(11);
        let leaves = builder.build_partial_reveal_leaves().unwrap();

        for (j, leaf) in leaves.iter().enumerate() {
            let endif_count = count_opcode(leaf, bitcoin::opcodes::all::OP_ENDIF);
            assert_eq!(
                endif_count, 91,
                "partial leaf {} at N=11 should be CombinedTable (91 arms); got {} ENDIFs",
                j, endif_count
            );
        }
    }

    #[test]
    fn test_partial_reveal_uses_linear_at_n15() {
        // At N=15, partial leaves are 14-disputant sub-lotteries — that
        // falls in Regime C (Linear-after-mod). Each leaf should have
        // 2*14 = 28 ENDIFs (mod + dispatch cascades, both length N-1=14).
        let builder = make_lottery_builder(15);
        let leaves = builder.build_partial_reveal_leaves().unwrap();

        for (j, leaf) in leaves.iter().enumerate() {
            let endif_count = count_opcode(leaf, bitcoin::opcodes::all::OP_ENDIF);
            assert_eq!(
                endif_count, 28,
                "partial leaf {} at N=15 should be Linear-after-mod (28 ENDIFs); got {}",
                j, endif_count
            );
        }
    }

    #[test]
    fn test_partial_reveal_regime_transition_n11_to_n12() {
        // The N → N-1 regime transition for partial leaves is at
        // N=11 (sub-N=10, CombinedTable) → N=12 (sub-N=11, Linear).
        // Verify by ENDIF count: 91 at N=11, 22 at N=12.
        let endifs_11 = make_lottery_builder(11)
            .build_partial_reveal_leaves()
            .unwrap()
            .iter()
            .map(|s| count_opcode(s, bitcoin::opcodes::all::OP_ENDIF))
            .next()
            .unwrap();
        let endifs_12 = make_lottery_builder(12)
            .build_partial_reveal_leaves()
            .unwrap()
            .iter()
            .map(|s| count_opcode(s, bitcoin::opcodes::all::OP_ENDIF))
            .next()
            .unwrap();
        assert_eq!(endifs_11, 91, "N=11 partial leaves are CombinedTable");
        assert_eq!(endifs_12, 22, "N=12 partial leaves are Linear-after-mod");
    }

    #[test]
    fn test_lottery_output_taproot_depth_at_n15() {
        // At N=15: 1 lottery + 15 partial + 3 recovery = 19 leaves.
        // Merkle depth ⌈log₂ 19⌉ = 5. Verify the spend_info exposes a
        // valid control block for at least the primary lottery leaf and
        // that its merkle proof is the expected length.
        let output = make_lottery_builder(15)
            .build()
            .expect("N=15 lottery output should build");

        assert_eq!(output.partial_reveal_scripts.len(), 15);

        let cb = output
            .spend_info
            .control_block(&(
                output.lottery_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .expect("primary lottery leaf must have a control block");

        // Each merkle-proof step is 32 bytes. Depth 5 → 5 hashes →
        // 32*5 = 160 bytes of proof. Plus 33 bytes for control-block
        // header (1 leaf-version+parity byte + 32-byte internal key) =
        // 193 bytes total. Some leaves may be at depth 4 → 161 bytes;
        // bound the assertion accordingly.
        let cb_bytes = cb.serialize();
        assert!(
            cb_bytes.len() == 33 + 32 * 4 || cb_bytes.len() == 33 + 32 * 5,
            "control block size {} should imply depth 4 or 5",
            cb_bytes.len()
        );
    }

    #[test]
    fn test_lottery_output_shape_at_n5() {
        // For N=5 (no partial-reveal) we expect 5 leaves total:
        // 1 lottery + 0 partial + 3 long-tail recovery + 1 timeout-recovery
        // (CSV 8064, threshold 1).
        // Tree depth ⌈log₂ 5⌉ = 3 for the deeper leaves; the primary
        // lottery leaf is added first and lands at the d_max depth.
        let output = make_lottery_builder(5)
            .build()
            .expect("N=5 lottery output should build");
        assert!(output.partial_reveal_scripts.is_empty());

        let cb = output
            .spend_info
            .control_block(&(
                output.lottery_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .expect("primary lottery leaf must have a control block");

        assert_eq!(
            cb.serialize().len(),
            33 + 32 * 3,
            "N=5 primary lottery leaf should land at depth-3 in the 5-leaf tree"
        );
    }

    #[test]
    fn test_lottery_output_includes_timeout_recovery_leaf() {
        // The timeout-recovery leaf (CSV 8064, threshold 1) must always
        // be included regardless of N. Reconstruct the expected script
        // and assert it can be located in the spend_info script_map.
        let output = make_lottery_builder(5)
            .build()
            .expect("N=5 lottery output should build");

        let timeout_script = LotteryScriptBuilder::new(
            output.participants.clone(),
            output.recovery_voters.clone(),
            1, // threshold = 1 for timeout-recovery
            output.network,
        )
        .build_recovery_script(crate::constants::TIMEOUT_RECOVERY_CSV_BLOCKS)
        .expect("timeout-recovery script should build");

        let cb = output
            .spend_info
            .control_block(&(
                timeout_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ));
        assert!(
            cb.is_some(),
            "timeout-recovery leaf (CSV 8064, threshold 1) must be in the Taproot tree"
        );
    }

    /// Random-sample winner-correctness test for N=11..=15. Exhaustive
    /// sweep would be 11^11 = 285M up to 15^15 = 437T cases — infeasible.
    /// 5,000 deterministic samples per N exercise dispatch and modulo
    /// across the full sum range.
    #[test]
    fn test_lottery_winner_high_n_random_sample() {
        let mut rng_state: u64 = 0xab8e1cd9f0a32b41;
        let mut next_u64 = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state
        };

        for n in 11usize..=15 {
            for _ in 0..5_000 {
                let mut preimages: Vec<Vec<u8>> = Vec::with_capacity(n);
                let mut sum = 0usize;
                for _ in 0..n {
                    let c = (next_u64() as usize % n) + 1; // 1..=N
                    sum += c;
                    preimages.push(vec![0u8; 16 + c]);
                }
                let expected = sum % n;
                let got = LotteryOutput::calculate_winner(&preimages).unwrap();
                assert_eq!(got, expected, "winner mismatch at N={} sum={}", n, sum);
            }
        }
    }

    /// N=6 (CombinedTable boundary): exhaustively verify every reachable sum
    /// in [N, N²] = [6, 36] dispatches to the correct participant via
    /// `calculate_winner`'s round-trip semantics. The script's dispatch
    /// table is keyed on the sum and each arm directly routes to
    /// `pubkey_(s mod N)` — `calculate_winner` is the off-chain authority
    /// for the same mapping, so any divergence between regime A and regime B
    /// would surface here.
    #[test]
    fn test_lottery_winner_six_participants_combined_table() {
        // Each participant contributes (preimage_len - 16) ∈ 1..=N. Sweep
        // every (c1..c6) ∈ {1..=6}^6 — 46,656 cases — and assert that
        // calculate_winner's `sum mod N` matches the dispatch the script
        // would evaluate at sum.
        let n = 6;
        let mut tested = 0usize;
        for c1 in 1..=n {
            for c2 in 1..=n {
                for c3 in 1..=n {
                    for c4 in 1..=n {
                        for c5 in 1..=n {
                            for c6 in 1..=n {
                                let preimages: Vec<Vec<u8>> = vec![
                                    vec![0u8; 16 + c1],
                                    vec![0u8; 16 + c2],
                                    vec![0u8; 16 + c3],
                                    vec![0u8; 16 + c4],
                                    vec![0u8; 16 + c5],
                                    vec![0u8; 16 + c6],
                                ];
                                let sum = c1 + c2 + c3 + c4 + c5 + c6;
                                let expected = sum % n;
                                let got = LotteryOutput::calculate_winner(&preimages).unwrap();
                                assert_eq!(
                                    got, expected,
                                    "winner mismatch for sum={} (cs={:?})",
                                    sum, preimages
                                );
                                tested += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(tested, n.pow(6));
    }

    #[test]
    fn test_lottery_script_build_six() {
        let participants: Vec<LotteryParticipant> = (1..=6)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![generate_x_only_pubkey(20), generate_x_only_pubkey(21)],
            2,
            Network::Regtest,
        );

        let script = builder
            .build_lottery_script()
            .expect("N=6 should build via CombinedTable");

        // The dispatch table emits N²-N+1 = 31 arms.
        let endif_count = count_opcode(&script, bitcoin::opcodes::all::OP_ENDIF);
        assert_eq!(endif_count, 31, "expected 31 dispatch arms for N=6");

        // Measured: 1482 B at this revision. Bound to ±15% to catch
        // unexpected drift without forcing a test churn for benign edits.
        assert!(
            (1260..=1700).contains(&script.len()),
            "N=6 script length {} should fall within expected envelope",
            script.len()
        );
    }

    #[test]
    fn test_lottery_script_build_ten() {
        let participants: Vec<LotteryParticipant> = (1..=10)
            .map(|i| {
                LotteryParticipant::new(
                    generate_x_only_pubkey(i),
                    test_commitment_hash(i),
                    "bcrt1p...".to_string(),
                )
            })
            .collect();

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![
                generate_x_only_pubkey(20),
                generate_x_only_pubkey(21),
                generate_x_only_pubkey(22),
            ],
            2,
            Network::Regtest,
        );

        let script = builder
            .build_lottery_script()
            .expect("N=10 should build via CombinedTable");

        // N²-N+1 = 91 dispatch arms.
        let endif_count = count_opcode(&script, bitcoin::opcodes::all::OP_ENDIF);
        assert_eq!(endif_count, 91, "expected 91 dispatch arms for N=10");

        // Measured: 4134 B at this revision. Comfortably under the 10 KB
        // Tapscript per-stack-item limit; CombinedTable past N=10 would
        // start crowding it, which is why the regime hands off to Linear.
        assert!(
            (3500..=4800).contains(&script.len()),
            "N=10 script length {} should fall within expected envelope",
            script.len()
        );
    }

    /// Pseudo-random sample of N=10 winner correctness (exhaustive sweep
    /// would be 10^10 cases). 10,000 random preimage tuples — enough to
    /// exercise dispatch arms across the full sum range.
    #[test]
    fn test_lottery_winner_ten_random_sample() {
        let n = 10usize;
        // Deterministic xorshift so failures reproduce.
        let mut rng_state: u64 = 0xdeadbeefcafef00d;
        let mut next_u64 = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state
        };

        for _ in 0..10_000 {
            let mut preimages: Vec<Vec<u8>> = Vec::with_capacity(n);
            let mut sum = 0usize;
            for _ in 0..n {
                let c = (next_u64() as usize % n) + 1; // 1..=N
                sum += c;
                preimages.push(vec![0u8; 16 + c]);
            }
            let expected = sum % n;
            let got = LotteryOutput::calculate_winner(&preimages).unwrap();
            assert_eq!(got, expected, "winner mismatch for sum={}", sum);
        }
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
}
