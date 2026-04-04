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

use bitcoin::{
    Network, ScriptBuf, TxOut, Amount, Witness,
    taproot::{TaprootBuilder, TaprootSpendInfo, LeafVersion},
    secp256k1::{Secp256k1, XOnlyPublicKey, PublicKey},
    Address,
};
use bitcoin::opcodes::all::*;
use bitcoin::script::Builder;
use serde::{Deserialize, Serialize};

use crate::error::{DepositsError, DepositsResult};

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
        Self { pubkey, is_tie_breaker }
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
        keys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
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
    pub fn new(threshold: usize, requires_tie_breaker: bool, timelock_blocks: u32, description: &str) -> Self {
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
        Self::new(majority, true, 0, "Majority immediate (tie-breaker required)")
    }

    /// Degraded tier with reduced threshold after timelock
    pub fn degraded(threshold: usize, requires_tie_breaker: bool, timelock_blocks: u32) -> Self {
        let desc = if requires_tie_breaker {
            format!("{}-of-n after {} blocks (tie-breaker required)", threshold, timelock_blocks)
        } else {
            format!("{}-of-n after {} blocks", threshold, timelock_blocks)
        };
        Self::new(threshold, requires_tie_breaker, timelock_blocks, &desc)
    }

    /// Emergency single-party recovery after extended timelock
    pub fn emergency_recovery(timelock_blocks: u32) -> Self {
        Self::new(1, false, timelock_blocks, &format!("Emergency recovery after {} blocks", timelock_blocks))
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
                ThresholdTier::new(majority, false, 0,
                    &format!("{}-of-{} quorum (immediate)", majority, n)),
                // Tier 1: minority of quorum (no operator) — after ~1 week
                ThresholdTier::new(minority, false, 1008,
                    &format!("{}-of-{} quorum (after 1008 blocks)", minority, n)),
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
    pub fn new(voter_set: VoterSet, config: ThresholdConfig, network: Network, ledger_hash: [u8; 32]) -> Self {
        Self { voter_set, config, network, ledger_hash }
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
            .push_slice(&self.ledger_hash)
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
                        "Tie-breaker required but not found".to_string()
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
                let tb = self.voter_set.tie_breaker()
                    .ok_or_else(|| DepositsError::InvalidState(
                        "Tie-breaker required but not found".to_string()
                    ))?;

                let mut keys = vec![tb.x_only()];
                for voter in self.voter_set.primary_voters() {
                    keys.push(voter.x_only());
                }
                // Sort for determinism
                keys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
                keys
            } else {
                sorted_keys.clone()
            };

            if keys_to_use.len() < tier.threshold {
                return Err(DepositsError::InvalidState(
                    format!("Not enough keys ({}) for threshold ({})", keys_to_use.len(), tier.threshold)
                ));
            }

            // First key uses CHECKSIG
            builder = builder
                .push_x_only_key(&keys_to_use[0])
                .push_opcode(OP_CHECKSIG);

            // Subsequent keys use CHECKSIGADD
            for key in keys_to_use.iter().skip(1) {
                builder = builder
                    .push_x_only_key(key)
                    .push_opcode(OP_CHECKSIGADD);
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
                "No threshold tiers configured".to_string()
            ));
        }

        // Add the commitment leaf (embeds ledger hash, unspendable)
        let commitment_leaf = self.build_commitment_leaf();

        // Create internal key from tie-breaker (enables key-path spending if all agree)
        let internal_key = self.voter_set.tie_breaker()
            .map(|v| v.x_only())
            .unwrap_or_else(|| self.voter_set.sorted_x_only_pubkeys()[0]);

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
                1  // Binary tree: both at depth 1
            } else {
                (i + 1) as u8
            };

            builder = builder.add_leaf(depth, script.clone())
                .map_err(|e| DepositsError::InvalidState(
                    format!("Failed to add Tapscript leaf: {:?}", e)
                ))?;
        }

        // Add commitment leaf at the deepest level (paired with last spending leaf)
        let commitment_depth = if total_leaves == 2 {
            1
        } else {
            num_spending_leaves as u8
        };
        builder = builder.add_leaf(commitment_depth, commitment_leaf)
            .map_err(|e| DepositsError::InvalidState(
                format!("Failed to add commitment leaf: {:?}", e)
            ))?;

        let spend_info = builder.finalize(&secp, internal_key)
            .map_err(|e| DepositsError::InvalidState(
                format!("Failed to finalize Taproot tree: {:?}", e)
            ))?;

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
    pub fn control_block_for_tier(&self, tier_index: usize) -> Option<bitcoin::taproot::ControlBlock> {
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

        let script = builder.build_threshold_leaf(&self.config.tiers[tier_index]).ok()?;
        self.spend_info.control_block(&(script, LeafVersion::TapScript))
    }

    /// Get the ledger hash committed to in this output
    pub fn ledger_hash(&self) -> [u8; 32] {
        self.ledger_hash
    }

    /// Verify that an on-chain script_pubkey matches this Taproot reserves output
    ///
    /// This is used by the watchtower/recovery system to verify that a force-closed
    /// channel's reserves output commits to the expected ledger state.
    pub fn verify_script_pubkey(&self, on_chain_script: &ScriptBuf) -> bool {
        &self.script_pubkey() == on_chain_script
    }
}

/// Verify that an on-chain script_pubkey corresponds to a Taproot reserves output
/// with the given parameters. Returns true if the script matches.
///
/// This is the primary verification method for force-close recovery:
/// 1. Watchtower detects force-close with reserves output
/// 2. Watchtower reconstructs expected Taproot address using known parameters
/// 3. If scripts match, the ledger_hash in the reserves is verified
///
/// Note: The ledger_hash cannot be directly extracted from a P2TR script_pubkey.
/// Verification works by reconstruction and comparison.
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
        use bitcoin::{Transaction, TxIn, TxOut, Sequence, Witness};

        // Estimate tx size for fee calculation
        // Taproot script-path spend: ~input overhead + ~65 witness bytes per signature + control block
        // Conservative estimate: 150 vbytes for input + 43 vbytes for output
        let estimated_vbytes = 200u64;
        let fee = estimated_vbytes * params.fee_rate_sat_vbyte;

        if fee >= params.reserves_amount {
            return Err(DepositsError::InvalidState(
                format!("Fee {} exceeds reserves amount {}", fee, params.reserves_amount)
            ));
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
            .map_err(|e| DepositsError::InvalidState(
                format!("Failed to compute sighash: {:?}", e)
            ))?;

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
                    witness.push(&[]);
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
        tx.input[0].witness = Self::create_checksigadd_witness(
            signatures,
            leaf_script,
            control_block,
        );
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
        Self { pubkey, commitment_hash, target_reserves }
    }
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
        Self { participants, recovery_voters, recovery_threshold, network }
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
                "Lottery requires at least 2 participants".to_string()
            ));
        }
        if n > 4 {
            return Err(DepositsError::InvalidState(
                "Lottery supports at most 4 participants".to_string()
            ));
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
            builder = builder.push_slice(&participant.commitment_hash);
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

        // Calculate winner index: sum mod N
        // NOTE: OP_MOD (0x97) is OP_SUCCESS in Tapscript, so we must emulate it
        // For n=2: mod 2 = AND 1
        // For n=3: use conditional subtraction
        // For n=4: mod 4 = AND 3
        // NOTE: OP_AND (0x84) and OP_OR (0x85) are OP_SUCCESS in Tapscript,
        // so we CANNOT use bitwise AND for mod 2/4.  Use conditional
        // subtraction (same approach as mod 3) for all cases.
        match n {
            2 => {
                // mod 2 via conditional subtraction.
                // Sum range for 2 participants: 2..8.  Repeatedly subtract 2.
                // Max iterations: 8/2 = 4 (sum 8 → 6 → 4 → 2 → 0).
                for _ in 0..4 {
                    builder = builder.push_opcode(OP_DUP);
                    builder = builder.push_int(2);
                    builder = builder.push_opcode(OP_GREATERTHANOREQUAL);
                    builder = builder.push_opcode(OP_IF);
                    builder = builder.push_int(2);
                    builder = builder.push_opcode(OP_SUB);
                    builder = builder.push_opcode(OP_ENDIF);
                }
            }
            3 => {
                // mod 3 via conditional subtraction.
                // Sum range for 3 participants: 3..12.  Repeatedly subtract 3.
                // Max iterations: 12/3 = 4.
                for _ in 0..4 {
                    builder = builder.push_opcode(OP_DUP);
                    builder = builder.push_int(3);
                    builder = builder.push_opcode(OP_GREATERTHANOREQUAL);
                    builder = builder.push_opcode(OP_IF);
                    builder = builder.push_int(3);
                    builder = builder.push_opcode(OP_SUB);
                    builder = builder.push_opcode(OP_ENDIF);
                }
            }
            4 => {
                // mod 4 via conditional subtraction.
                // Sum range for 4 participants: 4..16.  Repeatedly subtract 4.
                // Max iterations: 16/4 = 4.
                for _ in 0..4 {
                    builder = builder.push_opcode(OP_DUP);
                    builder = builder.push_int(4);
                    builder = builder.push_opcode(OP_GREATERTHANOREQUAL);
                    builder = builder.push_opcode(OP_IF);
                    builder = builder.push_int(4);
                    builder = builder.push_opcode(OP_SUB);
                    builder = builder.push_opcode(OP_ENDIF);
                }
            }
            _ => {
                return Err(DepositsError::InvalidState(
                    format!("Unsupported participant count for lottery: {}", n)
                ));
            }
        }
        // Stack: <sig> <winner_index>

        // Branch based on winner index
        // Use nested IF/ELSE for each possible winner
        for (i, participant) in self.participants.iter().enumerate() {
            builder = builder.push_opcode(OP_DUP);
            builder = builder.push_int(i as i64);
            builder = builder.push_opcode(OP_EQUAL);
            builder = builder.push_opcode(OP_IF);
            // Winner is participant i
            builder = builder.push_opcode(OP_DROP); // Drop the index
            builder = builder.push_x_only_key(&participant.pubkey);
            builder = builder.push_opcode(OP_CHECKSIG);
            builder = builder.push_opcode(OP_ELSE);
        }

        // If none matched (shouldn't happen with valid mod), fail
        builder = builder.push_opcode(OP_DROP);
        builder = builder.push_opcode(OP_PUSHBYTES_0); // OP_FALSE

        // Close all the IF/ELSE branches
        for _ in 0..n {
            builder = builder.push_opcode(OP_ENDIF);
        }

        Ok(builder.into_script())
    }

    /// Build a recovery script for when revelation stalls.
    ///
    /// After CSV timeout, the quorum (minus disputed operator) can recover funds.
    pub fn build_recovery_script(&self, csv_blocks: u32) -> DepositsResult<ScriptBuf> {
        if self.recovery_voters.len() < self.recovery_threshold {
            return Err(DepositsError::InvalidState(
                format!("Not enough recovery voters ({}) for threshold ({})",
                    self.recovery_voters.len(), self.recovery_threshold)
            ));
        }

        let mut builder = Builder::new();

        // Add CSV timelock
        builder = builder
            .push_int(csv_blocks as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);

        // Sort keys for deterministic script
        let mut sorted_keys = self.recovery_voters.clone();
        sorted_keys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

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
                builder = builder
                    .push_x_only_key(key)
                    .push_opcode(OP_CHECKSIGADD);
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
    /// Structure:
    /// - Leaf 0: Lottery claim script (preimage reveal + winner sig)
    /// - Leaf 1: Recovery (CSV 144 blocks, threshold T)
    /// - Leaf 2: Recovery (CSV 1008 blocks, threshold T-1)
    /// - Leaf 3: Recovery (CSV 4032 blocks, threshold T-2)
    pub fn build(&self) -> DepositsResult<LotteryOutput> {
        let secp = Secp256k1::new();

        // Build lottery claim script
        let lottery_script = self.build_lottery_script()?;

        // Build recovery scripts with degrading thresholds
        let recovery_scripts = vec![
            (144, self.recovery_threshold),                                    // ~1 day
            (1008, self.recovery_threshold.saturating_sub(1).max(1)),          // ~1 week
            (4032, self.recovery_threshold.saturating_sub(2).max(1)),          // ~4 weeks
        ];

        let mut leaves: Vec<ScriptBuf> = vec![lottery_script.clone()];
        for (csv, threshold) in recovery_scripts {
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
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
            0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
            0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
            0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
        ]).map_err(|_| DepositsError::InvalidState("Invalid NUMS point".to_string()))?;

        // Build Taproot tree with balanced structure
        let mut builder = TaprootBuilder::new();

        // Add leaves at appropriate depths for 4 leaves (balanced tree)
        // Depth 2 for all 4 leaves in a balanced binary tree
        for script in &leaves {
            builder = builder.add_leaf(2, script.clone())
                .map_err(|e| DepositsError::InvalidState(
                    format!("Failed to add Tapscript leaf: {:?}", e)
                ))?;
        }

        let spend_info = builder.finalize(&secp, nums_point)
            .map_err(|e| DepositsError::InvalidState(
                format!("Failed to finalize Taproot tree: {:?}", e)
            ))?;

        let address = Address::p2tr(&secp, nums_point, spend_info.merkle_root(), self.network);

        Ok(LotteryOutput {
            address,
            spend_info,
            participants: self.participants.clone(),
            lottery_script,
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
        self.spend_info.control_block(&(self.lottery_script.clone(), LeafVersion::TapScript))
    }

    /// Calculate the winner given revealed preimages.
    ///
    /// Each preimage must be 17-20 bytes. Returns the index of the winner.
    pub fn calculate_winner(preimages: &[Vec<u8>]) -> DepositsResult<usize> {
        let n = preimages.len();
        if n < 2 {
            return Err(DepositsError::InvalidState("Need at least 2 preimages".to_string()));
        }

        let mut sum: usize = 0;
        for (i, preimage) in preimages.iter().enumerate() {
            let len = preimage.len();
            if len < 17 || len > 20 {
                return Err(DepositsError::InvalidState(
                    format!("Preimage {} has invalid length {} (must be 17-20)", i, len)
                ));
            }
            sum += len - 16; // Contribution is 1-4
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
            return Err(DepositsError::InvalidState(
                format!("Expected {} preimages, got {}", self.participants.len(), preimages.len())
            ));
        }

        let control_block = self.lottery_control_block()
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
        let config_2 = ThresholdConfig::default_for_voter_count(2);
        assert_eq!(config_2.tiers.len(), 2);

        let config_5 = ThresholdConfig::default_for_voter_count(5);
        assert_eq!(config_5.tiers.len(), 3);
        // Tier 0: majority (3-of-5) + tie-breaker
        assert_eq!(config_5.tiers[0].threshold, 3);
        assert!(config_5.tiers[0].requires_tie_breaker);
        // Tier 1: quorum override (2-of-n without tie-breaker, immediate)
        assert_eq!(config_5.tiers[1].threshold, 2);
        assert!(!config_5.tiers[1].requires_tie_breaker);
        assert_eq!(config_5.tiers[1].timelock_blocks, 0);
        // Tier 2: emergency recovery (1-of-n)
        assert_eq!(config_5.tiers[2].threshold, 1);
    }

    fn test_ledger_hash() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn test_build_taproot_output() {
        let tie_breaker = generate_test_pubkey(1);
        let others: Vec<_> = (2..=4).map(generate_test_pubkey).collect();
        let voter_set = VoterSet::new(tie_breaker, others);

        let builder = TapscriptReservesBuilder::with_defaults(voter_set, Network::Regtest, test_ledger_hash());
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

        let builder = TapscriptReservesBuilder::with_defaults(voter_set, Network::Regtest, test_ledger_hash());
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

        let builder1 = TapscriptReservesBuilder::with_defaults(voter_set.clone(), Network::Regtest, hash1);
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
        let preimages = vec![
            vec![0u8; 17],
            vec![0u8; 18],
            vec![0u8; 19],
            vec![0u8; 20],
        ];
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

        let script = builder.build_lottery_script().expect("Should build lottery script");
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

        let recovery_voters = vec![
            generate_x_only_pubkey(10),
            generate_x_only_pubkey(11),
        ];

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
        let participants = vec![
            LotteryParticipant::new(
                generate_x_only_pubkey(1),
                test_commitment_hash(1),
                "bcrt1p...".to_string(),
            ),
        ];

        let builder = LotteryScriptBuilder::new(
            participants,
            vec![generate_x_only_pubkey(10)],
            1,
            Network::Regtest,
        );

        assert!(builder.build_lottery_script().is_err());
    }
}
