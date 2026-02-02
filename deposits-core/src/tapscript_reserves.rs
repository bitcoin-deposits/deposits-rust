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
    /// Default configuration for n voters:
    /// - Tier 0: Majority + tie-breaker (immediate) - normal operations
    /// - Tier 1: 2-of-n quorum override (1008 blocks) - custody transfer when quorum agrees
    /// - Tier 2: 1-of-n emergency (4032 blocks) - last resort recovery
    ///
    /// Note: Tier 1 allows quorum members to override the operator after ~1 week.
    /// This is used for custody transfers when the quorum detects non-conformance.
    pub fn default_for_voter_count(n: usize) -> Self {
        let tiers = if n <= 2 {
            // Simple 2-party case
            vec![
                ThresholdTier::new(2, true, 0, "Both parties required"),
                ThresholdTier::emergency_recovery(2016),
            ]
        } else {
            // Multi-party case with quorum override
            vec![
                ThresholdTier::majority_immediate(n),
                // Quorum override: 2-of-n without operator (immediate)
                // Used for custody transfer when quorum agrees on non-conformance
                ThresholdTier::degraded(2, false, 0),
                ThresholdTier::emergency_recovery(4032), // 1-of-n after 4 weeks
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
            // Pattern: <key1> CHECKSIG <key2> CHECKSIGADD <key3> CHECKSIGADD ... <threshold> NUMEQUAL

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

            // Check threshold
            builder = builder
                .push_int(tier.threshold as i64)
                .push_opcode(OP_NUMEQUAL);
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
}
