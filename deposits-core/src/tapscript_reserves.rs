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
    /// is responsible for picking the right value: `legacy` returns
    /// plain literals (1008/2016/4032), `cltv-offset-v2` returns
    /// `quorum_expiry + offset`. The script builder treats this as
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
    /// Build a [`ThresholdConfig`] for `n` voters under the
    /// **legacy** ruleset — the shape every pre-`protocol_version`
    /// QuorumBegin on chain commits to. `quorum_expiry` is ignored
    /// (legacy tiers use plain literal CLTV targets).
    ///
    /// Provided as a thin compatibility shim so existing call sites
    /// that haven't been ruleset-aware yet keep compiling. New code
    /// should call `crate::ruleset::lookup(name)` and run that
    /// ruleset's `tier_config_factory(n, quorum_expiry)` instead —
    /// this routes through the version the ledger committed to in
    /// its QuorumBegin.
    pub fn default_for_voter_count(n: usize) -> Self {
        (crate::ruleset::LEGACY.tier_config_factory)(n, 0)
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

    /// Create with the **legacy** ruleset's threshold configuration.
    /// Compatibility shim for call sites not yet ruleset-aware. New
    /// code should look up the ledger's active ruleset and run its
    /// `tier_config_factory` directly so v2 ledgers don't get the
    /// wrong cascade.
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
                0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35,
                0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf,
                0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
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
    let builder = TapscriptReservesBuilder::with_defaults(
        voter_set,
        network,
        expected_ledger_hash,
    );
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

/// Smallest N at which we add partial-reveal claim leaves to the lottery
/// Taproot output. The technical floor is `N = 3` — a single-non-revealer
/// sub-lottery needs `N - 1 >= 2` participants, which the lottery script
/// itself requires. Below the floor, the single-non-revealer case collapses
/// straight to the CSV-144 quorum-recovery cascade.
///
/// Historically this was `11`, on the reasoning that `P(all reveal)` was
/// high enough at small N that the recovery long-tail covered the rare
/// stall. Under the production policy cap `MAX_QUORUM_SIZE_POLICY = 7`
/// (see `constants.rs`) that left every deployable Q ∈ {3, 5, 7} with
/// *no* partial-reveal path at all — `K = 1` non-revealers (the dominant
/// failure mode per `CUSTODY_LOTTERY.md`) had no fast claim, so a single
/// withholding loser forced the entire quorum onto the CSV-144 cascade.
/// Dropping the floor to `3` makes the partial-reveal path available at
/// every supported Q.
pub const PARTIAL_REVEAL_MIN_N: usize = 3;

/// CSV block delay before the partial-reveal claim leaves become
/// spendable. Short enough to give honest revealers a faster path than
/// the CSV-144 recovery, but long enough that genuine reveals have time
/// to all land on chain first.
pub const PARTIAL_REVEAL_CSV_BLOCKS: u32 = 72;

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

/// Builder for lottery Tapscript outputs used in custody dispute resolution.
///
/// The lottery mechanism uses preimage-size entropy:
/// 1. Each participant commits HASH160(preimage) where preimage is `17..=16+N` bytes.
/// 2. When revealing, the SIZE of each preimage contributes entropy
///    (`size - 16` yields a value in `1..=N`).
/// 3. Sum of all contributions mod N determines the winner.
/// 4. Only the winner can spend with their signature + all preimages.
///
/// The script verifies all preimages, enforces `LEN(preimage) ∈ [17, 16+N]`
/// per-participant (so a committer who chose an out-of-range preimage cannot
/// poison the sum-mod-N draw for the rest of the quorum), and checks the
/// signer is the entropy-selected winner.
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
    /// 2. Enforce per-preimage size bounds: `17 <= LEN(preimage) <= 16+N`
    ///    (rejects out-of-range commitments that would skew sum-mod-N)
    /// 3. Extract size contribution: `LEN - 16` (yields a value in `1..=N`)
    /// 4. Sum all contributions
    /// 5. Calculate winner index: `sum mod N`
    /// 6. Branch to winner's pubkey and verify signature
    pub fn build_lottery_script(&self) -> DepositsResult<ScriptBuf> {
        let n = self.participants.len();
        self.build_lottery_script_with_bounds_n(n)
    }

    /// Build the lottery claim script with explicit preimage-length
    /// bounds. The bounds are `17..=16+bounds_n`. Primary lotteries pass
    /// `bounds_n = participants.len()`; partial-reveal sub-lotteries pass
    /// the *parent* `N` so commitments that are valid under the parent
    /// contract continue to spend the sub-leaf.
    fn build_lottery_script_with_bounds_n(
        &self,
        bounds_n: usize,
    ) -> DepositsResult<ScriptBuf> {
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
        if bounds_n < n || bounds_n > crate::constants::MAX_DISPUTANTS {
            return Err(DepositsError::InvalidState(format!(
                "bounds_n {} must satisfy participants.len() ({}) \
                 <= bounds_n <= MAX_DISPUTANTS ({})",
                bounds_n,
                n,
                crate::constants::MAX_DISPUTANTS
            )));
        }

        let mut builder = Builder::new();

        // Process each preimage and accumulate size contributions
        // Stack starts with: <sig> <preimage_n> ... <preimage_1>
        // After processing preimage_1: altstack has contribution_1

        // Per-participant bounds for the revealed preimage. The committer
        // chose `commitment_hash = HASH160(preimage)` at arming time; the
        // hash check below pins which preimage they must reveal, but it
        // does NOT constrain how long that preimage is — the committer
        // could have hashed a 1-byte or 10_000-byte string and the hash
        // check would still pass at reveal. We use `LEN(preimage) - 16`
        // as the per-participant contribution to the winner-selection
        // sum, so an out-of-range LEN poisons the lottery for the entire
        // quorum (the attacker shifts `sum mod N` to a winner of their
        // choosing). Force `LEN(preimage) ∈ [17, 16+N]` in script so the
        // reveal fails on the attacker's leaf rather than corrupting the
        // shared draw.
        let max_len: i64 = 16 + (bounds_n as i64);
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
            // Bounds: size >= 17 (so contribution >= 1)
            builder = builder.push_opcode(OP_DUP);
            builder = builder.push_int(17);
            builder = builder.push_opcode(OP_GREATERTHANOREQUAL);
            builder = builder.push_opcode(OP_VERIFY);
            // Bounds: size <= 16+N (so contribution <= N)
            builder = builder.push_opcode(OP_DUP);
            builder = builder.push_int(max_len);
            builder = builder.push_opcode(OP_LESSTHANOREQUAL);
            builder = builder.push_opcode(OP_VERIFY);
            // Stack: ... <preimage_i> <size>
            // Swap and drop the preimage (we only need the size)
            builder = builder.push_opcode(OP_SWAP);
            builder = builder.push_opcode(OP_DROP);
            // Stack: ... <size>
            // Subtract 16 to get contribution (1..=N)
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
    /// Empty `Vec` for `N < PARTIAL_REVEAL_MIN_N` (= 3) — the sub-lottery
    /// needs at least 2 participants to dispatch.
    ///
    /// This covers the dominant partial-reveal failure mode (one
    /// disputant fails to reveal) while preserving lottery randomness.
    /// Cases with two or more non-revealers fall back to the CSV-144
    /// quorum recovery long-tail. K≥2 coverage is a pure
    /// construction-time extension if production reliability data
    /// warrants it; no protocol or message changes needed.
    ///
    /// Note that the sub-lottery's regime is determined by `N-1`, not N:
    /// at N=3..=6 the partial leaves are 2..=5-disputant Linear; at
    /// N=7..=11 they are 6..=10-disputant CombinedTable; at N=12..=15
    /// they are 11..=14-disputant Linear-after-mod.
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
            // Use the parent `N` for size bounds: each surviving
            // participant's commitment was chosen under the parent-N
            // contract (preimage length in `17..=16+N`), so the
            // sub-lottery must accept the same range even though its own
            // participant count is `N-1`.
            let inner = sub_builder.build_lottery_script_with_bounds_n(n)?;

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
    /// Total leaves: 5 for `N = 2` (below `PARTIAL_REVEAL_MIN_N = 3`),
    /// `5 + N` otherwise. At N=15 that's 20 leaves → Merkle depth
    /// `⌈log₂ 20⌉ = 5`.
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
    /// Empty for `N < PARTIAL_REVEAL_MIN_N` (= 3). `partial_reveal_scripts[j]`
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

    /// The four recovery leaves in `(csv_blocks, threshold, script)` tuples,
    /// matching the order they were added in `LotteryScriptBuilder::build`:
    ///   - `(144,  T)`     ~1 day,  primary recovery
    ///   - `(1008, T-1)`   ~1 week
    ///   - `(4032, T-2)`   ~4 weeks
    ///   - `(8064, 1)`     ~8 weeks, the timeout-recovery escape hatch
    ///
    /// `T` is `self.recovery_threshold`. The lower thresholds clamp at 1 via
    /// `saturating_sub(N).max(1)`, mirroring `build`'s `recovery_specs`.
    ///
    /// Spenders pick whichever leaf they can satisfy: an honest sweep takes
    /// the lowest CSV that their available signer set meets the threshold for.
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

    /// The x-only recovery voter keys in the sorted order the recovery leaf
    /// script consumes them (script encodes the first key with CHECKSIG, then
    /// the rest with CHECKSIGADD; both `build_recovery_script` and this helper
    /// sort by `.serialize()`). Use this to build the `signatures: &[Option<
    /// [u8; 64]>]` arg to `ReservesSpendBuilder::create_checksigadd_witness`
    /// — index `i` of that arg corresponds to the key at `recovery_voter_order()[i]`.
    pub fn recovery_voter_order(&self) -> Vec<XOnlyPublicKey> {
        let mut sorted = self.recovery_voters.clone();
        sorted.sort_by_key(|k| k.serialize());
        sorted
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

    /// Derive a dispute-lottery preimage of the correct length from a
    /// 256-bit entropy seed and the disputant count `n`.
    ///
    /// # Why this exists
    ///
    /// The lottery selects the winner from the *byte lengths* of the
    /// revealed preimages: `contribution_i = LEN(preimage_i) - 16`, and
    /// `winner = (Σ contribution_i) mod n`. For the commit-reveal
    /// randomness-extraction property to hold, an honest disputant must
    /// choose its length uniformly from `[17, 16+n]` — equivalently its
    /// contribution uniformly from the complete residue system
    /// `{1, .., n}` mod `n`. See `CUSTODY_LOTTERY.md` §"Why this is fair".
    ///
    /// A prior implementation returned the raw 32-byte HMAC directly as
    /// the preimage. Length 32 is out of range for every realistic `n`
    /// (the on-chain claim leaf enforces `LEN ∈ [17, 16+n]` via `OP_SIZE`
    /// and [`calculate_winner`] rejects it), so the fast lottery-claim
    /// leaf was unspendable. This helper fixes that: same seed → same
    /// length → same bytes → same `HASH160`, at both arm-time (commitment)
    /// and reveal-time.
    ///
    /// # Length derivation (uniform over `[17, 16+n]`)
    ///
    /// The 256-bit seed is reduced mod `n` to pick the contribution:
    ///
    /// ```text
    /// contribution = (seed mod n) + 1     // uniform-ish in [1, n]
    /// length       = 16 + contribution    // in [17, 16+n]
    /// ```
    ///
    /// With a 256-bit uniform seed and `n <= MAX_DISPUTANTS = 15`, the
    /// modulo bias away from perfectly-uniform is at most
    /// `n / 2^256 < 2^-252`, i.e. cryptographically negligible: no
    /// residue class is favoured in any way an adversary could exploit.
    ///
    /// # Preimage bytes (anti-grinding)
    ///
    /// The preimage's *content* must (a) be a deterministic function of
    /// the seed so arm and reveal agree byte-for-byte, and (b) carry
    /// enough entropy that an adversary cannot, after seeing the target
    /// length, grind a *different* preimage of a *different* length with
    /// the same `HASH160` (a length swap would move the sum). The bytes
    /// are the first `length` bytes of `SHA256("deposits/lottery/preimage/v1"
    /// || seed || n)`, re-expanded by re-hashing if `length` ever exceeds
    /// 32 (it never does for `n <= 15`, where `length <= 31`, but the
    /// expansion keeps the helper total-correct for the full domain).
    /// Because `length >= 17`, the preimage carries at least 136 bits of
    /// entropy — HASH160's 160-bit output means a second-preimage of a
    /// different length costs ~2^80 work, far beyond any disputant.
    ///
    /// `n` must be in `2..=MAX_DISPUTANTS`; the returned preimage always
    /// satisfies `calculate_winner`'s per-preimage bound for that `n` and
    /// the on-chain leaf built with the same `bounds_n = n`.
    pub fn derive_lottery_preimage(seed: &[u8; 32], n: usize) -> DepositsResult<Vec<u8>> {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        if !(2..=crate::constants::MAX_DISPUTANTS).contains(&n) {
            return Err(DepositsError::InvalidState(format!(
                "lottery preimage derivation needs 2 <= n <= {} (got {})",
                crate::constants::MAX_DISPUTANTS,
                n
            )));
        }

        // Reduce the 256-bit seed mod n via Horner's method over bytes,
        // most-significant first: seed mod n = (((b0)*256 + b1)*256 + ...) mod n.
        // This is exact for the full 256-bit value without bignum types.
        let mut residue: u64 = 0;
        for &byte in seed.iter() {
            residue = (residue * 256 + byte as u64) % (n as u64);
        }
        let contribution = (residue as usize) + 1; // in [1, n]
        let length = 16 + contribution; // in [17, 16+n]

        // Deterministic preimage bytes: SHA256(domain || seed || n_le),
        // expanded by counter re-hashing if length > 32 (unreachable for
        // n <= 15, kept for total correctness).
        let mut out = Vec::with_capacity(length);
        let mut counter: u32 = 0;
        while out.len() < length {
            let mut eng = sha256::Hash::engine();
            eng.input(b"deposits/lottery/preimage/v1");
            eng.input(seed);
            eng.input(&(n as u64).to_le_bytes());
            eng.input(&counter.to_le_bytes());
            let block = sha256::Hash::from_engine(eng).to_byte_array();
            let take = (length - out.len()).min(block.len());
            out.extend_from_slice(&block[..take]);
            counter += 1;
        }
        debug_assert_eq!(out.len(), length);
        Ok(out)
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
            DepositsError::InvalidState(format!(
                "Failed to add armer reveal leaf: {:?}",
                e
            ))
        })?
        .add_leaf(1, sweep_script.clone())
        .map_err(|e| {
            DepositsError::InvalidState(format!(
                "Failed to add armer sweep leaf: {:?}",
                e
            ))
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
/// Both the primary-lottery claim and the partial-reveal claims expose every
/// participating armer's preimage in the witness stack. Walk the stack,
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
        // The legal preimage length range is `17..=16+N` per CUSTODY_LOTTERY.md.
        // N is at most MAX_DISPUTANTS = 15, so the upper bound is 31. Skip items
        // outside this range to avoid hashing the signature (64), leaf script
        // (variable larger), or control block (33+).
        if item.len() < 17 || item.len() > 16 + crate::constants::MAX_DISPUTANTS {
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
/// - **Edge case `N == 0`**: a single output for `slice_value - fee` to
///   `fallback_recipient` (typically the original operator's xonly key, mirroring
///   the respectful-confiscation change output). If `fallback_recipient` is None,
///   returns an error rather than producing an output the script couldn't agree
///   on. The lottery already failed if no one revealed, so this branch is
///   degenerate-but-defined.
pub fn build_forfeit_sweep_tx(
    armer_share_outpoint: bitcoin::OutPoint,
    slice_value_sats: u64,
    revealers: &[XOnlyPublicKey],
    fee_sats: u64,
    fallback_recipient: Option<&XOnlyPublicKey>,
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
        let dest = fallback_recipient.ok_or_else(|| {
            DepositsError::InvalidState(
                "No revealers and no fallback recipient — refusing to construct \
                 a sweep TX with no honest payee. Pass the original operator's \
                 xonly key as fallback per DEP-06."
                    .to_string(),
            )
        })?;
        let addr = bitcoin::Address::p2tr(&secp, *dest, None, network);
        outs.push(TxOut {
            value: Amount::from_sat(spendable),
            script_pubkey: addr.script_pubkey(),
        });
    } else {
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
    fn test_default_threshold_config_returns_legacy() {
        // `default_for_voter_count` is a compat shim that delegates to
        // the LEGACY ruleset (it doesn't know quorum_expiry). New
        // call sites should look up the ledger's active ruleset
        // directly — see `crate::ruleset`. This test pins the legacy
        // shape so a regression here would break script reconstruction
        // for every pre-`protocol_version` QuorumBegin on chain.
        let config_2 = ThresholdConfig::default_for_voter_count(2);
        assert_eq!(config_2.tiers.len(), 3);
        assert_eq!(config_2.tiers[0].timelock_blocks, 0);
        assert_eq!(config_2.tiers[1].timelock_blocks, 2016);
        assert_eq!(config_2.tiers[2].timelock_blocks, 4032);

        let config_5 = ThresholdConfig::default_for_voter_count(5);
        assert_eq!(config_5.tiers.len(), 4);
        assert_eq!(config_5.tiers[0].timelock_blocks, 0);
        assert_eq!(config_5.tiers[1].timelock_blocks, 1008);
        assert_eq!(config_5.tiers[2].timelock_blocks, 2016);
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

        let builder1 = TapscriptReservesBuilder::with_defaults(
            voter_set.clone(),
            Network::Regtest,
            hash1,
        );
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
    fn derive_lottery_preimage_length_in_range_and_deterministic() {
        // For every supported n, the derived preimage must land in
        // [17, 16+n] and be stable across calls (arm == reveal).
        for n in 2..=crate::constants::MAX_DISPUTANTS {
            for s in 0u8..32u8 {
                let seed = [s; 32];
                let p1 = LotteryOutput::derive_lottery_preimage(&seed, n).unwrap();
                let p2 = LotteryOutput::derive_lottery_preimage(&seed, n).unwrap();
                assert_eq!(p1, p2, "same seed+n must yield identical bytes");
                assert!(
                    (17..=16 + n).contains(&p1.len()),
                    "n={} seed={} len={} out of [17,{}]",
                    n,
                    s,
                    p1.len(),
                    16 + n
                );
                // A single derived preimage must satisfy calculate_winner's
                // per-preimage bound when placed among n preimages.
                let batch: Vec<Vec<u8>> = (0..n)
                    .map(|i| {
                        LotteryOutput::derive_lottery_preimage(&[s.wrapping_add(i as u8); 32], n)
                            .unwrap()
                    })
                    .collect();
                LotteryOutput::calculate_winner(&batch)
                    .expect("derived batch must be a valid winner input");
            }
        }
    }

    #[test]
    fn derive_lottery_preimage_length_is_uniform() {
        // The contribution (len-16) must be ~uniform over [1,n]. Drive
        // the derivation with many distinct random-ish seeds and assert
        // every residue class 1..=n is hit and the distribution is close
        // to flat (chi-square-free sanity: no class < half or > double
        // the expected count over a large sample).
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        for &n in &[2usize, 3, 5, 7, 15] {
            let trials = 20_000usize;
            let mut counts = vec![0usize; n + 1]; // index by contribution 1..=n
            for i in 0..trials {
                let mut eng = sha256::Hash::engine();
                eng.input(b"uniformity-test");
                eng.input(&(i as u64).to_le_bytes());
                let seed = sha256::Hash::from_engine(eng).to_byte_array();
                let p = LotteryOutput::derive_lottery_preimage(&seed, n).unwrap();
                let contribution = p.len() - 16;
                counts[contribution] += 1;
            }
            let expected = trials / n;
            for c in 1..=n {
                assert!(counts[c] > 0, "n={} residue class {} never hit", n, c);
                assert!(
                    counts[c] > expected / 2 && counts[c] < expected * 2,
                    "n={} class {} count {} far from expected {}",
                    n,
                    c,
                    counts[c],
                    expected
                );
            }
        }
    }

    #[test]
    fn derive_lottery_preimage_rejects_bad_n() {
        let seed = [1u8; 32];
        assert!(LotteryOutput::derive_lottery_preimage(&seed, 1).is_err());
        assert!(LotteryOutput::derive_lottery_preimage(
            &seed,
            crate::constants::MAX_DISPUTANTS + 1
        )
        .is_err());
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
        // PARTIAL_REVEAL_MIN_N is 3 (the sub-lottery needs `N-1 >= 2`
        // participants). At N=2 the partial-reveal builder must return
        // empty; the output still builds with the bare 4-leaf shape.
        let builder = make_lottery_builder(2);
        let leaves = builder
            .build_partial_reveal_leaves()
            .expect("partial-reveal builder should not error at N=2");
        assert!(
            leaves.is_empty(),
            "expected no partial-reveal leaves at N=2, got {}",
            leaves.len()
        );

        let output = builder.build().expect("N=2 lottery output should build");
        assert!(
            output.partial_reveal_scripts.is_empty(),
            "LotteryOutput should expose empty partial_reveal_scripts at N=2"
        );
    }

    #[test]
    fn test_partial_reveal_leaf_count_matches_n() {
        // For every N >= PARTIAL_REVEAL_MIN_N (=3), expect `N` partial-
        // reveal leaves — one per missing-disputant index.
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
            // Mirror build_partial_reveal_leaves: bounds_n is the
            // *parent* N (commitments were chosen under the parent
            // contract), not the sub-lottery's participant count.
            let inner = sub_builder.build_lottery_script_with_bounds_n(n).unwrap();

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
        // At N=5 we expect 10 leaves total: 1 primary lottery + 5 partial-
        // reveal (one per missing-disputant index) + 3 long-tail recovery
        // + 1 timeout-recovery (CSV 8064, threshold 1). Tree depth
        // ⌈log₂ 10⌉ = 4.
        let output = make_lottery_builder(5)
            .build()
            .expect("N=5 lottery output should build");
        assert_eq!(
            output.partial_reveal_scripts.len(),
            5,
            "expected one partial-reveal leaf per disputant at N=5"
        );

        let cb = output
            .spend_info
            .control_block(&(
                output.lottery_script.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .expect("primary lottery leaf must have a control block");

        let cb_len = cb.serialize().len();
        assert!(
            cb_len == 33 + 32 * 3 || cb_len == 33 + 32 * 4,
            "N=5 primary lottery leaf should land at depth 3 or 4 in the 10-leaf tree, got control-block len {}",
            cb_len
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
        let tx = build_forfeit_sweep_tx(
            outpoint,
            30_000,
            &revealers,
            500,
            None,
            Network::Regtest,
        )
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
        let tx2 = build_forfeit_sweep_tx(
            outpoint,
            30_000,
            &shuffled,
            500,
            None,
            Network::Regtest,
        )
        .expect("sweep tx builds");
        assert_eq!(
            bitcoin::consensus::encode::serialize(&tx),
            bitcoin::consensus::encode::serialize(&tx2),
            "sweep tx must be order-independent in its revealer input"
        );
    }

    #[test]
    fn test_forfeit_sweep_tx_zero_revealers_requires_fallback() {
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_raw_hash(
                <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                    [0x22; 32],
                ),
            ),
            vout: 2,
        };
        // No revealers, no fallback → refuse.
        assert!(
            build_forfeit_sweep_tx(outpoint, 30_000, &[], 500, None, Network::Regtest)
                .is_err()
        );
        // No revealers + fallback → single output of slice - fee to the
        // fallback's key-path P2TR, CSV sequence still set.
        let fallback = generate_x_only_pubkey(31);
        let tx = build_forfeit_sweep_tx(
            outpoint,
            30_000,
            &[],
            500,
            Some(&fallback),
            Network::Regtest,
        )
        .expect("fallback sweep builds");
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.output[0].value.to_sat(), 29_500);
        assert_eq!(
            tx.input[0].sequence,
            bitcoin::Sequence::from_height(ARMER_SHARE_SWEEP_CSV_BLOCKS as u16)
        );
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
        let ledger_hash: [u8; 32] = hex::decode(
            "7fc25d5245e7003be4f1c4138fbf608bf0ecbb4eca7be4954529d42168473b76",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let config = ThresholdConfig::default_for_voter_count(members.len() + 1);
        let builder = TapscriptReservesBuilder::new(
            voter_set,
            config,
            Network::Bitcoin,
            ledger_hash,
        );
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
