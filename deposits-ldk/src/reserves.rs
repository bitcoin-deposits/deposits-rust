//! Reserves Output Management
//!
//! This module handles the creation, validation, and management of ReservesOutputs
//! that are added to Lightning commitment transactions for Bitcoin Deposits protocol.
//!
//! Core types (`ReservesOutputProposal`, `SpendingPolicy`, `EmergencyRecovery`,
//! `ProposalStatus`) are defined in `deposits-core` and re-exported here.

use deposits_core::{
    DepositsError, DepositsResult,
    time_utils::now_unix_timestamp,
    tapscript_reserves::{TapscriptReservesBuilder, TaprootReservesOutput, VoterSet, ThresholdConfig},
};

use bitcoin::{
    Transaction, Address, Network, Amount, TxOut,
    secp256k1::{PublicKey, SecretKey},
    ScriptBuf, Witness,
};
use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::Secp256k1;

use std::collections::HashMap;
use std::str::FromStr;

use deposits_core::log_info;

// Re-export core types for backwards compatibility
pub use deposits_core::{
    ReservesOutputProposal, SpendingPolicy, EmergencyRecovery, ProposalStatus,
};

/// Manages reserves output proposals and their lifecycle
pub struct ReservesOutputManager<L>
where
    L: std::ops::Deref,
    L::Target: lightning::util::logger::Logger,
{
    /// Our node's secret key
    operator_secret_key: SecretKey,
    /// Active proposals by proposal_id
    proposals: std::sync::RwLock<HashMap<[u8; 32], ReservesOutputProposal>>,
    /// Proposal status tracking
    proposal_status: std::sync::RwLock<HashMap<[u8; 32], ProposalStatus>>,
    /// Network we're operating on
    network: Network,
    /// Logger
    logger: L,
    /// Registered other voters (channel partners that form the quorum)
    other_voters: std::sync::RwLock<Vec<PublicKey>>,
    /// Custom threshold configuration (optional, uses defaults if None)
    threshold_config: std::sync::RwLock<Option<ThresholdConfig>>,
    /// Generated Taproot outputs by proposal_id (for spending later)
    taproot_outputs: std::sync::RwLock<HashMap<[u8; 32], TaprootReservesOutput>>,
}

impl<L> ReservesOutputManager<L>
where
    L: std::ops::Deref,
    L::Target: lightning::util::logger::Logger,
{
    /// Create a new reserves output manager
    pub fn new(
        operator_secret_key: SecretKey,
        network: Network,
        logger: L,
    ) -> Self {
        Self {
            operator_secret_key,
            proposals: std::sync::RwLock::new(HashMap::new()),
            proposal_status: std::sync::RwLock::new(HashMap::new()),
            network,
            logger,
            other_voters: std::sync::RwLock::new(Vec::new()),
            threshold_config: std::sync::RwLock::new(None),
            taproot_outputs: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Register another channel partner as a voter in the reserves quorum
    ///
    /// These voters (along with the direct channel partner as tie-breaker) form the
    /// multisig quorum for Tapscript reserves outputs.
    pub fn register_voter(&self, pubkey: PublicKey) {
        let mut voters = self.other_voters.write().unwrap();
        if !voters.contains(&pubkey) {
            voters.push(pubkey);
            log_info!(self.logger, "Registered voter {} for reserves quorum", pubkey);
        }
    }

    /// Remove a voter from the reserves quorum
    pub fn unregister_voter(&self, pubkey: &PublicKey) {
        let mut voters = self.other_voters.write().unwrap();
        voters.retain(|v| v != pubkey);
        log_info!(self.logger, "Unregistered voter {} from reserves quorum", pubkey);
    }

    /// Get the current voter count (excluding the tie-breaker)
    pub fn voter_count(&self) -> usize {
        self.other_voters.read().unwrap().len()
    }

    /// Set a custom threshold configuration for reserves outputs
    pub fn set_threshold_config(&self, config: ThresholdConfig) {
        let mut tc = self.threshold_config.write().unwrap();
        *tc = Some(config);
    }

    /// Get the stored Taproot output for a proposal (needed for spending)
    pub fn get_taproot_output(&self, proposal_id: &[u8; 32]) -> Option<TaprootReservesOutput> {
        self.taproot_outputs.read().unwrap().get(proposal_id).cloned()
    }

    /// Check if Tapscript reserves are enabled (have at least one other voter)
    pub fn is_tapscript_enabled(&self) -> bool {
        !self.other_voters.read().unwrap().is_empty()
    }

    /// Create a new reserves output proposal
    pub fn create_proposal(
        &self,
        amount: u64,
        reserves_id: PublicKey,
        ledger_id: u16,
        emergency_timeout: u32,
    ) -> DepositsResult<ReservesOutputProposal> {
        // Generate unique proposal ID
        let proposal_id = self.generate_proposal_id(&reserves_id, amount, ledger_id);

        // Create deterministic address for the reserves
        let operator_id = self.operator_secret_key.public_key(&Secp256k1::new());
        let reserves_address = self.create_reserves_address(operator_id, reserves_id, ledger_id)?;

        // Create default spending policy
        let spending_policy = SpendingPolicy {
            cooperative_spending: true,
            partner_unilateral_timeout: emergency_timeout + 144, // +1 day
            operator_deposit_spending: true,
            emergency_recovery: EmergencyRecovery {
                partner_timeout: emergency_timeout + 1008, // +1 week
                operator_emergency_key: self.operator_secret_key.public_key(&Secp256k1::new()),
                require_proof_of_reserves: true,
            },
        };

        let mut proposal = ReservesOutputProposal {
            proposal_id,
            amount,
            reserves_id,
            ledger_id,
            reserves_address: reserves_address.to_string(),
            spending_policy,
            emergency_timeout,
            operator_signature: None,
            ledger_hash: [0u8; 32], // Set to zero initially, updated when reserves are committed
        };

        // Sign the proposal
        proposal.operator_signature = Some(self.sign_proposal(&proposal)?);

        // Store the proposal
        {
            let mut proposals = self.proposals.write().unwrap();
            let mut status = self.proposal_status.write().unwrap();
            proposals.insert(proposal_id, proposal.clone());
            status.insert(proposal_id, ProposalStatus::Draft);
        }

        log_info!(self.logger,
            "Created reserves output proposal {} for {} sats with partner {}",
            hex::encode(&proposal_id[..8]), amount, reserves_id);

        Ok(proposal)
    }

    /// Validate a received reserves output proposal
    pub fn validate_proposal(
        &self,
        proposal: &ReservesOutputProposal,
    ) -> DepositsResult<bool> {
        // Use core validation for basic parameters
        proposal.validate()?;

        // Additional validation: verify the address is correctly derived
        let operator_id = self.operator_secret_key.public_key(&Secp256k1::new());
        let expected_address = self.create_reserves_address(operator_id, proposal.reserves_id, proposal.ledger_id)?;

        if proposal.reserves_address != expected_address.to_string() {
            return Err(DepositsError::InvalidAddress(
                "Reserves address doesn't match expected derivation".to_string()
            ));
        }

        // TODO: Verify partner signature when we receive proposals from partners

        Ok(true)
    }

    /// Submit a proposal to partner (transition from Draft to Pending)
    pub fn submit_proposal(
        &self,
        proposal_id: [u8; 32],
    ) -> DepositsResult<()> {
        let mut status = self.proposal_status.write().unwrap();

        match status.get(&proposal_id) {
            Some(ProposalStatus::Draft) => {
                status.insert(proposal_id, ProposalStatus::Pending);

                log_info!(self.logger, "Submitted reserves output proposal {}", hex::encode(&proposal_id[..8]));

                Ok(())
            },
            Some(current_status) => {
                Err(DepositsError::InvalidState(
                    format!("Cannot submit proposal in state {:?}", current_status)
                ))
            },
            None => {
                Err(DepositsError::ProposalNotFound(
                    "Proposal not found".to_string()
                ))
            }
        }
    }

    /// Accept a reserves output proposal from partner
    pub fn accept_proposal(
        &self,
        proposal_id: [u8; 32],
    ) -> DepositsResult<()> {
        let mut status = self.proposal_status.write().unwrap();

        match status.get(&proposal_id) {
            Some(ProposalStatus::Pending) => {
                status.insert(proposal_id, ProposalStatus::Accepted);

                log_info!(self.logger, "Accepted reserves output proposal {}", hex::encode(&proposal_id[..8]));

                Ok(())
            },
            Some(current_status) => {
                Err(DepositsError::InvalidState(
                    format!("Cannot accept proposal in state {:?}", current_status)
                ))
            },
            None => {
                Err(DepositsError::ProposalNotFound(
                    "Proposal not found".to_string()
                ))
            }
        }
    }

    /// Reject a reserves output proposal
    pub fn reject_proposal(
        &self,
        proposal_id: [u8; 32],
        reason: String,
    ) -> DepositsResult<()> {
        let mut status = self.proposal_status.write().unwrap();

        status.insert(proposal_id, ProposalStatus::Rejected(reason.clone()));

        log_info!(self.logger, "Rejected reserves output proposal {}: {}",
            hex::encode(&proposal_id[..8]), reason);

        Ok(())
    }

    /// Create a reserves output for inclusion in commitment transaction
    ///
    /// When voters are registered (via `register_voter`), this creates a Tapscript
    /// multisig output with threshold-based spending tiers and timelock degradation.
    /// Otherwise, falls back to a simple P2WPKH address.
    pub fn create_reserves_output(
        &self,
        proposal_id: [u8; 32],
    ) -> DepositsResult<TxOut> {
        let proposals = self.proposals.read().unwrap();
        let status = self.proposal_status.read().unwrap();

        let proposal = proposals.get(&proposal_id)
            .ok_or_else(|| DepositsError::ProposalNotFound(
                "Proposal not found".to_string()
            ))?;

        match status.get(&proposal_id) {
            Some(ProposalStatus::Accepted) => {
                // Check if we have voters registered for Tapscript multisig
                let other_voters = self.other_voters.read().unwrap();

                if !other_voters.is_empty() {
                    // Build Tapscript reserves output with quorum voting
                    let voter_set = VoterSet::new(
                        proposal.reserves_id, // Partner is tie-breaker
                        other_voters.clone(),    // Other channel partners are voters
                    );

                    // Use custom config if set, otherwise use defaults
                    let config = self.threshold_config.read().unwrap().clone()
                        .unwrap_or_else(|| ThresholdConfig::default_for_voter_count(voter_set.total_count()));

                    let builder = TapscriptReservesBuilder::new(voter_set, config, self.network, proposal.ledger_hash);
                    let taproot_output = builder.build()?;

                    let tx_out = taproot_output.to_tx_out(proposal.amount);

                    // Store the Taproot output for later spending
                    {
                        let mut outputs = self.taproot_outputs.write().unwrap();
                        outputs.insert(proposal_id, taproot_output);
                    }

                    log_info!(self.logger,
                        "Created Tapscript reserves TxOut for proposal {} with {} sats ({} voters)",
                        hex::encode(&proposal_id[..8]), proposal.amount, other_voters.len() + 1);

                    Ok(tx_out)
                } else {
                    // Fallback to legacy P2WPKH address when no quorum is configured
                    let output = TxOut {
                        value: Amount::from_sat(proposal.amount),
                        script_pubkey: Address::from_str(&proposal.reserves_address).unwrap().assume_checked().script_pubkey(),
                    };

                    log_info!(self.logger, "Created legacy reserves TxOut for proposal {} with {} sats",
                        hex::encode(&proposal_id[..8]), proposal.amount);

                    Ok(output)
                }
            },
            Some(current_status) => {
                Err(DepositsError::InvalidState(
                    format!("Cannot create output for proposal in state {:?}", current_status)
                ))
            },
            None => {
                Err(DepositsError::ProposalNotFound(
                    "Proposal status not found".to_string()
                ))
            }
        }
    }

    /// Mark a reserves output as active in a commitment transaction
    pub fn activate_reserves_output(
        &self,
        proposal_id: [u8; 32],
        commitment_txid: bitcoin::Txid,
        output_index: u32,
    ) -> DepositsResult<()> {
        let mut status = self.proposal_status.write().unwrap();
        status.insert(proposal_id, ProposalStatus::Active);

        log_info!(self.logger, "Activated reserves output {} in commitment tx {}:{}",
            hex::encode(&proposal_id[..8]), commitment_txid, output_index);

        Ok(())
    }

    /// Get all active proposals
    pub fn get_active_proposals(&self) -> Vec<(ReservesOutputProposal, ProposalStatus)> {
        let proposals = self.proposals.read().unwrap();
        let status = self.proposal_status.read().unwrap();

        proposals.iter()
            .filter_map(|(id, proposal)| {
                status.get(id).map(|s| (proposal.clone(), s.clone()))
            })
            .collect()
    }

    /// Generate a unique proposal ID
    fn generate_proposal_id(
        &self,
        reserves_id: &PublicKey,
        amount: u64,
        ledger_id: u16,
    ) -> [u8; 32] {
        let mut hasher = sha256::Hash::engine();
        hasher.input(&self.operator_secret_key.public_key(&Secp256k1::new()).serialize());
        hasher.input(&reserves_id.serialize());
        hasher.input(&amount.to_be_bytes());
        hasher.input(&ledger_id.to_be_bytes());
        hasher.input(&now_unix_timestamp().to_be_bytes());

        sha256::Hash::from_engine(hasher).to_byte_array()
    }

    /// Sign a reserves output proposal
    fn sign_proposal(
        &self,
        proposal: &ReservesOutputProposal,
    ) -> DepositsResult<[u8; 64]> {
        // Create message to sign
        let mut message_bytes = Vec::new();
        message_bytes.extend_from_slice(&proposal.proposal_id);
        message_bytes.extend_from_slice(&proposal.amount.to_be_bytes());
        message_bytes.extend_from_slice(&proposal.reserves_id.serialize());
        message_bytes.extend_from_slice(&proposal.ledger_id.to_be_bytes());
        message_bytes.extend_from_slice(&proposal.emergency_timeout.to_be_bytes());

        // Sign with our secret key
        let secp = Secp256k1::new();
        let message_hash = sha256::Hash::hash(&message_bytes);
        let message = bitcoin::secp256k1::Message::from_digest(message_hash.to_byte_array());
        let signature = secp.sign_ecdsa(&message, &self.operator_secret_key);

        Ok(signature.serialize_compact())
    }

    /// Create a deterministic P2WPKH address for reserves output
    ///
    /// This generates a simple single-key address based on operator, partner, and ledger ID.
    /// The wallet can independently verify operator and partner signatures on operations.
    fn create_reserves_address(
        &self,
        operator_key: PublicKey,
        reserves_key: PublicKey,
        ledger_id: u16,
    ) -> DepositsResult<Address> {
        let secp = Secp256k1::new();

        // Deterministic key derivation: SHA256(operator_key || reserves_key || ledger_id || "reserves")
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&operator_key.serialize());
        key_material.extend_from_slice(&reserves_key.serialize());
        key_material.extend_from_slice(&ledger_id.to_be_bytes());
        key_material.extend_from_slice(b"bitcoin-deposits-reserves-v1");

        let key_hash = sha256::Hash::hash(&key_material);
        let secret_key = SecretKey::from_slice(key_hash.as_ref())
            .map_err(|_| DepositsError::InvalidPublicKey)?;
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // Create P2WPKH address (native segwit)
        let compressed_pk = bitcoin::CompressedPublicKey::try_from(bitcoin::PublicKey::new(public_key))
            .map_err(|_| DepositsError::InvalidPublicKey)?;

        Ok(bitcoin::Address::p2wpkh(&compressed_pk, self.network))
    }
}

/// Extension methods for ReservesOutputProposal that require Bitcoin transaction types
pub trait ReservesOutputProposalExt {
    /// Create a spending transaction for cooperative spending
    fn create_cooperative_spend(
        &self,
        destination: &Address,
        fee_rate: u64,
    ) -> DepositsResult<Transaction>;

    /// Get the expected script pubkey for this reserves output
    fn script_pubkey(&self) -> ScriptBuf;
}

impl ReservesOutputProposalExt for ReservesOutputProposal {
    fn create_cooperative_spend(
        &self,
        destination: &Address,
        fee_rate: u64, // sats per vbyte
    ) -> DepositsResult<Transaction> {
        // Estimate transaction size (typical P2TR input + P2TR output)
        let estimated_vsize = 150; // Conservative estimate
        let fee = fee_rate * estimated_vsize;

        if self.amount <= fee {
            return Err(DepositsError::InsufficientFunds(
                "Amount too small to cover fees".to_string()
            ));
        }

        let output_amount = self.amount - fee;

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(), // Will be filled by caller
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // Will be filled after signing
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: destination.script_pubkey(),
            }],
        };

        Ok(tx)
    }

    fn script_pubkey(&self) -> ScriptBuf {
        Address::from_str(&self.reserves_address).unwrap().assume_checked().script_pubkey()
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use std::sync::Arc;
    use lightning::util::test_utils::TestLogger;

    #[test]
    fn test_reserves_proposal_creation() {
        let logger = Arc::new(TestLogger::new());

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let manager = ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        );

        let proposal = manager.create_proposal(
            50000, // 50k sats
            partner_pk,
            1u16, // ledger_id
            144, // 1 day timeout
        ).unwrap();

        assert_eq!(proposal.amount, 50000);
        assert_eq!(proposal.reserves_id, partner_pk);
        assert!(proposal.operator_signature.is_some());

        // Validate the proposal
        assert!(manager.validate_proposal(&proposal).unwrap());
    }

    #[test]
    fn test_reserves_output_creation() {
        let logger = Arc::new(TestLogger::new());

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let manager = ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        );

        let proposal = manager.create_proposal(
            100000, // 100k sats
            partner_pk,
            2u16, // ledger_id
            288, // 2 day timeout
        ).unwrap();

        // Submit and accept the proposal
        manager.submit_proposal(proposal.proposal_id).unwrap();
        manager.accept_proposal(proposal.proposal_id).unwrap();

        // Create the reserves output
        let output = manager.create_reserves_output(proposal.proposal_id).unwrap();

        assert_eq!(output.value, Amount::from_sat(100000));
        assert_eq!(output.script_pubkey, proposal.script_pubkey());
    }

    #[test]
    fn test_tapscript_reserves_output_creation() {
        let logger = Arc::new(TestLogger::new());

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());
        let voter1_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());
        let voter2_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let manager = ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        );

        // Register other voters to enable Tapscript
        manager.register_voter(voter1_pk);
        manager.register_voter(voter2_pk);

        assert!(manager.is_tapscript_enabled());
        assert_eq!(manager.voter_count(), 2);

        // Create and accept proposal
        let proposal = manager.create_proposal(
            100000, // 100k sats
            partner_pk,
            1u16,
            288, // 2 day timeout
        ).unwrap();

        manager.submit_proposal(proposal.proposal_id).unwrap();
        manager.accept_proposal(proposal.proposal_id).unwrap();

        // Create the reserves output (should use Tapscript)
        let output = manager.create_reserves_output(proposal.proposal_id).unwrap();

        // Verify it's a P2TR output
        assert!(output.script_pubkey.is_p2tr(), "Should be a P2TR (Taproot) output");
        assert_eq!(output.value, Amount::from_sat(100000));

        // Verify we can retrieve the Taproot output for spending
        let taproot_output = manager.get_taproot_output(&proposal.proposal_id);
        assert!(taproot_output.is_some(), "Should have stored Taproot output");

        let taproot = taproot_output.unwrap();
        assert!(taproot.merkle_root().is_some(), "Should have script tree");
        assert_eq!(taproot.voter_set.total_count(), 3); // partner + 2 voters
    }

    #[test]
    fn test_legacy_reserves_without_voters() {
        let logger = Arc::new(TestLogger::new());

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let manager = ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        );

        // Don't register any voters - should use legacy P2WPKH
        assert!(!manager.is_tapscript_enabled());

        let proposal = manager.create_proposal(
            50000,
            partner_pk,
            1u16,
            144,
        ).unwrap();

        manager.submit_proposal(proposal.proposal_id).unwrap();
        manager.accept_proposal(proposal.proposal_id).unwrap();

        let output = manager.create_reserves_output(proposal.proposal_id).unwrap();

        // Should be a P2WPKH output (legacy mode)
        assert!(output.script_pubkey.is_p2wpkh(), "Should be P2WPKH without voters");
        assert_eq!(output.value, Amount::from_sat(50000));

        // No Taproot output stored
        assert!(manager.get_taproot_output(&proposal.proposal_id).is_none());
    }
}
