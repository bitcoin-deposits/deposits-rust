//! Commitment Transaction Integration
//!
//! This module handles the integration of ReservesOutputs into Lightning
//! commitment transactions, providing the core mechanism for Bitcoin Deposits
//! protocol enforcement at the channel level.

use deposits_core::{DepositsError, DepositsResult, time_utils::now_unix_timestamp};
use crate::reserves::{ReservesOutputManager, ReservesOutputProposal, ProposalStatus};

use bitcoin::{
    Transaction, TxOut, Amount,
    secp256k1::PublicKey,
    script::Builder,
    opcodes::all::OP_RETURN,
};

// Lightning imports commented out due to private module access
// These would be used in full Lightning integration
// use lightning::ln::channel::Channel;
// use lightning::ln::msgs::ChannelMessageHandler;

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::collections::HashMap;

/// Represents a ReservesOutput that has been included in a commitment transaction
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveReservesOutput {
    /// The original proposal
    pub proposal: ReservesOutputProposal,
    /// The commitment transaction this output is in
    pub commitment_txid: bitcoin::Txid,
    /// Index of this output in the commitment transaction
    pub output_index: u32,
    /// Current balance held in reserves
    pub current_balance: u64,
    /// Block height when this became active
    pub activated_at_height: u32,
    /// Whether this output is currently locked for spending
    pub is_locked: bool,
    /// Last update timestamp
    pub last_updated: u64,
}

/// Enhanced commitment transaction that includes ReservesOutputs
pub struct CommitmentTransactionEnhancer<L>
where
    L: std::ops::Deref,
    L::Target: lightning::util::logger::Logger,
{
    /// Channel ID this enhancer belongs to
    pub channel_id: [u8; 32],
    /// Reserves identifier
    pub reserves_id: PublicKey,
    /// Reserves output manager
    reserves_manager: Arc<ReservesOutputManager<L>>,
    /// Currently active reserves outputs for this channel
    active_reserves: RwLock<HashMap<[u8; 32], ActiveReservesOutput>>,
}

impl<L> CommitmentTransactionEnhancer<L>
where
    L: std::ops::Deref,
    L::Target: lightning::util::logger::Logger,
{
    /// Create a new commitment transaction enhancer for a channel
    pub fn new(
        channel_id: [u8; 32],
        reserves_id: PublicKey,
        reserves_manager: Arc<ReservesOutputManager<L>>,
    ) -> Self {
        Self {
            channel_id,
            reserves_id,
            reserves_manager,
            active_reserves: RwLock::new(HashMap::new()),
        }
    }

    /// Propose adding a new reserves output to commitment transactions
    pub fn propose_reserves_output(
        &self,
        amount: u64,
        ledger_id: u16,
        emergency_timeout: u32,
    ) -> DepositsResult<ReservesOutputProposal> {
        // Create the proposal using the reserves manager
        let proposal = self.reserves_manager.create_proposal(
            amount,
            self.reserves_id,
            ledger_id,
            emergency_timeout,
        )?;

        // TODO: Send proposal message to partner via Lightning protocol
        // This would be integrated with the Lightning message handler

        Ok(proposal)
    }

    /// Accept a reserves output proposal from partner and prepare for commitment
    pub fn accept_reserves_proposal(
        &self,
        proposal: ReservesOutputProposal,
    ) -> DepositsResult<()> {
        // Validate the proposal first
        self.reserves_manager.validate_proposal(&proposal)?;

        // Submit the proposal first (Draft -> Pending)
        self.reserves_manager.submit_proposal(proposal.proposal_id)?;

        // Accept it in the reserves manager
        self.reserves_manager.accept_proposal(proposal.proposal_id)?;

        // TODO: Send acceptance message to partner
        // This would trigger commitment transaction update

        Ok(())
    }

    /// Enhance a commitment transaction by adding approved reserves outputs and ledger hash
    pub fn enhance_commitment_transaction(
        &self,
        mut commitment_tx: Transaction,
        commitment_number: u64,
        ledger_hash: Option<[u8; 32]>,
    ) -> DepositsResult<Transaction> {
        // Get all accepted proposals that should be included
        let active_proposals = self.reserves_manager.get_active_proposals();

        for (proposal, status) in active_proposals {
            if let ProposalStatus::Accepted = status {
                // Only add if this is for our channel partner
                if proposal.reserves_id == self.reserves_id {
                    // Create the reserves output
                    let reserves_output = self.reserves_manager
                        .create_reserves_output(proposal.proposal_id)?;

                    // Add to commitment transaction
                    commitment_tx.output.push(reserves_output);

                    // Mark as active
                    let output_index = (commitment_tx.output.len() - 1) as u32;
                    self.activate_reserves_output(
                        proposal,
                        commitment_tx.compute_txid(),
                        output_index,
                        commitment_number as u32, // Simplified height approximation
                    )?;
                }
            }
        }

        // Add ledger hash as an OP_RETURN output if provided
        if let Some(hash) = ledger_hash {
            let ledger_hash_output = self.create_ledger_hash_output(hash)?;
            commitment_tx.output.push(ledger_hash_output);
        }

        Ok(commitment_tx)
    }

    /// Create an OP_RETURN output containing the current ledger hash
    ///
    /// This output commits the current ledger state to the commitment transaction,
    /// ensuring both parties agree on the ledger state when signing the commitment.
    fn create_ledger_hash_output(&self, ledger_hash: [u8; 32]) -> DepositsResult<TxOut> {
        // Create OP_RETURN script with ledger hash
        // Format: OP_RETURN <4-byte prefix> <32-byte ledger hash>
        // Prefix "BDLH" = Bitcoin Deposits Ledger Hash
        let prefix = b"BDLH";

        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(prefix)
            .push_slice(&ledger_hash)
            .into_script();

        // OP_RETURN outputs should have zero value
        Ok(TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        })
    }

    /// Mark a reserves output as active in a commitment transaction
    fn activate_reserves_output(
        &self,
        proposal: ReservesOutputProposal,
        commitment_txid: bitcoin::Txid,
        output_index: u32,
        block_height: u32,
    ) -> DepositsResult<()> {
        let active_output = ActiveReservesOutput {
            current_balance: proposal.amount,
            commitment_txid,
            output_index,
            activated_at_height: block_height,
            is_locked: false,
            last_updated: now_unix_timestamp(),
            proposal: proposal.clone(),
        };

        // Store in our active reserves
        {
            let mut active_reserves = self.active_reserves.write().unwrap();
            active_reserves.insert(proposal.proposal_id, active_output);
        }

        // Notify reserves manager
        self.reserves_manager.activate_reserves_output(
            proposal.proposal_id,
            commitment_txid,
            output_index,
        )?;

        Ok(())
    }

    /// Update the balance of a reserves output (called when deposits change)
    pub fn update_reserves_balance(
        &self,
        proposal_id: [u8; 32],
        new_balance: u64,
    ) -> DepositsResult<()> {
        let mut active_reserves = self.active_reserves.write().unwrap();

        if let Some(output) = active_reserves.get_mut(&proposal_id) {
            let old_balance = output.current_balance;
            output.current_balance = new_balance;
            output.last_updated = now_unix_timestamp();

            // Validate that reserves can only increase (key protocol rule!)
            if new_balance < old_balance {
                return Err(DepositsError::InvalidReservesDecrease(
                    format!("Reserves decreased from {} to {} sats", old_balance, new_balance)
                ));
            }

            Ok(())
        } else {
            Err(DepositsError::ReservesOutputNotFound(
                "Active reserves output not found".to_string()
            ))
        }
    }

    /// Get all active reserves outputs for this channel
    pub fn get_active_reserves(&self) -> Vec<ActiveReservesOutput> {
        let active_reserves = self.active_reserves.read().unwrap();
        active_reserves.values().cloned().collect()
    }

    /// Check if a reserves output can be spent cooperatively
    pub fn can_spend_cooperatively(
        &self,
        proposal_id: [u8; 32],
        _current_block_height: u32,
    ) -> DepositsResult<bool> {
        let active_reserves = self.active_reserves.read().unwrap();

        if let Some(output) = active_reserves.get(&proposal_id) {
            // Can spend if not locked and cooperative spending is enabled
            Ok(!output.is_locked && output.proposal.spending_policy.cooperative_spending)
        } else {
            Err(DepositsError::ReservesOutputNotFound(
                "Active reserves output not found".to_string()
            ))
        }
    }

    /// Check if partner can spend unilaterally (emergency timeout reached)
    pub fn can_partner_spend_unilaterally(
        &self,
        proposal_id: [u8; 32],
        current_block_height: u32,
    ) -> DepositsResult<bool> {
        let active_reserves = self.active_reserves.read().unwrap();

        if let Some(output) = active_reserves.get(&proposal_id) {
            let timeout_reached = current_block_height >=
                output.activated_at_height + output.proposal.spending_policy.partner_unilateral_timeout;

            Ok(timeout_reached)
        } else {
            Err(DepositsError::ReservesOutputNotFound(
                "Active reserves output not found".to_string()
            ))
        }
    }

    /// Lock a reserves output to prevent spending (used during transfers)
    pub fn lock_reserves_output(
        &self,
        proposal_id: [u8; 32],
    ) -> DepositsResult<()> {
        let mut active_reserves = self.active_reserves.write().unwrap();

        if let Some(output) = active_reserves.get_mut(&proposal_id) {
            output.is_locked = true;
            output.last_updated = now_unix_timestamp();
            Ok(())
        } else {
            Err(DepositsError::ReservesOutputNotFound(
                "Active reserves output not found".to_string()
            ))
        }
    }

    /// Unlock a reserves output
    pub fn unlock_reserves_output(
        &self,
        proposal_id: [u8; 32],
    ) -> DepositsResult<()> {
        let mut active_reserves = self.active_reserves.write().unwrap();

        if let Some(output) = active_reserves.get_mut(&proposal_id) {
            output.is_locked = false;
            output.last_updated = now_unix_timestamp();
            Ok(())
        } else {
            Err(DepositsError::ReservesOutputNotFound(
                "Active reserves output not found".to_string()
            ))
        }
    }

    /// Get the total reserves amount for this channel
    pub fn get_total_reserves(&self) -> u64 {
        let active_reserves = self.active_reserves.read().unwrap();
        active_reserves.values()
            .map(|output| output.current_balance)
            .sum()
    }

    /// Validate that a commitment transaction contains the expected ledger hash
    ///
    /// This ensures that both parties agree on the current ledger state before
    /// signing the commitment transaction.
    pub fn validate_commitment_ledger_hash(
        &self,
        commitment_tx: &Transaction,
        expected_ledger_hash: [u8; 32],
    ) -> DepositsResult<()> {
        // Search for OP_RETURN output containing ledger hash
        let prefix = b"BDLH";

        for output in &commitment_tx.output {
            if let Some(found_hash) = self.extract_ledger_hash_from_output(output, prefix) {
                if found_hash == expected_ledger_hash {
                    return Ok(()); // Found matching ledger hash
                } else {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "ledger_hash_mismatch".to_string(),
                        details: format!(
                            "Commitment transaction contains incorrect ledger hash. Expected: {:?}, Found: {:?}",
                            expected_ledger_hash,
                            found_hash
                        ),
                    });
                }
            }
        }

        // No ledger hash found
        Err(DepositsError::ProtocolViolation {
            violation_type: "missing_ledger_hash".to_string(),
            details: "Commitment transaction missing required ledger hash OP_RETURN output".to_string(),
        })
    }

    /// Extract ledger hash from an OP_RETURN output if present
    fn extract_ledger_hash_from_output(
        &self,
        output: &TxOut,
        expected_prefix: &[u8],
    ) -> Option<[u8; 32]> {
        // Check if this is an OP_RETURN output
        if output.value != Amount::ZERO {
            return None;
        }

        let script = &output.script_pubkey;
        let script_bytes = script.as_bytes();

        // Minimum length: OP_RETURN (1) + prefix_len (1) + prefix (4) + hash_len (1) + hash (32) = 39 bytes
        if script_bytes.len() < 39 {
            return None;
        }

        // Check for OP_RETURN opcode
        if script_bytes[0] != OP_RETURN.to_u8() {
            return None;
        }

        // Check prefix length and value
        let prefix_len = script_bytes[1] as usize;
        if prefix_len != expected_prefix.len() || script_bytes.len() < 2 + prefix_len + 1 + 32 {
            return None;
        }

        let actual_prefix = &script_bytes[2..2 + prefix_len];
        if actual_prefix != expected_prefix {
            return None;
        }

        // Check hash length
        let hash_len_pos = 2 + prefix_len;
        let hash_len = script_bytes[hash_len_pos] as usize;
        if hash_len != 32 || script_bytes.len() < hash_len_pos + 1 + hash_len {
            return None;
        }

        // Extract hash
        let hash_start = hash_len_pos + 1;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&script_bytes[hash_start..hash_start + 32]);

        Some(hash)
    }

    /// Validate that reserves satisfy the 100% rule for total deposits
    /// (100%+100% model: 100% in channel + 100% collateral from other channels)
    pub fn validate_reserves_ratio(
        &self,
        total_deposits: u64,
    ) -> DepositsResult<bool> {
        let total_reserves = self.get_total_reserves();
        let required_reserves = total_deposits; // 100% of deposits in this channel

        if total_reserves >= required_reserves {
            Ok(true)
        } else {
            Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: total_reserves
            })
        }
    }
}

/// Integration point for Lightning channel implementations
pub trait ReservesChannelExtension {
    /// Add reserves output proposals to commitment transaction building
    fn add_reserves_outputs(
        &self,
        commitment_tx: &mut Transaction,
        is_outbound: bool,
    ) -> DepositsResult<()>;

    /// Validate that commitment transaction includes required reserves
    fn validate_reserves_outputs(
        &self,
        commitment_tx: &Transaction,
    ) -> DepositsResult<()>;

    /// Handle reserves-related messages from channel partner
    fn handle_reserves_message(
        &self,
        message: crate::handler::messages::DepositsMessage,
    ) -> DepositsResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Network, secp256k1::rand::rngs::OsRng};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use std::sync::Arc;

    // Local TestLogger to avoid dependency on lightning's test_utils feature
    struct TestLogger;
    impl lightning::util::logger::Logger for TestLogger {
        fn log(&self, record: lightning::util::logger::Record) {
            println!("[{}] {}", record.level, record.args);
        }
    }

    #[test]
    fn test_commitment_enhancer_creation() {
        let logger = Arc::new(TestLogger);

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let reserves_manager = Arc::new(ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        ));

        let channel_id = [1u8; 32];
        let enhancer = CommitmentTransactionEnhancer::new(
            channel_id,
            partner_pk,
            reserves_manager,
        );

        assert_eq!(enhancer.channel_id, channel_id);
        assert_eq!(enhancer.reserves_id, partner_pk);
        assert_eq!(enhancer.get_total_reserves(), 0);
    }

    #[test]
    fn test_reserves_proposal_flow() {
        let logger = Arc::new(TestLogger);

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let reserves_manager = Arc::new(ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        ));

        let enhancer = CommitmentTransactionEnhancer::new(
            [2u8; 32],
            partner_pk,
            reserves_manager,
        );

        // Create a proposal
        let proposal = enhancer.propose_reserves_output(
            50000, // 50k sats
            1, // ledger_id
            144, // 1 day timeout
        ).unwrap();

        assert_eq!(proposal.amount, 50000);
        assert_eq!(proposal.reserves_id, partner_pk);

        // Accept the proposal
        enhancer.accept_reserves_proposal(proposal).unwrap();
    }

    #[test]
    fn test_reserves_balance_validation() {
        let logger = Arc::new(TestLogger);

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let reserves_manager = Arc::new(ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        ));

        let enhancer = CommitmentTransactionEnhancer::new(
            [4u8; 32],
            partner_pk,
            reserves_manager,
        );

        // Test 100% reserves rule (100%+100% model)
        let total_deposits = 100000; // 100k sats in deposits
        let is_valid = enhancer.validate_reserves_ratio(total_deposits);

        // Should fail since we have 0 reserves
        assert!(is_valid.is_err());
    }

    #[test]
    fn test_commitment_ledger_hash() {
        let logger = Arc::new(TestLogger);

        let mut rng = OsRng;
        let operator_sk = SecretKey::new(&mut rng);
        let partner_pk = SecretKey::new(&mut rng).public_key(&Secp256k1::new());

        let reserves_manager = Arc::new(ReservesOutputManager::new(
            operator_sk,
            Network::Regtest,
            logger,
        ));

        let enhancer = CommitmentTransactionEnhancer::new(
            [5u8; 32],
            partner_pk,
            reserves_manager,
        );

        // Test creating commitment with ledger hash
        let test_ledger_hash = [0xAAu8; 32];
        let base_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let enhanced_tx = enhancer.enhance_commitment_transaction(
            base_tx,
            1, // commitment_number
            Some(test_ledger_hash),
        ).unwrap();

        // Should contain ledger hash OP_RETURN output
        let ledger_hash_output = enhanced_tx.output.iter().find(|output| {
            output.value == Amount::ZERO &&
            output.script_pubkey.as_bytes().starts_with(&[OP_RETURN.to_u8()])
        }).expect("Should find ledger hash OP_RETURN output");

        // Test validation with correct hash
        let validation_result = enhancer.validate_commitment_ledger_hash(
            &enhanced_tx,
            test_ledger_hash,
        );

        assert!(validation_result.is_ok(), "Should validate correct ledger hash");

        // Test validation with wrong hash
        let wrong_hash = [0xBBu8; 32];
        let wrong_validation = enhancer.validate_commitment_ledger_hash(
            &enhanced_tx,
            wrong_hash,
        );

        assert!(wrong_validation.is_err(), "Should fail with wrong ledger hash");

    }
}
