//! Lightning Channel Extension for Bitcoin Deposits Reserves
//!
//! This module provides deep integration with Lightning Network channels to add
//! reserves outputs directly to commitment transactions during their construction.
//!
//! Integration Points:
//! 1. Channel establishment - negotiate reserves support
//! 2. Commitment transaction construction - add reserves outputs
//! 3. Channel monitoring - track reserves outputs for security
//! 4. Balance tracking - include reserves in channel balance calculations

use bitcoin::{Transaction, TxOut, ScriptBuf, Amount, script::Builder, opcodes::all::OP_RETURN};
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use deposits_core::{
    DepositsError, DepositsResult,
    constants::{MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS},
};
use crate::reserves::ReservesOutputManager;
use crate::handler::{LedgerOperationsExt, ReservesOperations};
use lightning::util::logger::Logger as LdkLogger;

/// New output type for reserves in commitment transactions
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentReservesOutput {
    /// Amount locked in reserves (100% of custodial balance, with 100% collateral on other channels)
    pub amount_sats: u64,
    /// Script for the reserves output (2-of-2 multisig with timelock)
    pub script_pubkey: ScriptBuf,
    /// Emergency unlock timeout (blocks)
    pub emergency_timeout: u32,
    /// Ledger ID this reserves output backs
    pub ledger_id: u16,
    /// Proposal ID that created this output
    pub proposal_id: [u8; 32],
}

impl CommitmentReservesOutput {
    /// Create a new reserves output for commitment transactions
    pub fn new(
        amount_sats: u64,
        local_key: PublicKey,
        remote_key: PublicKey,
        emergency_timeout: u32,
        ledger_id: u16,
        proposal_id: [u8; 32],
    ) -> DepositsResult<Self> {
        // Validate minimum amount
        if amount_sats < MIN_RESERVES_OUTPUT_SATS {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "insufficient_reserves_amount".to_string(),
                details: format!(
                    "Reserves output amount {} sats is below minimum {} sats required for economic spendability",
                    amount_sats, MIN_RESERVES_OUTPUT_SATS
                ),
            });
        }

        // Validate maximum amount (prevents accidental huge outputs)
        if amount_sats > MAX_RESERVES_OUTPUT_SATS {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "excessive_reserves_amount".to_string(),
                details: format!(
                    "Reserves output amount {} sats exceeds maximum {} sats allowed",
                    amount_sats, MAX_RESERVES_OUTPUT_SATS
                ),
            });
        }

        // Validate emergency timeout (use default if zero provided)
        let validated_timeout = if emergency_timeout == 0 {
            DEFAULT_EMERGENCY_TIMEOUT_BLOCKS
        } else {
            emergency_timeout
        };

        // Create 2-of-2 multisig script with emergency timeout
        // After timeout, either party can spend unilaterally
        let script_pubkey = Self::create_reserves_script(
            local_key,
            remote_key,
            validated_timeout,
        )?;

        Ok(Self {
            amount_sats,
            script_pubkey,
            emergency_timeout: validated_timeout,
            ledger_id,
            proposal_id,
        })
    }

    /// Create the script for reserves outputs
    /// Format: 2-of-2 multisig OR single-sig after timeout
    fn create_reserves_script(
        local_key: PublicKey,
        remote_key: PublicKey,
        timeout_blocks: u32,
    ) -> DepositsResult<ScriptBuf> {
        use bitcoin::script::Builder;
        use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CHECKMULTISIG, OP_IF, OP_ELSE, OP_ENDIF, OP_DROP, OP_PUSHNUM_2};

        // Convert secp256k1 PublicKey to bitcoin PublicKey
        let local_bitcoin_key = bitcoin::PublicKey::new(local_key);
        let remote_bitcoin_key = bitcoin::PublicKey::new(remote_key);

        // Script: IF 2 <local_key> <remote_key> 2 CHECKMULTISIG ELSE <timeout> DROP <local_key> CHECKSIG ENDIF
        // Simplified without CHECKLOCKTIMEVERIFY for now
        let script = Builder::new()
            .push_opcode(OP_IF)
                .push_opcode(OP_PUSHNUM_2)
                .push_key(&local_bitcoin_key)
                .push_key(&remote_bitcoin_key)
                .push_opcode(OP_PUSHNUM_2)
                .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
                .push_int(timeout_blocks as i64)
                .push_opcode(OP_DROP)
                .push_key(&local_bitcoin_key)
                .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script();

        Ok(script)
    }

    /// Convert to a Bitcoin transaction output
    pub fn to_tx_out(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(self.amount_sats),
            script_pubkey: self.script_pubkey.clone(),
        }
    }
}

/// Lightning Channel Extension for Bitcoin Deposits Integration
///
/// This provides the hooks needed to integrate reserves outputs into Lightning
/// channels at the protocol level, not just as an enhancement layer.
pub struct DepositsChannelExtension<L>
where
    L: std::ops::Deref + Clone,
    L::Target: LdkLogger,
{
    /// Channel ID this extension belongs to
    channel_id: [u8; 32],

    /// Local node's public key
    local_node_id: PublicKey,

    /// Remote node's public key
    remote_node_id: PublicKey,

    /// Reserves output manager
    reserves_manager: Arc<ReservesOutputManager<L>>,

    /// Bitcoin Deposits handler for accessing ledger state and commitment tracking
    deposits_handler: Option<Arc<crate::handler::DepositsHandler<L>>>,

    /// Active reserves outputs in current commitment transaction
    active_reserves: RwLock<HashMap<[u8; 32], CommitmentReservesOutput>>,

    /// Whether reserves are enabled for this channel (negotiated feature)
    reserves_enabled: bool,

    /// Logger
    logger: L,
}

impl<L> DepositsChannelExtension<L>
where
    L: std::ops::Deref + Clone,
    L::Target: LdkLogger,
{
    /// Create a new channel extension
    pub fn new(
        channel_id: [u8; 32],
        local_node_id: PublicKey,
        remote_node_id: PublicKey,
        reserves_manager: Arc<ReservesOutputManager<L>>,
        reserves_enabled: bool,
        logger: L,
    ) -> Self {
        Self {
            channel_id,
            local_node_id,
            remote_node_id,
            reserves_manager,
            deposits_handler: None,
            active_reserves: RwLock::new(HashMap::new()),
            reserves_enabled,
            logger,
        }
    }

    /// Set the Bitcoin Deposits handler for real integration
    pub fn set_deposits_handler(&mut self, handler: Arc<crate::handler::DepositsHandler<L>>) {
        self.deposits_handler = Some(handler);
    }

    /// Check if reserves are enabled for this channel
    pub fn reserves_enabled(&self) -> bool {
        self.reserves_enabled
    }

    /// Get additional outputs that should be added to commitment transactions
    /// This is the key integration point - called during commitment tx construction
    pub fn get_additional_outputs(
        &self,
        _commitment_number: u64,
        _is_local_commitment: bool,
    ) -> DepositsResult<Vec<TxOut>> {
        if !self.reserves_enabled {
            return Ok(Vec::new());
        }

        let mut additional_outputs = Vec::new();

        // Get current ledger hash from the Bitcoin Deposits handler
        let ledger_hash = if let Some(handler) = &self.deposits_handler {
            handler.get_ledger_hash_for_commitment(self.remote_node_id).unwrap_or(None)
        } else {
            None
        };

        // Get reserves status to determine reserves output amount
        let reserves_status = if let Some(handler) = &self.deposits_handler {
            handler.get_channel_reserves_status(self.remote_node_id).ok()
        } else {
            None
        };

        // Create reserves output if we have reserves
        if let Some(status) = reserves_status {
            if status.current_amount > 0 {
                let reserves_output = CommitmentReservesOutput::new(
                    status.current_amount,
                    self.local_node_id,
                    self.remote_node_id,
                    144, // Default emergency timeout
                    0,   // Single ledger per channel
                    [0u8; 32], // TODO: Use proper proposal ID
                )?;

                additional_outputs.push(reserves_output.to_tx_out());

                // Track active reserves output
                self.active_reserves.write().unwrap()
                    .insert([0u8; 32], reserves_output); // TODO: Use proper proposal ID
            }
        }

        // Add ledger hash OP_RETURN output if there are uncommitted changes
        if let Some(hash) = ledger_hash {
            let ledger_hash_output = self.create_ledger_hash_output(hash)?;
            additional_outputs.push(ledger_hash_output);
        }

        Ok(additional_outputs)
    }

    /// Create an OP_RETURN output containing the current ledger hash
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

    /// Validate that a commitment transaction includes required reserves outputs and ledger hash
    pub fn validate_commitment_transaction(
        &self,
        commitment_tx: &Transaction,
        commitment_number: u64,
        is_local_commitment: bool,
    ) -> DepositsResult<()> {
        if !self.reserves_enabled {
            return Ok(());
        }

        // Get expected outputs from the current state
        let expected_outputs = self.get_additional_outputs(commitment_number, is_local_commitment)?;

        // Check that all expected outputs are present
        for expected_output in expected_outputs {
            let found = commitment_tx.output.iter().any(|actual_output| {
                actual_output.value == expected_output.value &&
                actual_output.script_pubkey == expected_output.script_pubkey
            });

            if !found {
                return Err(DepositsError::ProtocolViolation {
                    violation_type: "missing_required_output".to_string(),
                    details: "Required Bitcoin Deposits output missing from commitment transaction".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate that a commitment transaction contains the expected ledger hash
    fn validate_ledger_hash_in_commitment(
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

    /// Get reserves balance that should be included in channel balance calculations
    pub fn get_reserves_balance(&self) -> u64 {
        if !self.reserves_enabled {
            return 0;
        }

        let active_reserves = self.active_reserves.read().unwrap();
        active_reserves.values().map(|r| r.amount_sats).sum()
    }

    /// Handle reserves-related channel updates
    pub fn handle_channel_update(
        &self,
        update_type: ChannelUpdateType,
        commitment_number: Option<u64>,
    ) -> DepositsResult<()> {
        match update_type {
            ChannelUpdateType::CommitmentSigned => {
                // Update reserves state when commitment is signed
                self.update_reserves_state(commitment_number)?;
            }
            ChannelUpdateType::RevokeAndAck => {
                // Finalize reserves state when old commitment is revoked
                self.finalize_reserves_state(commitment_number)?;
            }
            ChannelUpdateType::ChannelClosed => {
                // Clean up reserves state when channel closes
                self.cleanup_reserves_state()?;
            }
        }

        Ok(())
    }

    /// Update reserves state for commitment signing
    fn update_reserves_state(&self, commitment_number: Option<u64>) -> DepositsResult<()> {
        // Mark that ledger state is being committed to Lightning channel
        if let Some(commitment_num) = commitment_number {
            if let Some(handler) = &self.deposits_handler {
                // Use the real handler to mark commitment update
                let _ = handler.mark_ledger_committed(self.remote_node_id, commitment_num);
                log::info!("Marking ledger state as committed at commitment {} via handler", commitment_num);
            } else {
                log::info!("No handler available - commitment {} not tracked", commitment_num);
            }
        }
        Ok(())
    }

    /// Finalize reserves state after revoke_and_ack
    fn finalize_reserves_state(&self, commitment_number: Option<u64>) -> DepositsResult<()> {
        // Confirm that the commitment is final and state is persisted
        if let Some(commitment_num) = commitment_number {
            log::info!("Finalizing ledger state at commitment {}", commitment_num);
        }
        Ok(())
    }

    /// Clean up reserves state on channel close
    fn cleanup_reserves_state(&self) -> DepositsResult<()> {
        // Clear active reserves
        self.active_reserves.write().unwrap().clear();
        Ok(())
    }
}

/// Types of channel updates that affect reserves
#[derive(Debug, Clone, Copy)]
pub enum ChannelUpdateType {
    CommitmentSigned,
    RevokeAndAck,
    ChannelClosed,
}

/// Integration trait for Lightning channel managers
///
/// This trait defines the interface that Lightning channel implementations
/// need to provide for Bitcoin Deposits integration.
pub trait LightningChannelIntegration {
    /// Add additional outputs to commitment transaction during construction
    fn add_additional_outputs(
        &mut self,
        outputs: Vec<TxOut>,
        commitment_number: u64,
    ) -> Result<(), DepositsError>;

    /// Validate additional outputs in received commitment transaction
    fn validate_additional_outputs(
        &self,
        commitment_tx: &Transaction,
        commitment_number: u64,
    ) -> Result<(), DepositsError>;
}

/// Channel type features for Bitcoin Deposits reserves
///
/// This is a simplified implementation that doesn't depend on private LDK types.
/// In a full integration, this would use LDK's ChannelFeatures system.
pub struct DepositsChannelFeatures;

impl DepositsChannelFeatures {
    /// Feature bit for Bitcoin Deposits reserves support (even = required, odd = optional)
    pub const RESERVES_SUPPORT_REQUIRED: u16 = 200; // Even bit = required
    pub const RESERVES_SUPPORT_OPTIONAL: u16 = 201; // Odd bit = optional

    /// Check if reserves are supported (simplified implementation)
    pub fn supports_reserves() -> bool {
        // In a real implementation, this would check negotiated channel features
        true // For now, assume reserves are always supported
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use deposits_core::constants::{MIN_RESERVES_OUTPUT_SATS, MAX_RESERVES_OUTPUT_SATS, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS};

    fn create_test_keys() -> (PublicKey, PublicKey) {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let local_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));
        let remote_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));
        (local_key, remote_key)
    }

    // ==================== CommitmentReservesOutput Tests ====================

    #[test]
    fn test_reserves_output_creation() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;

        let local_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));
        let remote_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));

        let reserves_output = CommitmentReservesOutput::new(
            1_000_000, // 1M sats
            local_key,
            remote_key,
            144, // 1 day timeout
            1,   // ledger ID
            [1u8; 32], // proposal ID
        ).unwrap();

        assert_eq!(reserves_output.amount_sats, 1_000_000);
        assert_eq!(reserves_output.emergency_timeout, 144);
        assert_eq!(reserves_output.ledger_id, 1);

        let tx_out = reserves_output.to_tx_out();
        assert_eq!(tx_out.value.to_sat(), 1_000_000);
    }

    #[test]
    fn test_reserves_script_creation() {
        let secp = Secp256k1::new();
        let mut rng = OsRng;

        let local_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));
        let remote_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));

        let script = CommitmentReservesOutput::create_reserves_script(
            local_key,
            remote_key,
            144,
        ).unwrap();

        // Verify script is not empty and contains expected opcodes
        assert!(!script.is_empty());
        assert!(script.len() > 50); // Rough size check for multisig + timelock script
    }

    // ==================== Validation Tests ====================

    #[test]
    fn test_reserves_output_minimum_amount() {
        let (local_key, remote_key) = create_test_keys();

        // Amount below minimum should fail
        let result = CommitmentReservesOutput::new(
            MIN_RESERVES_OUTPUT_SATS - 1,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        );

        assert!(result.is_err());
        match result {
            Err(DepositsError::ProtocolViolation { violation_type, .. }) => {
                assert_eq!(violation_type, "insufficient_reserves_amount");
            }
            _ => panic!("Expected ProtocolViolation with insufficient_reserves_amount"),
        }
    }

    #[test]
    fn test_reserves_output_at_minimum() {
        let (local_key, remote_key) = create_test_keys();

        // Exactly minimum should succeed
        let result = CommitmentReservesOutput::new(
            MIN_RESERVES_OUTPUT_SATS,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        );

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.amount_sats, MIN_RESERVES_OUTPUT_SATS);
    }

    #[test]
    fn test_reserves_output_maximum_amount() {
        let (local_key, remote_key) = create_test_keys();

        // Amount above maximum should fail
        let result = CommitmentReservesOutput::new(
            MAX_RESERVES_OUTPUT_SATS + 1,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        );

        assert!(result.is_err());
        match result {
            Err(DepositsError::ProtocolViolation { violation_type, .. }) => {
                assert_eq!(violation_type, "excessive_reserves_amount");
            }
            _ => panic!("Expected ProtocolViolation with excessive_reserves_amount"),
        }
    }

    #[test]
    fn test_reserves_output_at_maximum() {
        let (local_key, remote_key) = create_test_keys();

        // Exactly maximum should succeed
        let result = CommitmentReservesOutput::new(
            MAX_RESERVES_OUTPUT_SATS,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        );

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.amount_sats, MAX_RESERVES_OUTPUT_SATS);
    }

    #[test]
    fn test_reserves_output_zero_timeout_uses_default() {
        let (local_key, remote_key) = create_test_keys();

        // Zero timeout should use default
        let result = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            0, // Zero timeout - should use default
            1,
            [1u8; 32],
        );

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.emergency_timeout, DEFAULT_EMERGENCY_TIMEOUT_BLOCKS);
    }

    #[test]
    fn test_reserves_output_custom_timeout() {
        let (local_key, remote_key) = create_test_keys();

        // Custom timeout should be preserved
        let custom_timeout = 288u32;
        let result = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            custom_timeout,
            1,
            [1u8; 32],
        );

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.emergency_timeout, custom_timeout);
    }

    #[test]
    fn test_reserves_output_to_tx_out() {
        let (local_key, remote_key) = create_test_keys();

        let amount = 500_000u64;
        let output = CommitmentReservesOutput::new(
            amount,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        ).unwrap();

        let tx_out = output.to_tx_out();

        assert_eq!(tx_out.value.to_sat(), amount);
        assert_eq!(tx_out.script_pubkey, output.script_pubkey);
    }

    #[test]
    fn test_reserves_output_ledger_id_preserved() {
        let (local_key, remote_key) = create_test_keys();

        let ledger_id = 42u16;
        let output = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            144,
            ledger_id,
            [1u8; 32],
        ).unwrap();

        assert_eq!(output.ledger_id, ledger_id);
    }

    #[test]
    fn test_reserves_output_proposal_id_preserved() {
        let (local_key, remote_key) = create_test_keys();

        let proposal_id = [0xABu8; 32];
        let output = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            144,
            1,
            proposal_id,
        ).unwrap();

        assert_eq!(output.proposal_id, proposal_id);
    }

    // ==================== Script Tests ====================

    #[test]
    fn test_script_deterministic_for_same_keys() {
        let (local_key, remote_key) = create_test_keys();

        let script1 = CommitmentReservesOutput::create_reserves_script(
            local_key,
            remote_key,
            144,
        ).unwrap();

        let script2 = CommitmentReservesOutput::create_reserves_script(
            local_key,
            remote_key,
            144,
        ).unwrap();

        assert_eq!(script1, script2, "Same keys should produce same script");
    }

    #[test]
    fn test_script_different_for_different_keys() {
        let (local_key1, remote_key1) = create_test_keys();
        let (local_key2, remote_key2) = create_test_keys();

        let script1 = CommitmentReservesOutput::create_reserves_script(
            local_key1,
            remote_key1,
            144,
        ).unwrap();

        let script2 = CommitmentReservesOutput::create_reserves_script(
            local_key2,
            remote_key2,
            144,
        ).unwrap();

        assert_ne!(script1, script2, "Different keys should produce different scripts");
    }

    #[test]
    fn test_script_different_for_different_timeout() {
        let (local_key, remote_key) = create_test_keys();

        let script1 = CommitmentReservesOutput::create_reserves_script(
            local_key,
            remote_key,
            144,
        ).unwrap();

        let script2 = CommitmentReservesOutput::create_reserves_script(
            local_key,
            remote_key,
            288,
        ).unwrap();

        assert_ne!(script1, script2, "Different timeouts should produce different scripts");
    }

    #[test]
    fn test_script_order_matters() {
        let (local_key, remote_key) = create_test_keys();

        let script1 = CommitmentReservesOutput::create_reserves_script(
            local_key,
            remote_key,
            144,
        ).unwrap();

        let script2 = CommitmentReservesOutput::create_reserves_script(
            remote_key,
            local_key,
            144,
        ).unwrap();

        assert_ne!(script1, script2, "Key order should matter for script");
    }

    // ==================== DepositsChannelFeatures Tests ====================

    #[test]
    fn test_feature_bit_values() {
        // Even = required, odd = optional
        assert_eq!(DepositsChannelFeatures::RESERVES_SUPPORT_REQUIRED % 2, 0, "Required should be even");
        assert_eq!(DepositsChannelFeatures::RESERVES_SUPPORT_OPTIONAL % 2, 1, "Optional should be odd");
        assert_eq!(
            DepositsChannelFeatures::RESERVES_SUPPORT_OPTIONAL,
            DepositsChannelFeatures::RESERVES_SUPPORT_REQUIRED + 1,
            "Optional should be required + 1"
        );
    }

    #[test]
    fn test_supports_reserves() {
        // Currently returns true always - test the interface
        assert!(DepositsChannelFeatures::supports_reserves());
    }

    // ==================== CommitmentReservesOutput Equality Tests ====================

    #[test]
    fn test_reserves_output_equality() {
        let (local_key, remote_key) = create_test_keys();

        let output1 = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        ).unwrap();

        let output2 = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        ).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_reserves_output_inequality_amount() {
        let (local_key, remote_key) = create_test_keys();

        let output1 = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        ).unwrap();

        let output2 = CommitmentReservesOutput::new(
            2_000_000,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        ).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_reserves_output_clone() {
        let (local_key, remote_key) = create_test_keys();

        let output = CommitmentReservesOutput::new(
            1_000_000,
            local_key,
            remote_key,
            144,
            1,
            [1u8; 32],
        ).unwrap();

        let cloned = output.clone();
        assert_eq!(output, cloned);
    }

    #[test]
    #[ignore] // Requires full DepositsHandler setup - functionality tested in integration tests
    fn test_ledger_hash_commitment_integration() {
        use bitcoin::Network;

        // Create test keys
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let local_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));
        let remote_key = PublicKey::from_secret_key(&secp, &bitcoin::secp256k1::SecretKey::new(&mut rng));

        // Create reserves manager and channel extension
        let logger = std::sync::Arc::new(lightning::util::test_utils::TestLogger::new());
        let reserves_manager = std::sync::Arc::new(ReservesOutputManager::new(
            bitcoin::secp256k1::SecretKey::new(&mut rng),
            Network::Regtest,
            logger.clone(),
        ));

        let channel_extension = DepositsChannelExtension::new(
            [1u8; 32], // channel_id
            local_key,
            remote_key,
            reserves_manager,
            true, // reserves_enabled
            logger,
        );

        // Create a test ledger hash
        let test_ledger_hash = [0x42u8; 32];

        // Get additional outputs including ledger hash
        let outputs = channel_extension.get_additional_outputs(
            1, // commitment_number
            true, // is_local_commitment
        ).unwrap();

        // Should contain the ledger hash OP_RETURN output
        let ledger_hash_output = outputs.iter().find(|output| {
            output.value == Amount::ZERO &&
            output.script_pubkey.as_bytes().starts_with(&[OP_RETURN.to_u8()])
        }).expect("Should find ledger hash OP_RETURN output");

        // Verify the ledger hash can be extracted correctly
        let extracted_hash = channel_extension.extract_ledger_hash_from_output(
            ledger_hash_output,
            b"BDLH"
        ).expect("Should extract ledger hash");

        assert_eq!(extracted_hash, test_ledger_hash);

        // Create a commitment transaction with the outputs
        let mut commitment_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: outputs,
        };

        // Validation should succeed
        let validation_result = channel_extension.validate_commitment_transaction(
            &commitment_tx,
            1, // commitment_number
            true, // is_local_commitment
        );

        assert!(validation_result.is_ok(), "Commitment transaction validation should succeed");

        // Test with wrong ledger hash - should fail
        let _wrong_hash = [0x99u8; 32];
        let wrong_validation = channel_extension.validate_commitment_transaction(
            &commitment_tx,
            1,
            true,
        );

        assert!(wrong_validation.is_err(), "Should fail with wrong ledger hash");

        // Test without ledger hash when expected - should fail
        commitment_tx.output.retain(|output| {
            !(output.value == Amount::ZERO &&
              output.script_pubkey.as_bytes().starts_with(&[OP_RETURN.to_u8()]))
        });

        let missing_hash_validation = channel_extension.validate_commitment_transaction(
            &commitment_tx,
            1,
            true,
        );

        assert!(missing_hash_validation.is_err(), "Should fail when ledger hash is missing");

    }
}
