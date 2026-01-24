// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

//! Channel Ledger - Bitcoin Deposits ledger for Lightning channels
//!
//! This module provides the `ChannelLedger` type which manages the state of
//! Bitcoin Deposits for a specific Lightning channel direction.

use bitcoin::secp256k1::PublicKey;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use deposits_core::{
    DepositsError, DepositsResult, now_unix_timestamp,
    ReservesStatus, Invoice,
    constants::MIN_RESERVES_RATIO_PERCENT,
};
use crate::wire::types::{Deposit, ReservesOutput, PendingInvoice, FeeStructure};
use crate::handler::messages::{
    DepositsMessage, LedgerUpdateMsg, LedgerOperation, CollateralAttestationMsg,
};
use lightning::util::ser::Readable;

/// A single ledger update entry - the atomic unit of ledger state transition
/// The ledger state is derived by applying updates in sequence from genesis
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerUpdate {
    /// Sequential update number (0 for first update, 1 for second, etc.)
    pub sequence_number: u64,
    /// The protocol message that represents this state transition (serialized)
    pub message: Vec<u8>,
    /// Hash of the previous update in the chain (0x0 for genesis/first update)
    pub previous_hash: [u8; 32],
    /// Hash of this update (computed from sequence_number, message, and previous_hash)
    pub consensus_hash: [u8; 32],
}

impl LedgerUpdate {
    /// Calculate the hash of this update based on its contents
    /// This computes the consensus_hash field from sequence_number, message, and previous_hash
    pub fn calculate_hash(&self) -> [u8; 32] {
        use bitcoin::hashes::{Hash, sha256};

        // Create deterministic serialization of update fields (excluding consensus_hash)
        let mut hash_input = Vec::new();

        // Include sequence_number
        hash_input.extend_from_slice(&self.sequence_number.to_le_bytes());

        // Include previous_hash
        hash_input.extend_from_slice(&self.previous_hash);

        // Include the protocol message bytes (already serialized)
        hash_input.extend_from_slice(&self.message);

        // Hash the combined input
        *sha256::Hash::hash(&hash_input).as_byte_array()
    }

    /// Get the deserialized message from this update
    pub fn get_message(&self) -> Result<crate::handler::messages::DepositsMessage, DepositsError> {
        use lightning::util::ser::Readable;
        use std::io::Cursor;

        let mut cursor = Cursor::new(&self.message);
        crate::handler::messages::DepositsMessage::read(&mut cursor)
            .map_err(|_| DepositsError::SerializationError)
    }
}

/// Bitcoin Deposits ledger for a specific Lightning channel
/// This is DIRECTIONAL - one ledger per (operator, partner) pair
/// Alice→Eve and Eve→Alice are two separate ledgers
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelLedger {
    /// The operator of this ledger (the node who creates deposits)
    pub operator_node_id: PublicKey,

    /// Lightning channel partner's public key (the node who cosigns/validates)
    pub partner_node_id: PublicKey,

    /// ledger address (as string)
    pub ledger_address: String,

    /// All deposits in this channel's ledger (keyed by depositor pubkey)
    pub deposits: HashMap<PublicKey, Deposit>,

    /// Current reserves output state
    pub reserves: ReservesOutput,

    /// Consensus hash of this ledger state
    /// This hash must be identical for both channel partners
    /// and is embedded in the Lightning channel commitment transaction
    pub consensus_hash: [u8; 32],

    /// Pending invoice awaiting payment
    pub pending_invoice: Option<PendingInvoice>,

    /// Messages sent to partner awaiting acknowledgment (message_hash -> message_type)
    pub pending_acks: HashMap<[u8; 32], u16>,

    /// Last update timestamp for this ledger
    pub last_updated: u64,

    /// Partner's deepest acknowledged hash
    /// This is the most recent ledger hash that our channel partner has sent an ACK for.
    /// When partner ACKs a message, we update this to the new_hash from that message.
    /// Starts at [0; 32] for new ledgers, updated as partner ACKs our messages.
    pub partner_deepest_ack_hash: [u8; 32],

    /// Channel's deepest embedded commitment hash
    /// This is the most recent ledger hash that has been embedded in a Lightning
    /// commitment transaction's reserves output.
    /// Updated when we successfully update the channel commitment with new reserves.
    /// Starts at [0; 32] for new ledgers, updated when commitments include new state.
    pub channel_deepest_commitment_hash: [u8; 32],

    /// History of all ledger updates for audit trail
    pub update_history: Vec<LedgerUpdate>,

    /// Track processed payment hashes to prevent duplicate credits
    /// Set of payment_hash values that have already been credited
    /// This is transient state (not persisted) - rebuilt from ledger history on restart
    #[serde(skip)]
    pub processed_payments: std::collections::HashSet<[u8; 32]>,

    /// Collateral partners who provide additional backing from other channels
    pub collateral_partners: Vec<PublicKey>,

    /// Collateral attestations from collateral partners
    /// Each attestation proves how much the partner can slash if operator misbehaves
    pub collateral_attestations: HashMap<PublicKey, crate::handler::messages::CollateralAttestationMsg>,
}

impl ChannelLedger {
    /// Create a new ChannelLedger for a Lightning channel partner
    pub fn new(
        operator_node_id: PublicKey,
        partner_node_id: PublicKey,
        ledger_address: bitcoin::Address,
    ) -> Self {
        ChannelLedger {
            operator_node_id,
            partner_node_id,
            ledger_address: ledger_address.to_string(),
            deposits: HashMap::new(),
            reserves: {
                let mut channel_id = [0u8; 32];
                channel_id.copy_from_slice(&partner_node_id.serialize()[1..]); // Skip first byte of pubkey
                ReservesOutput::new(
                    channel_id,
                    0,
                    PublicKey::from_slice(&[2; 33]).unwrap(), // Placeholder
                )
            },
            consensus_hash: [0u8; 32], // Genesis state - no updates yet
            pending_invoice: None,
            pending_acks: HashMap::new(),
            last_updated: now_unix_timestamp(),
            partner_deepest_ack_hash: [0u8; 32], // No ACKs yet
            channel_deepest_commitment_hash: [0u8; 32], // No commitments yet
            update_history: Vec::new(),
            processed_payments: std::collections::HashSet::new(),
            collateral_partners: Vec::new(),
            collateral_attestations: HashMap::new(),
        }
    }

    /// Add a deposit to this ledger
    pub fn add_deposit(
        &mut self,
        _depositor_pubkey: PublicKey,
        deposit_pubkey: PublicKey,
        fees: Option<FeeStructure>,
    ) -> Result<(), DepositsError> {
        // Apply the update (this will insert deposit, update consensus hash, and record in history)
        use crate::handler::messages::{DepositsMessage, LedgerUpdateMsg, LedgerOperation};
        let update_msg = LedgerUpdateMsg::new_with_operation(
            self.operator_node_id,
            self.partner_node_id,
            LedgerOperation::DepositOpen {
                pubkey: deposit_pubkey,
                fees: fees.map(|f| f.into()),
                payment_hash: None,
                invoice: None,
                cosigner_guarantee_signature: None,
            },
        );
        self.apply_update(DepositsMessage::LedgerUpdate(update_msg))?;

        Ok(())
    }

    /// Handle a Bitcoin Deposits protocol message for this channel ledger
    /// Returns response messages to send back to the partner
    pub fn handle_message(
        &mut self,
        message: DepositsMessage,
        sender_node_id: PublicKey,
    ) -> Result<(Vec<DepositsMessage>, Option<Vec<u8>>), DepositsError> {
        // Verify the message is from either the operator or partner of this ledger
        // (not some random third party)
        if sender_node_id != self.operator_node_id && sender_node_id != self.partner_node_id {
            return Err(DepositsError::InvalidPartner);
        }

        let responses = Vec::new();
        let mut cosignature = None;

        // Handle different message types
        match message {
            DepositsMessage::DepositOpen { pubkey, fees, .. } => {
                // Partner is requesting to add a deposit
                self.add_deposit(pubkey, pubkey, fees.map(|f| f.into()))?;
            }
            DepositsMessage::ReceivingCreditPayment { payment_hash, deposit_pubkey, amount, ref invoice_id, partner_id, sequence_number } => {
                // Partner is crediting a deposit after receiving a Lightning payment
                // Check if this payment has already been processed (idempotency)
                if self.processed_payments.contains(&payment_hash) {
                    // Payment already processed, skip to avoid duplicate ledger updates
                    // This is normal when messages are retransmitted
                    return Ok((responses, cosignature));
                }

                // Mark payment as processed
                self.processed_payments.insert(payment_hash);

                // Update timestamp to current time
                self.last_updated = now_unix_timestamp();

                // Apply the balance credit (use the message being processed)
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let credit_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::PaymentCredit {
                        payment_hash,
                        deposit_pubkey,
                        amount,
                        invoice_id: invoice_id.clone(),
                        sequence_number: self.update_history.len() as u64,
                    },
                );
                self.apply_update(DepositsMessage::LedgerUpdate(credit_msg))?;

                // Calculate new required reserves deterministically from deposit state
                // This ensures both operator and partner calculate the same reserves
                // Formula: reserves = 1.2 * sum(deposits) + max(outstanding_invoices)
                let total_deposits = self.calculate_total_deposit_balances();

                // Find the maximum outstanding invoice amount across all deposits
                let max_outstanding_invoice = self.deposits.values()
                    .flat_map(|d| d.invoices.iter())
                    .map(|inv| inv.amount)
                    .max()
                    .unwrap_or(0);

                // 100%+100% model: 100% reserves in this channel, 100% collateral from other channels
                let new_required_reserves = total_deposits.saturating_add(max_outstanding_invoice);

                // Apply the reserves update (using absolute target values)
                let old_reserves = self.reserves.amount;
                if new_required_reserves > old_reserves {
                    let reserves_msg = LedgerUpdateMsg::new_with_operation(
                        self.operator_node_id,
                        self.partner_node_id,
                        LedgerOperation::ReservesIncrease { new_amount: new_required_reserves },
                    );
                    self.apply_update(DepositsMessage::LedgerUpdate(reserves_msg))?;
                } else if new_required_reserves < old_reserves {
                    let reserves_msg = LedgerUpdateMsg::new_with_operation(
                        self.operator_node_id,
                        self.partner_node_id,
                        LedgerOperation::ReservesDecrease { new_amount: new_required_reserves },
                    );
                    self.apply_update(DepositsMessage::LedgerUpdate(reserves_msg))?;
                }
                // If equal, no update needed
            }
            DepositsMessage::ReceivingCosignInvoice { amount, payment_hash, expires, assigned_deposit, ref invoice_id, ref bolt11 } => {
                // Partner is requesting us to cosign an invoice
                // We need to validate that adequate reserves exist for this invoice exposure
                // and create a signature as proof of cosigning
                // HACK MVP: Use reserves.amount which will be updated to reflect operator's channel balance
                let pending_invoice = PendingInvoice::new(amount, payment_hash, expires, assigned_deposit, invoice_id.clone(), bolt11.clone());
                let signature = self.cosign_invoice(pending_invoice, self.reserves.amount)?;
                cosignature = Some(signature);
            }
            DepositsMessage::SendingLockPayment { pubkey, amount, payment_id, sequence_number, scriptpubkey_signature } => {
                // Operator is locking balance for an outgoing payment
                // Validate sufficient balance
                if let Some(deposit) = self.deposits.get(&pubkey) {
                    let available_balance = deposit.balance.saturating_sub(deposit.locked_balance);
                    if available_balance < amount {
                        return Err(DepositsError::InsufficientBalance);
                    }
                } else {
                    return Err(DepositsError::DepositNotFound);
                }

                // Update timestamp to current time
                self.last_updated = now_unix_timestamp();

                // Apply the update (use the message being processed)
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let lock_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::PaymentLock {
                        pubkey,
                        amount,
                        payment_id,
                        sequence_number: self.update_history.len() as u64,
                        scriptpubkey_signature,
                    },
                );
                self.apply_update(DepositsMessage::LedgerUpdate(lock_msg))?;
            }
            DepositsMessage::SendingFulfillPayment { pubkey, amount, payment_id, sequence_number: _, scriptpubkey_signature, preimage } => {
                // Operator is permanently deducting locked balance (payment succeeded)

                // Update timestamp to current time
                self.last_updated = now_unix_timestamp();

                // Apply the update (use the message being processed)
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let fulfill_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::PaymentFulfill {
                        pubkey,
                        amount,
                        payment_id,
                        sequence_number: self.update_history.len() as u64,
                        scriptpubkey_signature,
                        preimage,
                    },
                );
                self.apply_update(DepositsMessage::LedgerUpdate(fulfill_msg))?;

            }
            DepositsMessage::SendingFailPayment { pubkey, amount, payment_id, sequence_number: _ } => {
                // Operator is releasing locked balance (payment failed)
                // Update timestamp to current time
                self.last_updated = now_unix_timestamp();

                // Apply the update
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let fail_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::PaymentFail {
                        pubkey,
                        amount,
                        payment_id,
                        sequence_number: self.update_history.len() as u64,
                    },
                );
                self.apply_update(DepositsMessage::LedgerUpdate(fail_msg))?;
            }
            DepositsMessage::ReservesIncrease { new_amount, partner_id: _ } => {
                // Operator is declaring new reserves level (moving from channel to reserves)
                // Update timestamp for deterministic state
                self.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Apply reserves increase
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let reserves_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::ReservesIncrease { new_amount },
                );
                self.apply_update(DepositsMessage::LedgerUpdate(reserves_msg))?;
            }
            DepositsMessage::ReservesDecrease { new_amount, partner_id: _ } => {
                // Operator is moving reserves back to local channel balance
                // Message contains absolute new_amount target

                // Update timestamp for deterministic state
                self.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Apply reserves decrease with absolute target amount
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let reserves_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::ReservesDecrease { new_amount },
                );
                self.apply_update(DepositsMessage::LedgerUpdate(reserves_msg))?;
            }
            DepositsMessage::DepositClose { pubkey, partner_id: _ } => {
                // Operator is requesting to remove a deposit
                // Validate that the deposit exists and has zero balance
                if let Some(deposit) = self.deposits.get(&pubkey) {
                    if deposit.balance != 0 {
                        return Err(DepositsError::NonZeroBalance {
                            balance: deposit.balance
                        });
                    }
                    if !deposit.invoices.is_empty() {
                        return Err(DepositsError::OutstandingInvoices {
                            count: deposit.invoices.len()
                        });
                    }

                    // Update timestamp
                    self.last_updated = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Apply deposit removed update (this will remove the deposit via apply_update)
                    use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                    let close_msg = LedgerUpdateMsg::new_with_operation(
                        self.operator_node_id,
                        self.partner_node_id,
                        LedgerOperation::DepositClose { pubkey },
                    );
                    self.apply_update(DepositsMessage::LedgerUpdate(close_msg))?;
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            DepositsMessage::LedgerClose { partner_id: _ } => {
                // Operator is requesting to close the ledger
                // Validate that there are no deposits
                if !self.deposits.is_empty() {
                    return Err(DepositsError::ProtocolViolation {
                        violation_type: "LedgerCloseWithDeposits".to_string(),
                        details: format!("Cannot close ledger with {} active deposits", self.deposits.len())
                    });
                }

                // Update timestamp
                self.last_updated = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Apply ledger closed update
                use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
                let ledger_close_msg = LedgerUpdateMsg::new_with_operation(
                    self.operator_node_id,
                    self.partner_node_id,
                    LedgerOperation::LedgerClose,
                );
                self.apply_update(DepositsMessage::LedgerUpdate(ledger_close_msg))?;
            }
            // TODO: Handle other message types (transfer, etc.)
            _ => {
                // For unhandled message types, we'll return empty response for now
                // In a complete implementation, all message types would be handled
            }
        }

        Ok((responses, cosignature))
    }

    /// Add a message to pending acknowledgments
    pub fn add_pending_ack(&mut self, message_hash: [u8; 32], message_type: u16) {
        self.pending_acks.insert(message_hash, message_type);
    }

    /// Apply a ledger update to the state and record it in history
    /// This is the ONLY way ledger state should be modified.
    /// Uses to_operation() to handle both V1 and V2 message formats uniformly.
    pub fn apply_update(&mut self, message: DepositsMessage) -> Result<(), DepositsError> {
        use DepositsMessage;
        use crate::handler::messages::CollateralAttestationMsg;

        // Apply the state transition via LedgerOperation (unified V1/V2 handling)
        if let Some(operation) = message.to_operation() {
            self.apply_operation(&operation)?;
        } else {
            // Handle special messages that don't convert to LedgerOperation
            match &message {
                DepositsMessage::LedgerOpenRequest(_) => {
                    // Ledger opened - no state change needed, this is just for audit trail
                }
                DepositsMessage::CollateralAttestation { operator, collateral_partner, amount, block_height, signature, ledger_hash } => {
                    // V1 CollateralAttestation - not in LedgerOperation, handle directly
                    if self.collateral_partners.contains(collateral_partner) {
                        let msg = CollateralAttestationMsg {
                            operator: *operator,
                            collateral_partner: *collateral_partner,
                            amount: *amount,
                            block_height: *block_height,
                            signature: *signature,
                            ledger_hash: *ledger_hash,
                        };
                        self.collateral_attestations.insert(*collateral_partner, msg);
                    }
                }
                _ => {
                    // Other message types don't affect ledger state
                }
            }
        }

        // Update timestamp
        self.last_updated = now_unix_timestamp();

        // Record the update in history
        let previous_hash = self.update_history.last()
            .map(|u| u.consensus_hash)
            .unwrap_or([0u8; 32]);

        // Next sequence number is the count of existing updates
        let sequence_number = self.update_history.len() as u64;

        // Serialize the message using Lightning format with message type prefix
        // encode() includes the message type, which DepositsMessage::read() expects
        let message_bytes = message.encode();

        // Create the update with its own content-based hash
        let mut update = LedgerUpdate {
            sequence_number,
            message: message_bytes,
            previous_hash,
            consensus_hash: [0u8; 32], // Temporary value
        };

        // Calculate the hash based on this update's contents
        update.consensus_hash = update.calculate_hash();

        // The ledger's consensus hash is now the hash of the most recent update
        self.consensus_hash = update.consensus_hash;

        self.update_history.push(update);

        Ok(())
    }

    /// Apply a LedgerOperation to the ledger state (internal, single code path)
    /// This is the unified handler for all ledger-modifying operations.
    fn apply_operation(&mut self, operation: &crate::handler::messages::LedgerOperation) -> Result<(), DepositsError> {
        use crate::handler::messages::{LedgerOperation, CollateralAttestationMsg};

        match operation {
            LedgerOperation::ReservesAdd { amount, .. } => {
                self.reserves.amount = self.reserves.amount.saturating_add(*amount);
            }
            LedgerOperation::ReservesRemove => {
                self.reserves.amount = 0;
            }
            LedgerOperation::ReservesIncrease { new_amount } => {
                self.reserves.amount = *new_amount;
            }
            LedgerOperation::ReservesDecrease { new_amount } => {
                self.reserves.amount = *new_amount;
            }
            LedgerOperation::ReservesUpdateSpendTo { .. } => {
                // No balance state change
            }
            LedgerOperation::DepositOpen { pubkey, fees, .. } => {
                let deposit = Deposit::new(*pubkey, fees.clone());
                self.deposits.insert(*pubkey, deposit);
            }
            LedgerOperation::DepositClose { pubkey } => {
                self.deposits.remove(pubkey);
            }
            LedgerOperation::DepositUpdate { pubkey, new_fees } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.fees = new_fees.clone();
                }
            }
            LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => {
                if let Some(deposit) = self.deposits.get_mut(deposit_pubkey) {
                    deposit.balance += amount;
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::PaymentLock { pubkey, amount, .. } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.locked_balance += amount;
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::PaymentFail { pubkey, amount, .. } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.locked_balance = deposit.locked_balance.saturating_sub(*amount);
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::PaymentFulfill { pubkey, amount, .. } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.locked_balance = deposit.locked_balance.saturating_sub(*amount);
                    deposit.balance = deposit.balance.saturating_sub(*amount);
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::TransferLock { pubkey, amount, .. } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.locked_balance += amount;
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::TransferFail { .. } => {
                // TransferFail doesn't carry amount
            }
            LedgerOperation::TransferFulfill { pubkey, amount, .. } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.locked_balance = deposit.locked_balance.saturating_sub(*amount);
                    deposit.balance = deposit.balance.saturating_sub(*amount);
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::FeeCollect { pubkey, amount, block_height } => {
                if let Some(deposit) = self.deposits.get_mut(pubkey) {
                    deposit.balance = deposit.balance.saturating_sub(*amount);
                    deposit.last_fee_assessment = *block_height;
                } else {
                    return Err(DepositsError::DepositNotFound);
                }
            }
            LedgerOperation::CollateralIncrease { .. } => {
                // ChannelLedger doesn't track collateral amount directly
            }
            LedgerOperation::CollateralDecrease { .. } => {
                // ChannelLedger doesn't track collateral amount directly
            }
            LedgerOperation::CollateralAddPartner { collateral_partner, .. } => {
                if !self.collateral_partners.contains(collateral_partner) {
                    self.collateral_partners.push(*collateral_partner);
                }
            }
            LedgerOperation::CollateralRemovePartner { collateral_partner, .. } => {
                self.collateral_partners.retain(|p| p != collateral_partner);
                self.collateral_attestations.remove(collateral_partner);
            }
            LedgerOperation::CollateralAttestation { collateral_operator, amount, block_height, signature, ledger_hash } => {
                // Store attestation by signing partner
                let attestation_msg = CollateralAttestationMsg {
                    operator: *collateral_operator,
                    collateral_partner: self.partner_node_id,
                    amount: *amount,
                    block_height: *block_height,
                    signature: *signature,
                    ledger_hash: *ledger_hash,
                };
                self.collateral_attestations.insert(self.partner_node_id, attestation_msg);
            }
            LedgerOperation::LedgerClose => {
                self.deposits.clear();
                self.reserves.amount = 0;
            }
            LedgerOperation::Tombstone { .. } => {
                // Tombstone marks ledger as closed, no state changes
            }
        }
        Ok(())
    }

    /// Apply a ledger update atomically and return metadata needed for broadcasting
    /// Returns (prev_hash, new_hash, sequence_number) in a single atomic operation
    /// This prevents race conditions where another thread could append between operations
    pub fn apply_update_with_metadata(&mut self, message: DepositsMessage) -> Result<([u8; 32], [u8; 32], u64), DepositsError> {
        // Capture metadata BEFORE applying the update
        let prev_hash = self.update_history.last()
            .map(|u| u.consensus_hash)
            .unwrap_or([0u8; 32]);
        let sequence_number = self.update_history.len() as u64;

        // Apply the update (this will append to update_history and update consensus_hash)
        self.apply_update(message)?;

        // The new_hash is the consensus_hash after applying the update
        let new_hash = self.consensus_hash;

        Ok((prev_hash, new_hash, sequence_number))
    }

    /// Append a message to the ledger and return the new consensus hash
    /// This is an alias for apply_update that returns the new hash
    pub fn append_mut(&mut self, message: DepositsMessage) -> Result<[u8; 32], DepositsError> {
        self.apply_update(message)?;
        Ok(self.consensus_hash)
    }

    /// Append a message to the ledger and return metadata needed for broadcasting
    /// Returns (prev_hash, new_hash, sequence_number) in a single atomic operation
    /// This is an alias for apply_update_with_metadata
    pub fn append_mut_with_metadata(&mut self, message: DepositsMessage) -> Result<([u8; 32], [u8; 32], u64), DepositsError> {
        self.apply_update_with_metadata(message)
    }

    /// Get the ledger update history
    pub fn get_update_history(&self) -> &[LedgerUpdate] {
        &self.update_history
    }

    /// Remove a message from pending acknowledgments when ack received
    /// For now, we transition directly from Proposed to Committed on ACK
    /// (skipping Acknowledged until real commitment tx update is implemented)
    pub fn handle_ack(&mut self, message_hash: [u8; 32]) -> Option<u16> {
        self.pending_acks.remove(&message_hash)
        // Note: Caller (handle_received_ack) will call mark_committed_to_channel
        // to transition from Proposed to Committed
    }

    /// Get all pending acknowledgments (for monitoring/debugging)
    pub fn get_pending_acks(&self) -> &HashMap<[u8; 32], u16> {
        &self.pending_acks
    }

    /// Check if we're waiting for acknowledgment of a specific message
    pub fn is_waiting_for_ack(&self, message_hash: [u8; 32]) -> bool {
        self.pending_acks.contains_key(&message_hash)
    }

    /// Mark that the current ledger hash has been embedded in a Lightning channel commitment
    /// This updates channel_deepest_commitment_hash to track what state is locked in the channel
    pub fn mark_committed_to_channel(&mut self, ledger_hash: [u8; 32]) {
        self.channel_deepest_commitment_hash = ledger_hash;
    }

    /// Update partner's deepest ACK hash when we receive an ACK from them
    /// This tracks the most recent ledger state they've acknowledged
    pub fn mark_partner_ack(&mut self, acked_hash: [u8; 32]) {
        self.partner_deepest_ack_hash = acked_hash;
    }

    /// Add balance to a deposit with commitment change and reserves validation
    pub fn add_balance_to_deposit(
        &mut self,
        depositor_pubkey: PublicKey,
        amount: u64,
    ) -> Result<(), DepositsError> {
        // Check if deposit exists first
        if !self.deposits.contains_key(&depositor_pubkey) {
            return Err(DepositsError::DepositNotFound);
        }

        // Get current balance and calculate new balance
        let current_balance = self.deposits[&depositor_pubkey].balance;
        let new_balance = current_balance + amount;

        // Calculate what total deposits would be after this change
        let total_deposits_after = self.calculate_total_deposit_balances_if_changed(depositor_pubkey, new_balance);

        // Validate 100% reserves requirement
        self.validate_reserves_requirement_for_total(total_deposits_after)?;

        // If validation passes, apply the update
        use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
        let credit_msg = LedgerUpdateMsg::new_with_operation(
            self.operator_node_id,
            self.partner_node_id,
            LedgerOperation::PaymentCredit {
                payment_hash: [0u8; 32], // Placeholder for direct balance add
                deposit_pubkey: depositor_pubkey,
                amount,
                invoice_id: String::new(), // No invoice for direct add
                sequence_number: self.update_history.len() as u64,
            },
        );
        self.apply_update(DepositsMessage::LedgerUpdate(credit_msg))?;

        Ok(())
    }

    /// Credit deposit and move required amount to reserves
    /// This is the standard operation when a deposit payment is received
    pub fn credit_deposit_and_move_to_reserves(
        &mut self,
        depositor_pubkey: PublicKey,
        credit_amount: u64,
        reserve_move_amount: u64,
    ) -> Result<(), DepositsError> {
        // Check if deposit exists first
        if !self.deposits.contains_key(&depositor_pubkey) {
            return Err(DepositsError::DepositNotFound);
        }

        // Credit the deposit
        let current_balance = self.deposits[&depositor_pubkey].balance;
        let new_balance = current_balance + credit_amount;

        // Move amount to reserves
        let new_reserves_amount = self.reserves.amount + reserve_move_amount;

        // Calculate what total deposits would be after this change
        let total_deposits_after = self.calculate_total_deposit_balances_if_changed(depositor_pubkey, new_balance);

        // Validate that reserves will satisfy requirements with new total deposits
        let required_reserves = (total_deposits_after * 120) / 100;
        if new_reserves_amount < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: new_reserves_amount,
            });
        }

        // Apply the balance credit
        use crate::handler::messages::{LedgerUpdateMsg, LedgerOperation};
        let credit_msg = LedgerUpdateMsg::new_with_operation(
            self.operator_node_id,
            self.partner_node_id,
            LedgerOperation::PaymentCredit {
                payment_hash: [0u8; 32], // Placeholder for direct balance add
                deposit_pubkey: depositor_pubkey,
                amount: credit_amount,
                invoice_id: String::new(), // No invoice for direct add
                sequence_number: self.update_history.len() as u64,
            },
        );
        self.apply_update(DepositsMessage::LedgerUpdate(credit_msg))?;

        // Apply the reserves increase (using absolute target value)
        let reserves_msg = LedgerUpdateMsg::new_with_operation(
            self.operator_node_id,
            self.partner_node_id,
            LedgerOperation::ReservesIncrease { new_amount: new_reserves_amount },
        );
        self.apply_update(DepositsMessage::LedgerUpdate(reserves_msg))?;

        Ok(())
    }

    // REMOVED: remove_balance_from_deposit and update_reserves_amount
    // These methods directly mutated ledger state without creating proper ledger updates.
    // All state changes should go through apply_update() to maintain audit trail integrity.
    // Use protocol messages (SendingFulfillPayment, ReservesToReserves, etc.) instead.

    // REMOVED: add_to_reserves and reduce_reserves
    // These were wrappers around update_reserves_amount which has been removed.
    // Use protocol messages (ReservesToReserves, ReservesToLocal) instead.

    /// Calculate total deposit balances across all deposits
    pub fn calculate_total_deposit_balances(&self) -> u64 {
        self.deposits.values().map(|deposit| deposit.balance).sum()
    }

    /// Calculate total deposit balances if one deposit balance were changed
    fn calculate_total_deposit_balances_if_changed(&self, changed_depositor: PublicKey, new_balance: u64) -> u64 {
        self.deposits.iter().map(|(pubkey, deposit)| {
            if *pubkey == changed_depositor {
                new_balance // Use the hypothetical new balance
            } else {
                deposit.balance // Use existing balance
            }
        }).sum()
    }

    /// Calculate required reserves amount (100% of total deposits)
    /// The 100%+100% model: 100% reserves in channel + 100% collateral from other channels
    pub fn calculate_required_reserves(&self, total_deposits: u64) -> u64 {
        // Use constant from constants.rs (now 100%)
        (total_deposits * MIN_RESERVES_RATIO_PERCENT as u64) / 100
    }

    /// Validate that current reserves meet the 100% requirement for given total deposits
    pub fn validate_reserves_requirement_for_total(&self, total_deposits: u64) -> Result<(), DepositsError> {
        let required_reserves = self.calculate_required_reserves(total_deposits);
        let current_reserves = self.reserves.amount;

        if current_reserves < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: current_reserves,
            });
        }

        Ok(())
    }

    /// Check if reserves are adequate for current deposit balances
    pub fn validate_current_reserves_requirement(&self) -> Result<(), DepositsError> {
        let total_deposits = self.calculate_total_deposit_balances();
        self.validate_reserves_requirement_for_total(total_deposits)
    }

    /// Get reserves status information
    pub fn get_reserves_status(&self) -> ReservesStatus {
        let total_deposits = self.calculate_total_deposit_balances();
        let required_reserves = self.calculate_required_reserves(total_deposits);
        let current_reserves = self.reserves.amount;
        let excess_reserves = if current_reserves > required_reserves {
            current_reserves - required_reserves
        } else {
            0
        };

        // Calculate largest outstanding invoice (simplified - no invoices tracked yet)
        let max_outstanding_invoice = 0; // TODO: Calculate from pending invoices

        ReservesStatus {
            current_amount: current_reserves,
            required_amount: required_reserves,
            excess_amount: excess_reserves,
            total_deposit_balances: total_deposits,
            max_outstanding_invoice,
            deposit_count: self.deposits.len(),
            total_locked_balances: self.deposits.values().map(|d| d.locked_balance).sum(),
        }
    }

    /// Cosign an invoice - validate that reserves are adequate for this new invoice exposure
    /// This implements the critical security check: partner must verify reserves before
    /// operator can create invoices that increase exposure
    ///
    /// Returns a cosignature over the invoice payment_hash on success
    /// TODO: Replace placeholder signature with real ECDSA signature
    pub fn cosign_invoice(&mut self, pending_invoice: PendingInvoice, available_reserves_sat: u64) -> Result<Vec<u8>, DepositsError> {
        // Verify the deposit exists
        if !self.deposits.contains_key(&pending_invoice.assigned_deposit) {
            return Err(DepositsError::ProtocolViolation {
                violation_type: "invalid_invoice_deposit".to_string(),
                details: format!(
                    "Cannot cosign invoice: assigned deposit {} does not exist",
                    pending_invoice.assigned_deposit
                ),
            });
        }

        // Calculate total current deposit balances
        let total_deposits = self.calculate_total_deposit_balances();

        // Find the maximum outstanding invoice amount across all deposits
        // This represents our current maximum exposure
        let current_max_invoice = self.deposits.values()
            .flat_map(|d| d.invoices.iter())
            .map(|inv| inv.amount)
            .max()
            .unwrap_or(0);

        // The new invoice could become the new maximum if it's larger
        let new_max_invoice = std::cmp::max(current_max_invoice, pending_invoice.amount);

        // Calculate required reserves with the new invoice exposure
        // Formula: reserves >= total_deposits + max(invoice_amounts)
        // (100% in channel + 100% collateral from other channels via ensure_collateral_across_ledgers)
        let required_reserves = total_deposits.saturating_add(new_max_invoice);

        // Verify we have adequate reserves for this invoice
        // HACK: Using operator's channel balance (to_remote) as reserves for MVP
        if available_reserves_sat < required_reserves {
            return Err(DepositsError::InsufficientReserves {
                required: required_reserves,
                available: available_reserves_sat,
            });
        }

        // Add the invoice to the assigned deposit's invoice list
        if let Some(deposit) = self.deposits.get_mut(&pending_invoice.assigned_deposit) {
            // Construct invoice directly from pending invoice fields
            let invoice = Invoice {
                id: pending_invoice.invoice_id.clone(),
                payment_hash: pending_invoice.payment_hash,
                amount: pending_invoice.amount,
                expires: pending_invoice.expires,
                assigned_deposit: pending_invoice.assigned_deposit,
                bolt11: pending_invoice.bolt11.clone(),
            };
            deposit.invoices.push(invoice.into());

            // NOTE: Invoice creation doesn't create a ledger update or change the consensus hash
            // The consensus hash only changes when ledger updates are added to the update chain
            // TODO: Add proper InvoiceCreated update type to LedgerUpdateData if needed
        }

        // TODO: Create a proper signature over the payment_hash
        // For now, return a placeholder signature (hash of the payment_hash + "cosigned")
        // In production, this should be a real ECDSA signature from the partner's key
        use bitcoin::hashes::{Hash, sha256};
        let mut sig_input = Vec::new();
        sig_input.extend_from_slice(&pending_invoice.payment_hash);
        sig_input.extend_from_slice(b"cosigned");
        let signature_hash = sha256::Hash::hash(&sig_input);

        // Return the hash as a placeholder signature
        Ok(signature_hash.to_byte_array().to_vec())
    }
}
