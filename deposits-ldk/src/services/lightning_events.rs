//! Lightning Event Service
//!
//! Automatically handles Lightning Network events and coordinates with Bitcoin Deposits protocol.
//! This service replaces manual operations from tests:
//! - Manual: `alice_bd.mark_ledger_committed(bob_pk, 1)`
//! - Automated: Lightning commitment signed → automatic ledger commitment tracking
//! 
//! - Manual: `alice_bd.credit_deposit_balance(bob_pk, deposit_pubkey, amount)`
//! - Automated: Lightning payment received → automatic deposit crediting

use std::collections::{HashMap, VecDeque};
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::channelmanager::PaymentId;
use lightning::util::logger::Logger as LdkLogger;
use deposits_core::{log_info, log_warn};

use crate::handler::DepositsHandler;
use crate::handler::{PaymentTracking, LedgerOperationsExt};
use crate::hex_utils;
use super::{ServiceError, ReservesManagementService, LighthouseService};

/// Lightning event types that trigger Bitcoin Deposits state changes
#[derive(Debug, Clone)]
pub enum LightningEvent {
    /// Lightning payment was received - should credit deposit
    PaymentReceived {
        payment_hash: [u8; 32],
        amount_msat: u64,
        channel_id: [u8; 32],
    },
    
    /// Lightning payment was sent - handled by PaymentOrchestrationService
    PaymentSent {
        payment_id: PaymentId,
        payment_hash: [u8; 32],
        amount_msat: u64,
    },
    
    /// Lightning commitment transaction signed - should mark ledger committed
    CommitmentSigned {
        channel_id: [u8; 32],
        commitment_number: u64,
    },
    
    /// Channel closed - should handle cleanup
    ChannelClosed {
        channel_id: [u8; 32],
        partner_node_id: PublicKey,
    },
}

/// Maps channels to their partner node IDs
type ChannelPartnerMap = Arc<RwLock<HashMap<[u8; 32], PublicKey>>>;

/// Service that automatically handles Lightning events for Bitcoin Deposits
pub struct LightningEventService<L: Deref + Clone>
where
    L::Target: LdkLogger,
{
    /// Bitcoin Deposits protocol handler
    deposits_handler: Arc<DepositsHandler<L>>,

    /// Reserves management service for automatic reserves updates
    reserves_manager: Option<Arc<ReservesManagementService<L>>>,

    /// Lighthouse service for channel close monitoring
    /// Used to notify auditors when channels close (with or without reserves)
    lighthouse: Option<Arc<LighthouseService<L>>>,

    /// Map of channel IDs to partner node IDs
    channel_partners: ChannelPartnerMap,

    /// Queue of events to process
    event_queue: Arc<Mutex<VecDeque<LightningEvent>>>,

    /// Logger
    logger: L,
}

impl<L: Deref + Clone> LightningEventService<L>
where
    L::Target: LdkLogger,
{
    /// Create new Lightning event service
    pub fn new(
        deposits_handler: Arc<DepositsHandler<L>>,
        logger: L,
    ) -> Self {
        Self {
            deposits_handler,
            reserves_manager: None,
            lighthouse: None,
            channel_partners: Arc::new(RwLock::new(HashMap::new())),
            event_queue: Arc::new(Mutex::new(VecDeque::new())),
            logger,
        }
    }
    
    // Note: For advanced use cases, additional constructors could be added here
    // that work with handler references rather than owned handlers

    // NOTE: sync_handler_data removed - unused placeholder

    /// Set the reserves management service (optional dependency injection)
    pub fn set_reserves_manager(&mut self, reserves_manager: Arc<ReservesManagementService<L>>) {
        self.reserves_manager = Some(reserves_manager);
    }

    /// Set the lighthouse service for channel close monitoring (optional dependency injection)
    /// When set, channel close events will be forwarded to the lighthouse for tracking
    pub fn set_lighthouse(&mut self, lighthouse: Arc<LighthouseService<L>>) {
        self.lighthouse = Some(lighthouse);
    }

    /// Register a channel and its partner node ID
    pub fn register_channel(&self, channel_id: [u8; 32], partner_node_id: PublicKey) {
        let mut channel_partners = self.channel_partners.write().unwrap();
        channel_partners.insert(channel_id, partner_node_id);
    }
    
    /// Register a payment that should fund a specific deposit
    /// Delegates to the handler's payment registry
    pub fn register_payment_for_deposit(
        &self,
        payment_hash: [u8; 32],
        partner_node_id: PublicKey,
        deposit_pubkey: PublicKey,
        invoice_id: String,
        bolt11: String,
    ) {
        self.deposits_handler.register_deposit_invoice(
            payment_hash,
            partner_node_id,
            deposit_pubkey,
            invoice_id,
            bolt11,
        );
    }

    /// Get the bolt11 invoice string for a registered payment
    pub fn get_payment_bolt11(&self, payment_hash: &[u8; 32]) -> Option<String> {
        self.deposits_handler.get_deposit_invoice_bolt11(payment_hash)
    }

    /// Check if a payment hash is registered as a deposit invoice
    pub fn is_deposit_payment(&self, payment_hash: &[u8; 32]) -> bool {
        self.deposits_handler.is_deposit_invoice_payment(payment_hash)
    }

    /// **NON-CONFORMING**: Unregister a payment so it goes to the node instead of the deposit.
    /// This is for testing non-conforming protocol behavior where the operator receives
    /// funds that should have credited a deposit.
    #[cfg(feature = "bitcoin-deposits-non-conforming")]
    pub fn unregister_payment_for_deposit(&self, payment_hash: [u8; 32]) -> bool {
        self.deposits_handler.unregister_deposit_invoice(&payment_hash);
        log_info!(
            self.logger,
            "⚠️ NON-CONFORMING: Unregistered payment {} - funds will go to node instead of deposit",
            hex_utils::to_string(&payment_hash)
        );
        true
    }

    /// Handle Lightning payment received event
    /// Replaces manual: `alice_bd.credit_deposit_balance(bob_pk, deposit_pubkey, amount)`
    pub async fn handle_payment_received(
        &self,
        payment_hash: [u8; 32],
        amount_msat: u64,
        channel_id: [u8; 32],
    ) -> Result<(), ServiceError> {

        // Find which deposit this payment should fund
        let (partner_id, deposit_pubkey, invoice_id, _bolt11) = match self.find_deposit_for_payment(payment_hash) {
            Ok(result) => {
                result
            },
            Err(e) => {
                return Err(e);
            }
        };

        // If channel_id is provided (not all zeros), verify it matches expected partner
        if channel_id != [0; 32] {
            let channel_partner = self.get_partner_for_channel(channel_id)?;
            if channel_partner != partner_id {
                log_warn!(
                    self.logger,
                    "Payment received on wrong channel: expected partner {} but got {}",
                    partner_id, channel_partner
                );
                return Err(ServiceError::PartnerNotFound);
            }
        }

        log_info!(
            self.logger,
            "Processing payment received: {} msat for deposit {} on channel with partner {}",
            amount_msat, deposit_pubkey, partner_id
        );

        // Credit deposit using async method that sends message and waits for ACK
        self.deposits_handler.credit_deposit_and_move_reserves_async(
            partner_id,
            deposit_pubkey,
            amount_msat,
            payment_hash,
            invoice_id,
        ).await.map_err(|e| ServiceError::Protocol(e))?;
        
        // Automatically trigger reserves management if available
        if let Some(ref reserves_manager) = self.reserves_manager {
            reserves_manager.handle_deposit_balance_change(
                partner_id,
                amount_msat as i64, // Positive change
            )?;
        }
        
        // Clean up payment mapping
        self.deposits_handler.unregister_deposit_invoice(&payment_hash);

        log_info!(
            self.logger,
            "Successfully credited {} msat to deposit {} and updated reserves",
            amount_msat, deposit_pubkey
        );
        
        Ok(())
    }
    
    /// Handle real Lightning payment received event and coordinate with the real handler
    /// This method uses the real Lightning handler for operations instead of service handler
    pub fn handle_real_payment_received(
        &self,
        real_handler: &DepositsHandler<L>,
        payment_hash: [u8; 32],
        amount_msat: u64,
        channel_id: [u8; 32],
    ) -> Result<(), ServiceError> {
        // Find partner for this channel
        let partner_id = self.get_partner_for_channel(channel_id)?;

        // Find which deposit this payment should fund
        let (expected_partner, deposit_pubkey, _invoice_id, _bolt11) = self.find_deposit_for_payment(payment_hash)?;
        
        // Verify partner matches
        if expected_partner != partner_id {
            log_warn!(
                self.logger, 
                "Payment received on wrong channel: expected partner {} but got {}", 
                expected_partner, partner_id
            );
            return Err(ServiceError::PartnerNotFound);
        }
        
        log_info!(
            self.logger,
            "Processing real Lightning payment received: {} msat for deposit {} on channel with partner {}",
            amount_msat, deposit_pubkey, partner_id
        );
        
        // Use REAL Lightning handler to credit deposit and move 100% to reserves
        // (The other 100% collateral comes from other channels)
        real_handler.credit_deposit_and_move_reserves(
            partner_id,
            deposit_pubkey,
            amount_msat,
        ).map_err(ServiceError::Protocol)?;
        
        // Clean up payment mapping
        self.deposits_handler.unregister_deposit_invoice(&payment_hash);

        log_info!(
            self.logger,
            "Successfully credited {} msat to deposit {} using real Lightning handler",
            amount_msat, deposit_pubkey
        );
        
        Ok(())
    }
    
    /// Handle Lightning commitment signed event  
    /// Replaces manual: `alice_bd.mark_ledger_committed(bob_pk, commitment_number)`
    pub fn handle_commitment_signed(
        &self,
        channel_id: [u8; 32],
        commitment_number: u64,
    ) -> Result<(), ServiceError> {
        // Find partner for this channel
        let partner_id = self.get_partner_for_channel(channel_id)?;
        
        log_info!(
            self.logger,
            "Processing commitment signed: commitment #{} with partner {}",
            commitment_number, partner_id
        );
        
        // Automatically mark ledger committed (replaces manual test operation)
        self.deposits_handler.mark_ledger_committed(
            partner_id,
            commitment_number,
        )?;
        
        log_info!(
            self.logger,
            "Successfully marked ledger committed at commitment #{} with partner {}",
            commitment_number, partner_id
        );
        
        Ok(())
    }
    
    /// Handle Lightning commitment signed event using the real handler
    /// This method uses the real Lightning handler for commitment tracking
    pub fn handle_real_commitment_signed(
        &self,
        real_handler: &DepositsHandler<L>,
        channel_id: [u8; 32],
        commitment_number: u64,
    ) -> Result<(), ServiceError> {
        // Find partner for this channel
        let partner_id = self.get_partner_for_channel(channel_id)?;
        
        log_info!(
            self.logger,
            "Processing real commitment signed: commitment #{} with partner {}",
            commitment_number, partner_id
        );
        
        // Use REAL Lightning handler for commitment tracking (this is the key difference)
        real_handler.mark_ledger_committed(
            partner_id,
            commitment_number,
        ).map_err(ServiceError::Protocol)?;
        
        log_info!(
            self.logger,
            "Successfully marked ledger committed at commitment #{} with partner {} using real handler",
            commitment_number, partner_id
        );
        
        Ok(())
    }
    
    /// Handle Lightning payment sent event
    pub fn handle_payment_sent(
        &self,
        payment_id: PaymentId,
        _payment_hash: [u8; 32], 
        amount_msat: u64,
    ) -> Result<(), ServiceError> {
        log_info!(
            self.logger,
            "Processing payment sent: payment_id {:?}, {} msat",
            payment_id, amount_msat
        );
        
        // Payment sent events are primarily handled by PaymentOrchestrationService
        // This service just logs for monitoring purposes
        
        Ok(())
    }
    
    /// Handle channel closed event
    pub fn handle_channel_closed(
        &self,
        channel_id: [u8; 32],
        partner_node_id: PublicKey,
    ) -> Result<(), ServiceError> {
        self.handle_channel_closed_with_type(channel_id, partner_node_id, false)
    }

    /// Handle channel closed event with close type info
    /// is_cooperative: true if mutual close, false if force close
    pub fn handle_channel_closed_with_type(
        &self,
        channel_id: [u8; 32],
        partner_node_id: PublicKey,
        is_cooperative: bool,
    ) -> Result<(), ServiceError> {
        log_info!(
            self.logger,
            "Processing channel closed: channel {:?} with partner {}, cooperative={}",
            channel_id, partner_node_id, is_cooperative
        );

        // Notify lighthouse service if configured
        // This allows auditors to detect channel closes even without reserves outputs
        if let Some(ref lighthouse) = self.lighthouse {
            if let Some(event) = lighthouse.on_channel_closed(channel_id, is_cooperative) {
                log_info!(
                    self.logger,
                    "Lighthouse event emitted for channel close: {:?}",
                    event
                );
            }
        }

        // Clean up channel mapping
        let mut channel_partners = self.channel_partners.write().unwrap();
        channel_partners.remove(&channel_id);

        // Handle Bitcoin Deposits protocol cleanup for closed channels
        // This involves finalizing operations, settling reserves, and cleanup
        self.handle_channel_closure_cleanup(channel_id, partner_node_id)?;

        Ok(())
    }
    
    /// Handle Bitcoin Deposits protocol cleanup when a channel closes
    /// This ensures proper finalization of deposits and reserves
    fn handle_channel_closure_cleanup(
        &self,
        channel_id: [u8; 32],
        partner_node_id: PublicKey
    ) -> Result<(), ServiceError> {
        log_info!(
            self.logger,
            "Processing Bitcoin Deposits cleanup for closed channel: {:?} with partner: {}",
            hex_utils::to_string(&channel_id),
            partner_node_id
        );

        // TODO: Broadcast ChannelCloseTombstone to create permanent audit record
        // This will mark the ledger as closed and prevent sequence number mismatches on reconnection
        // Implementation pending: need to add public API to DepositsHandler for tombstone broadcast
        log_info!(
            self.logger,
            "Channel closed for partner {} - tombstone broadcast pending implementation",
            partner_node_id
        );

        // In a production system, this would also:
        // 1. Finalize any pending deposits for this channel
        // 2. Settle remaining reserves back to on-chain
        // 3. Clean up payment-to-deposit mappings for this partner
        // 4. Notify other services about the channel closure

        // Clean up payment deposits mapping for this partner
        self.deposits_handler.cleanup_payments_for_partner(partner_node_id);
        
        log_info!(
            self.logger,
            "Completed Bitcoin Deposits cleanup for channel with partner: {}",
            partner_node_id
        );
        
        // Notify reserves manager if available
        if let Some(ref _reserves_manager) = self.reserves_manager {
            // In production, this would notify the reserves manager about channel closure
            // so it can handle final reserves settlement back to on-chain
            log_info!(
                self.logger,
                "Would notify reserves manager about channel closure for partner: {}",
                partner_node_id
            );
        }
        
        Ok(())
    }
    
    /// Process all queued events (async version)
    pub async fn process_events(&self) -> Result<usize, ServiceError> {
        let mut processed = 0;

        loop {
            let event = {
                let mut queue = self.event_queue.lock().unwrap();
                queue.pop_front()
            };

            match event {
                Some(LightningEvent::PaymentReceived { payment_hash, amount_msat, channel_id }) => {
                    self.handle_payment_received(payment_hash, amount_msat, channel_id).await?;
                    processed += 1;
                },
                Some(LightningEvent::PaymentSent { payment_id, payment_hash, amount_msat }) => {
                    self.handle_payment_sent(payment_id, payment_hash, amount_msat)?;
                    processed += 1;
                },
                Some(LightningEvent::CommitmentSigned { channel_id, commitment_number }) => {
                    self.handle_commitment_signed(channel_id, commitment_number)?;
                    processed += 1;
                },
                Some(LightningEvent::ChannelClosed { channel_id, partner_node_id }) => {
                    self.handle_channel_closed(channel_id, partner_node_id)?;
                    processed += 1;
                },
                None => break, // No more events
            }
        }

        Ok(processed)
    }
    
    /// Queue a Lightning event for processing
    pub fn queue_event(&self, event: LightningEvent) {
        let mut queue = self.event_queue.lock().unwrap();
        queue.push_back(event);
    }
    
    /// Get partner node ID for a channel
    fn get_partner_for_channel(&self, channel_id: [u8; 32]) -> Result<PublicKey, ServiceError> {
        let channel_partners = self.channel_partners.read().unwrap();
        channel_partners
            .get(&channel_id)
            .copied()
            .ok_or(ServiceError::ChannelNotFound)
    }
    
    /// Find which deposit a payment should fund
    /// Returns (partner_node_id, deposit_pubkey, invoice_id, bolt11) if found
    pub fn find_deposit_for_payment(
        &self,
        payment_hash: [u8; 32],
    ) -> Result<(PublicKey, PublicKey, String, String), ServiceError> {
        self.deposits_handler
            .get_deposit_for_payment(&payment_hash)
            .ok_or(ServiceError::DepositNotFound)
    }
}

// Integration trait for the channel extension to call this service
// NOTE: These methods are placeholders for future channel extension integration
// They are currently unused and commented out because process_events() is now async
/*
impl<L: Deref + Clone> LightningEventService<L>
where
    L::Target: LdkLogger,
{
    /// Called by channel extension when commitment is signed
    /// This is the integration point that replaces manual commitment tracking
    pub fn on_commitment_signed_from_channel_extension(
        &self,
        channel_id: [u8; 32],
        commitment_number: u64,
    ) -> Result<(), ServiceError> {
        self.queue_event(LightningEvent::CommitmentSigned {
            channel_id,
            commitment_number,
        });

        // Process immediately for synchronous behavior
        self.process_events()?;

        Ok(())
    }

    /// Called by Lightning payment handling when payment is received
    /// This is the integration point that replaces manual deposit crediting
    pub fn on_payment_received_from_lightning(
        &self,
        payment_hash: [u8; 32],
        amount_msat: u64,
        channel_id: [u8; 32],
    ) -> Result<(), ServiceError> {
        self.queue_event(LightningEvent::PaymentReceived {
            payment_hash,
            amount_msat,
            channel_id,
        });

        // Process immediately for synchronous behavior
        self.process_events()?;

        Ok(())
    }
}
*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning::util::test_utils::TestLogger;
    use crate::handler::DepositsHandler;

    fn create_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut bytes = [seed; 32];
        if seed == 0 { bytes[0] = 1; }
        let secret = SecretKey::from_slice(&bytes).unwrap();
        PublicKey::from_secret_key(&secp, &secret)
    }

    fn create_test_handler() -> Arc<DepositsHandler<Arc<TestLogger>>> {
        let logger = Arc::new(TestLogger::new());
        Arc::new(DepositsHandler::new_for_testing(logger))
    }

    fn create_test_service() -> LightningEventService<Arc<TestLogger>> {
        let handler = create_test_handler();
        let logger = Arc::new(TestLogger::new());
        LightningEventService::new(handler, logger)
    }

    #[test]
    fn test_service_creation() {
        let service = create_test_service();

        // Service should start with no registered channels
        let partner = create_test_pubkey(1);
        let channel_id = [1u8; 32];

        // Getting partner for unregistered channel should fail
        let result = service.get_partner_for_channel(channel_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_channel() {
        let service = create_test_service();
        let partner = create_test_pubkey(2);
        let channel_id = [2u8; 32];

        // Register channel
        service.register_channel(channel_id, partner);

        // Should now be able to get partner
        let result = service.get_partner_for_channel(channel_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), partner);
    }

    #[test]
    fn test_register_multiple_channels() {
        let service = create_test_service();
        let partner1 = create_test_pubkey(10);
        let partner2 = create_test_pubkey(11);
        let channel1 = [10u8; 32];
        let channel2 = [11u8; 32];

        service.register_channel(channel1, partner1);
        service.register_channel(channel2, partner2);

        assert_eq!(service.get_partner_for_channel(channel1).unwrap(), partner1);
        assert_eq!(service.get_partner_for_channel(channel2).unwrap(), partner2);
    }

    #[test]
    fn test_register_payment_for_deposit() {
        let service = create_test_service();
        let partner = create_test_pubkey(20);
        let deposit_pubkey = create_test_pubkey(21);
        let payment_hash = [0xAA; 32];

        // Register payment
        service.register_payment_for_deposit(
            payment_hash,
            partner,
            deposit_pubkey,
            "invoice-123".to_string(),
            "lnbc100...".to_string(),
        );

        // Should be able to find the deposit
        assert!(service.is_deposit_payment(&payment_hash));

        let result = service.find_deposit_for_payment(payment_hash);
        assert!(result.is_ok());

        let (found_partner, found_deposit, invoice_id, bolt11) = result.unwrap();
        assert_eq!(found_partner, partner);
        assert_eq!(found_deposit, deposit_pubkey);
        assert_eq!(invoice_id, "invoice-123");
        assert_eq!(bolt11, "lnbc100...");
    }

    #[test]
    fn test_is_deposit_payment() {
        let service = create_test_service();
        let partner = create_test_pubkey(30);
        let deposit_pubkey = create_test_pubkey(31);
        let registered_hash = [0xBB; 32];
        let unregistered_hash = [0xCC; 32];

        service.register_payment_for_deposit(
            registered_hash,
            partner,
            deposit_pubkey,
            "inv".to_string(),
            "bolt11".to_string(),
        );

        assert!(service.is_deposit_payment(&registered_hash));
        assert!(!service.is_deposit_payment(&unregistered_hash));
    }

    #[test]
    fn test_get_payment_bolt11() {
        let service = create_test_service();
        let partner = create_test_pubkey(40);
        let deposit_pubkey = create_test_pubkey(41);
        let payment_hash = [0xDD; 32];

        service.register_payment_for_deposit(
            payment_hash,
            partner,
            deposit_pubkey,
            "inv".to_string(),
            "lnbc500n1ptest".to_string(),
        );

        let bolt11 = service.get_payment_bolt11(&payment_hash);
        assert!(bolt11.is_some());
        assert_eq!(bolt11.unwrap(), "lnbc500n1ptest");

        // Unregistered payment should return None
        let unknown_hash = [0xEE; 32];
        assert!(service.get_payment_bolt11(&unknown_hash).is_none());
    }

    #[test]
    fn test_find_deposit_for_payment_not_found() {
        let service = create_test_service();
        let unknown_hash = [0xFF; 32];

        let result = service.find_deposit_for_payment(unknown_hash);
        assert!(result.is_err());
        match result {
            Err(ServiceError::DepositNotFound) => {}
            other => panic!("Expected DepositNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_queue_event() {
        let service = create_test_service();

        // Queue multiple events
        service.queue_event(LightningEvent::CommitmentSigned {
            channel_id: [1u8; 32],
            commitment_number: 1,
        });

        service.queue_event(LightningEvent::PaymentSent {
            payment_id: PaymentId([2u8; 32]),
            payment_hash: [3u8; 32],
            amount_msat: 50_000,
        });

        // Verify queue has events
        let queue = service.event_queue.lock().unwrap();
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_handle_commitment_signed() {
        let service = create_test_service();
        let partner = create_test_pubkey(50);
        let channel_id = [50u8; 32];

        // Register channel first
        service.register_channel(channel_id, partner);

        // Handle commitment signed
        let result = service.handle_commitment_signed(channel_id, 1);

        // Will fail because there's no ledger, but shouldn't panic
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_commitment_signed_unknown_channel() {
        let service = create_test_service();
        let unknown_channel = [99u8; 32];

        let result = service.handle_commitment_signed(unknown_channel, 1);
        assert!(result.is_err());
        match result {
            Err(ServiceError::ChannelNotFound) => {}
            other => panic!("Expected ChannelNotFound, got: {:?}", other),
        }
    }

    #[test]
    fn test_handle_channel_closed() {
        let service = create_test_service();
        let partner = create_test_pubkey(60);
        let channel_id = [60u8; 32];

        // Register channel first
        service.register_channel(channel_id, partner);

        // Handle channel close
        let result = service.handle_channel_closed(channel_id, partner);
        assert!(result.is_ok());

        // Channel should now be unregistered
        let lookup_result = service.get_partner_for_channel(channel_id);
        assert!(lookup_result.is_err());
    }

    #[test]
    fn test_handle_channel_closed_with_type_cooperative() {
        let service = create_test_service();
        let partner = create_test_pubkey(70);
        let channel_id = [70u8; 32];

        service.register_channel(channel_id, partner);

        let result = service.handle_channel_closed_with_type(channel_id, partner, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_channel_closed_with_type_force() {
        let service = create_test_service();
        let partner = create_test_pubkey(71);
        let channel_id = [71u8; 32];

        service.register_channel(channel_id, partner);

        let result = service.handle_channel_closed_with_type(channel_id, partner, false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_payment_sent() {
        let service = create_test_service();
        let payment_id = PaymentId([80u8; 32]);
        let payment_hash = [81u8; 32];

        // Payment sent handling is mostly logging
        let result = service.handle_payment_sent(payment_id, payment_hash, 100_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_lightning_event_variants() {
        // Test that all event variants can be created
        let payment_received = LightningEvent::PaymentReceived {
            payment_hash: [1u8; 32],
            amount_msat: 50_000,
            channel_id: [2u8; 32],
        };

        let payment_sent = LightningEvent::PaymentSent {
            payment_id: PaymentId([3u8; 32]),
            payment_hash: [4u8; 32],
            amount_msat: 100_000,
        };

        let commitment_signed = LightningEvent::CommitmentSigned {
            channel_id: [5u8; 32],
            commitment_number: 42,
        };

        let channel_closed = LightningEvent::ChannelClosed {
            channel_id: [6u8; 32],
            partner_node_id: create_test_pubkey(90),
        };

        // All should be Debug-formattable
        let _ = format!("{:?}", payment_received);
        let _ = format!("{:?}", payment_sent);
        let _ = format!("{:?}", commitment_signed);
        let _ = format!("{:?}", channel_closed);
    }

    #[test]
    fn test_set_reserves_manager() {
        let handler = create_test_handler();
        let logger = Arc::new(TestLogger::new());
        let mut service = LightningEventService::new(Arc::clone(&handler), logger.clone());

        // Create a reserves manager
        let reserves_manager = Arc::new(super::super::ReservesManagementService::new(
            handler,
            std::time::Duration::from_secs(60),
            10_000,
            logger,
        ));

        // Set it
        service.set_reserves_manager(reserves_manager);

        // Service should now have the reserves manager (internal check)
        assert!(service.reserves_manager.is_some());
    }

    #[tokio::test]
    async fn test_process_events_empty_queue() {
        let service = create_test_service();

        // Process with empty queue
        let result = service.process_events().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_handle_payment_received_unknown_payment() {
        let service = create_test_service();
        let unknown_hash = [0xAB; 32];
        let channel_id = [0u8; 32]; // All zeros = no specific channel

        let result = service.handle_payment_received(unknown_hash, 50_000, channel_id).await;

        // Should fail because payment hash isn't registered
        assert!(result.is_err());
        match result {
            Err(ServiceError::DepositNotFound) => {}
            other => panic!("Expected DepositNotFound, got: {:?}", other),
        }
    }
}
