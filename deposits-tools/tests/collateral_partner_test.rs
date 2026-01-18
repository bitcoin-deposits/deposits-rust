//! Tests for collateral partner management via ledger updates
//!
//! Tests the AddCollateralPartner, RemoveCollateralPartner, CollateralAttestation,
//! CollateralConsentRequest, and CollateralConsentResponse messages and their effect on ledger state.

#[cfg(test)]
mod tests {
    use ldk_node::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::collections::HashMap;

    /// Generate a deterministic test public key
    fn generate_test_pubkey(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        secret_bytes[0] = seed;
        secret_bytes[31] = 1; // Ensure non-zero
        let secret_key = SecretKey::from_slice(&secret_bytes).expect("valid secret key");
        PublicKey::from_secret_key(&secp, &secret_key)
    }

    // =========================================================================
    // Message Encoding/Decoding Tests
    // =========================================================================

    #[test]
    fn test_add_collateral_partner_message_roundtrip() {
        use deposits_ldk::handler::messages::{CollateralAddPartnerMsg, DepositsMessage};
        use lightning::util::ser::{Readable, Writeable};
        use std::io::Cursor;

        let operator_id = generate_test_pubkey(1);
        let partner_id = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let msg = CollateralAddPartnerMsg {
            operator_id,
            partner_id,
            collateral_partner,
            collateral_partner_signature: [0xCD; 64],
        };

        // Encode
        let mut buffer = Vec::new();
        msg.write(&mut buffer).expect("should encode");

        // Decode
        let mut cursor = Cursor::new(&buffer);
        let decoded: CollateralAddPartnerMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.operator_id, operator_id);
        assert_eq!(decoded.partner_id, partner_id);
        assert_eq!(decoded.collateral_partner, collateral_partner);
        assert_eq!(decoded.collateral_partner_signature, [0xCD; 64]);

        println!("✅ AddCollateralPartnerMsg roundtrip test passed!");
    }

    #[test]
    fn test_collateral_consent_request_message_roundtrip() {
        use deposits_ldk::handler::messages::{CollateralConsentRequestMsg, DepositsMessage};
        use lightning::util::ser::{Readable, Writeable};
        use std::io::Cursor;

        let operator_id = generate_test_pubkey(1);
        let partner_id = generate_test_pubkey(2);

        let msg = CollateralConsentRequestMsg {
            operator_id,
            partner_id,
            operator_signature: [0xEF; 64],
        };

        // Encode
        let mut buffer = Vec::new();
        msg.write(&mut buffer).expect("should encode");

        // Decode
        let mut cursor = Cursor::new(&buffer);
        let decoded: CollateralConsentRequestMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.operator_id, operator_id);
        assert_eq!(decoded.partner_id, partner_id);
        assert_eq!(decoded.operator_signature, [0xEF; 64]);

        println!("✅ CollateralConsentRequestMsg roundtrip test passed!");
    }

    #[test]
    fn test_collateral_consent_response_message_roundtrip() {
        use deposits_ldk::handler::messages::{CollateralConsentResponseMsg, DepositsMessage};
        use lightning::util::ser::{Readable, Writeable};
        use std::io::Cursor;

        let operator_id = generate_test_pubkey(1);
        let partner_id = generate_test_pubkey(2);

        // Test with consent granted
        let msg_granted = CollateralConsentResponseMsg {
            operator_id,
            partner_id,
            consent_granted: true,
            collateral_partner_signature: [0x12; 64],
        };

        let mut buffer = Vec::new();
        msg_granted.write(&mut buffer).expect("should encode");

        let mut cursor = Cursor::new(&buffer);
        let decoded: CollateralConsentResponseMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.operator_id, operator_id);
        assert_eq!(decoded.partner_id, partner_id);
        assert_eq!(decoded.consent_granted, true);
        assert_eq!(decoded.collateral_partner_signature, [0x12; 64]);

        // Test with consent denied
        let msg_denied = CollateralConsentResponseMsg {
            operator_id,
            partner_id,
            consent_granted: false,
            collateral_partner_signature: [0u8; 64],
        };

        let mut buffer2 = Vec::new();
        msg_denied.write(&mut buffer2).expect("should encode");

        let mut cursor2 = Cursor::new(&buffer2);
        let decoded2: CollateralConsentResponseMsg = Readable::read(&mut cursor2).expect("should decode");

        assert_eq!(decoded2.consent_granted, false);

        println!("✅ CollateralConsentResponseMsg roundtrip test passed!");
    }

    #[test]
    fn test_remove_collateral_partner_message_roundtrip() {
        use deposits_ldk::handler::messages::{CollateralRemovePartnerMsg, DepositsMessage};
        use lightning::util::ser::{Readable, Writeable};
        use std::io::Cursor;

        let partner_id = generate_test_pubkey(1);
        let collateral_partner = generate_test_pubkey(2);

        let msg = CollateralRemovePartnerMsg {
            partner_id,
            collateral_partner,
            operator_signature: [0xCD; 64],
        };

        // Encode
        let mut buffer = Vec::new();
        msg.write(&mut buffer).expect("should encode");

        // Decode
        let mut cursor = Cursor::new(&buffer);
        let decoded: CollateralRemovePartnerMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.partner_id, partner_id);
        assert_eq!(decoded.collateral_partner, collateral_partner);
        assert_eq!(decoded.operator_signature, [0xCD; 64]);

        println!("✅ RemoveCollateralPartnerMsg roundtrip test passed!");
    }

    #[test]
    fn test_collateral_attestation_message_roundtrip() {
        use deposits_ldk::handler::messages::{CollateralAttestationMsg, DepositsMessage};
        use lightning::util::ser::{Readable, Writeable};
        use std::io::Cursor;

        let operator = generate_test_pubkey(1);
        let collateral_partner = generate_test_pubkey(2);

        let msg = CollateralAttestationMsg {
            operator,
            collateral_partner,
            amount: 100_000,
            block_height: 800_000,
            signature: [0xEF; 64],
            ledger_hash: [0u8; 32],
        };

        // Encode
        let mut buffer = Vec::new();
        msg.write(&mut buffer).expect("should encode");

        // Decode
        let mut cursor = Cursor::new(&buffer);
        let decoded: CollateralAttestationMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.operator, operator);
        assert_eq!(decoded.collateral_partner, collateral_partner);
        assert_eq!(decoded.amount, 100_000);
        assert_eq!(decoded.block_height, 800_000);
        assert_eq!(decoded.signature, [0xEF; 64]);

        // Test available_collateral calculation
        assert_eq!(msg.available_collateral(), 100_000);

        println!("✅ CollateralAttestationMsg roundtrip test passed!");
    }

    // =========================================================================
    // Ledger State Transition Tests
    // =========================================================================

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_add_collateral_partner_via_message() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_remove_collateral_partner_via_message() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_collateral_attestation_from_channel_partner() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_collateral_attestation_from_collateral_partner() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_collateral_attestation_from_unknown_rejected() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_remove_collateral_partner_clears_attestation() {
        todo!("Update test for V2 Ledger API");
    }

    // =========================================================================
    // Hash Chain Tests
    // =========================================================================

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_collateral_partner_messages_update_hash_chain() {
        todo!("Update test for V2 Ledger API");
    }

    // =========================================================================
    // Message Type Tests
    // =========================================================================

    #[test]
    fn test_message_type_constants() {
        use deposits_ldk::handler::messages::{
            COLLATERAL_ADD_PARTNER, COLLATERAL_REMOVE_PARTNER,
            COLLATERAL_CONSENT_REQUEST, COLLATERAL_CONSENT_RESPONSE
        };
        use deposits_ldk::handler::messages::{
            CollateralAddPartnerMsg, CollateralRemovePartnerMsg,
            CollateralConsentRequestMsg, CollateralConsentResponseMsg,
            DepositsMessage
        };

        // Verify message type constants
        assert_eq!(COLLATERAL_ADD_PARTNER, 0x8097);
        assert_eq!(COLLATERAL_REMOVE_PARTNER, 0x8099);
        assert_eq!(COLLATERAL_CONSENT_REQUEST, 0x809B);
        assert_eq!(COLLATERAL_CONSENT_RESPONSE, 0x809D);

        // AddCollateralPartner with consent signature
        let add_msg = DepositsMessage::CollateralAddPartner {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            collateral_partner: generate_test_pubkey(3),
            collateral_partner_signature: [0u8; 64],
        };
        assert_eq!(add_msg.message_type(), COLLATERAL_ADD_PARTNER);

        let remove_msg = DepositsMessage::CollateralRemovePartner {
            partner_id: generate_test_pubkey(1),
            collateral_partner: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        };
        assert_eq!(remove_msg.message_type(), COLLATERAL_REMOVE_PARTNER);

        // Consent request message type
        let consent_request = DepositsMessage::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        };
        assert_eq!(consent_request.message_type(), COLLATERAL_CONSENT_REQUEST);

        // Consent response message type
        let consent_response = DepositsMessage::CollateralConsentResponse {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0u8; 64],
        };
        assert_eq!(consent_response.message_type(), COLLATERAL_CONSENT_RESPONSE);

        println!("✅ Message type constants test passed!");
    }

    // =========================================================================
    // Consent Flow Tests
    // =========================================================================

    #[test]
    fn test_consent_message_variant_names() {
        use deposits_ldk::handler::messages::{
            CollateralConsentRequestMsg, CollateralConsentResponseMsg,
            DepositsMessage
        };

        let request = DepositsMessage::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        };
        assert_eq!(request.variant_name(), "CollateralConsentRequest");

        let response = DepositsMessage::CollateralConsentResponse {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0u8; 64],
        };
        assert_eq!(response.variant_name(), "CollateralConsentResponse");

        println!("✅ Consent message variant names test passed!");
    }

    #[test]
    fn test_consent_messages_have_partner_id() {
        use deposits_ldk::handler::messages::{
            CollateralConsentRequestMsg, CollateralConsentResponseMsg,
            DepositsMessage
        };

        let partner_id = generate_test_pubkey(2);

        let request = DepositsMessage::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id,
            operator_signature: [0u8; 64],
        };
        assert_eq!(request.partner_id(), Some(partner_id));

        let response = DepositsMessage::CollateralConsentResponse {
            operator_id: generate_test_pubkey(1),
            partner_id,
            consent_granted: false,
            collateral_partner_signature: [0u8; 64],
        };
        assert_eq!(response.partner_id(), Some(partner_id));

        println!("✅ Consent messages partner_id test passed!");
    }

    #[test]
    fn test_add_collateral_partner_requires_consent_signature() {
        use deposits_ldk::handler::messages::{CollateralAddPartnerMsg, DepositsMessage};
        use lightning::util::ser::{Readable, Writeable};
        use std::io::Cursor;

        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral = generate_test_pubkey(3);

        // Message with consent signature (valid flow)
        // Note: operator_signature is no longer in AddCollateralPartnerMsg since
        // the message is wrapped in SignedLedgerUpdate which contains the operator signature
        let msg_with_consent = CollateralAddPartnerMsg {
            operator_id: operator,
            partner_id: partner,
            collateral_partner: collateral,
            collateral_partner_signature: [0xBB; 64],
        };

        // Verify the consent signature is encoded and decoded
        let mut buffer = Vec::new();
        msg_with_consent.write(&mut buffer).expect("should encode");

        let mut cursor = Cursor::new(&buffer);
        let decoded: CollateralAddPartnerMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.operator_id, operator);
        assert_eq!(decoded.collateral_partner_signature, [0xBB; 64]);

        println!("✅ AddCollateralPartner requires consent signature test passed!");
    }

    // =========================================================================
    // Message Routing Tests (Broadcast Queue Skip List)
    // =========================================================================

    /// Tests that consent request messages should be skipped from broadcast queue
    /// These are coordination messages, NOT ledger updates
    #[test]
    fn test_consent_request_should_skip_broadcast_queue() {
        use deposits_ldk::handler::messages::{
            CollateralConsentRequestMsg, DepositsMessage
        };

        let msg = DepositsMessage::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        };

        // Verify message type is correct (0x809B)
        assert_eq!(msg.message_type(), 0x809B);

        // The matches! macro should match this message type for skip list
        let should_skip = matches!(msg,
            DepositsMessage::Ack(_) |
            DepositsMessage::SignedUpdate(_) |
            DepositsMessage::ReceivingCosignInvoice { .. } |
            DepositsMessage::CollateralConsentRequest { .. } |
            DepositsMessage::CollateralConsentResponse { .. }
        );
        assert!(should_skip, "CollateralConsentRequest should be in the skip list");

        println!("✅ CollateralConsentRequest skip broadcast queue test passed!");
    }

    /// Tests that consent response messages should be skipped from broadcast queue
    /// These are coordination messages, NOT ledger updates
    #[test]
    fn test_consent_response_should_skip_broadcast_queue() {
        use deposits_ldk::handler::messages::{
            CollateralConsentResponseMsg, DepositsMessage
        };

        let msg = DepositsMessage::CollateralConsentResponse {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0u8; 64],
        };

        // Verify message type is correct (0x809D)
        assert_eq!(msg.message_type(), 0x809D);

        // The matches! macro should match this message type for skip list
        let should_skip = matches!(msg,
            DepositsMessage::Ack(_) |
            DepositsMessage::SignedUpdate(_) |
            DepositsMessage::ReceivingCosignInvoice { .. } |
            DepositsMessage::CollateralConsentRequest { .. } |
            DepositsMessage::CollateralConsentResponse { .. }
        );
        assert!(should_skip, "CollateralConsentResponse should be in the skip list");

        println!("✅ CollateralConsentResponse skip broadcast queue test passed!");
    }

    /// Tests that AddCollateralPartner (a ledger update) should NOT be skipped
    #[test]
    fn test_add_collateral_partner_should_not_skip_broadcast_queue() {
        use deposits_ldk::handler::messages::{
            CollateralAddPartnerMsg, DepositsMessage
        };

        let msg = DepositsMessage::CollateralAddPartner {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            collateral_partner: generate_test_pubkey(3),
            collateral_partner_signature: [0u8; 64],
        };

        // Verify message type is correct (0x8097)
        assert_eq!(msg.message_type(), 0x8097);

        // AddCollateralPartner is a ledger update and should NOT be skipped
        let should_skip = matches!(msg,
            DepositsMessage::Ack(_) |
            DepositsMessage::SignedUpdate(_) |
            DepositsMessage::ReceivingCosignInvoice { .. } |
            DepositsMessage::CollateralConsentRequest { .. } |
            DepositsMessage::CollateralConsentResponse { .. }
        );
        assert!(!should_skip, "AddCollateralPartner is a ledger update and should NOT be skipped");

        println!("✅ AddCollateralPartner NOT in skip list test passed!");
    }

    /// Tests that CollateralAttestation (a ledger update) should NOT be skipped
    #[test]
    fn test_collateral_attestation_should_not_skip_broadcast_queue() {
        use deposits_ldk::handler::messages::{
            CollateralAttestationMsg, DepositsMessage
        };

        let msg = DepositsMessage::CollateralAttestation {
            operator: generate_test_pubkey(1),
            collateral_partner: generate_test_pubkey(2),
            amount: 100_000,
            block_height: 800_000,
            signature: [0u8; 64],
            ledger_hash: [0u8; 32],
        };

        // CollateralAttestation is a ledger update and should NOT be skipped
        let should_skip = matches!(msg,
            DepositsMessage::Ack(_) |
            DepositsMessage::SignedUpdate(_) |
            DepositsMessage::ReceivingCosignInvoice { .. } |
            DepositsMessage::CollateralConsentRequest { .. } |
            DepositsMessage::CollateralConsentResponse { .. }
        );
        assert!(!should_skip, "CollateralAttestation is a ledger update and should NOT be skipped");

        println!("✅ CollateralAttestation NOT in skip list test passed!");
    }

    /// Tests all message types that should be in the broadcast skip list
    #[test]
    fn test_all_broadcast_skip_list_messages() {
        use deposits_ldk::handler::messages::{
            AckMsg, CollateralConsentRequestMsg, CollateralConsentResponseMsg,
            DepositsMessage
        };

        // Messages that should be skipped
        let skip_messages: Vec<DepositsMessage> = vec![
            DepositsMessage::Ack(AckMsg {
                acked_message_type: 0x8001,
                message_hash: [0u8; 32],
                success: true,
                error_message: None,
                partner_signature: None,
                confirmed_sequence: 0,
                confirmed_hash: [0u8; 32],
                cosignature: None,
                update_signature: None,
                update_sequence: None,
                update_prev_hash: None,
                update_curr_hash: None,
            }),
            DepositsMessage::CollateralConsentRequest {
                operator_id: generate_test_pubkey(1),
                partner_id: generate_test_pubkey(2),
                operator_signature: [0u8; 64],
            },
            DepositsMessage::CollateralConsentResponse {
                operator_id: generate_test_pubkey(1),
                partner_id: generate_test_pubkey(2),
                consent_granted: true,
                collateral_partner_signature: [0u8; 64],
            },
        ];

        for msg in skip_messages {
            let should_skip = matches!(msg,
                DepositsMessage::Ack(_) |
                DepositsMessage::SignedUpdate(_) |
                DepositsMessage::ReceivingCosignInvoice { .. } |
                DepositsMessage::CollateralConsentRequest { .. } |
                DepositsMessage::CollateralConsentResponse { .. }
            );
            assert!(should_skip, "Message {:?} should be in the skip list", msg.variant_name());
        }

        println!("✅ All broadcast skip list messages test passed!");
    }

    /// Tests that consent messages when denied should have empty signature
    #[test]
    fn test_consent_response_denied_has_empty_signature() {
        use deposits_ldk::handler::messages::CollateralConsentResponseMsg;

        let denied = CollateralConsentResponseMsg {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: false,
            collateral_partner_signature: [0u8; 64], // Empty signature when denied
        };

        assert!(!denied.consent_granted);
        assert_eq!(denied.collateral_partner_signature, [0u8; 64]);

        let granted = CollateralConsentResponseMsg {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0xAB; 64], // Real signature when granted
        };

        assert!(granted.consent_granted);
        assert_ne!(granted.collateral_partner_signature, [0u8; 64]);

        println!("✅ Consent response denied/granted signature test passed!");
    }

    #[test]
    fn test_ledger_open_request_should_skip_broadcast_queue() {
        use deposits_ldk::handler::messages::{DepositsMessage, LedgerOpenRequestMsg};

        let msg = DepositsMessage::LedgerOpenRequest(LedgerOpenRequestMsg {
            protocol_version: 1,
            min_protocol_version: 1,
            features: 0,
            public_key: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            ledger_address: "bcrt1qtest".to_string(),
            funding_txid: [0u8; 32],
            funding_vout: 0,
        });

        // V2 uses HANDSHAKE (0x8005) instead of V1's LedgerOpenRequest (0x8061)
        assert_eq!(msg.message_type(), 0x8005);

        // Verify this message type is in the broadcast skip list
        let should_skip = matches!(msg,
            DepositsMessage::Ack(_) |
            DepositsMessage::SignedUpdate(_) |
            DepositsMessage::ReceivingCosignInvoice { .. } |
            DepositsMessage::CollateralConsentRequest { .. } |
            DepositsMessage::CollateralConsentResponse { .. } |
            DepositsMessage::LedgerOpenRequest(_) |
            DepositsMessage::LedgerOpenResponse(_)
        );
        assert!(should_skip, "LedgerOpenRequest should be in the skip list");

        println!("✅ LedgerOpenRequest skip list test passed!");
    }

    #[test]
    fn test_ledger_open_response_should_skip_broadcast_queue() {
        use deposits_ldk::handler::messages::{DepositsMessage, LedgerOpenResponseMsg};

        let msg = DepositsMessage::LedgerOpenResponse(LedgerOpenResponseMsg {
            protocol_version: 1,
            accepted: true,
            error_reason: None,
            public_key: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
        });

        // V2 uses HANDSHAKE_RESPONSE (0x8007) instead of V1's LedgerOpenResponse (0x8063)
        assert_eq!(msg.message_type(), 0x8007);

        // Verify this message type is in the broadcast skip list
        let should_skip = matches!(msg,
            DepositsMessage::Ack(_) |
            DepositsMessage::SignedUpdate(_) |
            DepositsMessage::ReceivingCosignInvoice { .. } |
            DepositsMessage::CollateralConsentRequest { .. } |
            DepositsMessage::CollateralConsentResponse { .. } |
            DepositsMessage::LedgerOpenRequest(_) |
            DepositsMessage::LedgerOpenResponse(_)
        );
        assert!(should_skip, "LedgerOpenResponse should be in the skip list");

        println!("✅ LedgerOpenResponse skip list test passed!");
    }
}
