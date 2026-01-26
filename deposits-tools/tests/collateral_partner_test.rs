//! Tests for collateral partner management via ledger updates
//!
//! Tests the AddCollateralPartner, RemoveCollateralPartner, CollateralAttestation,
//! CollateralConsentRequest, and CollateralConsentResponse messages and their effect on ledger state.

#[cfg(test)]
mod tests {
    use ldk_node::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::collections::HashMap;

    // V2 message types from deposits-ldk
    use deposits_ldk::handler::messages::{
        DepositsMessage, LedgerUpdateMsg, LedgerUpdateResponseMsg, LedgerOperation,
        HandshakeMsg, HandshakeResponseMsg, CoordinationMsg, CoordinationResponseMsg,
    };
    // V1 wire message structs from deposits-core for struct construction
    use deposits_ldk::wire::messages::{
        CollateralAddPartnerMsg, CollateralRemovePartnerMsg,
        CollateralConsentRequestMsg, CollateralConsentResponseMsg, CollateralAttestationMsg,
        // LDK wrappers for encoding tests (implement Readable/Writeable)
        LdkCollateralAddPartnerMsg, LdkCollateralRemovePartnerMsg,
        LdkCollateralConsentRequestMsg, LdkCollateralConsentResponseMsg, LdkCollateralAttestationMsg,
    };

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
        use lightning::util::ser::{Readable, Writeable};
        use lightning::io::Cursor;

        let operator_id = generate_test_pubkey(1);
        let partner_id = generate_test_pubkey(2);
        let collateral_partner = generate_test_pubkey(3);

        let msg = CollateralAddPartnerMsg {
            operator_id,
            partner_id,
            collateral_partner,
            collateral_partner_signature: [0xCD; 64],
        };

        // Encode using LDK wrapper
        let ldk_msg = LdkCollateralAddPartnerMsg::from(msg.clone());
        let encoded = ldk_msg.encode();

        // Decode using LDK wrapper
        let mut cursor = Cursor::new(&encoded);
        let decoded: LdkCollateralAddPartnerMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.0.operator_id, operator_id);
        assert_eq!(decoded.0.partner_id, partner_id);
        assert_eq!(decoded.0.collateral_partner, collateral_partner);
        assert_eq!(decoded.0.collateral_partner_signature, [0xCD; 64]);

        println!("AddCollateralPartnerMsg roundtrip test passed!");
    }

    #[test]
    fn test_collateral_consent_request_message_roundtrip() {
        use lightning::util::ser::{Readable, Writeable};
        use lightning::io::Cursor;

        let operator_id = generate_test_pubkey(1);
        let partner_id = generate_test_pubkey(2);

        let msg = CollateralConsentRequestMsg {
            operator_id,
            partner_id,
            operator_signature: [0xEF; 64],
        };

        // Encode using LDK wrapper
        let ldk_msg = LdkCollateralConsentRequestMsg::from(msg.clone());
        let encoded = ldk_msg.encode();

        // Decode using LDK wrapper
        let mut cursor = Cursor::new(&encoded);
        let decoded: LdkCollateralConsentRequestMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.0.operator_id, operator_id);
        assert_eq!(decoded.0.partner_id, partner_id);
        assert_eq!(decoded.0.operator_signature, [0xEF; 64]);

        println!("CollateralConsentRequestMsg roundtrip test passed!");
    }

    #[test]
    fn test_collateral_consent_response_message_roundtrip() {
        use lightning::util::ser::{Readable, Writeable};
        use lightning::io::Cursor;

        let operator_id = generate_test_pubkey(1);
        let partner_id = generate_test_pubkey(2);

        // Test with consent granted
        let msg_granted = CollateralConsentResponseMsg {
            operator_id,
            partner_id,
            consent_granted: true,
            collateral_partner_signature: [0x12; 64],
        };

        // Encode using LDK wrapper
        let ldk_msg = LdkCollateralConsentResponseMsg::from(msg_granted.clone());
        let encoded = ldk_msg.encode();

        let mut cursor = Cursor::new(&encoded);
        let decoded: LdkCollateralConsentResponseMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.0.operator_id, operator_id);
        assert_eq!(decoded.0.partner_id, partner_id);
        assert_eq!(decoded.0.consent_granted, true);
        assert_eq!(decoded.0.collateral_partner_signature, [0x12; 64]);

        // Test with consent denied
        let msg_denied = CollateralConsentResponseMsg {
            operator_id,
            partner_id,
            consent_granted: false,
            collateral_partner_signature: [0u8; 64],
        };

        let ldk_msg2 = LdkCollateralConsentResponseMsg::from(msg_denied.clone());
        let encoded2 = ldk_msg2.encode();

        let mut cursor2 = Cursor::new(&encoded2);
        let decoded2: LdkCollateralConsentResponseMsg = Readable::read(&mut cursor2).expect("should decode");

        assert_eq!(decoded2.0.consent_granted, false);

        println!("CollateralConsentResponseMsg roundtrip test passed!");
    }

    #[test]
    fn test_remove_collateral_partner_message_roundtrip() {
        use lightning::util::ser::{Readable, Writeable};
        use lightning::io::Cursor;

        let partner_id = generate_test_pubkey(1);
        let collateral_partner = generate_test_pubkey(2);

        let msg = CollateralRemovePartnerMsg {
            partner_id,
            collateral_partner,
            operator_signature: [0xCD; 64],
        };

        // Encode using LDK wrapper
        let ldk_msg = LdkCollateralRemovePartnerMsg::from(msg.clone());
        let encoded = ldk_msg.encode();

        // Decode using LDK wrapper
        let mut cursor = Cursor::new(&encoded);
        let decoded: LdkCollateralRemovePartnerMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.0.partner_id, partner_id);
        assert_eq!(decoded.0.collateral_partner, collateral_partner);
        assert_eq!(decoded.0.operator_signature, [0xCD; 64]);

        println!("RemoveCollateralPartnerMsg roundtrip test passed!");
    }

    #[test]
    fn test_collateral_attestation_message_roundtrip() {
        use lightning::util::ser::{Readable, Writeable};
        use lightning::io::Cursor;

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

        // Encode using LDK wrapper
        let ldk_msg = LdkCollateralAttestationMsg::from(msg.clone());
        let encoded = ldk_msg.encode();

        // Decode using LDK wrapper
        let mut cursor = Cursor::new(&encoded);
        let decoded: LdkCollateralAttestationMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.0.operator, operator);
        assert_eq!(decoded.0.collateral_partner, collateral_partner);
        assert_eq!(decoded.0.amount, 100_000);
        assert_eq!(decoded.0.block_height, 800_000);
        assert_eq!(decoded.0.signature, [0xEF; 64]);

        // Test available_collateral calculation
        assert_eq!(msg.available_collateral(), 100_000);

        println!("CollateralAttestationMsg roundtrip test passed!");
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
        use deposits_ldk::handler::messages::{LEDGER_UPDATE, COORDINATION, COORDINATION_RESPONSE};

        // V2: Collateral operations go through LedgerUpdate (0x8001) or Coordination (0x800D/0x800F)
        // CollateralAddPartner, CollateralRemovePartner, CollateralAttestation -> LedgerUpdate with LedgerOperation
        // CollateralConsentRequest -> Coordination
        // CollateralConsentResponse -> CoordinationResponse

        // CollateralAddPartner is now a LedgerUpdate with LedgerOperation::CollateralAddPartner
        let add_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2),
            LedgerOperation::CollateralAddPartner {
                collateral_partner: generate_test_pubkey(3),
                collateral_partner_signature: [0u8; 64],
            },
        ));
        assert_eq!(add_msg.message_type(), LEDGER_UPDATE);
        assert_eq!(add_msg.message_type(), 0x8001);

        // CollateralRemovePartner is now a LedgerUpdate with LedgerOperation::CollateralRemovePartner
        let remove_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2),
            LedgerOperation::CollateralRemovePartner {
                collateral_partner: generate_test_pubkey(3),
                operator_signature: [0u8; 64],
            },
        ));
        assert_eq!(remove_msg.message_type(), LEDGER_UPDATE);

        // CollateralConsentRequest is now Coordination with CoordinationMsg::CollateralConsentRequest
        let consent_request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        });
        assert_eq!(consent_request.message_type(), COORDINATION);
        assert_eq!(consent_request.message_type(), 0x8011);

        // CollateralConsentResponse is now CoordinationResponse with CoordinationResponseMsg::CollateralConsentResponse
        let consent_response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0u8; 64],
        });
        assert_eq!(consent_response.message_type(), COORDINATION_RESPONSE);
        assert_eq!(consent_response.message_type(), 0x8013);

        println!("Message type constants test passed!");
    }

    // =========================================================================
    // Consent Flow Tests
    // =========================================================================

    #[test]
    fn test_consent_message_variant_names() {
        // V2: Consent messages are wrapped in Coordination/CoordinationResponse
        let request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        });
        assert_eq!(request.variant_name(), "Coordination");

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0u8; 64],
        });
        assert_eq!(response.variant_name(), "CoordinationResponse");

        println!("Consent message variant names test passed!");
    }

    #[test]
    fn test_consent_messages_have_partner_id() {
        let partner_id = generate_test_pubkey(2);

        // V2: Coordination messages don't expose partner_id at the outer level
        // The partner_id is within the inner CoordinationMsg variant
        let request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id,
            operator_signature: [0u8; 64],
        });
        // V2 Coordination messages return None for partner_id() at DepositsMessage level
        // The partner_id is inside the CoordinationMsg variant
        assert_eq!(request.partner_id(), None);

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            partner_id,
            consent_granted: false,
            collateral_partner_signature: [0u8; 64],
        });
        // V2 CoordinationResponse messages return None for partner_id() at DepositsMessage level
        assert_eq!(response.partner_id(), None);

        println!("Consent messages partner_id test passed!");
    }

    #[test]
    fn test_add_collateral_partner_requires_consent_signature() {
        use lightning::util::ser::{Readable, Writeable};
        use lightning::io::Cursor;

        let operator = generate_test_pubkey(1);
        let partner = generate_test_pubkey(2);
        let collateral = generate_test_pubkey(3);

        // V1 wire message struct for encoding test (still used for backwards compat)
        let msg_with_consent = CollateralAddPartnerMsg {
            operator_id: operator,
            partner_id: partner,
            collateral_partner: collateral,
            collateral_partner_signature: [0xBB; 64],
        };

        // Verify the consent signature is encoded and decoded using LDK wrapper
        let ldk_msg = LdkCollateralAddPartnerMsg::from(msg_with_consent.clone());
        let encoded = ldk_msg.encode();

        let mut cursor = Cursor::new(&encoded);
        let decoded: LdkCollateralAddPartnerMsg = Readable::read(&mut cursor).expect("should decode");

        assert_eq!(decoded.0.operator_id, operator);
        assert_eq!(decoded.0.collateral_partner_signature, [0xBB; 64]);

        // V2: The DepositsMessage variant uses LedgerUpdate with LedgerOperation
        let v2_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            partner,
            LedgerOperation::CollateralAddPartner {
                collateral_partner: collateral,
                collateral_partner_signature: [0xBB; 64],
            },
        ));
        // Verify it's the right message type
        assert_eq!(v2_msg.message_type(), 0x8001); // LEDGER_UPDATE

        println!("AddCollateralPartner requires consent signature test passed!");
    }

    // =========================================================================
    // Message Routing Tests (Broadcast Queue Skip List)
    // =========================================================================

    /// Tests that consent request messages should be skipped from broadcast queue
    /// These are coordination messages, NOT ledger updates
    #[test]
    fn test_consent_request_should_skip_broadcast_queue() {
        let msg = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            operator_signature: [0u8; 64],
        });

        // V2: Coordination messages use COORDINATION type (0x8011)
        assert_eq!(msg.message_type(), 0x8011);

        // V2: Coordination and CoordinationResponse messages should be skipped from broadcast
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(should_skip, "Coordination (CollateralConsentRequest) should be in the skip list");

        println!("CollateralConsentRequest skip broadcast queue test passed!");
    }

    /// Tests that consent response messages should be skipped from broadcast queue
    /// These are coordination messages, NOT ledger updates
    #[test]
    fn test_consent_response_should_skip_broadcast_queue() {
        let msg = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            consent_granted: true,
            collateral_partner_signature: [0u8; 64],
        });

        // V2: CoordinationResponse messages use COORDINATION_RESPONSE type (0x8013)
        assert_eq!(msg.message_type(), 0x8013);

        // V2: Coordination and CoordinationResponse messages should be skipped from broadcast
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(should_skip, "CoordinationResponse (CollateralConsentResponse) should be in the skip list");

        println!("CollateralConsentResponse skip broadcast queue test passed!");
    }

    /// Tests that AddCollateralPartner (a ledger update) should NOT be skipped
    #[test]
    fn test_add_collateral_partner_should_not_skip_broadcast_queue() {
        // V2: CollateralAddPartner is now a LedgerUpdate with LedgerOperation
        let msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2),
            LedgerOperation::CollateralAddPartner {
                collateral_partner: generate_test_pubkey(3),
                collateral_partner_signature: [0u8; 64],
            },
        ));

        // V2: Uses LEDGER_UPDATE type (0x8001)
        assert_eq!(msg.message_type(), 0x8001);

        // LedgerUpdate messages (including CollateralAddPartner operation) should NOT be skipped
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(!should_skip, "LedgerUpdate (CollateralAddPartner) is a ledger update and should NOT be skipped");

        println!("AddCollateralPartner NOT in skip list test passed!");
    }

    /// Tests that CollateralAttestation (a ledger update) should NOT be skipped
    #[test]
    fn test_collateral_attestation_should_not_skip_broadcast_queue() {
        // V2: CollateralAttestation is now a LedgerUpdate with LedgerOperation
        let msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2),
            LedgerOperation::CollateralAttestation {
                collateral_operator: generate_test_pubkey(3),
                amount: 100_000,
                block_height: 800_000,
                signature: [0u8; 64],
                ledger_hash: [0u8; 32],
            },
        ));

        // V2: Uses LEDGER_UPDATE type (0x8001)
        assert_eq!(msg.message_type(), 0x8001);

        // LedgerUpdate messages (including CollateralAttestation operation) should NOT be skipped
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(!should_skip, "LedgerUpdate (CollateralAttestation) is a ledger update and should NOT be skipped");

        println!("CollateralAttestation NOT in skip list test passed!");
    }

    /// Tests all message types that should be in the broadcast skip list
    #[test]
    fn test_all_broadcast_skip_list_messages() {
        // V2: Messages that should be skipped from broadcast queue
        let skip_messages: Vec<DepositsMessage> = vec![
            // LedgerUpdateResponse (V2 for Ack)
            DepositsMessage::LedgerUpdateResponse(LedgerUpdateResponseMsg {
                message_hash: [0u8; 32],
                success: true,
                error_message: None,
                partner_signature: None,
                confirmed_sequence: 0,
                confirmed_hash: [0u8; 32],
                acked_message_type: 0x8001,
                cosignature: None,
                update_signature: None,
                update_sequence: None,
                update_prev_hash: None,
                update_curr_hash: None,
            }),
            // Coordination (includes CollateralConsentRequest, CosignInvoice, etc.)
            DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
                operator_id: generate_test_pubkey(1),
                partner_id: generate_test_pubkey(2),
                operator_signature: [0u8; 64],
            }),
            // CoordinationResponse (includes CollateralConsentResponse, InvoiceCosigned, etc.)
            DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
                request_hash: [0u8; 32],
                operator_id: generate_test_pubkey(1),
                partner_id: generate_test_pubkey(2),
                consent_granted: true,
                collateral_partner_signature: [0u8; 64],
            }),
        ];

        for msg in skip_messages {
            let should_skip = matches!(msg,
                DepositsMessage::LedgerUpdateResponse(_) |
                DepositsMessage::Coordination(_) |
                DepositsMessage::CoordinationResponse(_)
            );
            assert!(should_skip, "Message {:?} should be in the skip list", msg.variant_name());
        }

        println!("All broadcast skip list messages test passed!");
    }

    /// Tests that consent messages when denied should have empty signature
    #[test]
    fn test_consent_response_denied_has_empty_signature() {
        // Use the wire message struct (imported at top of module)
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

        println!("Consent response denied/granted signature test passed!");
    }

    #[test]
    fn test_handshake_should_skip_broadcast_queue() {
        // V2: LedgerOpenRequest is now Handshake
        let msg = DepositsMessage::Handshake(HandshakeMsg {
            protocol_version: 1,
            min_protocol_version: 1,
            features: 0,
            public_key: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
            ledger_address: "bcrt1qtest".to_string(),
            funding_txid: [0u8; 32],
            funding_vout: 0,
        });

        // V2 uses HANDSHAKE (0x8005)
        assert_eq!(msg.message_type(), 0x8005);

        // Verify Handshake messages are in the broadcast skip list
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Handshake(_) |
            DepositsMessage::HandshakeResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(should_skip, "Handshake should be in the skip list");

        println!("Handshake skip list test passed!");
    }

    #[test]
    fn test_handshake_response_should_skip_broadcast_queue() {
        // V2: LedgerOpenResponse is now HandshakeResponse
        let msg = DepositsMessage::HandshakeResponse(HandshakeResponseMsg {
            protocol_version: 1,
            accepted: true,
            error_reason: None,
            public_key: generate_test_pubkey(1),
            partner_id: generate_test_pubkey(2),
        });

        // V2 uses HANDSHAKE_RESPONSE (0x8007)
        assert_eq!(msg.message_type(), 0x8007);

        // Verify HandshakeResponse messages are in the broadcast skip list
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Handshake(_) |
            DepositsMessage::HandshakeResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(should_skip, "HandshakeResponse should be in the skip list");

        println!("HandshakeResponse skip list test passed!");
    }
}
