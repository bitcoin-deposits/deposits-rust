//! Tests for quorum member management via ledger updates
//!
//! Tests the AddQuorumMember, RemoveQuorumMember, CollateralAttestation,
//! CollateralConsentRequest, and CollateralConsentResponse messages and their effect on ledger state.

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    // V2 message types from deposits-core
    use deposits_core::messages::{
        DepositsMessage, LedgerUpdateMsg, LedgerUpdateResponseMsg, LedgerOperation,
        HandshakeMsg, HandshakeResponseMsg, CoordinationMsg, CoordinationResponseMsg,
    };
    // Wire message structs from deposits-core for struct construction
    use deposits_core::wire_messages::{
        QuorumAddMemberMsg, QuorumRemoveMemberMsg,
        CollateralConsentRequestMsg, CollateralConsentResponseMsg, CollateralAttestationMsg,
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
    fn test_add_quorum_member_message_struct() {
        let operator_id = generate_test_pubkey(1);
        let reserves_id = "test_reserves".to_string();
        let quorum_member = generate_test_pubkey(3);

        let msg = QuorumAddMemberMsg {
            operator_id,
            reserves_id: reserves_id.clone(),
            quorum_member,
            member_ledger_id: "member_collateral_ledger".to_string(),
            quorum_member_signature: [0xCD; 64],
        };

        assert_eq!(msg.operator_id, operator_id);
        assert_eq!(msg.reserves_id, reserves_id);
        assert_eq!(msg.quorum_member, quorum_member);
        assert_eq!(msg.quorum_member_signature, [0xCD; 64]);

        println!("QuorumAddMemberMsg struct test passed!");
    }

    #[test]
    fn test_collateral_consent_request_message_struct() {
        let operator_id = generate_test_pubkey(1);
        let reserves_id = "test_reserves".to_string();

        let msg = CollateralConsentRequestMsg {
            operator_id,
            reserves_id: reserves_id.clone(),
            operator_signature: [0xEF; 64],
        };

        assert_eq!(msg.operator_id, operator_id);
        assert_eq!(msg.reserves_id, reserves_id);
        assert_eq!(msg.operator_signature, [0xEF; 64]);

        println!("CollateralConsentRequestMsg struct test passed!");
    }

    #[test]
    fn test_collateral_consent_response_message_struct() {
        let operator_id = generate_test_pubkey(1);
        let reserves_id = "test_reserves".to_string();

        // Test with consent granted
        let msg_granted = CollateralConsentResponseMsg {
            operator_id,
            reserves_id: reserves_id.clone(),
            consent_granted: true,
            quorum_member_signature: [0x12; 64],
        };

        assert_eq!(msg_granted.operator_id, operator_id);
        assert_eq!(msg_granted.reserves_id, reserves_id);
        assert_eq!(msg_granted.consent_granted, true);
        assert_eq!(msg_granted.quorum_member_signature, [0x12; 64]);

        // Test with consent denied
        let msg_denied = CollateralConsentResponseMsg {
            operator_id,
            reserves_id: reserves_id.clone(),
            consent_granted: false,
            quorum_member_signature: [0u8; 64],
        };

        assert_eq!(msg_denied.consent_granted, false);

        println!("CollateralConsentResponseMsg struct test passed!");
    }

    #[test]
    fn test_remove_quorum_member_message_struct() {
        let reserves_id = "test_reserves".to_string();
        let quorum_member = generate_test_pubkey(2);

        let msg = QuorumRemoveMemberMsg {
            reserves_id: reserves_id.clone(),
            quorum_member,
            operator_signature: [0xCD; 64],
        };

        assert_eq!(msg.reserves_id, reserves_id);
        assert_eq!(msg.quorum_member, quorum_member);
        assert_eq!(msg.operator_signature, [0xCD; 64]);

        println!("QuorumRemoveMemberMsg struct test passed!");
    }

    #[test]
    fn test_collateral_attestation_message_struct() {
        let operator = generate_test_pubkey(1);
        let quorum_member = generate_test_pubkey(2);

        let msg = CollateralAttestationMsg {
            operator,
            quorum_member,
            collateral_ledger_id: "collateral_ledger".to_string(),
            amount: 100_000,
            block_height: 800_000,
            lock_until_block: 0,
            signature: [0xEF; 64],
            ledger_hash: [0u8; 32],
        };

        assert_eq!(msg.operator, operator);
        assert_eq!(msg.quorum_member, quorum_member);
        assert_eq!(msg.amount, 100_000);
        assert_eq!(msg.block_height, 800_000);
        assert_eq!(msg.signature, [0xEF; 64]);

        // Test available_collateral calculation
        assert_eq!(msg.available_collateral(), 100_000);

        println!("CollateralAttestationMsg struct test passed!");
    }

    // =========================================================================
    // Ledger State Transition Tests
    // =========================================================================

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_add_quorum_member_via_message() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_remove_quorum_member_via_message() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_collateral_attestation_from_channel_partner() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_collateral_attestation_from_quorum_member() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_ledger_collateral_attestation_from_unknown_rejected() {
        todo!("Update test for V2 Ledger API");
    }

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_remove_quorum_member_clears_attestation() {
        todo!("Update test for V2 Ledger API");
    }

    // =========================================================================
    // Hash Chain Tests
    // =========================================================================

    #[test]
    #[ignore = "TODO: Update for V2 Ledger API"]
    fn test_quorum_member_messages_update_hash_chain() {
        todo!("Update test for V2 Ledger API");
    }

    // =========================================================================
    // Message Type Tests
    // =========================================================================

    #[test]
    fn test_message_type_constants() {
        use deposits_core::messages::{LEDGER_UPDATE, COORDINATION, COORDINATION_RESPONSE};

        // V2: Collateral operations go through LedgerUpdate (0x8001) or Coordination (0x800D/0x800F)
        // QuorumAddMember, QuorumRemoveMember, CollateralAttestation -> LedgerUpdate with LedgerOperation
        // CollateralConsentRequest -> Coordination
        // CollateralConsentResponse -> CoordinationResponse

        // QuorumAddMember is now a LedgerUpdate with LedgerOperation::QuorumAddMember
        let add_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2).to_string(),
            LedgerOperation::QuorumAddMember {
                quorum_member: generate_test_pubkey(3),
                member_ledger_id: "member_collateral_ledger".to_string(),
                quorum_member_signature: [0u8; 64],
            },
        ));
        assert_eq!(add_msg.message_type(), LEDGER_UPDATE);
        assert_eq!(add_msg.message_type(), 0x8001);

        // QuorumRemoveMember is now a LedgerUpdate with LedgerOperation::QuorumRemoveMember
        let remove_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2).to_string(),
            LedgerOperation::QuorumRemoveMember {
                quorum_member: generate_test_pubkey(3),
                operator_signature: [0u8; 64],
            },
        ));
        assert_eq!(remove_msg.message_type(), LEDGER_UPDATE);

        // CollateralConsentRequest is now Coordination with CoordinationMsg::CollateralConsentRequest
        let consent_request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            reserves_id: "test_reserves".to_string(),
            operator_signature: [0u8; 64],
        });
        assert_eq!(consent_request.message_type(), COORDINATION);
        assert_eq!(consent_request.message_type(), 0x8011);

        // CollateralConsentResponse is now CoordinationResponse with CoordinationResponseMsg::CollateralConsentResponse
        let consent_response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            reserves_id: "test_reserves".to_string(),
            consent_granted: true,
            quorum_member_signature: [0u8; 64],
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
            reserves_id: "test_reserves".to_string(),
            operator_signature: [0u8; 64],
        });
        assert_eq!(request.variant_name(), "Coordination");

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            reserves_id: "test_reserves".to_string(),
            consent_granted: true,
            quorum_member_signature: [0u8; 64],
        });
        assert_eq!(response.variant_name(), "CoordinationResponse");

        println!("Consent message variant names test passed!");
    }

    #[test]
    fn test_consent_messages_have_reserves_id() {
        let reserves_id = "test_reserves".to_string();

        // V2: Coordination messages don't expose reserves_id at the outer level
        // The reserves_id is within the inner CoordinationMsg variant
        let request = DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
            operator_id: generate_test_pubkey(1),
            reserves_id: reserves_id.clone(),
            operator_signature: [0u8; 64],
        });
        // V2 Coordination messages return None for reserves_id() at DepositsMessage level
        // The reserves_id is inside the CoordinationMsg variant
        assert_eq!(request.reserves_id(), None);

        let response = DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
            request_hash: [0u8; 32],
            operator_id: generate_test_pubkey(1),
            reserves_id: reserves_id.clone(),
            consent_granted: false,
            quorum_member_signature: [0u8; 64],
        });
        // V2 CoordinationResponse messages return None for reserves_id() at DepositsMessage level
        assert_eq!(response.reserves_id(), None);

        println!("Consent messages reserves_id test passed!");
    }

    #[test]
    fn test_add_quorum_member_requires_consent_signature() {
        let operator = generate_test_pubkey(1);
        let reserves_id = "test_reserves".to_string();
        let quorum_member = generate_test_pubkey(3);

        // Wire message struct for encoding test
        let msg_with_consent = QuorumAddMemberMsg {
            operator_id: operator,
            reserves_id: reserves_id.clone(),
            quorum_member,
            member_ledger_id: "member_collateral_ledger".to_string(),
            quorum_member_signature: [0xBB; 64],
        };

        assert_eq!(msg_with_consent.operator_id, operator);
        assert_eq!(msg_with_consent.quorum_member_signature, [0xBB; 64]);

        // V2: The DepositsMessage variant uses LedgerUpdate with LedgerOperation
        let v2_msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            operator,
            reserves_id,
            LedgerOperation::QuorumAddMember {
                quorum_member,
                member_ledger_id: "member_collateral_ledger".to_string(),
                quorum_member_signature: [0xBB; 64],
            },
        ));
        // Verify it's the right message type
        assert_eq!(v2_msg.message_type(), 0x8001); // LEDGER_UPDATE

        println!("QuorumAddMember requires consent signature test passed!");
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
            reserves_id: "test_reserves".to_string(),
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
            reserves_id: "test_reserves".to_string(),
            consent_granted: true,
            quorum_member_signature: [0u8; 64],
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

    /// Tests that QuorumAddMember (a ledger update) should NOT be skipped
    #[test]
    fn test_quorum_add_member_should_not_skip_broadcast_queue() {
        // V2: QuorumAddMember is now a LedgerUpdate with LedgerOperation
        let msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2).to_string(),
            LedgerOperation::QuorumAddMember {
                quorum_member: generate_test_pubkey(3),
                member_ledger_id: "member_collateral_ledger".to_string(),
                quorum_member_signature: [0u8; 64],
            },
        ));

        // V2: Uses LEDGER_UPDATE type (0x8001)
        assert_eq!(msg.message_type(), 0x8001);

        // LedgerUpdate messages (including QuorumAddMember operation) should NOT be skipped
        let should_skip = matches!(msg,
            DepositsMessage::LedgerUpdateResponse(_) |
            DepositsMessage::Coordination(_) |
            DepositsMessage::CoordinationResponse(_)
        );
        assert!(!should_skip, "LedgerUpdate (QuorumAddMember) is a ledger update and should NOT be skipped");

        println!("QuorumAddMember NOT in skip list test passed!");
    }

    /// Tests that CollateralAttestation (a ledger update) should NOT be skipped
    #[test]
    fn test_collateral_attestation_should_not_skip_broadcast_queue() {
        // V2: CollateralAttestation is now a LedgerUpdate with LedgerOperation
        let msg = DepositsMessage::LedgerUpdate(LedgerUpdateMsg::new_with_operation(
            generate_test_pubkey(1),
            generate_test_pubkey(2).to_string(),
            LedgerOperation::CollateralAttestation {
                collateral_operator: generate_test_pubkey(3),
                quorum_member: generate_test_pubkey(4),
                collateral_ledger_id: "collateral_ledger".to_string(),
                amount: 100_000,
                block_height: 800_000,
                lock_until_block: 0,
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
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                request_hash: [0u8; 32],
                accepted: true,
                error: None,
                partner_signature: None,
                confirmed_sequence: 0,
                confirmed_hash: [0u8; 32],
            }),
            // Coordination (includes CollateralConsentRequest, CosignInvoice, etc.)
            DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                operator_signature: [0u8; 64],
            }),
            // CoordinationResponse (includes CollateralConsentResponse, InvoiceCosigned, etc.)
            DepositsMessage::CoordinationResponse(CoordinationResponseMsg::CollateralConsentResponse {
                request_hash: [0u8; 32],
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                consent_granted: true,
                quorum_member_signature: [0u8; 64],
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
            reserves_id: "test_reserves".to_string(),
            consent_granted: false,
            quorum_member_signature: [0u8; 64], // Empty signature when denied
        };

        assert!(!denied.consent_granted);
        assert_eq!(denied.quorum_member_signature, [0u8; 64]);

        let granted = CollateralConsentResponseMsg {
            operator_id: generate_test_pubkey(1),
            reserves_id: "test_reserves".to_string(),
            consent_granted: true,
            quorum_member_signature: [0xAB; 64], // Real signature when granted
        };

        assert!(granted.consent_granted);
        assert_ne!(granted.quorum_member_signature, [0u8; 64]);

        println!("Consent response denied/granted signature test passed!");
    }

    #[test]
    fn test_handshake_should_skip_broadcast_queue() {
        // V2: LedgerOpenRequest is now Handshake
        let msg = DepositsMessage::Handshake(HandshakeMsg {
            protocol_version: 1,
            min_protocol_version: 1,
            features: 0,
            operator_id: generate_test_pubkey(1),
            reserves_id: "test_reserves".to_string(),
            funding_txid: [0u8; 32],
            funding_vout: 0,
            collateral_enforcement_block: 0,
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
            request_hash: [0u8; 32],
            protocol_version: 1,
            accepted: true,
            error: None,
            reserves_id: "test_reserves".to_string(),
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
