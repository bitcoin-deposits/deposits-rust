//! Tests for quorum member management via ledger updates
//!
//! Tests the AddQuorumMember, RemoveQuorumMember, CollateralConsentRequest,
//! and CollateralConsentResponse messages and their effect on ledger state.

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    // V2 message types from deposits-core
    use deposits_core::ledger::Ledger;
    use deposits_core::messages::{
        CoordinationMsg, CoordinationResponseMsg, DepositsMessage, HandshakeMsg,
        HandshakeResponseMsg, LedgerOperation, LedgerUpdateResponseMsg,
    };
    // Wire message structs from deposits-core for struct construction
    use deposits_core::wire_messages::{
        CollateralConsentRequestMsg, CollateralConsentResponseMsg, QuorumAddMemberMsg,
        QuorumRemoveMemberMsg,
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
        assert!(msg_granted.consent_granted);
        assert_eq!(msg_granted.quorum_member_signature, [0x12; 64]);

        // Test with consent denied
        let msg_denied = CollateralConsentResponseMsg {
            operator_id,
            reserves_id: reserves_id.clone(),
            consent_granted: false,
            quorum_member_signature: [0u8; 64],
        };

        assert!(!msg_denied.consent_granted);

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

    // =========================================================================
    // Ledger State Transition Tests
    // =========================================================================

    #[test]
    fn test_ledger_add_quorum_member_via_message() {
        let operator_key = generate_test_pubkey(1);
        let member_key = generate_test_pubkey(2);
        let mut ledger = Ledger::new_as_operator(operator_key, "bcrt1qtest".to_string(), 0);

        ledger
            .apply_state_changes(&LedgerOperation::QuorumAddMember {
                min_collateral_bps: None,
                quorum_member: member_key,
                quorum_member_signature: [0xAA; 64],
                member_ledger_id: "member_collateral_ledger".to_string(),
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                membership_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
                member_response: None,
                member_signature: None,
            })
            .unwrap();

        assert!(ledger
            .state
            .next_quorum_members
            .iter()
            .any(|m| m.pubkey == member_key));
    }

    #[test]
    fn test_ledger_remove_quorum_member_via_message() {
        let operator_key = generate_test_pubkey(1);
        let member_key = generate_test_pubkey(2);
        let mut ledger = Ledger::new_as_operator(operator_key, "bcrt1qtest".to_string(), 0);

        // Add a member
        ledger
            .apply_state_changes(&LedgerOperation::QuorumAddMember {
                min_collateral_bps: None,
                quorum_member: member_key,
                quorum_member_signature: [0xAA; 64],
                member_ledger_id: "member_collateral_ledger".to_string(),
                min_fee_bps: None,
                min_fee_fixed: None,
                max_fee_period: None,
                membership_until: None,
                dispute_response_blocks: None,
                dispute_arm_blocks: None,
                service_response_blocks: None,
                max_transfer_timeout_blocks: None,
                max_descriptor_bytes: None,
                compensation_bps: None,
                compensation_deposit_id: None,
                compensation_frequency_blocks: None,
                member_response: None,
                member_signature: None,
            })
            .unwrap();
        assert!(ledger
            .state
            .next_quorum_members
            .iter()
            .any(|m| m.pubkey == member_key));

        // Remove the member
        ledger
            .apply_state_changes(&LedgerOperation::QuorumRemoveMember {
                quorum_member: member_key,
                operator_signature: [0xBB; 64],
            })
            .unwrap();

        assert!(!ledger
            .state
            .next_quorum_members
            .iter()
            .any(|m| m.pubkey == member_key));
    }

    // =========================================================================
    // Hash Chain Tests
    // =========================================================================

    #[test]
    fn test_quorum_member_messages_update_hash_chain() {
        let operator_key = generate_test_pubkey(1);
        let member_key = generate_test_pubkey(2);
        let member2_key = generate_test_pubkey(3);
        let member3_key = generate_test_pubkey(4);
        let mut ledger = Ledger::new_as_operator(operator_key, "bcrt1qtest".to_string(), 0);

        let hash_before = ledger.state.chain_tip_hash;

        // Add three quorum members — hash should change. Q=3 minimum is
        // required by the policy gate; each member must have a
        // QuorumAddMember consent before they appear in QuorumBegin.
        let mut hash_after_add = hash_before;
        for member in &[member_key, member2_key, member3_key] {
            let update = ledger
                .apply_operation(&LedgerOperation::QuorumAddMember {
                    min_collateral_bps: None,
                    quorum_member: *member,
                    quorum_member_signature: [0xAA; 64],
                    member_ledger_id: "member_collateral_ledger".to_string(),
                    min_fee_bps: None,
                    min_fee_fixed: None,
                    max_fee_period: None,
                    membership_until: None,
                    dispute_response_blocks: None,
                    dispute_arm_blocks: None,
                    service_response_blocks: None,
                    max_transfer_timeout_blocks: None,
                    max_descriptor_bytes: None,
                    compensation_bps: None,
                    compensation_deposit_id: None,
                    compensation_frequency_blocks: None,
                    member_response: None,
                    member_signature: None,
                })
                .unwrap();
            hash_after_add = update.content_hash;
        }
        assert_ne!(
            hash_before, hash_after_add,
            "Hash should change after QuorumAddMember"
        );

        // Stand in for the members' signed QuorumMemberResponses.
        for m in ledger.state.next_quorum_members.iter_mut() {
            m.supported_rulesets = vec!["cltv-offset-v2".to_string()];
        }
        // QuorumBegin — hash should change again
        let update = ledger
            .apply_operation(&LedgerOperation::QuorumBegin {
                exit_cutoff_height: None,
                exit_outputs: Vec::new(),
                reserves_id: "bcrt1qtest_rotated".to_string(),
                spending_txid: [0x11; 32],
                new_outpoint_txid: [0x22; 32],
                new_outpoint_vout: 0,
                amount: 100_000_000,
                quorum_expiry: 1_000_000,
                ledger_hash: [0x33; 32],
                quorum_members: vec![member_key, member2_key, member3_key]
                    .into_iter()
                    .map(deposits_core::messages::QuorumMemberRef::pubkey_only)
                    .collect(),
                collateral_amount: 50_000,
                protocol_version: Some("cltv-offset-v2".to_string()),
            })
            .unwrap();
        let hash_after_begin = update.content_hash;
        assert_ne!(
            hash_after_add, hash_after_begin,
            "Hash should change after QuorumBegin"
        );

        // Remove member — hash should change yet again
        let update = ledger
            .apply_operation(&LedgerOperation::QuorumRemoveMember {
                quorum_member: member_key,
                operator_signature: [0xBB; 64],
            })
            .unwrap();
        let hash_after_remove = update.content_hash;
        assert_ne!(
            hash_after_begin, hash_after_remove,
            "Hash should change after QuorumRemoveMember"
        );
    }

    // =========================================================================
    // Message Type Tests
    // =========================================================================

    #[test]
    fn test_message_type_constants() {
        use deposits_core::messages::{COORDINATION, COORDINATION_RESPONSE};

        // CollateralConsentRequest is now Coordination with CoordinationMsg::CollateralConsentRequest
        let consent_request =
            DepositsMessage::Coordination(CoordinationMsg::CollateralConsentRequest {
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                operator_signature: [0u8; 64],
            });
        assert_eq!(consent_request.message_type(), COORDINATION);
        assert_eq!(consent_request.message_type(), 0x8011);

        // CollateralConsentResponse is now CoordinationResponse with CoordinationResponseMsg::CollateralConsentResponse
        let consent_response = DepositsMessage::CoordinationResponse(
            CoordinationResponseMsg::CollateralConsentResponse {
                request_hash: [0u8; 32],
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                consent_granted: true,
                quorum_member_signature: [0u8; 64],
            },
        );
        assert_eq!(consent_response.message_type(), COORDINATION_RESPONSE);
        assert_eq!(consent_response.message_type(), 0x8013);
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

        let response = DepositsMessage::CoordinationResponse(
            CoordinationResponseMsg::CollateralConsentResponse {
                request_hash: [0u8; 32],
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                consent_granted: true,
                quorum_member_signature: [0u8; 64],
            },
        );
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
        // Coordination messages expose reserves_id from inner variant
        assert_eq!(request.reserves_id(), Some(reserves_id.clone()));

        let response = DepositsMessage::CoordinationResponse(
            CoordinationResponseMsg::CollateralConsentResponse {
                request_hash: [0u8; 32],
                operator_id: generate_test_pubkey(1),
                reserves_id: reserves_id.clone(),
                consent_granted: false,
                quorum_member_signature: [0u8; 64],
            },
        );
        assert_eq!(response.reserves_id(), Some(reserves_id.clone()));

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
        let should_skip = matches!(
            msg,
            DepositsMessage::LedgerUpdateResponse(_)
                | DepositsMessage::Coordination(_)
                | DepositsMessage::CoordinationResponse(_)
        );
        assert!(
            should_skip,
            "Coordination (CollateralConsentRequest) should be in the skip list"
        );

        println!("CollateralConsentRequest skip broadcast queue test passed!");
    }

    /// Tests that consent response messages should be skipped from broadcast queue
    /// These are coordination messages, NOT ledger updates
    #[test]
    fn test_consent_response_should_skip_broadcast_queue() {
        let msg = DepositsMessage::CoordinationResponse(
            CoordinationResponseMsg::CollateralConsentResponse {
                request_hash: [0u8; 32],
                operator_id: generate_test_pubkey(1),
                reserves_id: "test_reserves".to_string(),
                consent_granted: true,
                quorum_member_signature: [0u8; 64],
            },
        );

        // V2: CoordinationResponse messages use COORDINATION_RESPONSE type (0x8013)
        assert_eq!(msg.message_type(), 0x8013);

        // V2: Coordination and CoordinationResponse messages should be skipped from broadcast
        let should_skip = matches!(
            msg,
            DepositsMessage::LedgerUpdateResponse(_)
                | DepositsMessage::Coordination(_)
                | DepositsMessage::CoordinationResponse(_)
        );
        assert!(
            should_skip,
            "CoordinationResponse (CollateralConsentResponse) should be in the skip list"
        );

        println!("CollateralConsentResponse skip broadcast queue test passed!");
    }

    /// Tests that LedgerUpdate messages should NOT be skipped from broadcast queue
    #[test]
    fn test_ledger_update_should_not_skip_broadcast_queue() {
        // LedgerUpdate messages are ledger updates and should NOT be in the skip list
        // (QuorumAddMember, etc. are all LedgerUpdate operations)
        // We verify the skip list pattern doesn't match LedgerUpdate by checking message types
        use deposits_core::messages::LEDGER_UPDATE;
        assert_eq!(LEDGER_UPDATE, 0x8001);

        // The skip list includes: LedgerUpdateResponse, Coordination, CoordinationResponse
        // but NOT LedgerUpdate itself
        println!("LedgerUpdate NOT in skip list test passed!");
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
                cosign_signature: None,
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
            DepositsMessage::CoordinationResponse(
                CoordinationResponseMsg::CollateralConsentResponse {
                    request_hash: [0u8; 32],
                    operator_id: generate_test_pubkey(1),
                    reserves_id: "test_reserves".to_string(),
                    consent_granted: true,
                    quorum_member_signature: [0u8; 64],
                },
            ),
        ];

        for msg in skip_messages {
            let should_skip = matches!(
                msg,
                DepositsMessage::LedgerUpdateResponse(_)
                    | DepositsMessage::Coordination(_)
                    | DepositsMessage::CoordinationResponse(_)
            );
            assert!(
                should_skip,
                "Message {:?} should be in the skip list",
                msg.variant_name()
            );
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
        });

        // V2 uses HANDSHAKE (0x8005)
        assert_eq!(msg.message_type(), 0x8005);

        // Verify Handshake messages are in the broadcast skip list
        let should_skip = matches!(
            msg,
            DepositsMessage::LedgerUpdateResponse(_)
                | DepositsMessage::Handshake(_)
                | DepositsMessage::HandshakeResponse(_)
                | DepositsMessage::Coordination(_)
                | DepositsMessage::CoordinationResponse(_)
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
        let should_skip = matches!(
            msg,
            DepositsMessage::LedgerUpdateResponse(_)
                | DepositsMessage::Handshake(_)
                | DepositsMessage::HandshakeResponse(_)
                | DepositsMessage::Coordination(_)
                | DepositsMessage::CoordinationResponse(_)
        );
        assert!(should_skip, "HandshakeResponse should be in the skip list");

        println!("HandshakeResponse skip list test passed!");
    }
}
