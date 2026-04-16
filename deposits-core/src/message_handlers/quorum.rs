use super::*;

// ============================================================================
// Quorum Message Handlers
// ============================================================================

/// Handle a QuorumJoinRequest message.
///
/// Core logic for processing join requests, independent of Lightning implementation.
/// Returns a HandlerResult indicating whether the request should be accepted.
pub fn handle_quorum_join_request<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumJoinRequestMsgWire,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::{CoordinationResponseMsg, DepositsMessage};
    use crate::types::QuorumJoinRequestMsg as CoreQuorumMsg;

    // Validate: sender should match the requester
    if sender != msg.requester_pubkey {
        return Ok(HandlerResult::Rejected(
            "Sender doesn't match requester".to_string(),
        ));
    }

    // Get quorum manager
    let quorum_manager = ctx.quorum_manager().ok_or(HandlerError::InvalidState(
        "No quorum manager available".to_string(),
    ))?;

    // Convert to core type and delegate to QuorumManager
    let core_msg = CoreQuorumMsg {
        requester_pubkey: msg.requester_pubkey,
        operator_id: msg.operator_id,
        reserves_id: msg.reserves_id.clone(),
        protocol_version: msg.protocol_version,
        timestamp: msg.timestamp,
        signature: msg.signature,
    };

    match quorum_manager.handle_join_request(&core_msg) {
        Ok(response) => {
            // Queue response message
            let response_msg = DepositsMessage::CoordinationResponse(
                CoordinationResponseMsg::QuorumJoinResponse {
                    request_hash: [0u8; 32], // Wire layer will fill this
                    accepted: response.accepted,
                    members: response.members.clone(),
                    threshold: response.threshold,
                    last_sequence: response.last_sequence,
                    current_hash: response.current_hash,
                    rejection_reason: response.rejection_reason.clone(),
                },
            );
            ctx.queue_message(sender, response_msg)?;

            // Emit event and send state sync if accepted
            if response.accepted {
                ctx.emit_event(ProtocolEvent::QuorumMemberJoined {
                    operator: msg.operator_id,
                    reserves_id: msg.reserves_id.clone(),
                    member: msg.requester_pubkey,
                });
                // Send state sync to new member via provider
                ctx.send_quorum_state_sync(msg.requester_pubkey, msg.operator_id, &msg.reserves_id);
            }

            Ok(HandlerResult::Ok)
        }
        Err(e) => Ok(HandlerResult::Rejected(format!(
            "Quorum join failed: {:?}",
            e
        ))),
    }
}

/// Handle a QuorumVoteRequest message.
///
/// This is sent by quorum initiators to request votes for a reserves spend.
/// Voters must validate conformance before signing.
pub fn handle_quorum_vote_request<C: HandlerContext>(
    ctx: &C,
    msg: &QuorumVoteRequestMsg,
    sender: PublicKey,
) -> Result<HandlerResult, HandlerError> {
    let our_node_id = ctx.our_node_id();

    // Get local state from signed update log (more accurate than ledger state)
    let (our_sequence, our_state_hash) =
        match ctx.get_signed_update_log_state(&msg.operator_id, &msg.reserves_id) {
            Some(state) => state,
            None => {
                // No local state, abstain from voting
                return Ok(HandlerResult::Ok);
            }
        };

    // Initialize vote round for tracking
    ctx.init_vote_round(
        msg.vote_round_id,
        msg.operator_id,
        &msg.reserves_id,
        msg.sequence_number,
        msg.state_hash,
        msg.claimed_reserves,
        msg.reserves_outpoint.clone(),
        msg.destination_script.clone(),
        msg.fee_rate_sat_vbyte,
        2, // Default threshold
    );

    // Validate and create vote
    let is_conforming = true; // TODO: implement full conformance validation
    let vote = is_conforming && our_state_hash == msg.state_hash;
    let evidence = if !vote {
        Some(b"state_mismatch".to_vec())
    } else {
        None
    };

    // Sign the vote
    let signature =
        match ctx.sign_quorum_vote(&msg.vote_round_id, vote, our_sequence, &our_state_hash) {
            Some(sig) => sig,
            None => {
                // Cannot sign - no secret key available
                return Ok(HandlerResult::Ok);
            }
        };

    // Build and queue vote message
    let vote_msg = DepositsMessage::Coordination(CoordinationMsg::QuorumVote {
        vote_round_id: msg.vote_round_id,
        voter_pubkey: our_node_id,
        vote,
        voter_sequence: our_sequence,
        voter_state_hash: our_state_hash,
        evidence,
        signature,
        spend_signature: None, // TODO: implement spend signing
    });

    let _ = ctx.queue_message(sender, vote_msg);

    Ok(HandlerResult::Ok)
}

/// Handle a QuorumVote message.
///
/// This is a vote received from a quorum member in response to a vote request.
/// The vote is added to the pending round and if threshold is reached,
/// the ReservesSpendReady event is emitted.
pub fn handle_quorum_vote<C: HandlerContext>(
    ctx: &C,
    vote_round_id: [u8; 32],
    voter: PublicKey,
    vote: bool,
    spend_signature: Option<[u8; 64]>,
) -> Result<HandlerResult, HandlerError> {
    // Add vote via provider and check if threshold reached
    if let Some((operator, reserves_id, spend_data, conforming_votes, threshold)) =
        ctx.add_quorum_vote(vote_round_id, voter, vote, spend_signature)
    {
        // Emit spend ready event
        ctx.emit_event(ProtocolEvent::ReservesSpendReady {
            vote_round_id,
            operator,
            reserves_id,
            signed_tx_bytes: spend_data,
            conforming_votes,
            threshold,
        });
    }

    Ok(HandlerResult::Ok)
}

/// Handle a QuorumStateSync message.
///
/// Process signed updates received during quorum state synchronization.
/// After the final batch, updates our member state in the quorum manager.
pub fn handle_quorum_state_sync<C: HandlerContext>(
    ctx: &C,
    operator: PublicKey,
    reserves_id: &str,
    updates: &[Vec<u8>],
    _start_sequence: u64,
    is_final: bool,
) -> Result<HandlerResult, HandlerError> {
    use crate::messages::BinaryCodec;
    use crate::types::SignedLedgerUpdate;

    let mut applied_count = 0;
    let mut error_count = 0;

    // Process each update in the batch
    for update_bytes in updates {
        let mut cursor = std::io::Cursor::new(update_bytes);
        match SignedLedgerUpdate::read_from(&mut cursor) {
            Ok(signed_update) => match ctx.verify_and_store_signed_update(signed_update) {
                Ok(()) => applied_count += 1,
                Err(_) => error_count += 1,
            },
            Err(_) => error_count += 1,
        }
    }

    // Update quorum member state after final batch
    if is_final {
        if let Some((sequence, state_hash)) =
            ctx.get_signed_update_log_state(&operator, reserves_id)
        {
            let _ = ctx.update_quorum_member_state(operator, reserves_id, sequence, state_hash);
        }
    }

    Ok(HandlerResult::Response(
        ResponseData::QuorumStateSyncProcessed {
            applied: applied_count,
            errors: error_count,
            total: updates.len() as u32,
        },
    ))
}
