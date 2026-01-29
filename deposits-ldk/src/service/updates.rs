//! Ledger Updates API Handler
//!
//! Handler for retrieving ledger update history.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, LedgerOperationsExt};
use crate::handler::ledger_ext::SignedLedgerUpdateExt;
use crate::handler::messages::DepositsMessage;
use deposits_core::messages::LedgerOperation;
use super::proto::{
    GetLedgerUpdatesRequest, GetLedgerUpdatesResponse,
    LedgerUpdate, DepositsError,
};

/// Handle get_ledger_updates request
pub fn handle_get_ledger_updates<L>(
    handler: &DepositsHandler<L>,
    request: GetLedgerUpdatesRequest,
) -> Result<GetLedgerUpdatesResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let reserves_id = PublicKey::from_str(&request.ledger_id)
        .map_err(|_| DepositsError {
            code: "INVALID_LEDGER_ID".into(),
            message: "Invalid ledger_id (expected partner node pubkey)".into(),
        })?;

    let all_updates = handler.get_ledger_updates(reserves_id)
        .map_err(|e| DepositsError {
            code: "GET_UPDATES_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    // Get sync state to determine acknowledged/committed status
    let (ack_hash, commit_hash) = handler.get_ledger_sync_state(reserves_id)
        .unwrap_or(([0u8; 32], [0u8; 32]));

    // Build set of hashes that are acknowledged/committed
    // An update is acknowledged if its hash appears at or before the ack_hash in the chain
    let _ack_reached = false;
    let _commit_reached = false;
    let ack_seq = all_updates.iter()
        .find(|u| u.current_hash == ack_hash)
        .map(|u| u.sequence_number);
    let commit_seq = all_updates.iter()
        .find(|u| u.current_hash == commit_hash)
        .map(|u| u.sequence_number);

    // Apply pagination
    let from_sequence = request.from_sequence.unwrap_or(0) as usize;
    let limit = request.limit.unwrap_or(100) as usize;

    let updates: Vec<LedgerUpdate> = all_updates
        .into_iter()
        .skip(from_sequence)
        .take(limit)
        .map(|update| {
            // Decode message to get operation details
            let (operation_type, amount_sat, deposit_pubkey, description) =
                if let Ok(msg) = update.get_message() {
                    let op_name = msg.operation_name()
                        .unwrap_or_else(|| msg.variant_name())
                        .to_string();
                    let (amt, pk, desc) = extract_operation_details(&msg);
                    (op_name, amt, pk, desc)
                } else {
                    (format!("0x{:04x}", update.message_type), None, None, None)
                };

            // Check if this update is acknowledged/committed
            let acknowledged = ack_seq.map_or(false, |seq| update.sequence_number <= seq);
            let committed = commit_seq.map_or(false, |seq| update.sequence_number <= seq);

            LedgerUpdate {
                sequence_number: update.sequence_number,
                operation_type,
                signature: update.operator_signature.to_vec(),
                timestamp: update.timestamp,
                previous_hash: hex::encode(update.previous_hash),
                current_hash: hex::encode(update.current_hash),
                acknowledged,
                committed,
                amount_sat,
                deposit_pubkey,
                description,
            }
        })
        .collect();

    Ok(GetLedgerUpdatesResponse { updates })
}

/// Extract amount, deposit pubkey, and description from a decoded message
/// V2 format: All ledger operations are inside LedgerUpdate messages
fn extract_operation_details(msg: &DepositsMessage) -> (Option<u64>, Option<String>, Option<String>) {
    match msg {
        // V2 LedgerUpdate - extract from inner operation
        DepositsMessage::LedgerUpdate(m) => extract_from_ledger_operation(&m.operation),
        _ => (None, None, None),
    }
}

/// Extract details from a LedgerOperation
fn extract_from_ledger_operation(op: &LedgerOperation) -> (Option<u64>, Option<String>, Option<String>) {
    match op {
        LedgerOperation::DepositOpen { pubkey, .. } => (None, Some(pubkey.to_string()), None),
        LedgerOperation::DepositClose { pubkey } => (None, Some(pubkey.to_string()), None),
        LedgerOperation::PaymentCredit { deposit_pubkey, amount, .. } => (Some(*amount), Some(deposit_pubkey.to_string()), None),
        LedgerOperation::PaymentLock { pubkey, amount, .. } => (Some(*amount), Some(pubkey.to_string()), None),
        LedgerOperation::PaymentFail { pubkey, amount, .. } => (Some(*amount), Some(pubkey.to_string()), None),
        LedgerOperation::PaymentFulfill { pubkey, amount, .. } => (Some(*amount), Some(pubkey.to_string()), None),
        LedgerOperation::TransferLock { pubkey, amount, .. } => (Some(*amount), Some(pubkey.to_string()), None),
        LedgerOperation::TransferFail { pubkey, .. } => (None, Some(pubkey.to_string()), None),
        LedgerOperation::TransferFulfill { pubkey, amount, .. } => (Some(*amount), Some(pubkey.to_string()), None),
        LedgerOperation::ReservesAdd { amount, .. } => (Some(*amount), None, None),
        LedgerOperation::ReservesIncrease { new_amount } => (Some(*new_amount), None, None),
        LedgerOperation::ReservesDecrease { new_amount } => (Some(*new_amount), None, None),
        LedgerOperation::CollateralAddPartner { collateral_partner, .. } =>
            (None, None, Some(format!("partner:{}", &collateral_partner.to_string()[..8]))),
        LedgerOperation::CollateralRemovePartner { collateral_partner, .. } =>
            (None, None, Some(format!("partner:{}", &collateral_partner.to_string()[..8]))),
        LedgerOperation::CollateralIncrease { new_amount, .. } => (Some(*new_amount), None, None),
        LedgerOperation::CollateralDecrease { new_amount, .. } => (Some(*new_amount), None, None),
        LedgerOperation::CollateralAttestation { amount, .. } => (Some(*amount), None, None),
        LedgerOperation::FeeCollect { pubkey, amount, .. } => (Some(*amount), Some(pubkey.to_string()), None),
        _ => (None, None, None),
    }
}
