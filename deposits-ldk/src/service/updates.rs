//! Ledger Updates API Handler
//!
//! Handler for retrieving ledger update history.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, LedgerOperationsExt};
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
    L: Deref + Clone,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.ledger_id)
        .map_err(|_| DepositsError {
            code: "INVALID_LEDGER_ID".into(),
            message: "Invalid ledger_id (expected partner node pubkey)".into(),
        })?;

    let all_updates = handler.get_ledger_updates(partner_id)
        .map_err(|e| DepositsError {
            code: "GET_UPDATES_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    // Apply pagination
    let from_sequence = request.from_sequence.unwrap_or(0) as usize;
    let limit = request.limit.unwrap_or(100) as usize;

    let updates: Vec<LedgerUpdate> = all_updates
        .into_iter()
        .skip(from_sequence)
        .take(limit)
        .map(|update| LedgerUpdate {
            sequence_number: update.sequence_number,
            operation_type: format!("0x{:04x}", update.message_type),
            signature: update.operator_signature.to_vec(),
            timestamp: update.timestamp,
        })
        .collect();

    Ok(GetLedgerUpdatesResponse { updates })
}
