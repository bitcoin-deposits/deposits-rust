//! Deposit API Handlers
//!
//! Handlers for deposit operations: add, list, remove.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, DepositOperations, LedgerOperationsExt};
use super::proto::{
    AddDepositRequest, AddDepositResponse,
    ListDepositsRequest, ListDepositsResponse,
    RemoveDepositRequest, RemoveDepositResponse,
    DepositInfo, DepositsError,
};

/// Handle add_deposit request
pub async fn handle_add_deposit<L>(
    handler: &DepositsHandler<L>,
    request: AddDepositRequest,
) -> Result<AddDepositResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let deposit_pubkey = PublicKey::from_str(&request.deposit_pubkey)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid deposit_pubkey".into(),
        })?;

    handler.add_deposit_async(partner_id, deposit_pubkey, None).await
        .map_err(|e| DepositsError {
            code: "ADD_DEPOSIT_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(AddDepositResponse {
        deposit_pubkey: deposit_pubkey.to_string(),
    })
}

/// Handle list_deposits request
pub fn handle_list_deposits<L>(
    handler: &DepositsHandler<L>,
    request: ListDepositsRequest,
) -> Result<ListDepositsResponse, DepositsError>
where
    L: Deref + Clone,
    L::Target: LdkLogger,
{
    let deposits: Vec<DepositInfo> = if let Some(ledger_id) = request.ledger_id {
        // Filter by ledger
        let partner_id = PublicKey::from_str(&ledger_id)
            .map_err(|_| DepositsError {
                code: "INVALID_LEDGER_ID".into(),
                message: "Invalid ledger_id (expected partner node pubkey)".into(),
            })?;

        handler.get_deposits_for_partner(partner_id)
            .map(|deps| {
                deps.into_iter()
                    .map(|(pubkey, balance, locked)| DepositInfo {
                        deposit_pubkey: pubkey.to_string(),
                        ledger_id: partner_id.to_string(),
                        balance_sat: balance,
                        locked_balance_sat: locked,
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        // List all deposits across all ledgers
        let all_ledgers = handler.get_all_ledgers();
        all_ledgers
            .into_iter()
            .filter(|((op, _), _)| *op == handler.our_node_id)
            .flat_map(|((_, partner_id), ledger_arc)| {
                let ledger = ledger_arc.read().unwrap();
                ledger.state.deposits.iter()
                    .map(|(pubkey, deposit)| DepositInfo {
                        deposit_pubkey: pubkey.to_string(),
                        ledger_id: partner_id.to_string(),
                        balance_sat: deposit.balance,
                        locked_balance_sat: deposit.locked_balance,
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    Ok(ListDepositsResponse { deposits })
}

/// Handle remove_deposit request
pub fn handle_remove_deposit<L>(
    handler: &DepositsHandler<L>,
    request: RemoveDepositRequest,
) -> Result<RemoveDepositResponse, DepositsError>
where
    L: Deref + Clone,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.ledger_id)
        .map_err(|_| DepositsError {
            code: "INVALID_LEDGER_ID".into(),
            message: "Invalid ledger_id (expected partner node pubkey)".into(),
        })?;

    let deposit_pubkey = PublicKey::from_str(&request.deposit_pubkey)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid deposit_pubkey".into(),
        })?;

    // Get the ledger and remove the deposit
    let ledger_arc = handler.get_all_ledgers()
        .into_iter()
        .find(|((op, part), _)| *op == handler.our_node_id && *part == partner_id)
        .map(|(_, ledger)| ledger);

    let ledger_arc = ledger_arc.ok_or_else(|| DepositsError {
        code: "LEDGER_NOT_FOUND".into(),
        message: format!("No ledger found for partner {}", partner_id),
    })?;

    {
        let mut ledger = ledger_arc.write().unwrap();
        if ledger.state.deposits.remove(&deposit_pubkey).is_none() {
            return Err(DepositsError {
                code: "DEPOSIT_NOT_FOUND".into(),
                message: format!("Deposit {} not found in ledger", deposit_pubkey),
            });
        }
    }

    Ok(RemoveDepositResponse {})
}
