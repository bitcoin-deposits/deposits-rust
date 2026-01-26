//! Reserves API Handlers
//!
//! Handlers for reserves operations: get status, reduce reserves.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, ReservesOperations};
use super::proto::{
    GetReservesStatusRequest, GetReservesStatusResponse,
    AddReservesRequest, AddReservesResponse,
    ReduceReservesRequest, ReduceReservesResponse,
    RemoveReservesRequest, RemoveReservesResponse,
    DepositsError,
};

/// Handle get_reserves_status request
pub fn handle_get_reserves_status<L>(
    handler: &DepositsHandler<L>,
    request: GetReservesStatusRequest,
) -> Result<GetReservesStatusResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let status = handler.get_channel_reserves_status(partner_id)
        .map_err(|e| DepositsError {
            code: "STATUS_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(GetReservesStatusResponse {
        current_amount: status.current_amount,
        required_amount: status.required_amount,
        excess_amount: status.excess_amount,
        total_deposit_balances: status.total_deposit_balances,
    })
}

/// Handle add_reserves request
/// Adds reserves to the channel commitment with Taproot script embedding ledger hash
pub fn handle_add_reserves<L>(
    handler: &DepositsHandler<L>,
    request: AddReservesRequest,
) -> Result<AddReservesResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    handler.add_reserves_to_channel(partner_id, request.amount_sat)
        .map_err(|e| DepositsError {
            code: "ADD_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(AddReservesResponse {})
}

/// Handle reduce_reserves request
/// Uses async method which works properly in the server context
pub async fn handle_reduce_reserves<L>(
    handler: &DepositsHandler<L>,
    request: ReduceReservesRequest,
) -> Result<ReduceReservesResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    // Use async method - it works when deposits are 0 (excess = full amount)
    handler.reclaim_excess_reserves_async(partner_id, request.amount_sat).await
        .map_err(|e| DepositsError {
            code: "REDUCE_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(ReduceReservesResponse {})
}

/// Handle remove_reserves request
/// Removes the reserves output from the channel (requires reserves to be 0)
/// Uses async method which works properly in the server context
pub async fn handle_remove_reserves<L>(
    handler: &DepositsHandler<L>,
    request: RemoveReservesRequest,
) -> Result<RemoveReservesResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    // Use async method - it works properly in the async server context
    handler.remove_reserves_async(partner_id).await
        .map_err(|e| DepositsError {
            code: "REMOVE_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(RemoveReservesResponse {})
}
