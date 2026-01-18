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
    ReduceReservesRequest, ReduceReservesResponse,
    DepositsError,
};

/// Handle get_reserves_status request
pub fn handle_get_reserves_status<L>(
    handler: &DepositsHandler<L>,
    request: GetReservesStatusRequest,
) -> Result<GetReservesStatusResponse, DepositsError>
where
    L: Deref + Clone,
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

/// Handle reduce_reserves request
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

    handler.reclaim_excess_reserves_async(partner_id, request.amount_sat).await
        .map_err(|e| DepositsError {
            code: "REDUCE_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(ReduceReservesResponse {})
}
