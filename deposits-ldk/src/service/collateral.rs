//! Collateral API Handlers
//!
//! Handlers for collateral operations: add quorum member, remove quorum member, get info.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, CollateralOperations};
use super::proto::{
    QuorumAddMemberRequest, QuorumAddMemberResponse,
    QuorumRemoveMemberRequest, QuorumRemoveMemberResponse,
    GetCollateralInfoRequest, GetCollateralInfoResponse,
    QuorumMemberInfo, DepositsError,
};

/// Handle add_quorum_member request
pub async fn handle_add_quorum_member<L>(
    handler: &DepositsHandler<L>,
    request: QuorumAddMemberRequest,
) -> Result<QuorumAddMemberResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let reserves_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let quorum_member_id = PublicKey::from_str(&request.quorum_member_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid quorum_member_id".into(),
        })?;

    handler.add_quorum_member_async(reserves_id, quorum_member_id).await
        .map_err(|e| DepositsError {
            code: "ADD_COLLATERAL_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(QuorumAddMemberResponse {})
}

/// Handle remove_quorum_member request
pub fn handle_remove_quorum_member<L>(
    handler: &DepositsHandler<L>,
    request: QuorumRemoveMemberRequest,
) -> Result<QuorumRemoveMemberResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let reserves_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let quorum_member_id = PublicKey::from_str(&request.quorum_member_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid quorum_member_id".into(),
        })?;

    handler.remove_quorum_member(reserves_id, quorum_member_id)
        .map_err(|e| DepositsError {
            code: "REMOVE_COLLATERAL_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(QuorumRemoveMemberResponse {})
}

/// Handle get_collateral_info request
pub fn handle_get_collateral_info<L>(
    handler: &DepositsHandler<L>,
    request: GetCollateralInfoRequest,
) -> Result<GetCollateralInfoResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let reserves_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let info = handler.get_collateral_info(reserves_id)
        .ok_or_else(|| DepositsError {
            code: "LEDGER_NOT_FOUND".into(),
            message: format!("No ledger found for partner {}", reserves_id),
        })?;

    let partners: Vec<QuorumMemberInfo> = info.quorum_members
        .into_iter()
        .map(|p| QuorumMemberInfo {
            pubkey: p.pubkey.to_string(),
            collateral_amount: p.collateral_amount,
            block_height: p.block_height,
            has_attestation: p.has_attestation,
        })
        .collect();

    Ok(GetCollateralInfoResponse {
        partners,
        total_available_collateral: info.total_available_collateral,
    })
}
