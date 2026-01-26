//! Collateral API Handlers
//!
//! Handlers for collateral operations: add partner, remove partner, get info.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, CollateralOperations};
use super::proto::{
    AddCollateralPartnerRequest, AddCollateralPartnerResponse,
    RemoveCollateralPartnerRequest, RemoveCollateralPartnerResponse,
    GetCollateralInfoRequest, GetCollateralInfoResponse,
    CollateralPartnerInfo, DepositsError,
};

/// Handle add_collateral_partner request
pub async fn handle_add_collateral_partner<L>(
    handler: &DepositsHandler<L>,
    request: AddCollateralPartnerRequest,
) -> Result<AddCollateralPartnerResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let collateral_partner_id = PublicKey::from_str(&request.collateral_partner_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid collateral_partner_id".into(),
        })?;

    handler.add_collateral_partner_async(partner_id, collateral_partner_id).await
        .map_err(|e| DepositsError {
            code: "ADD_COLLATERAL_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(AddCollateralPartnerResponse {})
}

/// Handle remove_collateral_partner request
pub fn handle_remove_collateral_partner<L>(
    handler: &DepositsHandler<L>,
    request: RemoveCollateralPartnerRequest,
) -> Result<RemoveCollateralPartnerResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let collateral_partner_id = PublicKey::from_str(&request.collateral_partner_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid collateral_partner_id".into(),
        })?;

    handler.remove_collateral_partner(partner_id, collateral_partner_id)
        .map_err(|e| DepositsError {
            code: "REMOVE_COLLATERAL_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(RemoveCollateralPartnerResponse {})
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
    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    let info = handler.get_collateral_info(partner_id)
        .ok_or_else(|| DepositsError {
            code: "LEDGER_NOT_FOUND".into(),
            message: format!("No ledger found for partner {}", partner_id),
        })?;

    let partners: Vec<CollateralPartnerInfo> = info.collateral_partners
        .into_iter()
        .map(|p| CollateralPartnerInfo {
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
