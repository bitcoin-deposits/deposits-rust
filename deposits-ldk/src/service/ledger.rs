//! Ledger API Handlers
//!
//! Handlers for ledger operations: init, list, get, close.

use std::ops::Deref;
use std::str::FromStr;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Address;
use bitcoin::Network;
use lightning::util::logger::Logger as LdkLogger;

use crate::handler::{DepositsHandler, LedgerOperations, LedgerOperationsExt};
use super::proto::{
    InitLedgerRequest, InitLedgerResponse,
    ListLedgersRequest, ListLedgersResponse,
    GetLedgerRequest, GetLedgerResponse,
    CloseLedgerRequest, CloseLedgerResponse,
    LedgerInfo, DepositsError,
};

/// Handle init_ledger request
pub async fn handle_init_ledger<L>(
    handler: &DepositsHandler<L>,
    request: InitLedgerRequest,
) -> Result<InitLedgerResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::secp256k1::rand::rngs::OsRng;

    let partner_id = PublicKey::from_str(&request.partner_node_id)
        .map_err(|_| DepositsError {
            code: "INVALID_PUBKEY".into(),
            message: "Invalid partner_node_id".into(),
        })?;

    // Generate address if not provided
    let address = if request.ledger_address.is_empty() {
        // Generate a new address
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let secret_key = SecretKey::new(&mut rng);
        let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        // Create P2WPKH address (native segwit)
        let compressed_pk = bitcoin::CompressedPublicKey::try_from(bitcoin::PublicKey::new(public_key))
            .map_err(|e| DepositsError {
                code: "ADDRESS_GENERATION_FAILED".into(),
                message: format!("Failed to compress public key: {}", e),
            })?;

        // Store the private key for this ledger
        handler.store_ledger_private_key(partner_id, secret_key)
            .map_err(|e| DepositsError {
                code: "KEY_STORAGE_FAILED".into(),
                message: format!("Failed to store ledger private key: {}", e),
            })?;

        // Use regtest network (TODO: get from config)
        bitcoin::Address::p2wpkh(&compressed_pk, bitcoin::Network::Regtest)
    } else {
        // Parse provided address
        let address: Address<bitcoin::address::NetworkUnchecked> = request.ledger_address.parse()
            .map_err(|_| DepositsError {
                code: "INVALID_ADDRESS".into(),
                message: "Invalid ledger_address".into(),
            })?;
        address.assume_checked()
    };

    handler.initiate_ledger_handshake_async(partner_id, address).await
        .map_err(|e| DepositsError {
            code: "INIT_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(InitLedgerResponse {
        ledger_id: partner_id.to_string(),
    })
}

/// Handle list_ledgers request
pub fn handle_list_ledgers<L>(
    handler: &DepositsHandler<L>,
    _request: ListLedgersRequest,
) -> Result<ListLedgersResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let operator_ledgers = handler.list_operator_ledgers();
    let our_node_id = handler.our_node_id.to_string();

    let ledgers: Vec<LedgerInfo> = operator_ledgers
        .into_iter()
        .map(|partner_id| {
            // Get ledger details
            let ledger_arc = handler.get_all_ledgers()
                .into_iter()
                .find(|((op, part), _)| *op == handler.our_node_id && *part == partner_id)
                .map(|(_, ledger)| ledger);

            if let Some(ledger_arc) = ledger_arc {
                let ledger = ledger_arc.read().unwrap();
                LedgerInfo {
                    ledger_id: partner_id.to_string(),
                    operator_node_id: our_node_id.clone(),
                    partner_node_id: partner_id.to_string(),
                    operator_balance_sat: ledger.total_deposit_balance(),
                    partner_balance_sat: 0, // Partner balance tracked via reserves
                    reserves_sat: ledger.reserves_amount(),
                    deposit_count: ledger.state.deposits.len() as u64,
                    sequence_number: ledger.history.len() as u64,
                    channel_id: String::new(), // TODO: Track channel_id in ledger
                    status: "active".to_string(), // TODO: Track status in ledger
                    capacity_sat: 0, // TODO: Get from channel info
                    local_ledger_hash: String::new(), // TODO: Compute hash
                    remote_ledger_hash: String::new(), // TODO: Track remote hash
                }
            } else {
                LedgerInfo {
                    ledger_id: partner_id.to_string(),
                    operator_node_id: our_node_id.clone(),
                    partner_node_id: partner_id.to_string(),
                    ..Default::default()
                }
            }
        })
        .collect();

    Ok(ListLedgersResponse { ledgers })
}

/// Handle get_ledger request
pub fn handle_get_ledger<L>(
    handler: &DepositsHandler<L>,
    request: GetLedgerRequest,
) -> Result<GetLedgerResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.ledger_id)
        .map_err(|_| DepositsError {
            code: "INVALID_LEDGER_ID".into(),
            message: "Invalid ledger_id (expected partner node pubkey)".into(),
        })?;

    let ledger_arc = handler.get_all_ledgers()
        .into_iter()
        .find(|((op, part), _)| *op == handler.our_node_id && *part == partner_id)
        .map(|(_, ledger)| ledger);

    let ledger_arc = ledger_arc.ok_or_else(|| DepositsError {
        code: "LEDGER_NOT_FOUND".into(),
        message: format!("No ledger found for partner {}", partner_id),
    })?;

    let ledger = ledger_arc.read().unwrap();
    let ledger_info = LedgerInfo {
        ledger_id: partner_id.to_string(),
        operator_node_id: handler.our_node_id.to_string(),
        partner_node_id: partner_id.to_string(),
        operator_balance_sat: ledger.total_deposit_balance(),
        partner_balance_sat: 0, // Partner balance tracked via reserves
        reserves_sat: ledger.reserves_amount(),
        deposit_count: ledger.state.deposits.len() as u64,
        sequence_number: ledger.history.len() as u64,
        channel_id: String::new(), // TODO: Track channel_id in ledger
        status: "active".to_string(), // TODO: Track status in ledger
        capacity_sat: 0, // TODO: Get from channel info
        local_ledger_hash: String::new(), // TODO: Compute hash
        remote_ledger_hash: String::new(), // TODO: Track remote hash
    };

    Ok(GetLedgerResponse {
        ledger: Some(ledger_info),
    })
}

/// Handle close_ledger request (async version to avoid blocking event loop)
pub async fn handle_close_ledger<L>(
    handler: &DepositsHandler<L>,
    request: CloseLedgerRequest,
) -> Result<CloseLedgerResponse, DepositsError>
where
    L: Deref + Clone + Send + Sync,
    L::Target: LdkLogger,
{
    let partner_id = PublicKey::from_str(&request.ledger_id)
        .map_err(|_| DepositsError {
            code: "INVALID_LEDGER_ID".into(),
            message: "Invalid ledger_id (expected partner node pubkey)".into(),
        })?;

    handler.close_ledger_async(partner_id).await
        .map_err(|e| DepositsError {
            code: "CLOSE_FAILED".into(),
            message: format!("{:?}", e),
        })?;

    Ok(CloseLedgerResponse {})
}
