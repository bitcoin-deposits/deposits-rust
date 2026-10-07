//! DEP-03 §"Rotation ordering": a cosigner of a rotating `QuorumBegin` verifies the
//! signed rotation the request carries, in place of an on-chain outpoint check.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, Witness};
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::TlvDecode;
use deposits_protocol::types::SignedLedgerUpdate;

use crate::tapscript_reserves::{
    build_rotation_tx, RotationTxParams, TapscriptReservesBuilder, VoterSet,
    CONFISCATION_DEFAULT_FEERATE_SAT_VB,
};
use crate::vault_spend::vault_spend_signers;

/// The sequence of the `QuorumBegin` whose vault the next `QuorumBegin` rotates:
/// the latest one with no `DisputeAcquire` after it (an acquisition's first
/// `QuorumBegin` is funded by the lottery claim, not rotated).
pub fn rotating_quorum_begin_seq(history: &[SignedLedgerUpdate]) -> Option<u64> {
    let mut ordered: Vec<&SignedLedgerUpdate> = history.iter().collect();
    ordered.sort_by_key(|u| u.sequence_number);
    let mut seq = None;
    for u in ordered {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin { .. }) => seq = Some(u.sequence_number),
            Ok(LedgerOperation::DisputeAcquire { .. }) => seq = None,
            _ => {}
        }
    }
    seq
}

/// Verify `tx` is the rotation the rotating `QuorumBegin` `op` names, of the vault
/// `history`'s governing `QuorumBegin` created: its txid and output 0; without its
/// witness, byte-identical to the DEP-03 rotation; a witness satisfying a tier of the
/// vault to threshold; output 0 worth the op's amounts.
pub fn verify_rotation_tx(
    history: &[SignedLedgerUpdate],
    state: &crate::types::LedgerState,
    height: u32,
    op: &LedgerOperation,
    tx: &Transaction,
    network: Network,
) -> Result<(), String> {
    let LedgerOperation::QuorumBegin {
        reserves_id,
        new_outpoint_txid,
        new_outpoint_vout,
        amount,
        collateral_amount,
        exit_cutoff_height,
        ..
    } = op
    else {
        return Err("not a QuorumBegin".into());
    };
    if tx.compute_txid().to_byte_array() != *new_outpoint_txid || *new_outpoint_vout != 0 {
        return Err("rotation_tx is not the QuorumBegin's new outpoint".into());
    }
    let gov = rotating_quorum_begin_seq(history).ok_or("no vault to rotate")?;
    let mut operator = None;
    let mut governing = None;
    for u in history {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen { operator_id, .. }) => operator = Some(operator_id),
            Ok(q @ LedgerOperation::QuorumBegin { .. }) if u.sequence_number == gov => {
                governing = Some(q)
            }
            _ => {}
        }
    }
    let (
        Some(operator),
        Some(LedgerOperation::QuorumBegin {
            new_outpoint_txid: vtxid,
            new_outpoint_vout: vvout,
            amount: vamount,
            collateral_amount: vcoll,
            quorum_expiry,
            ledger_hash,
            quorum_members,
            protocol_version,
            ..
        }),
    ) = (operator, governing)
    else {
        return Err("governing QuorumBegin or LedgerOpen missing".into());
    };
    let rs = crate::ruleset::resolve_or_current(protocol_version.as_deref());
    let voters = VoterSet::new(operator, quorum_members.iter().map(|m| m.pubkey).collect());
    let n_voters = voters.total_count();
    let config = (rs.tier_config_factory)(n_voters, quorum_expiry);
    let vault_spk = TapscriptReservesBuilder::new(voters, config, network, ledger_hash)
        .build()
        .map_err(|e| e.to_string())?
        .script_pubkey();
    let vault_sats = (vamount + vcoll) / 1000;
    let prevout = TxOut {
        value: Amount::from_sat(vault_sats),
        script_pubkey: vault_spk,
    };
    vault_spend_signers(history, gov, tx, &[prevout])?;
    let new_vault_spk: ScriptBuf = reserves_id
        .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .map_err(|e| format!("reserves_id: {e}"))?
        .require_network(network)
        .map_err(|e| format!("reserves_id: {e}"))?
        .script_pubkey();
    let ours = build_rotation_tx(&RotationTxParams {
        vault: OutPoint::new(Txid::from_byte_array(vtxid), vvout),
        vault_sats,
        voters: n_voters,
        feerate_sat_vb: CONFISCATION_DEFAULT_FEERATE_SAT_VB,
        lock_time: tx.lock_time.to_consensus_u32(),
        new_vault_spk,
        splice_in: None,
        extra_outputs: due_exit_outputs(state, height, *exit_cutoff_height),
    })
    .ok_or("the DEP-03 rotation leaves the vault below dust")?;
    let mut stripped = tx.clone();
    for i in &mut stripped.input {
        i.witness = Witness::new();
    }
    if stripped != ours {
        return Err("rotation_tx differs from the DEP-03 rotation we build".into());
    }
    let new_sats = tx.output[0].value.to_sat();
    if new_sats != (amount + collateral_amount) / 1000 {
        return Err("QuorumBegin amounts do not sum to the rotation's new vault".into());
    }
    let extras: u64 = tx.output[1..].iter().map(|o| o.value.to_sat()).sum();
    let fee = vault_sats.saturating_sub(extras).saturating_sub(new_sats);
    if *collateral_amount != rotation_collateral(state, vault_sats, fee) {
        return Err("QuorumBegin collateral is not the DEP-20 §3 share".into());
    }
    Ok(())
}

/// DEP-20 §3 due exits at `height` under `cutoff` (absent: height − margin) as the
/// rotation's extra outputs: (exit_address, floor(amount / 1000)) in due order.
pub fn due_exit_outputs(
    state: &crate::types::LedgerState,
    height: u32,
    cutoff: Option<u32>,
) -> Vec<(ScriptBuf, u64)> {
    let cutoff = cutoff.unwrap_or(height.saturating_sub(crate::types::EXIT_CUTOFF_MARGIN_BLOCKS));
    state
        .due_exits(height, cutoff)
        .into_iter()
        .map(|(_, e)| (ScriptBuf::from_bytes(e.exit_address), e.amount / 1000))
        .collect()
}

/// The QuorumBegin `exit_outputs` entries for the due set (vout = i + 1).
pub fn due_exit_entries(
    state: &crate::types::LedgerState,
    height: u32,
    cutoff: u32,
) -> Vec<crate::messages::ExitOutput> {
    state
        .due_exits(height, cutoff)
        .into_iter()
        .enumerate()
        .map(|(i, (_, e))| crate::messages::ExitOutput {
            deposit_id: e.deposit_id,
            amount: e.amount,
            vout: i as u32 + 1,
        })
        .collect()
}

/// DEP-20 §3 Amounts: the new collateral bears only its share of the rotation fee:
/// floor(old_collateral × (V − F) × 1000 / (old_reserves + old_collateral)).
pub fn rotation_collateral(
    state: &crate::types::LedgerState,
    vault_sats: u64,
    fee_sats: u64,
) -> u64 {
    let old = state.reserves_amount as u128 + state.collateral_amount as u128;
    if old == 0 {
        return 0;
    }
    (state.collateral_amount as u128 * (vault_sats.saturating_sub(fee_sats)) as u128 * 1000 / old)
        as u64
}

/// Of published rotation candidates (transaction hex, e.g. Kind 9107 contents), the one
/// whose txid is `new_outpoint_txid`: the rotation a recorded `QuorumBegin` names.
pub fn published_rotation(
    new_outpoint_txid: [u8; 32],
    candidates: &[String],
) -> Option<Transaction> {
    candidates.iter().find_map(|h| {
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(h).ok()?).ok()?;
        (tx.compute_txid().to_byte_array() == new_outpoint_txid).then_some(tx)
    })
}

/// The new outpoint txid of the `QuorumBegin` latest in `history`, if any.
pub fn latest_quorum_begin_txid(history: &[SignedLedgerUpdate]) -> Option<[u8; 32]> {
    history
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::QuorumBegin {
                new_outpoint_txid, ..
            }) => Some((u.sequence_number, new_outpoint_txid)),
            _ => None,
        })
        .max_by_key(|(seq, _)| *seq)
        .map(|(_, t)| t)
}
