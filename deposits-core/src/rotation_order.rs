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
        extra_outputs: Vec::new(),
    })
    .ok_or("the DEP-03 rotation leaves the vault below dust")?;
    let mut stripped = tx.clone();
    for i in &mut stripped.input {
        i.witness = Witness::new();
    }
    if stripped != ours {
        return Err("rotation_tx differs from the DEP-03 rotation we build".into());
    }
    if tx.output[0].value.to_sat() != (amount + collateral_amount) / 1000 {
        return Err("QuorumBegin amounts do not sum to the rotation's new vault".into());
    }
    Ok(())
}
