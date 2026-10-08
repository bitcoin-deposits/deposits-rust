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
    splice_prevout: Option<TxOut>,
) -> Result<(), String> {
    let LedgerOperation::QuorumBegin {
        reserves_id,
        new_outpoint_txid,
        new_outpoint_vout,
        amount,
        collateral_amount,
        exit_cutoff_height,
        splice_in_outpoint,
        splice_in_amount,
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
    // DEP-20 §4: a splice-in is input 1; its prevout (looked up by the caller) enters the sighash.
    let splice = match (splice_in_outpoint, splice_prevout) {
        (None, _) => None,
        (Some(_), None) => return Err("splice-in outpoint not found".into()),
        (Some((stxid, svout)), Some(sp)) => {
            if *splice_in_amount != Some(sp.value.to_sat() * 1000) {
                return Err("splice_in_amount_msats is not the outpoint's value".into());
            }
            Some((OutPoint::new(Txid::from_byte_array(*stxid), *svout), sp))
        }
    };
    let mut prevouts = vec![prevout];
    if let Some((_, sp)) = &splice {
        prevouts.push(sp.clone());
        verify_simple_input(tx, 1, &prevouts)?;
    }
    vault_spend_signers(history, gov, tx, &prevouts)?;
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
        feerate_sat_vb: state.rotation_feerate(),
        lock_time: tx.lock_time.to_consensus_u32(),
        new_vault_spk,
        splice_in: splice.as_ref().map(|(o, sp)| (*o, sp.value.to_sat())),
        extra_outputs: settlement_outputs(state, height, *exit_cutoff_height).0,
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
    let added = splice.as_ref().map_or(0, |(_, sp)| sp.value.to_sat());
    let (_, exits_cost, dorm_cost) = settlement_outputs(state, height, *exit_cutoff_height);
    let fee = (vault_sats + added)
        .saturating_sub(extras)
        .saturating_sub(new_sats)
        .saturating_sub(exits_cost)
        .saturating_sub(dorm_cost);
    // DEP-20 §8.4: spin-outs' own costs come out of collateral; §8.3: so does the premium.
    let c = exit_cutoff_height
        .unwrap_or(height.saturating_sub(crate::types::EXIT_CUTOFF_MARGIN_BLOCKS));
    let c0 = rotation_collateral(state, vault_sats, fee)
        .saturating_sub((dorm_cost + migration_premium_sats(state, c)) * 1000);
    if *collateral_amount < c0 || *collateral_amount > c0 + added * 1000 {
        return Err("QuorumBegin collateral is not the DEP-20 §3-4 share".into());
    }
    Ok(())
}

/// Verify input `i`'s witness when it spends a P2TR key path or a P2WPKH output (a splice-in,
/// DEP-20 §4): a recorded rotation must be broadcastable.
pub fn verify_simple_input(tx: &Transaction, i: usize, prevouts: &[TxOut]) -> Result<(), String> {
    use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey};
    use bitcoin::sighash::{Prevouts, SighashCache};
    let secp = Secp256k1::verification_only();
    let spk = &prevouts[i].script_pubkey;
    let wit = &tx.input[i].witness;
    let mut cache = SighashCache::new(tx);
    if spk.is_p2tr() {
        let key = XOnlyPublicKey::from_slice(&spk.as_bytes()[2..34]).map_err(|e| e.to_string())?;
        let sig = wit.nth(0).ok_or("splice input has no witness")?;
        let sig = bitcoin::taproot::Signature::from_slice(sig).map_err(|e| e.to_string())?;
        let h = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), sig.sighash_type)
            .map_err(|e| e.to_string())?;
        secp.verify_schnorr(
            &sig.signature,
            &Message::from_digest(h.to_byte_array()),
            &key,
        )
        .map_err(|_| "splice input key-path signature does not verify".to_string())
    } else if spk.is_p2wpkh() {
        let (sig, pk) = (
            wit.nth(0).ok_or("no signature")?,
            wit.nth(1).ok_or("no pubkey")?,
        );
        let pk = PublicKey::from_slice(pk).map_err(|e| e.to_string())?;
        let ours = bitcoin::CompressedPublicKey(pk);
        if ScriptBuf::new_p2wpkh(&ours.wpubkey_hash()) != *spk {
            return Err("splice input pubkey does not match its P2WPKH".into());
        }
        let sig = bitcoin::ecdsa::Signature::from_slice(sig).map_err(|e| e.to_string())?;
        let h = cache
            .p2wpkh_signature_hash(i, spk, prevouts[i].value, sig.sighash_type)
            .map_err(|e| e.to_string())?;
        secp.verify_ecdsa(
            &Message::from_digest(h.to_byte_array()),
            &sig.signature,
            &pk,
        )
        .map_err(|_| "splice input signature does not verify".to_string())
    } else {
        Err("splice input must spend a P2TR key path or P2WPKH output".into())
    }
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
        .map(|(_, e)| {
            let cost = state.exit_cost(&e.exit_address);
            (
                ScriptBuf::from_bytes(e.exit_address),
                e.amount / 1000 - cost,
            )
        })
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

/// DEP-20 §3 exits' own share of the rotation fee: Σ exit_cost over the due set.
pub fn due_exits_cost(state: &crate::types::LedgerState, height: u32, cutoff: Option<u32>) -> u64 {
    let cutoff = cutoff.unwrap_or(height.saturating_sub(crate::types::EXIT_CUTOFF_MARGIN_BLOCKS));
    state
        .due_exits(height, cutoff)
        .iter()
        .map(|(_, e)| state.exit_cost(&e.exit_address))
        .sum()
}

/// DEP-20 §3 Amounts: the new collateral bears only its share of the vault's part of the
/// rotation fee (`fee_sats`: the fee less what the exits paid themselves):
/// floor(old_collateral × (V − F_v) × 1000 / (old_reserves + old_collateral)).
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

/// DEP-06 recovery voters: the members, other than the original operator (author of sequence
/// 0), of the latest `QuorumBegin` the original operator authored at a sequence at or below the
/// dispute's fork point (the lowest `last_valid_sequence` any `DisputeEnter` names; with no
/// `DisputeEnter`, every sequence). Sorted by x-only key; threshold floor(r/2) + 1.
pub fn lottery_recovery_voters(
    updates: &[SignedLedgerUpdate],
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, usize)> {
    let operator = updates.iter().find(|u| u.sequence_number == 0)?.operator_id;
    let fork_point = updates
        .iter()
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter {
                last_valid_sequence,
                ..
            }) => Some(last_valid_sequence),
            _ => None,
        })
        .min()
        .unwrap_or(u64::MAX);
    let mut best: Option<(u64, Vec<bitcoin::secp256k1::PublicKey>)> = None;
    for u in updates {
        if u.operator_id != operator || u.sequence_number > fork_point {
            continue;
        }
        if let Ok(LedgerOperation::QuorumBegin { quorum_members, .. }) =
            LedgerOperation::tlv_decode(&u.message)
        {
            if best.as_ref().is_none_or(|(s, _)| u.sequence_number > *s) {
                best = Some((
                    u.sequence_number,
                    quorum_members.iter().map(|m| m.pubkey).collect(),
                ));
            }
        }
    }
    let (_, members) = best?;
    let mut voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = members
        .iter()
        .filter(|pk| **pk != operator)
        .map(|pk| pk.x_only_public_key().0)
        .collect();
    voters.sort_by_key(|k| k.serialize());
    voters.dedup();
    let t = voters.len() / 2 + 1;
    Some((voters, t))
}

/// Every DEP-20 output a rotation at `height` pays after the new vault: the due exits (each
/// less its own cost), then the dormancy spin-outs (full balance). (extras, exits' own cost,
/// spin-outs' cost paid from collateral).
pub fn settlement_outputs(
    state: &crate::types::LedgerState,
    height: u32,
    cutoff: Option<u32>,
) -> (Vec<(ScriptBuf, u64)>, u64, u64) {
    let mut extras = due_exit_outputs(state, height, cutoff);
    let exits_cost = due_exits_cost(state, height, cutoff);
    let c = cutoff.unwrap_or(height.saturating_sub(crate::types::EXIT_CUTOFF_MARGIN_BLOCKS));
    let spins = state.dormancy_spin_outs(c);
    let mut dorm_cost = spins.len() as u64 * state.dormancy_cost();
    extras.extend(spins.into_iter().map(|(_, bal, spk)| (spk, bal / 1000)));
    // DEP-20 §8.3: the migration output, after the spin-outs; its own cost is a fee like theirs.
    if let Some((_, spk, sats)) = state.dormancy_migration(c) {
        dorm_cost += state.exit_cost(&spk);
        extras.push((ScriptBuf::from_bytes(spk), sats));
    }
    (extras, exits_cost, dorm_cost)
}

/// DEP-20 §8.3: the premium (sats) the migration output carries; collateral pays it (not a fee).
pub fn migration_premium_sats(state: &crate::types::LedgerState, cutoff: u32) -> u64 {
    match (state.dormancy_migration(cutoff), &state.migration) {
        (Some(_), Some(m)) => m.premium / 1000,
        _ => 0,
    }
}

/// DEP-20 §8.3: the QuorumBegin's migration fields at `cutoff` after `nexits` exits and
/// `nspins` spin-outs: (migration_manifest, migration_receiver, migration_vout).
pub fn migration_entries(
    state: &crate::types::LedgerState,
    cutoff: u32,
    nexits: usize,
    nspins: usize,
) -> (
    Vec<crate::messages::ManifestEntry>,
    Option<bitcoin::secp256k1::PublicKey>,
    Option<u32>,
) {
    match state.dormancy_migration(cutoff) {
        Some((entries, _, _)) => (
            entries,
            state.migration.as_ref().map(|m| m.receiver),
            Some((nexits + nspins + 1) as u32),
        ),
        None => (Vec::new(), None, None),
    }
}

/// The QuorumBegin `dormancy_outputs` entries after `nexits` exit outputs.
pub fn dormancy_entries(
    state: &crate::types::LedgerState,
    cutoff: u32,
    nexits: usize,
) -> Vec<crate::messages::ExitOutput> {
    state
        .dormancy_spin_outs(cutoff)
        .into_iter()
        .enumerate()
        .map(|(j, (id, bal, _))| crate::messages::ExitOutput {
            deposit_id: id,
            amount: bal,
            vout: (nexits + j + 1) as u32,
        })
        .collect()
}

/// DEP-03 Reference feerate bounds for median m: [max(1, m/2), max(2, 2m)].
pub fn feerate_bounds(m: u64) -> (u64, u64) {
    ((m / 2).max(1), (2 * m).max(2))
}
