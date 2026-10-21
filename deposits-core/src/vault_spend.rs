//! Unauthorised vault spend (DEP-06, `FraudProofType::UnauthorizedVaultSpend`).
//!
//! The protocol-layer dispatch settles the chain facts (the spent ledger is
//! known, the spend's block is in our chain); this module does the rest from
//! the spent ledger's own history: rebuild the reserves tapscript tree from its
//! `LedgerOpen` operator and the `QuorumBegin` at the governing sequence, find
//! the witness on the vault input, and verify the Schnorr signatures over the
//! BIP-341 script-path sighash. Mirrors cl-deposits'
//! `verify-unauthorized-vault-spend`.

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::{Amount, Network, ScriptBuf, Transaction, TxOut};
use deposits_protocol::fraud::{FraudEvidence, FraudProof};
use deposits_protocol::messages::LedgerOperation;
use deposits_protocol::tlv::TlvDecode;
use deposits_protocol::types::SignedLedgerUpdate;

use crate::ruleset;
use crate::tapscript_reserves::{TapscriptReservesBuilder, VoterSet};

/// The ruleset a `QuorumBegin` without a `protocol_version` was written under
/// is `legacy` in the reference; cl-deposits defaults to `cltv-offset-v2`
/// there. Both implementations write the field, so the default is unreachable
/// in practice.
const DEFAULT_RULESET: &str = "cltv-offset-v2";

/// DEP-03 §Fee ladder: the txids of a `QuorumBegin`'s rungs, rung 0 first; one without
/// `rotation_rungs` names one, its `new_outpoint_txid`.
pub fn quorum_begin_rungs(op: &LedgerOperation) -> Vec<[u8; 32]> {
    match op {
        LedgerOperation::QuorumBegin {
            rotation_rungs,
            new_outpoint_txid,
            ..
        } => {
            if rotation_rungs.is_empty() {
                vec![*new_outpoint_txid]
            } else {
                rotation_rungs.clone()
            }
        }
        _ => Vec::new(),
    }
}

/// Every txid a recorded `QuorumBegin` of `history` names: its rungs (DEP-03 §Fee ladder) and
/// its `spending_txid`. Not an authorisation by itself (DEP-06 §Spend challenge judges spends by
/// their anchor); kept for watchers that only need to know a txid is one of the ledger's own.
pub fn authorised_spend_txids(history: &[SignedLedgerUpdate]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for u in history {
        if let Ok(op @ LedgerOperation::QuorumBegin { spending_txid, .. }) =
            LedgerOperation::tlv_decode(&u.message)
        {
            out.push(spending_txid);
            out.extend(quorum_begin_rungs(&op));
        }
    }
    out
}

/// The `LedgerOpen` operator of a ledger's history (sequence 0).
fn ledger_operator(updates: &[SignedLedgerUpdate]) -> Option<bitcoin::secp256k1::PublicKey> {
    updates.iter().find_map(|u| {
        if u.sequence_number != 0 {
            return None;
        }
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen { .. }) => Some(u.operator_id),
            _ => None,
        }
    })
}

/// DEP-06 §Spend challenge: the update among `updates` that answers an anchored spend `txid` of
/// the vault the `QuorumBegin` at `governing_seq` of `spent_history` created, as a rotation: a
/// `QuorumBegin` whose `previous_hash` is `anchor`, signed by the ledger's operator, whose rungs
/// include `txid`, carrying valid cosignatures over it from at least the threshold of tier
/// `tier_index` (the tier the spend's witness uses) by keys of that tier (none needed at the
/// operator's solo tier). `updates` is whatever the judge holds of the ledger, any order, any
/// fork. Mirrors cl-deposits' `rotation-answer`; vector `tests/vectors/vault_spend_anchor.txt`.
pub fn rotation_answer<'a>(
    updates: &'a [SignedLedgerUpdate],
    spent_history: &[SignedLedgerUpdate],
    governing_seq: u64,
    anchor: &[u8; 32],
    txid: &[u8; 32],
    tier_index: usize,
) -> Option<&'a SignedLedgerUpdate> {
    let (builder, config, operator) = governing_reserves(spent_history, governing_seq).ok()?;
    let tier = config.tiers.get(tier_index)?;
    let keys = leaf_keys(&builder.build_threshold_leaf(tier).ok()?);
    let needed = if tier.threshold == 1 && tier.requires_tie_breaker {
        0
    } else {
        tier.threshold
    };
    let secp = Secp256k1::verification_only();
    updates.iter().find(|u| {
        let Ok(op) = LedgerOperation::tlv_decode(&u.message) else {
            return false;
        };
        if !matches!(op, LedgerOperation::QuorumBegin { .. })
            || u.previous_hash != *anchor
            || u.operator_id != operator
            || !quorum_begin_rungs(&op).contains(txid)
            || u.verify_operator_signature().is_err()
        {
            return false;
        }
        let mut seen = std::collections::HashSet::new();
        let good = u
            .cosignatures
            .iter()
            .filter(|c| seen.insert(c.cosigner_pubkey.serialize()))
            .filter(|c| keys.contains(&c.cosigner_pubkey.x_only_public_key().0))
            .filter(|c| {
                Signature::from_slice(&c.cosign_signature)
                    .map(|s| {
                        secp.verify_schnorr(
                            &s,
                            &Message::from_digest(u.cosign_digest(&c.member_ledger_hash)),
                            &c.cosigner_pubkey.x_only_public_key().0,
                        )
                        .is_ok()
                    })
                    .unwrap_or(false)
            })
            .count();
        good >= needed
    })
}

/// The reserves the `QuorumBegin` at `seq` built, from the ledger's operator: (builder, tier
/// config, operator).
fn governing_reserves(
    history: &[SignedLedgerUpdate],
    seq: u64,
) -> Result<
    (
        TapscriptReservesBuilder,
        crate::tapscript_reserves::ThresholdConfig,
        bitcoin::secp256k1::PublicKey,
    ),
    String,
> {
    let operator = ledger_operator(history).ok_or("no LedgerOpen on the spent ledger")?;
    let qb = history
        .iter()
        .filter(|u| u.sequence_number == seq)
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(op @ LedgerOperation::QuorumBegin { .. }) => Some(op),
            _ => None,
        })
        .ok_or("no such QuorumBegin on the spent ledger")?;
    let LedgerOperation::QuorumBegin {
        quorum_expiry,
        ledger_hash,
        quorum_members,
        protocol_version,
        ..
    } = qb
    else {
        unreachable!()
    };
    let rs = ruleset::lookup(protocol_version.as_deref().unwrap_or(DEFAULT_RULESET))
        .ok_or("unknown ruleset")?;
    let voters = VoterSet::new(operator, quorum_members.iter().map(|m| m.pubkey).collect());
    let config = (rs.tier_config_factory)(voters.total_count(), quorum_expiry);
    let builder =
        TapscriptReservesBuilder::new(voters, config.clone(), Network::Bitcoin, ledger_hash);
    Ok((builder, config, operator))
}

fn parse_prevouts(strings: &[String]) -> Result<Vec<TxOut>, String> {
    strings
        .iter()
        .map(|s| {
            let (sats, spk) = s.split_once(':').ok_or("prevout is not sats:spkhex")?;
            Ok(TxOut {
                value: Amount::from_sat(sats.parse().map_err(|_| "prevout sats")?),
                script_pubkey: ScriptBuf::from_bytes(
                    hex::decode(spk).map_err(|e| format!("prevout spk: {}", e))?,
                ),
            })
        })
        .collect()
}

/// The 32-byte keys a tier leaf pushes, in script order.
fn leaf_keys(leaf: &ScriptBuf) -> Vec<XOnlyPublicKey> {
    leaf.instructions()
        .filter_map(|i| match i {
            Ok(bitcoin::script::Instruction::PushBytes(b)) if b.len() == 32 => {
                XOnlyPublicKey::from_slice(b.as_bytes()).ok()
            }
            _ => None,
        })
        .collect()
}

/// The keys whose Schnorr signatures on the tier witness of the input that
/// spends the governing `QuorumBegin`'s vault outpoint verify, provided they
/// reach the tier's threshold. `Err` when the transaction does not spend that
/// vault or carries no verifying tier witness (a rotation's sweep of it by
/// someone who merely holds the outpoint, for example).
pub fn vault_spend_signers(
    spent_history: &[SignedLedgerUpdate],
    governing_quorumbegin_seq: u64,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Result<Vec<XOnlyPublicKey>, String> {
    tier_signers_at(spent_history, governing_quorumbegin_seq, tx, prevouts, None).map(|(s, _)| s)
}

/// As [`vault_spend_signers`], with the tier index the witness uses.
pub fn vault_spend_witness(
    spent_history: &[SignedLedgerUpdate],
    governing_quorumbegin_seq: u64,
    tx: &Transaction,
    prevouts: &[TxOut],
) -> Result<(Vec<XOnlyPublicKey>, usize), String> {
    tier_signers_at(spent_history, governing_quorumbegin_seq, tx, prevouts, None)
}

/// As [`vault_spend_signers`], for input `idx` (or, with `None`, the input spending the vault:
/// output 0 of any rung, DEP-03 §Fee ladder): DEP-20 §8.3 a migration output at the vault's
/// script is spent through a tier too. (signers, tier index).
pub fn tier_signers_at(
    spent_history: &[SignedLedgerUpdate],
    governing_quorumbegin_seq: u64,
    tx: &Transaction,
    prevouts: &[TxOut],
    input: Option<usize>,
) -> Result<(Vec<XOnlyPublicKey>, usize), String> {
    if prevouts.len() != tx.input.len() {
        return Err("prevouts do not match the inputs".into());
    }
    // Reserves from the LedgerOpen operator and the governing QuorumBegin.
    let mut ordered: Vec<&SignedLedgerUpdate> = spent_history.iter().collect();
    ordered.sort_by_key(|u| u.sequence_number);
    let mut operator = None;
    let mut qb = None;
    for u in ordered {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::LedgerOpen { operator_id, .. }) => operator = Some(operator_id),
            Ok(op @ LedgerOperation::QuorumBegin { .. })
                if u.sequence_number == governing_quorumbegin_seq =>
            {
                qb = Some(op)
            }
            _ => {}
        }
    }
    let (
        Some(operator),
        Some(
            qb @ LedgerOperation::QuorumBegin {
                new_outpoint_vout,
                quorum_expiry,
                ledger_hash,
                ..
            },
        ),
    ) = (operator, qb)
    else {
        return Err("no such QuorumBegin on the spent ledger".into());
    };
    let rungs = quorum_begin_rungs(&qb);
    let LedgerOperation::QuorumBegin {
        quorum_members,
        protocol_version,
        ..
    } = qb
    else {
        unreachable!()
    };
    let rs = ruleset::lookup(protocol_version.as_deref().unwrap_or(DEFAULT_RULESET))
        .ok_or("unknown ruleset")?;
    let voters = VoterSet::new(operator, quorum_members.iter().map(|m| m.pubkey).collect());
    let config = (rs.tier_config_factory)(voters.total_count(), quorum_expiry);
    let builder =
        TapscriptReservesBuilder::new(voters, config.clone(), Network::Bitcoin, ledger_hash);
    let output = builder.build().map_err(|e| e.to_string())?;

    // The input spending the vault, and its witness [sig_{n-1}..sig_0, leaf, control].
    let idx = match input {
        Some(i) if i < tx.input.len() => i,
        Some(_) => return Err("no such input".into()),
        None => tx
            .input
            .iter()
            .position(|i| {
                rungs.contains(&i.previous_output.txid.to_byte_array())
                    && i.previous_output.vout == new_outpoint_vout
            })
            .ok_or("the spend does not spend the vault outpoint")?,
    };
    let stack: Vec<&[u8]> = tx.input[idx].witness.iter().collect();
    let n = stack.len();
    if n < 3 {
        return Err("no tier witness on the vault input".into());
    }
    let (leaf_bytes, control_bytes) = (stack[n - 2], stack[n - 1]);
    let leaf = ScriptBuf::from_bytes(leaf_bytes.to_vec());
    let mut tier = None;
    for (i, t) in config.tiers.iter().enumerate() {
        let script = builder.build_threshold_leaf(t).map_err(|e| e.to_string())?;
        if script == leaf {
            tier = Some((i, t));
            break;
        }
    }
    let (tier_index, tier) = tier.ok_or("the witness leaf is no tier of the reserves")?;
    let control = output
        .control_block_for_tier(tier_index)
        .ok_or("no control block for the tier")?;
    if control.serialize() != control_bytes {
        return Err("the witness control block is not the reserves'".into());
    }

    let sighash = SighashCache::new(tx)
        .taproot_script_spend_signature_hash(
            idx,
            &Prevouts::All(prevouts),
            TapLeafHash::from_script(&leaf, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .map_err(|e| format!("sighash: {:?}", e))?;
    let msg = Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::verification_only();
    let keys = leaf_keys(&leaf);
    let sigs = stack[..n - 2].iter().rev();
    let signers: Vec<XOnlyPublicKey> = keys
        .iter()
        .zip(sigs)
        .filter(|(k, sig)| {
            sig.len() == 64
                && Signature::from_slice(sig)
                    .map(|s| secp.verify_schnorr(&s, &msg, k).is_ok())
                    .unwrap_or(false)
        })
        .map(|(k, _)| *k)
        .collect();
    if signers.len() < tier.threshold {
        return Err("no tier witness on the vault input verifies".into());
    }
    Ok((signers, tier_index))
}

/// DEP-06 §Spend challenge: the spent ledger's service window `w` at the governing `QuorumBegin`
/// (the largest `service_response_blocks` a seated member declared, 72 if none).
pub fn spend_window(spent_history: &[SignedLedgerUpdate], governing_seq: u64) -> u32 {
    let mut sorted: Vec<SignedLedgerUpdate> = spent_history.to_vec();
    sorted.sort_by_key(|u| u.sequence_number);
    deposits_protocol::fraud::governing_service_response_blocks(&sorted, governing_seq)
}

/// DEP-06 `UnauthorizedVaultSpend`. The accused must have signed (to the tier's threshold) a spend
/// of the vault (output 0 of a rung of the governing `QuorumBegin`) confirmed in a block
/// `height_of_block` knows. Unanchored form: the spend carries no anchor. Lapsed form: its anchor
/// `H` was challenged by `challenge_update` (a signed `QuorumChallenge` of this spend and anchor)
/// and `lapse_block_hash` is a block at least `w` past the later of the challenge's signed height
/// and the spend's. `answered(txid, anchor, tier_index)` is true when the verifier knows an answer
/// (a rotation or an authorised confiscation); a known answer rebuts the lapsed form. Mirrors
/// cl-deposits' `verify-unauthorized-vault-spend`; vector `tests/vectors/vault_spend_anchor.txt`.
pub fn verify_unauthorized_vault_spend(
    proof: &FraudProof,
    spent_history: &[SignedLedgerUpdate],
    height_of_block: &dyn Fn(&[u8; 32]) -> Option<u32>,
    answered: &dyn Fn(&[u8; 32], &[u8; 32], usize) -> bool,
) -> Result<(), String> {
    let FraudEvidence::UnauthorizedVaultSpend {
        spent_ledger_id,
        governing_quorumbegin_seq,
        spend_tx_hex,
        spend_block_hash,
        prevouts,
        challenge_update,
        lapse_block_hash,
    } = &proof.evidence
    else {
        return Err("verify_unauthorized_vault_spend: wrong evidence type".into());
    };

    let tx: Transaction = deserialize(&hex::decode(spend_tx_hex).map_err(|e| e.to_string())?)
        .map_err(|e| format!("spend tx: {}", e))?;
    let txid = tx.compute_txid().to_byte_array();
    let prevouts = parse_prevouts(prevouts)?;
    let spend_height = height_of_block(spend_block_hash).ok_or("spend block not in our chain")?;
    let (signers, tier_index) =
        vault_spend_witness(spent_history, *governing_quorumbegin_seq, &tx, &prevouts)?;
    let accused = hex::decode(&proof.accused).map_err(|e| format!("accused hex: {}", e))?;
    let accused = bitcoin::secp256k1::PublicKey::from_slice(&accused)
        .map_err(|e| format!("accused pubkey: {}", e))?
        .x_only_public_key()
        .0;
    if !signers.contains(&accused) {
        return Err("the accused is not among the verified signers".into());
    }
    let Some(anchor) = crate::tapscript_reserves::anchor_of(&tx) else {
        return match challenge_update {
            Some(_) => Err("an unanchored spend needs no challenge".into()),
            None => Ok(()),
        };
    };
    let Some(cu) = challenge_update else {
        return Err("an anchored spend is proven only by a lapsed challenge".into());
    };
    let cu = <SignedLedgerUpdate as deposits_protocol::tlv::TlvDecode>::tlv_decode(
        &hex::decode(cu).map_err(|e| format!("challenge hex: {}", e))?,
    )
    .map_err(|e| format!("challenge update: {:?}", e))?;
    if cu.verify_operator_signature().is_err() {
        return Err("the challenge is not a signed QuorumChallenge".into());
    }
    let Ok(LedgerOperation::QuorumChallenge {
        challenged_ledger_id,
        challenged_txid,
        challenged_anchor,
    }) = LedgerOperation::tlv_decode(&cu.message)
    else {
        return Err("the challenge is not a signed QuorumChallenge".into());
    };
    if hex::encode(challenged_ledger_id) != *spent_ledger_id
        || challenged_txid != txid
        || challenged_anchor != anchor
    {
        return Err("the challenge names another spend".into());
    }
    let lapse = lapse_block_hash
        .as_ref()
        .and_then(height_of_block)
        .ok_or("the lapse block is not in our chain")?;
    let w = spend_window(spent_history, *governing_quorumbegin_seq);
    if lapse < cu.block_height.max(spend_height) + w {
        return Err(format!(
            "the challenge's window ({} blocks) has not lapsed",
            w
        ));
    }
    if answered(&txid, &anchor, tier_index) {
        return Err("the spend is answered".into());
    }
    Ok(())
}
