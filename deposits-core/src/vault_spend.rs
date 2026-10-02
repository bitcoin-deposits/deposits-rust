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

/// Transaction ids a spend of this ledger's vault may legitimately have: every
/// recorded `QuorumBegin`'s rotation transaction and new outpoint.
pub fn authorised_spend_txids(history: &[SignedLedgerUpdate]) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    for u in history {
        if let Ok(LedgerOperation::QuorumBegin {
            spending_txid,
            new_outpoint_txid,
            ..
        }) = LedgerOperation::tlv_decode(&u.message)
        {
            out.push(spending_txid);
            out.push(new_outpoint_txid);
        }
    }
    out
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
        Some(LedgerOperation::QuorumBegin {
            new_outpoint_txid,
            new_outpoint_vout,
            quorum_expiry,
            ledger_hash,
            quorum_members,
            protocol_version,
            ..
        }),
    ) = (operator, qb)
    else {
        return Err("no such QuorumBegin on the spent ledger".into());
    };
    let rs = ruleset::lookup(protocol_version.as_deref().unwrap_or(DEFAULT_RULESET))
        .ok_or("unknown ruleset")?;
    let voters = VoterSet::new(operator, quorum_members.iter().map(|m| m.pubkey).collect());
    let config = (rs.tier_config_factory)(voters.total_count(), quorum_expiry);
    let builder =
        TapscriptReservesBuilder::new(voters, config.clone(), Network::Bitcoin, ledger_hash);
    let output = builder.build().map_err(|e| e.to_string())?;

    // The input spending the vault, and its witness [sig_{n-1}..sig_0, leaf, control].
    let idx = tx
        .input
        .iter()
        .position(|i| {
            i.previous_output.txid.to_byte_array() == new_outpoint_txid
                && i.previous_output.vout == new_outpoint_vout
        })
        .ok_or("the spend does not spend the vault outpoint")?;
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
    Ok(signers)
}

/// Valid when the accused signed (to the tier's threshold) a spend of the
/// vault outpoint the governing `QuorumBegin` names, and the spend is none of
/// `spent_history`'s recorded rotations nor any of `extra_authorised`
/// (confiscations the verifier knows). The block's presence in the verifier's
/// chain is checked by `verify_fraud_evidence`.
pub fn verify_unauthorized_vault_spend(
    proof: &FraudProof,
    spent_history: &[SignedLedgerUpdate],
    extra_authorised: &[[u8; 32]],
) -> Result<(), String> {
    let FraudEvidence::UnauthorizedVaultSpend {
        governing_quorumbegin_seq,
        spend_tx_hex,
        prevouts,
        ..
    } = &proof.evidence
    else {
        return Err("verify_unauthorized_vault_spend: wrong evidence type".into());
    };

    let tx: Transaction = deserialize(&hex::decode(spend_tx_hex).map_err(|e| e.to_string())?)
        .map_err(|e| format!("spend tx: {}", e))?;
    let txid = tx.compute_txid().to_byte_array();
    let prevouts = parse_prevouts(prevouts)?;
    if authorised_spend_txids(spent_history)
        .iter()
        .chain(extra_authorised)
        .any(|t| *t == txid)
    {
        return Err("the spend is a recorded rotation or confiscation".into());
    }

    let signers = vault_spend_signers(spent_history, *governing_quorumbegin_seq, &tx, &prevouts)?;
    let accused = hex::decode(&proof.accused).map_err(|e| format!("accused hex: {}", e))?;
    let accused = bitcoin::secp256k1::PublicKey::from_slice(&accused)
        .map_err(|e| format!("accused pubkey: {}", e))?
        .x_only_public_key()
        .0;
    if !signers.contains(&accused) {
        return Err("the accused is not among the verified signers".into());
    }
    Ok(())
}
