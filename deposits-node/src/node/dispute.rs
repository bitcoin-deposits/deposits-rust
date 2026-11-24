use super::*;

/// Compute the expected outputs of a confiscation transaction.
///
/// Used by the operator (`initiate_confiscations`) to build the tx and by
/// cosigners (`process_confiscation_sign_request`) to verify the operator's
/// proposed tx before signing. Both sides feeding the same inputs into this
/// function and comparing the result is what makes the bifurcation
/// cryptographically enforceable — a malicious operator can't get cosigners
/// to sign a tx that this function wouldn't have produced.
///
/// Outputs:
/// - **Punitive** proof OR dust-fallback: 1 output, full UTXO minus fee
///   to the lottery script.
/// - **Respectful** proof with sufficient funds: 2 outputs — lottery for
///   `max(obligations, P2WSH_DUST_LIMIT_SATS)`, original-operator P2WPKH
///   for the rest minus fee. (Lottery winner inherits obligations; the
///   operator gets back the excess collateral they posted.)
///
/// The dust-fallback bridge: when `obligations + fee` would leave under
/// `P2WPKH_DUST_LIMIT_SATS` for the operator, we collapse to a single
/// lottery output rather than emit unspendable change.
/// A tier-leaf witness: [sig_{n-1} .. sig_0 (empty where absent), leaf, control block].
/// DEP-03 §Confiscation ladder: the rung a holder broadcasts while none has confirmed,
/// `min(n − 1, ⌊(tip − h_c) / 6⌋)`.
pub(crate) fn ladder_rung_due(n: usize, h_c: u32, height: u32) -> usize {
    if n == 0 || height <= h_c {
        return 0;
    }
    (((height - h_c) / 6) as usize).min(n - 1)
}

/// A `confiscation_sign` answer's signatures, per rung and per input, each verified against
/// `rung_sighashes`: the longest prefix of rungs it signed in full. A signer that predates the
/// ladder answers rung 0 alone (`signature`, `sweep_signatures`). `None` if not even rung 0.
pub(crate) fn confiscation_response_signatures(
    result: &serde_json::Value,
    rung_sighashes: &[Vec<[u8; 32]>],
) -> Option<(bitcoin::secp256k1::PublicKey, Vec<Vec<[u8; 64]>>)> {
    use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1};
    let signer: bitcoin::secp256k1::PublicKey = result.get("signer")?.as_str()?.parse().ok()?;
    let sig64 = |v: &serde_json::Value| -> Option<[u8; 64]> {
        hex::decode(v.as_str()?).ok()?.try_into().ok()
    };
    let list = |v: Option<&serde_json::Value>| -> Vec<[u8; 64]> {
        v.and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(sig64).collect())
            .unwrap_or_default()
    };
    let per_rung: Vec<Vec<[u8; 64]>> =
        match result.get("rung_signatures").and_then(|v| v.as_array()) {
            Some(r0s) => {
                let sweeps = result
                    .get("rung_sweep_signatures")
                    .and_then(|v| v.as_array());
                r0s.iter()
                    .enumerate()
                    .map_while(|(i, s)| {
                        let mut v = vec![sig64(s)?];
                        v.extend(list(sweeps.and_then(|a| a.get(i))));
                        Some(v)
                    })
                    .collect()
            }
            None => {
                let mut v = vec![sig64(result.get("signature")?)?];
                v.extend(list(result.get("sweep_signatures")));
                vec![v]
            }
        };
    let secp = Secp256k1::verification_only();
    let xonly = signer.x_only_public_key().0;
    let verified: Vec<Vec<[u8; 64]>> = per_rung
        .into_iter()
        .zip(rung_sighashes)
        .map_while(|(sigs, hashes)| {
            (sigs.len() == hashes.len()
                && sigs.iter().zip(hashes).all(|(s, h)| {
                    Signature::from_slice(s)
                        .ok()
                        .map(|sig| {
                            secp.verify_schnorr(&sig, &Message::from_digest(*h), &xonly)
                                .is_ok()
                        })
                        .unwrap_or(false)
                }))
            .then_some(sigs)
        })
        .collect();
    (!verified.is_empty()).then_some((signer, verified))
}

pub(crate) fn tier_witness(
    voter_set: &deposits_core::VoterSet,
    sigs: &std::collections::HashMap<bitcoin::secp256k1::PublicKey, [u8; 64]>,
    leaf_script: &bitcoin::ScriptBuf,
    control_block: &bitcoin::taproot::ControlBlock,
) -> bitcoin::Witness {
    let mut witness = bitcoin::Witness::new();
    for x_only in voter_set.sorted_x_only_pubkeys().iter().rev() {
        match voter_set
            .all_voters()
            .into_iter()
            .find(|v| v.x_only_public_key().0 == *x_only)
            .and_then(|v| sigs.get(&v))
        {
            Some(sig) => witness.push(sig),
            None => witness.push([] as [u8; 0]),
        }
    }
    witness.push(leaf_script.as_bytes());
    witness.push(control_block.serialize());
    witness
}

pub fn build_expected_confiscation_outputs(
    lottery_script: bitcoin::ScriptBuf,
    original_operator: bitcoin::secp256k1::PublicKey,
    network: bitcoin::Network,
    reserves_amount: u64,
    fee: u64,
    is_respectful: bool,
    obligations_sats: u64,
) -> Result<Vec<bitcoin::TxOut>, String> {
    use bitcoin::{Amount, TxOut};
    use deposits_core::constants::{P2WPKH_DUST_LIMIT_SATS, P2WSH_DUST_LIMIT_SATS};

    let punitive_value = reserves_amount.saturating_sub(fee);

    if !is_respectful {
        return Ok(vec![TxOut {
            value: Amount::from_sat(punitive_value),
            script_pubkey: lottery_script,
        }]);
    }

    let lottery_value = obligations_sats.max(P2WSH_DUST_LIMIT_SATS);
    let operator_change = reserves_amount
        .saturating_sub(lottery_value)
        .saturating_sub(fee);

    if operator_change < P2WPKH_DUST_LIMIT_SATS {
        // Bifurcation would emit dust to the operator; collapse to
        // single-output punitive shape.
        return Ok(vec![TxOut {
            value: Amount::from_sat(punitive_value),
            script_pubkey: lottery_script,
        }]);
    }

    let pubkey_bytes: [u8; 33] = original_operator.serialize();
    let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| format!("original_operator pubkey doesn't compress: {}", e))?;
    let operator_addr = bitcoin::Address::p2wpkh(&compressed, network);

    Ok(vec![
        TxOut {
            value: Amount::from_sat(lottery_value),
            script_pubkey: lottery_script,
        },
        TxOut {
            value: Amount::from_sat(operator_change),
            script_pubkey: operator_addr.script_pubkey(),
        },
    ])
}

/// Derive the canonical lottery `recovery_voters` set (and its threshold)
/// from a ledger's update history.
///
/// The confiscation TX that `initiate_confiscations` broadcasts pays a
/// Taproot lottery output whose address is a function of BOTH the
/// DisputeArmed participants AND the recovery-voter set (the recovery
/// and attestation leaves are committed into the tree — see
/// `LotteryScriptBuilder::build`). If any later step reconstructs that
/// address with a *different* recovery-voter set, `find_utxo_for_script`
/// returns `None` and the reveal→claim→DisputeAcquire chain silently
/// stalls (funds are safe on-chain, but the ledger is never continued).
///
/// The canonical set is exactly the members of the ledger's **latest
/// `QuorumBegin`** (highest sequence), minus the original operator. That
/// is the set `initiate_confiscations` (line ~2154) and the cosigner-side
/// verifier / manual `recovery claim` (custody.rs ~1810) both use, so it
/// is the set the on-chain UTXO actually commits to. Deriving from
/// `QuorumAddMember` rows instead is wrong: forks rebroadcast the
/// operator's adds alongside their own dispute-time adds, so the set
/// drifts and the reconstructed address misses the real UTXO.
///
/// Returns `None` if no `QuorumBegin` or no `LedgerOpen` is observed.
pub(crate) fn recovery_voters_from_updates(
    updates: &[deposits_core::SignedLedgerUpdate],
) -> Option<(Vec<bitcoin::secp256k1::XOnlyPublicKey>, usize)> {
    deposits_core::rotation_order::lottery_recovery_voters(updates)
}

/// One line naming every input of a lottery address, so two members' views can be compared.
pub(crate) fn lottery_inputs_line(
    participants: &[deposits_core::tapscript_reserves::LotteryParticipant],
    voters: &[bitcoin::secp256k1::XOnlyPublicKey],
    threshold: usize,
) -> String {
    format!(
        "participants [{}] voters [{}] threshold {}",
        participants
            .iter()
            .map(|p| format!(
                "{}:{}:{}",
                &p.pubkey.to_string()[..12],
                &hex::encode(p.commitment_hash)[..12],
                p.target_reserves
            ))
            .collect::<Vec<_>>()
            .join(" "),
        voters
            .iter()
            .map(|v| v.to_string()[..12].to_string())
            .collect::<Vec<_>>()
            .join(" "),
        threshold
    )
}

/// DEP-03 §Grounded arms: whether an arm with no proof hash, no anchor and no
/// reason must wait for grounds it can cite. Not when we have ALREADY ENTERED
/// the dispute on our own fork: that `DisputeEnter` carried our grounds, and
/// only the arm is left. The gate there turned the background re-arm pass into
/// a no-op: ref6 (regtest, 2026-11-20T00:32:04Z) failed its arm on 9602cad2
/// when every quick collateral scan hit bitcoind's "Scan already in progress",
/// and then logged "no grounds we can cite yet; not joining" once a minute for
/// 19 minutes without ever scanning again, until a re-broadcast of the proof
/// happened to arrive.
pub(crate) fn grounds_gate_applies(
    ledger_grounds_arms: bool,
    has_reason: bool,
    already_entered: bool,
) -> bool {
    ledger_grounds_arms && !has_reason && !already_entered
}

/// What one of our forks of a ledger is, for choosing the fork a dispute uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnForkKind {
    /// Yielded or lost: over.
    Tombstoned,
    /// Disputed on a lapsed quorum (`quorum_expired`) and never armed.
    ExpiryUnarmed,
    /// A `quorum_expired` fork, armed or not, whose ground is answered: the base holds a
    /// `QuorumBegin` after its fork point (judged from the ledger's state, not the in-memory
    /// window), under strict-lottery-v8 one whose rotation spend confirmed
    /// ([`own_expiry_fork_kind`]). It stands down (`expiry_watch`), and no later dispute may use it: DEP-05 §"When a quorum_expired dispute
    /// ends", "A member MUST NOT let a live dispute on an earlier ground stand in for it" (signet
    /// soak, 2026-11-22: ref4's fork of 0aeebcc5 at 359090, re-established at 359228, absorbed
    /// the dispute of that quorum's own expiry at 12209: "Already have fork for ledger
    /// 0aeebcc5…: 0aeebcc51f7dc6142f8e7a804e96fbe4").
    ExpiryAnswered,
    /// Anything else live: a punitive dispute, or an armed one.
    Live,
}

/// The kind of our live fork on a `quorum_expired` `DisputeEnter` at `fork_last_valid_sequence`
/// (`armed` if it holds a `DisputeArmed`), against the base's latest `QuorumBegin`, under the
/// ruleset at the fork point. Vector `expiry_dispute_ends.json`, its `fork_reuse` cases.
pub(crate) fn own_expiry_fork_kind(
    ruleset_at_fork: &str,
    fork_last_valid_sequence: u64,
    armed: bool,
    base_latest_quorum_begin_sequence: Option<u64>,
    rotation_spend_confirmed: bool,
) -> OwnForkKind {
    let answered = base_latest_quorum_begin_sequence.is_some_and(|qb| {
        deposits_core::types::expiry_dispute_ended_under(
            ruleset_at_fork,
            fork_last_valid_sequence,
            qb,
            false,
            rotation_spend_confirmed,
        )
    });
    if answered {
        OwnForkKind::ExpiryAnswered
    } else if armed {
        OwnForkKind::Live
    } else {
        OwnForkKind::ExpiryUnarmed
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ForkChoice {
    /// Reuse this fork.
    Use(String),
    /// Fork afresh at the requested base; `bypassed` are un-armed expiry forks
    /// a punitive dispute must not be absorbed by.
    Create { bypassed: Vec<String> },
    /// The fork at this base is over.
    Refuse(String),
}

/// The fork a dispute at `exact` (`fork_tracking_key` of its base) uses, given
/// our forks of the ledger. The fork at its own base if live; else, as before,
/// any live fork of ours, EXCEPT that a punitive dispute is never absorbed by
/// an un-armed expiry fork: that fork's `DisputeEnter` (`quorum_expired`) is
/// not acting on the proof (DEP-19 §6 counts a non-expiry `DisputeEnter` or a
/// `DisputeArmed`), so reusing it signs nothing that answers the fraud.
/// Tombstoned forks are never reused.
pub(crate) fn fork_for_dispute(
    exact: &str,
    punitive: bool,
    ours: &[(String, OwnForkKind)],
) -> ForkChoice {
    if let Some((_, kind)) = ours.iter().find(|(k, _)| k == exact) {
        return match kind {
            OwnForkKind::Tombstoned => ForkChoice::Refuse(format!(
                "our fork {} at this base is over (yielded or lost)",
                &exact[..32.min(exact.len())]
            )),
            OwnForkKind::ExpiryUnarmed | OwnForkKind::ExpiryAnswered if punitive => ForkChoice::Refuse(format!(
                "our fork {} at this base is an un-armed expiry dispute; a punitive \
                 DisputeEnter cannot be appended to it",
                &exact[..32.min(exact.len())]
            )),
            _ => ForkChoice::Use(exact.to_string()),
        };
    }
    let mut bypassed = Vec::new();
    for (k, kind) in ours {
        match kind {
            OwnForkKind::Tombstoned => {}
            OwnForkKind::ExpiryUnarmed if punitive => bypassed.push(k.clone()),
            OwnForkKind::ExpiryAnswered => bypassed.push(k.clone()),
            _ => return ForkChoice::Use(k.clone()),
        }
    }
    ForkChoice::Create { bypassed }
}

impl Node {
    /// Our forks of `ledger_id` (excluding a base promoted to a resolved fork),
    /// each with its [`OwnForkKind`], live punitive ones first.
    pub(crate) fn our_fork_kinds(&self, ledger_id: &str) -> Vec<(String, OwnForkKind)> {
        let pk16 = hex::encode(self.node_id.serialize())[..16].to_string();
        let ledgers = self.handler.ledgers.lock().unwrap();
        let base = ledgers.get(ledger_id).cloned();
        let base_expiry = base
            .as_ref()
            .and_then(|b| b.read().unwrap().state.quorum_expiry);
        let base_qb = base.as_ref().and_then(|b| {
            let b = b.read().unwrap();
            super::expiry_watch::base_latest_quorum_begin_seq(b.state.quorum_begin_sequence, &b.history)
        });
        let mut out: Vec<(String, OwnForkKind)> = ledgers
            .iter()
            .filter(|(k, _)| {
                k.len() > ledger_id.len() && k.starts_with(ledger_id) && k.ends_with(&pk16)
            })
            .filter(|(_, a)| !base.as_ref().is_some_and(|b| Arc::ptr_eq(b, a)))
            .map(|(k, a)| {
                let l = a.read().unwrap();
                use deposits_core::types::DisputeState;
                let state = l.state.dispute_state;
                let expiry_lvs = matches!(state, DisputeState::Disputed | DisputeState::Armed)
                    .then(|| {
                        (super::expiry_watch::dispute_enter_is_expiry(&l.history, base_expiry)
                            == Some(true))
                        .then(|| super::expiry_watch::dispute_enter_last_valid(&l.history))
                        .flatten()
                    })
                    .flatten();
                let kind = match (state, expiry_lvs) {
                    (DisputeState::Tombstoned, _) => OwnForkKind::Tombstoned,
                    (_, Some(lvs)) => own_expiry_fork_kind(
                        &l.state.active_ruleset_name,
                        lvs,
                        state == DisputeState::Armed,
                        base_qb,
                        super::expiry_watch::REESTABLISHMENT_CONFIRMED
                            .get()
                            .is_some_and(|s| s.lock().unwrap().contains(k)),
                    ),
                    _ => OwnForkKind::Live,
                };
                (k.clone(), kind)
            })
            .collect();
        out.sort_by_key(|(k, kind)| (*kind != OwnForkKind::Live, k.clone()));
        out
    }
}

/// How long the re-arm pass waits on a ledger after `failures + 1` failed
/// arms in a row: one minute, doubling, at most 30 minutes.
pub(crate) fn rearm_backoff(failures: u32) -> std::time::Duration {
    std::time::Duration::from_secs((60u64 << failures.min(5)).min(30 * 60))
}

#[cfg(test)]
mod confiscation_outputs_tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, ScriptBuf};

    /// The unsigned confiscation, byte for byte, for cl-deposits to reproduce
    /// (tests/vectors/confiscation_tx.txt; REGEN_VECTORS=1 rewrites it). A
    /// 3-participant lottery (secrets [i;32], commitments [i;20], voters 21..23 at 2,
    /// signet), a vault of 8 voters, operator secret [9;32].
    #[test]
    fn confiscation_tx_vector_is_pinned() {
        use deposits_core::tapscript_reserves::{
            confiscation_fee_sats, LotteryParticipant, LotteryScriptBuilder,
            CONFISCATION_DEFAULT_FEERATE_SAT_VB,
        };
        let xonly = |i: u8| pk(i).x_only_public_key().0;
        let mut ps: Vec<LotteryParticipant> = (1..=3u8)
            .map(|i| LotteryParticipant::new(xonly(i), [i; 20], format!("tb1p{}", i)))
            .collect();
        ps.sort_by_key(|p| p.pubkey.serialize());
        let lottery = LotteryScriptBuilder::new(
            ps,
            vec![xonly(21), xonly(22), xonly(23)],
            2,
            Network::Signet,
        )
        .build()
        .unwrap();
        let fee = confiscation_fee_sats(8, CONFISCATION_DEFAULT_FEERATE_SAT_VB);
        let outpoint = bitcoin::OutPoint::new(
            bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::from_byte_array([0x11; 32])),
            1,
        );
        // DEP-03 §On-Chain State Anchor: the confiscation's last output.
        let anchor = [0xe5u8; 32];
        let mut lines = vec![
            format!("VEC fee={}", fee),
            format!("VEC anchor={}", hex::encode(anchor)),
        ];
        for (name, respectful, locktime) in [("punitive", false, 0u32), ("respectful", true, 1234)]
        {
            let mut outputs = build_expected_confiscation_outputs(
                lottery.script_pubkey(),
                pk(9),
                Network::Signet,
                50_000_000,
                fee,
                respectful,
                10_000_000,
            )
            .unwrap();
            outputs.push(bitcoin::TxOut {
                value: Amount::ZERO,
                script_pubkey: deposits_core::tapscript_reserves::anchor_script(&anchor),
            });
            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::from_consensus(locktime),
                input: vec![bitcoin::TxIn {
                    previous_output: outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::default(),
                }],
                output: outputs,
            };
            lines.push(format!(
                "VEC {}={}",
                name,
                hex::encode(bitcoin::consensus::encode::serialize(&tx))
            ));
        }
        let now = lines.join("\n") + "\n";
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/confiscation_tx.txt"
        );
        if std::env::var("REGEN_VECTORS").is_ok() {
            std::fs::write(path, &now).unwrap();
        }
        assert_eq!(
            now,
            std::fs::read_to_string(path).expect("vector (REGEN_VECTORS=1)")
        );
    }

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    fn lottery_script() -> ScriptBuf {
        // Any 34-byte witness-V1 script — the function doesn't introspect.
        let bytes = vec![0x51, 0x20] // OP_1 OP_PUSHBYTES_32
            .into_iter()
            .chain(std::iter::repeat_n(0xAB, 32))
            .collect::<Vec<u8>>();
        ScriptBuf::from(bytes)
    }

    #[test]
    fn punitive_emits_single_lottery_output() {
        let outs = build_expected_confiscation_outputs(
            lottery_script(),
            pk(1),
            Network::Regtest,
            10_000,
            400,
            false,
            0,
        )
        .unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].value, Amount::from_sat(9_600));
        assert_eq!(outs[0].script_pubkey, lottery_script());
    }

    #[test]
    fn respectful_with_zero_obligations_uses_dust_floor() {
        // No deposits → obligations = 0. Lottery output gets dust floor
        // (P2WSH_DUST_LIMIT_SATS = 330), operator gets the rest minus fee.
        let outs = build_expected_confiscation_outputs(
            lottery_script(),
            pk(1),
            Network::Regtest,
            10_000,
            400,
            true,
            0,
        )
        .unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].value, Amount::from_sat(330)); // P2WSH_DUST_LIMIT_SATS
        assert_eq!(outs[1].value, Amount::from_sat(10_000 - 330 - 400));
    }

    #[test]
    fn respectful_with_obligations_routes_obligations_to_lottery() {
        // 4000 sats of obligations → lottery gets 4000, operator gets the rest.
        let outs = build_expected_confiscation_outputs(
            lottery_script(),
            pk(1),
            Network::Regtest,
            10_000,
            400,
            true,
            4_000,
        )
        .unwrap();
        assert_eq!(outs.len(), 2);
        assert_eq!(outs[0].value, Amount::from_sat(4_000));
        assert_eq!(outs[1].value, Amount::from_sat(10_000 - 4_000 - 400));
    }

    #[test]
    fn respectful_falls_back_to_punitive_when_change_would_be_dust() {
        // Reserves barely covers obligations + fee → operator change would
        // be below P2WPKH_DUST_LIMIT_SATS = 294. Helper collapses to the
        // single punitive output rather than emit dust.
        let outs = build_expected_confiscation_outputs(
            lottery_script(),
            pk(1),
            Network::Regtest,
            5_000,
            400,
            true,
            4_500, // 5000 - 4500 - 400 = 100 < 294 → fallback
        )
        .unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].value, Amount::from_sat(4_600)); // 5000 - 400 fee
    }

    #[test]
    fn respectful_change_destination_is_p2wpkh_of_original_operator() {
        // The change output's script_pubkey must be the original operator's
        // P2WPKH. Reconstruct it independently and compare.
        let op = pk(7);
        let outs = build_expected_confiscation_outputs(
            lottery_script(),
            op,
            Network::Regtest,
            10_000,
            400,
            true,
            1_000,
        )
        .unwrap();
        assert_eq!(outs.len(), 2);
        let pubkey_bytes: [u8; 33] = op.serialize();
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes).unwrap();
        let expected_addr = bitcoin::Address::p2wpkh(&compressed, Network::Regtest);
        assert_eq!(outs[1].script_pubkey, expected_addr.script_pubkey());
    }
}

#[cfg(test)]
mod recovery_voter_derivation_tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
    use deposits_core::messages::{LedgerOperation, QuorumMemberRef};
    use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
    use deposits_core::{SignedLedgerUpdate, TlvEncode};

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    fn update(seq: u64, operator_id: PublicKey, op: LedgerOperation) -> SignedLedgerUpdate {
        SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: 0x8001,
            operator_id,
            ledger_id: [0u8; 32],
            sequence_number: seq,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        }
    }

    fn qb(members: &[PublicKey]) -> LedgerOperation {
        LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            splice_in_outpoint: None,
            splice_in_amount: None,
            reference_feerate: None,
            dormancy_outputs: Vec::new(),
            migration_manifest: Vec::new(),
            migration_receiver: None,
            migration_vout: None,
            consumed_notice: None,
            rotation_rungs: vec![],
            reserves_id: "bcrt1q...".to_string(),
            spending_txid: [0; 32],
            new_outpoint_txid: [0; 32],
            new_outpoint_vout: 0,
            amount: 1_000_000,
            quorum_expiry: 1_000_000,
            ledger_hash: [0; 32],
            quorum_members: members
                .iter()
                .copied()
                .map(QuorumMemberRef::pubkey_only)
                .collect(),
            collateral_amount: 0,
            protocol_version: Some("cltv-offset-v2".to_string()),
        }
    }

    /// The canonical recovery-voter set is the latest QuorumBegin's
    /// members minus the operator — NOT the union of QuorumAddMember rows
    /// (which include fork-time additions) and NOT the DisputeArmed set.
    #[test]
    fn recovery_voters_come_from_latest_quorum_begin_minus_operator() {
        let operator = pk(1);
        let m1 = pk(2);
        let m2 = pk(3);
        let m3 = pk(4);
        // A stray member added post-fork; must NOT leak into recovery set.
        let fork_added = pk(9);

        let updates = vec![
            update(
                0,
                operator,
                LedgerOperation::LedgerOpen {
                    operator_id: operator,
                    reserves_id: "bcrt1q...".to_string(),
                    genesis_block: 0,
                    reserves_amount: 100_000,
                    collateral_amount: 0,
                    protocol_version: None,
                },
            ),
            // Fork-time QuorumAddMember rows the old code would have folded in.
            update(
                6,
                m1,
                LedgerOperation::QuorumAddMember {
                    min_collateral_bps: None,
                    dormancy_blocks: None,
                    dormancy_notice_blocks: None,
                    quorum_member: fork_added,
                    quorum_member_signature: [0u8; 64],
                    member_ledger_id: "x".to_string(),
                    min_fee_bps: None,
                    min_fee_fixed: None,
                    max_fee_period: None,
                    membership_until: None,
                    dispute_response_blocks: None,
                    dispute_arm_blocks: None,
                    service_response_blocks: None,
                    max_transfer_timeout_blocks: None,
                    max_descriptor_bytes: None,
                    compensation_bps: None,
                    compensation_deposit_id: None,
                    compensation_frequency_blocks: None,
                    member_response: None,
                    member_signature: None,
                },
            ),
            // The canonical committed quorum (what the reserves UTXO used).
            update(4, operator, qb(&[operator, m1, m2, m3])),
        ];

        let (voters, threshold) =
            recovery_voters_from_updates(&updates).expect("QuorumBegin present");

        let mut got: Vec<XOnlyPublicKey> = voters.clone();
        got.sort_by_key(|k| k.serialize());
        let mut want: Vec<XOnlyPublicKey> = [m1, m2, m3]
            .iter()
            .map(|p| p.x_only_public_key().0)
            .collect();
        want.sort_by_key(|k| k.serialize());

        assert_eq!(
            got, want,
            "recovery voters must be QB members minus operator"
        );
        assert!(
            !voters.contains(&fork_added.x_only_public_key().0),
            "fork-time QuorumAddMember must not leak into recovery voters"
        );
        assert!(
            !voters.contains(&operator.x_only_public_key().0),
            "operator must be excluded from recovery voters"
        );
        assert_eq!(threshold, (3 / 2) + 1);
    }

    /// Regression for the confiscation-completion stall: the lottery
    /// address rebuilt with QuorumBegin-derived recovery voters (what the
    /// fix uses) matches the on-chain confiscation output, while the old
    /// stub (recovery voters = DisputeArmed participants) produced a
    /// DIFFERENT address that `find_utxo_for_script` never matched — so
    /// the claim silently failed and the ledger stayed disputed.
    #[test]
    fn quorum_begin_voters_match_confiscation_address_but_participant_stub_does_not() {
        let operator = pk(1);
        let m1 = pk(2);
        let m2 = pk(3);
        let m3 = pk(4);
        // Two disputants (a subset of the quorum).
        let d1 = pk(2);
        let d2 = pk(3);

        let participants = vec![
            LotteryParticipant::new(d1.x_only_public_key().0, [1u8; 20], "bcrt1qaaa".to_string()),
            LotteryParticipant::new(d2.x_only_public_key().0, [2u8; 20], "bcrt1qbbb".to_string()),
        ];
        let mut sorted = participants.clone();
        sorted.sort_by_key(|a| a.pubkey.serialize());

        // Canonical (on-chain) recovery voters = QB members minus operator.
        let canonical_voters: Vec<XOnlyPublicKey> = [m1, m2, m3]
            .iter()
            .map(|p| p.x_only_public_key().0)
            .collect();
        let canonical_threshold = (canonical_voters.len() / 2) + 1;
        let onchain_addr = LotteryScriptBuilder::new(
            sorted.clone(),
            canonical_voters.clone(),
            canonical_threshold,
            bitcoin::Network::Regtest,
        )
        .build()
        .unwrap()
        .address;

        // Fix path: derive voters from QuorumBegin → must reproduce address.
        let updates = vec![
            update(
                0,
                operator,
                LedgerOperation::LedgerOpen {
                    operator_id: operator,
                    reserves_id: "bcrt1q...".to_string(),
                    genesis_block: 0,
                    reserves_amount: 100_000,
                    collateral_amount: 0,
                    protocol_version: None,
                },
            ),
            update(4, operator, qb(&[operator, m1, m2, m3])),
        ];
        let (fix_voters, fix_threshold) =
            recovery_voters_from_updates(&updates).expect("QB present");
        let fix_addr = LotteryScriptBuilder::new(
            sorted.clone(),
            fix_voters,
            fix_threshold,
            bitcoin::Network::Regtest,
        )
        .build()
        .unwrap()
        .address;
        assert_eq!(
            fix_addr, onchain_addr,
            "QuorumBegin-derived voters must reproduce the on-chain lottery address"
        );

        // Old stub: recovery voters = DisputeArmed participants → wrong addr.
        let stub_voters: Vec<XOnlyPublicKey> = sorted.iter().map(|p| p.pubkey).collect();
        let stub_threshold = (stub_voters.len() / 2) + 1;
        let stub_addr = LotteryScriptBuilder::new(
            sorted.clone(),
            stub_voters,
            stub_threshold,
            bitcoin::Network::Regtest,
        )
        .build()
        .unwrap()
        .address;
        assert_ne!(
            stub_addr, onchain_addr,
            "the old participant-derived stub must NOT match the on-chain address \
             (this mismatch is the confiscation-completion stall)"
        );
    }
}

impl Node {
    /// Auto-arm for a dispute by creating a fork of the disputed ledger,
    /// then publishing DisputeEnter and DisputeArmed on the fork.
    ///
    /// This ensures the operator's own ledger stays in Normal state and is
    /// not affected by the dispute. The fork is stored under a compound
    /// tracking key and persisted as a separate JSONL file.
    pub(crate) async fn auto_arm_for_dispute(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
    ) -> Result<(), Error> {
        // Back-compat shim: callers that don't carry anchor evidence
        // (kind:9103 notification path, legacy invalid-update path)
        // produce a `DisputeEnter` without QuorumExpired evidence.
        // Receivers running the new verifier reject those; the legacy
        // kind:9103 receivers still rubber-stamp them (until the
        // receipt-verification commit lands).
        self.auto_arm_for_dispute_with_anchor(ledger_id, last_valid_seq, None)
            .await
    }

    /// Dispute on a verified fraud proof: the `DisputeEnter` cites its hash,
    /// disclosing it on the ledger and anchoring co-members' windows (DEP-19 §6).
    pub(crate) async fn auto_arm_for_dispute_on_proof(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
        proof_hash: [u8; 32],
        reason: &str,
    ) -> Result<(), Error> {
        self.arm_dispute(
            ledger_id,
            last_valid_seq,
            None,
            Some(proof_hash),
            Some(reason),
            &crate::chain_backend::ScanRetry::quick(),
        )
        .await
    }

    /// Dispute on a fault we found ourselves (an equivocation, a non-conforming cosigned
    /// update), labelled with its ground (DEP-05 §Deposed operator) rather than a generic
    /// reason a peer could not tell from an expiry dispute.
    pub(crate) async fn auto_arm_for_dispute_with_reason(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
        reason: &str,
    ) -> Result<(), Error> {
        self.arm_dispute(
            ledger_id,
            last_valid_seq,
            None,
            None,
            Some(reason),
            &crate::chain_backend::ScanRetry::quick(),
        )
        .await
    }

    /// Periodic: scan ledgers we cosign for, fire QuorumExpired
    /// auto-disputes on any whose `quorum_expiry` has been passed by
    /// the current chain tip.
    ///
    /// "We cosign for" = the ledger has an active quorum and our pubkey
    /// is in `state.quorum_members`. Operator-of-this-ledger ledgers are
    /// excluded (operators can't dispute their own ledger).
    ///
    /// Idempotent via the existing `custody_armed_<prefix>.marker` file:
    /// `auto_arm_for_dispute` writes that marker on success, and the
    /// fork-creation step short-circuits if the marker (or fork ledger)
    /// already exists.
    pub(crate) async fn auto_dispute_expired_quorums(&self) {
        // Live chain query, not the wallet's cached height. BDK's
        // background sync can lag far behind the live tip during
        // burst-mining; reading the cache would (a) gate the auto-task
        // on a stale view and (b) record a stale anchor on the fork-
        // branch DisputeEnter we publish. Both the grace-period guard
        // below and the persisted anchor must reflect the live chain.
        let (current_height, current_hash) = match self.wallet.fetch_block_info() {
            Ok(pair) => pair,
            Err(_) => return,
        };

        // Grace period (DEP-05 §Lifecycle): once `quorum_expiry` passes,
        // both re-establishment (operator-initiated) and confiscation
        // (cosigner-initiated) become available — but if cosigners
        // auto-dispute the instant expiry hits, the operator has zero
        // wall-clock window to attempt self-rescue. Hold off auto-
        // dispute until the Tier-1 boundary opens (`quorum_expiry +
        // 720`), giving the operator the post-expiry majority-
        // confiscation window to re-establish via `quorum repair`
        // before partner cosigners race to confiscate. Override via
        // `DEPOSITS_AUTO_DISPUTE_GRACE_BLOCKS` for test/dev.
        let grace_blocks = super::expiry_watch::auto_dispute_grace_blocks();

        // Snapshot: which ledgers are we a quorum member of that have
        // passed expiry by more than the grace period? Take a copy
        // under the lock so we can release before doing async work.
        let candidates: Vec<(String, u64, bitcoin::secp256k1::PublicKey)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut out = Vec::new();
            for (key, arc) in ledgers.iter() {
                // Skip fork compound keys (they end with `_NNNNNN_HEX16`),
                // and a replica replayed across a hole in its JSONL (its
                // quorum may be one a missing QuorumBegin replaced).
                if key.len() != 64 || self.handler.is_damaged(key) {
                    continue;
                }
                let l = arc.read().unwrap();
                let expiry = match l.state.quorum_expiry {
                    Some(e) => e,
                    None => continue,
                };
                let auto_dispute_block = expiry.saturating_add(grace_blocks);
                if current_height <= auto_dispute_block {
                    continue;
                }
                // Operator of own ledger doesn't auto-dispute.
                if l.operator_key() == self.node_id {
                    continue;
                }
                // Are we a quorum member?
                let in_quorum = l
                    .state
                    .quorum_members
                    .iter()
                    .any(|m| m.pubkey == self.node_id);
                if !in_quorum {
                    continue;
                }
                let tip_seq = l.state.sequence;
                out.push((key.clone(), tip_seq, l.state.parent_pubkey));
            }
            out
        };

        // Ledgers we already hold a dispute fork on: the fork is entered, and
        // finishing its arm is `auto_rearm_disputes`'s job. Re-running the arm
        // here every minute redid the expiry evidence and the collateral scan
        // for nothing on each expired ledger (signet soak, 2026-10-24).
        let our_pk16 = hex::encode(self.node_id.serialize())[..16].to_string();
        let disputed: std::collections::HashSet<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .keys()
                .filter(|k| k.len() > 64 && k.ends_with(&our_pk16))
                .map(|k| k[..64].to_string())
                .collect()
        };

        for (ledger_id, tip_seq, operator) in candidates {
            let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];
            if disputed.contains(&ledger_id) {
                tracing::debug!(
                    "Auto-dispute: ledger {} is past quorum_expiry and already disputed by us",
                    ledger_prefix
                );
                continue;
            }

            // Judge only a current replica. One that missed the operator's
            // QuorumBegin shows the old expiry and would accuse an operator
            // who rotated: ref3 held ledger C at 67859 while the relay carried
            // 101369 and C's quorum ran to 8888, and fired every minute. Queue
            // it for gap-fill instead; the replica lane catches it up.
            let relay_tip = self.relay_tip_seq(&ledger_id, &operator).await;
            if super::expiry_watch::replica_behind_relay(tip_seq, relay_tip) {
                tracing::info!(
                    "Ledger {} looks past quorum_expiry (current block {}) but our replica \
                     (seq {}) is behind the operator's on the relay ({:?}): not judging it",
                    ledger_prefix,
                    current_height,
                    tip_seq,
                    relay_tip
                );
                self.stale_joined_ledgers
                    .lock()
                    .unwrap()
                    .insert(ledger_id.clone());
                continue;
            }

            // Always invoke `auto_arm_for_dispute_with_anchor`; it is
            // idempotent (skips when a prior DisputeArmed already
            // declares replacement_collateral) and handles the re-arm
            // case (prior arm had None, now we have a funded UTXO).
            tracing::warn!(
                "Auto-dispute: ledger {} is past quorum_expiry (current block {}), firing fork-branch DisputeEnter",
                ledger_prefix,
                current_height
            );
            match self
                .auto_arm_for_dispute_with_anchor(
                    &ledger_id,
                    tip_seq,
                    Some((current_hash, current_height)),
                )
                .await
            {
                Ok(()) => tracing::info!("Auto-dispute fired for expired ledger {}", ledger_prefix),
                Err(e) => tracing::warn!("Auto-dispute for {} failed: {}", ledger_prefix, e),
            }
        }
    }

    /// Periodic: finish arming our dispute forks that are not armed with
    /// replacement collateral — Disputed with no `DisputeArmed` (the arm
    /// was refused for want of collateral, e.g. every scan retry lost to
    /// other members' scans on a shared bitcoind), or Armed by an older
    /// daemon with `replacement_collateral: None`.
    ///
    /// The arming triggers other than quorum expiry (equivocation, fraud
    /// proof, non-conforming cosig, a peer's DisputeEnter, a kind:9103
    /// notice) fire once, so without this such a fork stayed unarmed.
    /// The arm is idempotent: a fork already armed with collateral is left
    /// alone. The collateral lookup retries bitcoind's "Scan already in
    /// progress" with the full [`ScanRetry::default`] (up to ~1 min), so
    /// the main loop spawns this pass rather than awaiting it under the
    /// periodic 10 s timeout, and skips a cycle while one is running.
    ///
    /// [`ScanRetry::default`]: crate::chain_backend::ScanRetry
    pub(crate) async fn auto_rearm_disputes(&self) {
        use deposits_core::types::DisputeState;
        let our_pk16 = &hex::encode(self.node_id.serialize())[..16];
        let incomplete: Vec<(String, u64)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter(|(key, _)| key.len() > 64 && key.ends_with(our_pk16))
                .filter_map(|(key, arc)| {
                    let seq = super::fork_publish::fork_key_last_valid_seq(key)?;
                    let l = arc.read().unwrap();
                    if l.state.parent_pubkey != self.node_id {
                        return None;
                    }
                    let incomplete = match l.state.dispute_state {
                        DisputeState::Disputed => true,
                        DisputeState::Armed => matches!(
                            latest_dispute_armed(&l.history),
                            Some(deposits_core::messages::LedgerOperation::DisputeArmed {
                                replacement_collateral: None,
                                ..
                            })
                        ),
                        _ => false,
                    };
                    incomplete.then(|| (key[..64].to_string(), seq))
                })
                .collect()
        };
        // A failed arm (no collateral coin yet, most often) backs off per
        // ledger: 1, 2, 4 ... up to 30 minutes, cleared by a success.
        static BACKOFF: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, (std::time::Instant, u32)>>,
        > = std::sync::OnceLock::new();
        let backoff = BACKOFF.get_or_init(Default::default);
        for (ledger_id, last_valid_seq) in incomplete {
            if let Some((next, _)) = backoff.lock().unwrap().get(&ledger_id) {
                if std::time::Instant::now() < *next {
                    continue;
                }
            }
            // A base the replica has since pulled back would make a second
            // fork; leave that to the triggers that know the new base.
            if dispute_base(
                last_valid_seq,
                self.handler.first_non_conforming(&ledger_id),
            ) != last_valid_seq
            {
                continue;
            }
            match self
                .arm_dispute(
                    &ledger_id,
                    last_valid_seq,
                    None,
                    None,
                    None,
                    &crate::chain_backend::ScanRetry::default(),
                )
                .await
            {
                Ok(()) => {
                    backoff.lock().unwrap().remove(&ledger_id);
                    tracing::debug!("Re-arm pass on {}... done", &ledger_id[..16]);
                }
                Err(e) => {
                    let mut b = backoff.lock().unwrap();
                    // A shared bitcoind busy with another member's scan is
                    // contention, not a reason to back off for half an hour:
                    // retry it at the base interval, not a growing one.
                    let failures = if crate::chain_backend::is_scan_in_progress(&e) {
                        0
                    } else {
                        b.get(&ledger_id).map(|(_, f)| f + 1).unwrap_or(0)
                    };
                    let wait = rearm_backoff(failures);
                    b.insert(
                        ledger_id.clone(),
                        (std::time::Instant::now() + wait, failures),
                    );
                    tracing::warn!(
                        "Re-arm pass on {}...: {} (next try in {}s)",
                        &ledger_id[..16],
                        e,
                        wait.as_secs()
                    );
                }
            }
        }
    }

    /// Auto-arm carrying the QuorumExpired anchor evidence inline on
    /// the fork-branch `DisputeEnter`. Called by the periodic task that
    /// detects `current_block > quorum_expiry` on ledgers this node
    /// cosigns for, and by future callers that have block info handy.
    ///
    /// The replacement-collateral lookup retries bitcoind's "Scan already
    /// in progress" only briefly ([`ScanRetry::quick`]): the callers run
    /// under 5-10 s timeouts or on the event loop. If it still fails we do
    /// not arm; `auto_rearm_disputes` retries in the background with the
    /// full schedule.
    ///
    /// [`ScanRetry::quick`]: crate::chain_backend::ScanRetry::quick
    pub(crate) async fn auto_arm_for_dispute_with_anchor(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
        anchor: Option<([u8; 32], u32)>,
    ) -> Result<(), Error> {
        self.arm_dispute(
            ledger_id,
            last_valid_seq,
            anchor,
            None,
            None,
            &crate::chain_backend::ScanRetry::quick(),
        )
        .await
    }

    async fn arm_dispute(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
        anchor: Option<([u8; 32], u32)>,
        fraud_proof_hash: Option<[u8; 32]>,
        reason: Option<&str>,
        scan_retry: &crate::chain_backend::ScanRetry,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{hash160, Hash};

        use deposits_core::messages::LedgerOperation;

        let our_pubkey = self.node_id;

        // DEP-06 §Enter: the operator never disputes its own ledger, whatever
        // the caller (a fraud proof, our own expiry sweep, an auto-arm pass).
        if self.operates_ledger(ledger_id) {
            return Err(Error::Protocol(format!(
                "refusing to dispute ledger {}: we operate it (DEP-06 §Enter)",
                &ledger_id[..16.min(ledger_id.len())]
            )));
        }

        // Never fork past a known fault. The replica applies updates it
        // flags as non-conforming and follows the chain past them, so a
        // caller that took its base from the replica's tip (ref3 disputed
        // C's fault at 17,840 from last_valid_seq=20181) would carry the
        // fraud into the fork.
        let requested = last_valid_seq;
        let last_valid_seq = dispute_base(requested, self.handler.first_non_conforming(ledger_id));
        if last_valid_seq != requested {
            tracing::warn!(
                "Dispute on {}: last_valid_seq {} is past the first non-conforming update \
                 (seq {}); forking at {}",
                &ledger_id[..16.min(ledger_id.len())],
                requested,
                last_valid_seq + 1,
                last_valid_seq
            );
        }

        // DEP-03 "When the set is final": a dispute whose vault is already spent on the
        // confirmed chain is over. Entering or arming it again (after a restart, on a fork
        // DisputeEnter the relay replays, or on a pledge the confiscation itself spent)
        // only moved E, and with it every member's view of the set.
        if self.dispute_vault_spent(ledger_id, last_valid_seq).await == Some(true) {
            if logged_once(ledger_id) {
                tracing::info!(
                    "Dispute on {}: its vault is spent on the confirmed chain; not entering or arming",
                    &ledger_id[..16.min(ledger_id.len())]
                );
            }
            return Ok(());
        }

        // 0. Create a fork of the disputed ledger (or reuse existing one)
        // Punitive: not on a lapsed quorum (an expiry dispute carries its anchor). Joining
        // another member's punitive dispute on cited grounds is punitive too.
        let punitive = anchor.is_none() && reason.is_none_or(|r| r != "quorum_expired");
        let fork_key = self.create_dispute_fork(ledger_id, last_valid_seq, punitive)?;

        // Get the fork ledger's arc
        let fork_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(&fork_key)
            .cloned()
            .ok_or_else(|| Error::Protocol("Fork ledger not found after creation".to_string()))?;
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Track whether we actually added new operations (to avoid re-broadcast loops)
        let mut added_new_operations = false;

        // DEP-03 §Grounded arms: a punitive DisputeEnter carries the broadcast it acts on.
        // Joining another member's dispute without a proof of our own, we cite theirs:
        // the grounds of any other DisputeEnter on this ledger whose carried proof we have
        // verified (motive is never examined, the grounds are).
        let (fraud_proof_hash, fraud_proof, reason) = match fraud_proof_hash {
            Some(h) => (Some(h), super::inbound::known_broadcast_json(&h), reason),
            None if anchor.is_none() => match self.cited_grounds(ledger_id).await {
                Some((h, body, r)) => (Some(h), Some(body), Some(r)),
                // DEP-03 §Grounded arms: under grounded-arms-v7 a member does not join a dispute on
                // no grounds; it waits for a proof it can verify (the proof that started the
                // dispute reaches it moments later, and it enters then).
                None if grounds_gate_applies(
                    self.ledger_grounds_arms(ledger_id),
                    reason.is_some(),
                    self.entered_own_fork(ledger_id, last_valid_seq),
                ) =>
                {
                    tracing::info!(
                        "Dispute on {}: no grounds we can cite yet; not joining until we have a proof",
                        &ledger_id[..16.min(ledger_id.len())]
                    );
                    return Ok(());
                }
                None => (None, None, reason),
            },
            None => (None, None, reason),
        };
        let reason = reason.map(|r| r.to_string());
        // 1. Publish DisputeEnter on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            // The state machine is authoritative: if dispute_state has
            // moved past Normal then DisputeEnter has already been
            // applied (even if the history vector is missing the row —
            // e.g. JSONL truncated by a disk-full mid-write).
            // Re-publishing DisputeEnter on a Disputed/Armed fork would
            // be rejected by `validate_operation` anyway.
            let already_disputed =
                fork_ledger.state.dispute_state != deposits_core::types::DisputeState::Normal;

            if already_disputed {
                tracing::info!("Already have DisputeEnter on fork");
            } else {
                let (anchor_block_hash, anchor_block_height) = match anchor {
                    Some((h, n)) => (Some(h), Some(n)),
                    None => (None, None),
                };
                let dispute_op = LedgerOperation::DisputeEnter {
                    last_valid_sequence: last_valid_seq,
                    reason: if anchor.is_some() {
                        "quorum_expired".to_string()
                    } else {
                        reason.unwrap_or_else(|| "auto_dispute".to_string())
                    },
                    anchor_block_hash,
                    anchor_block_height,
                    fraud_proof_hash,
                    fraud_proof,
                };

                fork_ledger
                    .append_operation_with_block(dispute_op, current_block, block_hash)
                    .map_err(|e| {
                        Error::Protocol(format!("Failed to append DisputeEnter to fork: {:?}", e))
                    })?;

                // Set parent_pubkey to our key (we now operate this fork branch)
                fork_ledger.state.parent_pubkey = our_pubkey;

                // Patch operator_id on the appended update to our pubkey
                if let Some(update) = fork_ledger.history.last_mut() {
                    update.operator_id = our_pubkey;
                }

                tracing::info!("Published DisputeEnter on fork (parent_pubkey set to us)");
                added_new_operations = true;
            }
        }

        // Sign the dispute update on the fork
        self.sign_last_update(&fork_key)?;

        // A fresh DisputeEnter goes out NOW, before anything below can fail: entering is what
        // acting on a proof means (DEP-19 §6 counts a non-expiry DisputeEnter whether or not it
        // arms), and every step past here (attestations, collateral lookup, the lottery seed, the
        // arm) has an early `?` exit that used to leave the entry signed in memory only.
        // `publish_fork` queues it for the periodic retry if the relay refuses.
        if added_new_operations {
            // Write-ahead: durable, or not published at all.
            self.write_ahead_fork(&fork_key)?;
            let _ = self.publish_fork(&fork_key).await;
            added_new_operations = false;
        }

        // Test/recovery hook: when `<data_dir>/.pause_auto_dispute_actions`
        // exists, stop after publishing DisputeEnter and skip auto-arm.
        // The cooperative-refund Tier-3 test uses this marker so it
        // can drain reserves manually before each disputant arms with
        // the received UTXO as replacement collateral. File-based so
        // it works against already-running daemons.
        //
        // PERSIST FIRST: the unconditional `persist_ledger_to_disk` for
        // this fork sits at the end of the function (after the armed
        // step). Returning here without persisting leaves the fork
        // in-memory only — invisible to tests (and to operator tooling)
        // that observe via the JSONL files. Force a persist here so
        // the manual-orchestration path can see the same fork shape it
        // would see in the unpaused flow.
        if self.data_dir.join(".pause_auto_dispute_actions").exists() {
            if let Err(e) = self.handler.persist_ledger_to_disk(&fork_key) {
                tracing::error!(
                    "Failed to persist fork ledger before pause-marker return: {}",
                    e
                );
            }
            tracing::info!(
                ".pause_auto_dispute_actions marker present — skipping \
                 auto-arm (DisputeEnter published + persisted, manual \
                 orchestration takes over)"
            );
            return Ok(());
        }

        // 2. Copy our existing attestations from ALL of our operator ledger histories
        // (not from the fork - those prove we have collateral backing).
        // With multi-ledger operators, attestations may be spread across any of our
        // ledgers, so we must scan all of them.
        {
            // Collect arcs for all our owned ledgers
            let our_ledger_arcs: Vec<_> = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .iter()
                    .filter(|(lid, arc)| {
                        let l = arc.read().unwrap();
                        l.operator_key() == self.node_id && lid.len() <= 64
                    })
                    .map(|(_, arc)| arc.clone())
                    .collect()
            };

            // Collateral is now tracked at the UTXO level; no attestations to copy.
            // Add quorum members from our ledgers to the fork if needed.
            let mut quorum_members_to_add: Vec<(bitcoin::secp256k1::PublicKey, String)> =
                Vec::new();

            for ledger_arc in &our_ledger_arcs {
                let ledger = ledger_arc.read().unwrap();
                for member in &ledger.state.quorum_members {
                    if !quorum_members_to_add
                        .iter()
                        .any(|(pk, _)| pk == &member.pubkey)
                    {
                        quorum_members_to_add.push((member.pubkey, member.ledger_id.clone()));
                    }
                }
            }

            if !quorum_members_to_add.is_empty() {
                // Add quorum members to the fork
                for (member, member_ledger_id) in &quorum_members_to_add {
                    // Append + operator-sign + finalize EACH member in its own
                    // step. Chaining every op on the parent's `chain_hash()` is
                    // the whole-recovered-chain invariant (see the
                    // `recovery_chaining` module) — but
                    // `append_operation_with_block` advances `chain_tip_hash`
                    // only to the new op's `content_hash`; it becomes the
                    // `chain_hash()` solely when `sign_last_update` finalizes.
                    // Appending the whole batch first and signing once at the
                    // end (the old shape) chained the 2nd..Nth QuorumAddMember
                    // on their predecessor's `content_hash`, so a loser
                    // reimporting the resolved chain via the `chain_hash()`
                    // branch-walk stopped at the first internal link — the
                    // fork's depth read as 1, the disputed op0 branch won the
                    // depth tiebreak, and the loser converged onto the STALE
                    // chain (0/2 cosigs on every post-recovery deposit).
                    let appended = {
                        let mut fork_ledger = fork_arc.write().unwrap();

                        // QuorumAddMember on a fork stages into
                        // `next_quorum_members`; the fork has no
                        // QuorumBegin to promote them to the active set, so
                        // skip-if-already must consult both lists or every
                        // periodic re-appends the same member forever.
                        let already_known = fork_ledger
                            .state
                            .quorum_members
                            .iter()
                            .chain(fork_ledger.state.next_quorum_members.iter())
                            .any(|m| m.pubkey == *member);
                        if already_known {
                            continue;
                        }

                        let add_op = LedgerOperation::QuorumAddMember {
                            min_collateral_bps: None,
                            dormancy_blocks: None,
                            dormancy_notice_blocks: None,
                            quorum_member: *member,
                            quorum_member_signature: [0u8; 64],
                            member_ledger_id: member_ledger_id.clone(),
                            min_fee_bps: None,
                            min_fee_fixed: None,
                            max_fee_period: None,
                            membership_until: None,
                            dispute_response_blocks: None,
                            dispute_arm_blocks: None,
                            service_response_blocks: None,
                            max_transfer_timeout_blocks: None,
                            max_descriptor_bytes: None,
                            compensation_bps: None,
                            compensation_deposit_id: None,
                            compensation_frequency_blocks: None,
                            member_response: None,
                            member_signature: None,
                        };

                        match fork_ledger.append_operation_with_block(
                            add_op,
                            current_block,
                            block_hash,
                        ) {
                            Err(e) => {
                                tracing::warn!("Failed to add quorum member to fork: {:?}", e);
                                false
                            }
                            Ok(_) => {
                                if let Some(update) = fork_ledger.history.last_mut() {
                                    update.operator_id = our_pubkey;
                                }
                                tracing::info!(
                                    "Added quorum member to fork: {}...",
                                    &hex::encode(member.serialize())[..16]
                                );
                                added_new_operations = true;
                                true
                            }
                        }
                        // fork write-lock dropped here so sign_last_update
                        // (which re-locks the ledger map) can run.
                    };

                    // Sign + finalize this member's op so `chain_tip_hash`
                    // advances to its `chain_hash()` — making the NEXT
                    // member's `previous_hash` a chain_hash, not a content_hash.
                    if appended {
                        self.sign_last_update(&fork_key)?;
                    }
                }
            }
        }

        // 2b. DEP-06 §Confiscation obligations: record a dangling migration before arming.
        let pending_obligation = {
            let fork_ledger = fork_arc.read().unwrap();
            let recorded = fork_ledger.history.iter().any(|u| {
                matches!(
                    LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::ObligationRecord { .. })
                        | Ok(LedgerOperation::DisputeArmed { .. })
                )
            });
            if recorded {
                None
            } else {
                Some(match &fork_ledger.state.dormancy_accept {
                    Some(a) if !a.resolved => a.source.map(|s| (s, a.manifest_hash)),
                    _ => None,
                })
            }
        };
        // DEP-06: proven-uncredited offer payments are owed too: record each before arming.
        if pending_obligation.is_some() {
            let (ledger_id_hex, operator_history) = {
                let fork_ledger = fork_arc.read().unwrap();
                let id = hex::encode(fork_ledger.state.ledger_id);
                let op = fork_ledger.history.first().map(|u| u.operator_id);
                (
                    id,
                    fork_ledger
                        .history
                        .iter()
                        .filter(|u| Some(u.operator_id) == op)
                        .cloned()
                        .collect::<Vec<_>>(),
                )
            };
            // The proof this fork's own DisputeEnter acts on (TLV 345) first: a member that
            // enters on an offer proof can arm before the relay serves that proof back, and a
            // payment no participant records is not owed at confiscation (regtest 2026-11-04:
            // two reference members armed 0.05 s after the proof and confiscated without it).
            let own = {
                let fork_ledger = fork_arc.read().unwrap();
                fork_ledger.history.iter().rev().find_map(|u| {
                    match LedgerOperation::tlv_decode(&u.message) {
                        Ok(LedgerOperation::DisputeEnter {
                            fraud_proof: Some(body),
                            ..
                        }) => Some(body),
                        _ => None,
                    }
                })
            };
            let mut proofs: Vec<Vec<u8>> = Vec::new();
            let mut seen: Vec<(String, u32)> = Vec::new();
            if own.is_none() {
                tracing::debug!(
                    "no carried proof on our DisputeEnter for {}",
                    &ledger_id_hex[..16]
                );
            }
            if let Some(body) = own {
                // TLV 345 holds the broadcast as received ({proof, embedding, causal_chain}).
                let parsed = serde_json::from_str::<deposits_core::fraud::FraudBroadcast>(&body)
                    .map(|b| b.proof)
                    .or_else(|_| serde_json::from_str::<deposits_core::fraud::FraudProof>(&body));
                if let Ok(p) = parsed {
                    if let deposits_core::fraud::FraudEvidence::UncreditedOnchain {
                        txid,
                        vout,
                        ..
                    } = &p.evidence
                    {
                        let wallet = &self.wallet;
                        let oracle = |b: &[u8; 32]| wallet.confirms_block(b);
                        let verdict = if p.ledger_id != ledger_id_hex {
                            Err("names another ledger".to_string())
                        } else {
                            deposits_core::fraud::verify_uncredited_onchain(
                                &p,
                                &operator_history,
                                &oracle,
                            )
                        };
                        match verdict {
                            Ok(()) => {
                                seen.push((txid.clone(), *vout));
                                if let Ok(j) = serde_json::to_vec(&p) {
                                    proofs.push(j);
                                }
                            }
                            Err(e) => tracing::info!(
                                "our DisputeEnter's offer proof on {} not recorded: {}",
                                &ledger_id_hex[..16],
                                e
                            ),
                        }
                    }
                }
            }
            for j in self
                .fetch_uncredited_payment_proofs(&ledger_id_hex, &operator_history)
                .await
            {
                let key = serde_json::from_slice::<deposits_core::fraud::FraudProof>(&j)
                    .ok()
                    .and_then(|p| match p.evidence {
                        deposits_core::fraud::FraudEvidence::UncreditedOnchain {
                            txid,
                            vout,
                            ..
                        } => Some((txid, vout)),
                        _ => None,
                    });
                if let Some(k) = key {
                    if seen.contains(&k) {
                        continue;
                    }
                    seen.push(k);
                }
                proofs.push(j);
            }
            for json in proofs {
                let op = LedgerOperation::ObligationRecord {
                    source_notice_update: None,
                    source_qb_update: None,
                    uncredited_proof: Some(json),
                };
                let appended = {
                    let mut fork_ledger = fork_arc.write().unwrap();
                    match fork_ledger.append_operation_with_block(op, current_block, block_hash) {
                        Ok(_) => {
                            if let Some(update) = fork_ledger.history.last_mut() {
                                update.operator_id = our_pubkey;
                            }
                            true
                        }
                        Err(e) => {
                            tracing::warn!("payment ObligationRecord not appended: {:?}", e);
                            false
                        }
                    }
                };
                if appended {
                    self.sign_last_update(&fork_key)?;
                    added_new_operations = true;
                    tracing::info!("Recorded an uncredited payment on our fork (DEP-06)");
                }
            }
        }
        let pending_obligation = pending_obligation.flatten();
        if let Some((source, manifest_hash)) = pending_obligation {
            use deposits_core::TlvEncode;
            let hist = self.receiver_history(&hex::encode(source)).await;
            let nu = hist.iter().rev().find(|u| {
                matches!(LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::DormancyNotice { manifest_hash: Some(h), .. }) if h == manifest_hash)
            });
            let qu = nu.and_then(|nu| {
                use bitcoin::hashes::{sha256, Hash};
                let id = sha256::Hash::hash(&nu.message).to_byte_array();
                hist.iter().find(|u| {
                    matches!(LedgerOperation::tlv_decode(&u.message),
                        Ok(LedgerOperation::QuorumBegin { consumed_notice: Some(c), .. }) if c == id)
                })
            });
            if let (Some(nu), Some(qu)) = (nu, qu) {
                let op = LedgerOperation::ObligationRecord {
                    source_notice_update: Some(nu.tlv_encode()),
                    source_qb_update: Some(qu.tlv_encode()),
                    uncredited_proof: None,
                };
                let appended = {
                    let mut fork_ledger = fork_arc.write().unwrap();
                    match fork_ledger.append_operation_with_block(op, current_block, block_hash) {
                        Ok(_) => {
                            if let Some(update) = fork_ledger.history.last_mut() {
                                update.operator_id = our_pubkey;
                            }
                            true
                        }
                        Err(e) => {
                            tracing::warn!("ObligationRecord not appended to fork: {:?}", e);
                            false
                        }
                    }
                };
                if appended {
                    self.sign_last_update(&fork_key)?;
                    added_new_operations = true;
                    tracing::info!("Recorded the dangling migration on our fork (DEP-06)");
                }
            }
        }

        // 3. Publish DisputeArmed with preimage commitment on the fork.
        //
        // 3a. Under a read lock: is there a prior arm, and what floor must
        // the replacement collateral meet? The UTXO lookup below can take
        // up to a minute (bitcoind "Scan already in progress" retries), so
        // it runs with no lock held and the prior-arm check is repeated
        // under the write lock afterwards.
        //
        // We re-arm only when the prior arm was published with
        // `replacement_collateral: None` (older daemons, or
        // DEPOSITS_ALLOW_UNCOLLATERALIZED_ARM) and a funded UTXO has since
        // appeared. The re-arm must reuse the same `commitment_hash` so
        // the lottery commitment is immutable (otherwise a disputant could
        // grind for a winning commit after observing the entropy block).
        let (prior_arm, required_sats, obligations_msat) = {
            use crate::node::replacement_collateral::{
                compute_required_replacement_sats, CollateralPolicy,
            };
            let fork_ledger = fork_arc.read().unwrap();
            // The fork's state is the ledger at `last_valid_seq` (rebuilt
            // from genesis by `fork_state_at`) plus our DisputeEnter/
            // QuorumAddMember, which move no balances: obligations at the
            // fork point, as DEP-06 §Phase 1 and the cosigners' check
            // (`collateral_basis_at`) have it, never the disputed tip's.
            // Reserves and collateral change only at LedgerOpen/
            // QuorumBegin, so these are the latest QuorumBegin's, as the
            // cosigners use.
            let obligations_msat = fork_ledger.state.total_deposit_balance();
            let required_sats = compute_required_replacement_sats(
                obligations_msat,
                fork_ledger.state.collateral_amount,
                fork_ledger.state.reserves_amount,
                &CollateralPolicy::default(),
            )
            .unwrap_or(0);
            (
                latest_dispute_armed(&fork_ledger.history),
                required_sats,
                obligations_msat,
            )
        };
        let prior_collateral_was_none = matches!(
            &prior_arm,
            Some(LedgerOperation::DisputeArmed {
                replacement_collateral: None,
                ..
            })
        );
        // DEP-03: a pledge that has stopped passing the eligibility cut (spent,
        // or never confirmed) excludes us from the lottery. Re-arm with a fresh
        // one, which reopens the window (the latest arm counts and moves E), at
        // most `MAX_ARMS` arms in all.
        let arms_so_far = {
            let fork_ledger = fork_arc.read().unwrap();
            super::armers::arm_count(&fork_ledger.history)
        };
        let prior_pledge_failed = match &prior_arm {
            Some(LedgerOperation::DisputeArmed {
                replacement_collateral: Some(rc),
                ..
            }) if arms_so_far < super::armers::MAX_ARMS => {
                // Blocking chain calls (each with a 60 s HTTP timeout) on the blocking
                // pool, bounded: this runs inside handle_dispute on the run loop, where a
                // busy bitcoind once held the loop 120 s per dispute message and every
                // request it routes timed out (regtest, 2026-10-06). Unknown = keep the arm.
                let chain = self.wallet.chain_backend();
                let rc = *rc;
                let check = tokio::task::spawn_blocking(move || {
                    let tip = chain.get_tip_height().unwrap_or(0);
                    super::armers::pledge_failure(&*chain, &rc, tip, 0)
                });
                let custody_rearm = {
                    let chain = self.wallet.chain_backend();
                    let pledge = bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(rc.txid), rc.vout);
                    let vault = {
                        let l = fork_arc.read().unwrap();
                        dispute_vault(&l.history, &self.node_id)
                    };
                    let check = tokio::task::spawn_blocking(move || {
                        let funding = chain.get_tx(&pledge.txid).ok().flatten();
                        let vault_unspent = vault.iter().flatten().any(|v| {
                            matches!(chain.is_output_unspent(&v.txid, v.vout), Ok(Some(true)))
                        });
                        pledge_is_custody_rearm(funding.as_ref(), pledge.vout, vault_unspent)
                    });
                    matches!(
                        tokio::time::timeout(std::time::Duration::from_secs(4), check).await,
                        Ok(Ok(true))
                    )
                };
                if custody_rearm {
                    tracing::error!(
                        "Our declared pledge {}:{} is a lottery claim's output 0 (a ledger's custody); \
                         re-arming with a fresh pledge while the vault is unconfiscated",
                        bitcoin::Txid::from_byte_array(rc.txid),
                        rc.vout
                    );
                    true
                } else {
                match tokio::time::timeout(std::time::Duration::from_secs(4), check).await {
                    Ok(Ok(Ok(Some(why)))) => {
                        tracing::warn!("Our pledge no longer counts ({}); re-arming", why);
                        true
                    }
                    Ok(_) => false,
                    Err(_) => {
                        tracing::debug!("pledge check still running; keeping our arm for now");
                        false
                    }
                }
                }
            }
            _ => false,
        };
        let needs_arm = prior_arm.is_none() || prior_collateral_was_none || prior_pledge_failed;

        // P2WPKH of our operator key: the arm's `target_reserves`, and where
        // the replacement collateral must sit (RC4's claim-TX builder signs
        // against it).
        let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;
        let op_address = bitcoin::Address::p2wpkh(&compressed, self.wallet.network());

        // 3b. Find the replacement collateral (DEP-03 §"Replacement
        // collateral declaration": the declared amount must satisfy
        // `obligations × (collateral / reserves) + fee_estimate`), with no
        // lock held.
        let collateral = if needs_arm {
            let lookup = find_replacement_collateral(
                &*self.wallet.chain_backend(),
                op_address.script_pubkey().as_script(),
                required_sats,
                scan_retry,
                &self.pledge_exclusion(ledger_id),
            )
            .await;
            match &lookup {
                Ok(CollateralLookup::Found(rc)) => tracing::info!(
                    "Auto-arm replacement collateral: {} sats from {}:{} (required {}; \
                     obligations {} msat at seq {})",
                    rc.amount,
                    bitcoin::Txid::from_byte_array(rc.txid),
                    rc.vout,
                    required_sats,
                    obligations_msat,
                    last_valid_seq
                ),
                Ok(CollateralLookup::Undersized { value_sats }) => tracing::warn!(
                    "Auto-arm: operator-key P2WPKH {} holds only {} sats, required ≥ {} \
                     (obligations {} msat at seq {})",
                    op_address,
                    value_sats,
                    required_sats,
                    obligations_msat,
                    last_valid_seq
                ),
                Ok(CollateralLookup::NotFound) => tracing::warn!(
                    "Auto-arm: no UTXO at operator-key P2WPKH {} (required ≥ {} sats)",
                    op_address,
                    required_sats
                ),
                Ok(CollateralLookup::Reserved { free }) => tracing::warn!(
                    "Auto-arm: {} free coins are within the re-arm reserve",
                    free
                ),
                Err(e) => tracing::warn!(
                    "Auto-arm: replacement-collateral lookup failed after retries: {}",
                    e
                ),
            }
            Some(lookup)
        } else {
            None
        };

        // 3c. Publish under the write lock, re-checking the prior arm:
        // another auto-arm pass (the equivocation and fraud-proof paths can
        // fire together) may have armed while we were scanning.
        let mut not_armed: Option<String> = None;
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            let prior_arm = latest_dispute_armed(&fork_ledger.history);
            let prior_collateral_was_none = matches!(
                &prior_arm,
                Some(LedgerOperation::DisputeArmed {
                    replacement_collateral: None,
                    ..
                })
            );

            if prior_arm.is_some() && !prior_collateral_was_none && !prior_pledge_failed {
                tracing::info!("Already have DisputeArmed on fork (with replacement_collateral)");
            } else if let Some(lookup) = collateral {
                let (commitment_hash, preimage_was_persisted): ([u8; 20], bool) =
                    if let Some(LedgerOperation::DisputeArmed {
                        commitment_hash, ..
                    }) = &prior_arm
                    {
                        // Re-arm: reuse the prior commitment_hash to
                        // keep the lottery commitment immutable.
                        tracing::info!(
                            "Re-arming with prior commitment_hash {} (collateral upgrade)",
                            hex::encode(commitment_hash)
                        );
                        (*commitment_hash, true)
                    } else {
                        // First arm: derive the preimage from the
                        // signer's identity secret. The signer returns a
                        // 32-byte HMAC *seed*, shaped into a preimage whose
                        // *length* (17..=76) carries the lottery entropy.
                        // The same seed reproduces the identical bytes at
                        // reveal time, so nothing is persisted to disk.
                        let seed = self
                            .handler
                            .signer
                            .derive_dispute_lottery_preimage(ledger_id, last_valid_seq)
                            .map_err(|e| {
                                Error::Protocol(format!("derive lottery preimage: {}", e))
                            })?;
                        let preimage =
                        deposits_core::tapscript_reserves::LotteryOutput::derive_lottery_preimage(
                            &seed,
                        );
                        let h: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();
                        (h, true)
                    };
                let _ = preimage_was_persisted;

                // Round 1 only: the fork (DisputeEnter) is still signed, persisted and
                // published below, so the node can arm a later re-arm round (rearm.rs).
                let decision = if redteam_no_arm() {
                    tracing::info!(
                        "DEPOSITS_REDTEAM_NO_ARM: not arming {}",
                        &ledger_id[..16.min(ledger_id.len())]
                    );
                    ArmDecision::Refuse("DEPOSITS_REDTEAM_NO_ARM".into())
                } else {
                    dispute_armed_op(
                        current_block,
                        commitment_hash,
                        op_address.to_string(),
                        lookup,
                        prior_collateral_was_none || prior_pledge_failed,
                        allow_uncollateralized_arm(),
                    )
                };
                match decision {
                    ArmDecision::Arm(mut armed_op) => {
                        // A re-arm (collateral upgrade, failed pledge) of a later round's arm
                        // stays in that round: the fold refuses a lower round.
                        if let (
                            LedgerOperation::DisputeArmed { rearm_round, .. },
                            Some(LedgerOperation::DisputeArmed {
                                rearm_round: prior_round,
                                ..
                            }),
                        ) = (&mut armed_op, &prior_arm)
                        {
                            *rearm_round = *prior_round;
                        }
                        fork_ledger
                            .append_operation_with_block(armed_op, current_block, block_hash)
                            .map_err(|e| {
                                Error::Protocol(format!(
                                    "Failed to append DisputeArmed to fork: {:?}",
                                    e
                                ))
                            })?;

                        // Patch operator_id
                        if let Some(update) = fork_ledger.history.last_mut() {
                            update.operator_id = our_pubkey;
                        }

                        tracing::info!("Published DisputeArmed on fork");
                        added_new_operations = true;
                    }
                    // A prior arm without collateral stands; nothing better
                    // to upgrade it with yet.
                    ArmDecision::KeepPrior => tracing::info!(
                        "Re-arm skipped: still no funded UTXO at operator-key P2WPKH; \
                         will retry next periodic"
                    ),
                    ArmDecision::Refuse(why) => not_armed = Some(why),
                }
            }
        }

        // Sign the armed update on the fork
        self.sign_last_update(&fork_key)?;

        // Persist the fork (new JSONL file with compound key as filename). Write-ahead: what we
        // signed in this pass is durable before `publish_fork` below sends it, or not sent.
        if added_new_operations {
            self.write_ahead_fork(&fork_key)?;
        } else if let Err(e) = self.handler.persist_ledger_to_disk(&fork_key) {
            tracing::error!("Failed to persist fork ledger: {}", e);
        }

        // No marker file: the fork-branch's `dispute_state == Armed`
        // is the authoritative signal that we're armed for this
        // dispute. Both `initiate_confiscations` and the
        // `confiscation_sign` gate consult that directly.

        // Publish the fork's own updates (past the fork point; the prefix is
        // the operator's and already on the relay), only when we added some
        // or an earlier publication failed: incoming fork events re-trigger
        // auto_arm_for_dispute, and re-broadcasting on every call would loop.
        // A failure is logged and queued for the periodic retry
        // (`fork_publish`).
        let publication_pending = self
            .pending_fork_publications
            .lock()
            .unwrap()
            .contains(&fork_key);
        if added_new_operations || publication_pending {
            let _ = self.publish_fork(&fork_key).await;
        } else {
            tracing::debug!("Fork already fully armed and published, skipping re-broadcast");
        }

        // Not armed for want of collateral: the fork (DisputeEnter and
        // QuorumAddMembers) is persisted and published above, and the
        // periodic `auto_rearm_disputes` calls us again until we arm.
        match not_armed {
            Some(why) => Err(Error::Protocol(format!(
                "not arming dispute fork {} without replacement collateral: {}; will retry",
                &fork_key[..32.min(fork_key.len())],
                why
            ))),
            None => Ok(()),
        }
    }

    /// Our lottery preimage for `ledger_id`. Tries the legacy on-disk file
    /// first (random preimages from pre-derivation arms that still need to
    /// resolve), then derives from the signer using the fork's
    /// `last_valid_seq` parsed from the fork tracking key. `None` if we have
    /// no fork for this ledger.
    pub(crate) fn own_lottery_preimage(&self, ledger_id: &str) -> Option<Vec<u8>> {
        let preimage_file = self.data_dir.join(format!(
            "lottery_preimage_{}.hex",
            &ledger_id[..16.min(ledger_id.len())]
        ));
        if preimage_file.exists() {
            if let Ok(hex_str) = std::fs::read_to_string(&preimage_file) {
                if let Ok(bytes) = hex::decode(hex_str.trim()) {
                    return Some(bytes);
                }
            }
        }
        let fork_key = self.handler.find_our_fork(ledger_id)?;
        let last_valid_seq = super::fork_publish::fork_key_last_valid_seq(&fork_key)?;
        let seed = self
            .handler
            .signer
            .derive_dispute_lottery_preimage(ledger_id, last_valid_seq)
            .ok()?;
        Some(deposits_core::tapscript_reserves::LotteryOutput::derive_lottery_preimage(&seed))
    }

    /// Idempotency check for "have we published our lottery reveal for
    /// this ledger". The durable signal is a `kind:9100` request we
    /// previously sent with action `lottery_reveal`; this method
    /// consults an in-memory cache first, then falls back to a
    /// per-ledger Nostr fetch (populating the cache on hit). The cache
    /// is populated by `auto_reveal_preimage` after a successful
    /// publish, so the steady-state hot path doesn't query the relay.
    pub(crate) async fn have_revealed_lottery(&self, ledger_id: &str) -> bool {
        {
            let cache = self.revealed_ledgers.lock().unwrap();
            if cache.contains(ledger_id) {
                return true;
            }
        }
        use nostr_sdk::{Filter, Kind, TagKind};
        // Our durable Kind 9106 reveal (the request below is ephemeral and
        // a relay that drops ephemerals never returns it).
        let our_member = hex::encode(self.node_id.serialize());
        if let Ok(reveals) = self.nostr.fetch_custody_lottery_reveals(ledger_id).await {
            if reveals.iter().any(|r| r.member_pubkey == our_member) {
                self.revealed_ledgers
                    .lock()
                    .unwrap()
                    .insert(ledger_id.to_string());
                return true;
            }
        }
        let delegate = match self.nostr.delegate_pubkey() {
            Some(pk) => pk.x_only_public_key().0,
            None => return false,
        };
        let nostr_xonly = match nostr_sdk::PublicKey::from_slice(&delegate.serialize()) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let filter = Filter::new()
            .kind(Kind::Custom(crate::nostr::KIND_LEDGER_REQUEST))
            .author(nostr_xonly)
            .custom_tag(crate::nostr::TAG_LEDGER_REQ, [ledger_id])
            .limit(50);
        let events = match self
            .nostr
            .fetch_client()
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
        {
            Ok(e) => e,
            Err(_) => return false,
        };
        let found = events.iter().any(|e| {
            e.tags.iter().any(|tag| {
                tag.kind() == TagKind::custom("action")
                    && tag
                        .content()
                        .map(|c| c == "lottery_reveal")
                        .unwrap_or(false)
            })
        });
        if found {
            self.revealed_ledgers
                .lock()
                .unwrap()
                .insert(ledger_id.to_string());
        }
        found
    }

    /// Auto-reveal our lottery preimage when we see another participant's reveal
    pub(crate) async fn auto_reveal_preimage(&self, ledger_id: &str) {
        // Check if we're a quorum member of this ledger
        if !self.is_quorum_member_of_ledger(ledger_id) {
            return;
        }

        let preimage = match self.own_lottery_preimage(ledger_id) {
            Some(p) => p,
            None => {
                tracing::debug!("No preimage available for ledger {}", &ledger_id[..16]);
                return;
            }
        };

        if self.have_revealed_lottery(ledger_id).await {
            tracing::debug!("Already revealed preimage for ledger {}", &ledger_id[..16]);
            return;
        }
        self.publish_lottery_reveal(ledger_id, &preimage).await;
    }

    /// Publish `preimage` for `ledger_id`'s lottery: the `lottery_reveal` request (ephemeral) and
    /// the durable Kind 9106 reveal. Round 1's (`auto_reveal_preimage`) and a re-arm round's.
    pub(crate) async fn publish_lottery_reveal(&self, ledger_id: &str, preimage: &[u8]) {
        let preimage_hex = hex::encode(preimage);

        tracing::info!(
            "Auto-revealing lottery preimage for ledger {}...",
            &ledger_id[..16]
        );
        tracing::info!(
            "  Preimage length: {} bytes (contribution: {})",
            preimage.len(),
            preimage.len().saturating_sub(16)
        );

        // Publish reveal via Nostr
        let reveal_params = serde_json::json!({
            "ledger_id": ledger_id,
            "preimage": preimage_hex,
        });

        match self
            .nostr
            .send_ledger_request(ledger_id, "lottery_reveal", reveal_params)
            .await
        {
            Ok(request_id) => {
                self.track_sent_event(&request_id);
                tracing::info!(
                    "Lottery preimage revealed! Request ID: {}...",
                    &request_id[..16.min(request_id.len())]
                );
                self.revealed_ledgers
                    .lock()
                    .unwrap()
                    .insert(ledger_id.to_string());
            }
            Err(e) => {
                tracing::error!("Failed to send reveal: {:?}", e);
            }
        }

        // And durably: the request above is kind 20101, ephemeral, so a
        // relay does not keep it for anyone who was not listening, or
        // restarts. Kind 9106, signed by our operator key over the reveal
        // digest, is the form cl-deposits verifies and keeps.
        let digest = crate::nostr::custody_lottery_reveal_digest(ledger_id, preimage);
        match self.handler.signer.bip340_sign(
            &deposits_signer_api::SignContext::no_ledger(
                deposits_signer_api::SigPurpose::Bip340Untagged,
            ),
            &digest,
        ) {
            Ok(sig) => {
                if let Err(e) = self
                    .nostr
                    .publish_signed_custody_lottery_reveal(
                        ledger_id,
                        preimage,
                        &hex::encode(self.node_id.serialize()),
                        &sig,
                    )
                    .await
                {
                    tracing::error!("Failed to publish Kind 9106 reveal: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to sign Kind 9106 reveal: {}", e),
        }
    }

    /// Auto-claim or yield for any pending lottery disputes
    ///
    /// For each ledger where we've revealed our preimage:
    /// 1. Check if all preimages are collected
    /// 2. Determine winner
    /// 3. Winner: claim lottery output + publish DisputeAcquire
    /// 4. Loser: publish DisputeYield
    pub(crate) async fn auto_lottery_claim_or_yield(&self) {
        // Enumerate disputes-in-progress by fork-branch state: every
        // armed fork where we're the disputant is a candidate.
        // `try_lottery_claim_or_yield` gracefully reports "not ready"
        // when reveals haven't all landed yet, so we don't need an
        // explicit "have I revealed" gate here.
        let armed_ledger_ids: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter_map(|(key, arc)| {
                    if key.len() <= 64 {
                        return None;
                    }
                    let l = arc.read().unwrap();
                    // Ownership predicate: `parent_pubkey == our_pubkey`.
                    // A dispute fork inherits the ORIGINAL operator's
                    // `operator_key` (never patched), so keying on
                    // `operator_key()` here always skips a disputer's own
                    // fork — leaving the reveal→claim→DisputeAcquire chain
                    // dead. `auto_arm_for_dispute_with_anchor` sets
                    // `parent_pubkey` to the disputer's key; that is the
                    // same predicate `initiate_confiscations` uses, so all
                    // three dispute stages agree on which fork is ours.
                    if l.state.parent_pubkey != self.node_id {
                        return None;
                    }
                    if l.state.dispute_state != deposits_core::types::DisputeState::Armed {
                        return None;
                    }
                    Some(key[..64].to_string())
                })
                .collect()
        };

        for ledger_id in armed_ledger_ids {
            let ledger_prefix = ledger_id[..16.min(ledger_id.len())].to_string();
            let started = std::time::Instant::now();

            // Check if we've already claimed/yielded (completed marker)
            let completed_marker = self
                .data_dir
                .join(format!("lottery_completed_{}.marker", ledger_prefix));
            if completed_marker.exists() {
                continue;
            }

            // Try to claim or yield
            match self.try_lottery_claim_or_yield(&ledger_id).await {
                Ok(completed) => {
                    if completed {
                        // Create completed marker
                        if let Err(e) = std::fs::write(&completed_marker, "completed") {
                            tracing::warn!("Failed to write completed marker: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Lottery claim/yield for {} failed: {}", ledger_prefix, e);
                }
            }
            let ms = started.elapsed().as_millis();
            if ms >= 1000 {
                tracing::warn!(
                    "lottery {}: claim-or-yield pass took {} ms",
                    ledger_prefix,
                    ms
                );
            }
        }
    }

    /// Try to claim or yield for a specific ledger
    /// Returns Ok(true) if completed, Ok(false) if not ready, Err if failed
    pub(crate) async fn try_lottery_claim_or_yield(&self, ledger_id: &str) -> Result<bool, Error> {
        use super::lottery_recovery::{lottery_claim_path, LotteryClaimPath};
        use deposits_core::tapscript_reserves::{LotteryOutput, LOTTERY_REVEAL_CSV_BLOCKS};

        let our_pubkey = self.node_id;

        // Participants (the DEP-03 eligibility cut, sorted by x-only key),
        // the preimages revealed so far (matched by commitment hash), and
        // the recovery voters from the latest QuorumBegin: the set
        // `initiate_confiscations` committed to when it paid the lottery
        // output.
        let mut ctx = self.lottery_context(ledger_id).await?;
        let our_armed = ctx
            .our_armed
            .clone()
            .ok_or_else(|| Error::Protocol("Could not find our DisputeArmed".to_string()))?;
        // DEP-03 "When a pledge is live": another participant's binding acquire for our arm's
        // round (or a later one) ended the lottery. Its claim spent the output, so the locate
        // below never finds it and we would neither claim nor yield, holding our pledge for
        // good (regtest 1121-next4c: 12 of ref6's forks). Yield as the loser, once: the yield
        // goes through `publish_custody_yield`, which adopts a yield of ours already published
        // and never signs a second at one sequence.
        self.refresh_relay_acquires(ledger_id).await;
        if let Some(won) = self.lost_to_another(ledger_id, &our_armed) {
            tracing::info!(
                "Lottery for {}: {} acquired with claim {} (binding, round {}); we lost. Publishing DisputeYield.",
                &ledger_id[..16.min(ledger_id.len())],
                &hex::encode(won.acquirer.serialize())[..16],
                bitcoin::Txid::from_byte_array(won.claim),
                won.round
            );
            // DEP-06 "What a yield must say", reason 1: the winning claim we lost to.
            let reason = LedgerOperation::DisputeYield {
                lost_to: Some(won.claim),
                reestablished: None,
                excluded_by: None,
                superseded_by: None,
            };
            self.publish_custody_yield(ledger_id, &our_armed, reason).await?;
            return Ok(true);
        }
        // A later round's arm is decided by `rearm.rs` (`rearm_reveal_and_claim`), over THAT
        // round's lottery. This pass builds ROUND 1's: a round-2-only armer is not in it, so it
        // always "lost" and yielded, Tombstoning the fork for the round it armed in. ref7's
        // c8b9b7b1 (regtest rearm-rust 2026-11-21): round-2 arm at seq 26, this pass's yield at
        // 27 a minute later, then round 2 won, claimed and confirmed with no acquire possible.
        if !super::dispute_tip::round1_pass_decides(&our_armed) {
            tracing::debug!(
                "Lottery for {}: our arm (seq {}) is for round {:?}; the re-arm pass decides it",
                &ledger_id[..16.min(ledger_id.len())],
                our_armed.sequence_number,
                super::dispute_tip::arm_round(&our_armed)
            );
            return Ok(false);
        }
        let lottery = ctx.build_lottery(self.wallet.network())?;
        let t_locate = std::time::Instant::now();
        let mut located = self.locate_lottery_output(&lottery, ctx.landed)?;
        // DEP-06 "Authorised confiscation": the confiscation that landed may be a lottery over a
        // subset of the arms counted at its block (a proposer that saw fewer arms). The sole
        // participant of 751e6951's round 1 (ref6) never claimed because it looked only for the
        // lottery over every arm it holds now (signet soak, Nov 6..10). Look for the subsets that
        // include us, as the rebuild does (at most 8 armers), and take the one that pays.
        if located.is_none() && ctx.participants.len() > 1 && ctx.participants.len() <= 8 {
            let n = ctx.participants.len();
            let ours = ctx
                .participants
                .iter()
                .position(|(pk, _)| *pk == our_pubkey);
            if let Some(ours) = ours {
                for mask in (1u32..(1u32 << n) - 1).rev() {
                    if mask & (1 << ours) == 0 {
                        continue;
                    }
                    let sub = super::lottery_recovery::LotteryContext {
                        participants: (0..n)
                            .filter(|i| mask & (1 << i) != 0)
                            .map(|i| ctx.participants[i].clone())
                            .collect(),
                        preimages: (0..n)
                            .filter(|i| mask & (1 << i) != 0)
                            .map(|i| ctx.preimages[i].clone())
                            .collect(),
                        recovery_voters: ctx.recovery_voters.clone(),
                        recovery_threshold: ctx.recovery_threshold,
                        our_armed: ctx.our_armed.clone(),
                        landed: ctx.landed,
                    };
                    let Ok(l) = sub.build_lottery(self.wallet.network()) else {
                        continue;
                    };
                    if let Some(found) = self.locate_lottery_output(&l, ctx.landed)? {
                        tracing::info!(
                            "Lottery for {}: the landed output pays a subset of the arms ({} of {})",
                            &ledger_id[..16.min(ledger_id.len())],
                            sub.participants.len(),
                            n
                        );
                        located = Some(found);
                        ctx = sub;
                        break;
                    }
                }
            }
        }
        if t_locate.elapsed().as_millis() >= 1000 {
            tracing::warn!(
                "lottery {}: locate_lottery_output took {} ms",
                &ledger_id[..16.min(ledger_id.len())],
                t_locate.elapsed().as_millis()
            );
        }
        // The participant set we derived must be the one the confiscation's output commits to:
        // if no unspent output pays this lottery, our set is not the landed one (or it has not
        // landed yet), and neither a claim nor a yield may be decided from it. A yield is final
        // (DisputeYield, completed marker), so deciding from a set that is not on chain can leave
        // a sole participant yielding its own custody (soak, 30ea46ac, Nov 5).
        let Some((lottery_outpoint, lottery_value, confirmations)) = located else {
            // What we derived, so a mismatch with the landed output can be read off the log:
            // 751e6951's round-1 output (Nov 7..10) never matched ref6's set and nothing said why.
            let short = |b: &[u8]| hex::encode(&b[..4.min(b.len())]);
            tracing::info!(
                "Lottery for {}: no unspent output pays our participant set yet; not claiming or yielding \
                 (derived: participants [{}] voters [{}] threshold {} spk {})",
                &ledger_id[..16.min(ledger_id.len())],
                ctx.participants
                    .iter()
                    .map(|(pk, p)| format!("{}:{}", short(&pk.x_only_public_key().0.serialize()), short(&p.commitment_hash)))
                    .collect::<Vec<_>>()
                    .join(" "),
                ctx.recovery_voters.iter().map(|v| short(&v.serialize())).collect::<Vec<_>>().join(" "),
                ctx.recovery_threshold,
                short(lottery.script_pubkey().as_bytes())
            );
            return Ok(false);
        };

        // DEP-06 "What a yield must say", reason 3: the landed lottery (its set is final once
        // the confiscation confirms) does not include us although we armed. Yield naming the
        // confiscation that created it. Before this, an excluded armer could only "lose" a draw
        // it was not in.
        if !ctx.participants.iter().any(|(pk, _)| *pk == our_pubkey) {
            tracing::info!(
                "Lottery for {}: we armed but are not in the landed lottery ({}); yielding",
                &ledger_id[..16.min(ledger_id.len())],
                lottery_outpoint.txid
            );
            let reason = LedgerOperation::DisputeYield {
                lost_to: None,
                reestablished: None,
                excluded_by: Some(lottery_outpoint.txid.to_byte_array()),
                superseded_by: None,
            };
            self.publish_custody_yield(ledger_id, &our_armed, reason).await?;
            return Ok(true);
        }
        let (subset, ordered_preimages, winner_index) =
            match lottery_claim_path(&ctx.preimages, confirmations >= LOTTERY_REVEAL_CSV_BLOCKS) {
                LotteryClaimPath::Full(pre) => {
                    let w = if ctx.participants.len() == 1 {
                        0
                    } else {
                        LotteryOutput::calculate_winner(&pre).map_err(|e| {
                            Error::Protocol(format!("Failed to calculate winner: {:?}", e))
                        })?
                    };
                    (None, pre, w)
                }
                LotteryClaimPath::Subset(idx, pre) => {
                    let w = LotteryOutput::subset_winner(&idx, &pre).map_err(|e| {
                        Error::Protocol(format!("Failed to calculate winner: {:?}", e))
                    })?;
                    (Some(idx), pre, w)
                }
                LotteryClaimPath::Wait(why) => {
                    tracing::info!("Lottery for {}: {}", &ledger_id[..16], why);
                    return Ok(false);
                }
            };

        let (winner_pubkey, _) = &ctx.participants[winner_index];
        if *winner_pubkey != our_pubkey {
            // DEP-06 "What a yield must say" (yield-evidence-v9): a draw we computed as lost is
            // no reason yet. Wait for the winner's claim to bind; `lost_to_another` above yields
            // naming it, and our pledge stays held until then.
            if self.our_fork_needs_yield_evidence(ledger_id, &our_armed) {
                tracing::info!(
                    "We lost the lottery for ledger {}; awaiting the winner's binding claim to \
                     name (yield-evidence-v9)",
                    &ledger_id[..16]
                );
                return Ok(false);
            }
            tracing::info!(
                "We lost the lottery for ledger {}. Publishing DisputeYield.",
                &ledger_id[..16]
            );
            self.publish_custody_yield(ledger_id, &our_armed, LedgerOperation::dispute_yield())
                .await?;
            return Ok(true);
        }
        tracing::info!("We won the lottery for ledger {}!", &ledger_id[..16]);
        self.claim_lottery(
            ledger_id,
            (lottery_outpoint, lottery_value),
            &ctx.participants,
            &ordered_preimages,
            winner_index,
            subset.as_deref(),
            &our_armed,
            ctx.recovery_voters.clone(),
            ctx.recovery_threshold,
            None,
        )
        .await
    }

    /// Claim the lottery output as the winner. `lottery_utxo` is the output the caller located
    /// BY OUTPOINT (round 1: the landed confiscation's output 0; a later round: the re-arm
    /// spend's), with its value: the claim spends exactly that output.
    pub(crate) async fn claim_lottery(
        &self,
        ledger_id: &str,
        lottery_utxo: (bitcoin::OutPoint, u64),
        participants: &[(
            bitcoin::secp256k1::PublicKey,
            deposits_core::tapscript_reserves::LotteryParticipant,
        )],
        ordered_preimages: &[Vec<u8>],
        winner_index: usize,
        subset: Option<&[usize]>,
        our_armed: &deposits_core::SignedLedgerUpdate,
        recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
        recovery_threshold: usize,
        confiscation_txid: Option<[u8; 32]>,
    ) -> Result<bool, Error> {
        use bitcoin::hashes::{sha256, Hash};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use bitcoin::taproot::TapLeafHash;
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::{SignedLedgerUpdate, TlvEncode};
        use deposits_signer_api::{SigPurpose, SignContext};

        let our_pubkey = self.node_id;
        let (_, winner_participant) = &participants[winner_index];

        // Where the acquire goes, read off our fork BEFORE the claim is broadcast: the fork's
        // real tip (after any QuorumAddMember that followed the arm), never `our_armed + 1`. A
        // fork on which this arm's round already ended (our yield follows the arm) takes no
        // acquire at any sequence, so the claim is not broadcast either (regtest rearm-rust
        // 2026-11-21, ref7 / c8b9b7b1: arm 26, yield 27, a confirmed claim and an acquire
        // computed at 27 and refused there). `node::dispute_tip`.
        let acquire_at = {
            let fork = self.handler.find_our_fork(ledger_id).and_then(|k| {
                self.handler
                    .ledgers
                    .lock()
                    .unwrap()
                    .get(&k)
                    .map(|arc| arc.read().unwrap().history.clone())
            });
            super::dispute_tip::acquire_slot(fork.as_deref(), our_armed).map_err(|why| {
                Error::Protocol(format!(
                    "{}: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    why
                ))
            })?
        };

        // Build lottery participants list
        let lottery_participants: Vec<LotteryParticipant> =
            participants.iter().map(|(_, p)| p.clone()).collect();

        // Recovery voters are supplied by the caller, derived from the
        // ledger's latest QuorumBegin (minus operator) — the SAME set the
        // confiscation TX committed to on-chain. Deriving them from the
        // DisputeArmed participants here (the old stub) produced a
        // different Taproot address, so the claim's leaf and sighash would
        // not match the output being spent.

        // Build the lottery output
        let lottery_builder = LotteryScriptBuilder::new(
            lottery_participants.clone(),
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder
            .build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        // The lottery UTXO is the one the caller located by outpoint. It was once "any unspent
        // output at the lottery's script" (`find_utxo_for_script`), and a lottery's script
        // commits to its participants and voters only: ref7, sole armer of round 2 of two
        // ledgers with one quorum, claimed 70b0abb3's unclaimed round-2 output (46a66b12:0,
        // same script, same value) as a606a4ca's, spending a606a4ca's declared collateral, and
        // every later claim of a606a4ca's own output failed bad-txns-inputs-missingorspent
        // (regtest rearm-rust 1120-090836).
        let lottery_script = lottery_output.address.script_pubkey();
        let (lottery_outpoint, lottery_amount) = lottery_utxo;

        tracing::info!(
            "Found lottery UTXO: {} ({} sats)",
            lottery_outpoint,
            lottery_amount
        );

        // Parse winner's target address
        let target_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            winner_participant
                .target_reserves
                .parse()
                .map_err(|e| Error::Protocol(format!("Invalid target address: {}", e)))?;
        let target_address = target_address
            .require_network(self.wallet.network())
            .map_err(|e| Error::Protocol(format!("Address network mismatch: {}", e)))?;

        // The claim (DEP-03): the lottery output plus our declared replacement
        // collateral (a P2WPKH of our key), less claim_fee_floor.
        let our_compressed = bitcoin::CompressedPublicKey::from_slice(&our_pubkey.serialize())
            .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;
        let collateral_spk =
            bitcoin::Address::p2wpkh(&our_compressed, self.wallet.network()).script_pubkey();
        let collateral = match LedgerOperation::tlv_decode(&our_armed.message) {
            Ok(LedgerOperation::DisputeArmed {
                replacement_collateral: Some(rc),
                ..
            }) => Some((
                bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(rc.txid), rc.vout),
                rc.amount,
            )),
            _ => None,
        };
        // DEP-03 §"Claim transaction (multi-input)": input 1 MUST be the declared replacement
        // collateral at its declared value; any other coin is a WinnerCollateralDeviation. So a
        // declared pledge that is another lottery claim's output 0 (a ledger's custody) cannot be
        // swapped for a fresh coin here: the claim is refused, and the pledge is replaced by a
        // re-arm while the arm window is open, else by the next round's arm (regtest
        // 1121-next4c: ref6 declared fdff3a5f:0, ad87b48b's custody, on 9e23c858).
        if let Some((op, _)) = collateral {
            let funding = self.wallet.chain_backend().get_tx(&op.txid);
            if let Err(why) = claim_collateral_check(op, funding.as_ref().map(|t| t.as_ref())) {
                tracing::error!(
                    "REFUSING to claim the lottery of {}: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    why
                );
                return Err(Error::Protocol(format!("claim refused: {}", why)));
            }
        }
        let claim_tx = deposits_core::tapscript_reserves::build_lottery_claim_tx(
            lottery_outpoint,
            lottery_amount,
            collateral,
            target_address.script_pubkey(),
            deposits_core::tapscript_reserves::CLAIM_FEE_FLOOR_SATS,
            subset.is_some(),
        );
        let mut prevouts = vec![TxOut {
            value: Amount::from_sat(lottery_amount),
            script_pubkey: lottery_script.clone(),
        }];
        if let Some((_, sats)) = collateral {
            prevouts.push(TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: collateral_spk.clone(),
            });
        }

        let leaf = match subset {
            Some(idx) => lottery_output
                .subset_leaf(idx)
                .ok_or_else(|| Error::Protocol(format!("No claim leaf for subset {:?}", idx)))?
                .clone(),
            None => lottery_output.lottery_script.clone(),
        };
        let leaf_hash = TapLeafHash::from_script(&leaf, bitcoin::taproot::LeafVersion::TapScript);

        let mut sighash_cache = SighashCache::new(&claim_tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| Error::Protocol(format!("Failed to compute sighash: {}", e)))?;

        // Sign — Taproot script-spend on the lottery claim leaf.
        let sig_bytes = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::no_ledger(SigPurpose::OnchainSighash),
                sighash.as_ref(),
            )
            .map_err(|e| Error::Protocol(format!("lottery sighash sign: {}", e)))?;

        // Create witness: a subset claim also needs the voters' attestations.
        let witness = match subset {
            Some(idx) => {
                let sighash_bytes: [u8; 32] = *sighash.as_ref();
                let Some(voter_sigs) = self
                    .subset_attestations(
                        ledger_id,
                        &lottery_output,
                        idx,
                        &claim_tx,
                        &prevouts,
                        sighash_bytes,
                    )
                    .await?
                else {
                    return Ok(false);
                };
                lottery_output
                    .create_subset_claim_witness(idx, &sig_bytes, ordered_preimages, &voter_sigs)
                    .map_err(|e| Error::Protocol(format!("Failed to create witness: {:?}", e)))?
            }
            None => lottery_output
                .create_claim_witness(&sig_bytes, ordered_preimages)
                .map_err(|e| Error::Protocol(format!("Failed to create witness: {:?}", e)))?,
        };

        let mut claim_tx = claim_tx;
        claim_tx.input[0].witness = witness;
        if let Some((_, sats)) = collateral {
            use bitcoin::sighash::EcdsaSighashType;
            let rc_sighash = SighashCache::new(&claim_tx)
                .p2wpkh_signature_hash(
                    1,
                    &collateral_spk,
                    Amount::from_sat(sats),
                    EcdsaSighashType::All,
                )
                .map_err(|e| Error::Protocol(format!("collateral sighash: {}", e)))?;
            let rc_sig = self
                .handler
                .signer
                .ecdsa_sign_sighash(
                    &SignContext::no_ledger(SigPurpose::OnchainSighash),
                    rc_sighash.as_ref(),
                )
                .map_err(|e| Error::Protocol(format!("collateral sighash sign: {}", e)))?;
            let mut der = rc_sig.serialize_der().to_vec();
            der.push(EcdsaSighashType::All as u8);
            let mut w = Witness::new();
            w.push(&der);
            w.push(our_pubkey.serialize());
            claim_tx.input[1].witness = w;
        }

        // Broadcast
        tracing::info!("Broadcasting claim transaction...");
        self.wallet.broadcast(&claim_tx)?;

        let claim_txid = claim_tx.compute_txid();
        tracing::info!("Claim TX broadcast: {}", claim_txid);

        // Publish DisputeAcquire. The block_height and block_hash on
        // the SignedLedgerUpdate envelope still need to reflect a
        // recent on-chain anchor for fraud-proof anchoring; they are
        // unrelated to the lottery selection (which is enforced by
        // the on-chain claim TX itself).
        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        let claim_txid_bytes: [u8; 32] = *claim_txid.as_ref();

        let operation = LedgerOperation::DisputeAcquire {
            new_custodian: our_pubkey,
            claim_txid: claim_txid_bytes,
            new_reserves_address: winner_participant.target_reserves.clone(),
            // DEP-06: the claim spends the confiscation's lottery output (vout 0).
            // A later re-arm round's claim names round 1's confiscation, as cl's does.
            confiscation_txid: Some(confiscation_txid.unwrap_or_else(|| {
                use bitcoin::hashes::Hash;
                claim_tx.input[0].previous_output.txid.to_byte_array()
            })),
        };

        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed.
        //
        // The chain links on the PARENT's `chain_hash()`, NOT its
        // `content_hash`. `chain_hash = SHA256(content_hash ||
        // operator_signature)` — the exact value `commit_staged` /
        // `finalize_chain_hash` write to `state.chain_tip_hash`, and the
        // exact value `validate_hash_chain` compares each `previous_hash`
        // against. `our_armed` is the winner's own DisputeArmed, fetched
        // fully-signed from the relay, so its `operator_signature` is
        // populated and `chain_hash()` is well-defined. Chaining on
        // `content_hash` (the old behavior) produced a `previous_hash`
        // that `import_ledger` rejected as a broken chain, so losing
        // cosigners could never converge onto the resolved chain.
        //
        // The parent is our FORK'S TIP (`acquire_at`), which is `our_armed` only when nothing
        // followed the arm; `None` there means an acquire of ours already holds `sequence`.
        let (sequence, parent) = acquire_at;
        let parent = parent.unwrap_or_else(|| our_armed.clone());
        let parent_chain_hash = parent.chain_hash();
        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        // A retry (a broadcast that failed after the write-ahead, or a restart) publishes the
        // acquire we already signed at this sequence; it never signs a second one there.
        if let Some(stored) = self
            .handler
            .find_our_fork(ledger_id)
            .and_then(|k| self.own_update_at(&k, sequence))
            .or_else(|| self.journaled_at(ledger_id, sequence))
        {
            if !matches!(
                LedgerOperation::tlv_decode(&stored.message),
                Ok(LedgerOperation::DisputeAcquire { .. })
            ) {
                return Err(Error::Protocol(format!(
                    "seq {} of {} already holds another update of ours; not signing an acquire there",
                    sequence,
                    &ledger_id[..16.min(ledger_id.len())]
                )));
            }
            self.nostr
                .broadcast_ledger_update(&stored)
                .await
                .map_err(|e| Error::Protocol(format!("Failed to rebroadcast DisputeAcquire: {:?}", e)))?;
            if let Some(k) = self.handler.find_our_fork(ledger_id) {
                self.published_all(&k);
            }
            tracing::info!("DisputeAcquire already signed at seq {}: republished those bytes", sequence);
            return Ok(true);
        }

        let mut signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: parent_chain_hash,
            content_hash: [0u8; 32],
            block_height: deposits_core::ledger::signing_header_after(
                Some((parent.block_height, parent.block_hash)),
                current_block,
                current_block_hash,
            )
            .0,
            block_hash: deposits_core::ledger::signing_header_after(
                Some((parent.block_height, parent.block_hash)),
                current_block,
                current_block_hash,
            )
            .1,
        };
        signed_update.content_hash = signed_update.compute_hash();
        signed_update.operator_signature = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::operator_update(ledger_id_bytes, sequence),
                &signed_update.operator_digest(),
            )
            .map_err(|e| Error::Protocol(format!("operator sign: {}", e)))?;

        // WRITE-AHEAD (node::write_ahead): the acquire is durable before any relay sees it, and
        // a failed persist means it is not published. It used to be broadcast first and recorded
        // after, so a kill in between left it on the relays and not on our disk, and the claim's
        // retry signed another at this sequence under a later header.
        //
        // Our own fork (stored under `<ledger_id>_<seq>_<pk16>`, via `find_our_fork`) takes it
        // through `commit_self_authored_update` (allowlisted, lock-serialized, no mid-apply
        // awaits, fsync'd), so `state.operator_key` rotates to us, the dispute clears and the
        // fork file records the resolution. With no fork of ours (a manual-recovery operator)
        // it is journaled under `signed/` instead.
        let own_fork = self.handler.find_our_fork(ledger_id);
        let mut fresh = false;
        if let Some(fork_key) = &own_fork {
            match self.handler.commit_self_authored_update(
                fork_key,
                &operation,
                signed_update.clone(),
                current_block,
            ) {
                Ok(true) => fresh = true,
                Ok(false) => tracing::debug!(
                    "DisputeAcquire already present on fork {}",
                    &fork_key[..16.min(fork_key.len())],
                ),
                Err(e) => {
                    return Err(Error::Protocol(format!(
                        "DisputeAcquire not persisted to fork {}: {}; not publishing it",
                        &fork_key[..16.min(fork_key.len())],
                        e
                    )))
                }
            }
        } else {
            self.journal_signed(ledger_id, &signed_update)?;
        }
        let pending = match &own_fork {
            Some(k) => Some(self.write_ahead(k, &signed_update, true)?),
            None => None,
        };

        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeAcquire: {:?}", e)))?;
        if let Some(p) = &pending {
            self.published(p);
        }
        tracing::info!("DisputeAcquire published! We are now the operator.");

        if let (Some(fork_key), true) = (&own_fork, fresh) {
            tracing::info!(
                "DisputeAcquire applied + persisted to local fork {} (custody rotated to us, dispute cleared)",
                &fork_key[..16.min(fork_key.len())],
            );
            // DEP-06 §Residue: we owe it now, within the ledger's service_response_blocks.
            let conf_txid = claim_tx.input[0].previous_output.txid;
            match self.credit_residue(ledger_id, fork_key, conf_txid).await {
                Ok(n) if n > 0 => {
                    // Write-ahead for the credits: durable, or not published.
                    self.write_ahead_fork(fork_key)?;
                    let _ = self.publish_fork(fork_key).await;
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("residue of {}: {}", &ledger_id[..8], e),
            }
        }

        Ok(true)
    }

    /// DEP-06 §Residue, as the new operator after `DisputeAcquire` on `fork_key`: credit every
    /// owed entry the confiscation `conf_txid` did not pay. A migration dangling at the acquire:
    /// one `MigrationCredit` carrying the confiscation (the fold credits only its unpaid entries,
    /// and resolves the accept). A payment proven uncredited (recorded on the fork, or proved on
    /// the relays): its deposit opened if need be, then an `OnchainCredit` of its outpoint. Each
    /// is signed; the caller publishes the fork. Mirrors cl-deposits' `credit-residue`.
    pub(crate) async fn credit_residue(
        &self,
        ledger_id: &str,
        fork_key: &str,
        conf_txid: bitcoin::Txid,
    ) -> Result<usize, Error> {
        use deposits_core::TlvEncode;
        let conf = self
            .wallet
            .get_transaction(conf_txid)?
            .ok_or_else(|| Error::Protocol(format!("confiscation {conf_txid} not found")))?;
        let fork_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(fork_key)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("no fork {fork_key}")))?;
        let our_pubkey = self.handler.signer.pubkey();
        let (history, migration) = {
            let l = fork_arc.read().unwrap();
            let migration = l
                .state
                .dormancy_accept
                .as_ref()
                .filter(|a| !a.resolved)
                .and_then(|a| a.source.map(|s| (s, a.manifest_hash)));
            (l.history.clone(), migration)
        };
        let mut ops: Vec<LedgerOperation> = Vec::new();
        if let Some((source, manifest_hash)) = migration {
            let src = self.receiver_history(&hex::encode(source)).await;
            let nu = src.iter().rev().find(|u| {
                matches!(LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::DormancyNotice { manifest_hash: Some(h), .. }) if h == manifest_hash)
            });
            let qu = nu.and_then(|nu| {
                use bitcoin::hashes::{sha256, Hash};
                let id = sha256::Hash::hash(&nu.message).to_byte_array();
                src.iter().find(|u| {
                    matches!(LedgerOperation::tlv_decode(&u.message),
                        Ok(LedgerOperation::QuorumBegin { consumed_notice: Some(c), .. }) if c == id)
                })
            });
            if let (Some(nu), Some(qu)) = (nu, qu) {
                ops.push(LedgerOperation::MigrationCredit {
                    source_notice_update: nu.tlv_encode(),
                    source_qb_update: qu.tlv_encode(),
                    confiscation_tx: Some(bitcoin::consensus::serialize(&conf)),
                });
            }
        }
        // Payments: recorded on the fork before the acquire, and proved on the relays.
        let mut jsons: Vec<Vec<u8>> = history
            .iter()
            .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
                Ok(LedgerOperation::ObligationRecord {
                    uncredited_proof: Some(json),
                    ..
                }) => Some(json),
                _ => None,
            })
            .collect();
        jsons.extend(
            self.fetch_uncredited_payment_proofs(ledger_id, &history)
                .await,
        );
        let mut credited: Vec<([u8; 32], u32)> = history
            .iter()
            .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
                Ok(LedgerOperation::OnchainCredit { txid, vout, .. }) => Some((txid, vout)),
                _ => None,
            })
            .collect();
        let mut opened: Vec<[u8; 16]> = Vec::new();
        for json in jsons {
            let Ok(proof) = serde_json::from_slice::<deposits_core::fraud::FraudProof>(&json)
            else {
                continue;
            };
            let deposits_core::fraud::FraudEvidence::UncreditedOnchain {
                deposit_id,
                descriptor,
                txid,
                vout,
                amount_sats,
                funding_address,
                ..
            } = &proof.evidence
            else {
                continue;
            };
            let (Ok(t), Ok(d)) = (hex::decode(txid), hex::decode(deposit_id)) else {
                continue;
            };
            let (Ok(t), Ok(d)) = (<[u8; 32]>::try_from(t), <[u8; 16]>::try_from(d)) else {
                continue;
            };
            if proof.ledger_id != ledger_id || credited.contains(&(t, *vout)) {
                continue;
            }
            let e = deposits_core::messages::ManifestEntry {
                deposit_id: d,
                amount: amount_sats * 1000,
                fees: Default::default(),
                descriptor: descriptor.clone(),
            };
            // Residue: no output of the confiscation paid it.
            let paid = deposits_core::types::owed_spk_sats(&e).is_some_and(|(spk, v)| {
                conf.output
                    .iter()
                    .any(|o| o.script_pubkey == spk && o.value.to_sat() == v)
            });
            if paid {
                continue;
            }
            let open =
                fork_arc.read().unwrap().state.deposits.contains_key(&d) || opened.contains(&d);
            if !open {
                ops.push(LedgerOperation::DepositOpen {
                    deposit_id: d,
                    descriptor: descriptor.clone(),
                    fees: None,
                    transfer_fees: None,
                    payment_hash: None,
                    invoice: None,
                    cosigner_guarantee_signature: None,
                    receive_requires_sig: false,
                    fee_change_after_blocks: None,
                    fee_change_notice_blocks: None,
                    fee_change_limit_bps: None,
                    commitment: None,
                });
                opened.push(d);
            }
            ops.push(LedgerOperation::OnchainCredit {
                txid: t,
                vout: *vout,
                deposit_id: d,
                amount: e.amount,
                funding_address: funding_address.clone(),
                commitment: None,
            });
            credited.push((t, *vout));
        }
        let mut n = 0;
        for op in ops {
            let height = self.wallet.get_block_height().unwrap_or(0);
            let hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
            let appended = {
                let mut fork = fork_arc.write().unwrap();
                match fork.append_operation_with_block(op, height, hash) {
                    Ok(_) => {
                        if let Some(update) = fork.history.last_mut() {
                            update.operator_id = our_pubkey;
                        }
                        true
                    }
                    Err(e) => {
                        tracing::warn!(
                            "residue of {}: credit not appended: {:?}",
                            &ledger_id[..8],
                            e
                        );
                        false
                    }
                }
            };
            if appended {
                self.sign_last_update(fork_key)?;
                n += 1;
            }
        }
        if n > 0 {
            tracing::info!(
                "residue of {}: {} credit operation(s) appended (DEP-06)",
                &ledger_id[..8],
                n
            );
        }
        Ok(n)
    }

    /// Withdraw our armed dispute on `fork_key`: append `DisputeYield` to the
    /// fork (it is then Tombstoned, so the confiscation and lottery tasks,
    /// which drive only Armed forks, pass it by), sign, persist, and publish
    /// it. Used when the dispute's ground went away
    /// (`expiry_watch::stand_down_reestablished_expiry_disputes`). A fork
    /// write like `auto_arm_for_dispute_with_anchor`'s: the fork has no actor,
    /// and its only other writer does not touch it once it is Tombstoned.
    ///
    /// `reason` is the `DisputeYield` to append, carrying its evidence (DEP-06 "What a yield
    /// must say"): under `yield-evidence-v9` the fold refuses one without exactly one reason, so
    /// none is ever signed.
    pub(crate) async fn withdraw_dispute(
        &self,
        fork_key: &str,
        height: u32,
        reason: deposits_core::messages::LedgerOperation,
    ) -> Result<(), Error> {

        let fork_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(fork_key)
            .cloned()
            .ok_or_else(|| Error::Protocol(format!("Fork not found: {}", fork_key)))?;
        let block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);
        {
            let mut fork = fork_arc.write().unwrap();
            fork.append_operation_with_block(reason, height, block_hash)
                .map_err(|e| Error::Protocol(format!("DisputeYield refused: {:?}", e)))?;
            if let Some(update) = fork.history.last_mut() {
                update.operator_id = self.node_id;
            }
        }
        self.sign_last_update(fork_key)?;
        let update = fork_arc.read().unwrap().history.last().cloned();
        if let Some(update) = update {
            // Write-ahead: durable (fsync'd), or not published. A broadcast that fails leaves
            // the pending file for `publish_pending_updates`, which sends these bytes.
            let pending = self.write_ahead(fork_key, &update, true)?;
            self.nostr
                .broadcast_ledger_update(&update)
                .await
                .map_err(|e| {
                    Error::Protocol(format!("Failed to broadcast DisputeYield: {:?}", e))
                })?;
            self.published(&pending);
        }
        Ok(())
    }

    /// Whether our fork holding `our_armed` judges yields under `yield-evidence-v9` (DEP-06 "What a
    /// yield must say"): a draw we merely computed as lost is then no reason to yield yet.
    pub(crate) fn our_fork_needs_yield_evidence(
        &self,
        ledger_id: &str,
        our_armed: &deposits_core::SignedLedgerUpdate,
    ) -> bool {
        let tip = our_armed.chain_hash();
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers.iter().any(|(k, arc)| {
            let l = arc.read().unwrap();
            k.starts_with(ledger_id)
                && super::rearm::is_our_fork(k, &l.state.parent_pubkey, &self.node_id)
                && l.history.iter().any(|u| u.chain_hash() == tip)
                && deposits_core::types::ruleset_yield_evidence(&l.state.active_ruleset_name)
        })
    }

    /// Publish DisputeYield as a loser. `reason` is the yield to sign, carrying its evidence
    /// (DEP-06 "What a yield must say"; [`LedgerOperation::dispute_yield`] when none is known,
    /// which only a ruleset before `yield-evidence-v9` takes).
    pub(crate) async fn publish_custody_yield(
        &self,
        ledger_id: &str,
        our_armed: &deposits_core::SignedLedgerUpdate,
        reason: deposits_core::messages::LedgerOperation,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{sha256, Hash};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{SignedLedgerUpdate, TlvEncode};
        use deposits_signer_api::SignContext;

        let our_pubkey = self.node_id;

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Our own fork holding this arm takes the yield through the ordinary append, so
        // it is recorded, persisted and tombstoned HERE too. It used to be broadcast only: the
        // fork stayed Armed in our own records for good, and its pledge was never released
        // (regtest 1120-next4: 86 of ref6's 151 forks entered and armed, never concluded
        // locally, 29 of them marked lottery_completed).
        //
        // The yield goes at that fork's REAL tip, which is the arm only when nothing followed it:
        // an Armed fork also takes our QuorumAddMembers (ref7's 2fea4c6b, regtest 2026-11-21:
        // arm 221, adds 222..228, and a yield computed at 222 refused every pass). A fork on which
        // this arm's round already ended takes no second terminal update (`node::dispute_tip`).
        let mut concluded: Option<SignedLedgerUpdate> = None;
        let mut own_fork: Option<(String, SignedLedgerUpdate)> = None;
        {
            let ledgers = self.handler.ledgers.lock().unwrap();
            for (k, arc) in ledgers.iter() {
                let l = arc.read().unwrap();
                if !(k.len() > ledger_id.len()
                    && k.starts_with(ledger_id)
                    && super::rearm::is_our_fork(k, &l.state.parent_pubkey, &our_pubkey))
                {
                    continue;
                }
                match super::dispute_tip::after_our_arm(&l.history, our_armed) {
                    super::dispute_tip::AfterArm::Append(tip)
                        if l.state
                            .dispute_state
                            .allows_operation(LedgerOperation::dispute_yield().discriminant()) =>
                    {
                        own_fork = Some((k.clone(), tip.clone()));
                        break;
                    }
                    super::dispute_tip::AfterArm::Concluded(u) => {
                        concluded = Some(u.clone());
                        break;
                    }
                    _ => {}
                }
            }
        }
        if let Some(u) = concluded {
            if !matches!(LedgerOperation::tlv_decode(&u.message), Ok(LedgerOperation::DisputeYield { .. })) {
                return Err(Error::Protocol(format!(
                    "{}: our fork acquired this arm's round at seq {}; not yielding",
                    &ledger_id[..16.min(ledger_id.len())],
                    u.sequence_number
                )));
            }
            // Already yielded on our fork: publish those bytes, sign nothing.
            self.nostr
                .broadcast_ledger_update(&u)
                .await
                .map_err(|e| Error::Protocol(format!("Failed to rebroadcast DisputeYield: {:?}", e)))?;
            return Ok(());
        }
        // Sign a yield at tip+1 only if nothing of ours is there yet: a retry of this path (or a
        // restart between the broadcast and the lottery marker) would otherwise sign a second
        // yield at the same sequence with another header, an equivocation by us.
        let backfill_tip = own_fork.as_ref().map(|(_, t)| t.clone()).unwrap_or_else(|| our_armed.clone());
        let own_fork = own_fork.map(|(k, _)| k);
        match self.yield_backfill_for(ledger_id, &backfill_tip, false).await {
            super::yield_backfill::Backfill::Sign => {}
            super::yield_backfill::Backfill::Adopt(y) => {
                if let Some(fork_key) = &own_fork {
                    // The op those bytes carry (with whatever reason they were signed with).
                    let op = LedgerOperation::tlv_decode(&y.message)
                        .unwrap_or_else(|_| LedgerOperation::dispute_yield());
                    self.handler
                        .commit_self_authored_update(fork_key, &op, y.clone(), y.block_height)
                        .map_err(Error::Protocol)?;
                }
                tracing::info!(
                    "DisputeYield for {} already published at seq {}; recorded those bytes",
                    &ledger_id[..16.min(ledger_id.len())],
                    y.sequence_number
                );
                return Ok(());
            }
            super::yield_backfill::Backfill::Hold(why) => {
                return Err(Error::Protocol(format!("DisputeYield not signed: {}", why)));
            }
        }
        if let Some(fork_key) = own_fork {
            return self.withdraw_dispute(&fork_key, current_block, reason).await;
        }

        // Already signed at arm+1 (on a fork of ours, or journaled fork-less): publish those
        // bytes; never sign a second update at that sequence.
        let seq = our_armed.sequence_number + 1;
        let stored = {
            let keys: Vec<String> = self
                .handler
                .ledgers
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.len() > ledger_id.len() && k.starts_with(ledger_id))
                .cloned()
                .collect();
            keys.iter()
                .filter_map(|k| self.own_update_at(k, seq))
                .find(|u| u.previous_hash == our_armed.chain_hash())
                .or_else(|| self.journaled_at(ledger_id, seq))
        };
        if let Some(stored) = stored {
            if !matches!(LedgerOperation::tlv_decode(&stored.message), Ok(LedgerOperation::DisputeYield { .. })) {
                return Err(Error::Protocol(format!(
                    "seq {} of {} already holds another update of ours; not signing a yield there",
                    seq,
                    &ledger_id[..16.min(ledger_id.len())]
                )));
            }
            self.nostr
                .broadcast_ledger_update(&stored)
                .await
                .map_err(|e| Error::Protocol(format!("Failed to rebroadcast DisputeYield: {:?}", e)))?;
            return Ok(());
        }

        // Create DisputeYield operation
        let operation = reason;
        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed. Chain on the
        // parent's `chain_hash()` (= SHA256(content_hash ||
        // operator_signature)), the same convention as every normal op and
        // the winner's DisputeAcquire — so the whole recovered chain uses
        // ONE convention and `validate_hash_chain` stays strict.
        let parent_chain_hash = our_armed.chain_hash();
        let sequence = our_armed.sequence_number + 1;
        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let mut signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: parent_chain_hash,
            content_hash: [0u8; 32],
            block_height: deposits_core::ledger::signing_header_after(
                Some((our_armed.block_height, our_armed.block_hash)),
                current_block,
                current_block_hash,
            )
            .0,
            block_hash: deposits_core::ledger::signing_header_after(
                Some((our_armed.block_height, our_armed.block_hash)),
                current_block,
                current_block_hash,
            )
            .1,
        };
        signed_update.content_hash = signed_update.compute_hash();
        signed_update.operator_signature = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::operator_update(ledger_id_bytes, sequence),
                &signed_update.operator_digest(),
            )
            .map_err(|e| Error::Protocol(format!("operator sign: {}", e)))?;

        // No ledger of ours holds it: journal it (fsync'd, kept) before any relay sees it.
        self.journal_signed(ledger_id, &signed_update)?;
        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeYield: {:?}", e)))?;

        tracing::info!("DisputeYield published. Branch terminated.");
        Ok(())
    }

    /// Fetch the most recent kind:9101 fraud broadcast for `ledger_id`
    /// from the relay and return its `proof_type`. Used by
    /// `initiate_confiscations` and the cosigner-side verifier to
    /// decide whether the confiscation should bifurcate (respectful
    /// proofs) or send the full UTXO to the lottery (punitive).
    ///
    /// Returns `None` if no broadcast is on the relay or none decode
    /// cleanly. Callers fall back to punitive shape in that case.
    /// DEP-06: the proven-uncredited offer payments against `ledger_id` on the relays whose
    /// evidence verifies against `history` (the operator's), as proof JSON — owed at confiscation.
    pub(crate) async fn fetch_uncredited_payment_proofs(
        &self,
        ledger_id: &str,
        history: &[deposits_core::SignedLedgerUpdate],
    ) -> Vec<Vec<u8>> {
        use deposits_core::fraud::{FraudBroadcast, FraudEvidence};
        use nostr_sdk::{Filter, Kind};
        let filter = Filter::new()
            .kind(Kind::Custom(deposits_nostr::KIND_FRAUD_PROOF))
            .custom_tag(
                deposits_nostr::TAG_LEDGER_ID,
                [deposits_nostr::ledger_tag(ledger_id)],
            )
            .limit(200);
        let Ok(events) = self
            .nostr
            .fetch_client()
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
        else {
            return Vec::new();
        };
        let wallet = &self.wallet;
        let oracle = |b: &[u8; 32]| wallet.confirms_block(b);
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut seen: Vec<(String, u32)> = Vec::new();
        for e in events.iter() {
            let Ok(b) = serde_json::from_str::<FraudBroadcast>(&e.content) else {
                continue;
            };
            let FraudEvidence::UncreditedOnchain { txid, vout, .. } = &b.proof.evidence else {
                continue;
            };
            if b.proof.ledger_id != ledger_id || seen.contains(&(txid.clone(), *vout)) {
                continue;
            }
            if deposits_core::fraud::verify_uncredited_onchain(&b.proof, history, &oracle).is_ok() {
                seen.push((txid.clone(), *vout));
                if let Ok(j) = serde_json::to_vec(&b.proof) {
                    out.push(j);
                }
            }
        }
        out
    }

    pub(crate) async fn fetch_fraud_proof_type_for_ledger(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use deposits_core::fraud::FraudBroadcast;
        use nostr_sdk::{Filter, Kind};

        let client = self.nostr.fetch_client();
        let filter = Filter::new()
            .kind(Kind::Custom(deposits_nostr::KIND_FRAUD_PROOF))
            .custom_tag(
                deposits_nostr::TAG_LEDGER_ID,
                [deposits_nostr::ledger_tag(ledger_id)],
            )
            .limit(50);
        let events = client
            .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
            .await
            .ok()?;

        // A relay kind:9101 is only a SIGNAL — anyone can publish a
        // well-formed-looking FraudBroadcast with any proof_type. Independently
        // verify each before trusting it, or a bogus notice could drive an
        // unjustified confiscation (the cosign tx-shape verifier confirms the tx
        // *matches* the proof_type, not that the *fault is real*). Return the
        // most-recent broadcast that actually verifies — gap-fill + per-type
        // evidence + on-chain steps, plus structural + embedding + causal
        // chain for embedding-required types: the same checks the inbound
        // receive path runs.
        let mut candidates: Vec<(u64, FraudBroadcast)> = events
            .iter()
            .filter_map(|e| {
                serde_json::from_str::<FraudBroadcast>(&e.content)
                    .ok()
                    .map(|b| (e.created_at.as_u64(), b))
            })
            .collect();
        candidates.sort_by_key(|a| std::cmp::Reverse(a.0)); // newest first
        for (_ts, broadcast) in &candidates {
            match self.verify_fraud_broadcast_locally(broadcast).await {
                Ok(()) => return Some(broadcast.proof.proof_type.clone()),
                Err(e) => tracing::debug!(
                    "Ignoring unverifiable fraud broadcast for {}...: {}",
                    &ledger_id[..16.min(ledger_id.len())],
                    e
                ),
            }
        }
        None
    }

    /// Fallback evidence path for the QuorumExpired-in-DisputeEnter
    /// scheme: a deadline-miss dispute is not embedded into a kind:9101
    /// `FraudBroadcast` (the embedding step needs cosigning, which an
    /// expired quorum can't provide). Instead the disputant publishes a
    /// fork-branch `DisputeEnter` carrying `anchor_block_hash` +
    /// `anchor_block_height` inline.
    ///
    /// This function looks for such a fork-branch DisputeEnter for
    /// `ledger_id`, validates the anchor against our local block oracle
    /// using the same predicate the receiver enforces (oracle confirms
    /// hash at the asserted height, height > the ledger's
    /// `quorum_expiry`), and on success returns
    /// `FraudProofType::QuorumExpired` so the cosigner's confiscation
    /// verifier can treat it as authoritative evidence — equivalent to
    /// finding a kind:9101 of the same proof type.
    ///
    /// Returns `None` if no fork-branch DisputeEnter is observed, the
    /// anchor fields are missing, or the oracle/expiry checks fail.
    pub(crate) async fn fetch_quorum_expired_inline_evidence(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use deposits_core::fraud::FraudProofType;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tlv::TlvDecode;
        use deposits_core::SignedLedgerUpdate;
        use nostr_sdk::{Filter, Kind};

        // 1. Fetch all kind:LEDGER_UPDATE events for this ledger
        //    — both main-chain (operator-authored) and fork-branch
        //    (disputant-authored). Paginated; bloated forks
        //    overflow a single 500-event window.
        let mut updates: Vec<SignedLedgerUpdate> =
            self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return None;
        }
        updates.sort_by_key(|u| (u.sequence_number, u.operator_id));

        // 2. The original operator owns sequence 0. Their main-chain
        //    QuorumBegin tells us the ledger's recorded quorum_expiry.
        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)?;
        let mut ledger_quorum_expiry: Option<u32> = None;
        for u in &updates {
            if u.operator_id != original_operator {
                continue;
            }
            if let Ok(LedgerOperation::QuorumBegin {
                quorum_expiry: e, ..
            }) = LedgerOperation::tlv_decode(&u.message)
            {
                // Latest QuorumBegin wins (rotation extends expiry).
                ledger_quorum_expiry = Some(e);
            }
        }
        let ledger_quorum_expiry = ledger_quorum_expiry?;

        // 3. Build a block oracle that consults our own wallet's
        //    chain view — same pattern as the inbound DisputeEnter
        //    receiver verification.
        struct WalletOracle<'a> {
            wallet: &'a crate::wallet::Wallet,
        }
        impl<'a> deposits_core::fraud::BlockOracle for WalletOracle<'a> {
            fn confirms(&self, h: &[u8; 32]) -> Option<u32> {
                self.wallet.confirms_block(h)
            }
        }
        let oracle = WalletOracle {
            wallet: &self.wallet,
        };

        // 4. Walk fork-branch updates and check each DisputeEnter that
        //    carries inline anchor evidence + reason=quorum_expired.
        //    One valid candidate is enough.
        for u in &updates {
            if u.operator_id == original_operator {
                continue;
            }
            let Ok(op) = LedgerOperation::tlv_decode(&u.message) else {
                continue;
            };
            let LedgerOperation::DisputeEnter {
                anchor_block_hash: Some(hash),
                anchor_block_height: Some(height),
                last_valid_sequence,
                reason,
                ..
            } = op
            else {
                continue;
            };
            if reason != "quorum_expired" {
                continue;
            }
            // Find the main-chain tip sequence (highest seq from the
            // original operator) to satisfy validate_*'s fork-point
            // predicate.
            let main_tip_seq = updates
                .iter()
                .filter(|u| u.operator_id == original_operator)
                .map(|u| u.sequence_number)
                .max()
                .unwrap_or(0);
            if deposits_core::operation_validation::validate_dispute_enter_quorum_expired(
                &hash,
                height,
                last_valid_sequence,
                ledger_quorum_expiry,
                main_tip_seq,
                &oracle,
            )
            .is_ok()
            {
                return Some(FraudProofType::QuorumExpired);
            }
        }
        None
    }

    /// Self-verifying inline evidence for an Equivocation confiscation —
    /// counterpart to [`fetch_quorum_expired_inline_evidence`]. Equivocation
    /// needs no embedding/causal-chain: the proof is the operator's own two
    /// conflicting updates, which are already durable on the relay (the
    /// operator broadcast both as kind:9100). We fetch the ledger's full
    /// history and look for the original operator double-signing — two updates
    /// at the same `sequence_number` with different `content_hash`, both
    /// bearing a valid operator signature and both following an update of this
    /// ledger (or opening it). One such pair is unrecoverable proof
    /// of misbehavior, so any cosigner can independently confirm a confiscation
    /// is grounded without trusting a third party.
    pub(crate) async fn fetch_equivocation_inline_evidence(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use deposits_core::fraud::FraudProofType;
        use deposits_core::SignedLedgerUpdate;

        let updates: Vec<SignedLedgerUpdate> =
            self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return None;
        }

        // The original operator owns sequence 0 — equivocation is *their*
        // double-signing (fork-branch updates from disputants don't count).
        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)?;

        // Two different signed updates at one sequence, both bound to this
        // ledger by the hash chain (ledger_id is signed by no one and the
        // operator's key may run other ledgers, so a relabelled update of
        // another ledger must not count). Confirmed by verify_equivocation.
        let seq = deposits_core::fraud::find_equivocation(&updates, &original_operator)?;
        tracing::info!(
            "Ledger {}: Equivocation by the original operator at seq {}",
            &ledger_id[..16.min(ledger_id.len())],
            seq
        );
        Some(FraudProofType::Equivocation)
    }

    /// Self-verifying inline evidence for a NonConformingCosignature confiscation
    /// — counterpart to [`fetch_equivocation_inline_evidence`]. The fault is a
    /// quorum-cosigned update that fails conformance: honest cosigners refuse
    /// such updates at cosign time, so a cosigned non-conforming update on the
    /// relay is proof the quorum colluded (or a cosigner is faulty). We fetch the
    /// ledger's history and find the fault in one pass
    /// (`find_non_conforming_cosignature`: one forward replay, the candidate
    /// confirmed by `verify_non_conforming_cosignature`), not one full replay
    /// per cosigned update. No embedding/9101 needed — the bad update is
    /// already durable on the relay.
    pub(crate) async fn fetch_non_conforming_cosig_inline_evidence(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use deposits_core::fraud::FraudProofType;
        use deposits_core::SignedLedgerUpdate;

        let mut updates: Vec<SignedLedgerUpdate> =
            self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return None;
        }
        updates.sort_by_key(|u| u.sequence_number);

        // Equivocation/non-conformance is the original operator's misbehavior.
        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)?;

        let (seq, governing_qb, reason) = deposits_core::fraud::find_non_conforming_cosignature(
            &updates,
            &original_operator,
            &deposits_core::dep16::Dep16Authorizer::new(),
        )?;
        tracing::info!(
            "Ledger {}: NonConformingCosignature at seq {} (governing QuorumBegin {}): {}",
            &ledger_id[..16.min(ledger_id.len())],
            seq,
            governing_qb,
            reason
        );
        Some(FraudProofType::NonConformingCosignature)
    }

    /// Self-verifying inline evidence for a `NonConformingUpdate` confiscation
    /// — the operator-signed, uncosigned counterpart to
    /// [`fetch_non_conforming_cosig_inline_evidence`]. The fault is an update
    /// the *original operator* BIP-340-signed that fails to chain onto the
    /// canonical tip (wrong `previous_hash`) or carries a bad `content_hash`,
    /// or that chains but breaks a rule (the state machine or conformance
    /// refuses it on the replayed canonical state). The first is what `recovery start`'s hash-chain scan detects and disputes via
    /// kind:9103; here the cosigner independently re-derives the fault from the
    /// relay's durable copy of the bad update so the confiscation is grounded
    /// without a separately-broadcast kind:9101. No embedding needed — the bad
    /// update is already on the relay.
    pub(crate) async fn fetch_non_conforming_update_inline_evidence(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use deposits_core::fraud::FraudProofType;
        use deposits_core::SignedLedgerUpdate;

        let mut updates: Vec<SignedLedgerUpdate> =
            self.fetch_all_ledger_updates_paginated(ledger_id).await;
        if updates.is_empty() {
            return None;
        }
        updates.sort_by_key(|u| u.sequence_number);

        // NonConformingUpdate is the *original operator's* unilateral fault
        // (fork-branch updates from disputants are signed by a different key
        // and are excluded by the operator_id binding in the verifier).
        let original_operator = updates
            .iter()
            .find(|u| u.sequence_number == 0)
            .map(|u| u.operator_id)?;

        // One linear pass (canonical rebuild, chain-break scan, one forward
        // replay), not a full verification per update: with the state-replay
        // verdict that would replay the whole history once per update. The
        // candidate it returns has passed verify_non_conforming_update.
        let (seq, reason) = deposits_core::fraud::find_non_conforming_update(
            &updates,
            &original_operator,
            &deposits_core::dep16::Dep16Authorizer::new(),
        )?;
        tracing::info!(
            "Ledger {}: NonConformingUpdate by the original operator at seq {}: {}",
            &ledger_id[..16.min(ledger_id.len())],
            seq,
            reason
        );
        Some(FraudProofType::NonConformingUpdate)
    }

    /// Auto-initiate confiscation when all participants are armed
    ///
    /// For each ledger where we're armed but confiscation hasn't happened yet,
    /// check if all participants have armed. If so, build the confiscation TX,
    /// request signatures from quorum members, and broadcast.
    pub(crate) async fn auto_confiscate(&self) {
        // Test/recovery hook: pair with the auto-arm pause so the
        // cooperative-refund Tier-3 test can manually orchestrate the
        // post-DisputeEnter flow without auto-confiscate racing it.
        if self.data_dir.join(".pause_auto_dispute_actions").exists() {
            return;
        }

        // Phase 1: Check for pending confiscations that need signature collection
        self.collect_confiscation_signatures().await;

        // DEP-03 §Confiscation ladder: push the scheduled rung of every confiscation we
        // assembled until one confirms.
        self.bump_confiscations().await;

        // Phase 2: Initiate new confiscations for armed ledgers that don't have one pending
        self.initiate_confiscations().await;
    }

    /// Non-blocking: collect signatures for pending confiscation requests and broadcast when ready.
    pub(crate) async fn collect_confiscation_signatures(&self) {
        use bitcoin::secp256k1::PublicKey;

        use nostr_sdk::{Filter, Kind};

        let prefixes: Vec<String> = {
            let pending = self.pending_confiscations.lock().unwrap();
            pending.keys().cloned().collect()
        };

        for prefix in prefixes {
            // Check timeout (120s) — drop stale requests so we can re-initiate
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if let Some(pc) = pending.get(&prefix) {
                    if pc.created_at.elapsed() > std::time::Duration::from_secs(120) {
                        tracing::warn!(
                            "Confiscation request for {} timed out, will re-initiate",
                            prefix
                        );
                        drop(pending);
                        self.pending_confiscations.lock().unwrap().remove(&prefix);
                        continue;
                    }
                }
            }

            // Fetch recent response events (non-blocking, single fetch)
            let (request_id, required_sigs) = {
                let pending = self.pending_confiscations.lock().unwrap();
                match pending.get(&prefix) {
                    Some(pc) => (pc.request_id.clone(), pc.required_sigs),
                    None => continue,
                }
            };

            let since = nostr_sdk::Timestamp::now() - 120;
            let filter = Filter::new()
                .kind(Kind::Custom(crate::nostr::KIND_LEDGER_RESPONSE))
                .since(since);

            let response_events = match self
                .nostr
                .client()
                .fetch_events(vec![filter], Some(std::time::Duration::from_secs(5)))
                .await
            {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Process responses and add signatures
            let mut ready_to_broadcast = false;
            {
                let mut pending = self.pending_confiscations.lock().unwrap();
                let pc = match pending.get_mut(&prefix) {
                    Some(pc) => pc,
                    None => continue,
                };

                for event in response_events.iter() {
                    let mut is_our_request = false;
                    for tag in event.tags.iter() {
                        if tag.kind()
                            == nostr_sdk::TagKind::SingleLetter(crate::nostr::TAG_EVENT_REF)
                        {
                            if let Some(val) = tag.content() {
                                if val == request_id {
                                    is_our_request = true;
                                    break;
                                }
                            }
                        }
                    }

                    if !is_our_request {
                        continue;
                    }

                    if let Ok(response) =
                        serde_json::from_str::<crate::nostr::LedgerResponse>(&event.content)
                    {
                        if response.success {
                            if let Some(result) = &response.result {
                                if let Some((signer, sigs)) =
                                    confiscation_response_signatures(result, &pc.rung_sighashes)
                                {
                                    if let std::collections::hash_map::Entry::Vacant(e) =
                                        pc.signatures.entry(signer)
                                    {
                                        e.insert(sigs);
                                        tracing::info!("  Confiscation {}: received signature from {}... ({}/{})",
                                            &prefix, &signer.to_string()[..16], pc.signatures.len(), required_sigs);
                                    }
                                }
                            }
                        }
                    }
                }

                if pc.signatures.len() >= required_sigs {
                    ready_to_broadcast = true;
                }
            }

            if ready_to_broadcast {
                self.broadcast_confiscation(&prefix).await;
            }
        }
    }

    /// Build witness and broadcast a confiscation transaction that has enough signatures.
    pub(crate) async fn broadcast_confiscation(&self, prefix: &str) {
        let pc = match self.pending_confiscations.lock().unwrap().remove(prefix) {
            Some(pc) => pc,
            None => return,
        };
        tracing::info!(
            "  Building witness with {} signatures for {}...",
            pc.signatures.len(),
            prefix
        );
        self.assemble_and_broadcast_confiscation(pc);
    }

    /// DEP-03 §Confiscation ladder: assemble every rung (the longest prefix) that has the tier's
    /// threshold of signatures, keep the ladder for rebroadcast, and broadcast the rung the
    /// schedule names.
    fn assemble_and_broadcast_confiscation(&self, pc: PendingConfiscation) {
        let control_block = match pc.taproot_output.control_block_for_tier(pc.tier_index) {
            Some(cb) => cb,
            None => {
                tracing::error!("Failed to get control block for tier");
                return;
            }
        };
        let mut assembled: Vec<bitcoin::Transaction> = Vec::new();
        for (i, rung) in pc.rungs.iter().enumerate() {
            let signers: std::collections::HashMap<bitcoin::secp256k1::PublicKey, &Vec<[u8; 64]>> =
                pc.signatures
                    .iter()
                    .filter_map(|(k, v)| v.get(i).map(|s| (*k, s)))
                    .collect();
            if signers.len() < pc.required_sigs {
                break;
            }
            let mut tx = rung.clone();
            for input in 0..tx.input.len() {
                tx.input[input].witness = tier_witness(
                    &pc.voter_set,
                    &signers
                        .iter()
                        .filter_map(|(k, v)| v.get(input).map(|s| (*k, *s)))
                        .collect(),
                    &pc.leaf_script,
                    &control_block,
                );
            }
            assembled.push(tx);
        }
        if assembled.is_empty() {
            tracing::error!(
                "Confiscation {}: only {} of {} signatures on rung 0",
                pc.ledger_prefix,
                pc.signatures.len(),
                pc.required_sigs
            );
            return;
        }
        let height = self.fresh_height();
        // The schedule counts from our first broadcast of this ladder.
        let h_c = match self
            .confiscation_ladders
            .lock()
            .unwrap()
            .get(&pc.ledger_prefix)
        {
            Some((prior, h))
                if prior.first().map(|t| t.compute_txid())
                    == assembled.first().map(|t| t.compute_txid()) =>
            {
                *h
            }
            _ => height.max(pc.h_c),
        };
        let i = ladder_rung_due(assembled.len(), h_c, height);
        self.broadcast_confiscation_rung(&assembled[i], &pc.ledger_prefix, i);
        tracing::info!("  Lottery address: {}", pc.lottery_address);
        self.confiscation_ladders
            .lock()
            .unwrap()
            .insert(pc.ledger_prefix.clone(), (assembled, h_c));
    }

    fn broadcast_confiscation_rung(&self, tx: &bitcoin::Transaction, prefix: &str, rung: usize) {
        // "Transaction already in block chain" or "already in mempool" from bitcoind means
        // another disputant got there first: the same happy path as a fresh broadcast.
        let broadcast_result = self.wallet.broadcast(tx);
        let txid = tx.compute_txid();
        let ok = match &broadcast_result {
            Ok(_) => true,
            Err(e) => {
                let msg = e.to_string();
                msg.contains("Transaction already in block chain")
                    || msg.contains("txn-already-in-mempool")
                    || msg.contains("Transaction already in mempool")
            }
        };
        if ok {
            tracing::info!(
                "Confiscation of {} broadcast, rung {}: {}",
                prefix,
                rung,
                txid
            );
        } else if let Err(e) = broadcast_result {
            tracing::error!(
                "Failed to broadcast confiscation of {} (rung {}): {}",
                prefix,
                rung,
                e
            );
        }
    }

    /// DEP-03 §Confiscation ladder: while no rung of a confiscation we assembled has confirmed,
    /// broadcast the rung the schedule names (a BIP-125 replacement of the one below). Once one
    /// confirms, the ladder is dropped.
    pub(crate) async fn bump_confiscations(&self) {
        let ladders: Vec<(String, Vec<bitcoin::Transaction>, u32)> = self
            .confiscation_ladders
            .lock()
            .unwrap()
            .iter()
            .map(|(k, (r, h))| (k.clone(), r.clone(), *h))
            .collect();
        let height = self.fresh_height();
        for (prefix, rungs, h_c) in ladders {
            let confirmed = rungs.iter().any(|r| {
                matches!(
                    self.wallet.get_outpoint_value_and_confs(r.compute_txid(), 0),
                    Ok(Some((_, c))) if c >= 1
                )
            });
            if confirmed {
                self.confiscation_ladders.lock().unwrap().remove(&prefix);
                continue;
            }
            let i = ladder_rung_due(rungs.len(), h_c, height);
            self.broadcast_confiscation_rung(&rungs[i], &prefix, i);
        }
    }

    /// Non-blocking: initiate confiscation for armed ledgers that don't already have a pending request.
    pub(crate) async fn initiate_confiscations(&self) {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        use bitcoin::secp256k1::{Keypair, Message, PublicKey, XOnlyPublicKey};
        use bitcoin::sighash::{SighashCache, TapSighashType};
        use bitcoin::{Amount, Transaction, TxIn, TxOut, Witness};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::{
            SignedLedgerUpdate, TapscriptReservesBuilder, ThresholdConfig, TlvDecode, VoterSet,
        };

        use nostr_sdk::{Filter, Kind};
        use std::collections::HashMap;

        use deposits_signer_api::{SigPurpose, SignContext};
        let our_pubkey = self.node_id;

        // Enumerate disputes we're armed for by scanning fork-branch
        // ledgers in `DisputeState::Armed`. The fork's state is the
        // authoritative signal — no separate marker file needed.
        //
        // Ownership predicate: `parent_pubkey == our_pubkey`. A fork's
        // `operator_key` is inherited from the original (the accused
        // operator) and never changes; `parent_pubkey` is what
        // `auto_arm_for_dispute_with_anchor` sets to the disputer's
        // key when it publishes DisputeEnter on the fork. The same
        // predicate is used in `inbound.rs` to detect "our fork."
        // Using `operator_key()` here would always be false for any
        // disputer-owned fork, silently disabling auto-confiscate.
        let armed_ledger_ids: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter_map(|(key, arc)| {
                    if key.len() <= 64 {
                        return None;
                    }
                    let l = arc.read().unwrap();
                    if l.state.parent_pubkey != our_pubkey {
                        return None;
                    }
                    if l.state.dispute_state != deposits_core::types::DisputeState::Armed {
                        return None;
                    }
                    Some(key[..64].to_string())
                })
                .collect()
        };

        for ledger_id in armed_ledger_ids {
            let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];

            // Skip if we've already revealed (cache or relay query) —
            // reveal happens after confiscation, so this implies the
            // chain side is already past us. We do *not* short-circuit
            // on a separate "confiscated" signal here: the reserves
            // UTXO lookup at `find_utxo_for_script` below returns None
            // when the confiscation TX has already spent it, which is
            // the authoritative chain-side fallback.
            if self.have_revealed_lottery(&ledger_id).await {
                continue;
            }

            // Skip if we already have a pending confiscation for this ledger, or an assembled
            // ladder that bump_confiscations is pushing.
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if pending.contains_key(ledger_prefix)
                    || self
                        .confiscation_ladders
                        .lock()
                        .unwrap()
                        .contains_key(ledger_prefix)
                {
                    continue;
                }
            }

            tracing::debug!(
                "Checking if confiscation ready for ledger {}...",
                ledger_prefix
            );

            // Resolve the fork-branch tracking key (or fall back to
            // the original ledger key) for downstream `handler.ledgers`
            // lookups that need the in-memory fork's chain hash etc.
            let ledger_key = self
                .handler
                .find_our_fork(&ledger_id)
                .unwrap_or_else(|| ledger_id.clone());

            // Use the slow relay client for historical fetch
            // Paginated relay fetch — bloated forks would
            // otherwise hide DisputeArmed at the tail beyond a
            // single 500-event window.
            let paginated_updates: Vec<SignedLedgerUpdate> = self
                .fetch_all_ledger_updates_paginated(ledger_id.as_str())
                .await;
            if paginated_updates.is_empty() {
                continue;
            }
            // DEP-03 §"The dispute": only the current dispute's DisputeEnters and arms count.
            let paginated_updates =
                deposits_core::rotation_order::dispute_scope(&paginated_updates);

            // Extract DisputeArmed participants, quorum members, and reserves info.
            //
            // The voter set committed in the on-chain Taproot UTXO is exactly
            // what the operator put in the latest `QuorumBegin.quorum_members`
            // — that's the canonical source. Inferring it from QuorumAddMember
            // updates was unreliable: forks rebroadcast the operator's history
            // alongside their own additions; even with the patch that retags
            // fork additions to the forker's pubkey, dispute-time noise (e.g.
            // late QuorumJoin records, multi-fork interactions) added stray
            // members and broke the Taproot reconstruction with a
            // "Witness program hash mismatch".
            let mut quorum_members: Vec<PublicKey> = Vec::new();
            let mut reserves_address: Option<String> = None;
            let mut ledger_hash: Option<[u8; 32]> = None;
            let mut original_operator: Option<PublicKey> = None;
            let mut latest_quorum_begin_seq: Option<u64> = None;
            let mut quorum_expiry_at_qb: u32 = 0;
            let mut ruleset_at_qb: Option<String> = None;
            let mut feerate_at_qb: Option<u32> = None;
            let mut collateral_at_qb: u64 = 0;
            let mut armed_heights: HashMap<XOnlyPublicKey, u32> = HashMap::new();

            for update in &paginated_updates {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    match op {
                        LedgerOperation::LedgerOpen {
                            operator_id,
                            reserves_id,
                            ..
                        } => {
                            original_operator = Some(operator_id);
                            // Use LedgerOpen reserves_id as fallback if no QuorumBegin
                            if reserves_address.is_none() {
                                reserves_address = Some(reserves_id);
                            }
                        }
                        LedgerOperation::QuorumBegin {
                            reserves_id,
                            ledger_hash: lh,
                            quorum_members: qm,
                            quorum_expiry,
                            protocol_version,
                            reference_feerate,
                            collateral_amount,
                            ..
                        } => {
                            // Keep the latest QuorumBegin (highest sequence) since
                            // multiple rotations may exist on the relay.
                            let seq = update.sequence_number;
                            if latest_quorum_begin_seq.map(|cur| seq > cur).unwrap_or(true) {
                                latest_quorum_begin_seq = Some(seq);
                                reserves_address = Some(reserves_id);
                                ledger_hash = Some(lh);
                                // Local var is Vec<PublicKey> for downstream
                                // Taproot reconstruction; extract just the keys.
                                quorum_members = qm.into_iter().map(|m| m.pubkey).collect();
                                quorum_expiry_at_qb = quorum_expiry;
                                ruleset_at_qb = protocol_version;
                                feerate_at_qb = reference_feerate;
                                collateral_at_qb = collateral_amount;
                            }
                        }
                        LedgerOperation::DisputeArmed { armed_block, .. } => {
                            let x_only = update.operator_id.x_only_public_key().0;
                            // Each armer's first arm (a re-arm repeats it).
                            let h = armed_heights.entry(x_only).or_insert(armed_block);
                            *h = (*h).min(armed_block);
                        }
                        _ => {}
                    }
                }
            }

            // Need at least 2 armers to proceed
            if armed_heights.is_empty() {
                tracing::debug!(
                    "Not enough DisputeArmed participants yet ({}/2)",
                    armed_heights.len()
                );
                continue;
            }

            let original_operator = match original_operator {
                Some(op) => op,
                None => {
                    tracing::debug!(
                        "Could not find original operator (LedgerOpen) for {}",
                        ledger_prefix
                    );
                    continue;
                }
            };
            let reserves_address_str = match reserves_address {
                Some(addr) => addr,
                None => {
                    tracing::debug!("Could not find reserves address for {}", ledger_prefix);
                    continue;
                }
            };
            // ledger_hash comes from QuorumBegin; fall back to fork's current hash
            let ledger_hash_val = match ledger_hash {
                Some(lh) => lh,
                None => {
                    // No QuorumBegin found — use the fork ledger's current hash
                    let ledgers = self.handler.ledgers.lock().unwrap();
                    if let Some(fork_arc) = ledgers.get(&ledger_key) {
                        let fork = fork_arc.read().unwrap();
                        fork.state.chain_tip_hash
                    } else {
                        tracing::debug!("Could not find ledger hash for {}", ledger_prefix);
                        continue;
                    }
                }
            };

            // Filter out original operator from quorum_members (VoterSet adds operator as tie_breaker)
            quorum_members.retain(|pk| *pk != original_operator);

            // DEP-03 eligibility cut: armers whose replacement collateral
            // fails are excluded from the lottery rather than stalling it.
            let armer_set: super::armers::ArmerSet;
            // DEP-03 §Grounded arms: each disputant's grounds, judged before the cut.
            let grounds = self.grounds_verdicts(&paginated_updates).await;
            let participants: Vec<LotteryParticipant> =
                match super::armers::eligible_armers_grounded(
                    &*self.wallet.chain_backend(),
                    &paginated_updates,
                    None,
                    &grounds,
                ) {
                    Ok(set) if !set.participants.is_empty() => {
                        // The set and E, comparable with cl-deposits' "participants of" line.
                        tracing::info!(
                            "lottery participants of {} at snapshot {}: [{}]; excluded: [{}]",
                            ledger_prefix,
                            set.snapshot,
                            set.participants
                                .iter()
                                .map(|a| a.key.to_string()[..16].to_string())
                                .collect::<Vec<_>>()
                                .join(" "),
                            set.excluded
                                .iter()
                                .map(|(a, why)| format!("{} ({})", &a.key.to_string()[..16], why))
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        armer_set = set.clone();
                        set.lottery_participants()
                    }
                    Ok(set) => {
                        tracing::info!(
                            "Only {} of {} armers of ledger {} are lottery participants; waiting",
                            set.participants.len(),
                            armed_heights.len(),
                            ledger_prefix
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::debug!("Lottery participants for {}: {}", ledger_prefix, e);
                        continue;
                    }
                };
            tracing::info!("{} of {} armers are lottery participants for ledger {}..., initiating confiscation ({} quorum members)",
                participants.len(), armed_heights.len(), ledger_prefix, quorum_members.len());

            // Build recovery voters (quorum minus original operator)
            // DEP-06: the recovery voters of the vault's governing QuorumBegin (≤ the fork point).
            let Some((recovery_voters, recovery_threshold)) =
                super::armers::lottery_voters_with(&paginated_updates, &grounds)
            else {
                tracing::debug!(
                    "No QuorumBegin by the original operator at or before the fork point of {}",
                    ledger_prefix
                );
                continue;
            };

            tracing::info!(
                "lottery inputs (proposer) for {}: {}",
                ledger_prefix,
                lottery_inputs_line(&participants, &recovery_voters, recovery_threshold)
            );
            // Build the lottery output
            let lottery_builder = LotteryScriptBuilder::new(
                participants.clone(),
                recovery_voters,
                recovery_threshold,
                self.wallet.network(),
            );

            let lottery_output = match lottery_builder.build() {
                Ok(out) => out,
                Err(e) => {
                    tracing::error!("Failed to build lottery output: {:?}", e);
                    continue;
                }
            };

            tracing::info!("  Lottery address: {}", lottery_output.address);

            // Look up reserves UTXO
            let reserves_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
                match reserves_address_str.parse() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
            let reserves_addr = match reserves_addr.require_network(self.wallet.network()) {
                Ok(a) => a,
                Err(_) => continue,
            };

            let script_pubkey = reserves_addr.script_pubkey();
            let utxo = match self.wallet.vault_utxo_rungs(
                &deposits_core::rotation_order::vault_rungs_at_fork(&paginated_updates),
                &script_pubkey,
            ) {
                Ok(Some(u)) => u,
                Ok(None) => {
                    tracing::debug!("No unspent reserves UTXO found");
                    continue;
                }
                Err(_) => continue,
            };

            let (reserves_outpoint, reserves_amount) = utxo;
            tracing::info!(
                "  Found reserves: {} sats at {}",
                reserves_amount,
                reserves_outpoint
            );

            // Build confiscation transaction.
            //
            // Shape depends on the fraud proof type:
            //
            // - **Punitive** (default; e.g. UncreditedLightning): full UTXO →
            //   single lottery output. Cosigners split the proceeds via the
            //   recovery threshold, operator forfeits everything.
            // - **Respectful** (currently only `QuorumExpired`): bifurcated.
            //   Lottery output gets `max(obligations, P2WSH_DUST)` — enough
            //   for the lottery winner to inherit deposit obligations — and
            //   the rest returns to the original operator's P2WPKH (DEP-03
            //   §"Respectful confiscation tx"). Falls back to punitive shape
            //   if the change side would be dust.
            //
            // The proof type comes from either:
            //   1. a kind:9101 fraud broadcast on the relay, or
            //   2. (deadline-miss only) a fork-branch DisputeEnter with
            //      reason="quorum_expired" + inline anchor evidence.
            // We must agree with the cosigner's verifier on which shape
            // to build — they consult both paths in the same order. If
            // we built a punitive (1-output) tx but the cosigner read
            // the inline evidence as QuorumExpired (respectful → 2
            // outputs), the cosign refuses on tx-shape mismatch.
            // DEP-03 §"Confiscation fee": deterministic, so every cosigner builds the same tx.
            let fee = deposits_core::tapscript_reserves::confiscation_fee_sats(
                quorum_members.len() + 1,
                deposits_core::tapscript_reserves::CONFISCATION_DEFAULT_FEERATE_SAT_VB,
            );
            let proof_type = match self.fetch_fraud_proof_type_for_ledger(&ledger_id).await {
                Some(pt) => Some(pt),
                None => match self.fetch_quorum_expired_inline_evidence(&ledger_id).await {
                    Some(pt) => Some(pt),
                    None => match self.fetch_equivocation_inline_evidence(&ledger_id).await {
                        Some(pt) => Some(pt),
                        None => {
                            self.fetch_non_conforming_cosig_inline_evidence(&ledger_id)
                                .await
                        }
                    },
                },
            };
            let is_respectful = match grounds.respectful() {
                // DEP-03 §Grounded arms: the shape from the grounded DisputeEnters alone.
                Some(Ok(r)) => r,
                Some(Err(e)) => {
                    tracing::info!("Confiscation of {}: {}; waiting", ledger_prefix, e);
                    continue;
                }
                None => proof_type.map(|pt| pt.is_respectful()).unwrap_or(false),
            };

            let obligations_sats = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(&ledger_key)
                    .map(|arc| {
                        // total_deposit_balance is in msats; round down to sats.
                        arc.read().unwrap().state.total_deposit_balance() / 1000
                    })
                    .unwrap_or(0)
            };

            // DEP-06 §Confiscation obligations: sweep the migration outputs at the vault's
            // script and splice out the owed entries (the lottery output stays output 0).
            let obligations = match super::armers::confiscation_obligations(
                &*self.wallet.chain_backend(),
                &paginated_updates,
                &armer_set,
            ) {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!("Confiscation obligations for {}: {}", ledger_prefix, e);
                    continue;
                }
            };
            let _ = fee;
            // DEP-03 §On-Chain State Anchor: the chain hash at the dispute's fork point.
            let Some(anchor) = deposits_core::rotation_order::dispute_anchor(&paginated_updates)
            else {
                tracing::error!(
                    "Confiscation of {}: no DisputeEnter to anchor it",
                    ledger_prefix
                );
                continue;
            };
            // DEP-03 §Confiscation ladder: the nLockTime is the tier's (set below, before the
            // ladder is built from these parameters).
            let mut ladder_params = deposits_core::tapscript_reserves::ConfiscationTxParams {
                vault: (reserves_outpoint, reserves_amount),
                swept: obligations.swept.clone(),
                lottery_spk: lottery_output.script_pubkey(),
                voters: quorum_members.len() + 1,
                lock_time: 0,
                respectful: is_respectful,
                obligations_sats,
                residue_sats: obligations.residue_sats,
                splice_outs: obligations.splice_outs.clone(),
                operator: original_operator,
                anchor,
                feerate_sat_vb: deposits_core::tapscript_reserves::confiscation_feerate(
                    feerate_at_qb,
                ),
            };

            // Build the Taproot reserves structure for signing using
            // the ruleset that the disputed ledger committed to in
            // its latest QuorumBegin. Reconstructing under any other
            // ruleset would produce the wrong scriptPubKey.
            let voter_set = VoterSet::new(original_operator, quorum_members.clone());
            let voter_count = voter_set.all_voters().len();
            let ruleset = deposits_core::ruleset::resolve_or_current(ruleset_at_qb.as_deref());
            let threshold_config = (ruleset.tier_config_factory)(voter_count, quorum_expiry_at_qb);

            let taproot_builder = TapscriptReservesBuilder::new(
                voter_set.clone(),
                threshold_config.clone(),
                self.wallet.network(),
                ledger_hash_val,
            );

            let taproot_output = match taproot_builder.build() {
                Ok(out) => out,
                Err(e) => {
                    tracing::error!("Failed to build Taproot output: {:?}", e);
                    continue;
                }
            };

            // Diagnostic: confirm the reconstructed Taproot script_pubkey
            // matches the on-chain reserves UTXO. A mismatch here is the
            // root cause of `Witness program hash mismatch` at broadcast,
            // and indicates the reconstruction inputs (voter_set,
            // ledger_hash, threshold_config) drifted from what was used
            // when the rotation tx was built.
            {
                let reconstructed = taproot_output.script_pubkey();
                let on_chain = reserves_addr.script_pubkey();
                if reconstructed != on_chain {
                    tracing::warn!(
                        "Confiscation Taproot mismatch for ledger {}: \
                         reconstructed={}, on-chain={}, voter_count={}, \
                         ledger_hash={}, original_operator={}, members=[{}]",
                        ledger_prefix,
                        hex::encode(reconstructed.as_bytes()),
                        hex::encode(on_chain.as_bytes()),
                        voter_count,
                        hex::encode(ledger_hash_val),
                        hex::encode(original_operator.serialize()),
                        quorum_members
                            .iter()
                            .map(|m| hex::encode(&m.serialize()[..8]))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                }
            }

            // DEP-06 §Phase 2: recovery-quorum cosign threshold
            // cascades through the DEP-05 §Lifecycle tiers. Pick the
            // highest-numbered non-tie-breaker tier whose CLTV is
            // satisfied at the current chain tip. Higher = more
            // degraded = fewer recovery-quorum sigs required. Skip
            // requires_tie_breaker (operator-alone), which the
            // recovery quorum can't satisfy by definition.
            let current_height = self.wallet.get_block_height().ok().unwrap_or(0);
            let (tier_index, tier) = {
                let mut chosen: Option<(usize, &deposits_core::tapscript_reserves::ThresholdTier)> =
                    None;
                for (idx, t) in threshold_config.tiers.iter().enumerate() {
                    if t.requires_tie_breaker {
                        continue; // Tier 3 — operator only, recovery quorum can't sign
                    }
                    if current_height < t.timelock_blocks {
                        continue; // CLTV not yet satisfied
                    }
                    chosen = Some((idx, t));
                }
                match chosen {
                    Some((idx, t)) => (idx, t.clone()),
                    None => {
                        tracing::error!(
                            "No usable confiscation tier at chain tip {} \
                             (quorum_expiry={}, ruleset={})",
                            current_height,
                            quorum_expiry_at_qb,
                            ruleset.name,
                        );
                        continue;
                    }
                }
            };

            tracing::info!(
                "  Using Tier {} for confiscation (threshold={}/{}, lock_time={})",
                tier_index,
                tier.threshold,
                voter_count,
                tier.timelock_blocks,
            );

            // The nLockTime is the tier's CLTV target. Tier 0 has timelock_blocks=0. Tier 1+
            // require nLockTime ≥ quorum_expiry + offset so the OP_CLTV in the tier's leaf
            // script is satisfied.
            ladder_params.lock_time = tier.timelock_blocks;
            let rungs = deposits_core::tapscript_reserves::build_confiscation_ladder(
                &ladder_params,
                collateral_at_qb,
            );
            let confiscation_tx = rungs[0].clone();
            // DEP-03 §Confiscation ladder: the broadcast schedule counts from our first broadcast
            // (set when the rungs are assembled).
            let h_c = 0u32;

            // Build leaf script and compute sighash
            let leaf_script = match taproot_builder.build_threshold_leaf(&tier) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to build leaf script: {:?}", e);
                    continue;
                }
            };

            let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                &leaf_script,
                bitcoin::taproot::LeafVersion::TapScript,
            );

            let mut prevouts = vec![TxOut {
                value: Amount::from_sat(reserves_amount),
                script_pubkey: reserves_addr.script_pubkey(),
            }];
            prevouts.extend(obligations.swept.iter().map(|(_, sats)| TxOut {
                value: Amount::from_sat(*sats),
                script_pubkey: reserves_addr.script_pubkey(),
            }));
            // Per rung: one sighash per input (input 0 the vault, then the swept outputs), same leaf.
            let rung_sighashes: Vec<Vec<[u8; 32]>> = match rungs
                .iter()
                .map(|r| {
                    let mut c = SighashCache::new(r);
                    (0..r.input.len())
                        .map(|i| {
                            c.taproot_script_spend_signature_hash(
                                i,
                                &bitcoin::sighash::Prevouts::All(&prevouts),
                                leaf_hash,
                                TapSighashType::Default,
                            )
                            .map(|h| *h.as_ref())
                        })
                        .collect::<Result<Vec<[u8; 32]>, _>>()
                })
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("Failed to compute confiscation sighash: {}", e);
                    continue;
                }
            };
            let sighash_bytes: [u8; 32] = rung_sighashes[0][0];
            let sweep_sighashes: Vec<[u8; 32]> = rung_sighashes[0][1..].to_vec();

            // Sign every rung with our key — Taproot script-spend.
            let ours: Result<Vec<Vec<[u8; 64]>>, _> = rung_sighashes
                .iter()
                .map(|hs| {
                    hs.iter()
                        .map(|h| {
                            self.handler
                                .signer
                                .bip340_sign(&SignContext::no_ledger(SigPurpose::OnchainSighash), h)
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect();
            let ours = match ours {
                Ok(o) => o,
                Err(e) => {
                    tracing::error!("Confiscation sighash sign failed: {}", e);
                    continue;
                }
            };
            let mut signatures: HashMap<PublicKey, Vec<Vec<[u8; 64]>>> = HashMap::new();
            signatures.insert(our_pubkey, ours);

            tracing::info!("  Signed {} rungs with our key", rungs.len());

            // Request signatures from other quorum members via Nostr
            let required_sigs = tier.threshold;
            tracing::info!(
                "  Need {}/{} signatures, requesting co-signatures...",
                required_sigs,
                voter_count
            );

            // If we already have enough signatures (e.g., threshold=1), assemble and broadcast
            // immediately.
            if signatures.len() >= required_sigs {
                let pc = PendingConfiscation {
                    request_id: String::new(),
                    rungs: rungs.clone(),
                    rung_sighashes: rung_sighashes.clone(),
                    signatures,
                    required_sigs,
                    voter_set,
                    tier_index,
                    leaf_script,
                    taproot_output,
                    lottery_address: lottery_output.address.to_string(),
                    ledger_prefix: ledger_prefix.to_string(),
                    created_at: std::time::Instant::now(),
                    h_c,
                };
                tracing::info!("  Broadcasting confiscation (enough sigs locally)...");
                self.assemble_and_broadcast_confiscation(pc);
                continue;
            }

            // Send the request and store pending state (non-blocking)
            let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&confiscation_tx);
            let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);
            let unsigned_rungs: Vec<String> = rungs
                .iter()
                .map(|r| hex::encode(bitcoin::consensus::encode::serialize(r)))
                .collect();

            // Pull last_valid_sequence out of the fork compound key
            // (format `{ledger_id:64}_{fork_seq:06}_{op_prefix:16}`).
            // Cosigners use it to replay the disputed ledger to the
            // divergence point and verify each disputant's
            // `replacement_collateral` declaration before signing
            // (DEP-03 §"Replacement collateral declaration").
            let last_valid_sequence: Option<u64> = if ledger_key.len() == 88 {
                ledger_key.get(65..71).and_then(|s| s.parse::<u64>().ok())
            } else {
                None
            };

            let request_params = serde_json::json!({
                "ledger_id": ledger_id,
                "sighash": hex::encode(sighash_bytes),
                "unsigned_tx": unsigned_tx_hex,
                "lottery_address": lottery_output.address.to_string(),
                "violation_details": "Confiscation to lottery for dispute resolution",
                "last_valid_sequence": last_valid_sequence,
                // DEP-06 §Phase 2: tier_index lets the cosigner-side
                // rebuild the matching leaf for sighash verification.
                // Without this, cosigners would default to the
                // first-non-tie-breaker-tier-with-threshold>1 fallback
                // and miss when we're rotating at a degraded tier.
                "tier_index": tier_index,
                // DEP-06: one signature per swept migration output (inputs 1..)
                "sweep_sighashes": sweep_sighashes.iter().map(hex::encode).collect::<Vec<_>>(),
                // DEP-03 §Confiscation ladder: every rung, rung 0 first
                "unsigned_rungs": unsigned_rungs,
            });

            let request_id = match self
                .nostr
                .send_ledger_request(&ledger_id, "confiscation_sign", request_params)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("Failed to send sign request: {:?}", e);
                    continue;
                }
            };
            self.track_sent_event(&request_id);

            tracing::info!(
                "  Sent confiscation_sign request {}..., will collect signatures on next cycle",
                &request_id[..16.min(request_id.len())]
            );

            // Store pending state — signatures will be collected on subsequent periodic cycles
            let pending = PendingConfiscation {
                request_id,
                rungs: rungs.clone(),
                rung_sighashes,
                signatures,
                required_sigs,
                voter_set,
                tier_index,
                leaf_script,
                taproot_output,
                lottery_address: lottery_output.address.to_string(),
                ledger_prefix: ledger_prefix.to_string(),
                created_at: std::time::Instant::now(),
                h_c,
            };

            {
                use bitcoin::hashes::Hash;
                let mut known = self.known_confiscation_txids.lock().unwrap();
                for r in &pending.rungs {
                    known.insert(r.compute_txid().to_byte_array());
                }
            }
            self.pending_confiscations
                .lock()
                .unwrap()
                .insert(ledger_prefix.to_string(), pending);
            // DEP-03 §Arm manifests: the arm set we proposed from.
            for r in &rungs {
                self.publish_confiscation_manifest(&ledger_id, r, None)
                    .await;
            }
        }
    }

    /// Auto-reveal preimage when confiscation TX has 3+ confirmations
    ///
    /// For each ledger where we're armed but haven't revealed yet,
    /// check if the lottery UTXO exists with 3+ confirmations.
    pub(crate) async fn auto_reveal_on_confiscation(&self) {
        // Enumerate disputes by scanning fork-branch ledgers in Armed
        // state where we are the disputant. The fork's
        // `state.dispute_state == Armed` is the authoritative signal
        // that we have a preimage to reveal (derived deterministically
        // on demand, or read from a legacy `.hex` if one exists).
        let armed_ledger_ids: Vec<String> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter_map(|(key, arc)| {
                    if key.len() <= 64 {
                        return None;
                    }
                    let l = arc.read().unwrap();
                    // See `auto_lottery_claim_or_yield`: a dispute fork
                    // inherits the original operator's `operator_key`, so
                    // ownership must key on `parent_pubkey` (set to the
                    // disputer) — matching `initiate_confiscations`. Using
                    // `operator_key()` here skipped the disputer's own fork
                    // and the confiscation-confirmed reveal never fired.
                    if l.state.parent_pubkey != self.node_id {
                        return None;
                    }
                    if l.state.dispute_state != deposits_core::types::DisputeState::Armed {
                        return None;
                    }
                    Some(key[..64].to_string())
                })
                .collect()
        };

        for ledger_id in armed_ledger_ids {
            // Skip if already revealed. `auto_reveal_preimage` would
            // also short-circuit, but checking here saves a (~slow)
            // confirmation-depth Esplora query for already-resolved
            // disputes.
            if self.have_revealed_lottery(&ledger_id).await {
                continue;
            }

            // Check if confiscation TX is confirmed with 3+ blocks
            match self.check_confiscation_confirmed(&ledger_id, 3).await {
                Ok(true) => {
                    tracing::info!(
                        "Confiscation TX confirmed +3 for ledger {}. Auto-revealing preimage.",
                        &ledger_id[..16]
                    );
                    self.auto_reveal_preimage(&ledger_id).await;
                }
                Ok(false) => {
                    // Not yet confirmed enough
                }
                Err(e) => {
                    tracing::debug!(
                        "Could not check confiscation for {}: {}",
                        &ledger_id[..16],
                        e
                    );
                }
            }
        }
    }

    /// Check if the confiscation TX for a ledger has enough confirmations
    pub(crate) async fn check_confiscation_confirmed(
        &self,
        ledger_id: &str,
        min_confirmations: u32,
    ) -> Result<bool, Error> {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryParticipant, LotteryScriptBuilder};
        use deposits_core::TlvDecode;

        // Paginated relay fetch — bloated forks would otherwise
        // hide DisputeArmed at the tail beyond a single 500-event
        // window.
        // DEP-03 §When the set is final: a DisputeEnter above the confiscation's block takes no
        // part, in the voters below as in the armer set.
        let fetched = self.fetch_lottery_updates(ledger_id).await;
        let confiscated_at =
            super::lottery_recovery::confiscation_height(&*self.wallet.chain_backend(), &fetched);
        let paginated_updates =
            deposits_core::rotation_order::dispute_scope_final(&fetched, confiscated_at);
        if paginated_updates.is_empty() {
            return Err(Error::Protocol(
                "Failed to fetch ledger updates from relay".to_string(),
            ));
        }

        // Participants: the DEP-03 eligibility cut, the set the confiscation
        // was built with. The recovery-voter set is derived separately (below)
        // from the latest QuorumBegin so the reconstructed lottery address
        // matches the one the confiscation TX paid.
        let participants: Vec<LotteryParticipant> = self
            .lottery_armer_set(ledger_id)
            .await
            .map_err(Error::Protocol)?
            .lottery_participants();
        if participants.is_empty() {
            return Err(Error::Protocol(
                "Not enough participants for lottery".to_string(),
            ));
        }

        // Recovery voters = latest-QuorumBegin members minus operator.
        // MUST match `initiate_confiscations` (the on-chain payer), or the
        // rebuilt lottery address won't find the confiscation UTXO and we
        // never trigger the reveal.
        let (recovery_voters, recovery_threshold) =
            Box::pin(self.lottery_voters(&paginated_updates))
                .await
                .ok_or_else(|| {
                    Error::Protocol(
                        "No QuorumBegin/LedgerOpen found to derive recovery voters".to_string(),
                    )
                })?;

        let lottery_builder = LotteryScriptBuilder::new(
            participants,
            recovery_voters,
            recovery_threshold,
            self.wallet.network(),
        );

        let lottery_output = lottery_builder
            .build()
            .map_err(|e| Error::Protocol(format!("Failed to build lottery output: {:?}", e)))?;

        tracing::debug!(
            "check_confiscation_confirmed: lottery address = {}",
            lottery_output.address
        );

        // The confiscation that spent this dispute's vault, and its output 0 if it pays this
        // lottery: by outpoint, not "a UTXO at the lottery's script", which another dispute
        // with the same participants and quorum also pays (regtest 2026-11-20).
        let lottery_script = lottery_output.address.script_pubkey();
        let Some(outpoint) = super::lottery_recovery::landed_lottery_outpoint(
            &*self.wallet.chain_backend(),
            &paginated_updates,
        ) else {
            return Ok(false); // not confiscated yet (or the search has not reached it)
        };
        let confs = match self
            .wallet
            .unspent_output_paying(outpoint, &lottery_script)?
        {
            Some((_value, c)) => c,
            None => return Ok(false),
        };
        Ok(confs >= min_confirmations)
    }

    /// Auto-rotate to quorum and continue ledger after winning
    pub(crate) async fn auto_post_win_cleanup(&self) {
        // Find completed marker files (lottery finished, we might have won)
        let entries = match std::fs::read_dir(&self.data_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let completed_markers: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.starts_with("lottery_completed_") && name.ends_with(".marker")
            })
            .collect();

        for entry in completed_markers {
            let filename = entry.file_name().to_string_lossy().to_string();
            let ledger_prefix = filename
                .strip_prefix("lottery_completed_")
                .and_then(|s| s.strip_suffix(".marker"))
                .unwrap_or("");

            if ledger_prefix.is_empty() {
                continue;
            }

            // Skip if already rotated
            let rotated_marker = self
                .data_dir
                .join(format!("lottery_rotated_{}.marker", ledger_prefix));
            if rotated_marker.exists() {
                continue;
            }

            // Find the fork or original ledger key (prefer fork for dispute operations)
            let ledger_key = match self.find_fork_or_original_by_prefix(ledger_prefix) {
                Some(key) => key,
                None => continue,
            };

            // Extract the base ledger_id (first 64 chars) for Nostr queries
            let ledger_id = if ledger_key.len() > 64 {
                ledger_key[..64].to_string()
            } else {
                ledger_key.clone()
            };

            // Check if we won (we published DisputeAcquire)
            match self.check_if_we_won(&ledger_id).await {
                Ok(true) => {
                    tracing::info!(
                        "We won lottery for {}. Auto-rotating to quorum...",
                        &ledger_id[..16]
                    );

                    // Promote our resolved fork to BE the base ledger so the
                    // daemon operates it as the new custodian and can serve
                    // `deposit_open` (which resolves by base ledger_id). Without
                    // this the winner keeps the stale joined base entry (old
                    // operator, still disputed) and the recovered ledger stays
                    // unserviceable despite the on-chain win + published
                    // DisputeAcquire.
                    match self.handler.promote_dispute_fork_to_base(&ledger_id) {
                        Ok(true) => {
                            // The base entry's Arc (and thus operator_key) just
                            // changed to us. Drop any stale `is_operator_of_ledger`
                            // cache entry keyed to the pre-promotion (joined)
                            // ledger, or the deposit-open gate would keep
                            // dropping requests as `not_operator` despite the
                            // custody transfer.
                            self.operator_of_cache.lock().unwrap().remove(&ledger_id);
                            // Rebind the actor to the promoted base Arc. Even
                            // though promotion overwrites the current map Arc in
                            // place, the live actor may hold an EARLIER Arc that
                            // a prior `reimport_joined_ledger` purge+reinsert
                            // orphaned from the map — respawning guarantees the
                            // single writer commits against the resolved state
                            // (correct next sequence), not a stale seq-5 copy.
                            self.respawn_actor_for(&ledger_id);
                            tracing::info!(
                                "Now operating base ledger {} as new custodian",
                                &ledger_id[..16]
                            );
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(
                                "Failed to promote fork for {}: {}",
                                &ledger_id[..16],
                                e
                            );
                        }
                    }

                    // Auto-rotate
                    match self.auto_rotate_to_quorum(&ledger_id).await {
                        Ok(()) => {
                            // Mark as rotated
                            let _ = std::fs::write(&rotated_marker, "rotated");
                            tracing::info!("Rotation complete for {}", &ledger_id[..16]);

                            // Auto-continue
                            if let Err(e) = self.auto_continue_ledger(&ledger_id).await {
                                tracing::warn!("Auto-continue failed: {}", e);
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Auto-rotate failed for {}: {}", &ledger_id[..16], e);
                        }
                    }
                }
                Ok(false) => {
                    // We didn't win, nothing to do
                    let _ = std::fs::write(&rotated_marker, "not_winner");
                }
                Err(e) => {
                    tracing::debug!("Could not check win status for {}: {}", &ledger_id[..16], e);
                }
            }
        }
    }

    /// Check if we won the lottery for a ledger (we published DisputeAcquire)
    pub(crate) async fn check_if_we_won(&self, ledger_id: &str) -> Result<bool, Error> {
        use crate::nostr::KIND_LEDGER_UPDATE;
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;

        use nostr_sdk::{Filter, Kind};

        let our_pubkey = self.node_id;

        // Fast, race-free path: consult our OWN local fork first. When we win,
        // `claim_lottery` applies + persists the DisputeAcquire to the fork
        // (see `commit_self_authored_update`), so the fork history is the
        // authoritative local record of the win — available immediately, with
        // no dependence on the broadcast having propagated back through the
        // relay. Before this, `auto_post_win_cleanup` could poll the relay in
        // the window between claim and relay-propagation, see no DisputeAcquire,
        // conclude `not_winner`, write the terminal marker, and NEVER rotate /
        // re-open the recovered ledger — leaving the winner's own ledger
        // unserviceable despite the on-chain win.
        if let Some(fork_key) = self.handler.find_our_fork(ledger_id) {
            let has_local_acquire = {
                let ledgers = self.handler.ledgers.lock().unwrap();
                ledgers
                    .get(&fork_key)
                    .map(|arc| {
                        let l = arc.read().unwrap();
                        l.history.iter().any(|u| {
                            u.operator_id == our_pubkey
                                && matches!(
                                    LedgerOperation::tlv_decode(&u.message),
                                    Ok(LedgerOperation::DisputeAcquire { .. })
                                )
                        })
                    })
                    .unwrap_or(false)
            };
            if has_local_acquire {
                return Ok(true);
            }
        }

        // Fallback: paginated relay fetch — bloated forks would otherwise
        // hide DisputeAcquire at the tail beyond a single 500-event
        // window.
        let paginated_updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;

        for update in &paginated_updates {
            if update.operator_id == our_pubkey {
                if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                    if matches!(op, LedgerOperation::DisputeAcquire { .. }) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod recovery_chaining_tests {
    //! The dispute-recovery ops (DisputeAcquire / DisputeYield / the
    //! rotation QuorumBegin / the re-opened DepositOpens) are hand-built in
    //! `claim_lottery`, `publish_custody_yield`, `auto_rotate_to_quorum`, and
    //! `auto_continue_ledger`. They MUST chain on the parent's `chain_hash()`
    //! (= SHA256(content_hash || operator_signature)) — the single convention
    //! `validate_hash_chain` enforces — so a loser reimporting the resolved
    //! chain from the relay accepts it. These tests reproduce that hand-built
    //! chaining byte-for-byte and assert `validate_hash_chain` accepts it, and
    //! that the OLD `content_hash` convention is rejected (regression guard).
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use deposits_core::messages::LedgerOperation;
    use deposits_core::validation::LedgerConformanceValidator;
    use deposits_core::{SignedLedgerUpdate, TlvEncode};

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    /// Build a signed update chaining on `prev` (already the parent's
    /// chain_hash, or [0;32] for genesis). `content_hash` is
    /// `SignedLedgerUpdate::compute_hash`. A non-zero operator_signature is
    /// stamped so `chain_hash()` (which folds it in) is meaningful.
    fn signed(
        seq: u64,
        operator: PublicKey,
        op: &LedgerOperation,
        prev: [u8; 32],
    ) -> SignedLedgerUpdate {
        let message = op.tlv_encode();
        let mut u = SignedLedgerUpdate {
            message,
            message_type: 0x8001,
            operator_id: operator,
            ledger_id: [7u8; 32],
            sequence_number: seq,
            previous_hash: prev,
            content_hash: [0u8; 32],
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            // Distinct non-zero sig per seq so chain_hash != content_hash and
            // each parent's chain_hash is unique.
            operator_signature: [seq as u8 + 1; 64],
            cosignatures: Vec::new(),
        };
        u.content_hash = u.compute_hash();
        u
    }

    fn ledger_open(operator: PublicKey) -> LedgerOperation {
        LedgerOperation::LedgerOpen {
            operator_id: operator,
            reserves_id: "bcrt1qopen".to_string(),
            genesis_block: 0,
            reserves_amount: 1_000_000,
            collateral_amount: 0,
            protocol_version: None,
        }
    }

    fn dispute_acquire(new_custodian: PublicKey) -> LedgerOperation {
        LedgerOperation::DisputeAcquire {
            new_custodian,
            claim_txid: [3u8; 32],
            new_reserves_address: "bcrt1qwinner".to_string(),
            confiscation_txid: None,
        }
    }

    fn deposit_open(id: u8) -> LedgerOperation {
        LedgerOperation::DepositOpen {
            deposit_id: [id; 16],
            descriptor: "wpkh(deadbeef)".to_string(),
            fees: None,
            transfer_fees: None,
            payment_hash: None,
            invoice: None,
            cosigner_guarantee_signature: None,
            receive_requires_sig: false,
            fee_change_after_blocks: None,
            fee_change_notice_blocks: None,
            fee_change_limit_bps: None,
            commitment: None,
        }
    }

    /// A recovered chain — pre-dispute op(s) authored by the original
    /// operator, then the winner's DisputeAcquire and a re-opened
    /// DepositOpen authored by the new custodian — validates end to end
    /// when every link chains on the parent's `chain_hash()`.
    #[test]
    fn recovered_chain_links_on_chain_hash_and_validates() {
        let operator = pk(1);
        let winner = pk(2);

        // seq 0: LedgerOpen (genesis, prev = [0;32]).
        let u0 = signed(0, operator, &ledger_open(operator), [0u8; 32]);
        // seq 1: winner's DisputeAcquire chains on u0.chain_hash().
        let u1 = signed(1, winner, &dispute_acquire(winner), u0.chain_hash());
        // seq 2: re-opened DepositOpen chains on u1.chain_hash().
        let u2 = signed(2, winner, &deposit_open(0xAB), u1.chain_hash());

        LedgerConformanceValidator::validate_hash_chain(&[u0, u1, u2])
            .expect("recovered chain chained on chain_hash() must validate");
    }

    /// Regression guard: the OLD convention (chaining the recovery op on the
    /// parent's `content_hash`) breaks `validate_hash_chain` — this is the
    /// exact "Hash chain broken at sequence N: prev_hash mismatch" that
    /// blocked loser convergence before the fix.
    #[test]
    fn recovery_op_chained_on_content_hash_is_rejected() {
        let operator = pk(1);
        let winner = pk(2);

        let u0 = signed(0, operator, &ledger_open(operator), [0u8; 32]);
        // WRONG: chain the DisputeAcquire on u0.content_hash (old behavior).
        let u1_bad = signed(1, winner, &dispute_acquire(winner), u0.content_hash);

        // content_hash != chain_hash (operator_signature is non-zero), so the
        // validator's expected_prev (= u0.chain_hash()) mismatches.
        assert_ne!(u0.content_hash, u0.chain_hash());
        let err = LedgerConformanceValidator::validate_hash_chain(&[u0, u1_bad])
            .expect_err("content_hash-chained recovery op must be rejected");
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("prev_hash mismatch") || msg.to_lowercase().contains("hashchainbroken"),
            "unexpected error: {}",
            msg
        );
    }

    /// The multi-hop rotation tail (DisputeAcquire → QuorumBegin →
    /// DepositOpen, all by the new custodian) also validates — mirrors
    /// `auto_rotate_to_quorum` + `auto_continue_ledger` chaining each op on
    /// the previous signed update's `chain_hash()`.
    #[test]
    fn multi_hop_recovery_tail_validates() {
        let operator = pk(1);
        let winner = pk(2);

        let u0 = signed(0, operator, &ledger_open(operator), [0u8; 32]);
        let u1 = signed(1, winner, &dispute_acquire(winner), u0.chain_hash());
        let qb = LedgerOperation::QuorumBegin {
            exit_cutoff_height: None,
            exit_outputs: Vec::new(),
            splice_in_outpoint: None,
            splice_in_amount: None,
            reference_feerate: None,
            dormancy_outputs: Vec::new(),
            migration_manifest: Vec::new(),
            migration_receiver: None,
            migration_vout: None,
            consumed_notice: None,
            rotation_rungs: vec![],
            reserves_id: "bcrt1qrot".to_string(),
            spending_txid: [0; 32],
            new_outpoint_txid: [1; 32],
            new_outpoint_vout: 0,
            amount: 900_000,
            quorum_expiry: 1_000_000,
            ledger_hash: u1.content_hash,
            quorum_members: vec![deposits_core::messages::QuorumMemberRef::pubkey_only(
                winner,
            )],
            collateral_amount: 0,
            protocol_version: Some("cltv-offset-v2".to_string()),
        };
        let u2 = signed(2, winner, &qb, u1.chain_hash());
        let u3 = signed(3, winner, &deposit_open(0xCD), u2.chain_hash());

        LedgerConformanceValidator::validate_hash_chain(&[u0, u1, u2, u3])
            .expect("multi-hop recovery tail must validate");
    }

    fn quorum_add_member(member: PublicKey) -> LedgerOperation {
        LedgerOperation::QuorumAddMember {
            min_collateral_bps: None,
            dormancy_blocks: None,
            dormancy_notice_blocks: None,
            quorum_member: member,
            quorum_member_signature: [0u8; 64],
            member_ledger_id: "ledger".to_string(),
            min_fee_bps: None,
            min_fee_fixed: None,
            max_fee_period: None,
            membership_until: None,
            dispute_response_blocks: None,
            dispute_arm_blocks: None,
            service_response_blocks: None,
            max_transfer_timeout_blocks: None,
            max_descriptor_bytes: None,
            compensation_bps: None,
            compensation_deposit_id: None,
            compensation_frequency_blocks: None,
            member_response: None,
            member_signature: None,
        }
    }

    /// Regression guard for the loser-convergence stall: the fork-arming
    /// rotation appends SEVERAL `QuorumAddMember` ops back-to-back (one per
    /// carried quorum member). The buggy shape appended the whole batch and
    /// signed once at the end, so the 2nd..Nth op chained on its
    /// predecessor's `content_hash` (not `chain_hash`). `validate_hash_chain`
    /// rejects that — and, worse, a loser's `best_chain` walk (which steps
    /// `chain_hash()`) stopped at the first internal link, read the resolved
    /// fork's depth as 1, and lost the depth tiebreak to the disputed branch.
    /// The fix signs+finalizes each op in turn, so every internal link is a
    /// `chain_hash`. This test asserts the multi-`QuorumAddMember` rotation
    /// validates when chain_hash-linked, and is rejected when the internal
    /// links regress to content_hash.
    #[test]
    fn multi_quorum_add_member_rotation_must_chain_on_chain_hash() {
        let operator = pk(1);
        let winner = pk(2);
        let m1 = pk(10);
        let m2 = pk(11);

        // Common prefix: genesis by the original operator.
        let u0 = signed(0, operator, &ledger_open(operator), [0u8; 32]);
        // Fork tail authored by the winner: DisputeEnter, then THREE
        // QuorumAddMember (the rotation), then DisputeArmed, DisputeAcquire.
        let u1 = signed(
            1,
            winner,
            &LedgerOperation::DisputeEnter {
                last_valid_sequence: 0,
                reason: "auto_dispute".to_string(),
                anchor_block_hash: None,
                anchor_block_height: None,
                fraud_proof_hash: None,
                fraud_proof: None,
            },
            u0.chain_hash(),
        );
        let u2 = signed(2, winner, &quorum_add_member(winner), u1.chain_hash());
        let u3 = signed(3, winner, &quorum_add_member(m1), u2.chain_hash());
        let u4 = signed(4, winner, &quorum_add_member(m2), u3.chain_hash());
        let u5 = signed(
            5,
            winner,
            &LedgerOperation::DisputeArmed {
                armed_block: 105,
                commitment_hash: [9u8; 20],
                target_reserves: "bcrt1qwinner".to_string(),
                replacement_collateral: None,
                rearm_round: None,
            },
            u4.chain_hash(),
        );
        let u6 = signed(6, winner, &dispute_acquire(winner), u5.chain_hash());

        LedgerConformanceValidator::validate_hash_chain(&[
            u0.clone(),
            u1.clone(),
            u2.clone(),
            u3.clone(),
            u4.clone(),
            u5.clone(),
            u6.clone(),
        ])
        .expect("chain_hash-linked multi-member rotation must validate");

        // Regress ONE internal QuorumAddMember link to content_hash (the old
        // append-all-then-sign-once shape) — validation must reject it.
        let u3_bad = signed(3, winner, &quorum_add_member(m1), u2.content_hash);
        assert_ne!(u2.content_hash, u2.chain_hash());
        LedgerConformanceValidator::validate_hash_chain(&[u0, u1, u2, u3_bad])
            .expect_err("content_hash-linked internal rotation op must be rejected");
    }
}

/// The sequence a dispute forks after: the caller's `requested` base, but
/// never at or past `first_non_conforming`, the first update on the
/// original operator's chain known to be non-conforming.
pub(crate) fn dispute_base(requested: u64, first_non_conforming: Option<u64>) -> u64 {
    match first_non_conforming {
        Some(fault) if fault <= requested => fault.saturating_sub(1),
        _ => requested,
    }
}

/// True the first time per ledger (for once-only log lines).
fn logged_once(ledger_id: &str) -> bool {
    use std::sync::{Mutex, OnceLock};
    static SEEN: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    SEEN.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
        .lock()
        .unwrap()
        .insert(ledger_id.to_string())
}

impl Node {
    /// Whether `ledger_id`'s dispute is over because its vault is gone: `Some(true)` when our
    /// lottery for it completed (the durable marker) or the vault of its latest `QuorumBegin`
    /// is spent on the confirmed chain, `Some(false)` unspent, `None` unknown (the caller
    /// proceeds as before). The vault comes from the replica, else a fork of it, else the
    /// relay: a restarted replica's in-memory history may have lost the QuorumBegin.
    pub(crate) async fn dispute_vault_spent(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
    ) -> Option<bool> {
        // A dispute against a custodian that took the ledger after the last QuorumBegin (DEP-06
        // proof 11 against the winner) forks at or past that DisputeAcquire: the spent vault
        // is the one the old dispute confiscated, not this one's. Only a dispute from before
        // the custody change is the old one.
        let after_custody_change = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers.get(ledger_id).cloned()
        }
        .is_some_and(|arc| {
            super::armers::forks_past_custody_change(&arc.read().unwrap().history, last_valid_seq)
        });
        if after_custody_change {
            return Some(false);
        }
        let prefix = &ledger_id[..16.min(ledger_id.len())];
        if self
            .data_dir
            .join(format!("lottery_completed_{}.marker", prefix))
            .exists()
        {
            return Some(true);
        }
        let from_ledgers = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let arcs: Vec<_> = ledgers
                .iter()
                .filter(|(k, _)| k.starts_with(ledger_id))
                .map(|(_, a)| a.clone())
                .collect();
            drop(ledgers);
            // The newest QuorumBegin any of them holds (a fork stops at its fork point).
            arcs.iter()
                .filter_map(|a| super::vault_watch::current_vault(&a.read().unwrap().history))
                .max_by_key(|(_, seq)| *seq)
        };
        let vault = match from_ledgers {
            Some((v, _)) => v,
            None => {
                let updates = tokio::time::timeout(
                    std::time::Duration::from_secs(4),
                    self.fetch_lottery_updates(ledger_id),
                )
                .await
                .ok()?;
                super::vault_watch::current_vault(&updates)?.0
            }
        };
        let chain = self.wallet.chain_backend();
        let check = tokio::task::spawn_blocking(move || {
            super::armers::vault_spent_on_chain(&*chain, &vault)
        });
        tokio::time::timeout(std::time::Duration::from_secs(4), check)
            .await
            .ok()?
            .ok()?
    }
}

/// The latest `DisputeArmed` in a fork's history, if any.
pub(crate) fn latest_dispute_armed(
    history: &[deposits_core::SignedLedgerUpdate],
) -> Option<deposits_core::messages::LedgerOperation> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history
        .iter()
        .rev()
        .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(op @ LedgerOperation::DisputeArmed { .. }) => Some(op),
            _ => None,
        })
}

/// What the replacement-collateral lookup found at our operator-key P2WPKH.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CollateralLookup {
    Found(deposits_core::messages::ReplacementCollateral),
    /// A UTXO, but below the cosigners' floor.
    Undersized {
        value_sats: u64,
    },
    NotFound,
    /// Free coins covering the need exist, but no more than the reserve a re-arm leaves for
    /// new disputes (`PledgeExclusion::reserve`).
    Reserved {
        free: usize,
    },
}

/// Look up the replacement collateral at `script` (our operator-key
/// P2WPKH), retrying bitcoind's "Scan already in progress" per `retry`.
/// `Err` only when the lookup itself failed (retries exhausted, or any
/// other backend error).
/// What a new pledge must avoid: this dispute's own earlier pledge (kept while unspent) and the
/// coins our other arms pledged.
#[derive(Clone, Debug, Default)]
pub(crate) struct PledgeExclusion {
    pub own: Option<bitcoin::OutPoint>,
    pub taken: std::collections::HashSet<bitcoin::OutPoint>,
    /// Local policy, not DEP-03: a new coin is pledged only while MORE than this many free
    /// coins cover the need, so the last `reserve` stay for new disputes. 0 for a round-1 arm
    /// (a new dispute's arm may take the last coin: not arming is what dereliction is judged
    /// on); [`rearm_pledge_reserve`] for a re-arm round of an old dispute. Keeping its own
    /// unspent pledge (`own`) takes nothing and is never refused.
    pub reserve: usize,
}

/// The coins a re-arm (round >= 2) must leave free for new disputes' round-1 arms
/// (`DEPOSITS_REARM_PLEDGE_RESERVE`, default 2). Local policy: an old, unclaimed lottery
/// re-armed round after round would otherwise take every coin, and a node with nothing to
/// pledge cannot arm the next dispute (regtest 1121-next4c: ref6's re-arm passes spent 10 of
/// the 14 coins the pledge fix freed).
pub(crate) fn rearm_pledge_reserve() -> usize {
    std::env::var("DEPOSITS_REARM_PLEDGE_RESERVE")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(2)
}

/// The coin to pledge in a `DisputeArmed` (DEP-03 §Replacement collateral declaration): `own`
/// while it is unspent; else the smallest coin with at least `max(1, min_confs)`
/// confirmations covering `need` that is not `taken`, ties to the smaller outpoint (as
/// "txid:vout"); else none. A coin pledged to two disputes is spent by whichever claim lands
/// first and strands the other: regtest rearm-rust 1119-100553, where ref7's round-2 arm
/// pledged f9c1f754:0, another dispute's claim spent it three blocks before ref7's claim, and
/// that claim failed bad-txns-inputs-missingorspent until the test gave up. cl's
/// `pick-pledge`; vector `pledge_pick.json`.
pub(crate) fn pick_pledge(
    utxos: &[(crate::chain_backend::UnspentOutput, u32)],
    need: u64,
    min_confs: u32,
    exclude: &PledgeExclusion,
) -> Option<crate::chain_backend::UnspentOutput> {
    if let Some(own) = exclude.own {
        if let Some((u, _)) = utxos.iter().find(|(u, _)| u.outpoint == own) {
            return Some(u.clone());
        }
    }
    let free: Vec<_> = utxos
        .iter()
        .filter(|(u, c)| {
            *c >= min_confs.max(1) && !exclude.taken.contains(&u.outpoint) && u.value_sats >= need
        })
        .collect();
    if free.len() <= exclude.reserve {
        return None;
    }
    free.into_iter()
        .min_by(|(a, _), (b, _)| {
            a.value_sats
                .cmp(&b.value_sats)
                .then_with(|| a.outpoint.to_string().cmp(&b.outpoint.to_string()))
        })
        .map(|(u, _)| u.clone())
}

pub(crate) async fn find_replacement_collateral(
    backend: &dyn crate::chain_backend::ChainBackend,
    script: &bitcoin::Script,
    required_sats: u64,
    retry: &crate::chain_backend::ScanRetry,
    exclude: &PledgeExclusion,
) -> Result<CollateralLookup, Error> {
    let utxos = crate::chain_backend::find_unspent_outputs_retrying(backend, script, retry).await?;
    let utxos = without_custody_coins(backend, utxos);
    if let Some(u) = pick_pledge(&utxos, required_sats, 1, exclude) {
        return Ok(CollateralLookup::Found(
            deposits_core::messages::ReplacementCollateral {
                txid: *u.outpoint.txid.as_ref(),
                vout: u.outpoint.vout,
                amount: u.value_sats,
            },
        ));
    }
    if exclude.reserve > 0 {
        let unreserved = PledgeExclusion {
            reserve: 0,
            ..exclude.clone()
        };
        if pick_pledge(&utxos, required_sats, 1, &unreserved).is_some() {
            let free = utxos
                .iter()
                .filter(|(u, c)| {
                    *c >= 1 && !exclude.taken.contains(&u.outpoint) && u.value_sats >= required_sats
                })
                .count();
            return Ok(CollateralLookup::Reserved { free });
        }
    }
    // Nothing free covers it: report the largest free coin, as the single-coin lookup did.
    Ok(utxos
        .iter()
        .filter(|(u, _)| !exclude.taken.contains(&u.outpoint))
        .map(|(u, _)| u.value_sats)
        .max()
        .map_or(CollateralLookup::NotFound, |value_sats| {
            CollateralLookup::Undersized { value_sats }
        }))
}

/// Whether output `vout` of `tx` is a lottery claim's output 0: a ledger's custody until it is
/// spent (rotated into the ledger's vault), whatever our records say. Judged from the transaction
/// alone: its input 0 spends output 0 of its prevout through a taproot SCRIPT path (the witness
/// ends in a control block, 33 + 32k bytes with leaf version 0xc0) with nSequence 0xfffffffd (a
/// full claim, DEP-03) or the reveal CSV (a subset claim), and the coin is its one output (a
/// confiscation spends the vault the same way but has more than one; a re-arm spend carries a
/// tier CSV).
///
/// Regtest 1121-next4c: ref6 claimed ad87b48b's lottery output e6184d32:0 as 0588521b's (found by
/// script, before ff5b053), recorded the DisputeAcquire on 0588521b's fork, and then pledged the
/// claim's output fdff3a5f:0 on 9e23c858, where a win would have spent ad87b48b's reserves. 14 of
/// its 31 coins were claim outputs, 7 of them pledged; the claims of 4.99M sats were the smallest
/// coins covering a 5000-sat need, so they were picked FIRST. Vector `custody_coin.json`.
pub(crate) fn claim_output_shaped(tx: &bitcoin::Transaction, vout: u32) -> bool {
    let Some(i) = tx.input.first() else {
        return false;
    };
    let seq = i.sequence.to_consensus_u32();
    let script_path = i.witness.len() >= 2
        && i.witness.last().is_some_and(|cb| {
            cb.len() >= 33 && (cb.len() - 33) % 32 == 0 && cb[0] & 0xfe == 0xc0
        });
    vout == 0
        && tx.output.len() == 1
        && i.previous_output.vout == 0
        && script_path
        && (seq == 0xffff_fffd
            || seq == deposits_core::tapscript_reserves::LOTTERY_REVEAL_CSV_BLOCKS)
}

/// Whether a claim may spend `collateral` as its input 1, given its funding transaction as the
/// chain answered (`Err` when the chain could not be read). Refused when the coin is a lottery
/// claim's output 0 ([`claim_output_shaped`]): spending it moves a ledger's custody into this
/// claim, and the claim may not spend any other coin instead (DEP-03 §Claim transaction).
/// Refused too when its funding transaction cannot be read: asked again next pass.
pub(crate) fn claim_collateral_check(
    collateral: bitcoin::OutPoint,
    funding: Result<Option<&bitcoin::Transaction>, &crate::error::Error>,
) -> Result<(), String> {
    match funding {
        Ok(Some(tx)) if claim_output_shaped(tx, collateral.vout) => Err(format!(
            "our declared collateral {} is a lottery claim's output 0, a ledger's custody; a claim \
             must spend the declared pledge and nothing else, so it is not built (re-arm with a \
             fresh pledge, or arm the next round)",
            collateral
        )),
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "the funding transaction of our collateral {} is unreadable ({}); not claiming this pass",
            collateral, e
        )),
    }
}

/// Whether our latest arm's declared pledge must be replaced by a same-round re-arm (DEP-03
/// §Eligibility snapshot: "a re-arm replaces the declaration"; its latest arm counts and moves
/// E): it is a lottery claim's output 0, and the dispute's vault is still unspent, so no
/// confiscation has fixed the participant set and the arm window can still take a re-arm.
pub(crate) fn pledge_is_custody_rearm(
    pledge_funding: Option<&bitcoin::Transaction>,
    pledge_vout: u32,
    vault_unspent: bool,
) -> bool {
    vault_unspent && pledge_funding.is_some_and(|tx| claim_output_shaped(tx, pledge_vout))
}

/// `utxos` without the coins that are a lottery claim's output 0 ([`claim_output_shaped`]),
/// asked of the chain once per funding transaction (cached: a transaction never changes). A coin
/// whose funding transaction cannot be fetched this pass is left out too: pledging a ledger's
/// custody loses depositors' funds, skipping a coin for one pass costs a retry.
pub(crate) fn without_custody_coins(
    backend: &dyn crate::chain_backend::ChainBackend,
    utxos: Vec<(crate::chain_backend::UnspentOutput, u32)>,
) -> Vec<(crate::chain_backend::UnspentOutput, u32)> {
    static SHAPED: std::sync::OnceLock<std::sync::Mutex<HashMap<bitcoin::OutPoint, bool>>> =
        std::sync::OnceLock::new();
    let cache = SHAPED.get_or_init(Default::default);
    utxos
        .into_iter()
        .filter(|(u, _)| {
            let known = cache.lock().unwrap().get(&u.outpoint).copied();
            let custody = match known {
                Some(c) => c,
                None => match backend.get_tx(&u.outpoint.txid) {
                    Ok(Some(tx)) => {
                        let c = claim_output_shaped(&tx, u.outpoint.vout);
                        cache.lock().unwrap().insert(u.outpoint, c);
                        c
                    }
                    // Unknown to this backend (a test double): an ordinary coin.
                    Ok(None) => false,
                    Err(e) => {
                        tracing::warn!(
                            "pledge: {} left out this pass, its funding transaction is unreadable: {}",
                            u.outpoint,
                            e
                        );
                        return false;
                    }
                },
            };
            if custody {
                tracing::info!(
                    "pledge: {} ({} sats) is a lottery claim's output 0, a ledger's custody; never pledged",
                    u.outpoint,
                    u.value_sats
                );
            }
            !custody
        })
        .collect()
}

/// Whether to arm without replacement collateral when none is available
/// (`DEPOSITS_ALLOW_UNCOLLATERALIZED_ARM=1`). Off by default: strict
/// cosigners refuse a confiscation with any collateral-less armer (DEP-03),
/// and cl-deposits counts every `DisputeArmed` on a fork, so a None arm
/// later upgraded by a re-arm still reads as an armer without collateral
/// there. For test harnesses that dispute without funding the operator key.
pub(crate) fn allow_uncollateralized_arm() -> bool {
    matches!(
        std::env::var("DEPOSITS_ALLOW_UNCOLLATERALIZED_ARM").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Testing only (`DEPOSITS_REDTEAM_NO_ARM=1`): never arm, so the node is a recovery voter
/// and not a lottery participant (redteam/check-rearm-mixed.sh).
pub(crate) fn redteam_no_arm() -> bool {
    matches!(
        std::env::var("DEPOSITS_REDTEAM_NO_ARM").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Our coins `history` commits, in order: (every replacement collateral a `DisputeArmed` of
/// ours declares, output 0 of every `DisputeAcquire` claim of ours). A claim pays our own
/// P2WPKH, where our pledgeable coins are, but it is a ledger's custody until rotated into its
/// vault: selecting by script would pledge it to another dispute (the select-by-script hazard
/// of the claim, regtest 1120-090836; cl's `pledge-collateral`).
pub(crate) fn committed_outpoints(
    history: &[deposits_core::SignedLedgerUpdate],
    me: &bitcoin::secp256k1::PublicKey,
) -> (Vec<bitcoin::OutPoint>, Vec<bitcoin::OutPoint>) {
    use bitcoin::hashes::Hash;
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let (mut declared, mut custody) = (Vec::new(), Vec::new());
    for u in history.iter().filter(|u| u.operator_id == *me) {
        match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeArmed {
                replacement_collateral: Some(rc),
                ..
            }) => declared.push(bitcoin::OutPoint::new(
                bitcoin::Txid::from_byte_array(rc.txid),
                rc.vout,
            )),
            Ok(LedgerOperation::DisputeAcquire { claim_txid, .. }) => custody.push(
                bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(claim_txid), 0),
            ),
            _ => {}
        }
    }
    (declared, custody)
}

/// The dispute our fork (`fork_history`) is in: its vault (the latest QuorumBegin at or below
/// our DisputeEnter) and every `DisputeAcquire` in `histories` (the ledger's base and the forks
/// we hold, ours included) after that DisputeEnter, by someone other than `me` and naming
/// someone other than `me`, as (acquirer, claim), each claim once. `None` when we never
/// entered on this fork or no vault precedes the entry. Whether each binds is
/// `acquire_binding`'s to judge.
/// The vault the dispute our fork (`fork_history`) is in confiscates: the latest QuorumBegin at or
/// below our DisputeEnter, or `None` when we never entered.
pub(crate) fn dispute_vault(
    fork_history: &[deposits_core::SignedLedgerUpdate],
    me: &bitcoin::secp256k1::PublicKey,
) -> Option<super::acquire_binding::Vault> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let enter_seq = fork_history
        .iter()
        .filter(|u| u.operator_id == *me)
        .filter(|u| {
            matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::DisputeEnter { .. })
            )
        })
        .map(|u| u.sequence_number)
        .max()?;
    super::acquire_binding::vault_at(fork_history, enter_seq)
}

pub(crate) fn dispute_acquire_candidates(
    fork_history: &[deposits_core::SignedLedgerUpdate],
    histories: &[&[deposits_core::SignedLedgerUpdate]],
    me: &bitcoin::secp256k1::PublicKey,
) -> Option<(
    super::acquire_binding::Vault,
    Vec<(bitcoin::secp256k1::PublicKey, [u8; 32], u32)>,
)> {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    let enter_seq = fork_history
        .iter()
        .filter(|u| u.operator_id == *me)
        .filter(|u| {
            matches!(
                LedgerOperation::tlv_decode(&u.message),
                Ok(LedgerOperation::DisputeEnter { .. })
            )
        })
        .map(|u| u.sequence_number)
        .max()?;
    let vault = super::acquire_binding::vault_at(fork_history, enter_seq)?;
    // Each with its round bound (DEP-06 "A claim after the claimant's own yield":
    // `acquire_binding::min_round`), read off the history that carries it.
    let mut candidates: Vec<(bitcoin::secp256k1::PublicKey, [u8; 32], u32)> = Vec::new();
    for h in histories {
        let all: Vec<&deposits_core::SignedLedgerUpdate> = h.iter().collect();
        for u in h
            .iter()
            .filter(|u| u.sequence_number > enter_seq && u.operator_id != *me)
        {
            if let Ok(LedgerOperation::DisputeAcquire {
                claim_txid,
                new_custodian,
                ..
            }) = LedgerOperation::tlv_decode(&u.message)
            {
                if new_custodian != *me && !candidates.iter().any(|(_, c, _)| *c == claim_txid) {
                    let min = super::acquire_binding::min_round_for(&all, u);
                    candidates.push((u.operator_id, claim_txid, min));
                }
            }
        }
    }
    Some((vault, candidates))
}

/// The `DisputeAcquire`s the relay holds for a ledger, as last fetched by
/// `Node::refresh_relay_acquires`. The base ledger in memory cannot be asked: its loader drops
/// every update not by the ledger's operator, so a winner's acquire on its fork, adopted into
/// the base on disk, is gone after a restart (ref6's 9e23c858 holds 023d42a6's at seq 17 on
/// disk and not in memory).
fn relay_acquires_cache(
) -> &'static std::sync::Mutex<HashMap<String, Vec<deposits_core::SignedLedgerUpdate>>> {
    static M: std::sync::OnceLock<
        std::sync::Mutex<HashMap<String, Vec<deposits_core::SignedLedgerUpdate>>>,
    > = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

fn relay_acquires(ledger_id: &str) -> Vec<deposits_core::SignedLedgerUpdate> {
    relay_acquires_cache()
        .lock()
        .map(|m| m.get(ledger_id).cloned().unwrap_or_default())
        .unwrap_or_default()
}

/// A binding `DisputeAcquire` by another participant of one of our disputes
/// (`Node::others_binding_acquires`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OtherAcquire {
    pub acquirer: bitcoin::secp256k1::PublicKey,
    /// Its claim txid, internal byte order.
    pub claim: [u8; 32],
    /// The round the claim closes (`acquire_binding::judge_acquire_round`).
    pub round: u32,
}

/// One of our own dispute operations on a fork, as the pledge hold reads it (`fork_holds`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ForkEvent {
    Enter,
    /// A DisputeArmed, the coin it declares (if any) and its round (TLV 366; round 1 when
    /// absent).
    Arm {
        pledge: Option<bitcoin::OutPoint>,
        round: u32,
    },
    Yield,
    /// A DisputeAcquire: output 0 of its claim, and whether the acquire binds (DEP-06 "An
    /// acquire binds once its claim confirms"; for our own claim, that it confirmed).
    Acquire {
        claim: bitcoin::OutPoint,
        binds: bool,
    },
}

/// What one of our forks holds against a new pledge (DEP-03 "Replacement collateral
/// declaration", a coin pledged in a live dispute): `(pledges, custody)`.
///
/// A pledge is held from the DisputeArmed that declares it until the dispute ends for us:
/// - a `DisputeYield` after it (a yield, or the tombstone a lost lottery leaves, ends the
///   round; a later round's arm declares afresh);
/// - a binding `DisputeAcquire` (our claim confirmed; it spent the winner's pledge, or left
///   it free);
/// - retiring the fork (`retired`: voided or dropped as concluded);
/// - a binding `DisputeAcquire` by ANOTHER participant of the round of the arm (`others`: the
///   rounds of the dispute's binding acquires by others, judged by `acquire_binding` against
///   the dispute's lottery): that claim spent the round's lottery output, so the round is over
///   whether or not we ever yielded to it. It frees the pledges of our arms at that round or
///   earlier, never a later round's. Regtest 1121-next4c: 12 of ref6's 25 holding forks were
///   disputes another member had won, acquired and claimed, with no yield of ours.
///
/// Output 0 of a binding claim is the ledger's custody, held while that acquire stands (no
/// later arm on the fork; the caller only sees it while it is unspent). An acquire that does
/// not bind (yet) ends nothing: the claim may still confirm, and it spends the pledge.
/// Regtest 1120-next4: ref6 held 31 coins and could arm on nothing, 30 of them pledged by
/// disputes that had long ended. Vector `pledge_pick.json` (its `forks` cases).
pub(crate) fn fork_holds(
    events: &[ForkEvent],
    retired: bool,
    others: &[u32],
) -> (Vec<bitcoin::OutPoint>, Option<bitcoin::OutPoint>) {
    let (mut pledges, mut custody) = (Vec::<(bitcoin::OutPoint, u32)>::new(), None);
    if retired {
        return (Vec::new(), custody);
    }
    for e in events {
        match e {
            ForkEvent::Enter => {}
            ForkEvent::Arm { pledge, round } => {
                pledges.extend(pledge.map(|p| (p, *round)));
                custody = None;
            }
            ForkEvent::Yield => {
                pledges.clear();
                custody = None;
            }
            ForkEvent::Acquire { claim, binds } => {
                if *binds {
                    pledges.clear();
                    custody = Some(*claim);
                } else {
                    custody = None;
                }
            }
        }
    }
    if let Some(ended) = others.iter().max() {
        pledges.retain(|(_, round)| round > ended);
    }
    (pledges.into_iter().map(|(p, _)| p).collect(), custody)
}

/// Our dispute operations in `history`, oldest first; an acquire's `binds` from `confirmed`
/// (whether its claim txid is in a block).
pub(crate) fn fork_events(
    history: &[deposits_core::SignedLedgerUpdate],
    me: &bitcoin::secp256k1::PublicKey,
    confirmed: &dyn Fn(&bitcoin::Txid) -> bool,
) -> Vec<ForkEvent> {
    use bitcoin::hashes::Hash;
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    history
        .iter()
        .filter(|u| u.operator_id == *me)
        .filter_map(|u| match LedgerOperation::tlv_decode(&u.message) {
            Ok(LedgerOperation::DisputeEnter { .. }) => Some(ForkEvent::Enter),
            Ok(LedgerOperation::DisputeArmed {
                replacement_collateral,
                rearm_round,
                ..
            }) => Some(ForkEvent::Arm {
                pledge: replacement_collateral.map(|rc| {
                    bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(rc.txid), rc.vout)
                }),
                round: rearm_round.unwrap_or(1),
            }),
            // DEP-06 "An invalid yield is void": a yield naming a transaction (`lost_to`,
            // `excluded_by`) that is not confirmed frees no pledge; it reads as absent until it
            // is. One naming none (an earlier ruleset's, or `reestablished`, checked when it was
            // signed) counts as before. Mirrors cl's YIELD-EVIDENCE-SEEN-P.
            Ok(LedgerOperation::DisputeYield {
                lost_to,
                excluded_by,
                ..
            }) => match lost_to.or(excluded_by) {
                Some(t) if !confirmed(&bitcoin::Txid::from_byte_array(t)) => None,
                _ => Some(ForkEvent::Yield),
            },
            Ok(LedgerOperation::DisputeAcquire { claim_txid, .. }) => {
                let txid = bitcoin::Txid::from_byte_array(claim_txid);
                Some(ForkEvent::Acquire {
                    claim: bitcoin::OutPoint::new(txid, 0),
                    binds: confirmed(&txid),
                })
            }
            _ => None,
        })
        .collect()
}

/// What to do with a (re-)arm, given the collateral lookup.
#[derive(Debug)]
pub(crate) enum ArmDecision {
    Arm(deposits_core::messages::LedgerOperation),
    /// A re-arm with nothing better than the prior arm's `None`.
    KeepPrior,
    /// Don't arm; the reason. The caller returns an error and the arm is
    /// retried by `auto_rearm_disputes`.
    Refuse(String),
}

/// Decide the `DisputeArmed` to publish. A lookup failure never arms (the
/// scan may simply have lost a race with another member's); a missing or
/// undersized UTXO arms with `None` only when `allow_uncollateralized`.
pub(crate) fn dispute_armed_op(
    armed_block: u32,
    commitment_hash: [u8; 20],
    target_reserves: String,
    lookup: Result<CollateralLookup, Error>,
    is_rearm: bool,
    allow_uncollateralized: bool,
) -> ArmDecision {
    let replacement_collateral = match lookup {
        Ok(CollateralLookup::Found(rc)) => Some(rc),
        _ if is_rearm => return ArmDecision::KeepPrior,
        Err(e) => return ArmDecision::Refuse(format!("collateral lookup failed: {}", e)),
        Ok(CollateralLookup::Undersized { value_sats }) if !allow_uncollateralized => {
            return ArmDecision::Refuse(format!(
                "operator-key P2WPKH holds only {} sats, below the floor",
                value_sats
            ))
        }
        Ok(CollateralLookup::NotFound) if !allow_uncollateralized => {
            return ArmDecision::Refuse("no UTXO at the operator-key P2WPKH".to_string())
        }
        Ok(_) => None,
    };
    ArmDecision::Arm(deposits_core::messages::LedgerOperation::DisputeArmed {
        armed_block,
        commitment_hash,
        target_reserves,
        replacement_collateral,
        rearm_round: None,
    })
}

#[cfg(test)]
mod arm_collateral_tests {
    use super::*;
    use crate::chain_backend::fake::ScriptedScans;
    use crate::chain_backend::{ScanRetry, UnspentOutput};
    use deposits_core::messages::LedgerOperation;

    #[test]
    fn our_claim_output_is_custody_never_a_pledge() {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        use deposits_core::TlvEncode;
        let key = |b: u8| {
            bitcoin::secp256k1::PublicKey::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&[b; 32]).unwrap(),
            )
        };
        let (me, other) = (key(1), key(2));
        let upd = |op: LedgerOperation, by| deposits_core::SignedLedgerUpdate {
            message: op.tlv_encode(),
            message_type: 0x8001,
            operator_id: by,
            ledger_id: [0u8; 32],
            sequence_number: 1,
            previous_hash: [0u8; 32],
            content_hash: [0u8; 32],
            block_height: 100,
            block_hash: [0u8; 32],
            operator_signature: [0u8; 64],
            cosignatures: Vec::new(),
        };
        let acquire = |txid: [u8; 32], by| {
            upd(
                LedgerOperation::DisputeAcquire {
                    new_custodian: by,
                    claim_txid: txid,
                    new_reserves_address: "bcrt1qwinner".into(),
                    confiscation_txid: None,
                },
                by,
            )
        };
        let history = vec![acquire([7u8; 32], me), acquire([8u8; 32], other)];
        let (declared, custody) = committed_outpoints(&history, &me);
        let claim = bitcoin::OutPoint::new(
            {
                use bitcoin::hashes::Hash;
                bitcoin::Txid::from_byte_array([7u8; 32])
            },
            0,
        );
        assert!(declared.is_empty());
        assert_eq!(custody, vec![claim], "ours only, output 0");
        // At our address: the claim (the smallest coin covering the floor) and a larger coin.
        let at = |op, sats| {
            (
                UnspentOutput {
                    outpoint: op,
                    value_sats: sats,
                },
                6,
            )
        };
        let coin = utxo(90_000).outpoint;
        let utxos = vec![at(claim, 45_330), at(coin, 90_000)];
        assert_eq!(
            pick_pledge(&utxos, 30_000, 1, &PledgeExclusion::default())
                .unwrap()
                .outpoint,
            claim,
            "without the exclusion the custody is the pick"
        );
        let ex = PledgeExclusion {
            own: None,
            taken: custody.into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(pick_pledge(&utxos, 30_000, 1, &ex).unwrap().outpoint, coin);
    }

    fn utxo(sats: u64) -> UnspentOutput {
        UnspentOutput {
            outpoint: bitcoin::OutPoint::new(
                "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                    .parse()
                    .unwrap(),
                3,
            ),
            value_sats: sats,
        }
    }

    fn script() -> bitcoin::ScriptBuf {
        bitcoin::ScriptBuf::new()
    }

    #[tokio::test]
    async fn scan_in_progress_twice_then_utxo_arms_with_collateral() {
        let backend = ScriptedScans::new(vec![
            Err(ScriptedScans::scan_in_progress()),
            Err(ScriptedScans::scan_in_progress()),
            Ok(Some(utxo(50_000))),
        ]);
        let lookup = find_replacement_collateral(
            &backend,
            &script(),
            30_000,
            &ScanRetry::immediate(12),
            &PledgeExclusion::default(),
        )
        .await;
        assert_eq!(backend.calls(), 3);
        match dispute_armed_op(100, [7u8; 20], "addr".into(), lookup, false, false) {
            ArmDecision::Arm(LedgerOperation::DisputeArmed {
                replacement_collateral: Some(rc),
                ..
            }) => {
                assert_eq!(rc.amount, 50_000);
                assert_eq!(rc.vout, 3);
                let expected = utxo(0);
                let want: &[u8; 32] = expected.outpoint.txid.as_ref();
                assert_eq!(&rc.txid, want);
            }
            other => panic!("expected an arm carrying collateral, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn retries_exhausted_refuses_to_arm() {
        let backend = ScriptedScans::new(
            (0..5)
                .map(|_| Err(ScriptedScans::scan_in_progress()))
                .collect(),
        );
        let lookup = find_replacement_collateral(
            &backend,
            &script(),
            30_000,
            &ScanRetry::immediate(3),
            &PledgeExclusion::default(),
        )
        .await;
        assert_eq!(backend.calls(), 3);
        // Even with the uncollateralized escape hatch, a failed lookup
        // never arms: it only means the scan lost a race.
        assert!(matches!(
            dispute_armed_op(100, [7u8; 20], "addr".into(), lookup, false, true),
            ArmDecision::Refuse(_)
        ));
    }

    #[tokio::test]
    async fn other_errors_are_not_retried() {
        let backend = ScriptedScans::new(vec![
            Err(Error::Wallet("bitcoind scantxoutset error -1: boom".into())),
            Ok(Some(utxo(50_000))),
        ]);
        let lookup = find_replacement_collateral(
            &backend,
            &script(),
            30_000,
            &ScanRetry::immediate(12),
            &PledgeExclusion::default(),
        )
        .await;
        assert!(lookup.is_err());
        assert_eq!(backend.calls(), 1);
    }

    #[tokio::test]
    async fn no_or_small_utxo_refuses_unless_allowed() {
        for (scan, expect) in [
            (None, CollateralLookup::NotFound),
            (
                Some(utxo(10_000)),
                CollateralLookup::Undersized { value_sats: 10_000 },
            ),
        ] {
            let backend = ScriptedScans::new(vec![Ok(scan.clone()), Ok(scan)]);
            let retry = ScanRetry::immediate(12);
            let lookup = find_replacement_collateral(
                &backend,
                &script(),
                30_000,
                &retry,
                &PledgeExclusion::default(),
            )
            .await;
            assert_eq!(lookup.as_ref().unwrap(), &expect);
            assert!(matches!(
                dispute_armed_op(1, [0; 20], "a".into(), lookup, false, false),
                ArmDecision::Refuse(_)
            ));
            let lookup = find_replacement_collateral(
                &backend,
                &script(),
                30_000,
                &retry,
                &PledgeExclusion::default(),
            )
            .await;
            assert!(matches!(
                dispute_armed_op(1, [0; 20], "a".into(), lookup, false, true),
                ArmDecision::Arm(LedgerOperation::DisputeArmed {
                    replacement_collateral: None,
                    ..
                })
            ));
        }
    }

    #[test]
    fn rearm_without_collateral_keeps_the_prior_arm() {
        assert!(matches!(
            dispute_armed_op(
                1,
                [0; 20],
                "a".into(),
                Ok(CollateralLookup::NotFound),
                true,
                true
            ),
            ArmDecision::KeepPrior
        ));
        assert!(matches!(
            dispute_armed_op(
                1,
                [0; 20],
                "a".into(),
                Err(ScriptedScans::scan_in_progress()),
                true,
                false
            ),
            ArmDecision::KeepPrior
        ));
    }
}

#[cfg(test)]
mod rearm_backoff_tests {
    use super::rearm_backoff;

    #[test]
    fn doubles_from_a_minute_to_at_most_half_an_hour() {
        let secs: Vec<u64> = (0..8).map(|f| rearm_backoff(f).as_secs()).collect();
        assert_eq!(secs, vec![60, 120, 240, 480, 960, 1800, 1800, 1800]);
        assert_eq!(rearm_backoff(u32::MAX).as_secs(), 1800);
    }
}

#[cfg(test)]
mod dispute_base_tests {
    use super::dispute_base;

    #[test]
    fn a_base_past_the_fault_is_pulled_back_before_it() {
        // ref3 on ledger C: fault at 17,840, replica tip 20,181.
        assert_eq!(dispute_base(20_181, Some(17_840)), 17_839);
        assert_eq!(dispute_base(17_840, Some(17_840)), 17_839);
    }

    #[test]
    fn a_base_before_the_fault_or_with_none_known_is_kept() {
        assert_eq!(dispute_base(17_839, Some(17_840)), 17_839);
        assert_eq!(dispute_base(9_000, Some(17_840)), 9_000);
        assert_eq!(dispute_base(20_181, None), 20_181);
    }
}

impl crate::node::Node {
    /// DEP-03 §Grounded arms: another disputant's carried proof on `ledger_id` whose evidence
    /// verifies here, as (hash, body, reason), so a member joining that dispute cites the same
    /// grounds. Motive is never examined, the grounds are.
    pub(crate) async fn cited_grounds(
        &self,
        ledger_id: &str,
    ) -> Option<([u8; 32], String, &'static str)> {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;
        let candidates: Vec<([u8; 32], String)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut c = Vec::new();
            for (key, arc) in ledgers.iter() {
                if !key.starts_with(ledger_id) || key.len() == ledger_id.len() {
                    continue;
                }
                let l = arc.read().unwrap();
                for u in l.history.iter().rev() {
                    if let Ok(LedgerOperation::DisputeEnter {
                        fraud_proof_hash: Some(h),
                        fraud_proof: Some(body),
                        ..
                    }) = LedgerOperation::tlv_decode(&u.message)
                    {
                        c.push((h, body));
                        break;
                    }
                }
            }
            c
        };
        for (h, body) in candidates {
            let Ok(b) = serde_json::from_str::<deposits_core::fraud::FraudBroadcast>(&body) else {
                continue;
            };
            if b.proof.proof_hash() == h && self.verify_fraud_grounds(&b).await.is_ok() {
                return Some((h, body, b.proof.proof_type.dispute_reason()));
            }
        }
        None
    }
}

impl crate::node::Node {
    /// Whether we have already entered a dispute on `ledger_id` at
    /// `last_valid_seq`: our fork of it exists, we operate it, and it is past
    /// Normal (our `DisputeEnter` is applied).
    pub(crate) fn entered_own_fork(&self, ledger_id: &str, last_valid_seq: u64) -> bool {
        let base = dispute_base(last_valid_seq, self.handler.first_non_conforming(ledger_id));
        let key =
            crate::handler::DepositsHandler::fork_tracking_key(ledger_id, base, &self.node_id);
        let arc = self.handler.ledgers.lock().unwrap().get(&key).cloned();
        arc.is_some_and(|a| {
            let l = a.read().unwrap();
            l.state.parent_pubkey == self.node_id
                && l.state.dispute_state != deposits_core::types::DisputeState::Normal
        })
    }

    /// Whether `ledger_id`'s active ruleset grounds arms (DEP-18 grounded-arms-v7).
    pub(crate) fn ledger_grounds_arms(&self, ledger_id: &str) -> bool {
        let ledgers = self.handler.ledgers.lock().unwrap();
        ledgers
            .get(ledger_id)
            .map(|arc| {
                deposits_core::types::ruleset_grounds_arms(
                    &arc.read().unwrap().state.active_ruleset_name,
                )
            })
            .unwrap_or(false)
    }
}

/// DEP-06 Phase 4: arming a re-arm round on our own fork (rearm.rs drives it).
impl Node {
    /// Append our DisputeArmed for re-arm round `round` (TLV 366) to our fork, with a fresh
    /// preimage and a replacement-collateral pledge, and publish it.
    /// What a pledge for `ledger_id` must avoid: the latest pledge on our own fork of it (kept
    /// while unspent), and what each fork of ours still holds (`fork_holds`): the pledges of
    /// disputes that have not ended for us, and the custody of a binding claim. A pledge of a
    /// yielded, tombstoned, acquired or retired dispute is free again; counting every pledge
    /// ever declared left ref6 (regtest 1120-next4) with 31 coins and nothing it could pledge.
    pub(crate) fn pledge_exclusion(&self, ledger_id: &str) -> PledgeExclusion {
        let mut ex = PledgeExclusion::default();
        // (fork key, our updates on it) -- copied out, so the chain is not asked under the lock.
        let ours: Vec<(String, Vec<deposits_core::SignedLedgerUpdate>)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .filter_map(|(k, arc)| {
                    let l = arc.read().unwrap();
                    super::rearm::is_our_fork(k, &l.state.parent_pubkey, &self.node_id).then(|| {
                        let mine: Vec<_> = l
                            .history
                            .iter()
                            .filter(|u| u.operator_id == self.node_id)
                            .cloned()
                            .collect();
                        (k.clone(), mine)
                    })
                })
                .collect()
        };
        let confirmed = |t: &bitcoin::Txid| matches!(self.wallet.tx_block_height(*t), Ok(Some(_)));
        let backend = self.wallet.chain_backend();
        for (k, mine) in ours {
            if k.starts_with(ledger_id) {
                let (declared, _) = committed_outpoints(&mine, &self.node_id);
                if let Some(op) = declared.last() {
                    ex.own = Some(*op);
                }
            }
            let others: Vec<u32> = self
                .others_binding_acquires(&k, backend.as_ref())
                .into_iter()
                .map(|a| a.round)
                .collect();
            let (pledges, custody) =
                fork_holds(&fork_events(&mine, &self.node_id, &confirmed), false, &others);
            // Name every holder, so a coin that stays taken can be traced to the fork that holds it
            // (regtest 1121-next4c: 24 of ref6's coins, held by 25 forks the rule reads as live).
            for p in &pledges {
                tracing::debug!(
                    "pledge_exclusion: {} held as the pledge of our live fork {} (its last op of ours: {})",
                    p,
                    &k[..k.len().min(88)],
                    mine.last().map(|u| ledger_op_name(&u.message)).unwrap_or("none")
                );
            }
            if let Some(c) = &custody {
                tracing::debug!(
                    "pledge_exclusion: {} held as custody of our fork {} (a binding acquire)",
                    c,
                    &k[..k.len().min(88)]
                );
            }
            ex.taken.extend(pledges);
            ex.taken.extend(custody);
        }
        ex
    }

    /// The binding `DisputeAcquire`s by OTHER participants of the dispute our fork `fork_key`
    /// is in (DEP-03 "When a pledge is live"): every acquire on the ledger's base or any of its
    /// forks we hold, after our fork's DisputeEnter, not by us and not naming us, judged by
    /// `acquire_binding` against the dispute's vault (the latest QuorumBegin at the fork point),
    /// with the round its claim closes. Verdicts are cached (`note_verdicts`); one not yet final
    /// counts as not binding and is asked again on a later pass.
    pub(crate) fn others_binding_acquires(
        &self,
        fork_key: &str,
        backend: &dyn crate::chain_backend::ChainBackend,
    ) -> Vec<OtherAcquire> {
        use super::acquire_binding as ab;
        if fork_key.len() <= 64 {
            return Vec::new();
        }
        let ledger = &fork_key[..64];
        let found = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let Some(fork) = ledgers.get(fork_key).cloned() else {
                return Vec::new();
            };
            let fork = fork.read().unwrap();
            let others: Vec<_> = ledgers
                .iter()
                .filter(|(k, _)| k.starts_with(ledger) && k.as_str() != fork_key)
                .map(|(_, a)| a.clone())
                .collect();
            let others: Vec<_> = others.iter().map(|a| a.read().unwrap()).collect();
            let relay = relay_acquires(ledger);
            let mut histories: Vec<&[deposits_core::SignedLedgerUpdate]> = vec![&fork.history];
            histories.extend(others.iter().map(|l| l.history.as_slice()));
            histories.push(&relay);
            dispute_acquire_candidates(&fork.history, &histories, &self.node_id)
        };
        let Some((vault, candidates)) = found else {
            return Vec::new();
        };
        if candidates.is_empty() {
            return Vec::new();
        }
        let due: Vec<(ab::Vault, [u8; 32])> =
            candidates.iter().map(|(_, c, _)| (vault.clone(), *c)).collect();
        ab::note_verdicts(backend, &due);
        candidates
            .into_iter()
            .filter_map(|(acquirer, claim, min)| {
                ab::binds_round(&vault, &claim)
                    .filter(|r| *r >= min)
                    .map(|round| OtherAcquire {
                    acquirer,
                    claim,
                    round,
                })
            })
            .collect()
    }

    /// Fetch the relay's `DisputeAcquire`s for `ledger_id` (op-type tag 55: a few events, not
    /// the ledger) into the cache `pledge_exclusion` reads.
    pub(crate) async fn refresh_relay_acquires(&self, ledger_id: &str) {
        // At most every five minutes per ledger: the claim-or-yield pass runs every minute over
        // every armed fork.
        static LAST: std::sync::OnceLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
            std::sync::OnceLock::new();
        {
            let mut last = LAST.get_or_init(Default::default).lock().unwrap();
            if last
                .get(ledger_id)
                .is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(300))
            {
                return;
            }
            last.insert(ledger_id.to_string(), std::time::Instant::now());
        }
        let discriminant = deposits_core::messages::LedgerOperation::DisputeAcquire {
            new_custodian: self.node_id,
            claim_txid: [0; 32],
            new_reserves_address: String::new(),
            confiscation_txid: None,
        }
        .discriminant();
        let (fetched, _) = self
            .fetch_ledger_updates_window(ledger_id, &[discriminant], None)
            .await;
        if !fetched.is_empty() {
            relay_acquires_cache()
                .lock()
                .unwrap()
                .insert(ledger_id.to_string(), fetched);
        }
    }

    /// Another participant's binding acquire that ends the lottery `our_armed` is in: one for
    /// its round or a later one ([`Node::others_binding_acquires`]), whose claim does not pay
    /// our own target (a claim of ours someone else named is not a loss of ours).
    pub(crate) fn lost_to_another(
        &self,
        ledger_id: &str,
        our_armed: &deposits_core::SignedLedgerUpdate,
    ) -> Option<OtherAcquire> {
        use deposits_core::messages::LedgerOperation;
        use deposits_core::TlvDecode;
        let Ok(LedgerOperation::DisputeArmed {
            rearm_round,
            target_reserves,
            ..
        }) = LedgerOperation::tlv_decode(&our_armed.message)
        else {
            return None;
        };
        let round = rearm_round.unwrap_or(1);
        let tip = our_armed.chain_hash();
        let fork_key = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            ledgers
                .iter()
                .find(|(k, arc)| {
                    let l = arc.read().unwrap();
                    k.starts_with(ledger_id)
                        && super::rearm::is_our_fork(k, &l.state.parent_pubkey, &self.node_id)
                        && l.history.iter().any(|u| u.chain_hash() == tip)
                })
                .map(|(k, _)| k.clone())?
        };
        let backend = self.wallet.chain_backend();
        let ours = target_reserves
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .ok()
            .map(|a| a.assume_checked().script_pubkey());
        self.others_binding_acquires(&fork_key, backend.as_ref())
            .into_iter()
            .filter(|a| a.round >= round)
            .find(|a| {
                let txid = bitcoin::Txid::from_byte_array(a.claim);
                match backend.get_tx(&txid) {
                    Ok(Some(tx)) => tx
                        .output
                        .first()
                        .is_some_and(|o| Some(&o.script_pubkey) != ours.as_ref()),
                    _ => false,
                }
            })
    }

    pub(crate) async fn arm_rearm_round(
        &self,
        ledger_id: &str,
        fork_key: &str,
        round: u32,
    ) -> Result<(), String> {
        use bitcoin::hashes::{hash160, Hash};
        use deposits_core::messages::LedgerOperation;
        let fork_arc = self
            .handler
            .ledgers
            .lock()
            .unwrap()
            .get(fork_key)
            .cloned()
            .ok_or("our fork is gone")?;
        let required_sats = {
            use crate::node::replacement_collateral::{
                compute_required_replacement_sats, CollateralPolicy,
            };
            let l = fork_arc.read().unwrap();
            compute_required_replacement_sats(
                l.state.total_deposit_balance(),
                l.state.collateral_amount,
                l.state.reserves_amount,
                &CollateralPolicy::default(),
            )
            .unwrap_or(0)
        };
        let compressed = bitcoin::CompressedPublicKey::from_slice(&self.node_id.serialize())
            .map_err(|e| e.to_string())?;
        let op_address = bitcoin::Address::p2wpkh(&compressed, self.wallet.network());
        let rc = match find_replacement_collateral(
            &*self.wallet.chain_backend(),
            op_address.script_pubkey().as_script(),
            required_sats,
            &crate::chain_backend::ScanRetry::quick(),
            &PledgeExclusion {
                reserve: if round >= 2 { rearm_pledge_reserve() } else { 0 },
                ..self.pledge_exclusion(ledger_id)
            },
        )
        .await
        .map_err(|e| e.to_string())?
        {
            CollateralLookup::Found(rc) => rc,
            CollateralLookup::Reserved { free } => {
                tracing::warn!(
                    "Re-arm round {} of {} skipped for the reserve: {} free coin(s) cover {} sats, \
                     and a re-arm leaves the last {} for new disputes (DEPOSITS_REARM_PLEDGE_RESERVE)",
                    round,
                    &ledger_id[..16.min(ledger_id.len())],
                    free,
                    required_sats,
                    rearm_pledge_reserve()
                );
                return Err(format!(
                    "re-arm skipped for the reserve ({} free, reserve {})",
                    free,
                    rearm_pledge_reserve()
                ));
            }
            _ => {
                return Err(format!(
                    "no collateral of {} sats at {}",
                    required_sats, op_address
                ))
            }
        };
        let preimage = self
            .round_preimage(ledger_id, round)
            .ok_or("no preimage for the round")?;
        let commitment_hash: [u8; 20] = *hash160::Hash::hash(&preimage).as_byte_array();
        let block = self.wallet.get_block_height().map_err(|e| e.to_string())?;
        let block_hash = self.wallet.get_block_hash().map_err(|e| e.to_string())?;
        {
            let mut fork = fork_arc.write().unwrap();
            fork.append_operation_with_block(
                LedgerOperation::DisputeArmed {
                    armed_block: block,
                    commitment_hash,
                    target_reserves: op_address.to_string(),
                    replacement_collateral: Some(rc),
                    rearm_round: Some(round),
                },
                block,
                block_hash,
            )
            .map_err(|e| format!("{:?}", e))?;
            if let Some(u) = fork.history.last_mut() {
                u.operator_id = self.node_id;
            }
        }
        self.sign_last_update(fork_key).map_err(|e| e.to_string())?;
        // Write-ahead: durable, or not published.
        self.write_ahead_fork(fork_key).map_err(|e| e.to_string())?;
        tracing::info!(
            "re-arm {}: lottery round {} unclaimed; armed round {}",
            &ledger_id[..16],
            round - 1,
            round
        );
        let _ = self.publish_fork(fork_key).await;
        Ok(())
    }
}

#[cfg(test)]
mod pledge_pick_vector {
    use super::{fork_holds, pick_pledge, ForkEvent, PledgeExclusion};
    use crate::chain_backend::UnspentOutput;

    /// "aa:0" in the vector is a short stand-in for a txid: pad it to 64 hex digits.
    fn outpoint(s: &str) -> bitcoin::OutPoint {
        let (t, v) = s.split_once(':').unwrap();
        let t = format!("{:0>64}", t);
        bitcoin::OutPoint::new(t.parse().unwrap(), v.parse().unwrap())
    }

    #[test]
    fn the_pledged_coin_matches_the_shared_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/pledge_pick.json")).unwrap();
        let mut n = 0;
        for c in v["cases"].as_array().unwrap() {
            let utxos: Vec<(UnspentOutput, u32)> = c["utxos"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| {
                    (
                        UnspentOutput {
                            outpoint: outpoint(u["outpoint"].as_str().unwrap()),
                            value_sats: u["sats"].as_u64().unwrap(),
                        },
                        u["confirmations"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            let mut exclude = PledgeExclusion {
                own: c["own"].as_str().map(outpoint),
                taken: c["taken"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| outpoint(t.as_str().unwrap()))
                    .collect(),
                ..Default::default()
            };
            for f in c["forks"].as_array().into_iter().flatten() {
                let events: Vec<ForkEvent> = f["ops"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|o| match o["op"].as_str().unwrap() {
                        "enter" => ForkEvent::Enter,
                        "arm" => ForkEvent::Arm {
                            pledge: o["pledge"].as_str().map(outpoint),
                            round: o["round"].as_u64().unwrap_or(1) as u32,
                        },
                        "yield" => ForkEvent::Yield,
                        "acquire" => ForkEvent::Acquire {
                            claim: outpoint(&format!("{}:0", o["claim"].as_str().unwrap())),
                            binds: o["binds"].as_bool().unwrap(),
                        },
                        other => panic!("unknown fork op {other}"),
                    })
                    .collect();
                // Binding acquires by other participants of the dispute, by round.
                let others: Vec<u32> = f["others"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|a| a["binds"].as_bool().unwrap())
                    .map(|a| a["round"].as_u64().unwrap() as u32)
                    .collect();
                let (pledges, custody) =
                    fork_holds(&events, f["retired"].as_bool().unwrap(), &others);
                exclude.taken.extend(pledges);
                exclude.taken.extend(custody);
            }
            let got = pick_pledge(
                &utxos,
                c["need"].as_u64().unwrap(),
                c["min_confs"].as_u64().unwrap() as u32,
                &exclude,
            )
            .map(|u| u.outpoint);
            assert_eq!(
                got,
                c["expect"].as_str().map(outpoint),
                "{}",
                c["name"].as_str().unwrap()
            );
            n += 1;
        }
        assert_eq!(n, 21);
    }

    /// ref6's own disk (regtest 1121-next4c, ledger 9e23c858…): its fork at seq 12, entered at
    /// 13 and armed (round 1) at 23, never yielded; the base on its disk carries 023d42a6's
    /// DisputeAcquire at 17, claim fa26e514…, a ROUND-2 claim on chain: it spends the re-arm
    /// spend 10c3f9f2 (CSV 144), which spends output 0 of the confiscation eac2120a of this
    /// dispute's vault 6556e3bc:0. That acquire is the one candidate, judged against the vault before the
    /// fork; ref6's own fork holds none.
    #[test]
    fn ref6s_lost_dispute_names_the_winners_acquire() {
        use crate::handler::DepositsHandler;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        let lid = "9e23c858c7537cd1c61476d0122ba056cf16607716f54aa31e3e6a2dc21f6689";
        let fork = DepositsHandler::load_single_ledger_from_jsonl(
            &format!("{lid}_000012_02a417593a974f4f"),
            &dir.join("ref6_lost_fork.jsonl"),
        )
        .expect("fork loads");
        // The base's rows as written, the winner's included (what the relay delivers; the base's
        // loader would drop them as foreign-operator updates).
        let base_rows: Vec<deposits_core::SignedLedgerUpdate> =
            std::fs::read_to_string(dir.join("ref6_lost_base.jsonl"))
                .unwrap()
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter(|v| v["type"] == "Update")
                .map(|mut v| {
                    v.as_object_mut().unwrap().remove("type");
                    serde_json::from_value(v).unwrap()
                })
                .collect();
        let loaded = DepositsHandler::load_single_ledger_from_jsonl(lid, &dir.join("ref6_lost_base.jsonl"))
            .expect("base loads");
        // The loaded base keeps the operator's chain (0..=12) and the custody transfer chained
        // onto it: 023d42a6's Enter/Armed/Yield/Armed/Acquire at 13..=17, chained by hash (90f5f8a).
        {
            use deposits_core::messages::LedgerOperation;
            use deposits_core::tlv::TlvDecode;
            let seqs: Vec<u64> = loaded.history.iter().map(|u| u.sequence_number).collect();
            assert_eq!(seqs, (0..=17).collect::<Vec<u64>>());
            let winner = loaded.history[13].operator_id;
            assert_eq!(&hex::encode(winner.serialize())[..8], "023d42a6");
            assert!(
                loaded.history[..13].iter().all(|u| u.operator_id == loaded.history[0].operator_id),
                "0..=12 are the operator's chain"
            );
            assert!(loaded.history[..13].iter().all(|u| u.operator_id != winner));
            assert!(loaded.history[13..].iter().all(|u| u.operator_id == winner));
            let ops: Vec<&str> = loaded.history[13..]
                .iter()
                .map(|u| match LedgerOperation::tlv_decode(&u.message) {
                    Ok(LedgerOperation::DisputeEnter { .. }) => "enter",
                    Ok(LedgerOperation::DisputeArmed { .. }) => "armed",
                    Ok(LedgerOperation::DisputeYield { .. }) => "yield",
                    Ok(LedgerOperation::DisputeAcquire { .. }) => "acquire",
                    Ok(_) => "other",
                    Err(_) => "undecodable",
                })
                .collect();
            assert_eq!(ops, ["enter", "armed", "yield", "armed", "acquire"]);
            for w in loaded.history[12..].windows(2) {
                assert_eq!(w[1].previous_hash, w[0].chain_hash(), "seq {}", w[1].sequence_number);
            }
            assert_eq!(loaded.state.operator_key, winner, "the operator after load is 023d42a6");
        }
        let ref6 = fork.history.last().unwrap().operator_id;
        assert_eq!(&hex::encode(ref6.serialize())[..16], "02a417593a974f4f");
        let (vault, cands) =
            super::dispute_acquire_candidates(&fork.history, &[&fork.history, &base_rows], &ref6)
                .expect("entered, with a vault");
        // The vault before the fork (QuorumBegin at 12, rung 0), which the confiscation
        // eac2120a spent on chain.
        assert_eq!(
            vault[0].to_string(),
            "6556e3bc21d138c52f50188fa0ba2edf546632b388783f5ee1e3dc9956b9cb8b:0"
        );
        assert_eq!(cands.len(), 1, "{cands:?}");
        let mut claim = cands[0].1;
        claim.reverse();
        assert_eq!(
            hex::encode(claim),
            "fa26e5147cc81c3c5305418156671aed674bf303ccfd3774b99359e1829cc843"
        );
        assert_eq!(&hex::encode(cands[0].0.serialize())[..16], "023d42a6c1ace983");
        // Our own fork alone holds no one else's acquire.
        let (_, alone) =
            super::dispute_acquire_candidates(&fork.history, &[&fork.history], &ref6).unwrap();
        assert!(alone.is_empty());
        // And the fork, read as it stands, still holds its pledge until that acquire is judged.
        let held = super::fork_holds(&super::fork_events(&fork.history, &ref6, &|_| false), false, &[]).0;
        assert!(!held.is_empty());
        let freed = super::fork_holds(&super::fork_events(&fork.history, &ref6, &|_| false), false, &[2]).0;
        assert!(freed.is_empty(), "023d42a6's binding round-2 acquire ends our round-1 arm");
    }

    /// `custody_coin.json`: real ref6 transactions. A claim's output 0 (full and subset) is
    /// custody; faucet payments and a confiscation are not.
    #[test]
    fn custody_coins_match_the_shared_vector() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/custody_coin.json")).unwrap();
        let mut n = 0;
        for c in v["cases"].as_array().unwrap() {
            let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize_hex(
                c["hex"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(tx.compute_txid().to_string(), c["txid"].as_str().unwrap());
            assert_eq!(
                super::claim_output_shaped(&tx, c["vout"].as_u64().unwrap() as u32),
                c["custody"].as_bool().unwrap(),
                "{}",
                c["name"].as_str().unwrap()
            );
            // Any other output of a claim is not output 0.
            assert!(!super::claim_output_shaped(&tx, 1));
            n += 1;
        }
        assert_eq!(n, 5);
    }

    /// The incident: ref6's coins as a 5000-sat pledge saw them. The 4.99M-sat claim outputs
    /// are smaller than the 5M faucet coins, so the custody coin was the pick; without it the
    /// pick is a faucet coin.
    #[test]
    fn a_claim_output_is_never_the_pick() {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/custody_coin.json")).unwrap();
        let txs: Vec<bitcoin::Transaction> = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| bitcoin::consensus::encode::deserialize_hex(c["hex"].as_str().unwrap()).unwrap())
            .collect();
        struct Chain(Vec<bitcoin::Transaction>);
        type E = crate::error::Error;
        impl crate::chain_backend::ChainBackend for Chain {
            fn get_tip_height(&self) -> Result<u32, E> {
                Ok(110)
            }
            fn get_block_hash(&self, _: u32) -> Result<bitcoin::BlockHash, E> {
                Err(E::Wallet("fake".into()))
            }
            fn get_block_height_if_in_best_chain(&self, _: &bitcoin::BlockHash) -> Result<Option<u32>, E> {
                Ok(None)
            }
            fn get_tx(&self, t: &bitcoin::Txid) -> Result<Option<bitcoin::Transaction>, E> {
                Ok(self.0.iter().find(|x| x.compute_txid() == *t).cloned())
            }
            fn get_tx_block_height(&self, _: &bitcoin::Txid) -> Result<Option<u32>, E> {
                Ok(Some(100))
            }
            fn is_output_unspent(&self, _: &bitcoin::Txid, _: u32) -> Result<Option<bool>, E> {
                Ok(Some(true))
            }
            fn find_unspent_output_at(&self, _: &bitcoin::Script) -> Result<Option<UnspentOutput>, E> {
                Ok(None)
            }
            fn find_spending_tx(
                &self,
                _: &bitcoin::OutPoint,
                _: &bitcoin::Script,
                _: u32,
            ) -> Result<Option<bitcoin::Transaction>, E> {
                Ok(None)
            }
            fn broadcast_tx(&self, _: &bitcoin::Transaction) -> Result<bitcoin::Txid, E> {
                Err(E::Wallet("fake".into()))
            }
        }
        let coin = |tx: &bitcoin::Transaction, vout: u32| {
            (
                UnspentOutput {
                    outpoint: bitcoin::OutPoint::new(tx.compute_txid(), vout),
                    value_sats: tx.output[vout as usize].value.to_sat(),
                },
                6u32,
            )
        };
        // subset claim (4995330 sats), ref6's claim of ad87b48b (54994314), a faucet coin (5M).
        let utxos = vec![coin(&txs[1], 0), coin(&txs[0], 0), coin(&txs[3], 0)];
        let ex = PledgeExclusion::default();
        assert_eq!(
            pick_pledge(&utxos, 5_000, 1, &ex).unwrap().outpoint,
            utxos[0].0.outpoint,
            "the custody coin is the smallest: what ref6 pledged"
        );
        let chain = Chain(txs.clone());
        let free = super::without_custody_coins(&chain, utxos.clone());
        assert_eq!(free.len(), 1);
        assert_eq!(
            pick_pledge(&free, 5_000, 1, &ex).unwrap().outpoint,
            utxos[2].0.outpoint
        );
    }

    /// ref6's 9e23c858 arm (seq 23, the fixture) declares fdff3a5f:0, ad87b48b's custody (a real
    /// claim, in custody_coin.json). Its claim is refused; a faucet coin would be claimed with; an
    /// unreadable funding transaction is refused for the pass. A same-round re-arm replaces it only
    /// while the vault is unspent: 9e23c858's vault 6556e3bc:0 was confiscated (eac2120a), so
    /// there the replacement is the next round's arm.
    #[test]
    fn ref6s_custody_pledge_is_never_claimed_with() {
        use crate::handler::DepositsHandler;
        use bitcoin::hashes::Hash;
        use deposits_core::messages::LedgerOperation;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
        let fork = DepositsHandler::load_single_ledger_from_jsonl(
            "9e23c858c7537cd1c61476d0122ba056cf16607716f54aa31e3e6a2dc21f6689_000012_02a417593a974f4f",
            &dir.join("ref6_lost_fork.jsonl"),
        )
        .unwrap();
        let ref6 = fork.history.last().unwrap().operator_id;
        let Some(LedgerOperation::DisputeArmed {
            replacement_collateral: Some(rc),
            ..
        }) = super::latest_dispute_armed(&fork.history)
        else {
            panic!("ref6's fork ends in an arm with a pledge")
        };
        let pledge = bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(rc.txid), rc.vout);
        assert_eq!(
            pledge.to_string(),
            "fdff3a5f90d57a71e0cf73b6c9565ad2f417708dbe96a26ef24d8b2eba4b5307:0"
        );
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/custody_coin.json")).unwrap();
        let tx = |k: &str| -> bitcoin::Transaction {
            let c = v["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"].as_str().unwrap().contains(k))
                .unwrap();
            bitcoin::consensus::encode::deserialize_hex(c["hex"].as_str().unwrap()).unwrap()
        };
        let custody = tx("ad87b48b");
        assert_eq!(custody.compute_txid(), pledge.txid);
        assert!(super::claim_collateral_check(pledge, Ok(Some(&custody))).is_err());
        let faucet = tx("(output 0)");
        let faucet_coin = bitcoin::OutPoint::new(faucet.compute_txid(), 0);
        assert!(super::claim_collateral_check(faucet_coin, Ok(Some(&faucet))).is_ok());
        let e = crate::error::Error::Wallet("rpc down".into());
        assert!(super::claim_collateral_check(faucet_coin, Err(&e)).is_err());
        // Re-arm in the same round: only while the vault is unspent, only for a custody coin.
        assert!(super::pledge_is_custody_rearm(Some(&custody), 0, true));
        assert!(!super::pledge_is_custody_rearm(Some(&custody), 0, false));
        assert!(!super::pledge_is_custody_rearm(Some(&faucet), 0, true));
        assert!(!super::pledge_is_custody_rearm(None, 0, true));
        let vault = super::dispute_vault(&fork.history, &ref6).unwrap();
        assert_eq!(
            vault[0].to_string(),
            "6556e3bc21d138c52f50188fa0ba2edf546632b388783f5ee1e3dc9956b9cb8b:0",
            "spent on chain by the confiscation eac2120a: no same-round re-arm here"
        );
    }

    /// Local policy (not in the shared vector): a re-arm leaves the last `reserve` free coins
    /// for new disputes; a round-1 arm (reserve 0) may take the last; keeping its own pledge
    /// is never refused.
    #[test]
    fn a_rearm_leaves_the_reserve_and_a_new_dispute_may_take_it() {
        let coin = |s: &str, sats: u64| {
            (
                UnspentOutput {
                    outpoint: outpoint(s),
                    value_sats: sats,
                },
                6u32,
            )
        };
        let utxos = vec![coin("aa:0", 50_000), coin("bb:1", 30_000), coin("cc:0", 10_000)];
        let ex = |own: Option<&str>, taken: &[&str], reserve| PledgeExclusion {
            own: own.map(outpoint),
            taken: taken.iter().map(|t| outpoint(t)).collect(),
            reserve,
        };
        // Two coins cover 20000: a re-arm with reserve 2 takes neither, a round-1 arm takes one.
        assert_eq!(pick_pledge(&utxos, 20_000, 1, &ex(None, &[], 2)), None);
        assert_eq!(
            pick_pledge(&utxos, 20_000, 1, &ex(None, &[], 0)).map(|u| u.outpoint),
            Some(outpoint("bb:1"))
        );
        // Three cover 5000: the re-arm takes the smallest, two stay.
        assert_eq!(
            pick_pledge(&utxos, 5_000, 1, &ex(None, &[], 2)).map(|u| u.outpoint),
            Some(outpoint("cc:0"))
        );
        // A taken coin is not free: two left of three, the re-arm takes none.
        assert_eq!(pick_pledge(&utxos, 5_000, 1, &ex(None, &["aa:0"], 2)), None);
        // Its own unspent pledge is kept whatever the reserve.
        assert_eq!(
            pick_pledge(&utxos, 20_000, 1, &ex(Some("bb:1"), &["bb:1"], 2)).map(|u| u.outpoint),
            Some(outpoint("bb:1"))
        );
    }
}

#[cfg(test)]
mod grounds_gate_tests {
    use super::grounds_gate_applies;

    /// ref6 / 9602cad2: entered on a verified proof, arm refused for want of
    /// collateral (every quick scan lost to another scan), then the re-arm pass
    /// (no hash, no anchor, no reason) was gated as "no grounds" forever. Once
    /// we have entered, only the arm is left and the gate must not apply.
    #[test]
    fn an_entered_dispute_is_not_gated_on_grounds_again() {
        // Joining on no grounds under grounded arms: wait for a proof.
        assert!(grounds_gate_applies(true, false, false));
        // Already entered on our own fork: the re-arm pass proceeds.
        assert!(!grounds_gate_applies(true, false, true));
        // A reason, or a ruleset that does not ground arms: never gated.
        assert!(!grounds_gate_applies(true, true, false));
        assert!(!grounds_gate_applies(false, false, false));
    }
}

#[cfg(test)]
mod fork_choice_tests {
    use super::{fork_for_dispute, ForkChoice, OwnForkKind};

    const L: &str = "5effb9e8465b4e023758ed26f82ba5d5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn key(seq: u64) -> String {
        format!("{}_{:06}_023853c81e318be4", L, seq)
    }

    /// ref7, signet 2026-11-20: an un-armed quorum_expired fork at 296850 and a
    /// self-detected Equivocation at 432510. The punitive dispute forks at its
    /// own base; it used to reuse the expiry fork and sign nothing.
    #[test]
    fn a_punitive_dispute_is_not_absorbed_by_an_unarmed_expiry_fork() {
        let ours = vec![(key(296_850), OwnForkKind::ExpiryUnarmed)];
        assert_eq!(
            fork_for_dispute(&key(432_510), true, &ours),
            ForkChoice::Create {
                bypassed: vec![key(296_850)]
            }
        );
    }

    /// An expiry dispute still reuses the fork it has (no new fork per watch pass).
    #[test]
    fn an_expiry_dispute_reuses_its_fork() {
        let ours = vec![(key(296_850), OwnForkKind::ExpiryUnarmed)];
        assert_eq!(
            fork_for_dispute(&key(296_900), false, &ours),
            ForkChoice::Use(key(296_850))
        );
    }

    /// ref4, signet 2026-11-22: an un-armed quorum_expired fork of 0aeebcc5 at 359090, the
    /// quorum re-established at 359228 (and rotated to 436154), and that quorum expired at
    /// 12209. The dispute of the new expiry is on a new ground and forks afresh; the answered
    /// fork stands down instead of standing in for it. Before a re-establishment the expiry
    /// fork is still reused (`an_expiry_dispute_reuses_its_fork`).
    #[test]
    fn an_answered_expiry_fork_does_not_stand_in_for_a_new_ground() {
        let fork = |seq: u64| {
            format!(
                "0aeebcc51f7dc6142f8e7a804e96fbe441ddb852401ad3f55837f7d13155669b_{}_03abec63a919379b",
                seq
            )
        };
        let ours = vec![(fork(359_090), OwnForkKind::ExpiryAnswered)];
        for punitive in [false, true] {
            assert_eq!(
                fork_for_dispute(&fork(492_103), punitive, &ours),
                ForkChoice::Create {
                    bypassed: vec![fork(359_090)]
                }
            );
        }
        // At its own base it takes no punitive DisputeEnter, as an un-armed expiry fork.
        assert!(matches!(
            fork_for_dispute(&fork(359_090), true, &ours),
            ForkChoice::Refuse(_)
        ));
    }

    /// The shared vector's `fork_reuse` cases (deposits-protocol/tests/vectors/
    /// expiry_dispute_ends.json, identical in the spec and cl-deposits): our expiry fork, its
    /// kind as `our_fork_kinds` computes it, and whether a new dispute uses it.
    #[test]
    fn fork_reuse_matches_the_shared_vector() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../deposits-protocol/tests/vectors/expiry_dispute_ends.json"
        ))
        .unwrap();
        let cases = v["fork_reuse"].as_array().unwrap();
        assert!(cases.len() >= 8);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let fork = key(c["fork_last_valid_sequence"].as_u64().unwrap());
            let kind = super::own_expiry_fork_kind(
                c["ruleset"].as_str().unwrap(),
                c["fork_last_valid_sequence"].as_u64().unwrap(),
                c["fork_armed"].as_bool().unwrap(),
                c["latest_quorum_begin_sequence"].as_u64(),
                c["rotation_spend_confirmed"].as_bool().unwrap(),
            );
            let choice = fork_for_dispute(
                &key(c["new_last_valid_sequence"].as_u64().unwrap()),
                c["new_punitive"].as_bool().unwrap(),
                &[(fork.clone(), kind)],
            );
            assert_eq!(
                choice == ForkChoice::Use(fork),
                c["reuse"].as_bool().unwrap(),
                "{name}: {kind:?} -> {choice:?}"
            );
        }
    }

    /// The fork at the proof's own base is used whatever else exists.
    #[test]
    fn the_fork_at_the_proofs_own_base_wins() {
        let ours = vec![
            (key(296_850), OwnForkKind::ExpiryUnarmed),
            (key(432_510), OwnForkKind::Live),
        ];
        assert_eq!(
            fork_for_dispute(&key(432_510), true, &ours),
            ForkChoice::Use(key(432_510))
        );
    }

    /// A live punitive or armed fork elsewhere still absorbs (one dispute per
    /// ledger acting on it), as before.
    #[test]
    fn a_live_punitive_fork_absorbs_a_later_proof() {
        let ours = vec![(key(400_000), OwnForkKind::Live)];
        assert_eq!(
            fork_for_dispute(&key(432_510), true, &ours),
            ForkChoice::Use(key(400_000))
        );
    }

    /// Over is over: a tombstoned fork is skipped elsewhere and refused at its base,
    /// and an expiry fork at the exact base cannot take a punitive DisputeEnter.
    #[test]
    fn tombstoned_and_same_base_expiry_forks() {
        let ours = vec![(key(296_850), OwnForkKind::Tombstoned)];
        assert_eq!(
            fork_for_dispute(&key(432_510), true, &ours),
            ForkChoice::Create { bypassed: vec![] }
        );
        assert!(matches!(
            fork_for_dispute(&key(296_850), true, &ours),
            ForkChoice::Refuse(_)
        ));
        let ours = vec![(key(296_850), OwnForkKind::ExpiryUnarmed)];
        assert!(matches!(
            fork_for_dispute(&key(296_850), true, &ours),
            ForkChoice::Refuse(_)
        ));
    }
}

/// The operation's name, for logs.
fn ledger_op_name(message: &[u8]) -> &'static str {
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;
    match LedgerOperation::tlv_decode(message) {
        Ok(LedgerOperation::DisputeEnter { .. }) => "DisputeEnter",
        Ok(LedgerOperation::DisputeArmed { .. }) => "DisputeArmed",
        Ok(LedgerOperation::DisputeYield { .. }) => "DisputeYield",
        Ok(LedgerOperation::DisputeAcquire { .. }) => "DisputeAcquire",
        Ok(_) => "other",
        Err(_) => "undecodable",
    }
}
