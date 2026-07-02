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
/// leaves + partial-reveal leaves are committed into the tree — see
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
    use deposits_core::messages::LedgerOperation;
    use deposits_core::TlvDecode;

    let mut original_operator: Option<bitcoin::secp256k1::PublicKey> = None;
    let mut latest_qb_seq: Option<u64> = None;
    let mut qb_members: Vec<bitcoin::secp256k1::PublicKey> = Vec::new();

    for update in updates {
        if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
            match op {
                LedgerOperation::LedgerOpen { operator_id, .. } => {
                    original_operator = Some(operator_id);
                }
                LedgerOperation::QuorumBegin { quorum_members, .. } => {
                    let seq = update.sequence_number;
                    if latest_qb_seq.map(|cur| seq > cur).unwrap_or(true) {
                        latest_qb_seq = Some(seq);
                        qb_members = quorum_members.into_iter().map(|m| m.pubkey).collect();
                    }
                }
                _ => {}
            }
        }
    }

    let original_operator = original_operator?;
    latest_qb_seq?;

    let recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey> = qb_members
        .iter()
        .filter(|pk| **pk != original_operator)
        .map(|pk| pk.x_only_public_key().0)
        .collect();
    let recovery_threshold = (recovery_voters.len() / 2) + 1;
    Some((recovery_voters, recovery_threshold))
}

/// Disputant count `N` for this dispute's lottery, derived from a
/// ledger/fork history.
///
/// `N` fixes both the on-chain claim leaf's per-preimage length bound
/// `[17, 16+N]` and the winner arithmetic `sum mod N`, so the preimage
/// length chosen at arm-time must target the *same* `N` used at
/// confiscation-build and reveal/claim time. By the protocol invariant
/// "disputants = Q exactly" (operator barred from disputing own ledger),
/// `N = Q = |quorum_members \ {operator}|` from the latest `QuorumBegin`
/// — the same set [`recovery_voters_from_updates`] returns. That value is
/// immutable once `QuorumBegin` is on the fork, so every party and every
/// phase computes the identical `N`.
///
/// Returns `None` when no `QuorumBegin`/`LedgerOpen` is present or when
/// the resulting count falls outside the script's supported band
/// `2..=MAX_DISPUTANTS`.
pub(crate) fn dispute_lottery_n_from_history(
    history: &[deposits_core::SignedLedgerUpdate],
) -> Option<usize> {
    let (voters, _threshold) = recovery_voters_from_updates(history)?;
    let n = voters.len();
    if (2..=deposits_core::MAX_DISPUTANTS).contains(&n) {
        Some(n)
    } else {
        None
    }
}

#[cfg(test)]
mod confiscation_outputs_tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::{Amount, Network, ScriptBuf};

    fn pk(seed: u8) -> PublicKey {
        let secp = Secp256k1::new();
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[seed; 32]).unwrap())
    }

    fn lottery_script() -> ScriptBuf {
        // Any 34-byte witness-V1 script — the function doesn't introspect.
        let bytes = vec![0x51, 0x20] // OP_1 OP_PUSHBYTES_32
            .into_iter()
            .chain(std::iter::repeat(0xAB).take(32))
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
            cosign_signature: [0u8; 64],
            operator_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    fn qb(members: &[PublicKey]) -> LedgerOperation {
        LedgerOperation::QuorumBegin {
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
            protocol_version: None,
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
                },
            ),
            // Fork-time QuorumAddMember rows the old code would have folded in.
            update(
                6,
                m1,
                LedgerOperation::QuorumAddMember {
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
        let mut want: Vec<XOnlyPublicKey> =
            vec![m1, m2, m3].iter().map(|p| p.x_only_public_key().0).collect();
        want.sort_by_key(|k| k.serialize());

        assert_eq!(got, want, "recovery voters must be QB members minus operator");
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
        sorted.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        // Canonical (on-chain) recovery voters = QB members minus operator.
        let canonical_voters: Vec<XOnlyPublicKey> =
            vec![m1, m2, m3].iter().map(|p| p.x_only_public_key().0).collect();
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
        let stub_voters: Vec<XOnlyPublicKey> =
            sorted.iter().map(|p| p.pubkey).collect();
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
        const DEFAULT_GRACE_BLOCKS: u32 = 720;
        let grace_blocks: u32 = std::env::var("DEPOSITS_AUTO_DISPUTE_GRACE_BLOCKS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_GRACE_BLOCKS);

        // Snapshot: which ledgers are we a quorum member of that have
        // passed expiry by more than the grace period? Take a copy
        // under the lock so we can release before doing async work.
        let candidates: Vec<(String, u64)> = {
            let ledgers = self.handler.ledgers.lock().unwrap();
            let mut out = Vec::new();
            for (key, arc) in ledgers.iter() {
                // Skip fork compound keys (they end with `_NNNNNN_HEX16`).
                if key.len() != 64 {
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
                out.push((key.clone(), tip_seq));
            }
            out
        };

        for (ledger_id, tip_seq) in candidates {
            // Always invoke `auto_arm_for_dispute_with_anchor`; it is
            // idempotent (skips when a prior DisputeArmed already
            // declares replacement_collateral) and handles the re-arm
            // case (prior arm had None, now we have a funded UTXO).
            let ledger_prefix = &ledger_id[..16.min(ledger_id.len())];
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
                Ok(()) => tracing::info!(
                    "Auto-dispute fired for expired ledger {}",
                    ledger_prefix
                ),
                Err(e) => tracing::warn!(
                    "Auto-dispute for {} failed: {}",
                    ledger_prefix,
                    e
                ),
            }
        }
    }

    /// Auto-arm carrying the QuorumExpired anchor evidence inline on
    /// the fork-branch `DisputeEnter`. Called by the periodic task that
    /// detects `current_block > quorum_expiry` on ledgers this node
    /// cosigns for, and by future callers that have block info handy.
    pub(crate) async fn auto_arm_for_dispute_with_anchor(
        &self,
        ledger_id: &str,
        last_valid_seq: u64,
        anchor: Option<([u8; 32], u32)>,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{hash160, Hash};

        use deposits_core::messages::LedgerOperation;

        let our_pubkey = self.node_id;

        // 0. Create a fork of the disputed ledger (or reuse existing one)
        let fork_key = self.create_dispute_fork(ledger_id, last_valid_seq)?;

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

        // 1. Publish DisputeEnter on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            // The state machine is authoritative: if dispute_state has
            // moved past Normal then DisputeEnter has already been
            // applied (even if the history vector is missing the row —
            // e.g. JSONL truncated by a disk-full mid-write).
            // Re-publishing DisputeEnter on a Disputed/Armed fork would
            // be rejected by `validate_operation` anyway.
            let already_disputed = fork_ledger.state.dispute_state
                != deposits_core::types::DisputeState::Normal;

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
                        "auto_dispute".to_string()
                    },
                    anchor_block_hash,
                    anchor_block_height,
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

        // Determine the lottery's disputant count `N` (= Q) BEFORE taking
        // the fork write-lock (this is an async relay fetch and must not
        // straddle a held lock). We derive `N` from the ledger's canonical
        // chain fetched from the relay — the SAME source
        // `initiate_confiscations` uses to build the on-chain claim leaf's
        // `OP_SIZE` bounds — rather than the local fork history, which for
        // a disputing cosigner can be sparse (e.g. missing `QuorumBegin`).
        // Deriving both `N`s from the identical canonical source is what
        // guarantees the committed preimage length lands in the leaf's
        // `[17, 16+N]` band. Falls back to the local fork history if the
        // relay fetch yields nothing (offline / relay hiccup).
        let arm_n: usize = {
            let fetched = self
                .fetch_all_ledger_updates_paginated(ledger_id)
                .await;
            let from_relay = dispute_lottery_n_from_history(&fetched);
            match from_relay {
                Some(n) => n,
                None => {
                    let local = fork_arc.read().unwrap();
                    dispute_lottery_n_from_history(&local.history).ok_or_else(|| {
                        Error::Protocol(
                            "cannot determine lottery N (Q) for dispute preimage \
                             length at arm time (no QuorumBegin on relay or local \
                             fork history)"
                                .to_string(),
                        )
                    })?
                }
            }
        };

        // 3. Publish DisputeArmed with preimage commitment on the fork
        {
            let mut fork_ledger = fork_arc.write().unwrap();

            // Find the most recent DisputeArmed on this fork (if any). We
            // re-arm only when the prior arm was published with
            // `replacement_collateral: None` (the "fell back to a path
            // strict cosigners refuse" branch in this function) — typical
            // when the operator-key P2WPKH was unfunded at first-arm
            // time and got funded afterwards. The re-arm must reuse the
            // same `commitment_hash` so the lottery commitment is
            // immutable (otherwise a disputant could grind for a
            // winning commit after observing the entropy block).
            let prior_arm: Option<deposits_core::messages::LedgerOperation> = fork_ledger
                .history
                .iter()
                .rev()
                .find_map(|u| match LedgerOperation::tlv_decode(&u.message) {
                    Ok(op @ LedgerOperation::DisputeArmed { .. }) => Some(op),
                    _ => None,
                });

            let prior_collateral_was_none = matches!(
                &prior_arm,
                Some(LedgerOperation::DisputeArmed {
                    replacement_collateral: None,
                    ..
                })
            );

            let already_armed = prior_arm.is_some();

            if already_armed && !prior_collateral_was_none {
                tracing::info!("Already have DisputeArmed on fork (with replacement_collateral)");
            } else {
                let (commitment_hash, preimage_was_persisted): ([u8; 20], bool) =
                    if let Some(LedgerOperation::DisputeArmed { commitment_hash, .. }) =
                        &prior_arm
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
                        // fixed 32-byte HMAC *seed*; we shape it into a
                        // preimage whose *length* carries the lottery
                        // entropy and lands in `[17, 16+N]` for this
                        // dispute's disputant count `N` (= Q, from the
                        // fork's QuorumBegin — see `dispute_lottery_n`).
                        // The same seed + same `N` at reveal time
                        // reproduces the identical bytes, so we never
                        // persist it to disk and a disk-full event can't
                        // lose the dispute, while `HASH160(preimage)`
                        // stays consistent between commit and reveal.
                        let seed = self
                            .handler
                            .signer
                            .derive_dispute_lottery_preimage(ledger_id, last_valid_seq)
                            .map_err(|e| {
                                Error::Protocol(format!(
                                    "derive lottery preimage: {}",
                                    e
                                ))
                            })?;
                        // `N` (= Q) was resolved above from the canonical
                        // relay chain, before this write-lock was taken.
                        let n = arm_n;
                        let preimage =
                            deposits_core::tapscript_reserves::LotteryOutput::derive_lottery_preimage(
                                &seed, n,
                            )
                            .map_err(|e| {
                                Error::Protocol(format!(
                                    "shape lottery preimage: {}",
                                    e
                                ))
                            })?;
                        let h: [u8; 20] =
                            *hash160::Hash::hash(&preimage).as_byte_array();
                        (h, true)
                    };
                let _ = preimage_was_persisted;

                // Use P2WPKH address derived from our operator pubkey for target_reserves
                let pubkey_bytes: [u8; 33] = our_pubkey.serialize();
                let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey_bytes)
                    .map_err(|e| Error::Protocol(format!("Invalid pubkey: {}", e)))?;
                let target_reserves =
                    bitcoin::Address::p2wpkh(&compressed, self.wallet.network()).to_string();

                // Compute the cosigner-required replacement collateral floor
                // and pick a wallet UTXO that meets it. Per
                // DEP-03 §"Replacement collateral declaration", the
                // declared amount must satisfy
                // `obligations × (collateral / reserves) + fee_estimate`.
                // The disputant's UTXO must sit at the operator's P2WPKH
                // address — that's what RC4's claim-TX builder signs against.
                let replacement_collateral = {
                    use crate::node::replacement_collateral::{
                        compute_required_replacement_sats, CollateralPolicy,
                    };
                    let obligations_msat = fork_ledger.state.total_deposit_balance();
                    let collateral_msat = fork_ledger.state.collateral_amount;
                    let reserves_msat = fork_ledger.state.reserves_amount;
                    let policy = CollateralPolicy::default();
                    let required_sats = compute_required_replacement_sats(
                        obligations_msat,
                        collateral_msat,
                        reserves_msat,
                        &policy,
                    )
                    .unwrap_or(0);
                    let op_script = bitcoin::Address::p2wpkh(
                        &compressed,
                        self.wallet.network(),
                    )
                    .script_pubkey();
                    match self.wallet.find_utxo_for_script(&op_script) {
                        Ok(Some((outpoint, value_sats))) if value_sats >= required_sats => {
                            let txid_bytes: [u8; 32] = *outpoint.txid.as_ref();
                            tracing::info!(
                                "Auto-arm replacement collateral: {} sats from {}:{} (required {})",
                                value_sats, outpoint.txid, outpoint.vout, required_sats
                            );
                            Some(deposits_core::messages::ReplacementCollateral {
                                txid: txid_bytes,
                                vout: outpoint.vout,
                                amount: value_sats,
                            })
                        }
                        Ok(Some((_, value_sats))) => {
                            tracing::warn!(
                                "Auto-arm: operator-key P2WPKH UTXO has only {} sats, \
                                 required ≥ {} — declaring None and falling back to a \
                                 path strict cosigners will refuse",
                                value_sats, required_sats
                            );
                            None
                        }
                        Ok(None) => {
                            tracing::warn!(
                                "Auto-arm: no UTXO found at operator-key P2WPKH; \
                                 declaring no replacement_collateral"
                            );
                            None
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Auto-arm: esplora failure searching operator-key UTXO: {} \
                                 — declaring no replacement_collateral",
                                e
                            );
                            None
                        }
                    }
                };

                // For a re-arm (prior arm had collateral=None), abort if
                // we still don't have a funded UTXO — publishing
                // another `None` DisputeArmed gains nothing and just
                // grows the fork.
                if prior_collateral_was_none && replacement_collateral.is_none() {
                    tracing::info!(
                        "Re-arm skipped: still no funded UTXO at operator-key P2WPKH; \
                         will retry next periodic"
                    );
                    drop(fork_ledger);
                    return Ok(());
                }

                let armed_op = LedgerOperation::DisputeArmed {
                    armed_block: current_block,
                    commitment_hash,
                    target_reserves,
                    replacement_collateral,
                };

                fork_ledger
                    .append_operation_with_block(armed_op, current_block, block_hash)
                    .map_err(|e| {
                        Error::Protocol(format!("Failed to append DisputeArmed to fork: {:?}", e))
                    })?;

                // Patch operator_id
                if let Some(update) = fork_ledger.history.last_mut() {
                    update.operator_id = our_pubkey;
                }

                tracing::info!("Published DisputeArmed on fork");
                added_new_operations = true;
            }
        }

        // Sign the armed update on the fork
        self.sign_last_update(&fork_key)?;

        // Persist the fork (new JSONL file with compound key as filename)
        if let Err(e) = self.handler.persist_ledger_to_disk(&fork_key) {
            tracing::error!("Failed to persist fork ledger: {}", e);
        }

        // No marker file: the fork-branch's `dispute_state == Armed`
        // is the authoritative signal that we're armed for this
        // dispute. Both `initiate_confiscations` and the
        // `confiscation_sign` gate consult that directly.

        // Only broadcast if we actually added new operations to the fork.
        // Without this guard, incoming fork events re-trigger auto_arm_for_dispute,
        // which re-broadcasts all updates, creating an infinite feedback loop.
        if added_new_operations {
            if let Err(e) = self.broadcast_all_updates(&fork_key).await {
                tracing::warn!("Failed to broadcast dispute fork updates: {}", e);
            }
        } else {
            tracing::debug!("Fork already fully armed, skipping re-broadcast");
        }

        Ok(())
    }

    /// Look up our lottery preimage for `ledger_id`. Tries the legacy
    /// on-disk file first (random preimages from pre-derivation arms
    /// that still need to resolve), then falls back to deriving from
    /// the signer using the fork's `last_valid_seq` parsed from the
    /// fork tracking key. Returns `None` if we have no fork for this
    /// ledger.
    async fn lottery_preimage(&self, ledger_id: &str) -> Option<Vec<u8>> {
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
        // Fork key format: `<ledger_id>_<seq:06>_<pk_prefix_16hex>`.
        // The ledger_id is fixed-length 64 hex; seq starts at 65.
        let after_id = fork_key.get(65..)?;
        let seq_end = after_id.find('_')?;
        let last_valid_seq: u64 = after_id[..seq_end].parse().ok()?;
        // The signer returns a fixed 32-byte HMAC *seed*; the on-chain
        // lottery selects the winner from the preimage *length*, so we
        // shape the seed into a preimage whose length lands in the valid
        // range `[17, 16+N]` for this dispute's disputant count `N`.
        // `N` (= Q) is derived from the ledger's canonical relay chain —
        // the SAME source the confiscation build uses for the on-chain
        // `OP_SIZE` bounds — so arm-time and reveal-time derive the
        // identical `N` and the committed `HASH160(preimage)` matches the
        // revealed bytes. Falls back to the local fork history if the
        // relay fetch yields nothing.
        let seed = self
            .handler
            .signer
            .derive_dispute_lottery_preimage(ledger_id, last_valid_seq)
            .ok()?;
        let fetched = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        let n = dispute_lottery_n_from_history(&fetched)
            .or_else(|| self.dispute_lottery_n(&fork_key))?;
        deposits_core::tapscript_reserves::LotteryOutput::derive_lottery_preimage(&seed, n).ok()
    }

    /// Number of disputants `N` this dispute's lottery is built for.
    ///
    /// The on-chain claim leaf bounds every preimage to `[17, 16+N]` and
    /// [`LotteryOutput::calculate_winner`] computes `sum mod N`, both with
    /// `N = participants.len()` at confiscation-build time. By the
    /// protocol invariant "disputants = Q exactly" (the operator is barred
    /// from disputing their own ledger and every cosigner disputes a
    /// forked operator — see DEP-06 §"The Lottery"), that count equals the
    /// quorum size `Q = |quorum_members \ {operator}|` from the fork's
    /// latest `QuorumBegin`. That value is fixed at `QuorumBegin` and so is
    /// identical whether computed at arm-time or reveal-time, which is what
    /// keeps the committed `HASH160(preimage)` consistent with the revealed
    /// preimage's length.
    ///
    /// Returns `None` if the fork or its `QuorumBegin` cannot be found.
    fn dispute_lottery_n(&self, fork_key: &str) -> Option<usize> {
        let ledgers = self.handler.ledgers.lock().unwrap();
        let fork_arc = ledgers.get(fork_key)?;
        let fork = fork_arc.read().unwrap();
        dispute_lottery_n_from_history(&fork.history)
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
            .custom_tag(
                crate::nostr::TAG_LEDGER_REQ,
                [ledger_id],
            )
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
                    && tag.content().map(|c| c == "lottery_reveal").unwrap_or(false)
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

        let preimage = match self.lottery_preimage(ledger_id).await {
            Some(p) => p,
            None => {
                tracing::debug!("No preimage available for ledger {}", &ledger_id[..16]);
                return;
            }
        };
        let preimage_hex = hex::encode(&preimage);

        if self.have_revealed_lottery(ledger_id).await {
            tracing::debug!("Already revealed preimage for ledger {}", &ledger_id[..16]);
            return;
        }

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

            // Check if we've already claimed/yielded (completed marker)
            let completed_marker = self
                .data_dir
                .join(format!("lottery_completed_{}.marker", &ledger_prefix));
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
                    tracing::debug!("Lottery claim/yield not ready for {}: {}", ledger_prefix, e);
                }
            }
        }
    }

    /// Try to claim or yield for a specific ledger
    /// Returns Ok(true) if completed, Ok(false) if not ready, Err if failed
    pub(crate) async fn try_lottery_claim_or_yield(
        &self,
        ledger_id: &str,
    ) -> Result<bool, Error> {
        use crate::nostr::{KIND_LEDGER_REQUEST, KIND_LEDGER_UPDATE};
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        use bitcoin::secp256k1::PublicKey;
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tapscript_reserves::{LotteryOutput, LotteryParticipant};
        use deposits_core::{SignedLedgerUpdate, TlvDecode};

        use nostr_sdk::{Filter, Kind, TagKind};

        let our_pubkey = self.node_id;

        // Use the slow relay client for historical fetch
        let client = self.nostr.fetch_client();

        // Paginated fetch — bloated forks (thousands of duplicate
        // QuorumAddMember rows pre-2d3ae43 dedup-fix) overflow a
        // single 500-event window and would hide DisputeArmed at
        // the tail.
        let paginated_updates = self.fetch_all_ledger_updates_paginated(ledger_id).await;
        // Build a fake `Events`-shaped iterable below by walking the
        // already-decoded updates; the old code path encoded
        // SignedLedgerUpdate inside an `Event.content`, but
        // `fetch_all_ledger_updates_paginated` returns decoded
        // SignedLedgerUpdates directly.
        let _ = client; // pagination uses node.nostr.fetch_client internally

        // Fetch lottery reveals
        let reveal_filter = Filter::new()
            .kind(Kind::Custom(KIND_LEDGER_REQUEST))
            .custom_tag(crate::nostr::TAG_LEDGER_REQ, [ledger_id])
            .limit(100);

        let reveal_events = client
            .fetch_events(vec![reveal_filter], None)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to fetch reveals: {}", e)))?;

        // Extract DisputeArmed participants
        let mut participants: Vec<(PublicKey, LotteryParticipant)> = Vec::new();
        let mut our_armed: Option<SignedLedgerUpdate> = None;

        for update in &paginated_updates {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let LedgerOperation::DisputeArmed {
                    commitment_hash,
                    target_reserves,
                    ..
                } = op
                {
                    let x_only = update.operator_id.x_only_public_key().0;
                    participants.push((
                        update.operator_id,
                        LotteryParticipant::new(x_only, commitment_hash, target_reserves),
                    ));
                    if update.operator_id == our_pubkey {
                        our_armed = Some(update.clone());
                    }
                }
            }
        }

        if participants.is_empty() {
            return Err(Error::Protocol(
                "No DisputeArmed participants found".to_string(),
            ));
        }

        let our_armed = our_armed
            .ok_or_else(|| Error::Protocol("Could not find our DisputeArmed".to_string()))?;

        // Sort participants by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.1.pubkey.serialize().cmp(&b.1.pubkey.serialize()));

        // Collect revealed preimages.
        //
        // Preimages are matched to participants by HASH160(preimage) ==
        // commitment_hash, NOT by the reveal event's author key. The
        // reveal is a Nostr request authored by the node's Nostr/delegate
        // key, which is NOT the same as the participant's on-chain
        // (bitcoin x-only) operator key committed in DisputeArmed. Keying
        // the preimage map by `event.pubkey` and looking it up by the
        // participant's x-only key therefore never matched, and the claim
        // stalled forever on "Missing preimage from participant". The
        // commitment hash is the authorless, cryptographically-bound link.
        let mut revealed_preimages: Vec<Vec<u8>> = Vec::new();
        for event in reveal_events.iter() {
            let is_lottery_reveal = event.tags.iter().any(|tag| {
                tag.kind() == TagKind::custom("action")
                    && tag
                        .content()
                        .map(|c| c == "lottery_reveal")
                        .unwrap_or(false)
            });

            if is_lottery_reveal {
                if let Ok(content) = serde_json::from_str::<serde_json::Value>(&event.content) {
                    if let Some(preimage_hex) = content.get("preimage").and_then(|v| v.as_str()) {
                        if let Ok(preimage) = hex::decode(preimage_hex) {
                            if !revealed_preimages.contains(&preimage) {
                                revealed_preimages.push(preimage);
                            }
                        }
                    }
                }
            }
        }

        // Match each participant to a revealed preimage by commitment hash.
        use bitcoin::hashes::{hash160, Hash as _};
        let mut ordered_preimages: Vec<Vec<u8>> = Vec::new();
        for (_pubkey, participant) in &participants {
            let matched = revealed_preimages.iter().find(|p| {
                hash160::Hash::hash(p).to_byte_array() == participant.commitment_hash
            });
            match matched {
                Some(preimage) => ordered_preimages.push(preimage.clone()),
                None => {
                    // Not all commitments revealed yet — not an error,
                    // just wait for the remaining reveal(s).
                    return Ok(false);
                }
            }
        }

        // Determine winner
        let winner_index = LotteryOutput::calculate_winner(&ordered_preimages)
            .map_err(|e| Error::Protocol(format!("Failed to calculate winner: {:?}", e)))?;

        let (winner_pubkey, _winner_participant) = &participants[winner_index];

        // Recovery voters for the on-chain lottery address MUST come from
        // the ledger's latest QuorumBegin (minus operator) — the same set
        // `initiate_confiscations` committed to when it paid the lottery
        // UTXO. Any other set yields a different Taproot address and the
        // claim finds no UTXO to spend.
        let (recovery_voters, recovery_threshold) =
            recovery_voters_from_updates(&paginated_updates).ok_or_else(|| {
                Error::Protocol(
                    "No QuorumBegin/LedgerOpen found to derive recovery voters".to_string(),
                )
            })?;

        if *winner_pubkey == our_pubkey {
            // WE WON - claim the lottery
            tracing::info!("We won the lottery for ledger {}!", &ledger_id[..16]);
            self.claim_lottery(
                ledger_id,
                &participants,
                &ordered_preimages,
                winner_index,
                &our_armed,
                recovery_voters,
                recovery_threshold,
            )
            .await?;
        } else {
            // We lost - yield
            tracing::info!(
                "We lost the lottery for ledger {}. Publishing DisputeYield.",
                &ledger_id[..16]
            );
            self.publish_custody_yield(ledger_id, &our_armed).await?;
        }

        Ok(true)
    }

    /// Claim the lottery output as the winner
    pub(crate) async fn claim_lottery(
        &self,
        ledger_id: &str,
        participants: &[(
            bitcoin::secp256k1::PublicKey,
            deposits_core::tapscript_reserves::LotteryParticipant,
        )],
        ordered_preimages: &[Vec<u8>],
        winner_index: usize,
        our_armed: &deposits_core::SignedLedgerUpdate,
        recovery_voters: Vec<bitcoin::secp256k1::XOnlyPublicKey>,
        recovery_threshold: usize,
    ) -> Result<(), Error> {
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

        // Build lottery participants list
        let lottery_participants: Vec<LotteryParticipant> =
            participants.iter().map(|(_, p)| p.clone()).collect();

        // Recovery voters are supplied by the caller, derived from the
        // ledger's latest QuorumBegin (minus operator) — the SAME set the
        // confiscation TX committed to on-chain. Deriving them from the
        // DisputeArmed participants here (the old stub) produced a
        // different Taproot address, so `find_utxo_for_script` below found
        // no UTXO and the claim silently failed — leaving the ledger
        // disputed forever.

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

        // Find the lottery UTXO on-chain
        let lottery_script = lottery_output.address.script_pubkey();

        // Use wallet's esplora to find UTXO
        let lottery_utxo = self
            .wallet
            .find_utxo_for_script(&lottery_script)
            .map_err(|e| Error::Protocol(format!("Failed to find lottery UTXO: {:?}", e)))?;

        let (lottery_outpoint, lottery_amount) = lottery_utxo
            .ok_or_else(|| Error::Protocol("No unspent UTXO at lottery address".to_string()))?;

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

        // Build claim transaction
        let claim_fee = 400u64;
        let output_amount = lottery_amount.saturating_sub(claim_fee);

        let claim_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: lottery_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: target_address.script_pubkey(),
            }],
        };

        // Compute sighash
        let prevouts = vec![TxOut {
            value: Amount::from_sat(lottery_amount),
            script_pubkey: lottery_script.clone(),
        }];

        let leaf_hash = TapLeafHash::from_script(
            &lottery_output.lottery_script,
            bitcoin::taproot::LeafVersion::TapScript,
        );

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

        // Create witness
        let witness = lottery_output
            .create_claim_witness(&sig_bytes, ordered_preimages)
            .map_err(|e| Error::Protocol(format!("Failed to create witness: {:?}", e)))?;

        let mut claim_tx = claim_tx;
        claim_tx.input[0].witness = witness;

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
        let parent_chain_hash = our_armed.chain_hash();
        let sequence = our_armed.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&parent_chain_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Sign the update
        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(parent_chain_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let operator_sig_bytes = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::operator_update(ledger_id_bytes, sequence),
                msg_hash.as_ref(),
            )
            .map_err(|e| Error::Protocol(format!("operator sign: {}", e)))?;

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: parent_chain_hash,
            content_hash: new_hash,
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
        self.nostr
            .broadcast_ledger_update(&signed_update)
            .await
            .map_err(|e| Error::Protocol(format!("Failed to broadcast DisputeAcquire: {:?}", e)))?;

        tracing::info!("DisputeAcquire published! We are now the operator.");

        // Persist the DisputeAcquire to our OWN local fork ledger. Publishing
        // to Nostr alone left the on-chain win invisible to every local
        // reader: the DisputeAcquire never entered the winner's fork history,
        // so `deposits-wallet ledger custody` / `dispute status` /
        // `poll_dispute_acquire` (which scan the fork JSONL) still saw a
        // DISPUTED ledger under the original operator. Apply the SAME update
        // we just broadcast — byte-for-byte — through the state machine so
        // `state.operator_key` rotates to us, the disputed state clears
        // (`DisputeState::Normal`), the chain tip/sequence advance, and the
        // fork file on disk records the resolution. Routed through
        // `handler.commit_self_authored_update` (allowlisted, lock-serialized,
        // no mid-apply awaits) so it can't race the fork's actor.
        //
        // The fork is stored under a compound key
        // (`<ledger_id>_<seq>_<pk16>`); locate it via `find_our_fork`. If we
        // somehow have no local fork (e.g. a manual-recovery operator without
        // a persisted fork), skip local persistence rather than fail — the
        // broadcast already succeeded and losers reconverge from the relay.
        if let Some(fork_key) = self.handler.find_our_fork(ledger_id) {
            match self.handler.commit_self_authored_update(
                &fork_key,
                &operation,
                signed_update.clone(),
                current_block,
            ) {
                Ok(true) => tracing::info!(
                    "DisputeAcquire applied + persisted to local fork {} \
                     (custody rotated to us, dispute cleared)",
                    &fork_key[..16.min(fork_key.len())],
                ),
                Ok(false) => tracing::debug!(
                    "DisputeAcquire already present on fork {} — skipping",
                    &fork_key[..16.min(fork_key.len())],
                ),
                Err(e) => tracing::warn!(
                    "Failed to persist DisputeAcquire to fork {}: {} \
                     (broadcast still succeeded)",
                    &fork_key[..16.min(fork_key.len())],
                    e
                ),
            }
        } else {
            tracing::debug!(
                "No local fork for {} — skipping local DisputeAcquire persist \
                 (broadcast already published)",
                &ledger_id[..16.min(ledger_id.len())],
            );
        }

        Ok(())
    }

    /// Publish DisputeYield as a loser
    pub(crate) async fn publish_custody_yield(
        &self,
        ledger_id: &str,
        our_armed: &deposits_core::SignedLedgerUpdate,
    ) -> Result<(), Error> {
        use bitcoin::hashes::{sha256, Hash};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::{SignedLedgerUpdate, TlvEncode};
        use deposits_signer_api::SignContext;

        let our_pubkey = self.node_id;

        let current_block = self.wallet.get_block_height().unwrap_or(0);
        let current_block_hash = self.wallet.get_block_hash().unwrap_or([0u8; 32]);

        // Create DisputeYield operation
        let operation = LedgerOperation::DisputeYield;
        let message_bytes = operation.tlv_encode();

        // Build update continuing from our DisputeArmed. Chain on the
        // parent's `chain_hash()` (= SHA256(content_hash ||
        // operator_signature)), the same convention as every normal op and
        // the winner's DisputeAcquire — so the whole recovered chain uses
        // ONE convention and `validate_hash_chain` stays strict.
        let parent_chain_hash = our_armed.chain_hash();
        let sequence = our_armed.sequence_number + 1;
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&sequence.to_le_bytes());
        hash_input.extend_from_slice(&parent_chain_hash);
        hash_input.extend_from_slice(&message_bytes);
        let new_hash = *sha256::Hash::hash(&hash_input).as_byte_array();

        // Sign the update
        let update_msg = format!(
            "deposits:ledger:{}:{}:{}",
            hex::encode(parent_chain_hash),
            sequence,
            hex::encode(new_hash)
        );
        let msg_hash = sha256::Hash::hash(update_msg.as_bytes());

        let ledger_id_bytes: [u8; 32] = hex::decode(ledger_id)
            .map_err(|e| Error::Protocol(format!("Invalid ledger_id: {}", e)))?
            .try_into()
            .map_err(|_| Error::Protocol("Ledger ID must be 32 bytes".to_string()))?;

        let operator_sig_bytes = self
            .handler
            .signer
            .bip340_sign(
                &SignContext::operator_update(ledger_id_bytes, sequence),
                msg_hash.as_ref(),
            )
            .map_err(|e| Error::Protocol(format!("operator sign: {}", e)))?;

        let signed_update = SignedLedgerUpdate {
            message: message_bytes,
            message_type: 0x8001,
            operator_signature: operator_sig_bytes,
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
            cosign_signature: [0u8; 64],
            operator_id: our_pubkey,
            ledger_id: ledger_id_bytes,
            sequence_number: sequence,
            previous_hash: parent_chain_hash,
            content_hash: new_hash,
            block_height: current_block,
            block_hash: current_block_hash,
        };

        // Broadcast to Nostr
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
        // most-recent broadcast that actually verifies — gap-fill + structural +
        // embedding + causal chain + per-type evidence + on-chain steps, the
        // same checks the inbound receive path runs.
        let mut candidates: Vec<(u64, FraudBroadcast)> = events
            .iter()
            .filter_map(|e| {
                serde_json::from_str::<FraudBroadcast>(&e.content)
                    .ok()
                    .map(|b| (e.created_at.as_u64(), b))
            })
            .collect();
        candidates.sort_by(|a, b| b.0.cmp(&a.0)); // newest first
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
    /// bearing a valid operator signature. One such pair is unrecoverable proof
    /// of misbehavior, so any cosigner can independently confirm a confiscation
    /// is grounded without trusting a third party.
    pub(crate) async fn fetch_equivocation_inline_evidence(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use deposits_core::fraud::FraudProofType;
        use deposits_core::SignedLedgerUpdate;
        use std::collections::HashMap;

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

        // Group the original operator's updates by sequence; any sequence with
        // ≥2 distinct, signature-valid content_hashes is an equivocation.
        let mut by_seq: HashMap<u64, Vec<&SignedLedgerUpdate>> = HashMap::new();
        for u in &updates {
            if u.operator_id == original_operator {
                by_seq.entry(u.sequence_number).or_default().push(u);
            }
        }
        for group in by_seq.values() {
            for i in 0..group.len() {
                for j in (i + 1)..group.len() {
                    let (a, b) = (group[i], group[j]);
                    if a.content_hash != b.content_hash
                        && a.verify_operator_signature().is_ok()
                        && b.verify_operator_signature().is_ok()
                    {
                        return Some(FraudProofType::Equivocation);
                    }
                }
            }
        }
        None
    }

    /// Self-verifying inline evidence for a NonConformingCosignature confiscation
    /// — counterpart to [`fetch_equivocation_inline_evidence`]. The fault is a
    /// quorum-cosigned update that fails conformance: honest cosigners refuse
    /// such updates at cosign time, so a cosigned non-conforming update on the
    /// relay is proof the quorum colluded (or a cosigner is faulty). We fetch the
    /// ledger's history and, newest-first (the fault is typically the operator's
    /// latest cosigned op), reuse the audited `verify_non_conforming_cosignature`
    /// replay verifier on each cosigned update; the first that verifies grounds
    /// the confiscation. No embedding/9101 needed — the bad update is already
    /// durable on the relay.
    pub(crate) async fn fetch_non_conforming_cosig_inline_evidence(
        &self,
        ledger_id: &str,
    ) -> Option<deposits_core::fraud::FraudProofType> {
        use deposits_core::fraud::{FraudEvidence, FraudProof, FraudProofType};
        use deposits_core::messages::LedgerOperation;
        use deposits_core::tlv::TlvDecode;
        use deposits_core::SignedLedgerUpdate;
        use deposits_core::TlvEncode;

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
        let accused = hex::encode(original_operator.serialize());

        // The operator's QuorumBegin sequences — governing_quorumbegin_seq for a
        // fault at seq N is the latest QB at seq <= N.
        let qb_seqs: Vec<u64> = updates
            .iter()
            .filter(|u| u.operator_id == original_operator)
            .filter(|u| {
                matches!(
                    LedgerOperation::tlv_decode(&u.message),
                    Ok(LedgerOperation::QuorumBegin { .. })
                )
            })
            .map(|u| u.sequence_number)
            .collect();

        for u in updates.iter().rev() {
            // Only quorum-cosigned updates can be a NonConformingCosignature.
            if u.cosignatures.is_empty() {
                continue;
            }
            let Some(&governing_qb) =
                qb_seqs.iter().filter(|&&s| s <= u.sequence_number).max()
            else {
                continue; // pre-quorum update — not confiscation-relevant
            };
            let proof = FraudProof {
                proof_type: FraudProofType::NonConformingCosignature,
                accused: accused.clone(),
                ledger_id: ledger_id.to_string(),
                evidence: FraudEvidence::NonConformingCosignature {
                    fault_ledger_id: ledger_id.to_string(),
                    fault_sequence: u.sequence_number,
                    governing_quorumbegin_seq: governing_qb,
                    fault_update_hex: hex::encode(u.tlv_encode()),
                },
            };
            if deposits_core::fraud::verify_non_conforming_cosignature(
                &proof,
                &updates,
                &deposits_core::types::DenyAll,
            )
            .is_ok()
            {
                return Some(FraudProofType::NonConformingCosignature);
            }
        }
        None
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
                                if let (Some(signer_hex), Some(sig_hex)) = (
                                    result.get("signer").and_then(|v| v.as_str()),
                                    result.get("signature").and_then(|v| v.as_str()),
                                ) {
                                    if let (Ok(signer), Ok(sig_bytes)) =
                                        (signer_hex.parse::<PublicKey>(), hex::decode(sig_hex))
                                    {
                                        if sig_bytes.len() == 64
                                            && !pc.signatures.contains_key(&signer)
                                        {
                                            let mut sig_arr = [0u8; 64];
                                            sig_arr.copy_from_slice(&sig_bytes);
                                            pc.signatures.insert(signer, sig_arr);
                                            tracing::info!("  Confiscation {}: received signature from {}... ({}/{})",
                                                &prefix, &signer.to_string()[..16], pc.signatures.len(), required_sigs);
                                        }
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
        use bitcoin::Witness;

        let pc = match self.pending_confiscations.lock().unwrap().remove(prefix) {
            Some(pc) => pc,
            None => return,
        };

        tracing::info!(
            "  Building witness with {} signatures for {}...",
            pc.signatures.len(),
            prefix
        );

        let control_block = match pc.taproot_output.control_block_for_tier(pc.tier_index) {
            Some(cb) => cb,
            None => {
                tracing::error!("Failed to get control block for tier");
                return;
            }
        };

        let mut witness = Witness::new();
        let sorted_keys = pc.voter_set.sorted_x_only_pubkeys();

        for x_only in sorted_keys.iter().rev() {
            for voter in pc.voter_set.all_voters() {
                if voter.x_only_public_key().0 == *x_only {
                    if let Some(sig) = pc.signatures.get(&voter) {
                        witness.push(sig);
                    } else {
                        witness.push(&[] as &[u8]);
                    }
                    break;
                }
            }
        }

        witness.push(pc.leaf_script.as_bytes());
        witness.push(control_block.serialize());

        let mut confiscation_tx = pc.confiscation_tx;
        confiscation_tx.input[0].witness = witness;

        // Broadcast
        tracing::info!("  Broadcasting confiscation transaction...");

        // "Transaction already in block chain" or "already in mempool"
        // from bitcoind means another disputant got there first — the
        // tx is in fact confirmed/queued, so treat it as the same
        // happy-path as a fresh broadcast (write the marker, log).
        let broadcast_result = self.wallet.broadcast(&confiscation_tx);
        let confiscation_txid = confiscation_tx.compute_txid();
        let broadcast_succeeded = match &broadcast_result {
            Ok(_) => true,
            Err(e) => {
                let msg = e.to_string();
                msg.contains("Transaction already in block chain")
                    || msg.contains("txn-already-in-mempool")
                    || msg.contains("Transaction already in mempool")
            }
        };
        if broadcast_succeeded {
            tracing::info!(
                "Confiscation transaction in chain! Txid: {}",
                confiscation_txid
            );
            tracing::info!("  Lottery address: {}", pc.lottery_address);
        } else if let Err(e) = broadcast_result {
            tracing::error!("Failed to broadcast confiscation TX: {}", e);
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

            // Skip if we already have a pending confiscation for this ledger
            {
                let pending = self.pending_confiscations.lock().unwrap();
                if pending.contains_key(ledger_prefix) {
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
            let mut participants: Vec<LotteryParticipant> = Vec::new();
            let mut quorum_members: Vec<PublicKey> = Vec::new();
            let mut reserves_address: Option<String> = None;
            let mut ledger_hash: Option<[u8; 32]> = None;
            let mut original_operator: Option<PublicKey> = None;
            let mut latest_quorum_begin_seq: Option<u64> = None;
            let mut quorum_expiry_at_qb: u32 = 0;
            let mut ruleset_at_qb: Option<String> = None;

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
                            ..
                        } => {
                            // Keep the latest QuorumBegin (highest sequence) since
                            // multiple rotations may exist on the relay.
                            let seq = update.sequence_number;
                            if latest_quorum_begin_seq
                                .map(|cur| seq > cur)
                                .unwrap_or(true)
                            {
                                latest_quorum_begin_seq = Some(seq);
                                reserves_address = Some(reserves_id);
                                ledger_hash = Some(lh);
                                // Local var is Vec<PublicKey> for downstream
                                // Taproot reconstruction; extract just the keys.
                                quorum_members = qm.into_iter().map(|m| m.pubkey).collect();
                                quorum_expiry_at_qb = quorum_expiry;
                                ruleset_at_qb = protocol_version;
                            }
                        }
                        LedgerOperation::DisputeArmed {
                            commitment_hash,
                            target_reserves,
                            ..
                        } => {
                            let x_only = update.operator_id.x_only_public_key().0;
                            // Check if we already have this participant
                            if !participants.iter().any(|p| p.pubkey == x_only) {
                                participants.push(LotteryParticipant::new(
                                    x_only,
                                    commitment_hash,
                                    target_reserves,
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Need at least 2 participants to proceed
            if participants.len() < 2 {
                tracing::debug!(
                    "Not enough DisputeArmed participants yet ({}/2)",
                    participants.len()
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

            tracing::info!("All {} participants armed for ledger {}..., initiating confiscation ({} quorum members)",
                participants.len(), ledger_prefix, quorum_members.len());

            // Sort participants by pubkey for deterministic order
            participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

            // Build recovery voters (quorum minus original operator)
            let recovery_voters: Vec<XOnlyPublicKey> = quorum_members
                .iter()
                .filter(|pk| **pk != original_operator)
                .map(|pk| pk.x_only_public_key().0)
                .collect();

            let recovery_threshold = (recovery_voters.len() / 2) + 1;

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
            let utxo = match self.wallet.find_utxo_for_script(&script_pubkey) {
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
            let fee_rate = 2u64;
            let estimated_vsize = 200u64;
            let fee = fee_rate * estimated_vsize;
            let proof_type = match self.fetch_fraud_proof_type_for_ledger(&ledger_id).await {
                Some(pt) => Some(pt),
                None => match self.fetch_quorum_expired_inline_evidence(&ledger_id).await {
                    Some(pt) => Some(pt),
                    None => match self.fetch_equivocation_inline_evidence(&ledger_id).await {
                        Some(pt) => Some(pt),
                        None => self.fetch_non_conforming_cosig_inline_evidence(&ledger_id).await,
                    },
                },
            };
            let is_respectful = proof_type.map(|pt| pt.is_respectful()).unwrap_or(false);

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

            let outputs: Vec<TxOut> = match build_expected_confiscation_outputs(
                lottery_output.script_pubkey(),
                original_operator,
                self.wallet.network(),
                reserves_amount,
                fee,
                is_respectful,
                obligations_sats,
            ) {
                Ok(o) => {
                    if o.len() == 2 {
                        tracing::info!(
                            "  Bifurcated confiscation: lottery={} sats, operator change={} sats \
                             (obligations={} sats, fee={} sats, total={} sats)",
                            o[0].value.to_sat(),
                            o[1].value.to_sat(),
                            obligations_sats,
                            fee,
                            reserves_amount
                        );
                    }
                    o
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to build confiscation outputs for {}: {}",
                        ledger_prefix,
                        e
                    );
                    continue;
                }
            };

            // Provisional TX shape; lock_time is patched below once we
            // know which lifecycle tier we're spending under (degraded
            // tiers carry an absolute CLTV target the spending TX must
            // honour via nLockTime).
            let mut confiscation_tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: reserves_outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                }],
                output: outputs,
            };

            // Build the Taproot reserves structure for signing using
            // the ruleset that the disputed ledger committed to in
            // its latest QuorumBegin. Reconstructing under any other
            // ruleset would produce the wrong scriptPubKey.
            let voter_set = VoterSet::new(original_operator, quorum_members.clone());
            let voter_count = voter_set.all_voters().len();
            let ruleset = deposits_core::ruleset::resolve_or_legacy(
                ruleset_at_qb.as_deref(),
            );
            let threshold_config =
                (ruleset.tier_config_factory)(voter_count, quorum_expiry_at_qb);

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
            let current_height = self
                .wallet
                .get_block_height()
                .ok()
                .unwrap_or(0);
            let (tier_index, tier) = {
                let mut chosen: Option<(usize, &deposits_core::tapscript_reserves::ThresholdTier)> = None;
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

            // Patch the TX's nLockTime to match the tier's CLTV target.
            // Tier 0 has timelock_blocks=0 → unchanged. Tier 1+ require
            // nLockTime ≥ quorum_expiry + offset so the OP_CLTV in the
            // tier's leaf script is satisfied.
            confiscation_tx.lock_time = bitcoin::absolute::LockTime::from_consensus(
                tier.timelock_blocks,
            );

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

            let prevouts = vec![TxOut {
                value: Amount::from_sat(reserves_amount),
                script_pubkey: reserves_addr.script_pubkey(),
            }];

            let mut sighash_cache = SighashCache::new(&confiscation_tx);
            let sighash = match sighash_cache.taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            ) {
                Ok(sh) => sh,
                Err(e) => {
                    tracing::error!("Failed to compute sighash: {}", e);
                    continue;
                }
            };

            let sighash_bytes: [u8; 32] = *sighash.as_ref();

            // Sign with our key — Taproot script-spend on confiscation tx.
            let our_signature = match self.handler.signer.bip340_sign(
                &SignContext::no_ledger(SigPurpose::OnchainSighash),
                &sighash_bytes,
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Confiscation sighash sign failed: {}", e);
                    continue;
                }
            };

            let mut signatures: HashMap<PublicKey, [u8; 64]> = HashMap::new();
            signatures.insert(our_pubkey, our_signature);

            tracing::info!("  Signed with our key");

            // Request signatures from other quorum members via Nostr
            let required_sigs = tier.threshold;
            tracing::info!(
                "  Need {}/{} signatures, requesting co-signatures...",
                required_sigs,
                voter_count
            );

            // If we already have enough signatures (e.g., threshold=1), broadcast immediately
            if signatures.len() >= required_sigs {
                let control_block = match taproot_output.control_block_for_tier(tier_index) {
                    Some(cb) => cb,
                    None => {
                        tracing::error!("Failed to get control block for tier");
                        continue;
                    }
                };

                let mut witness = bitcoin::Witness::new();
                let sorted_keys = voter_set.sorted_x_only_pubkeys();

                for x_only in sorted_keys.iter().rev() {
                    for voter in voter_set.all_voters() {
                        if voter.x_only_public_key().0 == *x_only {
                            if let Some(sig) = signatures.get(&voter) {
                                witness.push(sig);
                            } else {
                                witness.push(&[] as &[u8]);
                            }
                            break;
                        }
                    }
                }

                witness.push(leaf_script.as_bytes());
                witness.push(control_block.serialize());

                let mut confiscation_tx = confiscation_tx;
                confiscation_tx.input[0].witness = witness;

                tracing::info!("  Broadcasting confiscation transaction (enough sigs locally)...");
                // See note at finalize_confiscation: an "already in
                // block chain / mempool" error means another disputant
                // beat us to the broadcast — still a success outcome.
                let broadcast_result = self.wallet.broadcast(&confiscation_tx);
                let txid = confiscation_tx.compute_txid();
                let broadcast_succeeded = match &broadcast_result {
                    Ok(_) => true,
                    Err(e) => {
                        let msg = e.to_string();
                        msg.contains("Transaction already in block chain")
                            || msg.contains("txn-already-in-mempool")
                            || msg.contains("Transaction already in mempool")
                    }
                };
                if broadcast_succeeded {
                    tracing::info!("Confiscation transaction in chain! Txid: {}", txid);
                } else if let Err(e) = broadcast_result {
                    tracing::error!("Failed to broadcast confiscation TX: {}", e);
                }
                continue;
            }

            // Send the request and store pending state (non-blocking)
            let unsigned_tx_bytes = bitcoin::consensus::encode::serialize(&confiscation_tx);
            let unsigned_tx_hex = hex::encode(&unsigned_tx_bytes);

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
                confiscation_tx,
                sighash_bytes,
                signatures,
                required_sigs,
                voter_set,
                tier_index,
                leaf_script,
                taproot_output,
                lottery_address: lottery_output.address.to_string(),
                ledger_prefix: ledger_prefix.to_string(),
                created_at: std::time::Instant::now(),
            };

            self.pending_confiscations
                .lock()
                .unwrap()
                .insert(ledger_prefix.to_string(), pending);
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
        let paginated_updates = self
            .fetch_all_ledger_updates_paginated(ledger_id)
            .await;
        if paginated_updates.is_empty() {
            return Err(Error::Protocol(
                "Failed to fetch ledger updates from relay".to_string(),
            ));
        }

        // Extract DisputeArmed participants. The recovery-voter set is
        // derived separately (below) from the canonical latest-QuorumBegin
        // source so the reconstructed lottery address matches the one the
        // confiscation TX actually paid.
        let mut participants: Vec<LotteryParticipant> = Vec::new();

        for update in &paginated_updates {
            if let Ok(op) = LedgerOperation::tlv_decode(&update.message) {
                if let LedgerOperation::DisputeArmed {
                    commitment_hash,
                    target_reserves,
                    ..
                } = op
                {
                    let x_only = update.operator_id.x_only_public_key().0;
                    if !participants.iter().any(|p| p.pubkey == x_only) {
                        participants.push(LotteryParticipant::new(
                            x_only,
                            commitment_hash,
                            target_reserves,
                        ));
                    }
                }
            }
        }

        if participants.len() < 2 {
            return Err(Error::Protocol(
                "Not enough participants for lottery".to_string(),
            ));
        }

        // Sort participants by x-only pubkey for deterministic order
        participants.sort_by(|a, b| a.pubkey.serialize().cmp(&b.pubkey.serialize()));

        // Recovery voters = latest-QuorumBegin members minus operator.
        // MUST match `initiate_confiscations` (the on-chain payer), or the
        // rebuilt lottery address won't find the confiscation UTXO and we
        // never trigger the reveal.
        let (recovery_voters, recovery_threshold) =
            recovery_voters_from_updates(&paginated_updates).ok_or_else(|| {
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

        // Check if lottery address has a UTXO with enough confirmations.
        // Ask Esplora directly for the tx's confirmation depth; no
        // local cache file needed.
        let lottery_script = lottery_output.address.script_pubkey();
        let outpoint = match self.wallet.find_utxo_for_script(&lottery_script)? {
            Some((op, _value)) => op,
            None => return Ok(false), // No UTXO at lottery address yet
        };
        let confs = match self
            .wallet
            .get_outpoint_value_and_confs(outpoint.txid, outpoint.vout)?
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
    /// chain_hash, or [0;32] for genesis). `content_hash` is computed the
    /// same way the recovery builders and `append_operation_with_block` do:
    /// SHA256(seq_le || prev || message). A non-zero operator_signature is
    /// stamped so `chain_hash()` (which folds it in) is meaningful.
    fn signed(seq: u64, operator: PublicKey, op: &LedgerOperation, prev: [u8; 32]) -> SignedLedgerUpdate {
        let message = op.tlv_encode();
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&seq.to_le_bytes());
        hash_input.extend_from_slice(&prev);
        hash_input.extend_from_slice(&message);
        let content_hash = *sha256::Hash::hash(&hash_input).as_byte_array();
        SignedLedgerUpdate {
            message,
            message_type: 0x8001,
            operator_id: operator,
            ledger_id: [7u8; 32],
            sequence_number: seq,
            previous_hash: prev,
            content_hash,
            block_height: 100 + seq as u32,
            block_hash: [0u8; 32],
            // Distinct non-zero sig per seq so chain_hash != content_hash and
            // each parent's chain_hash is unique.
            operator_signature: [seq as u8 + 1; 64],
            cosign_signature: [0u8; 64],
            cosigner_pubkey: None,
            member_ledger_hash: None,
            cosignatures: Vec::new(),
        }
    }

    fn ledger_open(operator: PublicKey) -> LedgerOperation {
        LedgerOperation::LedgerOpen {
            operator_id: operator,
            reserves_id: "bcrt1qopen".to_string(),
            genesis_block: 0,
            reserves_amount: 1_000_000,
            collateral_amount: 0,
        }
    }

    fn dispute_acquire(new_custodian: PublicKey) -> LedgerOperation {
        LedgerOperation::DisputeAcquire {
            new_custodian,
            claim_txid: [3u8; 32],
            new_reserves_address: "bcrt1qwinner".to_string(),
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
            reserves_id: "bcrt1qrot".to_string(),
            spending_txid: [0; 32],
            new_outpoint_txid: [1; 32],
            new_outpoint_vout: 0,
            amount: 900_000,
            quorum_expiry: 1_000_000,
            ledger_hash: u1.content_hash,
            quorum_members: vec![deposits_core::messages::QuorumMemberRef::pubkey_only(winner)],
            collateral_amount: 0,
            protocol_version: None,
        };
        let u2 = signed(2, winner, &qb, u1.chain_hash());
        let u3 = signed(3, winner, &deposit_open(0xCD), u2.chain_hash());

        LedgerConformanceValidator::validate_hash_chain(&[u0, u1, u2, u3])
            .expect("multi-hop recovery tail must validate");
    }

    fn quorum_add_member(member: PublicKey) -> LedgerOperation {
        LedgerOperation::QuorumAddMember {
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
