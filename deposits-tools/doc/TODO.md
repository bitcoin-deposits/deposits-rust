# Bitcoin Deposits Protocol - Implementation Status

## Core Systems

| # | System | Status | Description |
|---|--------|--------|-------------|
| 1 | Cryptographic Ledger | ✅ Complete | Hash chains, SignedLedgerUpdate, audit broadcasting |
| 2 | Multichannel Collateral | ✅ Complete | Attestations, validation, game theory enforcement |
| 3 | Dedicated Commitment Output | ✅ Complete | Tapscript reserves in commitment TX |
| 4 | Peer Multisig + VoterSet | ✅ Complete | VoterSet wired to reserves output, voter registration implemented |
| 5 | Invoice Cosigning | ✅ Complete | Partner cosigns invoices before valid |
| 6 | Enhanced Watchtower | ✅ Complete | Force-close detection, validation integration |
| 7 | Ledger Validation | ✅ Complete | validate_update_chain(), evaluate_and_vote() |
| 8 | Judgement Voting | ✅ Complete | Vote creation, submission, threshold checking |
| 9 | Tiered Recovery | ✅ Complete | Taproot (P2TR) reserves with ledger_hash, verification by reconstruction |
| 10 | Ledger Reassignment | ✅ Complete | ClaimManager, message handlers, signature collection |

---

## Detailed TODO

### System 2: Multichannel Collateral ✅
- [x] CollateralAttestationMsg (0x808D) codec support
- [x] CollateralAttestation message handler (stores attestations per ledger)
- [x] Collateral validation: reserves >= deposits AND attestations >= deposits
- [x] Ledger.validate_collateral_for_liability() with stale attestation detection
- [x] Ledger.can_add_deposit() and can_credit_payment() validation helpers
- [x] 8 new unit tests for collateral validation

**Game Theory:**
- Each ledger needs reserves ≥ deposits (direct backing)
- Each ledger also needs attestations ≥ deposits (collateral backing)
- Attestations = excess reserves in OTHER channels that partners can slash
- Same attestation backs multiple ledgers (capital efficiency)
- Theft requires colluding with enough partners that remaining attestations can't cover

### System 4: Peer Multisig + VoterSet ✅
- [x] Wire VoterSet into tapscript building for reserves output
- [x] Store voter set in ledger state (via collateral_partners field)
- [x] Ledger.construct_voter_set() derives VoterSet from ledger state
- [x] Implement voter registration via AddCollateralPartner message (0x8097)

### System 6: Enhanced Watchtower ✅
- [x] Detect force-close via process_block() and on_channel_closed()
- [x] Parse reserves output via check_for_created_outputs()
- [x] Ledger hash embedded in Taproot (P2TR) reserves output
- [x] verify_taproot_reserves() verifies on-chain script by reconstruction
- [x] Trigger recovery via initiate_recovery()
- [x] ChannelCloseTombstone broadcast for voter notification

### System 7: Ledger Validation ✅
- [x] validate_update_chain() in validation.rs
- [x] Hash chain integrity and signature verification
- [x] State replay against protocol rules
- [x] Reserves/collateral requirement checking
- [x] evaluate_and_vote() integrates validation with recovery

### System 8: Judgement Voting ✅
- [x] RecoveryVote created and signed in evaluate_and_vote()
- [x] submit_vote() collects votes in RecoveryManager
- [x] Threshold checking via vote counting
- [x] VoteResult returns when threshold met

### System 9: Tiered Recovery ✅
**Current**: Taproot (P2TR) reserves with ledger_hash commitment
**Architecture**: Pre-computed script_pubkey stored in ReservesOutputInfo
- [x] tapscript_reserves.rs: VoterSet, ThresholdTier with CSV timelocks
- [x] TapscriptReservesBuilder creates Taproot with tiered spending paths
- [x] ReservesSpendBuilder for claim tx construction
- [x] Integrate tapscript_reserves with commitment TX building (replaced P2WSH)
- [x] Add ledger_hash parameter to TapscriptReservesBuilder
- [x] verify_script_pubkey() and verify_taproot_reserves() for on-chain verification
- [x] Tests for verification by reconstruction

### System 10: Ledger Reassignment ✅
- [x] Wire ClaimManager to voting results (integrated in handler.rs)
- [x] Implement RecoveryClaimRequest flow (0x8091 message + handler)
- [x] Collect RecoveryClaimSignature from voters (0x8093 message + handler)
- [x] Build and broadcast claim transaction (broadcast_recovery_claim method)
- [x] RecoveryClaimComplete broadcast (0x8095 message) after confirmation
- [x] Codec support for all recovery claim messages

**Flow:**
1. RecoveryNonCompliant event → app calls initiate_claim_and_request_signatures()
2. RecoveryClaimRequest broadcast to voters → voters sign and respond
3. RecoveryClaimSignature collected → RecoveryClaimReady event when threshold met
4. App calls broadcast_recovery_claim() → transaction broadcast to Bitcoin
5. RecoveryClaimComplete broadcast → cleanup and RecoveryClaimCompleted event

---

## Priority Order

1. **System 6: Enhanced Watchtower** - Force-close detection is the trigger for everything
2. **System 7: Ledger Validation** - Must validate before voting
3. **System 8: Judgement Voting** - Collect votes after validation
4. **System 4: VoterSet** - Need voters identified for voting/claims
5. **System 9: Tiered Recovery** - Determine who can claim
6. **System 10: Ledger Reassignment** - Execute the claim
7. **System 2: Collateral** - Central to economic security (saving for last)

---

## Recently Completed

- [x] remote_ledger_hash in UpdateReserves for bidirectional verification
- [x] Invoice cosignature in NWC make_invoice
- [x] Payment preimage handling in NWC responses
- [x] ChannelCloseTombstone message for force-close notification
- [x] RecoveryVoteMsg and recovery.rs structures
- [x] ClaimManager and recovery_claim.rs structures
- [x] Channel watching for close detection (watch_channel, unwatch_channel, on_channel_closed)
- [x] ChannelClosedWithoutReserves event for collusion detection
- [x] Validation integration (evaluate_and_vote, validate_ledger methods in LighthouseService)
- [x] Vote submission after ledger validation
- [x] Taproot (P2TR) reserves replacing P2WSH 2-of-2 multisig
- [x] ledger_hash parameter in TapscriptReservesBuilder
- [x] verify_taproot_reserves() for on-chain verification by reconstruction
- [x] Pre-computed script_pubkey architecture in ReservesOutputInfo
- [x] VoterSet wiring: construct_voter_set() derives VoterSet from ledger state
- [x] build_taproot_reserves_script() uses VoterSet from ledger instead of hardcoded pubkeys
- [x] AddCollateralPartner message (0x8097) for voter registration during multi-party quorum setup
- [x] VoterSet fix: operator excluded from voters (they're being judged)
- [x] Recovery claim codec support (0x8091, 0x8093, 0x8095) for signature collection flow
- [x] CollateralAttestation (0x808D) codec and message handler
- [x] Collateral validation: validate_collateral_for_liability(), can_add_deposit(), can_credit_payment()
- [x] 8 unit tests for collateral validation (reserves + attestations game theory)
