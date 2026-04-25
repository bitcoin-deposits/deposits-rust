● Security Contours

  What the protocol actually protects against

  ┌──────────────────────────────────┬──────────────────────────────────────────────────────────────┬──────────────────────────────────┐
  │              Attack              │                           Defense                            │             Strength             │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Solo operator theft of on-chain  │ Cosigned offer + block_height monotonicity → autonomous      │ Strong                           │
  │ deposit                          │ fraud proof                                                  │                                  │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Operator withholding a transfer  │ DeliveryEmbed causally anchors request;                      │ Strong if ≥1 quorum member       │
  │ / withdrawal                     │ service_response_blocks → censorship proof                   │ cooperates                       │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Parallel chains / equivocation   │ Majority cosign over previous_hash from each member's        │ Strong if honest majority        │
  │                                  │ validated tip                                                │                                  │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Unilateral reserves grab         │ Tapscript tiers exclude operator from Tier 0/1; collateral   │ Strong                           │
  │                                  │ slashed via quorum                                           │                                  │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Small-scale operator misbehavior │ Economic deterrence (collateral ≫ single-steal upside)       │ Strong for large thefts          │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Coalition ≤49% of network        │ Multi-ledger × independent-quorum exponential safety         │ Moderate — assumes wallets can   │
  │                                  │ (simulation only)                                            │ detect sybils                    │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Lightning preimage theft         │ Non-autonomous — depends on external payer cooperation       │ Weak, explicitly acknowledged    │
  ├──────────────────────────────────┼──────────────────────────────────────────────────────────────┼──────────────────────────────────┤
  │ Unanimous quorum collusion       │ None — "cannot protect against"                              │ None                             │
  └──────────────────────────────────┴──────────────────────────────────────────────────────────────┴──────────────────────────────────┘

  What is not covered (by design, stated in whitepaper)

  - Unilateral exit — funds can be frozen indefinitely if the whole network fails.
  - Privacy — all ledgers are public.
  - Availability — any single deposit is only as available as its operator.
  - Lightning fraud without a cooperating payer.
  - Unanimous quorum collusion.

  ---
  Likely mistakes in the design

  1. Lightning deterrence is weaker than framed

  The whitepaper argues "downside is existential, upside is bounded" — but the operator is a rational selective attacker:
  - They can steal only from payers they judge unlikely to cooperate (anonymous, commercial, one-shot).
  - They can self-pay their own invoices with high amounts to harvest preimages risk-free (every self-pay is a fake-theft-proof).
  - The attacker needs only ~1 victim (of thousands) to not share the preimage. In practice, most users will not.

  The economic model holds only if a victim sharing their preimage is roughly uniform across payments — it isn't.

  2. Lottery is manipulable by selective non-reveal

  DEP-06 lottery: last-to-reveal participants see others' preimages before deciding whether to reveal. Non-revealers "forfeit" — but if
  forfeiting has lower EV than the lottery, and an adversary controls several disputants, they can filter outcomes. CUSTODY_LOTTERY.md's
  preimage-size variant has the same issue: grinding a hash at commitment time isn't the problem; strategic non-reveal at settlement time
  is. Collateral slashing for non-reveal mitigates but doesn't eliminate this.

  3. deposit_id = SHA256(descriptor)[0..16] — 128 bits

  Birthday collisions (~2⁶⁴) are fine for accidents, but:
  - An attacker can front-run: pre-register a deposit_id with a descriptor under their control that matches a descriptor the legitimate
  user has not yet published.
  - A legitimate wallet recovering from seed via deposit_id lookup (DEP-08) could be led to a lookalike. Collision on the full descriptor
  isn't required if the operator only stores the truncated ID.
  - Fix: use full 32-byte ID or bind to (operator, descriptor).

  4. Relay-filter d tag truncated to 16 hex chars (64 bits)

  Implementers will trust the tag instead of re-checking the full ledger_id from TLV, causing cross-ledger confusion that is not a
  cryptographic break but a correctness bomb.

  5. Fee-change geometry compounds

  fee_change_limit_bps is per adjustment. No cumulative cap and no minimum period between adjustments (only fee_change_notice_blocks). With
   10% cap and frequent notices, fees double in ~7 rounds — a slow-exit drain.

  6. Self-fill is a load-bearing assumption

  PROPOSAL.md explicitly assumes "operators are assumed to fill their own ledgers" — meaning reserve confiscation is priced at zero. The
  entire safety model collapses to "collateral only." Wallets can't distinguish self-filled reserves from real ones; if they don't heavily
  discount self-heavy operators they're vulnerable.

  7. "Honest-majority quorum" detection is handwaved

  Safety depends on wallets identifying quorum independence via "quorum-mincut graph metrics." The protocol provides primitives but no
  algorithm, no reference metric, no UX. Early-stage wallets will skip this, and the simulation numbers (49% safe) assume perfect sybil
  detection.

  8. Cross-ledger slashing is an assumption, not a mechanism

  "Proof of non-conformance on ledger A can be presented to ledger B's quorum, triggering slashing there" — but each ledger B has its own
  quorum with its own incentives. Nothing forces them to act on another ledger's fraud proof if they don't also gain from it. The "inactive
   member" deterrent (DEP-11) only works for members of the misbehaving ledger.

  9. No length bounds on causal chains

  Fraud proofs include a causal_chain walked by verifiers. DEPs don't specify a maximum length → DoS vector against verifier
  infrastructure.

  10. Ephemeral Nostr events are a request-path SPOF

  Requests (Kind 20101) are ephemeral. An operator + relay collusion, or simple relay unreliability, is indistinguishable from censorship.
  DeliveryEmbed costs money per escalation, so honest users pay a constant tax in adversarial conditions.

  11. receive_requires_sig splits the trust between on-chain and lightning

  On the on-chain side, a cosigned offer is itself proof of intent to receive. On lightning, an invoice is too. But receive_requires_sig
  adds a second check the operator must enforce that produces no artifact — if the operator doesn't enforce it and credits anyway, there's
  no way to prove it later. Silent enforcement without audit trace is a smell.

  12. Encrypt-to-self with NIP-04

  Wallet state (Kind 30078) uses NIP-04 (AES-CBC, no MAC). ECDH(self, self) gives a static key; malleable ciphertext; no forward secrecy.
  NIP-44 exists and is the standard — DEP-04 still specifies NIP-04.

  13. Nostr identity derived at m/84'/0'/0'/0/0

  BIP-84 is Bitcoin's native-segwit path. Using the same keyspace for Nostr creates cross-protocol key-reuse risk: a flaw in any Nostr
  client that signs attacker-chosen messages can produce signatures usable against Bitcoin. NIP-06 (m/44'/1237') exists for this reason.

  14. operator_signing_data = cosign_data || all_cosig_data excludes member_ledger_hash

  The operator's signature commits to signatures but not to member_ledger_hash values. Those live inside cosig_data's cosignatures
  indirectly (the cosigner signed over them). It works — but only if the operator verifies each cosigner sig before signing. An operator
  who skips that step can be tricked into signing with fabricated ledger hashes, breaking the web-of-causality assumption.

  ---
  Likely mistakes implementors will make

  These are the traps the spec doesn't guard against strongly enough. Items marked ✗ were verified in the current code.

  1. ✗ Cosignature ordering not enforced. The spec says "sorted by pubkey"; deposits-protocol/src/types/updates.rs:78,100-105 iterates in
  insertion order when computing current_hash. Two different orderings → two different valid hashes → signature malleability / fork
  potential. This is live in the repo right now.
  2. ✗ max_transfer_timeout_blocks not enforced. Field is defined in QuorumAddMember but no validator compares it to incoming
  timeout_height. An attacker can lock their own funds with timeout = u32::MAX, then do… something. At minimum it breaks the quorum's
  promise to depositors about frozen-balance windows.
  3. ✗ Integer-overflow fragility in fee math. deposits-protocol/src/types/core.rs computes balance * annualized_bps * blocks /
  (52560*10000) in u64. With balance ≈ 10¹³ msats and bps + blocks in reasonable ranges, the multiplication can overflow before the
  division rescues it. Needs u128 intermediate. Silent wrap = free operator fee change.
  4. ✗ receive_requires_sig not enforced on offer/invoice creation (only on incoming transfer). DEP-08 lists all three paths. The operator
  is "honest" here by convention, but if an implementer skips even one, unsolicited crediting is possible and un-auditable.
  5. ✗ Descriptor parsing has no satisfaction-cost bound. Only max_descriptor_bytes gates it. Miniscript can encode exponential
  satisfaction in small bytes. A 200-byte descriptor can force worst-case O(2^n) paths through the satisfier during witness verification.
  DoS on every transfer.
  6. Block_height / block_hash accepted as declared. Code doesn't cross-check against an actual chain source. Implementers may or may not
  verify externally; the spec doesn't mandate it. Fraud proofs rely on block_height being truthful, so implementations that skip
  verification leak the "signed past deadline" guarantee.
  7. floor(n/2)+1 vs common BFT muscle memory. Implementers accustomed to 2/3+1 or ceil(2n/3) from other BFT systems will write the wrong
  formula, making the quorum stricter or more permissive than spec.
  8. Chain reorg handling. Updates embed block_height and block_hash. On reorg, a TransferFail with an orphaned block_hash becomes invalid
  evidence. No reorg tolerance specified — implementers will either ignore reorgs (unsafe) or over-rollback (liveness hit).
  9. TLV non-canonical encoding accepted. Decoders that tolerate unordered TLV records produce the same struct from two different byte
  streams; if either can be signed, you have malleability. Spec says records are "ordered by type number" but doesn't say decoders MUST
  reject out-of-order input.
  10. DepositKeyRotate message scope. Signing message is SHA256(new_descriptor) alone — no nonce, no deposit_id binding. If implementers
  reuse the same new_descriptor across deposits (say, a wallet rotates to a key it already uses), the signature is replayable. Spec should
  require binding the current deposit_id, sequence, or chain_hash into the message.
  11. Lottery commitment verification edge cases. HASH160 is 160 bits — low-collision. The "lowest score" rule ties are unspecified.
  Implementers may resolve ties by pubkey, by arrival order, or crash.
  12. Fee collection timing against fee-change effective_block. Pro-rated fees across the effective_block boundary — do you apply old rate
  for the prefix and new rate for the suffix, or new rate to the whole period? Spec says "when FeeCollect runs at or after effective_block,
   new fees take effect" — naïve read says new rate applies retroactively to the whole period. That's probably wrong.
  13. Courier timeout inversion. DEP-13 warns explicitly; every Lightning implementation has gotten this wrong at least once. Expect
  regressions.
  14. Obligation-limit off-by-one during settlement. Obligations change on Credit/Fulfill but locked_balance moves on Lock/Complete.
  Implementers routinely conflate these two. The spec's carefulness in DEP-05 §Balance Accounting suggests the authors already hit this
  bug.
  15. Equivocating member_ledger_hash. A member can claim any tip when cosigning. Detection requires operators / wallets to actually walk
  the referenced chain. Implementers will skip this because it's expensive.
  16. Replaceable-event version skew on Kind 10301 (subkeys) and 39100 (ads). Relays may serve stale replaceable events. Clients that trust
   the first-received version without checking created_at against the wallet's last-known version allow revocation rollback.
  17. spending_txid / new_outpoint_txid not enforced on-chain before acceptance. DEP-06 says wallets MUST wait for on-chain confirmation
  before accepting post-dispute updates. Implementers often skip this for UX and quietly accept fake DisputeAcquires.
  18. Nostr relay filtering trust. Relays can omit events. Wallets need to cross-check the hash chain for gaps — implementers will query
  one relay, see prev_hash == tip, and assume full history.
  19. Descriptor→pubkey extraction for the pk(hex) fast path vs complex miniscript (deposits-protocol/src/types/core.rs:369). Two code
  paths for signature verification nearly always have divergent edge-case behavior. A descriptor that is technically pk(...) with extra
  whitespace or casing routes to the slow path with different witness expectations.
  20. Concurrent deposit_open with colliding IDs. Two near-simultaneous DepositOpen requests with descriptors that truncate to the same
  16-byte ID: which wins, does either reveal info about the other, is the loser's request echoed back with an error that leaks the winner's
   descriptor? Unspecified.

  ---
  Priority fixes to file as issues

  1. Sort cosignatures before hashing (live malleability bug).
  2. Enforce max_transfer_timeout_blocks on TransferLock (missing validator).
  3. Widen fee math to u128 or add explicit saturation checks.
  4. Enforce receive_requires_sig on offer/invoice creation paths, with tests.
  5. Migrate Kind 30078 encrypt-to-self to NIP-44.
  6. Move Nostr identity to NIP-06 (m/44'/1237') or separate seed.
  7. Bind DepositKeyRotate signing message to deposit_id and current chain_hash.
  8. Add a test vector suite for canonical TLV encoding that decoders must reject for non-canonical input.
