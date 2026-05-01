# Appendix B: Wire Format Reference

> **Audience**: developers, integrators implementing the protocol in another language
> **Prereqs**: chapter 4 (concepts), chapter 6 (Nostr kinds)
> **DEPs**: DEP-02 (state model), DEP-04 (peer messaging), DEP-06 (fraud proofs)

This appendix is the lookup reference. It enumerates every Nostr kind, every TLV tag, every `LedgerOperation` discriminant, every wire envelope. The book chapters explain *why* each shape exists; this appendix tells you *what bytes go where* when you're decoding a relay event in a hex editor or porting the protocol to a new language.

The authoritative source code lives in:

- `deposits-protocol/src/messages/constants.rs` — message-type constants
- `deposits-protocol/src/messages/types.rs` — `LedgerOperation` variants and discriminants
- `deposits-protocol/src/types/updates.rs` — `SignedLedgerUpdate` layout and TLV codec
- `deposits-protocol/src/tlv.rs` — TLV primitive codec
- `deposits-protocol/src/wire_messages.rs` — peer-message envelope structs
- `deposits-protocol/src/fraud.rs` — fraud-proof and broadcast shapes
- `deposits-node/src/nostr.rs` — Nostr kind numbers and tag conventions
- `deposits-protocol/src/constants.rs` — protocol-wide policy constants

If a table in this appendix contradicts the source code, the source code wins and the appendix is wrong.

## 1. Nostr kinds

Every protocol message is a Nostr event. The kind number determines retention semantics: kinds 1000–9999 are durable (relays retain), 10000–19999 are replaceable (one event per pubkey-kind), 20000–29999 are ephemeral (auto-deleted after seconds), 30000–39999 are parameterized replaceable (one event per `(pubkey, kind, d-tag)`). See [Chapter 6](06-peer-messaging.md) for the design rationale.

| Kind | Name | Retention | Publisher | Consumer | Payload |
|------|------|-----------|-----------|----------|---------|
| `9100` | `LEDGER_UPDATE` | durable | operator | wallets, members, watchers | base64 TLV: `SignedLedgerUpdate` (every state-machine transition) |
| `9101` | `FRAUD_PROOF` | durable | wallet, member, watcher | quorum members of accused operator | JSON: `FraudBroadcast` (proof + causal chain) |
| `9103` | `LEDGER_DISPUTE` | durable | quorum member | other members of same quorum | JSON: `LedgerDispute` (last conforming sequence + signature) |
| `9104` | `RECOVERY_AGREE` | durable | quorum member | other disputing members | JSON: independently verified fork point + signature |
| `9106` | `CUSTODY_LOTTERY_REVEAL` | durable | disputant | other disputants | JSON: `CustodyLotteryReveal` (preimage of `commitment_hash`) |
| `10301` | `SUBKEY_LIST` | replaceable | account pubkey | request verifiers | JSON: active and revoked subkeys (DEP-04 §Subkey Attestation) |
| `20101` | `LEDGER_REQUEST` | ephemeral | wallet, courier, member | operator (or addressed peer) | JSON: `LedgerRequest` (action + params) |
| `20102` | `LEDGER_RESPONSE` | ephemeral | operator | requesting wallet/peer | JSON: `LedgerResponse` (success + result/error) |
| `20103` | `SWAP_REQUEST` | ephemeral | swap taker | swap-ad publisher | JSON: bilateral peer-swap proposal |
| `20104` | `SWAP_RESPONSE` | ephemeral | swap-ad publisher | requesting taker | JSON: accept/reject |
| `25500` | `LIGHTNING_VERIFY_REQUEST` | ephemeral, gift-wrapped | wallet | attestation verifier | encrypted JSON: `lightning_address` or challenge response |
| `25501` | `LIGHTNING_VERIFY_RESPONSE` | ephemeral, gift-wrapped | attestation verifier | originating wallet | encrypted JSON: challenge / verify result |
| `39100` | `LEDGER_ADVERTISE` | parameterized replaceable (`d` = ledger ID) | operator | discovering wallets | JSON: `LedgerAdvertisement` (terms, fees, limits, reserves, current block) |
| `39101` | `PRICE_ORACLE` | parameterized replaceable (`d` = `"btcusd"`) | operator | wallets displaying fiat | JSON: `{ price, currency, timestamp }` |
| `39102` | `AGENT_ADVERTISE` | parameterized replaceable (`d` = courier pubkey) | courier | wallets routing across ledgers | JSON: `AgentAdvertisement` (per-ledger fees and balances) |
| `39103` | `SWAP_ADVERTISE` | parameterized replaceable (`d` = source deposit ID) | swap publisher | takers | JSON: source ledger + amount + acceptable destinations |
| `55502` | `DOMAIN_ATTESTATION` | durable | attestation verifier | operators (deposit access control) | JSON: pubkey + lightning address + verification method (DEP-04) |

The reserved gap `9105` and the otherwise-unused `9102` are not assigned. Older drafts used `9105` for a now-removed recovery-vote event; verifiers must ignore unknown kinds in the `9100–9199` range.

The constants live in `deposits-node/src/nostr.rs:79–163`. The ring-signature attestation extension reuses `55502` with a `method: "ringsig"` discriminator (`deposits-ringsig/src/wire.rs:46`); see [Chapter 18](18-ring-signatures.md).

## 2. Tags

Nostr events carry single-letter tags that relays index for filterable subscriptions (NIP-01). The protocol uses these conventions consistently across kinds. Constants live in `deposits-node/src/nostr.rs:166–179`.

| Tag | Name (`TAG_*`) | Semantic | Filterable | Used on |
|-----|----------------|----------|------------|---------|
| `d` | `LEDGER_ID` | NIP-01 identifier; ledger ID (full or 16-hex prefix) on durable events | yes | 9100, 9101, 9103, 9104, 9106, 39100, 39102, 39103 |
| `l` | `LEDGER_REQ` | ledger ID (16-hex prefix) on ephemeral request/response events | yes | 20101, 20102, 9106 |
| `n` | `SEQUENCE` | sequence number within a ledger's hash chain | yes (range queries via `#n`) | 9100 |
| `t` | `OP_TYPE` | operation-type discriminant (numeric, see §4) | yes | 9100 |
| `i` | `DEPOSIT_ID` | affected deposit ID(s); one tag per deposit referenced by the operation | yes | 9100 (DepositOpen, transfers, invoice ops) |
| `e` | `EVENT_REF` | NIP-01 event reference; on responses, points at the request event ID | yes | 20102, 9104 (referenced dispute), 25501 |
| `p` | `PUBKEY` | NIP-01 pubkey reference; addressee on DMs/swaps, accused on fraud proofs | yes | 9101 (accused operator), 20103/4, 55502 (verified user) |
| `va` | (custom) | DEP-04 subkey attestation signature | no | 20101 (when sender is a delegated subkey) |
| `v` | (custom) | DEP-04 subkey account pubkey (xonly hex) | no | 20101 (paired with `va`) |

Truncated ledger IDs in `d`/`l` tags are 16 hex chars (8 bytes) — collision-resistant with `2^64` values while keeping tags compact. The full 64-char ledger ID is recoverable from the event content.

## 3. SignedLedgerUpdate layout

`SignedLedgerUpdate` is the canonical durable record. Every Kind 9100 event carries one, base64-encoded in the event content. The TLV encoding sorts fields by tag number (BTreeMap-backed); decoders MUST reject non-canonical orderings (`TlvError::NonCanonicalOrder`). Byte sizes below are after the per-field varint type+length prefixes are stripped — those add 2–4 bytes per field.

Source: `deposits-protocol/src/types/updates.rs:1071–1213`.

| TLV tag | Field | Type | Size | Description |
|---------|-------|------|------|-------------|
| `0` | `operator_id` | compressed pubkey | 33 bytes | Operator's secp256k1 public key |
| `2` | `ledger_id` | bytes | 32 bytes | `SHA256(operator_key ‖ reserves_id ‖ genesis_block_le)` |
| `4` | `sequence_number` | u64 BE | 8 bytes | Position in the chain; starts at 0 (LedgerOpen) |
| `6` | `previous_hash` | bytes | 32 bytes | `chain_hash()` of the previous update; zeros for sequence 0 |
| `8` | `message` | bytes | variable | TLV-encoded `LedgerOperation` (see §4) |
| `10` | `block_height` | u32 BE | 4 bytes | Bitcoin chain tip when update was created. Omitted if zero |
| `12` | `block_hash` | bytes | 32 bytes | Bitcoin block hash at `block_height`. Omitted if all-zero |
| `14` | `cosigner_pubkey` | compressed pubkey | 33 bytes | **Legacy single-cosig**. Omitted when `cosignatures` (tag 22) is present |
| `16` | `member_ledger_hash` | bytes | 32 bytes | **Legacy single-cosig**. Cosigner's chain tip at cosign time |
| `18` | `cosign_signature` | bytes | 64 bytes | **Legacy single-cosig**. Schnorr over the cosign data |
| `20` | `operator_signature` | bytes | 64 bytes | Schnorr over `operator_signing_data()` (cosign data + cosignatures) |
| `22` | `cosignatures` | bytes | variable | **Multi-cosig** (post-`QuorumBegin`). Sequence of length-prefixed `CosignEntry` records, sorted by `cosigner_pubkey` |

Tag 22 (`cosignatures`) supersedes tags 14/16/18. When tag 22 is present, the legacy fields are absent and ignored. Each entry inside tag 22 is `[u16 BE entry_len = 129][33-byte pubkey][64-byte sig][32-byte member_ledger_hash]`. Entries MUST be sorted by `cosigner_pubkey.serialize()` byte-comparison (canonicalized on both encode and decode to defeat malleability).

`content_hash` is **not** transmitted on the wire. Receivers recompute it via `compute_hash()`:

```text
content_hash = SHA256(
    sequence_number_le ‖
    previous_hash ‖
    message ‖
    for each sorted CosignEntry: (member_ledger_hash ‖ cosign_signature)
)
```

For legacy single-cosig the trailing run is `[member_ledger_hash if present][cosign_signature if non-zero]`. The `chain_hash()` used as the next update's `previous_hash` is `SHA256(content_hash ‖ operator_signature)`.

The cosigner's signing message is BIP-340 tagged: `SHA256(SHA256("deposits/cosign") ‖ SHA256("deposits/cosign") ‖ cosign_data ‖ member_ledger_hash)`, where `cosign_data = sequence_number_le ‖ previous_hash ‖ message`. The operator's signing message is `SHA256(operator_signing_data())` (untagged Schnorr).

## 4. LedgerOperation variants

The operation message is its own TLV stream. The first TLV field (tag 0, length 1) is the discriminant byte; downstream tags carry per-variant data. The discriminant table below also serves as the `t`-tag value on Kind 9100 events for relay-side filtering.

Source: `deposits-protocol/src/messages/types.rs:505–637`.

### Lifecycle

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x01` | 1 | `LedgerOpen` | `operator_id`, `reserves_id`, `genesis_block`, `reserves_amount`, `collateral_amount` |
| `0x3C` | 60 | `LedgerClose` | (no fields) |

### Quorum and reserves rotation

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x0C` | 12 | `QuorumBegin` | `reserves_id`, `spending_txid`, `new_outpoint_txid`, `new_outpoint_vout`, `amount`, `quorum_expiry`, `ledger_hash`, `quorum_members[]`, `collateral_amount` |
| `0x2B` | 43 | `QuorumAddMember` | `quorum_member`, `quorum_member_signature`, `member_ledger_id`, optional fee/timing minimums, optional compensation |
| `0x2C` | 44 | `QuorumRemoveMember` | `quorum_member`, `operator_signature` |
| `0x2E` | 46 | `QuorumJoin` | `operator_id`, `ledger_id`, `membership_expires` (recorded on the joining member's own ledger) |

### Deposits

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x14` | 20 | `DepositOpen` | `deposit_id`, `descriptor`, `fees`, `transfer_fees`, `payment_hash`, `invoice`, `cosigner_guarantee_signature`, `receive_requires_sig`, `fee_change_after_blocks`, `fee_change_notice_blocks`, `fee_change_limit_bps` |
| `0x15` | 21 | `DepositClose` | `deposit_id` |
| `0x16` | 22 | `FeeChange` | `deposit_id`, `new_fees`, `effective_block` |
| `0x17` | 23 | `DepositKeyRotate` | `deposit_id`, `new_descriptor`, `witness` |

### Invoice (Lightning)

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x1E` | 30 | `InvoiceCredit` | `payment_hash`, `deposit_id`, `amount`, `invoice_id`, `sequence_number` |
| `0x1F` | 31 | `InvoiceLock` | `deposit_id`, `amount`, `payment_id`, `sequence_number`, `witness` |
| `0x20` | 32 | `InvoiceFail` | `deposit_id`, `amount`, `payment_id`, `sequence_number` |
| `0x21` | 33 | `InvoiceFulfill` | `deposit_id`, `amount`, `payment_id`, `sequence_number`, `witness`, `preimage` |

### On-chain

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x23` | 35 | `OnchainCredit` | `txid`, `vout`, `deposit_id`, `amount`, `funding_address` |
| `0x24` | 36 | `OnchainLock` | `deposit_id`, `amount`, `fee_sats`, `destination_address`, `withdrawal_id`, `witness` |
| `0x25` | 37 | `OnchainFail` | `deposit_id`, `withdrawal_id` |
| `0x26` | 38 | `OnchainFulfill` | `deposit_id`, `withdrawal_id`, `amount`, `txid`, `destination_address` |

### Inter-deposit transfers

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x46` | 70 | `TransferLock` | `nonce` (32 bytes — wallet-controlled embed for fraud proofs), `source_deposit_id`, `destination_deposit_id`, `amount`, `fee`, `completion_script`, `timeout_height`, `transfer_id`, `witness` |
| `0x47` | 71 | `TransferComplete` | `transfer_id`, `script_witness` |
| `0x48` | 72 | `TransferFail` | `transfer_id`, `block_hash`, `reason` (1 = timeout; 0 reserved/invalid) |

### Maintenance

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x32` | 50 | `FeeCollect` | `deposit_id`, `amount`, `block_height` |

### Custody dispute and recovery

These all encode at the envelope-level message type `LEDGER_UPDATE` (`0x8001`); the discriminant byte distinguishes them. See [Chapter 12](12-recovery-pipeline.md) and [Chapter 13](13-custody-lottery.md).

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x36` | 54 | `DisputeEnter` | `last_valid_sequence`, `reason` |
| `0x37` | 55 | `DisputeAcquire` | `new_custodian`, `claim_txid`, `new_reserves_address` |
| `0x38` | 56 | `DisputeYield` | (no fields — tombstones a non-winning branch) |
| `0x39` | 57 | `DisputeArmed` | `armed_block`, `commitment_hash` (HASH160, 20 bytes), `target_reserves` |

### Delivery escalation

| Disc (hex) | Disc (dec) | Variant | Key fields |
|------------|------------|---------|------------|
| `0x50` | 80 | `DeliveryEmbed` | `request_hash`, `target_ledger_id`, `target_operator` (appended to the *member's* ledger; see [Chapter 15](15-delivery-escalation.md)) |

Discriminants `0x00`, `0x02–0x0B`, `0x0D–0x13`, `0x18–0x1D`, `0x22`, `0x27–0x2A`, `0x2D`, `0x2F–0x31`, `0x33–0x35`, `0x3A–0x3B`, `0x3D–0x45`, `0x49–0x4F`, `0x51+` are unassigned. Decoders MUST return `CodecError::InvalidDiscriminant` rather than coerce to a default.

`embedded_hash()` returns the `nonce` field of `TransferLock` and the `request_hash` field of `DeliveryEmbed`. These are the only two operations that anchor 32-byte external hashes for fraud-proof embedding ([Chapter 11](11-fraud-proofs.md)).

## 5. Envelope message-type catalogue

The 16-bit `message_type` field on `SignedLedgerUpdate` and on peer-protocol envelopes is distinct from the operation discriminant. Operations marked `LEDGER_UPDATE` share the catch-all `0x8001`; the discriminant byte inside the TLV body distinguishes them. All values are odd to satisfy BOLT-1 "safe ignorability."

Source: `deposits-protocol/src/messages/constants.rs:17–115`.

### Envelope wire types (peer-to-peer transport)

| Hex | Const | Purpose |
|-----|-------|---------|
| `0x8001` | `LEDGER_UPDATE` | Carries a `SignedLedgerUpdate`. Default for dispute and delivery operations |
| `0x8003` | `LEDGER_UPDATE_RESPONSE` | Cosign reply or rejection |
| `0x8005` | `HANDSHAKE` | Initial peer greeting (legacy LDK path) |
| `0x8007` | `HANDSHAKE_RESPONSE` | Reply |
| `0x8009` | `SYNC` | Catch-up request from sequence N |
| `0x800B` | `SYNC_RESPONSE` | Length-prefixed updates |
| `0x800D` | reserved | Was `RECOVERY` (Lightning-channel-era; removed) |
| `0x800F` | reserved | Was `RECOVERY_RESPONSE`; removed |
| `0x8011` | `COORDINATION` | Generic coordination envelope |
| `0x8013` | `COORDINATION_RESPONSE` | Reply |

### Operation message types (used in `SignedLedgerUpdate.message_type`)

| Hex | Const | Operation |
|-----|-------|-----------|
| `0x801D` | `LEDGER_CLOSE` | `LedgerClose` |
| `0x8021` | `MAINTENANCE_FEE_COLLECT` | `FeeCollect` |
| `0x8031` | `RECEIVING_COSIGN_INVOICE` | (peer message — not a ledger op) |
| `0x8033` | `RECEIVING_CREDIT_PAYMENT` | `InvoiceCredit` |
| `0x8035` | `UNCREDITED_PAYMENT` | (peer message) |
| `0x8041` | `SENDING_LOCK_PAYMENT` | `InvoiceLock` |
| `0x8043` | `SENDING_FAIL_PAYMENT` | `InvoiceFail` |
| `0x8045` | `SENDING_FULFILL_PAYMENT` | `InvoiceFulfill` |
| `0x8057` | `SIGNED_UPDATE` | (control) |
| `0x8059` | `SYNC_REQUEST` | (control) |
| `0x805B` | `LEDGER_EXPORT_REQUEST` | (control — partner export) |
| `0x805D` | `LEDGER_EXPORT_RESPONSE` | (control) |
| `0x8061` | `LEDGER_OPEN_REQUEST` | `LedgerOpen` |
| `0x8063` | `LEDGER_OPEN_RESPONSE` | (peer reply) |
| `0x8071` | `ACK` | Generic acknowledgement |
| `0x8081` | `QUORUM_JOIN_REQUEST` | (peer) |
| `0x8083` | `QUORUM_JOIN_RESPONSE` | (peer) |
| `0x8085` | `QUORUM_STATE_SYNC` | (peer) |
| `0x8087` | `QUORUM_VOTE_REQUEST` | (peer) |
| `0x8089` | `QUORUM_VOTE` | (peer) |
| `0x808B` | `QUORUM_MEMBERSHIP_CHANGE` | (peer) |
| `0x808F` | `RECOVERY_VOTE` | Recovery legacy (deprecated) |
| `0x8091` | `RECOVERY_CLAIM_REQUEST` | Recovery legacy |
| `0x8093` | `RECOVERY_CLAIM_SIGNATURE` | Recovery legacy |
| `0x8095` | `RECOVERY_CLAIM_COMPLETE` | Recovery legacy |
| `0x8097` | `QUORUM_ADD_MEMBER` | `QuorumAddMember` |
| `0x8099` | `QUORUM_REMOVE_MEMBER` | `QuorumRemoveMember` |
| `0x809B` | `COLLATERAL_CONSENT_REQUEST` | (peer) |
| `0x809D` | `COLLATERAL_CONSENT_RESPONSE` | (peer) |
| `0x80AB` | `QUORUM_JOIN` | `QuorumJoin` |
| `0x80B5` | `QUORUM_BEGIN` | `QuorumBegin` |
| `0x80C1` | `RESERVES_ADD_OUTPUT` | (peer message) |
| `0x80C3` | `RESERVES_REMOVE_OUTPUT` | (peer message) |
| `0x80C9` | `RESERVES_UPDATE_OUTPUT` | (peer message) |
| `0x80CB` | `COLLATERAL_INCREASE` | (peer message) |
| `0x80CD` | `COLLATERAL_DECREASE` | (peer message) |
| `0x80CF` | `COLLATERAL_STATUS` | (peer message) |
| `0x80D1` | `DEPOSIT_OPEN` | `DepositOpen` |
| `0x80D3` | `DEPOSIT_CLOSE` | `DepositClose` |
| `0x80D5` | `FEE_CHANGE` | `FeeChange` |
| `0x80D7` | `DEPOSIT_KEY_ROTATE` | `DepositKeyRotate` |
| `0x80E1` | `ONCHAIN_CREDIT` / `UPDATE_RESERVES` | `OnchainCredit` (operation) — overlaps the reserves-commitment peer message; disambiguate by context |
| `0x80E3` | `ONCHAIN_LOCK` / `ACCEPT_RESERVES` | `OnchainLock` — same overlap |
| `0x80E5` | `ONCHAIN_FAIL` | `OnchainFail` |
| `0x80E7` | `ONCHAIN_FULFILL` | `OnchainFulfill` |
| `0x80F1` | `TRANSFER_LOCK` | `TransferLock` |
| `0x80F3` | `TRANSFER_COMPLETE` | `TransferComplete` |
| `0x80F5` | `TRANSFER_FAIL` | `TransferFail` |

Removed and reserved: `0x808D` was `COLLATERAL_ATTESTATION` and `0x809F` was `COLLATERAL_LOCK`; both retired during the collateral-in-UTXO migration. New implementations MUST NOT assign these values.

## 6. Request / response envelopes

Ephemeral peer interactions ride Kinds 20101/20102. The on-the-wire JSON is `LedgerRequest` / `LedgerResponse`; structured peer-protocol envelopes (HTTP-style RPCs from `wire_messages.rs`) are an inner shape carried inside the `params` blob.

### `LedgerRequest` (Kind 20101 content)

Source: `deposits-node/src/nostr.rs:333–373`.

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Discriminator: `deposit_open`, `make_invoice`, `transfer_lock`, `cosign_update`, `balance_query`, `recovery_*`, `delivery_*`, … |
| `ledger_id` | string (64-hex) | Target ledger |
| `params` | JSON value | Action-specific payload (variant of one of the structs in §6.1) |
| `event_id` | string | (skipped on serialize) Source Nostr event ID |
| `sender` | string (66-hex) | (skipped on serialize) Author pubkey |
| `gift_wrap_sender` | optional string | If gift-wrapped, the inner sender |
| `subkey_account` | optional string (xonly hex) | DEP-04 subkey delegation: account pubkey from `["v"]` tag |
| `subkey_attestation` | optional string (Schnorr hex) | DEP-04: signature from `["va"]` tag |

When `subkey_account` and `subkey_attestation` are both present, the operator validates the attestation as `BIP340-verify(subkey_account_xonly, SHA256("nostr301:" ‖ sender), subkey_attestation)` and treats the request as authorized by the account pubkey for access-control purposes.

### `LedgerResponse` (Kind 20102 content)

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | Outcome flag |
| `result` | optional JSON | Action-specific payload, present iff `success` |
| `error` | optional string | Error code or message, present iff `!success` |

The response event carries an `["e", request_event_id]` tag so the wallet can correlate replies to in-flight requests.

### Inner peer-protocol envelopes (from `wire_messages.rs`)

These are the canonical Rust struct shapes serialized into `params` (or onto a direct LDK custom-message channel for legacy paths). All public-key fields are 33-byte compressed secp256k1; signatures are 64-byte Schnorr; deposit IDs are 16 bytes.

| Struct | Action | Fields |
|--------|--------|--------|
| `DepositOpenMsg` | `deposit_open` | `reserves_id`, `pubkey`, optional `fees`, optional `payment_hash`, optional `invoice`, optional `cosigner_guarantee_signature` |
| `DepositCloseMsg` | `deposit_close` | `reserves_id`, `pubkey` |
| `FeeChangeMsg` | `fee_change` | `reserves_id`, `pubkey`, `new_fees` |
| `FeeCollectMsg` | `fee_collect` | `pubkey`, `amount`, `block_height` |
| `LedgerCloseMsg` | `ledger_close` | `reserves_id` |
| `ReceivingCreditPaymentMsg` | `credit_payment` | `payment_hash`, `deposit_pubkey`, `amount`, `invoice_id`, `reserves_id`, `sequence_number` |
| `SendingLockPaymentMsg` | `send_lock` | `pubkey`, `amount`, `payment_id`, `sequence_number`, `scriptpubkey_signature` |
| `SendingFailPaymentMsg` | `send_fail` | `pubkey`, `amount`, `payment_id`, `sequence_number` |
| `SendingFulfillPaymentMsg` | `send_fulfill` | `pubkey`, `amount`, `payment_id`, `sequence_number`, `scriptpubkey_signature`, `preimage` |
| `ReceivingCosignInvoiceMsg` | `make_invoice` | `amount`, `payment_hash`, `expires`, `assigned_deposit`, `invoice_id`, `bolt11` |
| `QuorumAddMemberMsg` | `quorum_add` | `operator_id`, `reserves_id`, `quorum_member`, `quorum_member_signature`, `member_ledger_id` |
| `QuorumRemoveMemberMsg` | `quorum_remove` | `reserves_id`, `quorum_member`, `operator_signature` |
| `CollateralConsentRequestMsg` | `consent_request` | `operator_id`, `reserves_id`, `operator_signature` |
| `CollateralConsentResponseMsg` | `consent_response` | `operator_id`, `reserves_id`, `consent_granted`, `quorum_member_signature` |
| `SyncRequestMsg` | `sync_request` | `ledger_id` (32 bytes), `last_known_sequence` |
| `QuorumJoinRequestMsgWire` | `quorum_join_request` | `requester_pubkey`, `operator_id`, `reserves_id`, `protocol_version`, `timestamp`, `signature`, optional compensation triple |
| `QuorumJoinResponseMsgWire` | `quorum_join_response` | `accepted`, `members[]`, `threshold`, `last_sequence`, `content_hash`, optional `rejection_reason` |
| `QuorumStateSyncMsg` | `quorum_state_sync` | `operator_id`, `reserves_id`, `updates[][]` (length-prefixed), `start_sequence`, `is_final` |
| `QuorumVoteRequestMsg` | `quorum_vote_request` | `operator_id`, `reserves_id`, `vote_round_id` (32 bytes), `sequence_number`, `state_hash`, `claimed_reserves`, `collateral_amounts[]`, `reserves_outpoint`, `destination_script`, `fee_rate_sat_vbyte` |
| `QuorumVoteMsgWire` | `quorum_vote` | `vote_round_id`, `voter_pubkey`, `vote`, `voter_sequence`, `voter_state_hash`, optional `evidence`, `signature`, optional `spend_signature` |
| `LedgerExportRequestMsg` | `ledger_export_request` | `operator_id`, `reserves_id`, optional `from_sequence`, `block_height` |
| `LedgerExportResponseMsg` | `ledger_export_response` | `operator_id`, `reserves_id`, `version`, `exported_at`, `block_height`, `update_count`, `updates_data` (length-prefixed run), `success`, optional `error_message` |
| `UpdateReservesMsg` | `update_reserves` | `channel_id` (32 bytes), `reserves_sats`, `script_pubkey`, `ledger_hash`, `remote_ledger_hash` |
| `AcceptReservesMsg` | `accept_reserves` | `channel_id` |

Cosign requests reuse the `LedgerUpdateMsg` struct (`messages/types.rs:106–121`): `operator_id`, `reserves_id`, `operation`, `sequence_number`, `previous_hash`, `content_hash`, `operator_signature`. The cosigner replies with `LedgerUpdateResponseMsg`: `request_hash`, `accepted`, optional `error`, optional `cosign_signature`, `confirmed_sequence`, `confirmed_hash`.

## 7. Fraud-proof shapes

Fraud broadcasts are JSON inside Kind 9101 events. The `proof_hash` of a `FraudProof` is the 32-byte value embedded into a ledger chain (typically as a `TransferLock.nonce` or a `DeliveryEmbed.request_hash`). The broadcast adds the embedding location and a causal chain proving the embedded hash propagated to the accused operator's ledger before the broadcast.

Source: `deposits-protocol/src/fraud.rs:32–820`. See [Chapter 11](11-fraud-proofs.md) for the verification walk.

### `FraudBroadcast`

| Field | Type | Description |
|-------|------|-------------|
| `proof` | `FraudProof` | The hashable evidence (see below) |
| `embedding` | `ProofEmbedding` | Where `proof.proof_hash()` was first anchored |
| `causal_chain` | `[CausalLink]` | Path from `embedding` to the accused operator's ledger; empty if directly embedded |

### `FraudProof`

| Field | Type | Description |
|-------|------|-------------|
| `proof_type` | enum (see below) | Discriminator |
| `accused` | string (66-hex) | Pubkey of the accused operator or member |
| `ledger_id` | string (64-hex) | Ledger where the fraud occurred |
| `evidence` | `FraudEvidence` | Per-type evidence payload |

`proof_hash()` is BIP-340-tagged: `SHA256(SHA256("deposits/fraud_proof") ‖ SHA256("deposits/fraud_proof") ‖ proof_type_disc ‖ accused_bytes ‖ ledger_id_bytes ‖ evidence.canonical_bytes())`.

### `FraudProofType` discriminants

| Disc | Variant | Plain meaning |
|------|---------|---------------|
| 0 | `UncreditedOnchainPayment` | Operator saw enough confirmations via a signed update but never credited the deposit |
| 1 | `UncreditedLightningPayment` | Operator cosigned an invoice and the preimage is observable, but no `InvoiceCredit` followed |
| 2 | `StaleCosignature` | A cosignature declares a `member_ledger_hash` that the member's chain had already advanced past |
| 3 | `DisputeDereliction` | A member was active (extended their own ledger) within the response window but didn't dispute observed fraud |
| 4 | `NonConformingUpdate` | Operator signed a ledger update that violates protocol rules (placeholder verifier as of writing) |

### `FraudEvidence` per-type fields

Verifier semantics: each variant produces canonical bytes via a stable serialization that pins down the specific transaction, sequence, hash, or other anchor. Verifiers MUST hash the same canonical bytes.

| Variant | Required fields |
|---------|----------------|
| `UncreditedOnchain` | `offer_id`, `funding_address`, `accused_operator_pubkey`, `deadline_block`, `cosigner_pubkey`, `cosigner_ledger_hash`, `cosign_signature`, `txid`, `vout`, `amount_sats`, `confirmed_at_block_hash` (32 bytes), `required_confirmations`, `proof_sequence` |
| `UncreditedLightning` | `invoice` (BOLT11), `payment_hash`, `deposit_id`, `amount_msat`, `cosigner_pubkey`, `cosigner_ledger_hash`, `cosign_signature`, `preimage`, `proof_sequence` |
| `StaleCosign` | `stale_update_sequence`, `stale_update_hash`, `declared_member_hash`, `member_later_sequence`, `member_later_hash`, `member_ledger_id` |
| `DisputeDereliction` | `original_fraud_hash`, `original_fraud_block_hash` (32 bytes), `required_response_blocks`, `member_ledger_id`, `member_active_sequence`, `member_pubkey` |
| `NonConforming` | `sequence`, `update_b64` (base64 TLV of the offending `SignedLedgerUpdate`), `violation` (free-form description) |

Hex string lengths in evidence: pubkeys are 66 chars (compressed, 33 bytes), x-only and Nostr-style pubkeys are 64 chars (32 bytes), txids and ledger hashes are 64 chars, ledger IDs are 64 chars. Block hashes embedded in evidence are 32-byte raw arrays serialized via the `serde_32` helper as a hex string.

### `ProofEmbedding`

| Field | Type | Description |
|-------|------|-------------|
| `ledger_id` | string (64-hex) | Ledger that holds the embedding |
| `sequence` | u64 | Sequence of the embedding update |
| `update_hash` | string (64-hex) | `content_hash` of that update |
| `field` | string | Which field carries the hash (`"transfer_nonce"`, `"delivery_request_hash"`) |

`verify_in_history` returns true iff the named ledger has an update at `sequence` whose `LedgerOperation.embedded_hash()` equals `proof.proof_hash()`.

### `CausalLink`

| Field | Type | Description |
|-------|------|-------------|
| `ledger_id` | string (64-hex) | The ledger this link's update lives on |
| `sequence` | u64 | Sequence of the link update |
| `update_hash` | string (64-hex) | `content_hash` of that update |
| `member_ledger_hash` | string (64-hex) | The hash carried in this update's cosignature |
| `source_ledger_id` | string (64-hex) | The ledger `member_ledger_hash` came from (the previous link's, or the embedding's) |

Verifiers walk the chain back-to-front: the *last* link must live on the accused operator's ledger, each prior link's `source_ledger_id` must equal the next link's `ledger_id`, and `member_ledger_hash` at each step must match a hash actually on the source ledger at the named sequence. The first link's `source_ledger_id` must equal `embedding.ledger_id`.

## 8. Notable constants

These are the policy and protocol numbers that wire-format implementers need to mirror. See `deposits-protocol/src/constants.rs` and `deposits-node/src/nostr.rs:184` for the source.

| Constant | Value | Meaning |
|----------|-------|---------|
| `DEPOSITS_PROTOCOL_VERSION` | `1` | Wire-format version field. Bump on incompatible TLV layout changes |
| `PROTOCOL_VERSION` (messages) | `2` | Peer-message envelope version. Currently `v2` (consolidated messages) |
| `MIN_PROTOCOL_VERSION` | `1` | Lowest version a v2 peer will speak to |
| `MAX_QUORUM_SIZE_POLICY` | `7` | Pre-release operational cap on `Q`, the cosigner count (operator not counted). Combined with `VALID_QUORUM_SIZES = {3, 5, 7}` (odd-only, ≥3). Disputants in any one lottery: `Q` exactly (operator is barred from disputing own ledger and was never in `Q`) |
| `MAX_DISPUTANTS` | `15` | Hard protocol cap on lottery participants. Builders and `recovery_confiscate` refuse larger sets |
| `TIMEOUT_RECOVERY_CSV_BLOCKS` | `8064` | CSV delay (~8 weeks) on the lottery script's last-resort timeout-recovery leaf |
| `MIN_RESERVES_OUTPUT_SATS` | `660` | Floor on a reserves output (above P2WSH dust) |
| `MAX_RESERVES_OUTPUT_SATS` | `1_000_000_000` | 10 BTC ceiling on a single reserves output |
| `DEFAULT_EMERGENCY_TIMEOUT_BLOCKS` | `144` | One-day default for the operator-solo spending leaf |
| `MIN_EMERGENCY_TIMEOUT_BLOCKS` | `144` | One day; cosigners refuse anything tighter |
| `MAX_EMERGENCY_TIMEOUT_BLOCKS` | `4320` | ~30 days; cosigners refuse anything looser |
| `MIN_RESERVES_RATIO_PERCENT` | `100` | Reserves must cover 100% of obligations |
| `P2WSH_DUST_LIMIT_SATS` | `330` | Bitcoin standardness floor for P2WSH outputs |
| `P2WPKH_DUST_LIMIT_SATS` | `294` | Bitcoin standardness floor for P2WPKH outputs |
| `FEE_RATE_FLOOR_SAT_PER_VBYTE` | `3` | Floor for reserves-spending fee estimates |
| `RESERVES_OUTPUT_SPENDING_WEIGHT_VBYTES` | `163` | Estimated vbytes to spend a reserves output |
| `COLLATERAL_REPORTING_PERIOD_BLOCKS` | `144` | One-day cadence for collateral declarations |
| `LEDGER_TAG_LEN` (Nostr) | `16` | Truncation length for ledger IDs in `d`/`l` tags (chars) |
| `MAX_TLV_VALUE_LENGTH` (codec) | `16 * 1024 * 1024` | Per-field hard cap to defeat decoder-OOM attacks |
| `MAX_VEC_COUNT` (codec) | `1_000_000` | Hard cap on TLV vector lengths |
| `MAX_STACK_SIZE` (witness) | `1000` | Max witness stack elements |
| `MAX_ELEMENT_SIZE` (witness) | `520` | Bitcoin script element limit (consensus) |

The `DEFAULT_COMPENSATION_BPS = 300` (3%) and `DEFAULT_COMPENSATION_FREQUENCY_BLOCKS` defaults are referenced by `QuorumAddMember` and `QuorumJoinRequestMsgWire`; a member that omits the optional compensation fields is signalling acceptance of these defaults (or, for `compensation_bps = None`, explicit waiver).

## Implementer's checklist

A from-scratch implementation should pass these conformance points before going on the wire:

1. **Varint roundtrip.** 1/3/5/9-byte big-endian encoding per the test in `tlv.rs:test_varint_roundtrip`. Reject the non-canonical short-form encodings (e.g. a 3-byte form for a value that fits in 1 byte) — `TlvError::InvalidVarint`.
2. **Canonical TLV ordering.** Decode MUST reject out-of-order tags (`TlvError::NonCanonicalOrder`). The reference encoder uses `BTreeMap`-backed ordering; a Vec-backed implementation MUST sort before emitting.
3. **`SignedLedgerUpdate.content_hash` recomputation.** TLV omits the field; the receiver computes it from the wire bytes via `compute_hash()`. Manual update construction in tests/CLIs must call `compute_hash()` after mutating any input — never hand-roll the SHA256.
4. **Cosignature canonicalization.** Always sort the `cosignatures` array by `cosigner_pubkey.serialize()` before hashing or signing. A buggy peer that sends them out of order: re-sort on receive.
5. **Discriminant exhaustiveness.** Reject unknown discriminant bytes with `CodecError::InvalidDiscriminant`. Forward-compatible behavior for unknown TLV *fields* is required (preserve and ignore); unknown *discriminants* are rejected so an attacker can't smuggle a no-op operation past validators.
6. **Schnorr signing message.** Cosign uses BIP-340 tagged hashing (`"deposits/cosign"`); operator signs an untagged SHA256 of `operator_signing_data()`. Don't conflate.
7. **Tag truncation.** Ledger IDs in `d`/`l` Nostr tags are 16 hex chars. Ledger IDs inside event content (`SignedLedgerUpdate.ledger_id`, fraud-proof JSON) are full 64 hex chars (32 bytes raw).

## Where this leads

For the *meaning* of these fields and the rules that govern them, see the protocol chapters: [Chapter 4](04-ledger-state.md) for the state-machine semantics, [Chapter 6](06-peer-messaging.md) for the Nostr layer, [Chapter 11](11-fraud-proofs.md) for fraud-proof construction, and [Chapter 13](13-custody-lottery.md) for the dispute-state operations. For canonical ground truth, the DEPs (DEP-02, DEP-04, DEP-06, etc.) and the Rust source files cited at the head of this appendix are authoritative.
