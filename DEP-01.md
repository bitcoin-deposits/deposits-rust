# DEP-01: Ledger Update Protocol

## Abstract

This document specifies the wire format, hash chain structure, and signing protocol for Bitcoin Deposits ledger updates. A ledger is an append-only chain of signed updates published as Nostr events, cooperatively maintained by an operator and a quorum of co-signers.

## Notation

- All multi-byte integers are big-endian unless stated otherwise
- `||` denotes concatenation
- `SHA256()` is the SHA-256 hash function
- `[N]` denotes a fixed-length byte array of N bytes
- Amounts are in millisatoshis unless stated otherwise

## TLV Encoding

All structures use Type-Length-Value encoding with BigSize varints, compatible with the Lightning Network TLV format (BOLT #1).

### BigSize

A BigSize integer is encoded as:

| Value Range | Encoding |
|---|---|
| 0x00..0xfc | 1 byte |
| 0xfd..0xffff | 0xfd followed by 2 bytes |
| 0x10000..0xffffffff | 0xfe followed by 4 bytes |
| 0x100000000..0xffffffffffffffff | 0xff followed by 8 bytes |

### TLV Record

    [BigSize: type] [BigSize: length] [length bytes: value]

Records are ordered by type number. Even types are required; odd types are optional and may be ignored by parsers that don't understand them.

### TLV Stream

A sequence of TLV records, ordered by ascending type number, concatenated until end of input.

## Signed Ledger Update

A signed ledger update is broadcast as a Nostr Kind 9100 event. The event content is a base64-encoded TLV stream with the following fields:

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | message | variable | Inner operation (TLV-encoded LedgerOperation) |
| 2 | message_type | 2 | Protocol message type constant |
| 4 | operator_id | 33 | Operator's compressed secp256k1 pubkey |
| 6 | ledger_id | 32 | Ledger identifier hash |
| 8 | sequence_number | 8 | Monotonically increasing sequence (u64 LE) |
| 10 | previous_hash | 32 | Chain hash of the previous update |
| 12 | current_hash | 32 | Hash of this update (see Hash Chain) |
| 16 | partner_signature | 64 | ECDSA co-signature from quorum member |
| 18 | operator_signature | 64 | Schnorr signature from operator |
| 20 | block_height | 4 | Block height at creation (u32, optional) |
| 22 | block_hash | 32 | Block hash at creation (optional) |
| 24 | cosigner_pubkey | 33 | Co-signing quorum member's pubkey (optional) |
| 26 | member_ledger_hash | 32 | Co-signer's ledger tip hash (optional) |

## Hash Chain

The hash chain has two levels: `current_hash` commits to the update content and co-signature; `chain_hash` folds in the operator's signature and becomes the next update's `previous_hash`.

### current_hash

    current_hash = SHA256(
        sequence_number (8 bytes LE)
        || previous_hash (32 bytes)
        || message (variable)
        [|| member_ledger_hash (32 bytes)]
        [|| partner_signature (64 bytes)]
    )

`member_ledger_hash` is included when present (co-signed update). `partner_signature` is included when non-zero. This creates causal ordering: the co-signer's ledger state and their attestation are baked into the hash.

### chain_hash

    chain_hash = SHA256(
        current_hash (32 bytes)
        || operator_signature (64 bytes)
    )

The operator signs `current_hash`. Their signature is then folded into `chain_hash`, which becomes the next update's `previous_hash`. This commits the chain to both signatures without circularity.

### Genesis

The first update (sequence 0) has `previous_hash` = `[0; 32]`.

## Signing

### Partner (Co-signer)

The co-signer signs a BIP-340 tagged hash:

    tag = SHA256("deposits/cosign")
    message = partner_signing_data || member_ledger_hash

    partner_signing_data =
        message (operation TLV bytes)
        || message_type (2 bytes LE)
        || sequence_number (8 bytes LE)
        || previous_hash (32 bytes)

    digest = SHA256(tag || tag || message)

The co-signer signs `digest` with ECDSA using their operator key, producing a 64-byte compact signature.

Note: `current_hash` is NOT in `partner_signing_data` because it is not finalized until after co-signing (it incorporates the partner signature itself).

### Operator

The operator signs `current_hash` with Schnorr (BIP-340):

    sig_input = SHA256(
        sequence_number (8 bytes LE)
        || previous_hash (32 bytes)
        || current_hash (32 bytes)
        || message (variable)
    )

The operator signs `sig_input` with their keypair, producing a 64-byte Schnorr signature stored in `operator_signature`.

## Ledger Operations

The `message` field contains a TLV-encoded operation. The first record (type 0) is always a 1-byte discriminant identifying the operation type.

### Discriminants

| Disc | Operation | Description |
|---|---|---|
| 1 | LedgerOpen | Initialize a new ledger |
| 10 | ReservesIncrease | Increase reserves amount |
| 11 | ReservesDecrease | Decrease reserves amount |
| 12 | ReservesRotate | Rotate reserves to new multisig UTXO |
| 20 | DepositOpen | Open a new deposit |
| 21 | DepositClose | Close a deposit |
| 22 | DepositUpdate | Announce a fee change |
| 23 | DepositKeyRotate | Rotate deposit spending key |
| 30 | InvoiceCredit | Credit deposit from lightning payment |
| 31 | InvoiceLock | Lock deposit for lightning payment |
| 32 | InvoiceFail | Fail a locked lightning payment |
| 33 | InvoiceFulfill | Fulfill a locked lightning payment |
| 35 | OnchainCredit | Credit deposit from on-chain payment |
| 36 | OnchainLock | Lock deposit for on-chain withdrawal |
| 37 | OnchainFail | Fail a locked withdrawal |
| 38 | OnchainFulfill | Fulfill a locked withdrawal |
| 40 | CollateralIncrease | Increase collateral amount |
| 41 | CollateralDecrease | Decrease collateral amount |
| 42 | CollateralAttestation | Record collateral attestation |
| 43 | QuorumAddMember | Add a quorum member |
| 44 | QuorumRemoveMember | Remove a quorum member |
| 45 | CollateralLock | Lock deposit balance as collateral |
| 46 | QuorumJoin | Record joining another operator's quorum |
| 50 | FeeCollect | Collect periodic fees from a deposit |
| 54 | CustodyDispute | Initiate custody dispute |
| 55 | CustodyAcquire | Winner acquires custody |
| 56 | CustodyYield | Loser yields custody |
| 57 | CustodyArmed | Pre-commitment for lottery |
| 60 | LedgerClose | Close the ledger |
| 70 | TransferLock | Lock funds for conditional transfer |
| 71 | TransferComplete | Complete a transfer |
| 72 | TransferTimeout | Timeout a transfer |

### Common TLV Field Types

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | discriminant | 1 | Operation type |
| 2 | amount | 8 | Amount in millisatoshis |
| 6 | quorum_members | N*33 | Concatenated compressed pubkeys |
| 8 | new_amount | 8 | New amount (msats) |
| 10 | pubkey | 33 | Compressed secp256k1 pubkey |
| 12 | fees | variable | Nested TLV: FeeStructure |
| 14 | payment_hash | 32 | Payment hash |
| 16 | invoice | variable | BOLT11 invoice string |
| 20 | new_fees | variable | Nested TLV: FeeStructure |
| 36 | block_height | 4 | Block height (u32) |
| 38 | collateral_operator | 33 | Operator being backed |
| 44 | quorum_member | 33 | Member pubkey |
| 56 | operator_id | 33 | Operator pubkey |
| 58 | reserves_id | variable | Reserves identifier string |
| 76 | lock_until_block | 4 | Lock expiry block height |
| 114 | member_ledger_id | variable | Member's ledger ID string |
| 115 | collateral_ledger_id | variable | Collateral ledger ID string |
| 200 | deposit_id | 16 | Deposit identifier |
| 202 | descriptor | variable | Miniscript descriptor string |
| 210 | nonce | 32 | Transfer nonce |
| 212 | source_deposit_id | 16 | Source deposit ID |
| 214 | destination_deposit_id | 16 | Destination deposit ID |
| 216 | completion_script | variable | Transfer completion script |
| 218 | timeout_height | 4 | Transfer timeout block height |
| 220 | transfer_id | 32 | Transfer identifier |
| 226 | transfer_fees | variable | Nested TLV: TransferFeeSchedule |
| 229 | is_collateral | 1 | Collateral deposit flag (odd, optional) |
| 231 | receive_requires_sig | 1 | Receive requires signature (odd, optional) |
| 233 | min_fee_bps | 2 | Member's min fee rate (odd, optional) |
| 235 | min_fee_fixed | 8 | Member's min fixed fee (odd, optional) |
| 237 | max_fee_period | 4 | Member's max fee period (odd, optional) |
| 239 | collateral_lock_amount | 8 | Member's collateral commitment (odd, optional) |
| 241 | collateral_lock_until | 4 | Collateral lock expiry (odd, optional) |
| 243 | fee_change_after_blocks | 4 | Blocks before fees can change (odd, optional) |
| 245 | fee_change_notice_blocks | 4 | Fee change notice period (odd, optional) |
| 247 | fee_change_limit_bps | 2 | Max fee change per adjustment (odd, optional) |
| 249 | effective_block | 4 | Fee change effective block (odd, optional) |

### FeeStructure (Nested TLV)

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | annualized_fixed | 8 | Fixed fee per year (msats) |
| 2 | annualized_bps | 2 | Fee rate (basis points per year) |
| 4 | frequency_blocks | 4 | Collection period (blocks) |

### TransferFeeSchedule (Nested TLV)

| Type | Name | Size | Description |
|---|---|---|---|
| 0 | fixed_sats | 8 | Fixed fee per transfer (sats) |
| 2 | rate_bps | 2 | Proportional fee (basis points) |

## Nostr Event Kinds

| Kind | Name | Persistence | Description |
|---|---|---|---|
| 9100 | Ledger Update | Durable | Signed ledger update (base64 TLV) |
| 9101 | Fraud Proof | Durable | Fraud proof broadcast (JSON) |
| 9103 | Dispute | Durable | Custody dispute notification (JSON) |
| 9104 | Recovery Agreement | Durable | Quorum member recovery agreement (JSON) |
| 20101 | Request | Ephemeral | Wallet-to-operator request (JSON) |
| 20102 | Response | Ephemeral | Operator-to-wallet response (JSON) |
| 39100 | Advertisement | Replaceable | Operator advertisement (JSON, NIP-33) |
| 39101 | Price Oracle | Replaceable | BTC/USD price (JSON, NIP-33) |

### Event Tags

| Tag | Usage | Description |
|---|---|---|
| `d` | Kind 9100, 39100 | Ledger ID (64 hex chars) |
| `seq` | Kind 9100 | Sequence number |
| `prev` | Kind 9100 | Previous hash (hex) |
| `hash` | Kind 9100 | Current hash (hex) |
| `t` | Kind 9100 | Operation discriminant number |
| `i` | Kind 9100 | Affected deposit IDs |
| `l` | Kind 20101, 20102 | Ledger ID for relay-side filtering |
| `action` | Kind 20101 | Request action name |
| `p` | Kind 9101 | Accused operator pubkey |

## Obligation Limits

A ledger's total obligations (sum of all deposit balances and locked amounts) must not exceed the lesser of:

1. The reserves amount (from ReservesIncrease/Rotate)
2. Twice the smallest quorum member's `collateral_lock_amount`

This is enforced when creating new funding offers or invoices.

## Fee Changes

Fee parameters are negotiated at deposit opening:

- `fee_change_after_blocks`: blocks after opening before any change
- `fee_change_notice_blocks`: blocks of notice before change takes effect
- `fee_change_limit_bps`: maximum change per adjustment (basis points of current fee, default 1000 = 10%)

A DepositUpdate (disc 22) announces new fees with an `effective_block`. The change takes effect when FeeCollect runs at or after that block.

## Fraud Proofs

A fraud proof is a hashable evidence document. Its SHA256 hash is embedded as a transfer nonce (field 210) on the accused operator's ledger or a connected ledger. Once signed by the operator, the evidence is causally ordered.

### Proof Hash

    tag = SHA256("deposits/fraud_proof")
    proof_hash = SHA256(tag || tag || proof_type_byte || accused_pubkey_bytes || ledger_id_bytes || evidence_bytes)

### Broadcast

A fraud broadcast (Kind 9101) contains:

- `proof`: the hashable evidence
- `embedding`: which ledger/sequence/field contains the proof hash
- `causal_chain`: sequence of co-signed updates linking the embedding to the accused ledger

Each causal link is a co-signed update on ledger X whose `member_ledger_hash` comes from ledger Y, proving X happened after Y.

## References

- [BOLT #1: Base Protocol](https://github.com/lightning/bolts/blob/master/01-messaging.md) -- TLV encoding
- [BIP-340: Schnorr Signatures](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) -- Tagged hashing, Schnorr signing
- [NIP-01: Basic Protocol](https://github.com/nostr-protocol/nips/blob/master/01.md) -- Nostr event structure
- [NIP-33: Parameterized Replaceable Events](https://github.com/nostr-protocol/nips/blob/master/33.md) -- Advertisement events
