# DEP-04: Peer Messaging

## Abstract

This document specifies the Nostr-based peer messaging protocol. All communication between wallets and operators, and between operators, uses Nostr events with specific Kind numbers, tags, and content formats.

## Relay Architecture

The protocol uses two types of relays:

- **Operator relays**: handle ephemeral request/response traffic. Each operator monitors one or more relays for incoming requests.
- **Ledger relay**: stores durable events (ledger updates, disputes, fraud proofs). Any relay that retains Kind 9100 events can serve as a ledger relay.

Wallets connect to both: operator relays for requests, ledger relays for reading history and advertisements.

## Event Kinds

### Ledger Protocol (operator ↔ wallet, operator ↔ operator)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 9100 | Ledger Update | Durable | deposits-node | Signed ledger update (base64 TLV, see DEP-02) |
| 9101 | Fraud Proof | Durable | deposits-node | Fraud proof broadcast (JSON, see DEP-06) |
| 9103 | Dispute | Durable | deposits-node | Custody dispute notification (JSON) |
| 9104 | Recovery Agreement | Durable | deposits-node | Quorum member recovery agreement (JSON) |
| 9106 | Custody Lottery Reveal | Durable | deposits-node | Disputant's preimage reveal during the on-chain lottery (JSON, see DEP-06 §Phase 3) |
| 20101 | Request | Ephemeral | deposits-node, wallet | Wallet-to-operator request (JSON) |
| 20102 | Response | Ephemeral | deposits-node | Operator-to-wallet response (JSON) |

### Discovery and Pricing (operator → relay → wallet)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 39100 | Advertisement | Replaceable | deposits-node | Operator terms, fees, reserves (JSON, NIP-33, `d`=ledger ID) |
| 39101 | Price Oracle | Replaceable | deposits-node | BTC/USD price (JSON, NIP-33, `d`=`btcusd`) |
| 39102 | Courier Advertisement | Replaceable | deposits-node | Cross-ledger routing capacity and fees (JSON, NIP-33, see DEP-13) |

### Identity Verification (wallet ↔ lightning-verifier ↔ operator)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 25500 | Verify Request | Ephemeral | wallet | Wallet-to-verifier verification request (JSON) |
| 25501 | Verify Response | Ephemeral | lightning-verifier | Verifier-to-wallet response: invoice, challenge, or result (JSON) |
| 55502 | Domain Attestation | Durable | lightning-verifier | Published attestation linking npub to lightning address (JSON) |

### Wallet Infrastructure (wallet → relay → wallet)

| Kind | Name | Persistence | Service | Description |
|---|---|---|---|---|
| 10301 | Subkey Management | Replaceable | *reserved* | Subkey attestation/revocation list (JSON) |
| 30078 | Wallet State | Replaceable | wallet | NIP-04 encrypted state backup to self (NIP-78, `d`=`deposits-wallet/state`) |

## Event Tags

| Tag | Usage | Description |
|---|---|---|
| `d` | Kind 9100 | Ledger ID prefix (16 hex chars, truncated for relay filtering). |
| `d` | Kind 39100 | Ledger ID (64 hex chars). Enables NIP-33 replacement. |
| `seq` | Kind 9100 | Sequence number (for relay-side ordering) |
| `prev` | Kind 9100 | Previous chain hash (hex) |
| `hash` | Kind 9100 | Current hash (hex) |
| `t` | Kind 9100 | Operation discriminant number (for relay-side filtering) |
| `i` | Kind 9100 | Affected deposit IDs (for per-deposit filtering) |
| `l` | Kind 20101, 20102 | Ledger ID (for relay-side request routing) |
| `action` | Kind 20101 | Request action name |
| `d` | Kind 39102 | Courier pubkey (hex). Enables NIP-33 replacement per courier. |
| `service` | Kind 39102 | Service type (e.g., `htlc_routing`) |
| `n` | Kind 39102 | Network name |
| `p` | Kind 20101 | Courier pubkey (for courier-addressed requests, see DEP-13) |
| `p` | Kind 9101 | Accused operator pubkey |
| `l` | Kind 9106 | Ledger ID (hex) — disputed ledger this reveal applies to |
| `member` | Kind 9106 | Revealing disputant's pubkey (hex) |
| `d` | Kind 30078 | App namespace (`deposits-wallet/state`). Enables NIP-78 replacement. |
| `p` | Kind 25500 | Verifier pubkey (hex) |
| `e` | Kind 25501 | Request event ID (for response matching) |
| `p` | Kind 55502 | Verified user pubkey (hex) |

## Request/Response Protocol

Wallets send ephemeral Kind 20101 events to operator relays. The content is JSON with an `action` field and operation-specific parameters. The operator processes the request and responds with a Kind 20102 event tagged with the request's event ID.

### Request Actions

| Action | Description | See |
|---|---|---|
| deposit_open | Open a new deposit | DEP-08 |
| make_offer | Create on-chain funding offer | DEP-10 |
| make_invoice | Create lightning invoice | DEP-10 |
| pay_invoice | Pay lightning invoice from deposit | DEP-10 |
| withdraw | On-chain withdrawal | DEP-10 |
| transfer_lock | Lock funds for transfer | DEP-09 |
| transfer_complete | Complete a transfer | DEP-09 |
| balance_query | Query deposit balance | DEP-08 |
| cosign_update | Request co-signature on update | DEP-02 |
| cosign_offer | Request co-signature on offer | DEP-10 |
| cosign_invoice | Request co-signature on invoice | DEP-10 |
| partner_add | Add quorum member | DEP-05 |
| partner_join | Record quorum join | DEP-05 |
| request_route | Request cross-ledger route from courier | DEP-13 |

### Response Format

```json
{
  "success": true,
  "result": { ... },
  "error": null
}
```

## Advertisements (Kind 39100)

Operators publish NIP-33 replaceable events advertising their terms. The `d` tag is the ledger_id, ensuring only the latest advertisement per ledger is retained. Content includes:

- `operator_pubkey` — the operator's protocol-level secp256k1 pubkey (33-byte compressed hex). This is the trust anchor: slashing, ledger updates' `operator_signature`, and on-chain custody all flow from this identity. Wallets MUST verify the advertisement's outer Nostr event signature against this key.
- `delegate_pubkey` — *(optional, since 2026-05)* the daemon's per-host **delegate Nostr key** (33-byte compressed hex). When non-empty, this is the pubkey wallets address Nostr-layer messaging to (NIP-04 DM recipient, Kind 9100 event author). The operator's protocol-level key never leaves the signer; the delegate handles everything else. Empty (`""`) on advertisements published by daemons that haven't been moved off the "operator key for everything" model — wallets MUST then fall back to `operator_pubkey` for messaging. See §Operator → Delegate Delegation below.
- Reserves amount (the deposit-capacity portion of the on-chain UTXO)
- Collateral amount (the security-bond portion; mirrors `collateral_amount_msats` from the ledger's most recent `LedgerOpen` / `QuorumBegin`)
- Fee schedules (periodic and transfer)
- Deposit limits (min/max)
- Access-control flags (whether `deposit_open` requires an attestation; allowed lightning-address domains)
- Relay URL
- Operator's observed Bitcoin chain tip at publish time

Earlier drafts also carried `total_obligations` and `available_headroom`. Both were dropped — the operator can trivially inflate them with self-paid Lightning invoices, so they're not reliable trust signals. Wallets that need capacity information should either discover a courier already holding funds on this ledger, or trust the protocol invariant `reserves ≥ obligations` enforced by the quorum's co-signers.

Wallets discover operators by fetching Kind 39100 events from ledger relays.

## Operator → Delegate Delegation

A two-key model separates the operator's *protocol-level identity* from the daemon's *Nostr-layer identity*.

**The operator key** (`operator_pubkey`) is the trust anchor. It signs:
- The advertisement's outer Nostr event signature (Kind 39100)
- The `operator_signature` inside every `SignedLedgerUpdate` (Kind 9100 content)
- Cosignatures on other operators' ledgers (when this operator is a quorum member)
- Invoice cosignatures (the operator's half of a co-signed BOLT11 attestation)
- DEP-04 subkey attestations

In a deployment running `deposits-signer` (out-of-process signer holding the operator seed), this key never leaves the signer. The daemon talks to the signer over a local Unix socket and receives BIP-340 signatures back over the wire.

**The delegate key** (`delegate_pubkey`) is the daemon's per-host Nostr identity. It signs:
- Kind 9100 ledger update events (outer Nostr event signature only — the inner `operator_signature` is still signed by the operator key)
- All Nostr-layer DM envelopes (NIP-04 / NIP-44 encrypt + decrypt; the daemon decrypts inbound DMs to its delegate npub)
- Gift-wrap envelopes (Kind 1059 outer)

The delegate key is held in process by the daemon and persisted under the daemon's data directory. Compromise of the daemon's host leaks the delegate key but **not** the operator key — slashing-equivalent fraud is structurally unavailable to an attacker who has only the delegate.

### Wallet trust path

A wallet acquires `operator_pubkey` out-of-band (e.g. configured manually, discovered via a public listing). To interact with that operator:

1. Fetch the advertisement: `kind=39100, author=operator_pubkey`. Verify outer event sig against `operator_pubkey`.
2. Read `delegate_pubkey` from advertisement content. If empty, treat `operator_pubkey` as the delegate (legacy fallback).
3. For ledger updates: subscribe to `kind=9100, #l=<ledger_id>` and verify two layers — the outer Nostr event sig against `delegate_pubkey`, and the inner `operator_signature` against `operator_pubkey` (from the ledger's `LedgerOpen`). The operator-protocol verification is what protects the deposit; the outer is just transport authenticity.
4. For NIP-04/44 DMs: encrypt to `delegate_pubkey`. Decrypt inbound DMs from the operator with `delegate_pubkey` as the sender.

### Why this isn't NIP-26 / DEP-04 subkey attestation

NIP-26 delegated event signing and the existing DEP-04 subkey-attestation pattern (Kind 10301) are *wallet-side* mechanisms — a user delegates from a long-lived account key to ephemeral subkeys. The operator → delegate split here is *operator-side* and uses the advertisement itself as the delegation document: the operator's signature on the advertisement carries the delegate pubkey in the content, so the trust path is "wallet trusts operator → operator endorses delegate." A separate Kind 10301 attestation event would be redundant.

### Backwards compatibility

Older wallets that don't read `delegate_pubkey` will treat the advertisement's event author as the operator's messaging identity. This works as long as the daemon's `self.keys` is the operator key (operator-key-for-everything mode). Once the daemon switches to delegate-key-for-Nostr (this commit's follow-up), the advertisement still authors as `operator_pubkey` (signed by signer), but Kind 9100 events author as `delegate_pubkey`. Older wallets filtering Kind 9100 by `author=operator_pubkey` will miss them and need to follow the delegation. Operators rolling forward should publish a transition advertisement with both keys' addresses available before flipping.

## Wallet Identity and NIP-07

Wallets derive a Nostr keypair from their BIP-39 seed at derivation path `m/84'/0'/0'/0/0`. This key signs requests (Kind 20101) and verification events (Kind 25500).

Alternatively, wallets MAY delegate identity to a NIP-07 browser extension (`window.nostr`). When NIP-07 mode is active:

- Verification requests (Kind 25500) are signed by the extension
- The wallet key is retained for deposit operations (Kind 20101), which require the derived key
- Subkey attestation (Kind 10301) is disabled, since the wallet does not control the signing key
- The extension's relay list (`window.nostr.getRelays()`) is used for state sync

The choice between wallet key and NIP-07 is stored in wallet state and can be toggled in settings.

## Wallet State Sync (Kind 30078)

Wallets persist operational state (deposits, relays, key index) to Nostr relays using NIP-78 application-specific data events. The `d` tag is `deposits-wallet/state`, making it a parameterized replaceable event — only the latest version is retained.

Content is NIP-04 encrypted to the wallet's own pubkey (encrypt-to-self). In NIP-07 mode, `window.nostr.nip04.encrypt` is used; otherwise, the wallet implements NIP-04 directly (ECDH shared secret + AES-256-CBC).

The encrypted payload contains:

```json
{
  "network": "bitcoin",
  "relays": ["ws://..."],
  "ledgerRelay": "wss://...",
  "deposits": [...],
  "keyIndex": 3,
  "useNip07": false
}
```

The seed and mnemonic are never included — they are the key itself.

State is synced to both operator relays and identity relays (from NIP-07) with a 5-second debounce after local saves. On wallet import, state is restored from relays automatically.

## Domain Attestation (Kind 55502)

An external verification service publishes Kind 55502 events attesting that a Nostr pubkey controls a specific lightning address. The operator queries for these events during deposit access control (see DEP-08).

```json
{
  "npub": "npub1...",
  "lightning_address": "user@domain.com",
  "verified_at": "2026-01-15T12:00:00+00:00",
  "method": "nip05"
}
```

The event is authored by the verifier and tagged `#p` with the verified pubkey. Verification methods:

- **`nip05`**: The domain's `.well-known/nostr.json` maps the user to this pubkey. Free.
- **`challenge`**: The verifier paid random amounts to the lightning address and the user reported them correctly. Requires payment.

The verifier communicates with wallets via Kind 25500 (request) and Kind 25501 (response) ephemeral events. The wallet sends a verification request; the verifier responds with an invoice, challenge, or attestation result.

## Subkey Attestation (Kind 10301)

A root keypair signs attestations authorizing independent subkeys to act on its behalf. The attestation message is `SHA256("nostr301:<hex-subkey-pubkey>")`, signed with BIP-340 Schnorr.

Events signed by a subkey include:
- `["v", "<hex-account-pubkey>"]` — the account this subkey acts for
- `["va", "<hex-attestation-signature>"]` — proof of authorization

Kind 10301 (replaceable) manages the subkey set:

```json
{
  "inbox_keys": ["<hex-subkey1>", "<hex-subkey2>"],
  "revoked_subkeys": ["<hex-subkey3>"]
}
```

Revocation is a policy check — the attestation signature remains cryptographically valid, but verifiers MUST check the Kind 10301 event for revocations before trusting a subkey.

## Relay Tag Truncation

Kind 9100 events use a truncated 16-character prefix of the ledger ID in the `d` tag for relay-side filtering efficiency. The full 64-character ledger ID is encoded in the TLV content (tag 2, LEDGER_ID). Wallets and operators MUST use the full ledger ID from TLV when constructing requests — not the truncated tag value.

Kind 20101 request events carry the full ledger ID in the `l` tag.

## Offline Operation

Wallets need no persistent connections. They can go offline indefinitely and catch up by fetching Kind 9100 events from any relay that has them. The hash chain provides integrity verification — a wallet replays events and validates the chain regardless of when they were fetched.

## Related DEPs

- [DEP-02](DEP-02.md): Ledger update wire format (Kind 9100 content)
- [DEP-06](DEP-06.md): Fraud proof broadcast format (Kind 9101 content)
- [DEP-12](DEP-12.md): Certified delivery (Kind 20101 wallet → member request, durable record via DeliveryEmbed on Kind 9100)

## References

- [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) -- Nostr event structure
- [NIP-04](https://github.com/nostr-protocol/nips/blob/master/04.md) -- Encrypted direct messages
- [NIP-07](https://github.com/nostr-protocol/nips/blob/master/07.md) -- Browser extension signing (`window.nostr`)
- [NIP-33](https://github.com/nostr-protocol/nips/blob/master/33.md) -- Parameterized replaceable events
- [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) -- Application-specific data
