# Chapter 6: Peer Messaging

> **Audience**: developers, integrators, operators
> **Prereqs**: chapters 2, 3 (Nostr section)
> **DEPs**: DEP-04

A protocol that scales custody across many independent operators needs a messaging layer that doesn't reintroduce the centralization it's trying to escape. Wallets must be able to come online after weeks offline and replay the events they missed. Operators must be reachable by wallets they have never seen before. Members must be able to listen for fraud broadcasts on ledgers they didn't even know existed last week. And no party — not the operator, not the wallet, not some "deposits foundation" running a directory — gets to be the bottleneck through which the rest must talk.

This chapter is about how the protocol gets that property out of [Nostr](03-background.md#nostr-as-transport) — a content-addressable broadcast layer with multi-publisher retention, where the relay's only job is to keep events around for everybody to read. It walks through the kinds the protocol uses, what each one carries, how durability/ephemerality maps to message intent, the tags that let relays do server-side filtering, and the request/response patterns built on top.

## Why Nostr

The protocol's transport requirements are unusual:

1. **Content-addressable, not endpoint-addressable.** A wallet looks up "the latest update on ledger `a3f5...`" not "ask `node-7.example.com:9101`." A wallet that just imported a ledger from a friend has the ledger ID; it has no idea where the operator hosts.

2. **Multi-publisher retention.** A ledger update broadcast by an operator must be readable indefinitely, by anybody, regardless of whether the operator stays online. If an operator vanishes a year after publishing an update, that update is still load-bearing — part of the chain a fraud-proof verifier replays.

3. **Asymmetric availability.** Operators are mostly online; wallets are mostly offline. The transport must let an offline wallet reconstruct ledger state from any third party that has the events, without coordination with the operator.

4. **No global directory.** Operators advertise on relays they choose; wallets find operators by querying relays they trust.

Nostr fits all four. Events are signed at the publisher, retained at the relay, and delivered to subscribers via filter-based subscriptions. Relays are a library — anybody can run one — and the wallet's connection set is a deployment choice, not a protocol constraint.

The flip side: Nostr is *only* a transport. It has no notion of state, no schema, no consensus. The protocol layers all of that on top using kind numbers, tags, and TLV-encoded content. NIP-01 gives us the event shape; everything else is convention.

## The kinds catalogue

Every protocol message is a Nostr event. The `kind` field is a 16-bit integer that classifies the event; the protocol uses about a dozen kinds, grouped by purpose. Two properties of each kind matter:

- **Persistence.** Nostr's kind-number ranges have implicit retention semantics. Kinds 1000–9999 are *regular* events that relays should retain. Kinds 20000–29999 are *ephemeral* — relays auto-delete them after a short TTL (seconds to minutes), suitable for transient peer-to-peer traffic. Kinds 30000–39999 are *parameterized replaceable* (NIP-33), where a single canonical event per `(pubkey, kind, d-tag)` triple replaces older versions.
- **Service.** Which party publishes this kind. The protocol has events published by operators (most), by wallets (requests, fraud broadcasts), by external attestation services, and by the relay's own state.

What follows is a tour of the kinds, with which DEPs they're specified by, how they're persisted, who reads them, and what they carry. The constants live in `deposits-node/src/nostr.rs` lines 79–163.

### Durable ledger events

These are the events that *must* be retained. A wallet replaying a ledger from cold reconstructs state from these alone.

**Kind 9100 — Ledger Update.** The fundamental event of the protocol. Published by the operator after every state-machine transition (deposit opens, transfer locks, invoice fulfillments, fee changes, dispute events, custody handoffs). Content is base64-encoded TLV ([DEP-02](../DEP-02.md)) carrying a `SignedLedgerUpdate`: the operation bytes, chain context (`previous_hash`, `sequence_number`, block height), the operator's signature, and the cosignatures from a majority of quorum members. Tagged with the ledger ID prefix, the sequence number, an operation-type discriminant, and zero or more deposit IDs.

This is the only event whose content is binary-and-not-JSON. The choice is deliberate: ledger updates are signed against the canonical TLV bytes, so any JSON re-encoding step would risk breaking signature verification. TLV plus base64 means the bytes the operator signed are exactly the bytes the verifier hashes.

**Kind 9101 — Fraud Proof Broadcast.** Published by anyone — wallet, member, ex-operator, third-party watcher — who has assembled cryptographic evidence that a ledger contains a non-conforming event. Content is JSON; shape is documented in [DEP-06](../DEP-06.md) and visited in detail in [Chapter 11](11-fraud-proofs.md). Tagged with the accused operator's pubkey (`p`-tag) so members watching for fraud against operators they cosign can filter efficiently. The persistence guarantee is what makes fraud proofs work — the proof must be verifiable long enough for a member to fork the ledger, race the lottery, and complete custody transfer.

**Kind 9103 — Dispute.** A quorum member's notification that they have observed a fraud-worthy condition on a ledger they cosign. JSON content — last conforming hash, sequence at which the violation was detected, reason code, the disputer's signature. The act of publishing this is what causes fork-branch construction at other members.

**Kind 9104 — Recovery Agreement.** Member-published, JSON. Each member of a disputed ledger broadcasts their agreement to participate in recovery (and which fork-branch hash they have settled on). This event is how members converge on a shared dispute state without an explicit consensus protocol — they read each other's agreements, and once a majority agree on the same fork point, recovery is armed.

**Kind 9106 — Custody Lottery Reveal.** Disputants publish their lottery preimages here during the [reveal phase](13-custody-lottery.md) of the on-chain custody lottery. JSON content — the preimage, the dispute the reveal applies to. Tagged with the ledger ID (`l`-tag) and the revealing disputant's pubkey (`member` tag) so other disputants can fetch all reveals to compute the lottery winner.

**Kind 39100 — Ledger Advertisement.** The discovery layer. NIP-33 parameterized replaceable: `d`-tag is the full 64-char ledger ID, so a relay only retains the latest ad per ledger. Content is JSON: operator name and pubkey, reserves and collateral amounts, fee schedules, deposit limits, access-control flags, the operator's preferred relay URL, and the operator's observed Bitcoin chain tip at publish time. This is what a wallet fetches to find operators to deposit with. The chain tip is a small load-bearing detail — it lets the wallet detect operators who claim to be live but haven't seen a block in days.

What an ad does *not* contain: total obligations, available headroom. Earlier drafts carried both. They were dropped because the operator can trivially inflate them with self-paid Lightning invoices, so they don't carry meaningful trust signal. A wallet that needs capacity information either discovers a courier already holding funds on this ledger, or trusts the protocol invariant `reserves >= obligations` enforced by the cosigners.

### Discovery and pricing

**Kind 39101 — Price Oracle.** NIP-33 replaceable, `d`-tag = `"btcusd"`. Operators publish a BTC/USD rate wallets consult when displaying balances in fiat. There is no protocol consensus on price — each operator's oracle is just a publication, and wallets weight whichever operators they trust.

**Kind 39102 — Courier Advertisement.** NIP-33 replaceable, `d`-tag = courier pubkey. Couriers ([Chapter 16](16-couriers.md)) advertise the cross-ledger routes they support and their directional fees. Tagged with `service` (e.g. `htlc_routing`) and `n` (network).

**Kind 39103 — Swap Advertisement.** NIP-33 replaceable. A peer-to-peer extension of the courier model: a wallet holding a deposit on ledger A advertises willingness to swap to ledger B at a stated fee, without a courier middleman.

### Ephemeral request/response

These events are *not* retained. A relay drops them after seconds. They carry the synchronous interactions wallets and operators have with each other.

**Kind 20101 — Ledger Request.** Wallet → operator (or wallet → courier). Content is JSON with an `action` field (`deposit_open`, `make_invoice`, `transfer_lock`, etc.) and operation-specific parameters. Tagged with the ledger ID (`l`-tag) and the action name. The full enumeration of actions is in [DEP-04](../DEP-04.md) and Appendix B; the request DEP for each action lives in the operation's own DEP (transfers in DEP-09, payment channels in DEP-10, and so on).

The same kind also serves a second purpose: members send `cosign_update` requests to each other on this kind. The action discriminant tells the operator's daemon whether to dispatch to the wallet-facing path or the cosign path. (Operators dispatch on action; relays don't care.)

**Kind 20102 — Ledger Response.** Operator → wallet. Reply to a Kind 20101 request, tagged with the request's event ID via `e`-tag. Content is JSON `{ success, result, error }`. The success/error split is uniform across all actions; the shape of `result` depends on the action.

**Kind 20103 / 20104 — Swap Request / Swap Response.** Ephemeral peer-swap negotiation events between a swap-ad publisher and a taker. Same shape as the ledger request/response pair but addressed via `p`-tag to the swap ad's author rather than via `l`-tag to a ledger.

### Identity and infrastructure

**Kind 25500 / 25501 — Lightning Verify Request / Response.** Wallet ↔ Lightning verifier. Used by the attestation service to verify a wallet controls a Lightning address (LUD-06/16). Gift-wrapped (see below) so the verifier doesn't leak verification requests to relay clients.

**Kind 55502 — Domain Attestation.** Verifier-published, durable. Content is JSON: the verified pubkey, the lightning address, when it was verified, by what method (`nip05` or `challenge`). Tagged with the verified user's pubkey (`p`-tag). Operators query for this kind during deposit access control. [Chapter 17](17-attestation-service.md) covers attestations end to end.

**Kind 10301 — Subkey List.** NIP-33 replaceable, one per pubkey. JSON content lists currently-authorized subkeys (`inbox_keys`) and revoked ones (`revoked_subkeys`). The DEP-04 subkey delegation scheme consults this event before trusting an attestation signature carried in a request's `va` tag.

**Kind 30078 — Wallet State.** NIP-78 application-specific data. Each wallet encrypt-to-self stores its operational state (deposits, relays, key index). The seed and mnemonic are never included — they *are* the key. Not a protocol-level facility; a wallet-side convenience for restore-from-relay.

## Tags

Nostr lets events carry tag arrays. Single-letter tags are indexed by relays for filter-side queries; multi-letter tags are visible to clients but not server-filterable. The protocol's tag conventions are:

| Tag | Meaning | Used on |
|---|---|---|
| `d` | Ledger ID prefix (16 hex chars) | Kind 9100 |
| `d` | Ledger ID (64 hex chars), full | Kind 39100 (NIP-33 replacement key) |
| `d` | Courier pubkey | Kind 39102 (NIP-33 replacement key) |
| `d` | App namespace `deposits-wallet/state` | Kind 30078 (NIP-33 replacement key) |
| `n` | Sequence number, decimal | Kind 9100 |
| `t` | Operation discriminant, decimal | Kind 9100 |
| `i` | Affected deposit ID, hex | Kind 9100, repeated per deposit |
| `l` | Ledger ID, full | Kind 20101, 20102, 9106 |
| `p` | Target/accused pubkey | Kind 9101 (accused), 20101 (courier-addressed), 25500 (verifier), 55502 (verified) |
| `e` | Referenced event ID | Kind 20102 (request being replied to) |
| `action` | Request action name | Kind 20101 |
| `member` | Revealing disputant | Kind 9106 |

The `d`-tag on Kind 9100 is the most important from a relay-load perspective. Ledger IDs are 64-char hex hashes; truncating to a 16-char prefix (the first 8 bytes) lets relays index efficiently while preserving 2^64 collision resistance — comfortably enough that no two distinct ledgers will ever share a prefix. Wallets and operators MUST read the full ledger ID from the TLV content (tag 2, `LEDGER_ID`), not the truncated tag — the tag is for filtering, not authoritative.

The `n`, `t`, and `i` tags exist for the same reason: relay-side filtering. A member who only cares about TransferLock operations on their cosigned ledgers subscribes with `#t = TransferLock_discriminant` and gets a 50× reduction in inbound traffic. A wallet that cares only about its own deposit `D7` subscribes with `#i = D7`. None of these are correctness-critical — they're throughput optimizations.

The `l`-tag on Kind 20101/20102 is the request-routing tag. An operator subscribing to `#l = its_ledger_id` receives every wallet's request for that ledger and nothing else.

## Wire shape of a Kind 9100 event

To make this concrete, here is what an actual ledger-update event looks like on the wire (formatted; the actual event is one line of JSON):

```json
{
  "id": "fb9e4c81d2...",
  "pubkey": "8a2c61b047...",
  "kind": 9100,
  "created_at": 1735603200,
  "tags": [
    ["d", "a3f5c81d4e9b7c20"],
    ["n", "47"],
    ["t", "12"],
    ["i", "9b1e2f7c..."]
  ],
  "content": "AQAEYXJyaW...AwQGBQ==",
  "sig": "f83e2a7b9c..."
}
```

What the receiver does with this:

1. Decode `content` from base64 to TLV bytes.
2. TLV-decode to a `SignedLedgerUpdate` (operation message + chain context + signatures).
3. Recompute `content_hash` via `update.compute_hash()`. The TLV format omits the hash — receivers always recompute, never trust a transmitted hash.
4. Look up the previous update by `previous_hash`. If absent, fetch from a relay (gap-fill).
5. Apply the operation against the current `LedgerState` via `LedgerState::apply`. Errors here mean the update is non-conforming and should trigger a fraud proof, not a reject-and-forget.
6. Verify the operator's signature and cosigner signatures against the cosign data. ⌊Q/2⌋+1 valid cosignatures from the ledger's active quorum are required.
7. If everything checks, persist to the local `<ledger_id>.jsonl` file and advance the in-memory `Ledger`'s state.

The Nostr `pubkey` and `sig` on the outer envelope are *not* the operator's signature on the ledger update. They're the publishing key's signature on the Nostr event itself — useful for anti-spam at the relay layer, irrelevant to ledger validity. The protocol-level signatures are inside the TLV content. (In practice the publishing key is the operator's nostr-derived key, which is itself derived from the operator's secp256k1 key, but that's a key-derivation convention, not a layered cryptographic guarantee. The ledger's authority is the inner signatures.)

## Request/response pattern

A wallet wanting to perform any operation against a ledger sends a Kind 20101 request and waits for a Kind 20102 response. The pattern is:

1. **Wallet** builds a `LedgerRequest` with `action`, `ledger_id`, `params` (action-specific JSON). Optionally signs the request body (some actions require it — transfers, withdrawals — others don't).
2. **Wallet** subscribes to Kind 20102 events filtered by `#l = ledger_id` *before* publishing. This is critical: operators can respond in milliseconds, and a post-publish subscribe race can lose the response.
3. **Wallet** publishes Kind 20101 with `#l = ledger_id`, `#action = action_name`, signed by the wallet's nostr key.
4. **Relay** broadcasts to subscribers; the operator's daemon picks it up because it subscribes to `#l = its_ledger_id`.
5. **Operator** dispatches by action to the appropriate handler in `request_handlers/`. The handler validates, possibly stages a ledger operation, possibly requests cosignatures, possibly broadcasts a Kind 9100 update, and assembles a response.
6. **Operator** publishes Kind 20102 with `#e = request_event_id` and `#l = ledger_id`. Content is `{ success, result, error }` JSON.
7. **Wallet** receives via the subscription set up in step 2, matches by `request_id` (the `e`-tag value), and processes.

The operator's response window is 30–60 seconds in the reference deployment. If the operator doesn't respond in that window — process down, host network-partitioned, deliberately ignoring — the wallet has two escalation paths: switch operators if the deposit is on a redundant ledger, or invoke the [delivery-escalation flow](15-delivery-escalation.md) (Kind 20101 to a quorum member, who notarizes the operator's silence into a `DeliveryEmbed` on Kind 9100, which becomes the basis of a fraud proof if the operator stays silent).

The `request_id` correlation is the `e`-tag on the response, not a UUID in the JSON body. This is a NIP-01 convention — every Nostr event has an event ID, and replies reference it via `e`. The wallet's match is "this Kind 20102 has an `e`-tag equal to my Kind 20101's event ID."

A worked example: a wallet locking a transfer.

```
Wallet sends Kind 20101:
  tags = [["l", "a3f5...full64"], ["action", "transfer_lock"]]
  content = {
    "nonce": "...",
    "source_deposit_id": "...",
    "destination_deposit_id": "...",
    "amount": 1000000,
    "fee": 220,
    "completion_script": "...",
    "timeout_height": 850000,
    "transfer_id": "...",
    "signature": "...wallet_sig_over_hash..."
  }

Operator receives, validates wallet signature, checks balance,
constructs LedgerOperation::TransferLock, runs cosign round,
publishes Kind 9100 with the new SignedLedgerUpdate, then sends:

Kind 20102:
  tags = [["l", "a3f5...full64"], ["e", "<request_event_id>"]]
  content = {
    "success": true,
    "result": { "transfer_id": "...", "sequence_number": 48 },
    "error": null
  }
```

The wallet matches the response by event ID, marks the lock as confirmed locally, and is done. The new state is in the Kind 9100 the operator just published, which the wallet will also see on its Kind 9100 subscription — the response is for low-latency confirmation, but the *authoritative* record is the durable ledger update.

## Cosign request/response

Operators talking to their quorum members use the same request/response infrastructure but with a multicast twist. When the operator wants to commit an update, it needs ⌊Q/2⌋+1 cosignatures.

The operator sends a single Kind 20101 with `action = "cosign_update"`, `#l = ledger_id`, and content carrying the cosign data and content hash. Every quorum member who has subscribed to requests on this ledger receives it. Each member runs the `Ledger::checked_apply` pipeline against the proposed update, signs, and sends back a Kind 20102. The first ⌊Q/2⌋+1 valid responses are aggregated into the cosignatures array on the resulting `SignedLedgerUpdate`.

The protocol does not do a full round-trip with every member; it's a fan-out to all members and a first-N-responding race. Members who are slow simply don't make it onto this update — their cosignatures aren't required, only a majority is. This keeps update latency at roughly one round-trip even when one or two members are sluggish or temporarily offline. ([Chapter 7](07-quorum-and-collateral.md) covers what happens when a member is *persistently* unreachable — eventually the operator removes them from the quorum via `QuorumRemoveMember` and replaces them with a new member via `QuorumAddMember`.)

The semaphore in `coordination.rs::request_cosign` (line 288) serializes cosign requests within the operator: only one cosign round runs at a time. Without this serialization, multiple concurrent commits would compete for the same cosigning channel and produce distributed deadlocks under load. Updates are still high-throughput; the bottleneck per ledger is one round at a time, and one operator's ledgers are independent.

## Gift-wrapping for privacy

Some requests reveal sensitive context: an admin command an operator runs against another operator, or a Lightning verification request that would otherwise leak a Lightning address to anyone watching the relay. For these the protocol uses a gift-wrap envelope inspired by NIP-59 (rumor → seal → outer wrap), with deliberate divergences from NIP-17.

The shape is:

1. **Rumor.** A normal Nostr event JSON (kind, content, tags, pubkey, created_at) that is *not* signed. This is the message the recipient should ultimately see.
2. **Seal.** A Kind 13 event whose content is the rumor JSON encrypted (NIP-04 / ECDH + AES-256-CBC) from the real sender's key to the recipient's key. The seal *is* signed by the real sender, so the recipient can authenticate.
3. **Outer wrap.** A Kind 20101 (or whatever request kind is being wrapped) whose content is the seal JSON encrypted from a *throwaway* key to the recipient's key. The outer wrap is signed by the throwaway key.

The recipient unwraps in reverse. The throwaway key on the outer wrap means relay-watchers can't link the wrap to the real sender — they see only an event from a one-time pubkey to the recipient. The seal's signature inside lets the recipient verify the real sender once decrypted.

Why not NIP-17? NIP-17 is for direct messaging; the protocol's gift-wrap rides the existing Kind 20101/20102 request pipeline (subscription filter, request unwrap, action dispatch, response routing). The divergences are intentional. The outer envelope's kind is 20101 (not NIP-17's 1059) so requests-handlers see it natively; the inner seal's kind is 13 so the seal step is recognizable; tagging is `e` on the outer for response routing. A standard NIP-17 client wouldn't make sense of these envelopes — and that's fine, the protocol is communicating with peers that speak its dialect, not with random Nostr DM apps.

The detail to keep in mind: gift-wrapped requests carry the real sender's pubkey in the `gift_wrap_sender` field after unwrapping. Operator-side handlers that care about *who* sent the request use this, not the outer wrap's pubkey. See `LedgerRequest::gift_wrap_sender` in `deposits-node/src/nostr.rs:359`.

## Subscription strategy

Putting it together, here's what each party subscribes to on the relay:

**Operator** subscribes to:
- Kind 9100 with `#d = ledger_prefix` for every ledger they cosign as a member (so they see updates they're a member of).
- Kind 20101 with `#l = ledger_id` for every ledger they operate (incoming wallet requests + cosign requests from members of *other* operators they cosign for).
- Kind 9101 with `#p = own_pubkey` (fraud broadcasts naming this operator).
- Kind 9103 with `#l = ledger_id` for every ledger they cosign (member dispute notifications).
- Kind 9106 with `#l = ledger_id` for ledgers they're disputing (custody-lottery preimage reveals).

**Wallet** subscribes to:
- Kind 9100 with `#d = ledger_prefix` for each ledger it has deposits on (to track operator activity).
- Kind 20102 with `#l = ledger_id` for ledgers it has open requests against (to receive responses).
- Kind 39100 broadly when discovering operators (one-shot fetches, not long-lived subscriptions).
- Kind 9101 with `#p = own_operator_pubkey` if it wants to be alerted about its operator being accused of fraud.

**Member** subscribes to a superset of operator: their own ledgers' inbound traffic, plus every cosigned ledger's request traffic so they receive cosign requests, plus fraud broadcasts.

The general rule is that subscriptions are scoped as tightly as possible by `#l` or `#d` or `#p` to keep relay-side fan-out manageable. Open subscriptions on an ungated kind (e.g. Kind 20101 with no filter) would deliver every request on every ledger to every subscriber, which is expensive and unnecessary.

## Offline operation

Wallets need no persistent connection. The protocol's design makes this work:

- Every state-transitioning event is a durable Kind 9100. A wallet that has been offline for a month catches up by fetching all Kind 9100 events for its ledgers since `last_seen_sequence`, validating the chain, and applying state transitions.
- The hash chain provides integrity. The wallet doesn't need to trust the relay it fetches from; it validates `previous_hash` linkage and operator+cosigner signatures locally.
- Events on different relays converge. If the wallet's preferred relay is down, any other relay that retains the events will do. The wallet's relay set is multi-rooted, not single-rooted.

This is the property that makes the protocol's promised UX — "deposit money, go live your life, come back when you need it" — realizable. The wallet doesn't need to maintain a session, doesn't need to keep a websocket open, doesn't need to be reachable. It has the keys; it can rebuild state from any retention-respecting relay.

## What stays in your head

- Every protocol message is a Nostr event. Kind ranges encode persistence: 9000s = durable, 20000s = ephemeral, 39000s = NIP-33 replaceable.
- Kind 9100 is the ledger update — base64 TLV in `content`, signature inside, NOT in the Nostr envelope.
- Tags exist for relay-side filtering: `d` for ledger ID prefix, `n`/`t`/`i` for sequence/op-type/deposit, `l` for full ledger ID on requests/responses, `p` for target pubkey.
- Wallets ↔ operators talk over the Kind 20101/20102 request/response pair. Match responses by `e`-tag, not by anything in the content body.
- Operators ↔ members talk over the same kinds with `cosign_update` action. Multicast; first-N-respond wins; operator commits on ⌊Q/2⌋+1 valid cosignatures.
- Gift-wrap (NIP-59-shaped, not NIP-17 interoperable) hides admin and verification traffic from relay-watchers while routing through the same request pipeline.
- Wallets are offline-tolerant by design. The hash chain plus durable Kind 9100 retention means any retention-respecting relay can serve as a catch-up source.

## Where this leads

[Chapter 7](07-quorum-and-collateral.md) opens up the structure that the cosign-request pattern implicitly assumed: how a quorum is formed in the first place, how members are added and removed, what the reserves/collateral split means on the on-chain UTXO, and what the cosigners are actually checking before they sign. After that, [Chapter 8](08-deposits-and-transfers.md) walks through the wallet-facing operations — deposits and transfers — that ride this messaging layer end to end.
