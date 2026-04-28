# Chapter 21: The Wallet

> **Audience**: developers, integrators (especially), wallet users (for deep dive)
> **Prereqs**: chapters 4, 8, 9, 19
> **DEPs**: none directly (implements wallet-side of all of them)

This chapter walks through `deposits-wallet` — the depositor's CLI client. It is the smallest of the three top-level binaries (the other two being `deposits-node` and `deposits-attest`), about 7,000 lines of Rust spread across eleven files in `deposits-wallet/src/wallet_cli/`. It ships no daemon, owns no on-chain wallet, and has no long-running connection to anything. Every CLI invocation is a one-shot: open a Nostr connection, sign a request, wait for the response, persist any new local state, exit.

The wallet is what someone running deposits sees. The protocol's elegance lives in the daemon and the wire spec; the *experience* of holding a deposits-protocol balance lives here. So this chapter spends time on the local-state model, key derivation, and evidence retention — the parts the protocol chapters in Part II don't cover because they're not protocol concerns, but which determine whether a wallet implementation is actually usable.

## What the wallet does

The depositor's client. It holds the keys for deposits the user controls, talks Nostr to operator relays, and drives every wallet-initiated operation in the protocol:

- Discovery: enumerating advertised operators and routing agents.
- Account management: opening deposits, querying balance, syncing local records against the operator.
- Spending: locking and completing transfers, paying Lightning invoices, requesting on-chain withdrawals.
- Receiving: requesting BOLT-11 invoices to receive Lightning, requesting on-chain funding addresses.
- Cross-ledger routing: paying a deposit on a different ledger via a courier.
- Escalation: invoking [DEP-12 delivery embedding](15-delivery-escalation.md) when an operator stops responding.
- Inspection and recovery: replaying a ledger from the relay, tracing custody changes.

The wallet does *not* hold an on-chain Bitcoin wallet of its own. To fund a deposit on-chain the user asks the operator for an address (`deposits-wallet offer`), gets back an address co-signed by quorum members, and sends to it from any external wallet — Bitcoin Core, Sparrow, hardware. To withdraw on-chain they ask the operator to spend the reserves UTXO to a destination. There is no UTXO management on the wallet side; that is the operator's job.

This is one of the protocol's defining UX differences from Lightning. A Lightning wallet manages channel state, fee bumps, watchtowers. A deposits-protocol wallet manages keys, signs requests, listens. The on-chain footprint, the BDK wallet, and the Bitcoin RPC connection live in `deposits-node` — see [Chapter 20](20-the-daemon.md).

## No daemon

A common question the first time someone reads the wallet code: where is the long-running process? There isn't one. Every subcommand is a self-contained `async fn` invoked from `main.rs:36-67`, each one of these:

```rust
async fn open_new_deposit(args: &[String]) -> Result<(), Box<dyn Error>> {
    let config = parse_config(args)?;
    let transport = NostrTransportBuilder::new(secret_key)
        .relay(&config.relays[0])
        .build()
        .await?;
    let req_id = transport.send_ledger_request(...).await?;
    let response = transport.wait_for_response(&req_id, 30000).await?;
    persist_locally(...);
    Ok(())
}
```

Open Nostr connection, send request, wait for response, write to disk, exit. If the operator doesn't respond within the per-command timeout (typically 30s for control-plane operations, 120s for Lightning payments — `deposits-wallet/src/wallet_cli/payments.rs:1294`), the command fails. There is no retry loop, no background sync, no watchdog.

The implications are deliberate. A wallet can sit dormant for months — when it next runs, `deposits-wallet sync` queries the relay for the current state of every deposit and exits. No "forgot to plug in your watchtower" failure mode. A hostile process inspecting an idle wallet finds a seed file (chmod 0600, `mod.rs:282`) and a JSON manifest, where a Lightning wallet would be holding revocation secrets in memory. And each subcommand is a process, so shell loops and CI scripts drive the wallet without library bindings — the `deposits-test` integration suite drives `deposits-wallet` via `Command::new("deposits-wallet")` for exactly this reason.

The cost: the wallet cannot detect "operator stopped responding to me" except when the user runs a command. If you care about that, you run a [delivery embed](15-delivery-escalation.md) explicitly. The protocol's escalation primitive is a wallet *action*, not a daemon background task.

## Subcommand structure

The CLI dispatches in `deposits-wallet/src/main.rs:35-72` against a flat top-level command list. There's no `clap` subcommand tree; just a `match` on `args[1]`. Grouped by purpose:

**Discovery** (`wallet_cli/discover.rs`)

| Command | What it does |
|---|---|
| `discover` | Fetch all `Kind:39101` (ledger advertisement) and `Kind:39102` (agent advertisement) events from the relay, decode, print sorted by operator |
| `info <ledger_id>` | Resolve a ledger-id prefix (16 hex chars is enough) and print its full advertisement: reserves, collateral, fees, quorum, current block |

**Account** (`wallet_cli/deposit.rs`)

| Command | What it does |
|---|---|
| `open <ledger_id>` | Send `deposit_open` to the operator. Creates the deposit account but does not fund it |
| `offer <alias> <sats>` | Ask the operator for an on-chain funding address; persist the returned address and quorum cosignatures |
| `list` | Read `deposits.json` and print each deposit's alias, ledger ID prefix, status |
| `balance` | Run `sync` first, then print balances. The sync step is what makes balance more than a stale cache |
| `sync` | Send `balance_query` to each deposit's operator, update local state |

**Spending** (`wallet_cli/payments.rs`)

| Command | What it does |
|---|---|
| `transfer <alias> <amt>` | Construct a hash-locked `TransferLock` request, sign with deposit key, send to operator |
| `transfer_complete <id>` | Reveal the preimage to settle a previously-locked transfer |
| `send <alias> <amt> --to <dst>` | Happy-path intra-ledger transfer (lock + immediate complete) |
| `pay_invoice <alias> <bolt11>` | Sign an `InvoiceLock` request authorizing the operator to pay this BOLT-11 from the deposit |
| `make_invoice <alias> <sats>` | Ask the operator to issue a BOLT-11 invoice payable into the deposit |
| `withdraw <alias> <amt> --to <addr>` | Sign a withdrawal request — the operator will spend reserves to the address, members co-sign |
| `route <from> <to> <amt>` | Cross-ledger transfer via a courier (DEP-13) |
| `spread <total>` | Open + offer across N discovered operators in one shot |
| `history <alias>` | Replay the deposit's relevant ledger updates and print a transaction log |

**Escalation** (`wallet_cli/escalate.rs`)

| Command | What it does |
|---|---|
| `escalate` | Pay a quorum member to embed a request hash on their ledger when the operator ignores you |

**Identity** (`wallet_cli/attest.rs`, `wallet_cli/ringsig.rs`)

| Command | What it does |
|---|---|
| `attest`, `revoke`, `subkeys` | DEP-04 subkey delegation: sign a sub-key with the master nsec, publish/revoke |
| `ringsig-link` | bLSAG ring-signature over the wallet's set of trusted operators (Chapter 18) |

**Swaps** (`wallet_cli/swap.rs`)

| Command | What it does |
|---|---|
| `swap-advertise`, `swap-list`, `swap-request`, `swap-listen` | Peer-to-peer swap matching across ledgers |

**Inspection** (`wallet_cli/ledger.rs`)

| Command | What it does |
|---|---|
| `ledger list` | Enumerate every advertised ledger across the relay |
| `ledger show <id>` | Print every signed update on a ledger, decoded |
| `ledger validate <id>` | Replay the entire chain locally and check hash-chain integrity, sequence ordering, signatures |
| `ledger custody <id>` | Trace `LedgerOpen` → `QuorumAddMember` → `QuorumBegin` → `DisputeEnter` → `DisputeAcquire` events; print the custody history |

**Regtest helpers** (`wallet_cli/regtest.rs`)

| Command | What it does |
|---|---|
| `regtest-faucet <alias>` | On regtest only: send sats from a Bitcoin Core node to the deposit's funding address and mine a block |

The full list, run `deposits-wallet help` (`wallet_cli/mod.rs:85`).

## Local state

The wallet's persistence is intentionally trivial. Three files in `~/.deposits-wallet/` (override with `--data-dir` or `WALLET_DATA_DIR`):

```
~/.deposits-wallet/
├── seed.hex                    # 32-byte hex master seed (chmod 0600)
├── deposit_key_index.txt       # last-used BIP32 index for deposit keys
└── deposits.json               # array of per-deposit records
```

`deposits.json` is plain serde JSON. One record per deposit account, with the shape (`deposit.rs:303-310`):

```json
{
  "alias": "savings",
  "ledger_id": "f4...",
  "deposit_pubkey": "02ab...",
  "key_index": 3,
  "status": "open",
  "created_at": "2026-04-27T19:45:00Z"
}
```

After an `offer` command lands, the record gets enriched with the operator's response: `funding_address`, `min_deposit`, `max_deposit`, `offer_id`, `cosignatures` (an array of `(member_pubkey, signature)` pairs that the wallet retains as a fraud-proof fixture; see *Evidence retention* below). After a `make_invoice` lands the wallet stores the cosigned BOLT-11 against the same record. The file is read-modify-write under no explicit locking — the assumption is one wallet process at a time per data-dir. If you run two `pay_invoice` commands in parallel the JSON write race can clobber state, which is a known limitation marked for fixing in [the batch-mode subcommand](#concurrency-and-batch-mode) below.

There is no SQLite, no LMDB, no encrypted blob. The seed is the only secret; everything else is reconstructible from the seed plus what's on the relay.

## Key management

A single 32-byte master seed (`seed.hex`) is generated on first run with `OsRng::fill_bytes` (`mod.rs:280`) if no `--seed` flag is passed. From this seed, BIP-32 derives every key the wallet uses:

```rust
// mod.rs:367-384
pub fn derive_secret_key_at_index(
    seed: &[u8; 32],
    network: bitcoin::Network,
    index: u32,
) -> Result<SecretKey, ...> {
    let xpriv = Xpriv::new_master(network, seed)?;
    let path = DerivationPath::from_str(&format!("m/84'/0'/0'/0/{}", index))?;
    let derived = xpriv.derive_priv(&secp, &path)?;
    Ok(derived.private_key)
}
```

Path `m/84'/0'/0'/0/0` is the wallet's Nostr identity key — the npub that signs requests to operators. Path `m/84'/0'/0'/0/1`, `/2`, `/3`, ... are deposit keys — one per opened deposit, allocated incrementally and tracked in `deposit_key_index.txt` (`mod.rs:387-405`).

A few consequences of this scheme:

**Recoverability.** From the seed alone, the wallet can re-derive every deposit pubkey it would have created. Combined with the relay (which retains every ledger's history), the wallet can rediscover what deposits the user opened: for each candidate deposit-pubkey (indices 1, 2, 3, ...), query the relay for `DepositOpen` events naming that pubkey, and rebuild `deposits.json` from scratch. The `replay-ledger` utility in `deposits-tools` is the inspection-side primitive for this; the wallet does not yet ship a `recover-from-seed` subcommand, but the data model supports it.

**Per-deposit isolation.** Each deposit has its own pubkey, so cross-deposit linkage requires the operator (who sees all the requests on their ledger) — not the relay (which sees per-deposit traffic but no shared identifier). This is part of the wallet-side privacy story; the protocol surface is public, but the wallet's *use* of it can be unlinked across deposits if the user is careful about timing and amounts.

**Nostr identity override.** A wallet can be given an explicit Nostr identity with `--nsec-file <path>` (`mod.rs:332-357`). When that's set, the override key is used for every wallet-side Nostr signature — instead of the seed-derived index 0. This matters when the operator gates `deposit_open` behind a [lightning-verify attestation](17-attestation-service.md) tied to a specific npub: the wallet must sign as the same npub the verifier attested to, otherwise the attestation doesn't match the sender the operator sees.

The wallet does *not* support hardware-key signing today. Every signature is produced in-process with `secp.sign_schnorr`. This is a known gap; the protocol does not require a software-only wallet, the reference implementation just hasn't built the integration.

## Authentication

Every spending request is signed by the deposit's wallet key. The signature is a Schnorr signature over a canonical signing message constructed in `deposits-core/src/signature_utils.rs`. Different request types have different signing messages — `withdrawal_signing_message`, `transfer_lock_signing_message`, `invoice_lock_signing_message` — but the shape is the same: a SHA-256 of a fixed-format byte sequence over the request's load-bearing fields.

For example, the transfer-lock signing message includes: nonce, source deposit-id, destination deposit-id, amount, fee, completion script, timeout block-height (`payments.rs:320-329`). The wallet computes the message hash, signs with the deposit keypair, and sends `signature: hex::encode(signature.serialize())` as part of the JSON request body.

The operator validates by:

1. Looking up the source `Deposit` on its ledger and finding its `descriptor` (e.g., `pk(02ab...)`) — this gives the expected pubkey.
2. Recomputing the same signing message from the request's fields.
3. Calling `secp.verify_schnorr(sig, msg, expected_pubkey)`.

If the signature doesn't verify against the deposit's stored pubkey, the request is rejected. The wallet's deposit-pubkey is bound to the deposit at `DepositOpen` time and cannot be rotated without closing and reopening the deposit; this is the wallet's commitment to a specific key for as long as the deposit exists.

The Nostr transport layer adds a second signature on top — every Nostr event is signed with the wallet's identity key (BIP-32 index 0). The two signatures serve different purposes: the Nostr signature authenticates "this event came from this npub"; the embedded deposit signature authorizes "this deposit's keyholder signed this exact spend." The operator checks both.

## Evidence retention

The protocol's fraud-proof story (Chapter 11) relies on the wallet being able to produce evidence on demand. Three classes of evidence the wallet must keep:

**Cosigned BOLT-11 invoices.** When the wallet calls `make_invoice`, the operator returns a BOLT-11 invoice plus a quorum cosignature attesting that the operator promised to credit the deposit on payment. The wallet persists this in `deposits.json`. If the wallet pays the invoice off-network (someone else routes Lightning to the operator's node) and the operator fails to credit the deposit, the wallet has the cosigned invoice plus the preimage from the payment receipt; that combination is an `UncreditedLightning` fraud proof per [DEP-08](../DEP-08.md).

**Cosigned on-chain offers.** When the wallet calls `offer`, the operator returns a Bitcoin address plus quorum cosignatures attesting that funds sent to this address before the deadline must be credited as a deposit. The wallet retains the cosignatures alongside the address. If the wallet sends to that address, the transaction confirms, and the operator fails to credit, the wallet has an `UncreditedOnchain` fraud proof. The verification helper `verify_offer_cosignature` (`mod.rs:409-438`) is what the wallet uses at receive-time to make sure the cosigs are well-formed before relying on them.

**Transfer-lock cosignatures.** Less load-bearing than the previous two, since transfers are intra-ledger and the operator's record is already public on the relay. But the wallet keeps its own copy of the signed `TransferLock` request and the operator's response so that if the operator's published ledger update later disagrees with what the wallet received in-band, the wallet has the disagreement on hand as evidence of operator equivocation.

In all cases the wallet's responsibility is to keep the evidence durably. There is no protocol-level acknowledgement that the wallet has retained anything; the wallet implementation just persists everything before declaring an operation successful. If the user loses `~/.deposits-wallet/deposits.json` they lose the offer/invoice cosignatures stored there — and with them, the ability to file fraud proofs that depend on those cosignatures. The `seed.hex` plus the relay can recover *which deposits exist*, but cannot recover *which offers were issued and accepted*; that's wallet-local state.

This argues for a backup story stronger than what the reference implementation ships. A real-world wallet would replicate `deposits.json` to a second host or write the offer cosigs into a more durable side-channel; the reference implementation does the simple thing on disk.

## The escalation flow

`wallet_cli/escalate.rs` is the wallet's primitive for putting a request hash into a member's ledger when the operator stops responding. The mechanics are covered in [Chapter 15](15-delivery-escalation.md); here we document the CLI surface.

The wallet calls:

```
deposits-wallet escalate \
    --member-ledger <member_ledger_id_hex> \
    --request-hash <32-byte hex> \
    --target-ledger <operator_ledger_id_hex> \
    --target-operator <33-byte pubkey hex> \
    --relay <ws://...>
```

The implementation (`escalate.rs:30-148`) is straightforward: validate the four hex inputs, build a Nostr request, send a `delivery_embed` action to the chosen quorum member's daemon, await the response. The member's daemon, on receipt, creates a `DeliveryEmbed` operation on its own ledger; once the operator co-signs that ledger's next update, the operator's `member_ledger_hash` causally references the embed, proving the operator has seen the request hash.

From the wallet's perspective the command is a one-shot — the `service_response_blocks` clock runs in the daemon code and is observed by the same wallet on its next `sync`. The escalate command is the *trigger*; the *outcome* is observed by reading the relay later. Today the wallet must pass `--member-ledger` explicitly to pick the member; the design also anticipates a future `payment_commitment` parameter (a `TransferLock` from the wallet's deposit on the member's ledger to pay the member for the embed), so the narrow single-member surface is deliberate.

## Discovery and trust

Operator discovery in `deposits-wallet discover` is a single Nostr query: fetch every `Kind:39101` event matching the configured network (`regtest`/`testnet`/`bitcoin`), decode, print. The advertisement includes everything needed to evaluate an operator: their name (if pseudonymous), their reserves and collateral amounts, fees, deposit min/max, current block, the relay they listen on for requests.

What the discover command does *not* do: build trust. Every operator on the network can advertise. Newcomers, operators with thin collateral, and operators with quorums that share heavy overlap all show up indistinguishably. Building a trust ranking is the wallet's job, and the inputs are:

1. **The advertisement itself.** Larger collateral, longer time-since-genesis, lower fee variance — all visible on `Kind:39101`.
2. **Attestations.** [Chapter 17](17-attestation-service.md). Operators with NIP-05 / Lightning-address / domain attestations from a verifier the wallet knows have a verified real-world identity. The wallet can configure a list of trusted verifier pubkeys and reject operators that don't have an attestation from any of them.
3. **Quorum graph.** Each ledger advertisement includes its quorum members' pubkeys. A wallet that's been around for a while has its own ledger's quorum, plus the quorums of operators it trusts; computing graph metrics (vertex-connectivity from "wallet's known operators" to a candidate ledger's quorum) gives the wallet an objective measure of independence.
4. **Ring-signature WoT.** [Chapter 18](18-ring-signatures.md). The `ringsig-link` subcommand publishes a wallet-side claim that "I am an operator from the set {A, B, C}" without revealing which one. Wallets can use these to learn about operator clusters without doxxing the publishers.

The reference implementation collects (1) and (2) automatically — when an operator gates `deposit_open` behind an attestation, the wallet runs `run_verification_flow` (`deposit.rs:337-501`) to obtain the attestation through a Lightning-verify round-trip. The graph-distance scoring of (3) is not yet wired into the wallet UI; that's a known follow-up. The `ringsig-link` infrastructure of (4) is operational but exposed as a CLI primitive rather than baked into discover.

A wallet on multiple relays sees more operators. `--relay` can be passed multiple times; `parse_config` accumulates them (`mod.rs:242`); transport builds with `relays(...)` to subscribe to all of them (`deposit.rs:923`). Multi-relay subscription is what makes the protocol routable across operator-controlled relays and shared community relays simultaneously.

## Offline and catchup

A wallet that's been offline for a week reconnects, runs `deposits-wallet sync` (or any spending command, which forces a sync), and:

1. For each deposit in `deposits.json`, sends a `balance_query` request to the operator.
2. The operator responds with the deposit's current balance, locked balance, and the latest block height the operator has applied to the ledger.
3. The wallet updates `deposits.json` with the new balance and any state transitions (a pending offer that's now confirmed and credited, a pending transfer that completed while offline, etc.).

There is no per-deposit "ledger replay" the wallet has to run. The operator is the source of truth for the deposit's current balance, and the wallet trusts it — modulo the fraud-proof guarantee that any lie the operator tells about the balance is detectable and slashable later. The trust assumption inside `sync` is the same trust assumption the protocol makes everywhere: operator-claims-balance is fine to display because if the operator lied, fraud-proof recovery will eventually correct it.

For deeper inspection — when the wallet wants to be sure, not just trust — the `ledger validate` and `ledger custody` subcommands replay the entire ledger from the relay. `ledger custody` (`wallet_cli/ledger.rs:552-895`) walks every signed update, tracks `LedgerOpen` → `QuorumAddMember` → `QuorumBegin` → `DisputeEnter` → `DisputeAcquire` events, and prints the custody history. This is what a wallet would run before a large deposit, and what a wallet would run if it suspects something is wrong.

## Custody changes

When a fraud proof fires against an operator, the recovery pipeline (Chapter 12) eventually produces a `DisputeAcquire` operation on the disputed ledger that names the new operator. The wallet observes this event next time it queries the ledger.

The current implementation handles this by re-fetching the ledger advertisement, which the new operator publishes after acquiring custody. The wallet's `sync` and `balance_query` paths therefore find the updated `parent_pubkey` automatically — subsequent requests are sent to the new operator's npub, the new operator's daemon is the one that responds, and the wallet's local `deposits.json` is updated to record the operator change.

Two things to flag for wallet authors:

- The `deposits.json` schema doesn't currently track the operator pubkey separately from the ledger ID, which means a custody change is invisible to the wallet user from `list` output. A polished implementation would render the custody chain in `list`, so the user can see "this deposit's custodian changed three days ago." The plumbing is there (`ledger custody`); UI integration is a follow-up.
- A wallet that hasn't run in months may have missed multiple custody changes and several advertised-relay rotations. The catchup story works because each custody change emits a fresh advertisement on the relay, and advertisements are addressable by ledger-id (not by operator-pubkey). As long as *some* relay retains the advertisement chain, the wallet finds the current custodian on its next reconnect.

## Concurrency and batch mode

The default wallet is single-process. `deposits.json` is read-modify-write with no locking; running two commands concurrently against the same data-dir is not supported. For users who genuinely want batch operations there is a `batch` subcommand (`wallet_cli/batch.rs:62-384`) that loads all deposits into memory once, opens a single Nostr connection, and dispatches a series of commands (one per stdin line) over that connection. The state is held in memory and serialized to `deposits.json` once at the end. Batch mode is what the integration test harness uses (`deposits-test/src/regtest.rs`) when it needs to drive dozens of operations against a single wallet quickly.

Multiple *wallets* against multiple *data-dirs* against the same relay is fine and expected — that's the operator-side load case. The constraint is per-data-dir, and the workaround is batch mode if you need more than one operation in flight per wallet.

## A user's day

To make the surface concrete:

```bash
# Discover operators on the regtest cluster.
deposits-wallet discover --relay ws://localhost:17779

# Open a deposit with operator alice (selected by ledger-id prefix).
deposits-wallet open f4a2b1c3 --alias savings --relay ws://localhost:17779

# Request an on-chain funding address for 50_000 sats.
deposits-wallet offer savings 50000 --relay ws://localhost:17779
# Prints:
#   Funding address: bcrt1q...
#   Deadline: block 280
#   Cosigs from quorum: 3 valid signatures retained

# Fund it from any wallet.
bitcoin-cli sendtoaddress bcrt1q... 0.0005
bitcoin-cli generatetoaddress 6 $(bitcoin-cli getnewaddress)

# Sync to pick up the operator's deposit_credit.
deposits-wallet sync --relay ws://localhost:17779
deposits-wallet balance --relay ws://localhost:17779
# savings: 50000 sats (0 locked)

# Send 10_000 sats to a peer's deposit-id.
deposits-wallet send savings 10000 \
    --to 7d4e5f6a... \
    --relay ws://localhost:17779

# Days later: pay a Lightning invoice.
deposits-wallet pay_invoice savings lnbcrt1m1p... \
    --relay ws://localhost:17779

# Check what's happened on the operator's chain.
deposits-wallet ledger custody f4a2b1c3 --relay ws://localhost:17779
# Prints the LedgerOpen, QuorumBegin, all our DepositOpen, InvoiceLock,
# and TransferLock entries, plus any DisputeEnter/DisputeAcquire if the
# operator misbehaved while we were away.
```

That sequence touches discovery, account, funding, intra-ledger transfer, Lightning, and audit. About six commands, each one a one-shot, each one self-contained.

## What stays in your head

- The wallet is a one-shot CLI: each command opens a Nostr connection, signs a request, waits, persists, exits. No daemon, no background sync.
- Local state is `seed.hex` + `deposits.json` + a key-index counter. Everything else is recoverable from the seed plus the relay.
- Keys derive from a single seed by BIP-32: index 0 is the Nostr identity, index N is the Nth deposit's spending key.
- Authentication is two-layered: a Nostr signature on the event envelope, and a Schnorr signature on the deposit-specific signing message inside the request body. The operator validates both.
- The wallet retains cosigned offers and cosigned BOLT-11s as fraud-proof evidence. Losing those is losing the ability to escalate certain failure modes; the seed alone is not enough.
- Escalation (`deposits-wallet escalate`) is a wallet *action*, not a daemon background task. The wallet picks a quorum member to record the request hash on; the protocol's clock starts running once the operator co-signs the next update on that member's ledger.
- Discovery is read-the-relay; trust is the wallet's job — built from advertisements, attestations, quorum graph, and ring-signature WoT.

## Where this leads

[Chapter 22](22-testing-and-fuzzing.md) covers how the protocol is tested: in-process simulations at the `core` level, Tier-3 cluster tests that drive `deposits-node` and `deposits-wallet` against a live regtest cluster, and the adversarial fuzzer that stress-tests the state machine. Many of the wallet's CLI surfaces shown in this chapter are exercised end-to-end by those tests; reading the test code is one of the better ways to see the wallet in action.
