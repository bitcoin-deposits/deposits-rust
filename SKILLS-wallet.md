# SKILLS — wallet (depositor)

How to hold deposits: get a wallet, open accounts, receive and send funds, verify your balance.

For the operator side, see [SKILLS-operator.md](SKILLS-operator.md). For the *why* behind any step, see [SKILLS-protocol.md](SKILLS-protocol.md) and the [DEPs](DEP-01.md).

---

## 1. Pick a wallet

| Wallet | Best for | Where |
|---|---|---|
| `wallet-cli.sh` (bash + Docker) | Quick checks, scripting, a depositor's first run | `deposits-tools/docker/wallet-cli.sh` |
| `deposits-wallet` (Rust binary) | Power users, every command, swaps, attestations | `cargo run -p deposits-wallet --` or `deposits-tools/bin/deposits-wallet` |
| Web wallet | A real human in a browser | `https://wallet.bitcoindeposits.net/` (or `deposits-web/wallet/index.html` locally) |

The bash CLI delegates crypto to a running operator container or local Python — it's the lightest path. Use the Rust binary if you don't have a node container handy or want subcommands the bash script doesn't cover (`spread`, `route`, `swap-*`, `attest`).

---

## 2. Bootstrap a wallet

```bash
# Bash CLI (writes seed + deposits.json under --wallet)
./deposits-tools/docker/wallet-cli.sh --wallet ~/.depo init
./deposits-tools/docker/wallet-cli.sh --wallet ~/.depo pubkey

# Rust binary (uses --data-dir or WALLET_DATA_DIR)
deposits-wallet --data-dir ~/.depo --network bitcoin --seed <hex> discover
```

**Seed handling.** The seed is 32 bytes of hex in `<data-dir>/seed`. Keep it 0600 and back it up — you can rebuild every deposit record from the seed + the relay, but the seed itself is the only thing you can't reconstruct. Both wallets refuse to accept the seed inline on argv (`ps` leakage); they want a file or env var.

**Per-deposit key isolation.** The wallet derives a fresh BIP-84 child for each `open`. The `pubkey [--index N]` subcommand is for inspecting an existing slot; new opens auto-increment.

**Identity vs. deposit keys.** Your seed-derived key at index 0 is your default Nostr identity (used for `verify` attestations and DEP-04 subkey delegations). Deposit keys live at higher indexes. If an operator gates deposits behind a Lightning attestation tied to your identity, you can override with `--nsec-file <path>` to sign as your own npub.

---

## 3. Find a ledger and open a deposit

```bash
# List operators advertising on the network
wallet-cli.sh --wallet ~/.depo discover

# Inspect one (fees, capacity, balance cap, quorum)
wallet-cli.sh --wallet ~/.depo info <ledger_id>

# Open a deposit account on it (no funds yet — this just creates the record)
wallet-cli.sh --wallet ~/.depo open <ledger_id> [--alias home]
```

**`<ledger_id>` accepted forms.**
- Full 52-char bech32-data (the canonical form, what advertisements carry).
- 64-char hex.
- Any unambiguous prefix — the wallet resolves it via Kind 39100 lookup.

The lnurl gateway, by contrast, only accepts the full canonical forms. Don't try to hand it a short prefix; that's a security boundary, not a UX bug.

**Read fees correctly.** `LedgerAdvertisement::minimum_fees` returns *annualized* msats. To compare against what you'll pay per period, divide by `52560 / fee_period_blocks`. The wallet does this for you in `info`; if you're parsing advertisements yourself, don't forget the conversion.

**`maxSendable` (lnurl).** Operators advertise a per-deposit balance cap; the lnurl gateway uses it to set lnurl-pay's `maxSendable`. If your sender refuses to pay because the amount exceeds the cap, that's why.

**Pick more than one operator.** A deposit is only as available as the operator running it. `spread <total> [--count N]` opens deposits across N discovered operators in one shot — diversify if you're holding meaningful balances.

---

## 4. Receive funds

```bash
# 1. On-chain — get a one-shot funding address
wallet-cli.sh --wallet ~/.depo offer home 100000

# 2. Lightning BOLT11 — operator + cosigner co-sign the invoice
wallet-cli.sh --wallet ~/.depo make_invoice home 50000

# 3. Lightning Address (lnurl-pay) — share this with anyone
wallet-cli.sh --wallet ~/.depo lnurl
# → home@<ledger_id>.ledger.bitcoindeposits.net
```

The lnurl gateway lives at `<ledger_id>.ledger.bitcoindeposits.net`. It gift-wraps `make_invoice` requests to the operator (NIP-59-shaped, NIP-04 inner) so the relay sees only `Kind 1059` envelopes; the operator decrypts to find the request inside.

**Zaps work.** The gateway supports NIP-57: pass `nostr=<urlencoded zap request>` to `/lnurl/pay/...`, and the operator publishes a Kind 9735 receipt referencing the zap request. Receivers see the zap in their feed; the deposit shows it as an `InvoiceCredit` op.

**Verify the BOLT11 came from your quorum.** `make_invoice` responses carry operator + cosigner BIP-340 signatures over the BOLT11 (tagged hash `invoice_cosign_signing_message`). The wallet checks these on receipt; if you're scripting against the gateway directly, verify them yourself before quoting the invoice to a payer — otherwise an operator who pockets funds can't be slashed.

---

## 5. Send funds

```bash
# Pay a BOLT11 with deposits funds
wallet-cli.sh pay_invoice home lnbc...

# Pay a Lightning Address
wallet-cli.sh --wallet ~/.depo pay-lnurl alice@example.com 1000

# NIP-57 zap (pay-lnurl + zap request envelope)
wallet-cli.sh --wallet ~/.depo zap alice@example.com 1000

# Intra-ledger transfer to another deposit on the same ledger
deposits-wallet send home 5000 --to <recipient_pubkey>

# Cross-ledger via courier (sender and receiver on different operators)
deposits-wallet route home other_alias 10000

# On-chain withdrawal
deposits-wallet withdraw home 100000 --to bc1q...
```

**Cross-ledger routing.** `route` finds a courier deposit that bridges the sender's and receiver's ledgers and runs an HTLC across both. There's no "Lightning Network" per se — couriers are just deposits with two ledger relationships.

**Swaps (atomic cross-ledger trades).** `swap-advertise`, `swap-list`, `swap-request`, `swap-listen` — same machinery, but for trustless deposit-for-deposit swaps. Built on the transfer primitive ([DEP-09](DEP-09.md)).

---

## 6. Verify your own balance

The chain is public. You don't have to trust the operator's word.

```bash
# Validate hash chain locally
deposits-wallet ledger validate <ledger_id>

# Show every update + decoded TLV
deposits-wallet ledger show <ledger_id>

# Trace quorum rotations / disputes / acquisitions
deposits-wallet ledger custody <ledger_id>

# Show transaction history for one deposit
deposits-wallet history home
```

The balance shown by `balance` is computed locally from the validated chain; it does not trust the operator. If `validate` fails, the chain has been tampered with or you've fetched a partial set of updates — try a different relay before assuming malice.

For deeper verification (per-update TLV breakdown, BIP-340 signature check, content_hash recomputation, cosignature linkage), see [SKILLS-protocol.md](SKILLS-protocol.md).

**Operator pubkey vs. event publisher pubkey.** When an operator runs with a separate signer ([SIGNER.md](SIGNER.md)), the daemon's *Nostr publisher* pubkey is structurally distinct from the operator's *protocol* pubkey. Kind 9100 / 39100 events are published under the Nostr pubkey; the operator's protocol pubkey appears in the event's *content* (e.g. the advertisement's `operator_id` field, or a ledger update's `operator_id`). When the wallet verifies `operator_signature`, it always uses the *protocol* pubkey from content — not the event's outer `pubkey`. Wallets that filter or subscribe by the operator's npub will need to use the publisher pubkey for that, and the protocol pubkey for trust assertions. (Today's wallets treat them as the same; the depositor-facing protocol update is staged, not yet shipped.)

---

## 7. When things go wrong

**Operator unresponsive.** Wallet requests run through the messaging relay, which is ephemeral — a queued request can drop. Retry first. Persistent silence past `quorum_expiry` is what the `QuorumExpired` fraud proof exists for: cosigners refuse to sign past the deadline, the dispute pipeline triggers, and the lottery transfers custody. As a depositor you don't act in the lottery — your deposit moves with the ledger to the new custodian (`DisputeAcquire`).

**Operator running but `make_invoice` fails with "BadSignature."** The LDK sidecar regenerates its TLS cert on every container start; the operator's cached `lightning.crt` goes stale. This is an operator-side fix (`docker cp` the new cert) — flag it to them.

**Stuck "Member consent failed" / "Cosign timeout."** Either the operator hasn't rotated quorum recently or a cosigner is offline. Try a different deposit (different operator) and report the issue.

**Disputed ledger.** Watch the explorer's custody trace; once the new operator publishes a fresh advertisement, your wallet can resume normal operation against them. Your deposit's funds are protected by the on-chain confiscation tx — they don't disappear.

**Fork detection.** Two updates at the same `seq` with conflicting `content_hash` is an equivocation fraud proof — broadcast it (`deposits-wallet ledger custody` will flag the conflict). The wallet treats the canonical chain as "the one with majority cosignatures," but late-discovered conflicts still produce slashable evidence.

**You lost your seed.** You're done. There's no recovery path — your deposits are still on-chain, but only your seed signs withdrawals. Back it up before depositing real value.

---

## 8. Useful one-liners

```bash
# What's my lnurl for each tracked deposit?
wallet-cli.sh --wallet ~/.depo lnurl

# Quick balance across all deposits
wallet-cli.sh --wallet ~/.depo balance

# Find which operator runs a deposit you've forgotten about
deposits-wallet ledger custody <ledger_id> | grep DepositOpen

# Tail every update on a ledger from the relay in real time
deposits-tools/bin/nostr-updates.sh ws://localhost:17779 <ledger_id>
```
