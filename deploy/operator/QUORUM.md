# Forming a quorum with peers

A deposits operator on their own is a single point of failure — collateral
isn't slashable, fraud isn't constrained, the protocol's safety properties
don't kick in. Operators form a **quorum** with `Q-1` other operators so
that protocol-level signing requires a majority. Each member puts up an
existing ledger as collateral; misbehaviour by any member is provable
on-chain and slashes that collateral.

This document covers **how 3+ operators on different boxes form a quorum
together** using the deposits-node CLI. It's the "private" flow — peers
who know each other (out of band) and want to be in a quorum together.

The "public" flow (advertise on a relay, accept strangers) is on the
roadmap but not yet implemented. See [PACKAGING_PLAN.md](../../PACKAGING_PLAN.md)
Tier 3.

## Prerequisites

Each peer needs:

1. A running `deposits-node` operator (e.g. via [`deploy/operator/`](./README.md))
2. At least one **owned ledger** opened and funded. The collateral they're
   putting up on the quorum is one of these existing ledgers — the
   protocol uses the ledger's reserves as the slashable bond.
3. The other peers' operator pubkeys + the ledger_ids they're contributing
   as collateral. Coordinate these via a chat / email / phone before
   running the wizard.

If you haven't opened a ledger yet, do that first: `deposits-node ledger open`
(see [SKILLS-operator.md](https://github.com/bitcoin-deposits/deposits/blob/main/SKILLS-operator.md) §7).

## Step 1 — every peer shares their identity

On each box, the operator runs:

```bash
deposits-node quorum show-identity
```

Output:

```
Operator pubkey: 02abc1234...

Owned ledgers (any can be used as your collateral on a peer's quorum):
  4f3a9b2c1d... 
  bbbb1234aa...

Share with a peer who wants you in their quorum:
  pubkey:   02abc1234...
  ledger:   <pick one ledger ID from the list above>

Or paste this line for one of your ledgers:
  02abc1234...:4f3a9b2c1d...
```

Each operator copies their `pubkey:ledger` line and sends it to the
others via whatever side channel they prefer. The choice of which
ledger to put up as collateral is up to each peer — they pick from
their own owned ledgers based on which one's reserves they're willing
to risk on this quorum.

## Step 2 — one operator runs `form-with`

Pick one operator to drive the formation. Call them **Alice**.
**Alice** decides which of her own ledgers will be the quorum's main
ledger (the one the quorum signs against), then runs:

```bash
deposits-node quorum form-with \
    --ledger-id <alice_main_ledger_id> \
    --member <bob_pubkey>:<bob_collateral_ledger_id> \
    --member <carol_pubkey>:<carol_collateral_ledger_id> \
    --begin --amount-sats 1000000
```

Replace:
- `<alice_main_ledger_id>` with one of Alice's owned ledger IDs (from
  her own `quorum show-identity` output)
- `<bob_pubkey>:<bob_collateral_ledger_id>` with the line Bob sent her
- `<carol_pubkey>:<carol_collateral_ledger_id>` with the line Carol sent her
- `1000000` with the amount of sats to lock as the quorum's reserves

The wizard:
1. For each `--member`, sends a `quorum_add` request to that peer
   (over Nostr). The peer's daemon receives the request, validates the
   collateral match, signs a consent, and replies. Alice's daemon
   records the `QuorumAddMember` operation on the ledger.
2. After all members are added: runs `quorum_begin` with the amount,
   which rotates Alice's reserves into the quorum's Taproot multisig
   on-chain.

If you want to review the membership state before activating, omit
`--begin --amount-sats`:

```bash
deposits-node quorum form-with \
    --ledger-id <alice_main_ledger_id> \
    --member <bob_pubkey>:<bob_ledger_id> \
    --member <carol_pubkey>:<carol_ledger_id>
# review:
deposits-node quorum list
# then activate when ready:
deposits-node quorum begin <alice_main_ledger_id> --amount-sats 1000000
```

## Step 3 — peers verify their membership

Bob and Carol's daemons auto-respond to the membership request. After
Alice's `form-with` completes, they can verify their side:

```bash
deposits-node quorum list
```

They should see a "Serving on quorums" section listing Alice's ledger.

## Sizing Q

The quorum size `Q` is the **number of cosigners**, not counting the
operator. Valid sizes: 3, 5, 7. The cosign threshold is `(Q/2) + 1`:

| Q | Threshold | Operators total (incl. originator) |
|---|---|---|
| 3 | 2 of 3 cosigners + originator | 4 |
| 5 | 3 of 5 cosigners + originator | 6 |
| 7 | 4 of 7 cosigners + originator | 8 |

Pick `Q` based on:
- **Trust assumption**: bigger `Q` = harder for a single collusion to
  reach threshold, but more partners you need to maintain a relationship
  with.
- **Liveness budget**: every operation needs the threshold to cosign in
  ~10 seconds. Bigger `Q` means more daemons that have to be online and
  responsive. 3 is generally a good starting point; bigger only if your
  trust threshold demands it.

`Q=3` is the typical default and what `setup.sh 3` exercises. You don't
specify `Q` directly in `form-with` — it's the number of `--member`
flags you pass.

## Membership expiry

By default, quorum membership expires after a configurable block
window. Operators can refresh via `quorum refresh` before expiry
(documented in the per-command help: `deposits-node quorum refresh --help`).

If a member doesn't refresh in time, the quorum can rotate via Tier-1
recovery flows after the timeout. See
[SKILLS-operator.md](https://github.com/bitcoin-deposits/deposits/blob/main/SKILLS-operator.md) §7 for the quorum
lifecycle.

## Troubleshooting

### "failed to add member: timeout waiting for consent"

The peer's daemon didn't respond in time. Check:
- Their daemon is running: ask them to run `deposits-node health`
- They're connected to the same messaging relay as you. By default
  this is the operator's primary `--relay` URL; if you and the peer
  use different relays, the request might not reach them.
- Their daemon's logs for an inbound `quorum_join` request that failed
  validation (most often: the `member_ledger_id` you specified doesn't
  match what their daemon thinks they own).

### "member's ledger ID must be 64 hex chars"

The `<pk>:<lid>` you pasted didn't have a colon between them, or the
ledger ID has typos. Re-run `quorum show-identity` on the peer's box
and re-paste.

### "ledger has no reserves"

The `--ledger-id` you specified for your own side doesn't have any
funded reserves yet. Open a ledger and fund it before forming a
quorum: `ledger open` then send sats to the funding address.

### "begin failed: insufficient reserves"

The `--amount-sats` you passed exceeds your ledger's reserves. Lower
the amount or fund the ledger first.

## After formation

Once `form-with --begin` succeeds, your ledger is now quorum-protected:
- Spending requires cosignatures from the majority of members.
- All members hold each other accountable; fraud by any member can be
  proven on-chain and slashes that member's collateral.
- New deposits are admissible against this ledger via the
  `deposits-wallet` flow.

See [SKILLS-operator.md](https://github.com/bitcoin-deposits/deposits/blob/main/SKILLS-operator.md) for ongoing
operational concerns (monitoring, dispute handling, quorum refresh).
