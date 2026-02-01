# Commitment Signature Failure Investigation

## Problem Summary

Channels are force-closing with "Invalid commitment tx signature from peer" error. This occurs during reserves synchronization in the Bitcoin Deposits protocol.

## Error Pattern

```
❌ COMMITMENT SIGNATURE FAILED: no fallback available. awaiting=false, remote=Some(1000), previous=None, pending=None
```

The error occurs when:
1. Alice receives `UpdateReserves` from Bob (new reserves value)
2. Alice confirms the reserves, moving from `pending_remote_reserves` to `remote_reserves`
3. Alice receives a `commitment_signed` that was built by Bob BEFORE Bob's reserves update
4. Alice tries to verify with current reserves but it fails
5. Fallback mechanisms don't work because state was cleared too early

## Root Cause Analysis

### The Reserves Sync Flow

When a node updates its reserves:
1. Node sends `UpdateReserves` message with new reserves value
2. Peer receives, validates, confirms with `AcceptReserves`
3. Both sides should now build commitments with the new reserves

### The Race Condition

The problem occurs when:
1. Bob sends `commitment_signed` (built with OLD reserves or no reserves)
2. Bob sends `UpdateReserves` (announcing NEW reserves)
3. Alice receives `UpdateReserves`, confirms it (now expects NEW reserves)
4. Alice receives `commitment_signed` (built with OLD reserves)
5. Signature mismatch - Alice expects NEW, Bob used OLD

### Fallback State Management Issues

The code has several places where `awaiting_remote_reserves_commitment` flag is managed:

1. **Set to true** in `confirm_pending_reserves()` when confirming remote reserves
2. **Cleared in `commitment_signed` handler** after one successful verification (TOO EARLY)
3. **Should be cleared in `revoke_and_ack`** after peer confirms sync

## What We've Tried

### Fix Attempt 1: Extended Fallback Logic (Current State)

Changes made to `vendor/rust-lightning/lightning/src/ln/channel.rs`:

#### 1. Don't clear awaiting flag immediately (line 5443-5449)
```rust
// BEFORE: Cleared immediately after one successful verification
self.context.awaiting_remote_reserves_commitment = false;
self.context.previous_remote_reserves = None;

// AFTER: Keep fallback state for potential more old commits
log_debug!(logger, "Commitment verified with new reserves for channel {}, keeping fallback state...");
// Don't clear awaiting or previous
```

#### 2. Don't clear at end of commitment_signed (line 5520-5527)
```rust
// BEFORE: Also cleared here
self.context.previous_remote_reserves = None;
self.context.awaiting_remote_reserves_commitment = false;

// AFTER: Just log, don't clear
log_debug!(logger, "Keeping awaiting_remote_reserves_commitment=true...");
```

#### 3. Clear in revoke_and_ack instead (line 5855-5865)
```rust
if self.context.awaiting_remote_reserves_commitment {
    log_debug!(logger, "Clearing awaiting_remote_reserves_commitment for channel {} after revoke_and_ack");
    self.context.awaiting_remote_reserves_commitment = false;
    // Keep previous_remote_reserves - it will be replaced by next confirm_pending_reserves
}
```

#### 4. Extended fallback conditions (line 5289)
```rust
// BEFORE: Only tried fallback if awaiting flag was set
} else if self.context.awaiting_remote_reserves_commitment {

// AFTER: Try fallback if we have previous reserves OR awaiting flag is set
} else if self.context.previous_remote_reserves.is_some() || self.context.awaiting_remote_reserves_commitment {
```

#### 5. Added final "no reserves" fallback (line 5322-5354)
```rust
// New fallback: try with NO reserves as last resort
} else if self.context.remote_reserves.is_some() {
    // Try with remote_reserves = None (no reserves output)
    log_debug!(logger, "🔄 COMMITMENT FALLBACK: first try failed, trying with NO remote reserves");
    // ... build commitment with remote_reserves = None
}
```

### Result of Fix Attempt 1

- **Partial success**: Some channels survive
- **Still failing**: Alice→Charlie channel still gets tombstone
- The `previous_remote_reserves` issue persists when previous value was `None`

## Remaining Issues

### Issue 1: `previous_remote_reserves = None` Semantics

When remote had no reserves before an update:
- `remote_reserves` was `None` (Option::None)
- After confirm: `previous_remote_reserves = remote_reserves.take()` = `None`
- We can't distinguish between:
  - "Never stored previous" (don't try fallback)
  - "Previous was no reserves" (try fallback with no reserves output)

Both are represented as `Option::None`.

### Issue 2: Timing of Multiple Commitments

Multiple `commitment_signed` messages can be in flight simultaneously:
- #654: Built with no reserves
- #653: Built with new reserves (1000 sats)
- #652: Built with... ???

The sequence of commitment numbers (counting DOWN from 281474976710655) makes tracking complex.

### Issue 3: The Awaiting Flag Gate

At line 6491-6497, new `UpdateReserves` is rejected if `awaiting_remote_reserves_commitment = true`:
```rust
if self.context.awaiting_remote_reserves_commitment {
    return Err(ChannelError::Ignore("Awaiting commitment_signed for previously confirmed reserves"));
}
```

This creates a tension:
- Keep `awaiting = true` longer → more fallback capability, but can't accept new updates
- Clear `awaiting = false` earlier → can accept new updates, but lose fallback

## Observed Failure Sequence (Latest)

From Alice's perspective (channel with Charlie):
```
Alice → Charlie (4 updates)
    0 [00000000~5f07e5a3] ✓3🔒 LedgerOpenRequest
    1 [5f07e5a3~f838b7d0] ✓3🔒 AddQuorumMember     qm:Bob
    2 [f838b7d0~22356f4e] ✓3🔒 ReservesToReserves       10000 sat
    3 [22356f4e~47ab1fda] ✓3   ChannelCloseTombstone    <-- FAILURE
```

The tombstone appears right after `ReservesToReserves`.

## Potential Solutions to Explore

### Solution A: Track "Previous Reserves Stored" Separately

Add a flag to distinguish "never stored previous" from "previous was None":
```rust
previous_remote_reserves: Option<ReservesConfig>,
previous_remote_reserves_stored: bool,  // NEW: true even if previous was None
```

### Solution B: Always Try No-Reserves Fallback

Make the "no reserves" fallback unconditional - always try it as last resort regardless of flags.

### Solution C: Delay Commitment After Reserves Update

After sending `UpdateReserves`, wait for `AcceptReserves` before sending any `commitment_signed`. This eliminates the race but adds latency.

### Solution D: Include Reserves Hash in Commitment Signature

Add reserves configuration hash to the `commitment_signed` message so receiver knows exactly what reserves the sender used.

### Solution E: Revise Reserves Sync Protocol

Change the protocol so reserves sync happens atomically with commitment:
1. Send `UpdateReserves` with commitment number
2. Don't use new reserves until that commitment is acknowledged

## Files Involved

- `vendor/rust-lightning/lightning/src/ln/channel.rs` - Main channel logic
  - `commitment_signed` handler (~line 5100-5550)
  - `revoke_and_ack` handler (~line 5776-6058)
  - `update_reserves` handler (~line 6478-6560)
  - `build_commitment_transaction` (~line 3200-3400)

- `src/deposits/handler.rs` - Deposits protocol handler
  - Triggers reserves updates
  - Manages ledger state

## Debug Logging Added

Key debug log patterns to search for:
- `BUILD_COMMITMENT_TX:` - Shows reserves values used when building
- `COMMITMENT FALLBACK:` - Shows when fallback logic is triggered
- `COMMITMENT SIGNATURE FAILED:` - Shows failure details
- `awaiting_remote_reserves_commitment` - Flag state changes

## Latest Failure Analysis (December 28, 2025)

### Charlie's Failure Sequence (channel 58265462...)

```
21:05:29 - Charlie verifies holder #654 with remote=None ✓
21:05:30 - Charlie receives UpdateReserves(10000) from Alice
21:05:30 - Charlie confirms: remote_reserves=10000, previous=None, awaiting=true
21:05:30 - Charlie verifies holder #653 with remote=10000 ✓
21:05:30 - Charlie builds counterparty #653 for Alice
21:05:30 - Charlie verifies holder #652 with remote=10000 - FAILS
21:05:30 - FALLBACK: tries with previous=None
21:05:30 - Charlie builds holder #652 with remote=None - STILL FAILS!
21:05:30 - Channel closes
```

### Key Observation

The fallback WAS triggered and worked correctly:
```
🔄 COMMITMENT FALLBACK: first try failed, trying previous reserves (None) for channel 58265462...
BUILD_COMMITMENT_TX: for=holder, local_reserves=None, remote_reserves=None
❌ COMMITMENT SIGNATURE FAILED after previous_reserves fallback
```

But even with `remote=None`, the signature still didn't match.

### What This Tells Us

Alice built commitment #652 for Charlie with something that's NEITHER:
- `local_reserves=10000` (new reserves)
- `local_reserves=None` (old/no reserves)

**Possible explanations:**
1. Alice built with a DIFFERENT reserves amount (intermediate value?)
2. There's a commitment number mismatch (Alice thinks it's #653, Charlie thinks it's #652)
3. Something else in the commitment differs (HTLC state, fee, etc.)
4. Alice built with different `script_pubkey` or `ledger_hash` values

### Need to Investigate

Look at what Alice ACTUALLY built for commitment #652:
- What reserves values did Alice use?
- What commitment number did Alice think she was building?
- Are there any HTLCs that differ between the two?

## ROOT CAUSE IDENTIFIED (December 28, 2025 - Latest)

### The Actual Bug: Duplicate Commitment Number

**Alice sends TWO commitment_signed messages for the SAME commitment number!**

#### Evidence from Logs

**Alice's build logs:**
```
21:05:30 - COMMITMENT TX #281474976710653 for counterparty (HTLC fulfill)
21:05:30 - COMMITMENT TX #281474976710653 for counterparty (accept_reserves commit)
```

Alice NEVER built #652. She built #653 twice.

**Charlie's verification:**
```
21:05:30 - Verifies holder #653 - SUCCESS
21:05:30 - Verifies holder #652 - FAILS (both reserves values tried)
```

Charlie expects #652 for the second message because his counter advanced after validating #653.

#### Why This Happens

The `accept_reserves` handler calls `send_commitment_no_state_update()`:

```rust
// In accept_reserves (line 6635):
match self.send_commitment_no_state_update(logger) {
```

This function:
1. Uses `cur_counterparty_commitment_transaction_number` (still at #653)
2. Signs for that commitment number
3. Does NOT decrement the counter (that happens in revoke_and_ack handler)

Meanwhile, the HTLC fulfill also uses the same commitment number flow:
1. Also uses `cur_counterparty_commitment_transaction_number` (#653)
2. Signs for #653
3. Gets sent first

Both commitment_signed messages are for #653, but Charlie:
1. Validates first one as #653 ✓
2. His counter advances to #652
3. Tries to validate second one as #652 ✗

#### The Missing Guard

Normal commitment flow (line 5569) checks:
```rust
if need_commitment && !self.context.channel_state.is_awaiting_remote_revoke() {
    // send commitment
}
```

But `accept_reserves` uses `send_commitment_no_state_update()` which is designed for
`channel_reestablish` and **bypasses the awaiting_remote_revoke check**.

### The Fix

In `accept_reserves`, check `is_awaiting_remote_revoke()` BEFORE calling
`send_commitment_no_state_update()`. If already awaiting, return `Ok(None)` and let
the reserves be committed in the next natural commitment update.

```rust
// In accept_reserves, BEFORE line 6635:
if self.context.channel_state.is_awaiting_remote_revoke() {
    log_debug!(logger, "Cannot immediately commit reserves - awaiting revoke_and_ack");
    return Ok(None);  // Reserves will be committed in next natural update
}
```

## Next Steps

1. ~~Add logging to show EXACTLY what reserves Alice uses when building each counterparty commitment~~
2. ~~Log the commitment number Alice thinks she's building vs what Charlie expects~~
3. ~~Consider if there's a commitment number tracking issue~~ **CONFIRMED: This is the issue!**
4. ~~Check if HTLCs or other commitment fields differ~~

**Action:** Fix the `accept_reserves` handler to check `is_awaiting_remote_revoke()` before
attempting to send a commitment_signed.

## FIX APPLIED (December 28, 2025)

### Two-Part Fix

#### Part 1: Prevent duplicate commitment_signed in accept_reserves

Added guard in `accept_reserves` (line 6633-6641):
```rust
if self.context.channel_state.is_awaiting_remote_revoke() {
    log_debug!(logger, "Cannot immediately commit reserves - already awaiting revoke_and_ack");
    return Ok(None);
}
```

#### Part 2: Clear awaiting_remote_reserves_commitment correctly

**Problem:** The flag was only cleared when RECEIVING a revoke_and_ack, but in one-sided
reserves updates, the receiver only SENDS an RAA - they never receive one.

**Fix:** Clear the flag immediately after successfully verifying a commitment with the
NEW reserves (not fallback). Changed lines 5476-5491:

```rust
} else if self.context.awaiting_remote_reserves_commitment {
    // First try succeeded with NEW reserves - the peer has committed to the new reserves.
    // Clear the flag because:
    // 1. The peer built their commitment with our new reserves (signature verified)
    // 2. We will send back our RAA to acknowledge
    // 3. The reserves transition is complete from our side
    log_debug!(logger, "Commitment verified with new reserves, clearing awaiting flag");
    self.context.awaiting_remote_reserves_commitment = false;
}
```

### Test Results

All tests pass:
- reinit.sh completes successfully
- test.sh completes with all NWC operations working
- All ledgers show ✓3🔒 status (fully synchronized, no tombstones)
- No channel force-closes
