# Deposit Access Control

Deposit open requests are gated by a three-tier access control system.
All list files live in the node's data directory and are hot-reloaded
on each periodic cycle (no restart required).

## Evaluation order

```
deposit_open request
        |
        v
  +-----------+     yes
  | Denylist? |----------> REJECT
  +-----------+
        | no
        v
  +-------------------+     yes
  | Any lists exist?  |--no--> ALLOW (open access)
  +-------------------+
        | yes
        v
  +------------------+     yes
  | Npub allowlist?  |----------> ALLOW
  +------------------+
        | no
        v
  +--------------------+     yes
  | Domain allowlist   |--no--> REJECT
  | configured?        |
  +--------------------+
        | yes
        v
  +---------------------------+
  | Query relays for kind     |
  | 55502 attestation from    |     found, domain
  | trusted verifier, tagged  |---- in allowlist ---> ALLOW
  | with sender pubkey        |
  +---------------------------+
        | not found
        v
      REJECT
```

## List files

All files use the same format: one entry per line, blank lines and
lines starting with `#` are ignored, entries are lowercased.

### deposit_allowlist.txt

Hex npubs that are always allowed to open deposits, regardless of
attestation status.

```
# Alice (operator)
a1b2c3d4e5f6...
# Bob (known user)
f6e5d4c3b2a1...
```

### deposit_denylist.txt

Hex npubs that are always rejected. Checked first — overrides the
allowlist and attestation checks.

```
# Known bad actor
deadbeefcafe...
```

### deposit_domain_allowlist.txt

Lightning address domains. If a sender isn't on the npub allowlist,
the node queries relays for a lightning-verify attestation (kind 55502)
linking their npub to a lightning address. If the domain part of that
address appears in this file, the deposit is allowed.

```
# Major custodial wallets
getalby.com
walletofsatoshi.com
strike.me

# Our own domain
example.com
```

## Environment variable

| Variable | Description |
|---|---|
| `ATTESTATION_VERIFIER_PUBKEY` | Hex pubkey of the lightning-verify service whose kind 55502 attestations are trusted. Required for domain-based access control to function. |

If unset or empty, the attestation/domain path is skipped entirely —
only the npub allowlist and denylist are active.

## Lightning-verify attestation

The attestation is a kind 55502 nostr event published by the
lightning-verify service:

```json
{
  "npub": "npub1...",
  "lightning_address": "user@getalby.com",
  "verified_at": "2026-01-15T12:00:00+00:00",
  "method": "nip05"
}
```

The event is tagged `#p` with the verified npub, authored by the
verifier's pubkey. The node queries for events matching:

- Kind: 55502
- Author: `ATTESTATION_VERIFIER_PUBKEY`
- `#p` tag: the deposit open sender's hex pubkey

If found, the `lightning_address` field is parsed, the domain is
extracted, and checked against `deposit_domain_allowlist.txt`.

### Verification methods

The `method` field indicates how the lightning-verify service confirmed
the link between npub and lightning address:

- **`nip05`** — The lightning address domain's `.well-known/nostr.json`
  maps the user to this npub. Free, no payment needed.
- **`challenge`** — The service paid random amounts to the lightning
  address and the user correctly reported them. Requires payment of
  `challenge_sats + fees + premium`.

Both methods produce the same kind 55502 attestation and are treated
identically by the deposit access control system.

## Backwards compatibility

If no list files exist and `ATTESTATION_VERIFIER_PUBKEY` is unset,
the system behaves exactly as before: open access, anyone can open
deposits. Adding only `deposit_allowlist.txt` (the original behavior)
continues to work unchanged.

## Examples

### Allowlist-only (original behavior)

```
data_dir/
  deposit_allowlist.txt    # hex npubs, one per line
```

Only listed npubs can open deposits. No attestation checks.

### Domain-based with denylist

```
data_dir/
  deposit_denylist.txt           # blocked npubs
  deposit_domain_allowlist.txt   # allowed domains
```

```bash
ATTESTATION_VERIFIER_PUBKEY=<your-lightning-verify-pubkey>
```

Anyone with a verified lightning address on an allowed domain can open
deposits, unless they're on the denylist. No explicit npub allowlist
needed.

### Combined

```
data_dir/
  deposit_denylist.txt           # blocked npubs
  deposit_allowlist.txt          # VIP npubs (always allowed)
  deposit_domain_allowlist.txt   # allowed domains for everyone else
```

VIPs are always allowed. Everyone else needs a verified lightning
address on an approved domain. Denied npubs are always blocked.
