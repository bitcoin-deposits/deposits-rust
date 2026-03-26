# Deposit Access Control

Deposit open requests are gated by an access control system that must
be explicitly enabled. All list files live in the node's data directory
and are hot-reloaded on each periodic cycle (no restart required).

## Enabling

Set `DEPOSIT_ACCESS_CONTROL=true` to enable. When disabled (the
default), all deposit opens are allowed — only the denylist is checked.

## Evaluation order

```
deposit_open request
        |
        v
  +-----------+     yes
  | Denylist? |----------> REJECT  (always checked)
  +-----------+
        | no
        v
  +---------------------+
  | DEPOSIT_ACCESS_      |--no--> ALLOW (open access)
  | CONTROL enabled?     |
  +---------------------+
        | yes
        v
  +------------------+     yes
  | Npub allowlist?  |----------> ALLOW
  +------------------+
        | no
        v
  +--------------------+
  | Domain allowlist   |--no--> REJECT
  | has entries?       |
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

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `DEPOSIT_ACCESS_CONTROL` | `false` | Set to `true` to enable allowlist/domain checks. Denylist is always active regardless. |
| `ATTESTATION_VERIFIER_PUBKEY` | unset | Hex pubkey of the lightning-verify service whose kind 55502 attestations are trusted. Required for domain-based access control. |

## List files

All files use the same format: one entry per line, blank lines and
lines starting with `#` are ignored, entries are lowercased.

### deposit_denylist.txt

Hex npubs that are always rejected. Checked regardless of whether
access control is enabled — this is the kill switch.

```
# Known bad actor
deadbeefcafe...
```

### deposit_allowlist.txt

Hex npubs that are always allowed to open deposits when access control
is enabled.

```
# Alice (operator)
a1b2c3d4e5f6...
# Bob (known user)
f6e5d4c3b2a1...
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

## Examples

### Denylist only (default)

```bash
# No DEPOSIT_ACCESS_CONTROL set — open access with a kill switch
```

```
data_dir/
  deposit_denylist.txt    # blocked npubs
```

Anyone can open deposits except denied npubs.

### Npub allowlist

```bash
DEPOSIT_ACCESS_CONTROL=true
```

```
data_dir/
  deposit_allowlist.txt    # hex npubs, one per line
```

Only listed npubs can open deposits.

### Domain-based with denylist

```bash
DEPOSIT_ACCESS_CONTROL=true
ATTESTATION_VERIFIER_PUBKEY=<your-lightning-verify-pubkey>
```

```
data_dir/
  deposit_denylist.txt           # blocked npubs
  deposit_domain_allowlist.txt   # allowed domains
```

Anyone with a verified lightning address on an allowed domain can open
deposits, unless they're on the denylist.

### Combined

```bash
DEPOSIT_ACCESS_CONTROL=true
ATTESTATION_VERIFIER_PUBKEY=<your-lightning-verify-pubkey>
```

```
data_dir/
  deposit_denylist.txt           # blocked npubs
  deposit_allowlist.txt          # VIP npubs (always allowed)
  deposit_domain_allowlist.txt   # allowed domains for everyone else
```

VIPs are always allowed. Everyone else needs a verified lightning
address on an approved domain. Denied npubs are always blocked.
