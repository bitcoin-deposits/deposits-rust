# deposits-attestation

Nostr-native service that verifies an npub controls a lightning address.

The proof mechanism is challenge-response over lightning payments: the service
pays random amounts to the lightning address and asks the user to report what
they received. A correct answer produces a signed attestation published to
relays.

## How it works

```
User                          Service                       Lightning Address
 |                              |                               |
 |-- kind 25500 -------------->|                               |
 |   {lightning_address}       |                               |
 |                             |-- resolve LNURL -------------->|
 |                             |<-- callback, min/max ---------|
 |                             |-- probe invoice for fees ----->|
 |                             |<-- BOLT11 with route hints ---|
 |<-- kind 25501 -------------|                               |
 |   {session_id, invoice}    |                               |
 |                             |                               |
 |   ... user pays invoice ... |                               |
 |                             |                               |
 |-- kind 25500 -------------->|                               |
 |   {action: challenge}       |-- list_payments (check paid) |
 |                             |-- generate N random amounts   |
 |                             |   summing to challenge_sats   |
 |                             |-- pay amount_1 -------------->|
 |                             |-- pay amount_2 -------------->|
 |                             |-- pay amount_3 -------------->|
 |<-- kind 25501 -------------|                               |
 |   {status: challenge_sent}  |                               |
 |                             |                               |
 |   ... user checks wallet ...|                               |
 |                             |                               |
 |-- kind 25500 -------------->|                               |
 |   {action: verify,          |                               |
 |    amounts: [a, b, c]}      |-- sorted comparison           |
 |                             |                               |
 |<-- kind 25501 -------------|                               |
 |   {status: verified,        |                               |
 |    signature, event_id}     |                               |
 |                             |-- kind 55502 (attestation) -->| relays
```

### NIP-05 fast path

Before starting the challenge flow, the service checks if the lightning address
is already attestable via NIP-05. If `user@domain.com` is the lightning address,
it fetches `https://domain.com/.well-known/nostr.json?name=user` and checks
whether the returned pubkey matches the requester. If so, the domain already
vouches for this npub — the attestation is issued immediately with
`method: "nip05"`, no invoice or payment needed.

### Why random amounts?

The service divides the challenge total into N random positive integers using a
uniform distribution over all ordered compositions (stars-and-bars method). This
maximizes entropy: for 1000 sats across 3 payments there are C(999,2) = 498,501
equally likely outcomes. An attacker who doesn't control the lightning address
would need to guess the exact amounts within the timeout window.

### Fee estimation

Rather than using a fixed fee, the service requests a probe invoice from the
LNURL-pay endpoint and inspects the BOLT11 route hints to compute worst-case
routing fees. Falls back to a configurable default when route hints are absent.

## Event kinds

| Kind  | Range     | Purpose                           |
|-------|-----------|-----------------------------------|
| 25500 | Ephemeral | Verification requests from users  |
| 25501 | Ephemeral | Service responses                 |
| 55502 | Regular   | Durable attestation events        |

Requests are tagged `#p` with the service pubkey. Responses are tagged `#p` with
the requester plus `#e` referencing the request. Attestations are tagged `#p`
with the verified npub.

## Configuration

| Variable                    | Default              | Description                                    |
|-----------------------------|----------------------|------------------------------------------------|
| `VERIFY_NSEC`               | **required**         | Service identity (hex secret key or bech32 nsec) |
| `VERIFY_RELAYS`             | `wss://relay.damus.io` | Comma-separated relay URLs                   |
| `VERIFY_ATTESTATION_RELAYS` | same as `VERIFY_RELAYS` | Separate relays for publishing attestations |
| `VERIFY_CHALLENGE_SATS`     | `1000`               | Total sats divided across challenge payments   |
| `VERIFY_NUM_PAYMENTS`       | `3`                  | Number of challenge payments                   |
| `VERIFY_MAX_ATTEMPTS`       | `3`                  | Wrong guesses before session is locked         |
| `VERIFY_PREMIUM_SATS`       | `0`                  | Extra sats charged on top of challenge + fees  |
| `VERIFY_FEE_FALLBACK_SATS`  | `10`                 | Per-payment fee when route hints unavailable    |
| `VERIFY_TIMEOUT_SECS`       | `600`                | Seconds to complete verification               |
| `VERIFY_FEE_CACHE_SECS`    | `3600`               | TTL for cached fee estimates per domain         |
| `VERIFY_NIP05_CACHE_SECS`  | `3600`               | TTL for cached NIP-05 lookups per domain        |
| `LDK_CLI`                   | `ldk-server-cli`     | Path to ldk-server-cli binary                  |
| `LDK_HOST`                  | `localhost`          | LDK server host                                |
| `LDK_PORT`                  | `3000`               | LDK server port                                |
| `LDK_API_KEY`               | `test_api_key`       | LDK server API key                             |
| `LDK_TLS_CERT`              | none                 | Optional TLS certificate path                  |

Any variable can also be loaded from a file by appending `_FILE` to the
name (e.g. `VERIFY_NSEC_FILE=/run/secrets/nsec`). The `_FILE` variant
takes precedence. This is the standard Docker secrets pattern.

## Usage

```bash
# Generate a key for the service
openssl rand -hex 32 > nsec.key

# Run
VERIFY_NSEC_FILE=nsec.key cargo run -p deposits-attestation --bin deposits-attest
```

The service logs its npub on startup. Clients send kind 25500 events tagged with
that pubkey.

### Invoice formula

```
invoice_sats = challenge_sats + (num_payments * estimated_fee) + premium_sats
```

Setting `VERIFY_PREMIUM_SATS` lets you charge for the service. The challenge
sats are returned to the user (via their lightning address), so the effective
cost to the user is `fees + premium`.

## Attestation format

On successful verification the service publishes a kind 55502 event:

```json
{
  "npub": "npub1...",
  "lightning_address": "user@domain.com",
  "verified_at": "2026-01-01T00:00:00+00:00",
  "method": "nip05"
}
```

The `method` field indicates how verification was performed: `"nip05"` for
NIP-05 fast path, `"challenge"` for the lightning payment challenge-response.

The response to the user also includes a standalone BIP-340 schnorr signature
over `SHA256("LIGHTNING_VERIFY:{npub}:{address}:{timestamp}:{verifier_pubkey}")`
for out-of-band verification.

## Tests

```bash
cargo test
```

## Docker

### Standalone (bundled relay)

All-in-one image with the verifier and a strfry relay. NIP-05
verification works out of the box. Challenge-response requires LDK.

```bash
# Build (from the workspace root)
docker build -f deposits-attestation/Dockerfile -t deposits-attestation .

# Run (NIP-05 only — no LDK needed)
docker run -d --name ln-verify \
  -p 7777:7777 \
  -v /path/to/nsec:/data/secrets/nsec:ro \
  -e VERIFY_NSEC_FILE=/data/secrets/nsec \
  -e VERIFY_RELAYS=wss://relay.damus.io \
  deposits-attestation
```

Port 7777 exposes the bundled relay. Clients send kind 25500 events
there. The verifier also publishes to `VERIFY_RELAYS` for durable
storage of attestations and other events.

### Compose (with LDK for challenge flow)

```yaml
lightning-verify:
  build: .
  environment:
    - VERIFY_NSEC_FILE=/run/secrets/verify_nsec
    - VERIFY_RELAYS=wss://relay.damus.io
    - LDK_HOST=ldk-server
    - LDK_PORT=3000
    - LDK_API_KEY_FILE=/run/secrets/ldk_api_key
    - RUST_LOG=info
  volumes:
    - /path/to/nsec:/run/secrets/verify_nsec:ro
    - /path/to/ldk/api_key:/run/secrets/ldk_api_key:ro
  restart: unless-stopped
```

## Requirements

- Rust 1.85+
- For challenge-response flow: a running
  [ldk-server](https://github.com/lightningdevkit/ldk-server) instance
  accessible via `ldk-server-cli`
- NIP-05 verification works without LDK

## License

MIT
