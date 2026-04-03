# LNURL-pay Gateway for Bitcoin Deposits

An HTTP service that gives every deposit a lightning address. Payers
send sats to `<pubkey>@<ledger>.pay.example.com` and the deposit
gets credited automatically.

## How it works

```
Payer                    LNURL Gateway               Operator Node
  |                          |                            |
  |  GET /.well-known/       |                            |
  |  lnurlp/<pubkey>         |                            |
  |  Host: <ledger>.domain   |                            |
  |------------------------->|                            |
  |  {callback, min, max}    |                            |
  |<-------------------------|                            |
  |                          |                            |
  |  GET /lnurl/callback/    |                            |
  |  <pubkey>?amount=N       |  kind 20101 make_invoice   |
  |------------------------->|--------------------------->|
  |                          |  kind 20102 {invoice: ...} |
  |  {pr: "lnbc..."}        |<---------------------------|
  |<-------------------------|                            |
  |                          |                            |
  |  Pay BOLT11 invoice      |                            |
  |------------------------------------------------------>|
  |                          |        auto_credit         |
  |                          |         deposit            |
```

The gateway connects to operator relays via Nostr. It signs requests
with its own key (not an operator key) — operators process
`make_invoice` from any authorized sender.

## Lightning address format

```
<deposit_pubkey>@<bech32_ledger_id>.<base_domain>
```

The 32-byte ledger ID is encoded as bech32 data (52 chars) in the
subdomain. A wildcard DNS record routes all subdomains to the gateway.

Example:
```
037e7f9e0cdb02ec3860f56541a40a00061aff1563cb3d9ae7fc7443e537f1a372@hdq5hj7hatfpcqfkcwz32zzxkjqsg8s2wch2f0xpxj24h6uxdpvs.pay.example.com
```

## Docker

### Build

From the repository root:

```bash
docker build -f deposits-tools/Dockerfile.lnurl -t deposits-lnurl .
```

### Run

```bash
docker run -d \
  --name lnurl \
  -p 3000:3000 \
  -e LNURL_NSEC="<hex-or-nsec-key>" \
  -e LNURL_RELAYS="ws://alice:7777,ws://bob:7777" \
  -e LNURL_DOMAIN="pay.example.com" \
  deposits-lnurl
```

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `LNURL_NSEC` | yes | — | Nostr secret key (hex or nsec bech32). Used to sign `make_invoice` requests. |
| `LNURL_RELAYS` | yes | — | Comma-separated relay URLs. Must include the operators' relays. |
| `LNURL_DOMAIN` | yes | — | Base domain. Subdomains are bech32-encoded ledger IDs. |
| `LNURL_LISTEN` | no | `0.0.0.0:3000` | HTTP listen address. |
| `LNURL_MIN_SATS` | no | `1` | Minimum payment in sats. |
| `LNURL_MAX_SATS` | no | `1000000` | Maximum payment in sats. |
| `LNURL_DEFAULT_LEDGER` | no | — | Hex ledger ID for single-ledger deployments (no subdomain needed). |

For key management, `LNURL_NSEC_FILE` can point to a file containing
the key (Docker secrets pattern).

### Docker Compose

```yaml
services:
  lnurl:
    build:
      context: .
      dockerfile: deposits-tools/Dockerfile.lnurl
    ports:
      - "3000:3000"
    environment:
      LNURL_NSEC_FILE: /run/secrets/lnurl_nsec
      LNURL_RELAYS: ws://alice:7777,ws://bob:7777
      LNURL_DOMAIN: pay.example.com
    secrets:
      - lnurl_nsec

secrets:
  lnurl_nsec:
    file: ./secrets/lnurl_nsec
```

## DNS setup

Add a wildcard record for the base domain:

```
*.pay.example.com.  A     <gateway-ip>
pay.example.com.    A     <gateway-ip>
```

Or with a reverse proxy (nginx, caddy, frp):

```
*.pay.example.com → localhost:3000
```

## TLS

The gateway serves plain HTTP. For production, terminate TLS at a
reverse proxy. The LNURL spec requires HTTPS, so the proxy must
handle wildcard certificates.

With Let's Encrypt wildcard certs (DNS-01 challenge):
```bash
certbot certonly --dns-cloudflare -d "*.pay.example.com" -d "pay.example.com"
```

Or use Caddy which handles this automatically:
```
*.pay.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy localhost:3000
}
```

## Testing

```bash
# Metadata endpoint (use -H to simulate subdomain)
curl -H "Host: <bech32_ledger>.pay.example.com" \
  http://localhost:3000/.well-known/lnurlp/<deposit_pubkey>

# Create invoice
curl -H "Host: <bech32_ledger>.pay.example.com" \
  "http://localhost:3000/lnurl/callback/<deposit_pubkey>?amount=10000"

# Single-ledger mode (with LNURL_DEFAULT_LEDGER set)
curl http://localhost:3000/.well-known/lnurlp/<deposit_pubkey>
```

## Generating the bech32 subdomain

The subdomain is the ledger ID (32 bytes) encoded as bech32 data
characters — the same charset used in Bitcoin segwit addresses
(`qpzry9x8gf2tvdw0s3jn54khce6mua7l`), without HRP or checksum.

To convert a hex ledger ID to a subdomain:

```python
CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def hex_to_subdomain(hex_id):
    data = bytes.fromhex(hex_id)
    acc, bits, result = 0, 0, []
    for b in data:
        acc = (acc << 8) | b
        bits += 8
        while bits >= 5:
            bits -= 5
            result.append(CHARSET[(acc >> bits) & 0x1f])
    if bits > 0:
        result.append(CHARSET[(acc << (5 - bits)) & 0x1f])
    return ''.join(result)
```
