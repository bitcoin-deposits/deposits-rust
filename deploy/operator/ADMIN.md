# Operator admin UI

The daemon embeds a read-only browser UI for ops visibility — what
ledgers exist, who's quorumed-up, recent ledger operations, and
whether the signer is reachable. PACKAGING_PLAN.md Tier 5.

It's **read-only by design**: no buttons that move money, no quorum
formation, no signer config. Those live in CLI subcommands precisely
because they're the actions worth a thoughtful prompt and a `tmux`
scrollback. The UI is for "did the thing I just did actually take?"

## What it shows

```
deposits / operator admin       ●  signer
─────────────────────────────────────────────
[dashboard] [ledgers] [quorum] [activity] [signer]

  ledgers          active quorums       serving on     block height
       3                  2                   1            865432
```

- **dashboard** — operator pubkey, network, chain tip, totals strip
- **ledgers** — each ledger's reserves key + amount, deposits count,
  quorum members
- **quorum** — for every ledger you participate in, who the active
  members are, whose ledger it is, your role
- **activity** — last N `LedgerOperation`s across all ledgers, with
  variant name and timestamp
- **signer** — pubkey + connection state, refreshed every 10s

## Authentication

A 32-byte hex bearer token is generated on first boot at
`<data-dir>/admin-token` (mode 0600). It's logged once with a
`PASTE INTO BROWSER` hint. The browser keeps it in `localStorage`
after the token gate accepts it.

To rotate the token: `rm <data-dir>/admin-token` and restart. A new
one is generated on next boot.

To find the token on a running operator:

```bash
docker exec deposits-node cat /var/lib/deposits/admin-token
```

## Browser access

By default the UI binds `127.0.0.1:8765` — loopback only. Reach it
from the host:

```bash
open http://127.0.0.1:8765/    # macOS
xdg-open http://127.0.0.1:8765/  # Linux
```

In Docker the port is published via `docker-compose.yml`; if you
removed that mapping or run the daemon non-Dockerized on a remote
host, see "Remote access" below.

### Remote access (through TLS)

Don't expose `8765` directly. The token is bearer-only — anyone with
it has full read access — and the server speaks plain HTTP. Front it
with caddy / nginx / traefik terminating TLS:

```
# /etc/caddy/Caddyfile
admin.your-operator.example {
  reverse_proxy 127.0.0.1:8765
}
```

Then `--admin-bind 127.0.0.1:8765` (the default) stays loopback and
caddy is the only thing speaking to the outside world.

## CLI flags

The relevant `deposits-node run` options:

```
--admin-bind <addr>   Bind address (default: 127.0.0.1:8765)
--admin-disabled      Don't start the admin UI at all
```

To bind a different port: `--admin-bind 127.0.0.1:9876`. To bind all
interfaces (only behind a real reverse proxy + firewall):
`--admin-bind 0.0.0.0:8765`. The token still gates access either way.

## Why it's so small

The UI is one HTML file, one `<style>`, one `<script>`. No build
step, no bundler, no framework. The same shape as `deposits-web/
explorer/` — vanilla CSS variables for the dark theme, fetch() for
the API, `localStorage` for the token. The whole frontend is
`include_str!`'d into the binary so there's no static-file shipping
question.

If you want richer interaction (writes, signer config, quorum
formation) — those belong as separate CLI subcommands, not in here.
