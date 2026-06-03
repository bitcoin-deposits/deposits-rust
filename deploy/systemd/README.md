# systemd bare-metal install

The target operator already runs their own bitcoin + LN node under
systemd and wants `deposits-node` as another unit alongside
`bitcoind.service` / `lnd.service` — not as a docker container.
This directory ships the unit files, an env-file template, and a
bootstrap script.

If you'd prefer docker, see [`../operator/`](../operator/). If you're
on Umbrel, see [`../umbrel/`](../umbrel/).

## What gets installed

```
/usr/local/bin/deposits-node            # daemon binary
/usr/local/bin/deposits-signer          # signer binary

/etc/systemd/system/deposits-signer.service
/etc/systemd/system/deposits-node.service
/etc/deposits/deposits-node.env         # daemon config (root:deposits 0640)

/var/lib/deposits/                      # daemon state (deposits:deposits 0750)
/var/lib/dsigner/                       # signer state (dsigner:dsigner 0700)
/run/dsigner/socket                     # signer socket (dsigner:dsigner 0750)
```

Two system users:
- **`dsigner`** — runs the signer. Holds the seed. No shell, no home.
  Stricter hardening profile (see [`deposits-signer.service`](deposits-signer.service)).
- **`deposits`** — runs the daemon. Holds the ledger history + wallet.
  Member of the `dsigner` group so it can reach the signer socket.

## 5-minute install

```bash
git clone https://github.com/bitcoin-deposits/deposits-rust.git
cd deposits-rust/deploy/systemd

make install-all                                # build + copy + bootstrap
sudo editor /etc/deposits/deposits-node.env     # network, relays, backend creds
make start                                      # systemctl enable --now
make logs                                       # journalctl -f
```

The full target list:

| target          | what it does                                                  |
|-----------------|---------------------------------------------------------------|
| `make`          | show all targets (also `make help`)                           |
| `make build`    | `cargo build --release -p deposits-node -p deposits-signer`   |
| `make install`  | build + copy binaries to `/usr/local/bin/`                    |
| `make bootstrap`| run `init.sh`: users + dirs + seed + signer + unit files      |
| `make install-all` | `install` + `bootstrap`                                    |
| `make start`    | `systemctl enable --now deposits-signer deposits-node`        |
| `make stop`     | disable + stop both                                           |
| `make restart`  | restart both (signer first)                                   |
| `make status`   | `systemctl status` for both                                   |
| `make logs`     | `journalctl -u deposits-node -u deposits-signer -f`           |
| `make admin-token` | print the bearer token for the admin UI                    |
| `make upgrade`  | `git pull` + rebuild + reinstall + restart                    |
| `make uninstall`| stop, remove binaries + unit files (preserves `/var/lib` data)|

All targets are idempotent. `make install-all` re-run on an already
installed host doesn't regenerate the seed or clobber config.

If you'd rather see the underlying commands, the targets are thin
wrappers around `cargo`, `install(1)`, `systemctl`, and `init.sh` —
read the [`Makefile`](Makefile) for the exact dance.

## Configuration

All daemon config lives in `/etc/deposits/deposits-node.env`. The
template is [`deposits-node.env.example`](deposits-node.env.example).
Required edits before first start:

- `NETWORK` — `bitcoin` / `testnet` / `signet` / `regtest`
- `OPERATOR_NAME` — appears in advertisements
- `RELAY_LEDGERS` — durable nostr relay for ledger updates
- One Lightning backend block (`LND_*` / `CLN_*` / `LDK_*`)
- One chain backend block (`BITCOIND_*` / `ESPLORA_URL` / `ELECTRUM_*`)

`SIGNER_PUBKEY` is populated by `init.sh` automatically.

### Talking to a local LND or CLN

The daemon needs to read either LND's macaroon + TLS cert or CLN's
`lightning-rpc` socket. Both are typically owned by the LN daemon's
user (e.g., `lnd:lnd` or `lightningd:lightning`).

**Simplest fix**: add the `deposits` user to the LN daemon's group:

```bash
sudo usermod -a -G lnd deposits        # or 'lightning' for CLN
```

Then make sure the macaroon / socket is group-readable (usually it
is by default). Restart `deposits-node` after the group change so
its supplementary groups update.

If you don't want to grant group access, copy the macaroon to a
deposits-readable path and reference that path in the env file —
just remember to update the copy after LND rotates the macaroon.

### Talking to a local bitcoind

Same pattern. Either add `deposits` to the `bitcoin` group so it can
read `/var/lib/bitcoind/.cookie` (preferred — cookie auto-rotates),
or set explicit `BITCOIND_RPC_USER` / `BITCOIND_RPC_PASS`.

## Upgrading

```bash
cd /path/to/deposits-rust/deploy/systemd
make upgrade
```

The on-disk state (`/var/lib/deposits/`, `/var/lib/dsigner/`)
survives — only the binaries are replaced. The unit files are
installed once by `init.sh`; re-run `make bootstrap` if a release
ships new unit files.

## What to back up

The only file that's not recoverable from the chain or the network is
the **operator seed**. It lives at:

```
/var/lib/dsigner/seed       # 32-byte hex, mode 0600
```

`init.sh` will print the seed on generation. Copy it to cold storage
(paper, encrypted USB, your password manager). With the seed you can
re-derive the signer and re-import every ledger from the relay.

Also worth backing up but recoverable with effort:

- `/var/lib/deposits/wallet/ledgers/*.jsonl` — the operator's ledger
  history. Replicated to your nostr relay; can be re-fetched if lost,
  but a local backup avoids the round trip after a wipe.
- `/etc/deposits/deposits-node.env` — your config. Not secret per se
  (the macaroon path is, the macaroon itself isn't).

## Admin UI access

After first start, the admin UI listens on `127.0.0.1:8765` by default.
Token: `sudo cat /var/lib/deposits/admin-token`. Open
`http://127.0.0.1:8765/` and paste the token.

For remote access, front it with caddy/nginx terminating TLS — see
[`../operator/ADMIN.md`](../operator/ADMIN.md) for the reverse-proxy
pattern. Don't expose port 8765 raw to the internet; the token is
bearer-only.

## Quorum formation

Once the daemon is healthy, see
[`../operator/QUORUM.md`](../operator/QUORUM.md) for forming a
quorum with peer operators — same `quorum form-with` /
`quorum show-identity` flow whether you're running under docker
or systemd.

## Hardening notes

Both unit files apply the systemd hardening profile pragmatic for
daemons of this shape:

- `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`,
  `PrivateTmp`, `ProtectKernel{Tunables,Modules,Logs}`,
  `ProtectControlGroups`, `RestrictNamespaces`,
  `LockPersonality`, `MemoryDenyWriteExecute`,
  `RestrictRealtime`, `RestrictSUIDSGID`,
  `SystemCallArchitectures=native`, `SystemCallFilter=@system-service`
- `CapabilityBoundingSet=` / `AmbientCapabilities=` — neither
  process needs any capabilities

The signer additionally has `PrivateDevices=true` and the
`AF_PACKET`-less `RestrictAddressFamilies`. If you don't use the
remote-signer mode (the daemon talks to the signer over a Unix
socket only), you can tighten further by setting
`RestrictAddressFamilies=AF_UNIX` on `deposits-signer.service`.

## Troubleshooting

- **`Failed to connect to signer socket`** — check `/run/dsigner/`
  exists (created by `deposits-signer.service`'s `RuntimeDirectory=`)
  and is mode 0750 owned by `dsigner:dsigner`. Verify `deposits` is in
  the `dsigner` group: `id deposits`. If you added it after the
  daemon was running, restart with `systemctl restart deposits-node`.

- **`Permission denied` reading macaroon / cookie** — add `deposits`
  to the LN/bitcoin daemon's group (see above), then restart.

- **Daemon log shows nostr relay connection errors** — check
  `RELAY_LEDGERS` is reachable from this host:
  `wscat -c wss://relay.bitcoindeposits.net`. Behind a corporate
  firewall, websockets sometimes need an HTTP proxy.

- **`SIGNER_PUBKEY` mismatch warning** — the daemon pins the signer's
  pubkey. If you regenerated the signer keypair (deleted
  `/var/lib/dsigner/transport_secret`), re-run `init.sh` to update
  the env file.
