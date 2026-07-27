# Umbrel community-apps package for deposits-node

The Umbrel-shaped wrap of [`deploy/operator/`](../operator/). Once the
operator deployment is in place, the app-store manifest is mostly
mechanical.

## What's in this directory

```
deploy/umbrel/
├── umbrel-app.yml      ← app-store metadata (name, version, deps, gallery, etc.)
├── docker-compose.yml  ← Umbrel-shaped compose (uses APP_BITCOIN_NODE_IP etc.)
├── icon.svg            ← the app's icon
└── README.md           ← you are here
```

The compose mirrors [`../operator/docker-compose.yml`](../operator/docker-compose.yml)
but adapted to Umbrel's conventions: services use Umbrel's injected
inter-app env vars (`APP_BITCOIN_NODE_IP`, `APP_LIGHTNING_NODE_*`,
`APP_DATA_DIR`) instead of operator-supplied `.env` values.

## How submission works

The Umbrel community app store lives at
[getumbrel/umbrel-apps](https://github.com/getumbrel/umbrel-apps).
Apps are submitted via PR — each app gets a directory at the repo root.

To submit:
1. Fork `getumbrel/umbrel-apps`.
2. Copy this directory into the fork as `deposits-node/`.
3. Add the gallery screenshots as `1.jpg` / `2.jpg` / `3.jpg` inside
   that directory (the manifest references them by these names).
4. Open a PR. Umbrel's review covers:
   - manifest schema validity (`manifestVersion: 1`, required fields)
   - the `image:` in `docker-compose.yml` references a real published
     image, not a `:latest` floating tag from a personal account
   - no port conflicts with already-installed apps
   - app behaves on a fresh Umbrel (no startup crashes, no spam)

## Status — what's blocking actual submission

We've got the manifest + compose + icon ready. Three things need to
land before a PR makes sense:

1. **Published Docker images.** The compose pins
   `ghcr.io/bitcoin-deposits/deposits-node:0.1.0`. That image needs to
   exist — currently `deposits-node:latest` is built locally per
   developer. Set up CI to publish on tag.
2. **Gallery screenshots.** Need three real screenshots: app's
   Umbrel App-Store page might use them; for now they're referenced by
   filename only and will appear broken until added.
3. **Bootstrap UX inside Umbrel.** The non-Umbrel variant uses
   `deploy/operator/init.sh` (an interactive wizard) to generate the
   signer keypair, extract the daemon transport pubkey, allowlist it,
   and write `SIGNER_PUBKEY`. Umbrel users can't run interactive
   shells against an app from the UI — we need either an `exports.sh`-
   triggered first-boot script or a "first time setup" web page.
   Until that lands, document the manual bootstrap via `docker exec`
   in this directory's README.

## Manual bootstrap on Umbrel (until proper first-boot UX lands)

After install, the app starts but the daemon refuses to come up
(no `SIGNER_PUBKEY`). Run from your Umbrel SSH:

```bash
APP=$HOME/umbrel/app-data/deposits-node

# 1. Initialize the signer (generates transport keypair + reads seed)
docker exec -it ${APP}-deposits-signer-1 \
    deposits-signer init --data-dir /var/lib/dsigner

# 2. Get the signer's pubkey
SIGNER_PK=$(docker exec ${APP}-deposits-signer-1 \
    deposits-signer pubkey --data-dir /var/lib/dsigner)

# 3. Get the daemon's transport pubkey
NODE_PK=$(docker exec ${APP}-deposits-node-1 \
    deposits-node transport-pubkey --data-dir /var/lib/deposits)

# 4. Allowlist the daemon on the signer
docker exec ${APP}-deposits-signer-1 \
    deposits-signer trust add --data-dir /var/lib/dsigner ${NODE_PK}

# 5. Inject SIGNER_PUBKEY into the app's compose and restart
sed -i "s|SIGNER_PUBKEY=.*|SIGNER_PUBKEY=${SIGNER_PK}|" \
    $HOME/umbrel/app-data/deposits-node/.env
cd $HOME/umbrel/app-data/deposits-node && docker compose up -d
```

Then form a quorum with peers per
[../operator/QUORUM.md](../operator/QUORUM.md) — same commands work,
just via `docker exec` to the daemon container instead of from the
host.

## Other appliance stores

The mechanical translation to other community-app formats (Start9
`.s9pk`, Citadel community-apps, MyNode add-ons) is left as a
per-store follow-on. Same compose, different manifest format and
review process for each. The recommendation is
Umbrel first (largest user base), then Start9 (polished UX warrants
the heavier manifest), then others as demand surfaces.
