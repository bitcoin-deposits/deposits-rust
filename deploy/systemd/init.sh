#!/bin/bash
# deposits-node systemd bootstrap.
#
# Idempotent. Run as root after `cargo build --release` and copying the
# binaries into /usr/local/bin/. Creates the users + dirs, seeds the
# signer, writes /etc/deposits/deposits-node.env (mode 0640), and
# allowlists the daemon's transport pubkey on the signer.
#
# Doesn't enable or start the services — that's the operator's call,
# typically `systemctl enable --now deposits-signer deposits-node`
# after they've edited the env file for their setup.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NODE_BIN="${NODE_BIN:-/usr/local/bin/deposits-node}"
SIGNER_BIN="${SIGNER_BIN:-/usr/local/bin/deposits-signer}"
ENV_FILE="${ENV_FILE:-/etc/deposits/deposits-node.env}"
NODE_DATA_DIR="${NODE_DATA_DIR:-/var/lib/deposits}"
SIGNER_DATA_DIR="${SIGNER_DATA_DIR:-/var/lib/dsigner}"
NODE_USER="${NODE_USER:-deposits}"
SIGNER_USER="${SIGNER_USER:-dsigner}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

ok()      { echo -e "  ${GREEN}✓${RESET} $*"; }
warn()    { echo -e "  ${YELLOW}!${RESET} $*"; }
err()     { echo -e "  ${RED}✗${RESET} $*" >&2; }
heading() { echo; echo -e "${BOLD}== $* ==${RESET}"; }

if [ "$(id -u)" -ne 0 ]; then
    err "init.sh must run as root (creates users, writes /etc files)."
    exit 1
fi

# --- 1. Preflight: binaries present? --------------------------------------

heading "Preflight"

[ -x "$NODE_BIN" ] || { err "Missing $NODE_BIN — build with 'cargo build --release -p deposits-node' and copy target/release/deposits-node to $NODE_BIN"; exit 1; }
[ -x "$SIGNER_BIN" ] || { err "Missing $SIGNER_BIN — build with 'cargo build --release -p deposits-signer' and copy target/release/deposits-signer to $SIGNER_BIN"; exit 1; }
ok "Binaries present: $NODE_BIN, $SIGNER_BIN"

# --- 2. Users + groups ----------------------------------------------------

heading "Step 1/5: Users + groups"

if ! id -u "$SIGNER_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SIGNER_USER"
    ok "Created system user '$SIGNER_USER'"
else
    ok "User '$SIGNER_USER' already exists"
fi

if ! id -u "$NODE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$NODE_USER"
    ok "Created system user '$NODE_USER'"
else
    ok "User '$NODE_USER' already exists"
fi

# The daemon talks to the signer over a Unix socket under /run/dsigner/,
# which deposits-signer.service creates with mode 0750 owned by
# dsigner:dsigner. Add the deposits user to the dsigner group so the
# socket is reachable.
if ! id -nG "$NODE_USER" | grep -qw "$SIGNER_USER"; then
    usermod -a -G "$SIGNER_USER" "$NODE_USER"
    ok "Added '$NODE_USER' to group '$SIGNER_USER' (for signer socket access)"
else
    ok "'$NODE_USER' already in group '$SIGNER_USER'"
fi

# --- 3. Data dirs ---------------------------------------------------------

heading "Step 2/5: Data directories"

install -d -m 0700 -o "$SIGNER_USER" -g "$SIGNER_USER" "$SIGNER_DATA_DIR"
ok "$SIGNER_DATA_DIR ($SIGNER_USER:$SIGNER_USER, 0700)"

install -d -m 0750 -o "$NODE_USER" -g "$NODE_USER" "$NODE_DATA_DIR"
ok "$NODE_DATA_DIR ($NODE_USER:$NODE_USER, 0750)"

install -d -m 0755 -o root -g root /etc/deposits
ok "/etc/deposits (root:root, 0755)"

# --- 4. Env file ----------------------------------------------------------

heading "Step 3/5: Env file"

if [ ! -f "$ENV_FILE" ]; then
    install -m 0640 -o root -g "$NODE_USER" "$SCRIPT_DIR/deposits-node.env.example" "$ENV_FILE"
    ok "Copied env.example to $ENV_FILE (root:$NODE_USER, 0640)"
    warn "Edit $ENV_FILE before starting the daemon — at minimum:"
    echo "    NETWORK / OPERATOR_NAME / RELAY_LEDGERS / chain + LN backend creds"
else
    ok "Env file already at $ENV_FILE (left in place)"
fi

# --- 5. Seed + signer bootstrap -------------------------------------------

heading "Step 4/5: Operator seed + signer bootstrap"

if [ -f "$SIGNER_DATA_DIR/transport_secret" ]; then
    ok "Signer already initialized at $SIGNER_DATA_DIR (skipping seed dance)"
else
    seed_file_path="$SIGNER_DATA_DIR/seed"
    echo
    echo "  Operator seed source:"
    echo "    1) generate a new one (will print once — back it up immediately)"
    echo "    2) import from a file you control"
    read -rp "  choice [1/2]: " choice
    # Portable hex-encode of /dev/urandom — xxd ships in vim-common
    # which isn't on debian-slim by default. od is in coreutils and
    # is guaranteed present on every linux distro.
    hex_random() {
        od -An -vtx1 -N32 /dev/urandom | tr -d ' \n'
    }
    case "$choice" in
        1|"")
            hex_random > "$seed_file_path"
            chmod 0600 "$seed_file_path"
            chown "$SIGNER_USER:$SIGNER_USER" "$seed_file_path"
            ok "Generated 32-byte seed at $seed_file_path"
            warn "BACK THIS UP NOW. There is no recovery if you lose it."
            echo "    ${BOLD}Seed (hex):${RESET} $(cat "$seed_file_path")"
            echo
            ;;
        2)
            read -rp "  Path to existing 32-byte hex seed file: " src
            [ -f "$src" ] || { err "Not a file: $src"; exit 1; }
            install -m 0600 -o "$SIGNER_USER" -g "$SIGNER_USER" "$src" "$seed_file_path"
            ok "Imported seed to $seed_file_path"
            ;;
        *)
            err "Invalid choice: $choice"
            exit 1
            ;;
    esac

    echo "  Running deposits-signer init..."
    sudo -u "$SIGNER_USER" "$SIGNER_BIN" init \
        --data-dir "$SIGNER_DATA_DIR" \
        --seed-file "$seed_file_path" >/dev/null
    rm -f "$seed_file_path"
    ok "Signer initialized; seed material lives only in $SIGNER_DATA_DIR/seed"
fi

signer_pubkey=$(sudo -u "$SIGNER_USER" "$SIGNER_BIN" pubkey --data-dir "$SIGNER_DATA_DIR" | tr -d '\n')
ok "Signer transport pubkey: ${BOLD}$signer_pubkey${RESET}"

# Write SIGNER_PUBKEY back to the env file. Idempotent.
if grep -q '^SIGNER_PUBKEY=' "$ENV_FILE"; then
    sed -i "s|^SIGNER_PUBKEY=.*|SIGNER_PUBKEY=$signer_pubkey|" "$ENV_FILE"
else
    echo "SIGNER_PUBKEY=$signer_pubkey" >> "$ENV_FILE"
fi
ok "Wrote SIGNER_PUBKEY to $ENV_FILE"

# --- 6. Daemon allowlist on signer ----------------------------------------

heading "Step 5/5: Allowlist daemon on signer"

node_pubkey=$(sudo -u "$NODE_USER" "$NODE_BIN" transport-pubkey --data-dir "$NODE_DATA_DIR" | tr -d '\n')
ok "Daemon transport pubkey: ${BOLD}$node_pubkey${RESET}"
sudo -u "$SIGNER_USER" "$SIGNER_BIN" trust add --data-dir "$SIGNER_DATA_DIR" "$node_pubkey" >/dev/null 2>&1 || true
ok "Daemon allowlisted on signer"

# --- 7. Install unit files + wrapper --------------------------------------

heading "Install unit files"

install -m 0755 "$SCRIPT_DIR/deposits-node-wrapped.sh" /usr/local/bin/deposits-node-wrapped
ok "Installed wrapper at /usr/local/bin/deposits-node-wrapped"

install -m 0644 "$SCRIPT_DIR/deposits-signer.service" /etc/systemd/system/deposits-signer.service
install -m 0644 "$SCRIPT_DIR/deposits-node.service"   /etc/systemd/system/deposits-node.service
ok "Unit files installed at /etc/systemd/system/"
# systemctl daemon-reload only works when systemd is PID 1. In a
# container or chroot, gracefully skip and let the operator run it
# after they reboot into a real init.
if systemctl daemon-reload 2>/dev/null; then
    ok "systemd reloaded"
else
    warn "systemctl daemon-reload skipped (no running systemd — run after reboot)"
fi

# --- done -----------------------------------------------------------------

echo
echo "${BOLD}${GREEN}deposits-node bootstrap complete.${RESET}"
echo
echo "  1. Review $ENV_FILE (network + relays + backend creds)"
echo "  2. systemctl enable --now deposits-signer deposits-node"
echo "  3. Watch logs: journalctl -u deposits-node -u deposits-signer -f"
echo "  4. Admin UI token: cat $NODE_DATA_DIR/admin-token  (after first start)"
echo
