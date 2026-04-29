# Dockerfile for deposits-node nodes
# Builds the deposits-node CLI and runs it

FROM rust:bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock

# Crates we actually build (and their in-tree deps).
COPY deposits-protocol ./deposits-protocol
COPY deposits-core ./deposits-core
COPY deposits-node ./deposits-node
COPY deposits-ringsig ./deposits-ringsig
COPY deposits-wallet ./deposits-wallet

# Workspace members we don't build still need their Cargo.toml + a
# stub source so cargo can resolve the workspace. Each stub
# replicates the [[bin]] entries from the real Cargo.toml so the
# workspace's `bin` namespace stays stable.
COPY deposits-tools/Cargo.toml deposits-tools/Cargo.toml
RUN mkdir -p deposits-tools/src deposits-tools/src/bin && \
    echo "" > deposits-tools/src/lib.rs && \
    for bin in decode-updates treasury-address treasury-send \
               discover replay-ledger; do \
        echo "fn main() {}" > deposits-tools/src/bin/$bin.rs; \
    done && \
    echo "fn main() {}" > deposits-tools/src/bin/standalone_reserves_demo.rs

COPY deposits-test/Cargo.toml deposits-test/Cargo.toml
RUN mkdir -p deposits-test/src && echo "" > deposits-test/src/lib.rs

COPY deposits-attestation/Cargo.toml deposits-attestation/Cargo.toml
RUN mkdir -p deposits-attestation/src deposits-attestation/src/bin && \
    echo "" > deposits-attestation/src/lib.rs && \
    echo "fn main() {}" > deposits-attestation/src/bin/deposits-attest.rs

COPY deposits-lnurl/Cargo.toml deposits-lnurl/Cargo.toml
RUN mkdir -p deposits-lnurl/src deposits-lnurl/src/bin && \
    echo "" > deposits-lnurl/src/lib.rs && \
    echo "fn main() {}" > deposits-lnurl/src/bin/deposits-lnurl.rs

# Build deposits-node and deposits-wallet. The two binaries live in
# different packages, so cargo needs `-p` for each. The
# `dangerous-testing` feature is a deposits-node-only feature flag
# enabling testing-only subcommands (forge-stale-cosig, etc.). DO
# NOT use this image in production.
RUN cargo build --release \
    -p deposits-node --bin deposits-node --features deposits-node/dangerous-testing \
    -p deposits-wallet --bin deposits-wallet

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries from builder
COPY --from=builder /app/target/release/deposits-node /usr/local/bin/
COPY --from=builder /app/target/release/deposits-wallet /usr/local/bin/

# Env-resolving entrypoint shared with deposits-node/Dockerfile.
# Reads NODE_SEED_FILE, ADMIN_NPUB, NETWORK, ELECTRUM_URL, LEDGER_RELAY,
# EPHEMERAL_RELAYS, NODE_NAME, RELAY_PORT, METRICS_PORT, etc. from
# the environment and translates them to deposits-node CLI flags.
# The strfry-availability check inside the entrypoint gracefully
# no-ops when strfry isn't bundled in the image.
COPY deposits-tools/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Create data directory
RUN mkdir -p /data

# Set environment defaults
ENV RUST_LOG=info,deposits_node=debug
ENV DATA_DIR=/data

# Expose no ports by default (nostr uses outbound connections)
# API port could be added later

# `node-cli.sh` invokes commands via `docker exec` (bypassing
# ENTRYPOINT), so daemon-mode entrypoint here is compatible with both
# the standalone-daemon use case (compose-driven) and the
# CLI-via-exec use case.
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
