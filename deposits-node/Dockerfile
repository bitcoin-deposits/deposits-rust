FROM rust:slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev gcc libc6-dev make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml ./

# Copy crates
COPY deposits-protocol/ deposits-protocol/
COPY deposits-core/ deposits-core/
COPY deposits-node/ deposits-node/

# Stub out deposits-tools + tests so the workspace resolves without
# pulling in their sources (they're not built in this image).
COPY deposits-tools/Cargo.toml deposits-tools/Cargo.toml
RUN mkdir -p deposits-tools/src && echo "" > deposits-tools/src/lib.rs && \
    mkdir -p deposits-tools/src/bin && \
    for bin in decode-updates treasury-address \
               treasury-send standalone_reserves_demo discover replay-ledger deposits-lnurl; do \
        echo "fn main() {}" > deposits-tools/src/bin/$bin.rs; \
    done

COPY tests/Cargo.toml tests/Cargo.toml
RUN mkdir -p tests/src && echo "" > tests/src/lib.rs

RUN cargo build --release --bin deposits-node --bin deposits-wallet

# Runtime — Debian slim. Operators point `LEDGER_RELAY` at an external
# strfry (or another Nostr relay) they run alongside. Bundling strfry in
# the same image requires matching libc across strfry (Alpine/musl) and
# the deposits-node binary (Debian/glibc), which is more pain than it's
# worth for a testing/bootstrap tool.
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates libsecp256k1-1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/deposits-node /usr/local/bin/
COPY --from=builder /build/target/release/deposits-wallet /usr/local/bin/

COPY deposits-tools/docker/entrypoint.sh /entrypoint.sh
COPY deposits-tools/docker/strfry.conf.tmpl /etc/strfry.conf.tmpl

RUN mkdir -p /data /config

EXPOSE 7777 9100

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
