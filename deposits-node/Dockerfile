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

# Stub out deposits-tools so workspace resolves (not built)
COPY deposits-tools/Cargo.toml deposits-tools/Cargo.toml
RUN mkdir -p deposits-tools/src && echo "" > deposits-tools/src/lib.rs && \
    mkdir -p deposits-tools/src/bin && \
    for bin in deposits-admin network-init status decode-updates treasury-address \
               treasury-send standalone_reserves_demo discover replay-ledger; do \
        echo "fn main() {}" > deposits-tools/src/bin/$bin.rs; \
    done

RUN cargo build --release --bin deposits-node

# Runtime
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates liblmdb0 libflatbuffers2 libsecp256k1-1 libzstd1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/deposits-node /usr/local/bin/

COPY deposits-tools/docker/entrypoint.sh /entrypoint.sh
COPY deposits-tools/docker/strfry.conf.tmpl /etc/strfry.conf.tmpl

RUN mkdir -p /data /config

EXPOSE 7777

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
