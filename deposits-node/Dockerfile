FROM rust:slim-bookworm AS node-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy workspace Cargo.toml and strip the [patch] section (references a local
# path that doesn't exist in the Docker build context)
COPY Cargo.toml ./
RUN sed -i '/\[patch.crates-io\]/,$ d' Cargo.toml

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

# Build strfry
FROM debian:bookworm AS relay-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git g++ make pkg-config libtool autoconf \
    libssl-dev zlib1g-dev liblmdb-dev libflatbuffers-dev \
    libsecp256k1-dev libzstd-dev && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/hoytech/strfry.git /strfry && \
    cd /strfry && \
    git submodule update --init && \
    make setup-golpe && \
    make -j$(nproc)

# Runtime
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates liblmdb0 libflatbuffers2 libsecp256k1-1 libzstd1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=node-builder /build/target/release/deposits-node /usr/local/bin/
COPY --from=relay-builder /strfry/strfry /usr/local/bin/

COPY deposits-node/docker/entrypoint.sh /entrypoint.sh
COPY deposits-node/docker/strfry.conf.tmpl /etc/strfry.conf.tmpl

RUN mkdir -p /data /config

EXPOSE 7777

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
