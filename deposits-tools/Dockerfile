# Dockerfile for deposits-node nodes
# Builds the deposits-node CLI and runs it

FROM rust:1.85-bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

COPY deposits-protocol ./deposits-protocol
COPY deposits-core ./deposits-core
COPY deposits-node ./deposits-node
COPY Cargo.toml ./Cargo.toml
COPY Cargo.lock ./Cargo.lock

# Stub out deposits-tools so workspace resolves (not built)
COPY deposits-tools/Cargo.toml deposits-tools/Cargo.toml
RUN mkdir -p deposits-tools/src && echo "" > deposits-tools/src/lib.rs && \
    mkdir -p deposits-tools/src/bin && \
    for bin in decode-updates treasury-address \
               treasury-send standalone_reserves_demo discover replay-ledger; do \
        echo "fn main() {}" > deposits-tools/src/bin/$bin.rs; \
    done

# Build deposits-node and deposits-wallet with dangerous-testing for test environments
# WARNING: Do not use this image in production
RUN cargo build --release -p deposits-node --bin deposits-node --bin deposits-wallet --features dangerous-testing

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

# Create data directory
RUN mkdir -p /data

# Set environment defaults
ENV RUST_LOG=info,deposits_node=debug
ENV DATA_DIR=/data

# Expose no ports by default (nostr uses outbound connections)
# API port could be added later

ENTRYPOINT ["/usr/local/bin/deposits-node"]
CMD ["run", "--data-dir", "/data"]
