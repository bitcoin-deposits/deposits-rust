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

COPY deposits-core ./deposits-core
COPY deposits-node ./deposits-node
COPY nostr-sdk-performance ./nostr-sdk-performance
COPY Cargo.lock ./Cargo.lock

# Create a minimal workspace Cargo.toml for Docker build
# Patch native-tls to 0.2.17 to fix Rust 1.85 compatibility
# Patch nostr-relay-pool with our performance fork (skip event verification)
RUN echo '[workspace]\nmembers = ["deposits-core", "deposits-node"]\nresolver = "2"\n\n[profile.release]\ndebug = true\n\n[patch.crates-io]\nnative-tls = { git = "https://github.com/sfackler/rust-native-tls", tag = "v0.2.17" }\nnostr-relay-pool = { path = "nostr-sdk-performance/nostr-relay-pool" }' > Cargo.toml

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
