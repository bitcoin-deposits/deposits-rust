# Dockerfile for deposits-bdk nodes
# Builds the deposits-bdk CLI and runs it

FROM rust:1.85-bookworm AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy only what deposits-bdk needs (exclude deposits-ldk which requires rust-lightning)
COPY deposits-rust/deposits-core ./deposits-core
COPY deposits-rust/deposits-bdk ./deposits-bdk

# Create a minimal workspace Cargo.toml for Docker build
RUN echo '[workspace]\nmembers = ["deposits-core", "deposits-bdk"]\nresolver = "2"' > Cargo.toml

# Build deposits-bdk with dangerous-testing for test environments
# WARNING: Do not use this image in production
RUN cargo build --release -p deposits-bdk --bin deposits-bdk --features dangerous-testing

# Runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/deposits-bdk /usr/local/bin/

# Create data directory
RUN mkdir -p /data

# Set environment defaults
ENV RUST_LOG=info,deposits_bdk=debug
ENV DATA_DIR=/data

# Expose no ports by default (nostr uses outbound connections)
# API port could be added later

ENTRYPOINT ["/usr/local/bin/deposits-bdk"]
CMD ["run", "--data-dir", "/data"]
