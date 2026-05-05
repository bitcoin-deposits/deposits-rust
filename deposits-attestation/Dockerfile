# Dockerfile for deposits-attestation
# Build from the workspace root:
#   docker build -f deposits-attestation/Dockerfile -t deposits-attestation .

FROM rust:bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Workspace root + real sources for this crate AND for `deposits-ringsig`
# (a path-dep of deposits-attestation, real sources required).
COPY Cargo.toml Cargo.lock ./
COPY deposits-attestation ./deposits-attestation
COPY deposits-ringsig     ./deposits-ringsig

# Stub out other workspace members so the workspace manifest resolves
# without pulling their dependency trees.
COPY deposits-protocol/Cargo.toml ./deposits-protocol/Cargo.toml
COPY deposits-core/Cargo.toml     ./deposits-core/Cargo.toml
COPY deposits-node/Cargo.toml     ./deposits-node/Cargo.toml
COPY deposits-wallet/Cargo.toml   ./deposits-wallet/Cargo.toml
COPY deposits-lnurl/Cargo.toml    ./deposits-lnurl/Cargo.toml
COPY deposits-signer-api/Cargo.toml ./deposits-signer-api/Cargo.toml
COPY deposits-signer/Cargo.toml     ./deposits-signer/Cargo.toml
COPY deposits-tools/Cargo.toml    ./deposits-tools/Cargo.toml
COPY deposits-test/Cargo.toml     ./deposits-test/Cargo.toml
RUN for c in deposits-protocol deposits-core deposits-node deposits-wallet deposits-lnurl deposits-signer-api deposits-signer deposits-tools deposits-test; do \
        mkdir -p "$c/src" && echo "" > "$c/src/lib.rs"; \
    done && \
    mkdir -p deposits-node/src/bin deposits-wallet/src/bin deposits-tools/src/bin && \
    for bin in deposits-node deposits-wallet htlc-agent; do \
        echo "fn main() {}" > "deposits-node/src/bin/${bin}.rs" 2>/dev/null || true; \
    done && \
    echo "fn main() {}" > deposits-wallet/src/bin/deposits-wallet.rs 2>/dev/null || true

RUN cargo build --release -p deposits-attestation --bin deposits-attest

FROM debian:bookworm-slim

# python3 is for the bundled lnurl-server.py (NIP-05 / LNURL-pay test
# fixture). coreutils provides `od` used in the entrypoint to hex-encode
# the LDK API key.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates python3 coreutils && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/deposits-attest /usr/local/bin/
COPY deposits-attestation/docker/lnurl-server.py             /app/lnurl-server.py
COPY deposits-attestation/docker/lnaddr-attest-entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV RUST_LOG=info
ENTRYPOINT ["/bin/sh", "/app/entrypoint.sh"]
