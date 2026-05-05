# Dockerfile for deposits-lnurl
# Build from the workspace root:
#   docker build -f deposits-lnurl/Dockerfile -t deposits-lnurl .

FROM rust:slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY deposits-lnurl ./deposits-lnurl

# Per-ledger explorer page baked into the binary at compile time via
# `include_str!`. Lives outside the crate so the wallet can share the
# same vendor / TLV-catalog tree later, but the build needs it present
# at the path the source references.
COPY deposits-web ./deposits-web

# Stub out other workspace members so the workspace manifest resolves
# without pulling their source trees.
COPY deposits-protocol/Cargo.toml ./deposits-protocol/Cargo.toml
COPY deposits-core/Cargo.toml     ./deposits-core/Cargo.toml
COPY deposits-node/Cargo.toml     ./deposits-node/Cargo.toml
COPY deposits-wallet/Cargo.toml   ./deposits-wallet/Cargo.toml
COPY deposits-attestation/Cargo.toml ./deposits-attestation/Cargo.toml
COPY deposits-ringsig/Cargo.toml  ./deposits-ringsig/Cargo.toml
COPY deposits-signer-api/Cargo.toml  ./deposits-signer-api/Cargo.toml
COPY deposits-signer/Cargo.toml      ./deposits-signer/Cargo.toml
COPY deposits-tools/Cargo.toml    ./deposits-tools/Cargo.toml
COPY deposits-test/Cargo.toml     ./deposits-test/Cargo.toml
RUN for c in deposits-protocol deposits-core deposits-node deposits-wallet deposits-attestation deposits-ringsig deposits-signer-api deposits-signer deposits-tools deposits-test; do \
        mkdir -p "$c/src" && echo "" > "$c/src/lib.rs"; \
    done

RUN cargo build --release -p deposits-lnurl --bin deposits-lnurl

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/deposits-lnurl /usr/local/bin/

EXPOSE 3000

CMD ["deposits-lnurl"]
