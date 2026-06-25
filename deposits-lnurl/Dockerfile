# Dockerfile for deposits-lnurl
# Build from the workspace root:
#   docker build -f deposits-lnurl/Dockerfile -t deposits-lnurl .

FROM rust:slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
# Vendored miniscript fork — referenced by `[patch.crates-io]` in
# the workspace Cargo.toml.
COPY third_party ./third_party
COPY deposits-lnurl ./deposits-lnurl
# deposits-nostr is a real path-dep of deposits-lnurl
# (`install_default_crypto_provider` + transport types).
COPY deposits-nostr ./deposits-nostr
# deposits-protocol is a real path-dep of deposits-nostr.
COPY deposits-protocol ./deposits-protocol

# NOTE: deposits-web is NOT pulled into the builder. The binary loads
# its HTML/JS assets at runtime from $DEPOSITS_WEB_DIR (set in the
# final stage), which means HTML edits do not invalidate this build
# layer.

# Stub out other workspace members so the workspace manifest resolves
# without pulling their source trees.
COPY deposits-core/Cargo.toml     ./deposits-core/Cargo.toml
COPY deposits-node/Cargo.toml     ./deposits-node/Cargo.toml
COPY deposits-wallet/Cargo.toml   ./deposits-wallet/Cargo.toml
COPY deposits-attestation/Cargo.toml ./deposits-attestation/Cargo.toml
COPY deposits-ringsig/Cargo.toml  ./deposits-ringsig/Cargo.toml
COPY deposits-signer-api/Cargo.toml  ./deposits-signer-api/Cargo.toml
COPY deposits-signer/Cargo.toml      ./deposits-signer/Cargo.toml
COPY deposits-tools/Cargo.toml    ./deposits-tools/Cargo.toml
COPY deposits-test/Cargo.toml     ./deposits-test/Cargo.toml
# deposits-node depends on deposits-hub-proto; deposits-hub is a member too.
COPY deposits-hub-proto/Cargo.toml ./deposits-hub-proto/Cargo.toml
COPY deposits-hub/Cargo.toml       ./deposits-hub/Cargo.toml
RUN for c in deposits-core deposits-node deposits-wallet deposits-attestation deposits-ringsig deposits-signer-api deposits-signer deposits-tools deposits-test deposits-hub-proto deposits-hub; do \
        mkdir -p "$c/src" && echo "" > "$c/src/lib.rs"; \
    done && \
    echo "fn main() {}" > deposits-hub/src/main.rs

RUN cargo build --release -p deposits-lnurl --bin deposits-lnurl

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/deposits-lnurl /usr/local/bin/

# Static UI assets served alongside the LNURL endpoints. Loaded once
# at startup; serving paths match the on-disk layout under wallet/
# and explorer/. Editing HTML/JS only invalidates this layer (and any
# downstream), not the cargo build.
COPY deposits-web /usr/share/deposits-web
ENV DEPOSITS_WEB_DIR=/usr/share/deposits-web

EXPOSE 3000

CMD ["deposits-lnurl"]
