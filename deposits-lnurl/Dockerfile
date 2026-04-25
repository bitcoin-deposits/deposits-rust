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

# Stub out other workspace members so the workspace manifest resolves
# without pulling their source trees.
COPY deposits-protocol/Cargo.toml ./deposits-protocol/Cargo.toml
COPY deposits-core/Cargo.toml     ./deposits-core/Cargo.toml
COPY deposits-node/Cargo.toml     ./deposits-node/Cargo.toml
COPY deposits-wallet/Cargo.toml   ./deposits-wallet/Cargo.toml
COPY deposits-attestation/Cargo.toml ./deposits-attestation/Cargo.toml
COPY deposits-tools/Cargo.toml    ./deposits-tools/Cargo.toml
COPY deposits-test/Cargo.toml     ./deposits-test/Cargo.toml
RUN for c in deposits-protocol deposits-core deposits-node deposits-wallet deposits-attestation deposits-tools deposits-test; do \
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
