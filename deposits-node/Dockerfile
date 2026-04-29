# Builder stage — native musl via rust:alpine so the final binary can
# run alongside strfry (also musl) in a single Alpine runtime image.
FROM rust:alpine AS builder

# musl-dev + gcc for crates with build.rs / C shims (bitcoin, secp256k1,
# jemalloc). openssl-dev + openssl-libs-static for any native-tls
# consumers that don't swap to rustls. perl + make for openssl's build.
# linux-headers for jemalloc's configure step.
RUN apk add --no-cache \
    musl-dev gcc g++ make perl pkgconfig linux-headers \
    openssl-dev openssl-libs-static

WORKDIR /build

COPY Cargo.toml ./

# Crates we actually build (and their in-tree deps).
COPY deposits-protocol/ deposits-protocol/
COPY deposits-core/ deposits-core/
COPY deposits-node/ deposits-node/
COPY deposits-ringsig/ deposits-ringsig/
COPY deposits-wallet/ deposits-wallet/

# Workspace members we don't build still need their Cargo.toml + a
# stub source so cargo can resolve the workspace.
COPY deposits-tools/Cargo.toml deposits-tools/Cargo.toml
RUN mkdir -p deposits-tools/src deposits-tools/src/bin && \
    echo "" > deposits-tools/src/lib.rs && \
    for bin in decode-updates treasury-address treasury-send \
               discover replay-ledger; do \
        echo "fn main() {}" > deposits-tools/src/bin/$bin.rs; \
    done && \
    echo "fn main() {}" > deposits-tools/src/bin/standalone_reserves_demo.rs

COPY deposits-test/Cargo.toml deposits-test/Cargo.toml
RUN mkdir -p deposits-test/src && echo "" > deposits-test/src/lib.rs

COPY deposits-attestation/Cargo.toml deposits-attestation/Cargo.toml
RUN mkdir -p deposits-attestation/src deposits-attestation/src/bin && \
    echo "" > deposits-attestation/src/lib.rs && \
    echo "fn main() {}" > deposits-attestation/src/bin/deposits-attest.rs

COPY deposits-lnurl/Cargo.toml deposits-lnurl/Cargo.toml
RUN mkdir -p deposits-lnurl/src deposits-lnurl/src/bin && \
    echo "" > deposits-lnurl/src/lib.rs && \
    echo "fn main() {}" > deposits-lnurl/src/bin/deposits-lnurl.rs

# native-tls (pulled in transitively) wants system openssl; point it at
# Alpine's static libs so the final binary has no runtime .so dependencies
# beyond libc/libgcc.
ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR=/usr/lib \
    OPENSSL_INCLUDE_DIR=/usr/include

RUN cargo build --release \
    -p deposits-node --bin deposits-node \
    -p deposits-wallet --bin deposits-wallet

# Runtime — use the pluja/strfry image as the base so the bundled strfry
# binary runs natively (it's musl-linked and expects Alpine libs).
# deposits-node is now also musl, so no cross-libc weirdness.
FROM docker.io/pluja/strfry:latest

RUN apk add --no-cache ca-certificates libgcc

COPY --from=builder /build/target/release/deposits-node /usr/local/bin/
COPY --from=builder /build/target/release/deposits-wallet /usr/local/bin/

# strfry ships at /app/strfry — expose it on PATH for the entrypoint.
RUN ln -s /app/strfry /usr/local/bin/strfry

COPY deposits-tools/docker/entrypoint.sh /entrypoint.sh
COPY deposits-tools/docker/strfry.conf.tmpl /etc/strfry.conf.tmpl

RUN mkdir -p /data /config

EXPOSE 7777 9100

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
