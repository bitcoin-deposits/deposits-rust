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
COPY deposits-signer-api/ deposits-signer-api/
COPY deposits-signer/ deposits-signer/
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

# Build args:
#   FEATURES — extra cargo features. Pass `dangerous-testing` to enable
#              the testing-only `forge-stale-cosig`, `fork-update`, etc.
#              commands. WARNING: never enable this for a mainnet image.
#                docker build --build-arg FEATURES=dangerous-testing ...
#
# The `--features` flag is wired against `deposits-node/...`; passing
# an empty string is a valid no-op so the default build is feature-free.
ARG FEATURES=""
RUN cargo build --release \
    -p deposits-node --bin deposits-node \
    -p deposits-wallet --bin deposits-wallet \
    -p deposits-signer --bin deposits-signer \
    $(test -n "$FEATURES" && echo "--features deposits-node/$FEATURES")

# Stub for glibc's `__res_init`. gcompat 1.1.0 (Alpine 3.18, what
# pluja/strfry:latest pins to) references the symbol as UND but doesn't
# define it, so glibc binaries we pull in (ldk-server-cli) fail to
# relocate. The function returns 0 on success and is a no-op for our
# call paths — DNS resolution actually goes through musl's
# getaddrinfo, which doesn't read glibc's resolver state. Drop this
# stub when the strfry base moves to gcompat ≥1.1.1.
RUN echo 'int __res_init(void) { return 0; }' > /tmp/res_init_stub.c && \
    gcc -shared -fPIC -Wl,-soname,libres_init_stub.so \
        -o /tmp/libres_init_stub.so /tmp/res_init_stub.c

# Runtime — use the pluja/strfry image as the base so the bundled strfry
# binary runs natively (it's musl-linked and expects Alpine libs).
# deposits-node is now also musl, so no cross-libc weirdness.
FROM docker.io/pluja/strfry:latest

# gcompat: glibc-compat shim for /ldk/ldk-server-cli, which is shipped
# glibc-built (matches the lightning sidecar's runtime). Without it the
# binary fails to load on this Alpine/musl base with "Error relocating:
# __res_init: symbol not found" and similar glibc-only symbols.
#
# gcompat 1.1.0 (Alpine 3.18) ships only libgcompat.so.0 + libresolv.so.2
# and doesn't create the `libc.so.6`/`libm.so.6` aliases that loaders
# look up by name. Without them ldd shows `libc.so.6 => ld-linux.so.2`
# (the stub loader) and __res_init / gnu_get_libc_version don't
# resolve. gcompat ≥1.1.1 creates these symlinks itself; until the
# strfry base updates, do it here.
RUN apk add --no-cache ca-certificates libgcc gcompat && \
    ln -sf /lib/libgcompat.so.0 /lib/libc.so.6 && \
    ln -sf /lib/libgcompat.so.0 /lib/libm.so.6 && \
    ln -sf /lib/libgcompat.so.0 /usr/lib/libc.so.6 && \
    ln -sf /lib/libgcompat.so.0 /usr/lib/libm.so.6

COPY --from=builder /build/target/release/deposits-node /usr/local/bin/
COPY --from=builder /build/target/release/deposits-wallet /usr/local/bin/
COPY --from=builder /build/target/release/deposits-signer /usr/local/bin/
COPY --from=builder /tmp/libres_init_stub.so /lib/libres_init_stub.so

# strfry ships at /app/strfry — expose it on PATH for the entrypoint.
RUN ln -s /app/strfry /usr/local/bin/strfry

COPY deposits-tools/docker/entrypoint.sh /entrypoint.sh
COPY deposits-tools/docker/strfry.conf.tmpl /etc/strfry.conf.tmpl

# LDK CLI wrapper — translates the deposit-node's named-flag style to
# the real ldk-server-cli's positional args and adds self-pay support
# when multiple operators share one LDK node. Activated by mounting the
# `lightning` container's volumes — see docker-compose.nodes.yml.
COPY deposits-tools/bin/ldk-cli-wrapper.sh /app/ldk-cli-wrapper.sh
RUN chmod +x /app/ldk-cli-wrapper.sh

# python3 + bash for the wrapper's BOLT11 parsing + flock + jsonl
# bookkeeping. The strfry base is alpine so we add them here rather
# than relying on the host.
RUN apk add --no-cache bash python3

RUN mkdir -p /data /config

EXPOSE 7777 9100

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
