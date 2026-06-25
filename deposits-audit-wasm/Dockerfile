# Builder image for the explorer audit wasm module.
#
# secp256k1-sys (pulled transitively via bitcoin) compiles vendored C to wasm,
# which requires clang — hence this dedicated image rather than the host
# toolchain. wasm-bindgen-cli is pinned to the wasm-bindgen crate version.
FROM rust:bookworm

RUN apt-get update && apt-get install -y --no-install-recommends clang \
    && rm -rf /var/lib/apt/lists/*
RUN rustup target add wasm32-unknown-unknown
RUN cargo install wasm-bindgen-cli --version 0.2.114 --locked
