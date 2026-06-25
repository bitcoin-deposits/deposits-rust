#!/usr/bin/env bash
# Build the explorer audit wasm module inside the clang-equipped builder image
# and emit the wasm-bindgen `--target web` glue + .wasm into the explorer.
#
# Output: deposits-web/explorer/wasm/{deposits_audit_wasm.js,*_bg.wasm}
#
# Run from the repo root. Requires Docker (for clang to compile secp256k1's C
# to wasm). The first run builds the image (compiles wasm-bindgen-cli); reruns
# reuse it and the mounted cargo registry cache.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=deposits-wasm-builder
OUT=deposits-web/explorer/wasm

docker build -t "$IMAGE" deposits-audit-wasm/

docker run --rm \
  -v "$PWD":/work -w /work \
  -v deposits-cargo-cache:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/work/target-wasm \
  "$IMAGE" bash -c "
    set -e
    # Excluded from the workspace, so build via --manifest-path (standalone).
    cargo build --release --manifest-path deposits-audit-wasm/Cargo.toml \
      --target wasm32-unknown-unknown
    wasm-bindgen --target web --no-typescript \
      --out-dir $OUT \
      target-wasm/wasm32-unknown-unknown/release/deposits_audit_wasm.wasm
    ls -la $OUT
  "
echo "wasm built into $OUT"
