#!/bin/bash
# Generate parsers from the Kaitai Struct definition
#
# Requires: kaitai-struct-compiler (brew install kaitai-struct-compiler)
#
# Usage: ./generate.sh

set -e
cd "$(dirname "$0")"

mkdir -p generated

echo "Generating JavaScript parser..."
kaitai-struct-compiler --target javascript --outdir generated deposits_protocol.ksy

echo "Generating Python parser..."
kaitai-struct-compiler --target python --outdir generated deposits_protocol.ksy

echo "Generating Rust parser..."
kaitai-struct-compiler --target rust --outdir generated deposits_protocol.ksy

echo "Done. Generated files in generated/"
ls -la generated/
