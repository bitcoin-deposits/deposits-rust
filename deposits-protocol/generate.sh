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

# Fix Rust keyword conflict: 'type' is reserved
echo "Fixing Rust keyword conflicts..."
sed -i '' '
  s/fn type(/fn record_type(/g
  s/self_rc\.type\./self_rc.record_type./g
  s/self\.type\./self.record_type./g
  s/type: RefCell/record_type: RefCell/g
' generated/deposits_protocol.rs

# Fix varint type mismatch (u8/u16/u32/u64 branches need explicit casts)
sed -i '' 's/\*self\.value_4() } else { if \*self\.first_byte() == 253 { \*self\.value_2() } else { \*self\.first_byte() } } }) as u64/*self.value_4() as u64 } else if *self.first_byte() == 253 { *self.value_2() as u64 } else { *self.first_byte() as u64 } }/' generated/deposits_protocol.rs

# Fix over-replacement of message_type
sed -i '' 's/message_record_type/message_type/g' generated/deposits_protocol.rs

echo "Verifying Rust compilation..."
cd ..
cargo check --package deposits-protocol --features kaitai-parser 2>&1 | tail -1

echo "Done. Generated files:"
ls -la deposits-protocol/generated/
