#!/bin/bash
cd "$(dirname "$0")/.."

../target/release/status ledger-updates "$@"
