#!/bin/bash
cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
PROJECT_DIR="$(cd ".." && pwd)"
WORKSPACE_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
"$WORKSPACE_DIR/target/release/status" ledger-updates "$@"
