#!/usr/bin/env bash
# `cargo zigbuild "$@"` with scripts/zig-shim first on PATH. The toolchain
# comes from rust-toolchain.toml (run from inside the repo).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATH="$SCRIPT_DIR/zig-shim:$PATH" exec cargo zigbuild "$@"
