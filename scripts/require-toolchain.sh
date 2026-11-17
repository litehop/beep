#!/usr/bin/env bash
# Fails unless the channel pinned in rust-toolchain.toml is installed. A
# floating `nightly` does not satisfy it: aya-build and the loader must build
# with the pinned toolchain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$SCRIPT_DIR/../rust-toolchain.toml")"
[[ -n "$channel" ]] || { echo "FAIL: no channel in rust-toolchain.toml" >&2; exit 1; }

rustup toolchain list 2>/dev/null | grep -q "^${channel}-" || {
  echo "FAIL: toolchain $channel not installed (run 'rustup show' in the repo to install it from rust-toolchain.toml)" >&2
  exit 1
}
