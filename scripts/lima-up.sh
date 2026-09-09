#!/usr/bin/env bash
# Bring up (or resume) the Lima VM used by scripts/smoke.sh and
# scripts/smoke-wg-2node.sh.
#
# Usage: scripts/lima-up.sh [vm-name]   (default: beep-smoke)
set -euo pipefail

VM_NAME="${1:-beep-smoke}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIMA_YAML="$SCRIPT_DIR/../lima/beep.yaml"

if [ -d "${HOME}/.lima/${VM_NAME}" ]; then
  echo "VM '$VM_NAME' already provisioned, starting (idempotent if already running)..."
  limactl start "$VM_NAME"
else
  echo "Provisioning VM '$VM_NAME' (first run)..."
  limactl start --tty=false --name="$VM_NAME" "$LIMA_YAML"
fi
