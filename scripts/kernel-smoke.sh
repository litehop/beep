#!/usr/bin/env bash
# Boots a pinned stock Linux kernel under virtme-ng (QEMU/KVM, the runner's
# own userland shared into the guest) and runs scripts/smoke-remote.sh against
# an already-built loader inside it. Verifier acceptance and TCX/Geneve
# behaviour differ by kernel, so this is the only place the 6.6 floor is
# actually exercised.
#
# Kernels are Ubuntu mainline-PPA generic builds (the same source aya's
# integration-test xtask uses), pinned by version and sha256. They are
# distro-style kernels with virtio/9p/veth/geneve as modules, which is why the
# modules package is unpacked into the runner's /lib/modules: virtme-ng loads
# them from the shared root.
#
# Usage: scripts/kernel-smoke.sh <6.6|6.12|latest> <path-to-beep-binary>
#   Host prerequisites: sudo, qemu-system-x86, virtme-ng, /dev/kvm (rw),
#   bpftool and nc on PATH (the guest reuses the host's userland).
#   KERNEL_CACHE_DIR (default /tmp/beep-kernel-cache) holds the downloaded debs.
set -euo pipefail

BASE_URL="https://kernel.ubuntu.com/mainline"

# Bump deliberately: each entry is a full release pin, "latest" included.
kernel_pins() {
  case "$1" in
    6.6)
      VERSION=6.6.158
      BUILD=0606158.202610031241
      IMAGE_SHA256=4ede8333ddb591b98cbd67b0f808841d99293bafda4e13a1c4f220beb0d241f4
      MODULES_SHA256=23a148e72234e57fa5662c336d4c2a61baaf27f2dba77d9098e58b68eb6d25da
      ;;
    6.12)
      VERSION=6.12.112
      BUILD=0612112.202610031248
      IMAGE_SHA256=aef277f274a42ec7c983e4c815de833549914bc4c1225d25cf91c6a725abe68e
      MODULES_SHA256=3a38208d1c640bbe69c20389404f6d457d1a3d51851610d7b02d97c22ed3fc00
      ;;
    latest)
      VERSION=7.2.6
      BUILD=070206.202609141300
      IMAGE_SHA256=9d3929b017a488c8ca265ff14bb19f15217097247a709816e0875eaa7dcc4b61
      MODULES_SHA256=bf1689c1a32e9cc141575fb551cbec60d2e6d42762587aa9ce9194301469066d
      ;;
    *)
      echo "FAIL: unknown kernel '$1' (want 6.6, 6.12 or latest)" >&2
      exit 2
      ;;
  esac
  FLAVOUR="${BUILD%%.*}"
}

fetch_verified() {
  local file="$1" sha="$2"
  if ! { [ -f "$CACHE/$file" ] && echo "$sha  $CACHE/$file" | sha256sum -c --status; }; then
    curl -sSfL --retry 3 --max-time 300 -o "$CACHE/$file" "$BASE_URL/v$VERSION/amd64/$file"
  fi
  echo "$sha  $CACHE/$file" | sha256sum -c
}

guest() {
  local bin="$1"
  echo "==> guest kernel: $(uname -r)"
  # The runner ships /usr/sbin/bpftool, a linux-tools wrapper that only works
  # for the host's own kernel release; the workflow's standalone build is in
  # /usr/local/bin.
  export PATH="/usr/local/bin:$PATH"
  mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
  install -m 0755 "$bin" /tmp/beep-smoke
  bash scripts/smoke-remote.sh run
}

if [ "${1:-}" = "--guest" ]; then
  guest "$2"
  exit 0
fi

[ $# -eq 2 ] || { echo "usage: $0 <6.6|6.12|latest> <beep-binary>" >&2; exit 2; }
kernel_pins "$1"
bin="$(realpath "$2")"
CACHE="${KERNEL_CACHE_DIR:-/tmp/beep-kernel-cache}"
RELEASE="$VERSION-$FLAVOUR-generic"
IMAGE_DEB="linux-image-unsigned-${RELEASE}_$VERSION-${BUILD}_amd64.deb"
MODULES_DEB="linux-modules-${RELEASE}_$VERSION-${BUILD}_amd64.deb"

[ -f "$bin" ] || { echo "FAIL: $bin is not a file" >&2; exit 2; }
[ -w /dev/kvm ] || { echo "FAIL: /dev/kvm is not writable; this job needs KVM, TCG is too slow" >&2; exit 2; }

mkdir -p "$CACHE"
fetch_verified "$IMAGE_DEB" "$IMAGE_SHA256"
fetch_verified "$MODULES_DEB" "$MODULES_SHA256"

kdir="$(mktemp -d)"
trap 'rm -rf "$kdir"' EXIT
dpkg -x "$CACHE/$IMAGE_DEB" "$kdir"
sudo dpkg -x "$CACHE/$MODULES_DEB" /

for opt in CONFIG_BPF_SYSCALL=y CONFIG_NET_XGRESS=y CONFIG_NET_NS=y CONFIG_DEBUG_INFO_BTF=y \
  CONFIG_GENEVE=m CONFIG_VETH=m CONFIG_NET_CLS_BPF=m; do
  grep -qx "$opt" "/boot/config-$RELEASE" || { echo "FAIL: kernel $RELEASE lacks $opt" >&2; exit 1; }
done

echo "==> booting $RELEASE"
# The guest command is a plain path list (no shell metacharacters) because vng
# re-quotes --exec.
sudo vng --run "$kdir/boot/vmlinuz-$RELEASE" --user root --cpus 2 --memory 2G \
  --exec "bash $PWD/scripts/kernel-smoke.sh --guest $bin"
