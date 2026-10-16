#!/usr/bin/env bash
# deploy/patches/client-cert-kubeconfig.yaml removes the `serviceaccount`
# volume and mount by index. If daemonset.yaml stops keeping them last, the
# patch's test ops fail (or, without them, delete bpffs); catch it here first.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DS="$SCRIPT_DIR/../deploy/daemonset.yaml"

# Names of the entries directly under the pod-level `volumes:` list.
pod_volumes() {
  awk '/^      volumes:/ {on=1; next} on && /^      [^ #]/ {on=0}
       on && /^        - name: / {print $3}' "$1"
}
# Names of the entries under the (last) container's `volumeMounts:`.
controller_mounts() {
  awk '/^      containers:/ {c=1}
       c && /^          volumeMounts:/ {on=1; n=0; next}
       on && /^          [^ #-]/ {on=0}
       on && /^      [^ ]/ {on=0}
       on && /^            - name: / {print $3}' "$1"
}

fail=0
check_last() { # <what> <want> <names...>
  local what=$1 want=$2 last
  shift 2
  last=${*: -1}
  if [ "$last" = "$want" ]; then
    echo "PASS: $what"
  else
    echo "FAIL: $what: last is '$last', not '$want'; the client-cert patch would remove the wrong entry" >&2
    fail=1
  fi
}

# shellcheck disable=SC2046
check_last "serviceaccount is the last pod volume" serviceaccount $(pod_volumes "$DS")
# shellcheck disable=SC2046
check_last "serviceaccount is the last controller mount" serviceaccount $(controller_mounts "$DS")

# The checker itself must catch an appended volume.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
{ cat "$DS"; printf '        - name: extra\n          emptyDir: {}\n'; } >"$TMP/appended.yaml"
if [ "$(pod_volumes "$TMP/appended.yaml" | tail -n1)" = extra ]; then
  echo "PASS: checker sees a volume appended after serviceaccount"
else
  echo "FAIL: checker missed a volume appended after serviceaccount" >&2
  fail=1
fi

# Indices the patch hardcodes must match the manifest.
[ "$(pod_volumes "$DS" | sed -n 3p)" = serviceaccount ] || { echo "FAIL: volumes/2 is not serviceaccount" >&2; fail=1; }
[ "$(controller_mounts "$DS" | sed -n 2p)" = serviceaccount ] || { echo "FAIL: volumeMounts/1 is not serviceaccount" >&2; fail=1; }

exit "$fail"
