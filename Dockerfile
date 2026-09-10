# syntax=docker/dockerfile:1

# beep-controller is built in CI (see .github/workflows/delivery.yaml) as a
# gnu binary for each target arch, with glibc pinned to 2.36 (Debian
# bookworm's version) via cargo-zigbuild's target-suffix syntax -- this
# image only copies the prebuilt binary matching the platform buildx is
# assembling. Since this stage has no RUN steps, buildx needs no QEMU
# emulation to "build" a foreign-arch image; it just picks the right file
# off disk.
#
# debian:bookworm-slim matches the pinned glibc 2.36 the binaries were
# linked against. No ca-certificates package is needed: beep-kubeconfig
# builds its TLS root store from the CA cert embedded in the mounted
# kubeconfig/ServiceAccount token, not the OS trust store. The DaemonSet
# grants CAP_BPF/CAP_NET_ADMIN at the pod level (deploy/daemonset.yaml).
FROM debian:bookworm-slim AS runtime

ARG TARGETARCH

COPY dist/linux/${TARGETARCH}/beep-controller /usr/local/bin/beep-controller
ENTRYPOINT ["/usr/local/bin/beep-controller"]
