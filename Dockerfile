# syntax=docker/dockerfile:1

# beep-controller is built in CI (see .github/workflows/delivery.yaml) as a
# statically-linked musl binary for each target arch -- this image only
# copies the prebuilt binary matching the platform buildx is assembling.
# Since this stage has no RUN steps, buildx needs no QEMU emulation to
# "build" a foreign-arch image; it just picks the right file off disk.
#
# scratch is safe here because beep-kubeconfig builds its TLS root store
# from the CA cert embedded in the mounted kubeconfig/ServiceAccount token,
# not the OS trust store -- no ca-certificates package needed. The
# DaemonSet grants CAP_BPF/CAP_NET_ADMIN at the pod level
# (deploy/daemonset.yaml), so the image only needs to carry the binary, not
# a shell or package manager.
FROM scratch AS runtime

ARG TARGETARCH

COPY dist/linux/${TARGETARCH}/beep-controller /usr/local/bin/beep-controller
ENTRYPOINT ["/usr/local/bin/beep-controller"]
