# syntax=docker/dockerfile:1

# beep-controller's build.rs cross-builds beep-ebpf for bpfel-unknown-none via
# aya-build, which needs the pinned nightly toolchain (rust-toolchain.toml)
# with rust-src, plus bpf-linker on PATH -- same requirements as CI's
# ebpf-build job. buildx runs this stage once per target platform, so each
# build is native to that platform, not cross-compiled.
FROM rust:1-slim-bookworm AS builder

ARG TARGETARCH

# curl/zstd fetch and unpack the prebuilt bpf-linker release (statically
# linked, so it runs unmodified on this glibc builder); cmake/clang/nasm/perl
# are needed to build aws-lc-sys, rustls-post-quantum's crypto backend
# (kubeconfig's TLS client).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake clang libclang-dev nasm perl \
        curl ca-certificates zstd \
    && rm -rf /var/lib/apt/lists/*

# The eBPF object is arch-neutral bpfel bytes, but bpf-linker itself is a
# native binary run by build.rs on the host doing the build -- fetch the
# release matching this stage's own platform (TARGETARCH), same binary
# CI's taiki-e/install-action step installs.
RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) bpf_linker_arch=x86_64; \
               bpf_linker_sha256=e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8 ;; \
        arm64) bpf_linker_arch=aarch64; \
               bpf_linker_sha256=341ec1c595496877cae2b073544c2226d78a922739632b5732dbaa48507f1380 ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/bpf-linker.tar.zst \
        "https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-${bpf_linker_arch}-unknown-linux-musl.tar.zst"; \
    echo "${bpf_linker_sha256}  /tmp/bpf-linker.tar.zst" | sha256sum -c -; \
    tar --zstd -xf /tmp/bpf-linker.tar.zst -C /usr/local/bin; \
    rm /tmp/bpf-linker.tar.zst; \
    chmod +x /usr/local/bin/bpf-linker

WORKDIR /src
COPY . .

# rustup ships in the rust:* images; invoking cargo from a directory
# containing rust-toolchain.toml auto-installs and switches to the pinned
# nightly (same toolchain dtolnay/rust-toolchain@nightly gives CI), so no
# separate `rustup toolchain install` step is needed.
RUN cargo build --release -p beep-controller

# Minimal runtime: the DaemonSet grants CAP_BPF/CAP_NET_ADMIN at the pod
# level (deploy/daemonset.yaml), so the image only needs to carry the binary,
# not a shell or package manager.
FROM debian:bookworm-slim AS runtime
COPY --from=builder /src/target/release/beep-controller /usr/local/bin/beep-controller
ENTRYPOINT ["/usr/local/bin/beep-controller"]
