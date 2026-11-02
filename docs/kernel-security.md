# Kernel security

You are responsible for keeping the host kernel patched when a fix for a beep-relevant CVE ships; beep requires Linux 6.6 or newer.

## Scope

This page lists kernel CVEs in code paths beep depends on:

- TCX attach and detach of the tc-bpf classifiers
- the BPF map types (hash, LRU hash, array, per-CPU array) and the skb, checksum, redirect and tunnel-key helpers that `ebpf/src/main.rs` uses
- tc-level Geneve tunnel handling (`bpf_skb_set_tunnel_key`, `bpf_skb_get_tunnel_key`, tunnel options)

General host-kernel CVEs outside these paths are not listed.

## Tested kernels

CI `kernel-smoke` boots pinned Ubuntu mainline builds in QEMU. The pins are exact versions in `scripts/kernel-smoke.sh`, so `latest` is a pinned release, not a moving target.

| Matrix entry | Resolves to |
| --- | --- |
| `6.6` | 6.6.161 |
| `6.12` | 6.12.115 |
| `latest` | 7.2.6 |

The unpinned Lima developer rigs run Debian 13 (Linux 6.12.x) for `beep-smoke` and Ubuntu 24.04 (distro Linux 6.8) for `beep-node-a`, `beep-node-b` and `client`. Their point releases are not pinned, so they are not a patch-level guarantee.

Run the newest point release of the 6.6 or 6.12 branch, or 7.0 or newer. That is at or above every fix in the table below. The pinned CI `kernel-smoke` kernels (6.6.161, 6.12.115, 7.2.6) carry the CVE-2026-45932 fix.

## CVEs

| CVE | beep mechanism | Impact on beep | Fixed in | Upstream commit |
| --- | --- | --- | --- | --- |
| [CVE-2026-45932](https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/45xxx/CVE-2026-45932.json) | TCX detach | `BPF_PROG_DETACH` without a prog fd on a tcx device skips the `CAP_NET_ADMIN`/`CAP_SYS_ADMIN` check. An unprivileged local user can detach beep's classifiers and stop load balancing on that node. Local vector, CVSS 3.1 7.3, not gated by `unprivileged_bpf_disabled`. Introduced with TCX (`e420bed02507`), so every 6.6+ kernel is affected until patched. | 6.6.160 ([changelog](https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.6.160)), 6.12.114 ([changelog](https://cdn.kernel.org/pub/linux/kernel/v6.x/ChangeLog-6.12.114)), 7.0 | `ae23bc81ddf7c17b663c4ed1b21e35527b0a7131` |

Distro kernels backport fixes under their own version numbers. Check your distro's advisory instead of comparing against the upstream number.

## Adding entries

A beep-relevant kernel CVE gets a row in this table and a `CHANGELOG.md` note.
