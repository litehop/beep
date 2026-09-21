# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-09-21

### Added

- Dual-stack (IPv4 + IPv6) inner services: Service VIPs, backends, and
  clients can now be IPv6 alongside existing IPv4 ones, with the real
  client source address preserved across a genuine cross-node hop (#116,
  #118, #119). This is **inner** dual-stack only — v4/v6 service, client,
  and backend addresses — carried over an **IPv4 Geneve outer/transport**.
  The IPv6 underlay is not yet supported; see Known Limitations.

### Fixed

- The Geneve return leg's client-bound redirect carried the L3 underlay's
  all-zero L2 header. Redirecting that packet onto a real Ethernet egress
  interface got it classified `PACKET_OTHERHOST` and dropped by the kernel.
  `try_geneve_decap_return` now synthesizes a valid L2 header when the
  return leg's uplink is Ethernet, fixing round trips where a bare-metal/
  Ethernet client-ingress node forwards to a WireGuard backend uplink
  (#121).

### Verified on Lima VMs

| Rig | Nodes | Client | Transport | Client-egress L2 | Family | Proves |
| --- | --- | --- | --- | --- | --- | --- |
| `smoke.sh` (+ CI memory-smoke) | 1 | co-located netns | local veth | Ethernet | v4 | verifier-accept, encap/decap round trip, multi-port Service, flow preservation across restart, anti-flush, in-kernel NODE_ALLOW drop |
| `smoke-wg-2node.sh --family 4` | 2 + foreign client VM | foreign | WireGuard `wg0` | tunnel (ipip) | v4 | cross-node round trip, `wg0` traversal |
| `smoke-wg-2node-dualstack.sh` (#119) | 2 | co-located netns | WireGuard `wg0` | tunnel (ipip/ip6tnl) | v4+v6 inner | concurrent v4+v6 round trips, client-IP preservation, genuine cross-node |
| `smoke-eth-ingress-2node.sh` | 2 + foreign client VM | foreign | WireGuard `wg0` | Ethernet (`eth0`) | v4 | Ethernet ingress + wg transport, symmetric return |
| `smoke-wg-2node-ethclient.sh` (#121) | 2 | co-located netns | WireGuard `wg0` | Ethernet (veth) | v4 | return-leg L2 synthesis on real Ethernet egress |

Every cross-node rig above tunnels Geneve over a real `wg0` WireGuard link;
none of them exercise a WireGuard-free cross-node path. The
`smoke-wg-2node-ethclient.sh` rig proving the #121 fix runs v4 only by
design — the bug it targets is family-agnostic, so one family is sufficient
to prove the redirect path.

### Known Limitations / Not Yet Verified

- IPv6 Geneve outer/underlay is incomplete: `geneve_ingress`'s NODE_ALLOW
  peer attestation reads `bpf_tunnel_key`'s `remote_ipv4` only, so the
  dual-stack support above is inner-only, over an IPv4 transport.
- No WireGuard-free cross-node transport has been verified; every
  cross-node rig above tunnels Geneve over `wg0`.
- All verification runs on Lima VMs, not real cloud or bare-metal hardware.
- Only a single backend Pod per node has been exercised; multi-Pod load
  balancing is not yet load-tested.
- Only a single uplink interface is exercised per node in any given rig.

## [0.2.0]

### Added

- Multi-symmetric-uplink: `--uplink-iface` is now repeatable. Each
  configured uplink gets its own L2 header and ingress-ifindex admission,
  and the reverse leg replies out the same physical uplink the client's
  packet arrived on. N=1 (single-uplink deployments) is unchanged.
- `NODE_ALLOW`: outer-Geneve peer-node attestation gate for decap.
  Populated additively (upsert-only) until the controller's own Node LIST
  is known complete (`fronts_known`), so a cold-started controller never
  wipes an already-pinned peer set on a partial view. Two ADRs formalize
  the trust model this assumes: the Geneve underlay L2 is not trustworthy
  (`NODE_ALLOW` is defense-in-depth, not a substitute for a cryptographic
  underlay like WireGuard), and the startup-blackout window is a
  deliberate security-vs-availability tradeoff, not an oversight.
- The embedded eBPF object is DWARF-stripped, and CI asserts it stays
  stripped, keeping the loader binary's embedded payload lean.

### Changed

- `deploy/`'s rp_filter node-prep now runs in a privileged initContainer
  instead of requiring the main container to hold node-wide privileges for
  its whole lifetime.
- The k3s e2e rig now deploys and verifies the commit-under-test's image
  `:sha`, not the DaemonSet's `:latest`, so cross-node tests catch
  regressions in the actual candidate build.

### Known Limitations

- Asymmetric relay/egress-interface selection is deferred: replying out a
  different uplink than the one a packet ingressed on is explicitly out of
  scope for this release.
- IPv6 dual-stack is in progress, not shipped. v0.2.0 is IPv4-only, same as
  v0.1.0.
- Single backend per Service, carried over from v0.1.0: multi-endpoint
  load balancing across several ready pods is still not implemented.
- Real-fleet fidelity remains unproven beyond the k3s-on-Lima VM rig,
  carried over from v0.1.0.

## [0.1.0]

### Added

- North-south `type=LoadBalancer` Service delivery via a
  Geneve-encapsulated, eBPF (aya, tc-bpf) dataplane with full-tuple
  conntrack.
- Single-node and cross-node delivery, proven on the k3s-on-Lima VM rig.
- Real client-IP preservation: the forward leg's DNAT rewrites only the
  destination IP/port, never the client's source IP.
- Controller memory footprint CI-gated (idle/loaded RSS tracked in the
  memory-smoke job).
- Docker Hub image `docker.io/valerauko/beep-lb`, natively pullable over
  IPv6.

### Known Limitations

- Single backend per Service. Multi-endpoint load balancing across several
  pods is not implemented; a Service with more than one ready endpoint
  gets only one of them selected. Real N-endpoint selection is deferred to
  a fast-follow release.
- Real-fleet fidelity unproven. Client-IP preservation is verified against
  the k3s-on-Lima VM rig, not against a real cloud provider's
  uRPF/NAT/IPv6 edge cases. Deferred, off the v0.1.0 path.
- Lives in the u7s monorepo's `beep/` subtree; an independent repo split
  for its own release cadence is not yet done.
