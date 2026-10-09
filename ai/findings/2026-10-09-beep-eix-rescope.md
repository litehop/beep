# beep-eix rescope audit

Bead: beep-eix
Date: 2026-10-09T02:11Z (checked at main 9b555ec)

**Answer: multi-symmetric-uplink is fully shipped; what remains is (a) an
operator decision on whether asymmetric relay/egress selection is needed at
all, and (b) one concrete gap, NODE_ALLOW admission of multi-homed peers
(HIGH only if v1 targets multi-homed nodes). Do not close beep-eix until the
decision is made; its description is stale and should be rewritten.**

## What shipped

- Repeatable `--uplink-iface`: `src/main.rs:131-132` (`Vec<String>`,
  required). Single `--geneve-iface` remains: `src/main.rs:135-136`.
- Per-uplink `UplinkConfig { l2_hlen }`: `common/src/lib.rs:360-362`;
  `UPLINK_CONFIG` map, max 8 entries, keyed by ifindex:
  `ebpf/src/main.rs:419`. Loader fill with ARPHRD to l2_hlen mapping and
  unsupported-type error: `src/lib.rs:735-749`, `src/lib.rs:715`.
- Attach loop over N uplinks for ingress and egress-return hooks, geneve0
  ingress single: `src/main.rs:466-490`.
- Ingress admission keyed on packet ingress ifindex (map hit = admission +
  l2_hlen): `ebpf/src/main.rs:537-567`.
- Symmetric return: `FlowValue.forward.ingress_ifindex` stamped at admission
  (`common/src/lib.rs:380`) and used by the decap-return redirect
  (`ebpf/src/main.rs:1449`, `:1493`); `redirect_client_bound` picks
  `bpf_redirect_neigh` for Ethernet, `bpf_redirect` for L3-only
  (`ebpf/src/main.rs:1368-1372`).
- Egress-return hook looks up by its own attach ifindex:
  `ebpf/src/main.rs:1599`.
- Design: `docs/decisions/servicelb-multi-symmetric-uplink.md` (explicitly
  defers asymmetric egress selection, line 54). README: `README.md:56`.
  Shipped in #112 and v0.2.0 (#115).

## What remains

1. **Asymmetric relay/egress-interface selection: not implemented, no
   design.** Two distinct legs:
   - Client-return leg: hardwired to the ingress uplink
     (`ebpf/src/main.rs:1449`). Return via a different uplink (e.g. ingress
     eth0, return wg0) is impossible by design.
   - Forward Geneve leg (front node to backend node): the dataplane only sets
     the tunnel key remote (`ebpf/src/main.rs:682-702`) and redirects to
     `geneve_ifindex` (`:679`, `:735`, `:810`, `:852`, `:1701`). The kernel
     FIB picks the underlay interface for the outer packet. beep has no
     egress-interface knob here; the operator controls it via routing. The
     bead's "eth1 VPC-local relay" case may already be satisfiable by routes
     to the peer node IP, unverified.
   - Nothing in the tree models a "relay interface" (`CONFIG` holds only
     `geneve_ifindex`; ADR line 23).
2. **NODE_ALLOW multi-homed peers**: `NODE_ALLOW` is keyed on the tunnel
   remote (outer source) one address per node (`ebpf/src/main.rs:249`,
   `:914`, `:1325`; capacity 32). A peer whose outer source differs from the
   recorded address is dropped. beep-5ng was closed as superseded by this
   bead but no work was done; the population side (controller) is not in this
   repo (grep for node address handling finds nothing in src/).
3. **Single `--geneve-iface`** (`src/main.rs:136`, `CONFIG` one entry): a
   second Geneve device (e.g. per-underlay) cannot be configured. Only
   relevant if (1) is answered with "per-interface Geneve devices".
4. **`UPLINK_CONFIG` cap of 8** (`ebpf/src/main.rs:419`): loader behavior when
   more than 8 `--uplink-iface` values are given is unverified here.
5. Acceptance criteria in the bead ("designated relay/egress interface",
   "selects the correct egress interface for the relay leg") are unmet and
   unspecified.

## Proposed follow-on beads

| Sev | Bead | Scope |
|-----|------|-------|
| MED | NODE_ALLOW multi-IP peer admission | Allow several outer-source addresses per peer; define who populates; cross-node test. Decision-awaiting on Q1/Q4. |
| MED | Document/verify forward-leg underlay selection via routing | Test + doc that Geneve outer egress follows FIB (eth1/wg0 chosen by route to peer IP); resolves whether eix needs code at all. No decision needed. |
| DEFER | Asymmetric client-return egress selection | Per-flow or per-uplink policy for return interface != ingress. Decision-awaiting on Q2. |
| LOW | Loader guard for >8 uplinks | Fail loud at load if uplink count exceeds `UPLINK_CONFIG` capacity (verify first whether already guarded). |
| DEFER | Multiple `--geneve-iface` | Only if Q3 answered "yes". |

## Open design questions for the operator

- Q1. Is multi-homed / NAT node support (outer source differing from the
  recorded node IP) in v1.0 scope?
- Q2. Is there a real topology where the client-return leg must egress a
  different interface than it arrived on (asymmetric routing)? If not, drop
  it from v1 and close eix.
- Q3. Should the Geneve relay leg ever be steered by beep (explicit
  interface or per-peer map), or is FIB/route configuration the intended
  mechanism?
- Q4. Where does node address population live (controller repo?), and should
  NODE_ALLOW accept an address set per peer or one entry per address?
- Q5. Should eix close once the MED routing-verification bead lands, with
  asymmetric selection tracked only as DEFER?

Not verified: live behavior (no VM used); controller population code;
`UPLINK_CONFIG` overflow handling.
