# QUIC CID-based keying

**Answer:** keep 4-tuple pass-through (today's behaviour); if QUIC connection
migration must survive, route on a server_id carried in the backend-chosen
Connection ID and resolved statelessly on every node, not on a CID-to-flow
map, and do not build it until the operator questions below are answered.

Settles the open cost question of `docs/design/ebpf-lb-dataplane.md` (Conntrack
section: "CID-based keying is deferred"). Status: proposal, not implemented.

## What migration breaks today

QUIC flows are keyed like TCP/UDP: `FlowKey` is the 5-tuple plus a direction
tag (`common/src/lib.rs`, `FlowValue` union at :394). Ingress derives the
backend in two steps, both tuple-based:

- Front resolution: `front_endpoint(LbFrontKey)` reads `FRONT_META` then
  `FRONT_ENDPOINTS` (`ebpf/src/main.rs:389`); the endpoint is slot 0, no
  per-flow choice yet.
- Pin: the flow key is built at `main.rs:645`; a `FLOW_TABLE` forward hit
  (:661) means established, otherwise the choice is minted into `FWD_PENDING`
  (:671) and promoted on the first return packet.

When a client migrates (new source IP or port, RFC 9000 section 9) the key
changes, so the packet is a new flow: it re-resolves and may select a
different backend, which has no connection state and answers with a stateless
reset. NAT rebinding and mobile handover trigger this without any attacker.
Pins are also node-local: a client that lands on a different node (ECMP,
anycast, reconnect) has no pin there at all.

## CID-routing options

QUIC CIDs are chosen by the receiving endpoint (RFC 9000 section 7.2), so a
non-terminating dataplane can only observe or route on what the backend
chose; it cannot mint them. (`QuicDcidKey` in `common/src/lib.rs:164-188`
assumes an LB that mints the DCID; that contradicts this and is unused.)

**A. CID-to-flow map.** On the first backend reply, learn the server-chosen
SCID and insert `CID -> backend` into a map. Needs no backend cooperation, but
the table is per node: it fixes migration on the same node only, adds a
learn-on-return path, and costs one entry per CID (each connection issues
several). A client arriving on another node still misses.

**B. Server_id in the CID (QUIC-LB draft).** The backend encodes a
server_id into every CID it issues; any node decodes it from the DCID and
resolves `server_id -> backend` from a small replicated table. Stateless in
the dataplane, so it also fixes cross-node reconnection that pins cannot. Cost:

- backend cooperation (only Envoy generates QUIC-LB CIDs today);
- shared decode parameters on every node, rotated in lockstep, when the
  encrypted variants are used (the plaintext variant needs no secret but
  exposes server_id and links a client's CIDs);
- a cluster-wide `server_id -> endpoint` table. Envoy publishes no
  discoverable mapping (server_id is static per-instance config), and the
  draft leaves distribution out of scope, so beep's controller would have to
  assign, publish and inject the IDs itself.

**C. Tuple pass-through (current).** No cost; migration drops affinity.

Option A is dominated: it pays per-CID state and still cannot cross nodes.
B is the only option that addresses the operator's cross-node concern.

## Interaction with multi-endpoint selection

`ai/findings/2026-09-19-beep-5lw-multipod-lb-plan.md` picks a slot by tuple
hash modulo ready count, and makes ingress steer from the stored pin.

- A hash of the tuple is the wrong selector for a migrating client, which is
  exactly why B bypasses it: on a decodable CID, the server_id wins and the
  hash is only for flows without one (Initial packets, non-QUIC).
- Node-local preference must not override a decoded server_id; it can only
  break ties among slots when no server_id is present.
- Pin-steering stays correct as the fallback and as the cache: after a CID
  decode the pin could be written under the new tuple, so later packets skip
  the parse.
- Server_ids are per endpoint, so slot renumbering ("per-front dense slots")
  must not leak into them. B needs a stable id independent of slot index.
- Endpoint churn: a decoded server_id naming a removed endpoint must fall
  back to hash selection, not drop (backend would reset anyway).

## Verifier and map costs (estimates, unmeasured)

- Parsing: short-header DCID is at a fixed offset after the UDP header with
  a configured length; long headers carry a length byte. Bounded, no loops.
  Adds one more bounds-checked packet read to ingress, which already carries
  verifier pressure from the v4/v6 duplication.
- Decode: plaintext is a byte copy. Encrypted variants need AES; whether the
  deployed kernels expose usable crypto kfuncs to tc programs is unverified.
- Maps: `SERVER_IDS` is `server_id -> LbFrontBackend`-sized (about 40 B) per
  endpoint, tiny next to `FRONT_ENDPOINTS` (8192). Option A would instead
  contest the 16384-entry `FLOW_TABLE` (`main.rs:360`) with per-CID entries.

## Needs data, deferred, operator questions

Deferred (not designed here): encrypted CID decode; CID rotation handling
beyond "decode every packet"; QUIC v2 and long-header edge cases.

Needs data:

- Fraction of client traffic that actually migrates or re-lands on another
  node; if small, C remains right.
- Whether any in-scope backend emits QUIC-LB CIDs at all.
- Kernel support for crypto in tc eBPF on the target kernels.

Operator questions:

1. Is cross-node client landing real (ECMP/anycast on the front) or are
   clients pinned to one node by upstream routing?
2. Does beep own server_id assignment (CRD or ConfigMap and injection into
   backends), or is QUIC migration out of scope for beep?
3. Is plaintext server_id acceptable, avoiding the shared secret?
4. May the wire format of beep's own state (`FlowKey`) stay unchanged, with
   `SERVER_IDS` as a new map only?
