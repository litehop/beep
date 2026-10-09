# QUIC keying stays 4-tuple; future CID routing uses server_id, not a CID map

**Status:** Proposed
**Date:** 2026-10-09

## Context

QUIC connection migration changes the 5-tuple, so `FLOW_TABLE` treats the
packet as a new flow and may re-select a backend. CIDs are chosen by the
backend (RFC 9000 section 7.2), so beep cannot mint them. Analysis:
`docs/design/quic-cid-keying.md`.

## Decision

- Keep 4-tuple keying for QUIC. No CID parsing and no new map now.
- If migration affinity is required later, route on a server_id carried in
  the backend-issued CID (QUIC-LB draft), resolved through a replicated
  `server_id -> endpoint` map on every node.
- Do not build a CID-to-flow map: it is per-node state, costs an entry per
  CID, and cannot serve a client that lands on another node.

## Consequences

Migrating clients lose affinity (stateless reset, reconnect) until the
server_id route exists. Building it later obliges beep to own server_id
assignment and distribution (Envoy publishes none), plus backend injection
and, for encrypted CIDs, a lockstep-rotated secret. The unused
`QuicDcidKey` helpers in `beep-common` assume an LB-minted DCID and should
be removed.

## Alternatives

CID-to-flow map (rejected above); LB-minted CIDs (impossible for a
non-terminating dataplane); terminating QUIC in beep (out of scope).
