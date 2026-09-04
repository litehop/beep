//! Pure-Rust conntrack key encode/decode + backend source-port remap logic
//! for the ServiceLB eBPF dataplane, extracted out of `servicelb-ebpf` so it
//! is unit-testable outside a kernel (a conntrack keying bug is not
//! verifiable by inspection alone). Shared by `servicelb-ebpf` as a no_std
//! dependency; `cargo test` here runs natively with `std`'s test harness
//! (see `Cargo.toml`).
//!
//! Design settled in `ai/extended-context/ebpf-lb-dataplane.md`'s "Conntrack
//! & affinity" section and its "Settled wire-format decisions".
#![cfg_attr(not(test), no_std)]

/// TCP/UDP flow-affinity key: IPv6-primary, 37 bytes (16+16+2+2+1), no
/// padding. A flat byte array rather than a `#[repr(C)]` struct: the kernel
/// hashes/compares a `BPF_MAP_TYPE_*_HASH` key's raw bytes, and a padded
/// struct leaves compiler-inserted alignment gaps as uninitialized garbage
/// that differs between independent call sites even when every named field
/// matches (the exact bug `servicelb-ebpf`'s old `FlowKey` hit on a live
/// kernel). A byte array has no such gap by construction.
pub const TCP_FLOW_KEY_LEN: usize = 37;
pub type TcpFlowKey = [u8; TCP_FLOW_KEY_LEN];

/// Embeds an IPv4 address (already in the wire-token representation --
/// exact bytes as read off the packet, see `servicelb-ebpf`'s module doc)
/// as an IPv4-mapped IPv6 address (RFC 4291 SS2.5.5.2: `::ffff:a.b.c.d`),
/// so one 37-byte key shape covers both address families -- IPv4 flows and
/// real IPv6 flows never collide, since a genuine IPv6 address can't carry
/// the `::ffff:0:0/96` prefix this produces.
pub fn ipv4_mapped_v6(wire_ip: u32) -> [u8; 16] {
    let mut v6 = [0u8; 16];
    v6[10] = 0xff;
    v6[11] = 0xff;
    v6[12..16].copy_from_slice(&wire_ip.to_ne_bytes());
    v6
}

/// Inverse of `ipv4_mapped_v6`: recovers the original wire-token IPv4
/// address if `v6` carries the `::ffff:0:0/96` prefix, `None` if it's a
/// genuine (non-mapped) IPv6 address.
pub fn unmap_ipv4(v6: &[u8; 16]) -> Option<u32> {
    if v6[0..10] == [0u8; 10] && v6[10..12] == [0xff, 0xff] {
        Some(u32::from_ne_bytes(v6[12..16].try_into().unwrap()))
    } else {
        None
    }
}

/// Packs a TCP/UDP flow key. `client_port`/`other_port` are wire tokens
/// (see module doc); `other` is the VIP on the forward/ingress role or the
/// backend Pod on the reverse/backend role (`ebpf-lb-dataplane.md`).
pub fn encode_tcp_flow_key(
    client_ip: [u8; 16],
    client_port: u16,
    other_ip: [u8; 16],
    other_port: u16,
    proto: u8,
) -> TcpFlowKey {
    let mut key = [0u8; TCP_FLOW_KEY_LEN];
    key[0..16].copy_from_slice(&client_ip);
    key[16..32].copy_from_slice(&other_ip);
    key[32..34].copy_from_slice(&client_port.to_ne_bytes());
    key[34..36].copy_from_slice(&other_port.to_ne_bytes());
    key[36] = proto;
    key
}

/// Unpacks a TCP/UDP flow key; the exact inverse of `encode_tcp_flow_key`.
pub fn decode_tcp_flow_key(key: &TcpFlowKey) -> ([u8; 16], u16, [u8; 16], u16, u8) {
    let client_ip: [u8; 16] = key[0..16].try_into().unwrap();
    let other_ip: [u8; 16] = key[16..32].try_into().unwrap();
    let client_port = u16::from_ne_bytes(key[32..34].try_into().unwrap());
    let other_port = u16::from_ne_bytes(key[34..36].try_into().unwrap());
    let proto = key[36];
    (client_ip, client_port, other_ip, other_port, proto)
}

/// QUIC flow-affinity key: a fixed-length prefix of the Destination
/// Connection ID the LB itself mints into the RFC 9000 SS17.2 Initial-packet
/// DCID -- not derived from the client's address, so it carries no
/// TCP-style collision risk (`ebpf-lb-dataplane.md`). Fixed-length because
/// the 1-RTT short header (RFC 9000 SS17.3.1) has no length field; 8 bytes
/// is this dataplane's externally-agreed length (one hop, no chained-LB
/// scheme needed yet).
pub const QUIC_DCID_KEY_LEN: usize = 8;
pub type QuicDcidKey = [u8; QUIC_DCID_KEY_LEN];

/// Packs a QUIC DCID key from a minted DCID's leading bytes. Zero-pads a
/// shorter-than-`QUIC_DCID_KEY_LEN` input rather than panicking -- the LB
/// always mints exactly this length in practice, but a pure function
/// should be total.
pub fn encode_quic_dcid_key(dcid_prefix: &[u8]) -> QuicDcidKey {
    let mut key = [0u8; QUIC_DCID_KEY_LEN];
    let n = dcid_prefix.len().min(QUIC_DCID_KEY_LEN);
    key[..n].copy_from_slice(&dcid_prefix[..n]);
    key
}

/// Unpacks a QUIC DCID key; the exact inverse of `encode_quic_dcid_key` for
/// a full-length input.
pub fn decode_quic_dcid_key(key: &QuicDcidKey) -> [u8; QUIC_DCID_KEY_LEN] {
    *key
}

/// Backend source-port remap, on-conflict-only (Decision 3,
/// `ai/extended-context/ebpf-lb-dataplane.md`). The backend's naive
/// reverse-flow key `(CLIENT_IP, SRC_PORT, PodIP, TargetPort, proto)`
/// collides when two Services with different front addresses (VIPs) share
/// a backend Pod:targetPort and the client reuses one ephemeral source
/// port across both -- legal, since the two connections differ by remote
/// (front) address even though local port matches. Remapping the backend-
/// facing source port (not the client's real IP -- that would destroy
/// real-client-IP-at-L3, ADR servicelb-ebpf-geneve-dataplane.md) makes the
/// reverse key unique again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPortDecision {
    /// No prior entry for this reverse key, or the prior entry belongs to
    /// the same front address (same flow refreshing) -- use the client's
    /// real source port unchanged.
    NoRemap,
    /// A different front address already holds this reverse key -- use
    /// this synthetic port instead, only on the backend-facing segment
    /// (un-remapped back to the real port on return).
    Remap(u16),
}

/// `existing_front`: the front (VIP_IP, VIP_PORT) already stored under the
/// naive reverse key, if any (`None` = first writer, no conflict possible).
/// `new_front`: the front address the current packet arrived through.
/// `original_port`: the client's real source port -- excluded as a
/// candidate remap value so the two resulting reverse keys are guaranteed
/// distinct, not just probably distinct.
pub fn resolve_backend_src_port(
    existing_front: Option<([u8; 16], u16)>,
    new_front: ([u8; 16], u16),
    original_port: u16,
) -> BackendPortDecision {
    match existing_front {
        None => BackendPortDecision::NoRemap,
        Some(front) if front == new_front => BackendPortDecision::NoRemap,
        Some(_) => BackendPortDecision::Remap(synthetic_backend_port(
            new_front.0,
            new_front.1,
            original_port,
        )),
    }
}

/// IANA dynamic/private port range (RFC 6335 SS6) -- this dataplane
/// controls both ends of the backend<->Pod segment the remapped port is
/// visible on, so it doesn't need to avoid the client's own ephemeral
/// range at all, just be internally distinct.
pub const REMAP_PORT_BASE: u16 = 49152;
pub const REMAP_PORT_RANGE: u16 = u16::MAX - REMAP_PORT_BASE + 1; // 16384

/// Deterministic (not counter-based, no allocator map needed): the same
/// conflicting front always remaps the same way, so re-deriving it
/// packet-by-packet is idempotent -- the reverse-flow map itself is the
/// only state this needs.
pub fn synthetic_backend_port(front_ip: [u8; 16], front_port: u16, avoid: u16) -> u16 {
    let ip_word = u32::from_ne_bytes(front_ip[12..16].try_into().unwrap())
        ^ u32::from_ne_bytes(front_ip[0..4].try_into().unwrap());
    let mixed =
        ip_word ^ ip_word.rotate_right(16) ^ (front_port as u32) ^ ((front_port as u32) << 3);
    let offset = (mixed as u16) % REMAP_PORT_RANGE;
    let mut candidate = REMAP_PORT_BASE.wrapping_add(offset);
    if candidate == avoid {
        let bumped = (offset + 1) % REMAP_PORT_RANGE;
        candidate = REMAP_PORT_BASE.wrapping_add(bumped);
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    // A conntrack keying bug corrupts flow affinity silently instead of
    // failing loudly, so every encode/decode path is round-tripped here
    // rather than trusted by inspection.

    #[test]
    fn tcp_key_round_trips_ipv6_addresses() {
        let client_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let other_ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let key = encode_tcp_flow_key(client_ip, 0x1234, other_ip, 0x5678, 6);
        assert_eq!(
            decode_tcp_flow_key(&key),
            (client_ip, 0x1234, other_ip, 0x5678, 6)
        );
    }

    #[test]
    fn tcp_key_round_trips_ipv4_via_mapped_embedding() {
        // The sizing table's whole justification for 37 bytes over 13
        // (IPv4-only) is that one map shape serves both families -- prove
        // an IPv4 address survives the v6 embedding and back unchanged.
        let client_v4: u32 = 0x0100_000a; // wire-token bytes: 10.0.0.1
        let other_v4: u32 = 0x0200_000a; // 10.0.0.2
        let key = encode_tcp_flow_key(
            ipv4_mapped_v6(client_v4),
            0x1234,
            ipv4_mapped_v6(other_v4),
            0x5678,
            17,
        );
        let (client_ip, client_port, other_ip, other_port, proto) = decode_tcp_flow_key(&key);
        assert_eq!(unmap_ipv4(&client_ip), Some(client_v4));
        assert_eq!(unmap_ipv4(&other_ip), Some(other_v4));
        assert_eq!((client_port, other_port, proto), (0x1234, 0x5678, 17));
    }

    #[test]
    fn unmap_ipv4_rejects_a_genuine_ipv6_address() {
        // A real IPv6 flow must never be silently misread as IPv4 --
        // that would let an IPv6 and an IPv4 flow collide despite the
        // whole point of the mapped-embedding scheme being to keep them
        // disjoint.
        let real_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(unmap_ipv4(&real_v6), None);
    }

    #[test]
    fn quic_dcid_key_round_trips() {
        let dcid = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = encode_quic_dcid_key(&dcid);
        assert_eq!(decode_quic_dcid_key(&key), dcid);
    }

    #[test]
    fn quic_dcid_key_zero_pads_a_short_input() {
        let key = encode_quic_dcid_key(&[9, 9]);
        assert_eq!(key, [9, 9, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn non_colliding_flow_leaves_client_src_port_untouched() {
        // The happy path (first writer, or the same flow's later packets)
        // must never remap -- doing so on every packet would break the
        // client's real connection identity for the common case.
        let vip_a = (ipv4_mapped_v6(0x0100_000a), 0x5000u16);
        assert_eq!(
            resolve_backend_src_port(None, vip_a, 0x9999),
            BackendPortDecision::NoRemap
        );
        assert_eq!(
            resolve_backend_src_port(Some(vip_a), vip_a, 0x9999),
            BackendPortDecision::NoRemap
        );
    }

    #[test]
    fn two_services_sharing_a_backend_pod_and_client_port_get_a_unique_reverse_tuple() {
        // The exact scenario Decision 3 closes: Service A and Service B
        // have different front addresses but resolve to the same backend
        // Pod:targetPort, and the client reuses one local port for both
        // connections (legal -- remote addresses differ). Without the
        // remap, both flows' reverse keys are byte-identical and the
        // second write clobbers the first, misrouting its replies.
        let client_ip = ipv4_mapped_v6(0x0100_000a);
        let pod_ip = ipv4_mapped_v6(0x0a00_a8c0);
        let target_port = 0x1f90u16;
        let client_src_port = 0x9999u16;
        let front_a = (ipv4_mapped_v6(0x0100_000a), 0x5000u16);
        let front_b = (ipv4_mapped_v6(0x0200_000a), 0x5001u16);

        // Service A's flow writes first: no existing entry, no conflict.
        let decision_a = resolve_backend_src_port(None, front_a, client_src_port);
        assert_eq!(decision_a, BackendPortDecision::NoRemap);
        let port_a = client_src_port;

        // Service B's flow arrives with the same natural reverse key
        // already held by Service A's (different) front -- conflict.
        let decision_b = resolve_backend_src_port(Some(front_a), front_b, client_src_port);
        let BackendPortDecision::Remap(port_b) = decision_b else {
            panic!("expected a remap on front-address conflict, got {decision_b:?}");
        };
        assert_ne!(
            port_b, client_src_port,
            "remapped port must differ from the client's real port, or the reverse key still collides"
        );

        let key_a = encode_tcp_flow_key(client_ip, port_a, pod_ip, target_port, 6);
        let key_b = encode_tcp_flow_key(client_ip, port_b, pod_ip, target_port, 6);
        assert_ne!(
            key_a, key_b,
            "Decision 3's whole purpose: the two services' reverse tuples must be unique by construction"
        );
    }

    #[test]
    fn synthetic_port_never_collides_with_the_port_it_must_avoid() {
        // The internal bump-on-self-collision branch only fires on a rare
        // arithmetic coincidence -- not reachable by inspection, so sweep
        // a spread of fronts against one fixed avoid value.
        let avoid = 0x9999u16;
        for ip_octet in 0u8..=255 {
            for port in [1u16, 100, 5000, 49152, 60000] {
                let front_ip = ipv4_mapped_v6(u32::from_ne_bytes([10, 0, 0, ip_octet]));
                let candidate = synthetic_backend_port(front_ip, port, avoid);
                assert_ne!(candidate, avoid);
            }
        }
    }
}
