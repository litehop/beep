//! Reply packets for traffic addressed to an owned front that has no ready
//! backend: a TCP RST (RFC 793 reset generation) or an ICMP/ICMPv6
//! destination-unreachable, so clients fail fast instead of retrying into
//! silence.
//!
//! Each `*_in_place` function turns the offending packet's own headers into
//! the reply inside one fixed-size buffer, checksums included, and says
//! whether a reply is due at all. The dataplane loads the offending headers
//! into the buffer, calls the function, and copies the buffer onto the wire.
//! One buffer, no copies of the addresses: the BPF stack is 512 bytes in
//! total and shared with the steering path, so nothing here may keep a second
//! copy of the packet or spill state (hence the volatile accesses below, which
//! stop LLVM from fusing byte runs into `memset`/`memcpy` calls -- each such
//! call costs a 32-byte frame in the verifier's accounting -- and from
//! hoisting loads ahead of stores). Every `*_in_place` function takes a `raw`
//! checksum summer, described at [`internet_checksum`]'s helpers below.

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_ICMPV6: u8 = 58;
const REPLY_TTL: u8 = 64;

/// IPv4 offending header (20, no options) + first 14 TCP bytes, loaded by
/// the caller into the front of a buffer of [`TCP_RST_V4_LEN`] bytes.
pub const TCP_RST_V4_IN_LEN: usize = 34;
/// IPv4 RST: 20-byte IP header + 20-byte TCP header.
pub const TCP_RST_V4_LEN: usize = 40;
/// IPv6 offending header (40, no extension headers) + first 14 TCP bytes.
pub const TCP_RST_V6_IN_LEN: usize = 54;
/// IPv6 RST: 40-byte IP header + 20-byte TCP header.
pub const TCP_RST_V6_LEN: usize = 60;
/// Offending IPv4 header plus the first 8 payload bytes (RFC 792); the
/// caller loads it at `ICMP_UNREACH_V4_LEN - ICMP_QUOTE_V4_LEN`.
pub const ICMP_QUOTE_V4_LEN: usize = 28;
/// IPv4 ICMP reply: IP header (20) + ICMP header (8) + quote.
pub const ICMP_UNREACH_V4_LEN: usize = 20 + 8 + ICMP_QUOTE_V4_LEN;
/// Offending IPv6 header plus an 8-byte UDP header: enough for the sender to
/// demultiplex the error, far under the 1280-byte limit of RFC 4443.
pub const ICMP6_QUOTE_LEN: usize = 48;
/// IPv6 ICMPv6 reply: IP header (40) + ICMPv6 header (8) + quote.
pub const ICMP6_UNREACH_LEN: usize = 40 + 8 + ICMP6_QUOTE_LEN;

/// The fields of an incoming TCP segment a reset is derived from (host order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: u32,
}

impl TcpSegment {
    /// `hdr` holds at least the first 14 bytes of the TCP header; `l4_len` is
    /// the IP payload length (TCP header included), from which the data
    /// offset is subtracted so TCP options never count as payload.
    #[inline(always)]
    pub fn parse(hdr: &[u8], l4_len: u32) -> TcpSegment {
        let header_len = u32::from(hdr[12] >> 4) * 4;
        TcpSegment {
            seq: u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]),
            ack: u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
            flags: hdr[13],
            payload_len: l4_len.saturating_sub(header_len),
        }
    }
}

/// Sequence numbers and flags of the RST answering a `TcpSegment`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpReset {
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
}

/// RFC 793 reset generation. `None` for a segment that is itself a RST: a
/// reset is never answered, or two such hosts would ping-pong forever.
#[inline(always)]
pub fn tcp_reset_for(seg: TcpSegment) -> Option<TcpReset> {
    if seg.flags & TCP_RST != 0 {
        return None;
    }
    if seg.flags & TCP_ACK != 0 {
        return Some(TcpReset {
            seq: seg.ack,
            ack: 0,
            flags: TCP_RST,
        });
    }
    let syn_fin = u32::from(seg.flags & TCP_SYN != 0) + u32::from(seg.flags & TCP_FIN != 0);
    Some(TcpReset {
        seq: 0,
        ack: seg.seq.wrapping_add(seg.payload_len).wrapping_add(syn_fin),
        flags: TCP_RST | TCP_ACK,
    })
}

/// RFC 1122 3.2.2 / RFC 1812: no reply to or from an address that is not a
/// single reachable host (unspecified, loopback, multicast, class E and the
/// limited broadcast), which is what prevents broadcast reply storms.
#[inline(always)]
pub fn v4_reply_allowed(src: [u8; 4], dst: [u8; 4]) -> bool {
    fn single_host(a: [u8; 4]) -> bool {
        a[0] != 0 && a[0] != 127 && a[0] < 224
    }
    single_host(src) && single_host(dst)
}

/// RFC 4443 2.4(e): no reply to or from an unspecified, loopback or
/// multicast address. Both slices are 16 bytes.
#[inline(always)]
pub fn v6_reply_allowed(src: &[u8], dst: &[u8]) -> bool {
    fn single_host(a: &[u8]) -> bool {
        let leading_zero = a[..15].iter().all(|&b| b == 0);
        let unspecified_or_loopback = leading_zero && a[15] <= 1;
        !unspecified_or_loopback && a[0] != 0xff
    }
    single_host(src) && single_host(dst)
}

/// A non-first IPv4 fragment carries no L4 header, so its "ports" are payload
/// bytes; replying would address a flow that does not exist. `frag_field` is
/// the host-order flags/offset halfword.
#[inline(always)]
pub fn v4_is_non_first_fragment(frag_field: u16) -> bool {
    frag_field & 0x1fff != 0
}

// Checksums are delegated to a `raw` summer with `bpf_csum_diff` semantics:
// it adds `data` (length a multiple of 4) as native-endian 16-bit words onto
// a native-endian `seed`, leaving carries unfolded. In the dataplane that is
// the kernel helper, which keeps every sum a single call: summing in
// Rust-in-BPF is either unrolled (several KiB of object per call site) or a
// loop the verifier widens and rejects, and unrolled code spills registers
// onto the shared 512-byte stack. Host tests pass a software summer.

/// Folds carries into 16 bits (not complemented).
#[inline(always)]
fn fold16(mut acc: u32) -> u16 {
    acc = (acc & 0xffff) + (acc >> 16);
    acc = (acc & 0xffff) + (acc >> 16);
    acc as u16
}

/// Unfolded big-endian-domain sum of `data` onto the big-endian-domain
/// `seed`. One's-complement addition commutes with byte swapping, so the
/// native-endian result of `raw` only needs its folded 16 bits swapped back.
#[inline(always)]
fn sum_be(raw: &impl Fn(&[u8], u32) -> u32, data: &[u8], seed: u32) -> u32 {
    let native_seed = u32::from(u16::from_be(fold16(seed)));
    u32::from(u16::from_be(fold16(raw(data, native_seed))))
}

/// RFC 1071 checksum of `data` (length a multiple of 4) seeded with `seed`,
/// e.g. a pseudo-header sum.
#[inline(always)]
pub fn internet_checksum(raw: &impl Fn(&[u8], u32) -> u32, data: &[u8], seed: u32) -> u16 {
    !fold16(sum_be(raw, data, seed))
}

#[inline(always)]
fn get16(buf: &[u8], at: usize) -> u16 {
    (u16::from(buf[at]) << 8) | u16::from(buf[at + 1])
}

#[inline(always)]
fn put16(buf: &mut [u8], at: usize, v: u16) {
    buf[at] = (v >> 8) as u8;
    buf[at + 1] = v as u8;
}

#[inline(always)]
fn put32(buf: &mut [u8], at: usize, v: u32) {
    put16(buf, at, (v >> 16) as u16);
    put16(buf, at + 2, v as u16);
}

/// Zeroes `n` bytes with volatile writes so LLVM cannot fuse the run into a
/// `memset` call.
#[inline(always)]
fn zero(buf: &mut [u8], at: usize, n: usize) {
    for i in 0..n {
        // SAFETY: `buf[at + i]` is a live, exclusive `u8`.
        unsafe { core::ptr::write_volatile(&mut buf[at + i], 0) };
    }
}

// L4 checksums cover the pseudo-header, whose addresses sit immediately in
// front of the L4 header in the reply buffer (`buf[12..]` for IPv4, `buf[8..]`
// for IPv6): one summed range, seeded with the protocol and length words.

/// Overwrites everything but the addresses (`buf[12..20]`, already the
/// reply's) of the IPv4 header at the start of `buf`, checksum included: DF
/// set, id 0, TTL 64.
#[inline(always)]
fn write_ipv4_fields(
    raw: &impl Fn(&[u8], u32) -> u32,
    buf: &mut [u8],
    total_len: u16,
    tos: u8,
    proto: u8,
) {
    buf[0] = 0x45;
    buf[1] = tos;
    put16(buf, 2, total_len);
    put16(buf, 4, 0);
    put16(buf, 6, 0x4000);
    buf[8] = REPLY_TTL;
    buf[9] = proto;
    put16(buf, 10, 0);
    let csum = internet_checksum(raw, &buf[..20], 0);
    put16(buf, 10, csum);
}

/// Overwrites the non-address fields of the IPv6 header at the start of
/// `buf` (version, traffic class, flow label, length, next header, hop limit).
#[inline(always)]
fn write_ipv6_fields(buf: &mut [u8], payload_len: u16, next: u8) {
    put32(buf, 0, 0x6000_0000);
    put16(buf, 4, payload_len);
    buf[6] = next;
    buf[7] = REPLY_TTL;
}

// The functions below build a reply from the offending packet in place. The
// caller loads the offending packet's headers into `buf` with the two address
// fields *exchanged* -- the offending source where the reply's destination
// goes, the offending destination where its source goes -- which is one extra
// `bpf_skb_load_bytes` per address instead of code to swap them here. The
// reply is then complete: nothing is carried between header and body.

/// Turns the offending IPv4 TCP segment in `buf` ([`TCP_RST_V4_IN_LEN`]
/// bytes loaded at the front, addresses exchanged; the rest is overwritten)
/// into the RST that answers it, from the front back to the client. The IP
/// header must have no options. Returns false -- `buf` is then unspecified and
/// nothing may be sent -- for a segment that is itself a RST, a non-first
/// fragment, or addresses that must never be answered.
#[inline(always)]
pub fn tcp_rst_in_place_v4(
    buf: &mut [u8; TCP_RST_V4_LEN],
    raw: impl Fn(&[u8], u32) -> u32,
) -> bool {
    let src = [buf[12], buf[13], buf[14], buf[15]];
    let dst = [buf[16], buf[17], buf[18], buf[19]];
    if v4_is_non_first_fragment(get16(buf, 6)) || !v4_reply_allowed(src, dst) {
        return false;
    }
    let l4_len = u32::from(get16(buf, 2)).saturating_sub(20);
    let Some(rst) = tcp_reset_for(TcpSegment::parse(&buf[20..34], l4_len)) else {
        return false;
    };
    let (sport, dport) = (get16(buf, 20), get16(buf, 22));
    put16(buf, 20, dport);
    put16(buf, 22, sport);
    put32(buf, 24, rst.seq);
    put32(buf, 28, rst.ack);
    buf[32] = 5 << 4;
    buf[33] = rst.flags;
    // window 0, checksum (below), urgent pointer 0.
    zero(buf, 34, 6);
    let csum = internet_checksum(&raw, &buf[12..40], u32::from(IPPROTO_TCP) + 20);
    put16(buf, 36, csum);
    write_ipv4_fields(&raw, buf, TCP_RST_V4_LEN as u16, 0, IPPROTO_TCP);
    true
}

/// IPv6 counterpart of [`tcp_rst_in_place_v4`] ([`TCP_RST_V6_IN_LEN`] bytes
/// loaded; no extension headers).
#[inline(always)]
pub fn tcp_rst_in_place_v6(
    buf: &mut [u8; TCP_RST_V6_LEN],
    raw: impl Fn(&[u8], u32) -> u32,
) -> bool {
    if !v6_reply_allowed(&buf[8..24], &buf[24..40]) {
        return false;
    }
    let l4_len = u32::from(get16(buf, 4));
    let Some(rst) = tcp_reset_for(TcpSegment::parse(&buf[40..54], l4_len)) else {
        return false;
    };
    let (sport, dport) = (get16(buf, 40), get16(buf, 42));
    put16(buf, 40, dport);
    put16(buf, 42, sport);
    put32(buf, 44, rst.seq);
    put32(buf, 48, rst.ack);
    buf[52] = 5 << 4;
    buf[53] = rst.flags;
    zero(buf, 54, 6);
    write_ipv6_fields(buf, 20, IPPROTO_TCP);
    let csum = internet_checksum(&raw, &buf[8..60], u32::from(IPPROTO_TCP) + 20);
    put16(buf, 56, csum);
    true
}

/// Builds the ICMP destination-unreachable / port-unreachable (type 3, code
/// 3) reply to the IPv4 packet whose first [`ICMP_QUOTE_V4_LEN`] bytes the
/// caller loaded verbatim at `buf[28..]`, plus the exchanged addresses at
/// `buf[12..20]`. Returns false when no reply is due (see
/// [`tcp_rst_in_place_v4`]).
#[inline(always)]
pub fn icmp_unreachable_in_place_v4(
    buf: &mut [u8; ICMP_UNREACH_V4_LEN],
    raw: impl Fn(&[u8], u32) -> u32,
) -> bool {
    let src = [buf[12], buf[13], buf[14], buf[15]];
    let dst = [buf[16], buf[17], buf[18], buf[19]];
    if v4_is_non_first_fragment(get16(buf, 34)) || !v4_reply_allowed(src, dst) {
        return false;
    }
    put16(buf, 20, 0x0303);
    zero(buf, 22, 6);
    let csum = internet_checksum(&raw, &buf[20..ICMP_UNREACH_V4_LEN], 0);
    put16(buf, 22, csum);
    // Internetwork control precedence (RFC 1812 4.3.2.5).
    write_ipv4_fields(&raw, buf, ICMP_UNREACH_V4_LEN as u16, 0xc0, IPPROTO_ICMP);
    true
}

/// ICMPv6 destination-unreachable / port-unreachable (type 1, code 4) reply
/// to the IPv6 packet whose first [`ICMP6_QUOTE_LEN`] bytes the caller loaded
/// verbatim at `buf[48..]`, plus the exchanged addresses at `buf[8..40]`.
#[inline(always)]
pub fn icmp6_unreachable_in_place(
    buf: &mut [u8; ICMP6_UNREACH_LEN],
    raw: impl Fn(&[u8], u32) -> u32,
) -> bool {
    if !v6_reply_allowed(&buf[8..24], &buf[24..40]) {
        return false;
    }
    write_ipv6_fields(buf, (ICMP6_UNREACH_LEN - 40) as u16, IPPROTO_ICMPV6);
    put16(buf, 40, 0x0104);
    zero(buf, 42, 6);
    let seed = u32::from(IPPROTO_ICMPV6) + (ICMP6_UNREACH_LEN - 40) as u32;
    let csum = internet_checksum(&raw, &buf[8..ICMP6_UNREACH_LEN], seed);
    put16(buf, 42, csum);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT4: [u8; 4] = [203, 0, 113, 2];
    const FRONT4: [u8; 4] = [203, 0, 113, 1];
    const CLIENT6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    const FRONT6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

    /// Software stand-in for `bpf_csum_diff`: native-endian 16-bit words
    /// added onto the seed, carries left unfolded.
    fn native_sum(data: &[u8], seed: u32) -> u32 {
        let mut acc = seed;
        for i in (0..data.len()).step_by(2) {
            acc += u32::from(u16::from_ne_bytes([data[i], data[i + 1]]));
        }
        acc
    }

    fn seg(seq: u32, ack: u32, flags: u8, payload_len: u32) -> TcpSegment {
        TcpSegment {
            seq,
            ack,
            flags,
            payload_len,
        }
    }

    /// Receiver-side validation, independent of the builders' own helpers:
    /// summing a correct segment together with its pseudo-header folds to
    /// 0xffff, the check a client's stack applies before accepting a reply.
    fn verifies(words: &[u8], pseudo: &[u8]) -> bool {
        let mut acc: u32 = 0;
        for chunk in pseudo.chunks(2).chain(words.chunks(2)) {
            acc += (u32::from(chunk[0]) << 8) | u32::from(chunk[1]);
        }
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        acc == 0xffff
    }

    fn v4_pseudo(src: &[u8], dst: &[u8], proto: u8, len: u16) -> Vec<u8> {
        [src, dst, &[0, proto], &len.to_be_bytes()].concat()
    }

    fn v6_pseudo(src: &[u8], dst: &[u8], next: u8, len: u32) -> Vec<u8> {
        [src, dst, &len.to_be_bytes(), &[0, 0, 0, next]].concat()
    }

    /// Offending client packet as the dataplane loads it: IPv4 header (with
    /// the client/front address fields exchanged) + 14 TCP bytes, then 0xff
    /// filler standing in for whatever the stack held before the reply.
    fn v4_tcp_in(flags: u8, seq: u32, ack: u32, tcp_len: u16, doff: u8) -> [u8; TCP_RST_V4_LEN] {
        let mut b = [0xffu8; TCP_RST_V4_LEN];
        b[..20].copy_from_slice(&[
            0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 203, 0, 113, 1, 203, 0, 113, 2,
        ]);
        b[2..4].copy_from_slice(&(20 + tcp_len).to_be_bytes());
        b[20..22].copy_from_slice(&40000u16.to_be_bytes());
        b[22..24].copy_from_slice(&19100u16.to_be_bytes());
        b[24..28].copy_from_slice(&seq.to_be_bytes());
        b[28..32].copy_from_slice(&ack.to_be_bytes());
        b[32] = doff << 4;
        b[33] = flags;
        b
    }

    fn v6_tcp_in(flags: u8, seq: u32, ack: u32, tcp_len: u16) -> [u8; TCP_RST_V6_LEN] {
        let mut b = [0xffu8; TCP_RST_V6_LEN];
        b[..8].copy_from_slice(&[0x60, 0, 0, 0, 0, 0, 6, 64]);
        b[4..6].copy_from_slice(&tcp_len.to_be_bytes());
        b[8..24].copy_from_slice(&FRONT6);
        b[24..40].copy_from_slice(&CLIENT6);
        b[40..42].copy_from_slice(&40000u16.to_be_bytes());
        b[42..44].copy_from_slice(&443u16.to_be_bytes());
        b[44..48].copy_from_slice(&seq.to_be_bytes());
        b[48..52].copy_from_slice(&ack.to_be_bytes());
        b[52] = 5 << 4;
        b[53] = flags;
        b
    }

    #[test]
    fn syn_without_ack_gets_rst_ack_so_connect_fails_immediately() {
        // A client's SYN carries no ACK; without ack = seq+1 the client
        // ignores the RST as out-of-window and hangs in SYN_SENT until timeout.
        let rst = tcp_reset_for(seg(1000, 0, TCP_SYN, 0)).unwrap();
        assert_eq!(
            rst,
            TcpReset {
                seq: 0,
                ack: 1001,
                flags: TCP_RST | TCP_ACK
            }
        );
    }

    #[test]
    fn data_segment_without_ack_acks_payload_plus_fin() {
        let rst = tcp_reset_for(seg(50, 0, TCP_FIN, 10)).unwrap();
        assert_eq!(rst.ack, 61);
    }

    #[test]
    fn rst_ack_number_wraps_at_sequence_space_end() {
        let rst = tcp_reset_for(seg(u32::MAX, 0, TCP_SYN, 0)).unwrap();
        assert_eq!(rst.ack, 0);
    }

    #[test]
    fn established_segment_gets_rst_at_the_peers_expected_seq() {
        // Seq must equal the segment's ACK or the client discards the RST as
        // out-of-window and the connection hangs instead of resetting.
        let rst = tcp_reset_for(seg(7, 4242, TCP_ACK, 100)).unwrap();
        assert_eq!(
            rst,
            TcpReset {
                seq: 4242,
                ack: 0,
                flags: TCP_RST
            }
        );
    }

    #[test]
    fn rst_segment_is_never_answered_so_two_rejecting_hosts_cannot_storm() {
        assert_eq!(tcp_reset_for(seg(1, 1, TCP_RST | TCP_ACK, 0)), None);
        assert_eq!(tcp_reset_for(seg(1, 0, TCP_RST, 0)), None);
    }

    #[test]
    fn tcp_options_are_not_counted_as_payload_in_the_rst_ack() {
        // A SYN with 20 bytes of options (data offset 10) has zero payload;
        // counting the options would ack seq+21 and the client would discard
        // the RST as acknowledging data it never sent.
        let mut buf = v4_tcp_in(TCP_SYN, 1000, 0, 40, 10);
        assert!(tcp_rst_in_place_v4(&mut buf, native_sum));
        assert_eq!(&buf[28..32], &1001u32.to_be_bytes());
    }

    #[test]
    fn broadcast_multicast_and_non_host_addresses_never_get_a_reply() {
        let host = [10, 0, 0, 1];
        for bad in [
            [255, 255, 255, 255],
            [224, 0, 0, 1],
            [239, 1, 1, 1],
            [240, 0, 0, 1],
            [0, 0, 0, 0],
            [127, 0, 0, 1],
        ] {
            assert!(!v4_reply_allowed(bad, host), "src {bad:?} would storm");
            assert!(!v4_reply_allowed(host, bad), "dst {bad:?} would storm");
        }
        assert!(v4_reply_allowed(CLIENT4, FRONT4));
    }

    #[test]
    fn v6_multicast_unspecified_and_loopback_never_get_a_reply() {
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        let mut mcast = [0u8; 16];
        mcast[0] = 0xff;
        mcast[1] = 0x02;
        mcast[15] = 1;
        for bad in [[0u8; 16], loopback, mcast] {
            assert!(!v6_reply_allowed(&bad, &FRONT6));
            assert!(!v6_reply_allowed(&CLIENT6, &bad));
        }
        assert!(v6_reply_allowed(&CLIENT6, &FRONT6));
    }

    #[test]
    fn only_non_first_fragments_are_excluded() {
        assert!(!v4_is_non_first_fragment(0x4000), "DF packet is replied to");
        assert!(
            !v4_is_non_first_fragment(0x2000),
            "first fragment (MF, offset 0) still has the L4 header"
        );
        assert!(
            v4_is_non_first_fragment(0x0001),
            "later fragments have no L4 header"
        );
        assert!(v4_is_non_first_fragment(0x2005));
    }

    #[test]
    fn ipv4_header_checksum_matches_the_well_known_vector() {
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&native_sum, &hdr, 0), 0xb861);
    }

    #[test]
    fn v4_syn_becomes_a_valid_rst_ack_from_the_front_to_the_client() {
        let mut out = v4_tcp_in(TCP_SYN, 1000, 0, 20, 5);
        assert!(tcp_rst_in_place_v4(&mut out, native_sum));
        assert!(verifies(&out[..20], &[]), "IP header checksum");
        assert!(
            verifies(&out[20..], &v4_pseudo(&FRONT4, &CLIENT4, 6, 20)),
            "TCP checksum: a client drops a RST that fails it and hangs"
        );
        assert_eq!(&out[2..4], &40u16.to_be_bytes());
        assert_eq!(&out[12..16], &FRONT4, "reply source is the front");
        assert_eq!(&out[16..20], &CLIENT4);
        assert_eq!(&out[20..22], &19100u16.to_be_bytes(), "front's port");
        assert_eq!(&out[22..24], &40000u16.to_be_bytes());
        assert_eq!(&out[24..28], &0u32.to_be_bytes());
        assert_eq!(&out[28..32], &1001u32.to_be_bytes());
        assert_eq!(out[33], TCP_RST | TCP_ACK);
    }

    #[test]
    fn v4_established_segment_gets_a_bare_rst_at_its_ack() {
        let mut out = v4_tcp_in(TCP_ACK, 9, 777, 120, 5);
        assert!(tcp_rst_in_place_v4(&mut out, native_sum));
        assert_eq!(&out[24..28], &777u32.to_be_bytes());
        assert_eq!(out[33], TCP_RST);
        assert!(verifies(&out[20..], &v4_pseudo(&FRONT4, &CLIENT4, 6, 20)));
    }

    #[test]
    fn v4_rst_never_answers_a_rst_or_a_broadcast_or_a_later_fragment() {
        let mut rst = v4_tcp_in(TCP_RST, 1, 0, 20, 5);
        assert!(!tcp_rst_in_place_v4(&mut rst, native_sum), "RST storm");
        let mut bcast = v4_tcp_in(TCP_SYN, 1, 0, 20, 5);
        bcast[12..16].copy_from_slice(&[255, 255, 255, 255]);
        assert!(
            !tcp_rst_in_place_v4(&mut bcast, native_sum),
            "broadcast storm"
        );
        let mut frag = v4_tcp_in(TCP_SYN, 1, 0, 20, 5);
        frag[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
        assert!(
            !tcp_rst_in_place_v4(&mut frag, native_sum),
            "no L4 header in a later fragment"
        );
    }

    #[test]
    fn v6_syn_becomes_a_valid_rst_ack_with_pseudo_header_checksum() {
        // IPv6 has no header checksum, so a wrong pseudo-header sum is the
        // only thing a client's stack would catch -- and drop the reset for.
        let mut out = v6_tcp_in(TCP_SYN, 9, 0, 20);
        assert!(tcp_rst_in_place_v6(&mut out, native_sum));
        assert!(verifies(&out[40..], &v6_pseudo(&FRONT6, &CLIENT6, 6, 20)));
        assert_eq!(&out[4..6], &20u16.to_be_bytes());
        assert_eq!(out[6], 6);
        assert_eq!(&out[8..24], &FRONT6);
        assert_eq!(&out[24..40], &CLIENT6);
        assert_eq!(&out[40..42], &443u16.to_be_bytes());
        assert_eq!(&out[44..48], &0u32.to_be_bytes());
        assert_eq!(&out[48..52], &10u32.to_be_bytes());
        assert_eq!(out[53], TCP_RST | TCP_ACK);
    }

    #[test]
    fn v6_rst_never_answers_a_rst_or_a_multicast_destination() {
        let mut rst = v6_tcp_in(TCP_RST, 1, 0, 20);
        assert!(!tcp_rst_in_place_v6(&mut rst, native_sum));
        let mut mcast = v6_tcp_in(TCP_SYN, 1, 0, 20);
        mcast[8] = 0xff;
        assert!(!tcp_rst_in_place_v6(&mut mcast, native_sum));
    }

    fn v4_udp_in() -> [u8; ICMP_UNREACH_V4_LEN] {
        let mut b = [0xffu8; ICMP_UNREACH_V4_LEN];
        // Exchanged addresses where the reply's header takes them from.
        b[12..16].copy_from_slice(&FRONT4);
        b[16..20].copy_from_slice(&CLIENT4);
        b[28..48].copy_from_slice(&[
            0x45, 0, 0, 40, 0x12, 0x34, 0x40, 0, 64, 17, 0xab, 0xcd, 203, 0, 113, 2, 203, 0, 113, 1,
        ]);
        b[48..56].copy_from_slice(&[0x9c, 0x40, 0x4a, 0x9c, 0, 20, 0xde, 0xad]);
        b
    }

    #[test]
    fn v4_udp_gets_port_unreachable_quoting_the_offender() {
        let mut out = v4_udp_in();
        let quote: Vec<u8> = out[28..].to_vec();
        assert!(icmp_unreachable_in_place_v4(&mut out, native_sum));
        assert!(verifies(&out[..20], &[]), "IP header checksum");
        assert!(verifies(&out[20..], &[]), "ICMP checksum");
        assert_eq!((out[20], out[21]), (3, 3), "type/code port unreachable");
        assert_eq!(
            &out[28..],
            &quote[..],
            "the client matches the error by its quote"
        );
        assert_eq!(&out[12..16], &FRONT4);
        assert_eq!(&out[16..20], &CLIENT4);
        assert_eq!(out[9], 1);
        assert_eq!(&out[2..4], &56u16.to_be_bytes());
    }

    #[test]
    fn v4_icmp_is_not_sent_for_multicast_sources_or_later_fragments() {
        let mut mcast = v4_udp_in();
        mcast[16..20].copy_from_slice(&[224, 0, 0, 5]);
        assert!(!icmp_unreachable_in_place_v4(&mut mcast, native_sum));
        let mut frag = v4_udp_in();
        frag[34..36].copy_from_slice(&0x0008u16.to_be_bytes());
        assert!(!icmp_unreachable_in_place_v4(&mut frag, native_sum));
    }

    fn v6_udp_in() -> [u8; ICMP6_UNREACH_LEN] {
        let mut b = [0xffu8; ICMP6_UNREACH_LEN];
        b[8..24].copy_from_slice(&FRONT6);
        b[24..40].copy_from_slice(&CLIENT6);
        b[48..56].copy_from_slice(&[0x60, 0, 0, 0, 0, 12, 17, 64]);
        b[56..72].copy_from_slice(&CLIENT6);
        b[72..88].copy_from_slice(&FRONT6);
        b[88..96].copy_from_slice(&[0x9c, 0x40, 0x4a, 0x9c, 0, 12, 0xbe, 0xef]);
        b
    }

    #[test]
    fn v6_udp_gets_port_unreachable_with_pseudo_header_checksum() {
        let mut out = v6_udp_in();
        let quote: Vec<u8> = out[48..].to_vec();
        assert!(icmp6_unreachable_in_place(&mut out, native_sum));
        assert!(verifies(&out[40..], &v6_pseudo(&FRONT6, &CLIENT6, 58, 56)));
        assert_eq!((out[40], out[41]), (1, 4), "type/code port unreachable");
        assert_eq!(&out[48..], &quote[..]);
        assert_eq!(&out[8..24], &FRONT6);
        assert_eq!(&out[24..40], &CLIENT6);
        assert_eq!(&out[4..6], &56u16.to_be_bytes());
        assert!(out.len() <= 1280, "RFC 4443 minimum-MTU bound");
    }

    #[test]
    fn v6_icmp_is_not_sent_to_a_multicast_destination() {
        let mut mcast = v6_udp_in();
        mcast[8] = 0xff;
        assert!(!icmp6_unreachable_in_place(&mut mcast, native_sum));
    }

    #[test]
    fn stale_buffer_bytes_never_leak_into_a_reply() {
        // The dataplane leaves the buffer's tail uninitialised; a field the
        // builder skipped would ship stack garbage and fail the client's
        // checksum. Output must not depend on the filler.
        let mut a = v4_tcp_in(TCP_SYN, 5, 0, 20, 5);
        let mut b = a;
        a[34..].fill(0x00);
        b[34..].fill(0xa5);
        assert!(tcp_rst_in_place_v4(&mut a, native_sum) && tcp_rst_in_place_v4(&mut b, native_sum));
        assert_eq!(a, b);

        let mut a = v6_tcp_in(TCP_SYN, 5, 0, 20);
        let mut b = a;
        a[54..].fill(0x00);
        b[54..].fill(0xa5);
        assert!(tcp_rst_in_place_v6(&mut a, native_sum) && tcp_rst_in_place_v6(&mut b, native_sum));
        assert_eq!(a, b);

        let mut a = v4_udp_in();
        let mut b = a;
        // Everything the caller does not load: the header fields around the
        // exchanged addresses, and the ICMP header.
        a[..12].fill(0x00);
        a[20..28].fill(0x00);
        b[..12].fill(0xa5);
        b[20..28].fill(0xa5);
        assert!(
            icmp_unreachable_in_place_v4(&mut a, native_sum)
                && icmp_unreachable_in_place_v4(&mut b, native_sum)
        );
        assert_eq!(a, b);

        let mut a = v6_udp_in();
        let mut b = a;
        a[..8].fill(0x00);
        a[40..48].fill(0x00);
        b[..8].fill(0xa5);
        b[40..48].fill(0xa5);
        assert!(
            icmp6_unreachable_in_place(&mut a, native_sum)
                && icmp6_unreachable_in_place(&mut b, native_sum)
        );
        assert_eq!(a, b);
    }

    #[test]
    fn checksum_verifier_rejects_a_corrupted_reply() {
        // Guards the test oracle itself: if `verifies` accepted anything, the
        // checksum tests above would pass vacuously.
        let mut out = v4_tcp_in(TCP_SYN, 1, 0, 20, 5);
        assert!(tcp_rst_in_place_v4(&mut out, native_sum));
        out[30] ^= 1;
        assert!(!verifies(&out[20..], &v4_pseudo(&FRONT4, &CLIENT4, 6, 20)));
    }
}
