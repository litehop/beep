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
//! copy of the packet or spill unrolled-loop state (hence the `black_box` and
//! volatile writes below, which stop LLVM from unrolling or from fusing byte
//! runs into `memset`/`memcpy` calls -- each such call costs a 32-byte frame
//! in the verifier's accounting).

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

/// One's-complement sum of big-endian 16-bit words, not yet folded. The
/// length is a compile-time constant at every call site, so LLVM unrolls the
/// loop (the verifier cannot bound a rolled one: it widens the counter), and
/// the volatile reads keep the loads in order -- hoisted ahead of the adds
/// they would spill a dozen 8-byte registers to the BPF stack.
#[inline(always)]
fn sum_words(data: &[u8], mut acc: u32) -> u32 {
    for i in 0..data.len() / 2 {
        // SAFETY: `2 * i + 1 < data.len()`.
        let (hi, lo) = unsafe {
            (
                core::ptr::read_volatile(&data[2 * i]),
                core::ptr::read_volatile(&data[2 * i + 1]),
            )
        };
        acc += (u32::from(hi) << 8) | u32::from(lo);
    }
    acc
}

#[inline(always)]
fn fold(mut acc: u32) -> u16 {
    acc = (acc & 0xffff) + (acc >> 16);
    acc = (acc & 0xffff) + (acc >> 16);
    !(acc as u16)
}

/// RFC 1071 checksum of `data` (even length) seeded with `init`, e.g. a
/// pseudo-header sum.
#[inline(always)]
pub fn internet_checksum(data: &[u8], init: u32) -> u16 {
    fold(sum_words(data, init))
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

/// `buf[to..to + n] = buf[from..from + n]` (disjoint ranges). Volatile in
/// both directions: LLVM would otherwise turn it into a `memcpy` call, or
/// hoist all the loads ahead of the stores and spill them to the BPF stack.
#[inline(always)]
fn copy_within_volatile(buf: &mut [u8], to: usize, from: usize, n: usize) {
    for i in 0..n {
        // SAFETY: both indices are in bounds of live `u8`s.
        unsafe {
            let b = core::ptr::read_volatile(&buf[from + i]);
            core::ptr::write_volatile(&mut buf[to + i], b);
        }
    }
}

/// Exchanges `buf[a..a + n]` and `buf[b..b + n]` (disjoint ranges); volatile
/// for the same reasons as [`copy_within_volatile`].
#[inline(always)]
fn swap_ranges_volatile(buf: &mut [u8], a: usize, b: usize, n: usize) {
    for i in 0..n {
        // SAFETY: both indices are in bounds of live `u8`s.
        unsafe {
            let x = core::ptr::read_volatile(&buf[a + i]);
            let y = core::ptr::read_volatile(&buf[b + i]);
            core::ptr::write_volatile(&mut buf[a + i], y);
            core::ptr::write_volatile(&mut buf[b + i], x);
        }
    }
}

/// Pseudo-header sum for an IPv4 L4 segment; `addrs` is `src || dst`.
#[inline(always)]
fn v4_pseudo_sum(addrs: &[u8], proto: u8, len: u16) -> u32 {
    sum_words(addrs, 0) + u32::from(proto) + u32::from(len)
}

/// Pseudo-header sum for an IPv6 L4 segment; `addrs` is `src || dst`.
#[inline(always)]
fn v6_pseudo_sum(addrs: &[u8], next: u8, len: u32) -> u32 {
    sum_words(addrs, 0) + (len >> 16) + (len & 0xffff) + u32::from(next)
}

/// Overwrites the first 20 bytes of `buf` with a complete IPv4 header
/// (checksum included): DF set, id 0, TTL 64. The reply's source and
/// destination addresses are read from `buf` at `src_at`/`dst_at` (possibly
/// inside the header being overwritten) right here rather than carried in
/// locals from earlier checks: held across the checksum loops they would be
/// spilled to the BPF stack.
#[inline(always)]
fn write_ipv4_header(
    buf: &mut [u8],
    total_len: u16,
    tos: u8,
    proto: u8,
    src_at: usize,
    dst_at: usize,
) {
    // SAFETY: all indices are in bounds of live `u8`s.
    let (s, d) = unsafe {
        (
            [
                core::ptr::read_volatile(&buf[src_at]),
                core::ptr::read_volatile(&buf[src_at + 1]),
                core::ptr::read_volatile(&buf[src_at + 2]),
                core::ptr::read_volatile(&buf[src_at + 3]),
            ],
            [
                core::ptr::read_volatile(&buf[dst_at]),
                core::ptr::read_volatile(&buf[dst_at + 1]),
                core::ptr::read_volatile(&buf[dst_at + 2]),
                core::ptr::read_volatile(&buf[dst_at + 3]),
            ],
        )
    };
    buf[0] = 0x45;
    buf[1] = tos;
    put16(buf, 2, total_len);
    put16(buf, 4, 0);
    put16(buf, 6, 0x4000);
    buf[8] = REPLY_TTL;
    buf[9] = proto;
    put16(buf, 10, 0);
    buf[12..16].copy_from_slice(&s);
    buf[16..20].copy_from_slice(&d);
    let csum = internet_checksum(&buf[..20], 0);
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

/// Turns the offending IPv4 TCP segment in `buf` ([`TCP_RST_V4_IN_LEN`]
/// bytes loaded at the front; the rest is overwritten) into the RST that
/// answers it, from the front back to the client. The IP header must have no
/// options. Returns false -- `buf` is then unspecified and nothing may be
/// sent -- for a segment that is itself a RST, a non-first fragment, or
/// addresses that must never be answered.
#[inline(always)]
pub fn tcp_rst_in_place_v4(buf: &mut [u8; TCP_RST_V4_LEN]) -> bool {
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
    // The sum is order-independent, so the pre-swap `src || dst` serves.
    let pseudo = v4_pseudo_sum(&buf[12..20], IPPROTO_TCP, 20);
    let csum = internet_checksum(&buf[20..40], pseudo);
    put16(buf, 36, csum);
    write_ipv4_header(buf, TCP_RST_V4_LEN as u16, 0, IPPROTO_TCP, 16, 12);
    true
}

/// IPv6 counterpart of [`tcp_rst_in_place_v4`] ([`TCP_RST_V6_IN_LEN`] bytes
/// loaded; no extension headers).
#[inline(always)]
pub fn tcp_rst_in_place_v6(buf: &mut [u8; TCP_RST_V6_LEN]) -> bool {
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
    swap_ranges_volatile(buf, 8, 24, 16);
    write_ipv6_fields(buf, 20, IPPROTO_TCP);
    let pseudo = v6_pseudo_sum(&buf[8..40], IPPROTO_TCP, 20);
    let csum = internet_checksum(&buf[40..60], pseudo);
    put16(buf, 56, csum);
    true
}

/// Builds the ICMP destination-unreachable / port-unreachable (type 3, code
/// 3) reply to the IPv4 packet whose first [`ICMP_QUOTE_V4_LEN`] bytes the
/// caller loaded at `buf[28..]`. Returns false when no reply is due (see
/// [`tcp_rst_in_place_v4`]).
#[inline(always)]
pub fn icmp_unreachable_in_place_v4(buf: &mut [u8; ICMP_UNREACH_V4_LEN]) -> bool {
    let src = [buf[40], buf[41], buf[42], buf[43]];
    let dst = [buf[44], buf[45], buf[46], buf[47]];
    if v4_is_non_first_fragment(get16(buf, 34)) || !v4_reply_allowed(src, dst) {
        return false;
    }
    put16(buf, 20, 0x0303);
    zero(buf, 22, 6);
    let csum = internet_checksum(&buf[20..ICMP_UNREACH_V4_LEN], 0);
    put16(buf, 22, csum);
    // Internetwork control precedence (RFC 1812 4.3.2.5).
    write_ipv4_header(buf, ICMP_UNREACH_V4_LEN as u16, 0xc0, IPPROTO_ICMP, 44, 40);
    true
}

/// ICMPv6 destination-unreachable / port-unreachable (type 1, code 4) reply
/// to the IPv6 packet whose first [`ICMP6_QUOTE_LEN`] bytes the caller loaded
/// at `buf[48..]`.
#[inline(always)]
pub fn icmp6_unreachable_in_place(buf: &mut [u8; ICMP6_UNREACH_LEN]) -> bool {
    // Quoted source at 56..72, quoted destination at 72..88.
    if !v6_reply_allowed(&buf[56..72], &buf[72..88]) {
        return false;
    }
    copy_within_volatile(buf, 8, 72, 16);
    copy_within_volatile(buf, 24, 56, 16);
    write_ipv6_fields(buf, (ICMP6_UNREACH_LEN - 40) as u16, IPPROTO_ICMPV6);
    put16(buf, 40, 0x0104);
    zero(buf, 42, 6);
    let pseudo = v6_pseudo_sum(&buf[8..40], IPPROTO_ICMPV6, (ICMP6_UNREACH_LEN - 40) as u32);
    let csum = internet_checksum(&buf[40..ICMP6_UNREACH_LEN], pseudo);
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

    /// Offending client packet: IPv4 header + 14 TCP bytes, then 0xff filler
    /// standing in for whatever the stack held before the reply was built.
    fn v4_tcp_in(flags: u8, seq: u32, ack: u32, tcp_len: u16, doff: u8) -> [u8; TCP_RST_V4_LEN] {
        let mut b = [0xffu8; TCP_RST_V4_LEN];
        b[..20].copy_from_slice(&[
            0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 203, 0, 113, 2, 203, 0, 113, 1,
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
        b[8..24].copy_from_slice(&CLIENT6);
        b[24..40].copy_from_slice(&FRONT6);
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
        assert!(tcp_rst_in_place_v4(&mut buf));
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
        assert_eq!(internet_checksum(&hdr, 0), 0xb861);
    }

    #[test]
    fn v4_syn_becomes_a_valid_rst_ack_from_the_front_to_the_client() {
        let mut out = v4_tcp_in(TCP_SYN, 1000, 0, 20, 5);
        assert!(tcp_rst_in_place_v4(&mut out));
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
        assert!(tcp_rst_in_place_v4(&mut out));
        assert_eq!(&out[24..28], &777u32.to_be_bytes());
        assert_eq!(out[33], TCP_RST);
        assert!(verifies(&out[20..], &v4_pseudo(&FRONT4, &CLIENT4, 6, 20)));
    }

    #[test]
    fn v4_rst_never_answers_a_rst_or_a_broadcast_or_a_later_fragment() {
        let mut rst = v4_tcp_in(TCP_RST, 1, 0, 20, 5);
        assert!(!tcp_rst_in_place_v4(&mut rst), "RST storm");
        let mut bcast = v4_tcp_in(TCP_SYN, 1, 0, 20, 5);
        bcast[16..20].copy_from_slice(&[255, 255, 255, 255]);
        assert!(!tcp_rst_in_place_v4(&mut bcast), "broadcast storm");
        let mut frag = v4_tcp_in(TCP_SYN, 1, 0, 20, 5);
        frag[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
        assert!(
            !tcp_rst_in_place_v4(&mut frag),
            "no L4 header in a later fragment"
        );
    }

    #[test]
    fn v6_syn_becomes_a_valid_rst_ack_with_pseudo_header_checksum() {
        // IPv6 has no header checksum, so a wrong pseudo-header sum is the
        // only thing a client's stack would catch -- and drop the reset for.
        let mut out = v6_tcp_in(TCP_SYN, 9, 0, 20);
        assert!(tcp_rst_in_place_v6(&mut out));
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
        assert!(!tcp_rst_in_place_v6(&mut rst));
        let mut mcast = v6_tcp_in(TCP_SYN, 1, 0, 20);
        mcast[24] = 0xff;
        assert!(!tcp_rst_in_place_v6(&mut mcast));
    }

    fn v4_udp_in() -> [u8; ICMP_UNREACH_V4_LEN] {
        let mut b = [0xffu8; ICMP_UNREACH_V4_LEN];
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
        assert!(icmp_unreachable_in_place_v4(&mut out));
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
        mcast[40..44].copy_from_slice(&[224, 0, 0, 5]);
        assert!(!icmp_unreachable_in_place_v4(&mut mcast));
        let mut frag = v4_udp_in();
        frag[34..36].copy_from_slice(&0x0008u16.to_be_bytes());
        assert!(!icmp_unreachable_in_place_v4(&mut frag));
    }

    fn v6_udp_in() -> [u8; ICMP6_UNREACH_LEN] {
        let mut b = [0xffu8; ICMP6_UNREACH_LEN];
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
        assert!(icmp6_unreachable_in_place(&mut out));
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
        mcast[72] = 0xff;
        assert!(!icmp6_unreachable_in_place(&mut mcast));
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
        assert!(tcp_rst_in_place_v4(&mut a) && tcp_rst_in_place_v4(&mut b));
        assert_eq!(a, b);

        let mut a = v6_tcp_in(TCP_SYN, 5, 0, 20);
        let mut b = a;
        a[54..].fill(0x00);
        b[54..].fill(0xa5);
        assert!(tcp_rst_in_place_v6(&mut a) && tcp_rst_in_place_v6(&mut b));
        assert_eq!(a, b);

        let mut a = v4_udp_in();
        let mut b = a;
        a[..28].fill(0x00);
        b[..28].fill(0xa5);
        assert!(icmp_unreachable_in_place_v4(&mut a) && icmp_unreachable_in_place_v4(&mut b));
        assert_eq!(a, b);

        let mut a = v6_udp_in();
        let mut b = a;
        a[..48].fill(0x00);
        b[..48].fill(0xa5);
        assert!(icmp6_unreachable_in_place(&mut a) && icmp6_unreachable_in_place(&mut b));
        assert_eq!(a, b);
    }

    #[test]
    fn checksum_verifier_rejects_a_corrupted_reply() {
        // Guards the test oracle itself: if `verifies` accepted anything, the
        // checksum tests above would pass vacuously.
        let mut out = v4_tcp_in(TCP_SYN, 1, 0, 20, 5);
        assert!(tcp_rst_in_place_v4(&mut out));
        out[30] ^= 1;
        assert!(!verifies(&out[20..], &v4_pseudo(&FRONT4, &CLIENT4, 6, 20)));
    }
}
