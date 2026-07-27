//! Generic-netlink message encoding/decoding (platform independent).
//!
//! Netlink uses host byte order, so we encode with native-endian integers.
//! Layout:
//!   * `nlmsghdr`  : len(u32) type(u16) flags(u16) seq(u32) pid(u32)   (16 bytes)
//!   * `genlmsghdr`: cmd(u8) version(u8) reserved(u16)                 (4 bytes)
//!   * attributes : `nlattr` { len(u16) type(u16) } + data, padded to 4 bytes.

// netlink message flags
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_DUMP: u16 = 0x0300; // ROOT | MATCH

// netlink message types
pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;
pub const NLMSG_MIN_TYPE: u16 = 0x10;

// generic netlink control family
pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

pub const NLA_F_NESTED: u16 = 0x8000;

/// Round a length up to the 4-byte netlink alignment.
pub fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// A single netlink attribute (TLV).
#[derive(Clone, Debug)]
pub struct Attr {
    pub typ: u16,
    pub data: Vec<u8>,
}

impl Attr {
    pub fn u8(typ: u16, v: u8) -> Attr {
        Attr { typ, data: vec![v] }
    }
    pub fn u32(typ: u16, v: u32) -> Attr {
        Attr {
            typ,
            data: v.to_ne_bytes().to_vec(),
        }
    }
    pub fn u16v(typ: u16, v: u16) -> Attr {
        Attr {
            typ,
            data: v.to_ne_bytes().to_vec(),
        }
    }
    /// A null-terminated string attribute (generic-netlink convention).
    pub fn string(typ: u16, s: &str) -> Attr {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        Attr { typ, data }
    }
    pub fn bytes(typ: u16, b: &[u8]) -> Attr {
        Attr {
            typ,
            data: b.to_vec(),
        }
    }
    pub fn nested(typ: u16, attrs: &[Attr]) -> Attr {
        let mut data = Vec::new();
        for a in attrs {
            a.encode(&mut data);
        }
        Attr {
            typ: typ | NLA_F_NESTED,
            data,
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        let len = 4 + self.data.len();
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&self.typ.to_ne_bytes());
        out.extend_from_slice(&self.data);
        // pad to alignment
        out.resize(nla_align(out.len()), 0);
    }
}

/// A generic-netlink request message.
pub struct GenlMessage {
    pub family: u16,
    pub cmd: u8,
    pub version: u8,
    pub flags: u16,
    pub seq: u32,
    pub attrs: Vec<Attr>,
}

impl GenlMessage {
    pub fn new(family: u16, cmd: u8, flags: u16, seq: u32) -> GenlMessage {
        GenlMessage {
            family,
            cmd,
            version: 1,
            flags: flags | NLM_F_REQUEST,
            seq,
            attrs: Vec::new(),
        }
    }

    pub fn attr(mut self, a: Attr) -> GenlMessage {
        self.attrs.push(a);
        self
    }

    /// Serialize to a wire buffer (the `nlmsg_len` is filled in).
    pub fn to_bytes(&self, pid: u32) -> Vec<u8> {
        // genlmsghdr + attributes
        let mut body = Vec::new();
        body.push(self.cmd);
        body.push(self.version);
        body.extend_from_slice(&0u16.to_ne_bytes()); // reserved
        for a in &self.attrs {
            a.encode(&mut body);
        }

        let total = 16 + body.len();
        let mut buf = Vec::with_capacity(nla_align(total));
        buf.extend_from_slice(&(total as u32).to_ne_bytes());
        buf.extend_from_slice(&self.family.to_ne_bytes());
        buf.extend_from_slice(&self.flags.to_ne_bytes());
        buf.extend_from_slice(&self.seq.to_ne_bytes());
        buf.extend_from_slice(&pid.to_ne_bytes());
        buf.extend_from_slice(&body);
        buf
    }
}

/// A parsed top-level netlink message.
#[derive(Debug)]
pub struct ParsedNlmsg<'a> {
    pub typ: u16,
    pub flags: u16,
    pub seq: u32,
    /// Everything after the 16-byte `nlmsghdr` (for genl: genlmsghdr + attrs).
    pub payload: &'a [u8],
}

impl ParsedNlmsg<'_> {
    /// The generic-netlink command (first byte of the payload).
    pub fn genl_cmd(&self) -> Option<u8> {
        self.payload.first().copied()
    }
    /// The attribute area (payload after the 4-byte genlmsghdr).
    pub fn genl_attrs(&self) -> &[u8] {
        if self.payload.len() >= 4 {
            &self.payload[4..]
        } else {
            &[]
        }
    }
    /// For NLMSG_ERROR: the (negated) errno in the first 4 bytes.
    pub fn error_code(&self) -> Option<i32> {
        if self.typ == NLMSG_ERROR && self.payload.len() >= 4 {
            Some(i32::from_ne_bytes([
                self.payload[0],
                self.payload[1],
                self.payload[2],
                self.payload[3],
            ]))
        } else {
            None
        }
    }
}

pub struct Messages<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Iterator for Messages<'a> {
    type Item = ParsedNlmsg<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.off + 16 > self.buf.len() {
            return None;
        }
        let off = self.off;
        let len = u32::from_ne_bytes([
            self.buf[off],
            self.buf[off + 1],
            self.buf[off + 2],
            self.buf[off + 3],
        ]) as usize;
        if len < 16 || off + len > self.buf.len() {
            self.off = self.buf.len();
            return None;
        }
        let typ = u16::from_ne_bytes([self.buf[off + 4], self.buf[off + 5]]);
        let flags = u16::from_ne_bytes([self.buf[off + 6], self.buf[off + 7]]);
        let seq = u32::from_ne_bytes([
            self.buf[off + 8],
            self.buf[off + 9],
            self.buf[off + 10],
            self.buf[off + 11],
        ]);
        self.off += nla_align(len);
        Some(ParsedNlmsg {
            typ,
            flags,
            seq,
            payload: &self.buf[off + 16..off + len],
        })
    }
}

/// Iterate the netlink messages packed in a received buffer without allocating.
pub fn messages(buf: &[u8]) -> Messages<'_> {
    Messages { buf, off: 0 }
}

/// Parse packed messages into an owned index. Receive hot paths should use
/// [`messages`] when they only need one forward pass.
pub fn parse_messages(buf: &[u8]) -> Vec<ParsedNlmsg<'_>> {
    messages(buf).collect()
}

/// Parse attributes into reusable caller-owned storage.
pub fn parse_attrs_into<'a>(buf: &'a [u8], out: &mut Vec<(u16, &'a [u8])>) {
    out.clear();
    let mut off = 0;
    while off + 4 <= buf.len() {
        let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        let typ = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]) & !NLA_F_NESTED;
        if len < 4 || off + len > buf.len() {
            break;
        }
        out.push((typ, &buf[off + 4..off + len]));
        off += nla_align(len);
    }
}

/// Parse a flat attribute area into `(type, data)` pairs (nesting flag stripped).
pub fn parse_attrs(buf: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    parse_attrs_into(buf, &mut out);
    out
}

/// Look up one attribute by type.
pub fn find_attr<'a>(attrs: &[(u16, &'a [u8])], typ: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(t, _)| *t == typ).map(|(_, d)| *d)
}

/// Convert a 2.4 GHz channel number to its centre frequency in MHz.
pub fn freq_for_channel(ch: u8) -> u32 {
    match ch {
        14 => 2484,
        n if (1..=13).contains(&n) => 2407 + 5 * n as u32,
        // 5 GHz: ch 36..=165
        n => 5000 + 5 * n as u32,
    }
}

/// Convert an nl80211 operating frequency to its 802.11 channel number.
///
/// The band is intentionally determined by the frequency at the call site:
/// channel 1 is valid in both 2.4 and 6 GHz.
pub fn channel_for_freq(freq: u32) -> Option<u8> {
    let channel = match freq {
        2484 => 14,
        2412..=2472 if (freq - 2407).is_multiple_of(5) => (freq - 2407) / 5,
        5000..=5895 if (freq - 5000).is_multiple_of(5) => (freq - 5000) / 5,
        5935 => 2,
        5955..=7115 if (freq - 5950).is_multiple_of(5) => (freq - 5950) / 5,
        _ => return None,
    };
    u8::try_from(channel).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn getfamily_request_roundtrips() {
        let msg = GenlMessage::new(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, NLM_F_ACK, 42)
            .attr(Attr::string(CTRL_ATTR_FAMILY_NAME, "nl80211"));
        let bytes = msg.to_bytes(0);

        let parsed = parse_messages(&bytes);
        assert_eq!(parsed.len(), 1);
        let m = &parsed[0];
        assert_eq!(m.typ, GENL_ID_CTRL);
        assert_eq!(m.seq, 42);
        assert_eq!(m.genl_cmd(), Some(CTRL_CMD_GETFAMILY));
        let attrs = parse_attrs(m.genl_attrs());
        let name = find_attr(&attrs, CTRL_ATTR_FAMILY_NAME).unwrap();
        assert_eq!(&name[..7], b"nl80211");
        assert_eq!(name[7], 0, "null terminated");
    }

    #[test]
    fn parse_family_response_with_mcast_groups() {
        // Hand-build a CTRL_NEWFAMILY-style response: FAMILY_ID + nested
        // MCAST_GROUPS containing one group {NAME="mlme", ID=7}.
        let group = Attr::nested(
            1, // index within MCAST_GROUPS
            &[
                Attr::u32(CTRL_ATTR_MCAST_GRP_ID, 7),
                Attr::string(CTRL_ATTR_MCAST_GRP_NAME, "mlme"),
            ],
        );
        let msg = GenlMessage::new(GENL_ID_CTRL, 1, 0, 1)
            .attr(Attr::u16v(CTRL_ATTR_FAMILY_ID, 0x1c))
            .attr(Attr::nested(CTRL_ATTR_MCAST_GROUPS, &[group]));
        let bytes = msg.to_bytes(0);

        let parsed = parse_messages(&bytes);
        let attrs = parse_attrs(parsed[0].genl_attrs());
        let fid = find_attr(&attrs, CTRL_ATTR_FAMILY_ID).unwrap();
        assert_eq!(u16::from_ne_bytes([fid[0], fid[1]]), 0x1c);

        let groups = find_attr(&attrs, CTRL_ATTR_MCAST_GROUPS).unwrap();
        // groups is a list of nested groups; each is an attr whose data is the
        // group's attrs.
        let group_list = parse_attrs(groups);
        let (_, grp0) = group_list[0];
        let grp_attrs = parse_attrs(grp0);
        let id = find_attr(&grp_attrs, CTRL_ATTR_MCAST_GRP_ID).unwrap();
        let name = find_attr(&grp_attrs, CTRL_ATTR_MCAST_GRP_NAME).unwrap();
        assert_eq!(u32::from_ne_bytes([id[0], id[1], id[2], id[3]]), 7);
        assert_eq!(&name[..4], b"mlme");
    }

    #[test]
    fn channel_to_freq() {
        assert_eq!(freq_for_channel(1), 2412);
        assert_eq!(freq_for_channel(6), 2437);
        assert_eq!(freq_for_channel(11), 2462);
        assert_eq!(freq_for_channel(14), 2484);
        assert_eq!(freq_for_channel(36), 5180);
    }

    #[test]
    fn frequency_to_channel_across_wifi_bands() {
        assert_eq!(channel_for_freq(2412), Some(1));
        assert_eq!(channel_for_freq(2484), Some(14));
        assert_eq!(channel_for_freq(5500), Some(100));
        assert_eq!(channel_for_freq(5955), Some(1));
        assert_eq!(channel_for_freq(7115), Some(233));
        assert_eq!(channel_for_freq(5501), None);
    }
}
