use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum KeyRole {
    Pairwise,
    Group,
    Integrity,
    BeaconIntegrity,
}

pub(super) struct KeyInstall<'a> {
    pub(super) ifindex: u32,
    pub(super) peer: Option<&'a [u8; 6]>,
    pub(super) index: u8,
    pub(super) material: &'a [u8],
    pub(super) cipher: u32,
    pub(super) sequence: Option<&'a [u8]>,
    pub(super) link_id: Option<u8>,
    pub(super) vlan_id: Option<u16>,
    pub(super) role: KeyRole,
}

impl<'a> KeyInstall<'a> {
    pub(super) fn pairwise(
        ifindex: u32,
        peer: &'a [u8; 6],
        material: &'a [u8],
        cipher: u32,
    ) -> Self {
        Self {
            ifindex,
            peer: Some(peer),
            index: 0,
            material,
            cipher,
            sequence: None,
            link_id: None,
            vlan_id: None,
            role: KeyRole::Pairwise,
        }
    }

    pub(super) fn group(ifindex: u32, index: u8, material: &'a [u8], link_id: Option<u8>) -> Self {
        Self {
            ifindex,
            peer: None,
            index,
            material,
            cipher: WLAN_CIPHER_SUITE_CCMP,
            sequence: None,
            link_id,
            vlan_id: None,
            role: KeyRole::Group,
        }
    }

    pub(super) fn integrity(
        ifindex: u32,
        index: u8,
        material: &'a [u8],
        _sequence: &'a [u8],
        link_id: Option<u8>,
        beacon: bool,
    ) -> Self {
        Self {
            ifindex,
            peer: None,
            index,
            material,
            cipher: WLAN_CIPHER_SUITE_BIP_CMAC_128,
            // A freshly installed IGTK has no receive sequence counter to
            // restore. driver_nl80211 omits NL80211_KEY_SEQ in this path.
            sequence: None,
            link_id,
            vlan_id: None,
            role: if beacon {
                KeyRole::BeaconIntegrity
            } else {
                KeyRole::Integrity
            },
        }
    }

    pub(super) fn with_vlan_offload(mut self, vlan_id: u32, enabled: bool) -> Self {
        self.vlan_id = (enabled && vlan_id != 0).then_some(vlan_id as u16);
        self
    }
}

pub(super) fn new_key_message(family: u16, seq: u32, key: &KeyInstall<'_>) -> GenlMessage {
    let mut attributes = vec![
        Attr::bytes(NL80211_KEY_DATA, key.material),
        Attr::u32(NL80211_KEY_CIPHER, key.cipher),
    ];
    if let Some(sequence) = key.sequence {
        attributes.push(Attr::bytes(NL80211_KEY_SEQ, sequence));
    }
    attributes.push(Attr::u8(NL80211_KEY_IDX, key.index));

    let mut message = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, key.ifindex));
    if let Some(peer) = key.peer {
        message = message.attr(Attr::bytes(NL80211_ATTR_MAC, peer));
    }
    message = message.attr(Attr::nested_unflagged(NL80211_ATTR_KEY, &attributes));
    if let Some(vlan_id) = key.vlan_id {
        message = message.attr(Attr::u16v(NL80211_ATTR_VLAN_ID, vlan_id));
    }
    if let Some(link_id) = key.link_id {
        message = message.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    message
}

pub(super) fn default_key_message(
    family: u16,
    seq: u32,
    key: &KeyInstall<'_>,
) -> Option<GenlMessage> {
    let role = match key.role {
        KeyRole::Pairwise => return None,
        KeyRole::Group => default_multicast_key_attr(key.index),
        KeyRole::Integrity => Attr::nested_unflagged(
            NL80211_ATTR_KEY,
            &[
                Attr::u8(NL80211_KEY_IDX, key.index),
                Attr::bytes(NL80211_KEY_DEFAULT_MGMT, &[]),
                Attr::nested(
                    NL80211_KEY_DEFAULT_TYPES,
                    &[Attr::bytes(NL80211_KEY_DEFAULT_TYPE_MULTICAST, &[])],
                ),
            ],
        ),
        KeyRole::BeaconIntegrity => Attr::nested_unflagged(
            NL80211_ATTR_KEY,
            &[
                Attr::u8(NL80211_KEY_IDX, key.index),
                Attr::bytes(NL80211_KEY_DEFAULT_BEACON, &[]),
                Attr::nested(
                    NL80211_KEY_DEFAULT_TYPES,
                    &[Attr::bytes(NL80211_KEY_DEFAULT_TYPE_MULTICAST, &[])],
                ),
            ],
        ),
    };
    let mut message = GenlMessage::new(family, NL80211_CMD_SET_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, key.ifindex))
        .attr(role);
    if let Some(vlan_id) = key.vlan_id {
        message = message.attr(Attr::u16v(NL80211_ATTR_VLAN_ID, vlan_id));
    }
    if let Some(link_id) = key.link_id {
        message = message.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    Some(message)
}

pub(super) fn nl_install_key(sock: &mut NetlinkSocket, family: u16, key: KeyInstall<'_>) -> bool {
    let seq = sock.next_seq();
    if let Err(error) = sock.request_ack(new_key_message(family, seq, &key)) {
        eprintln!(
            "netlink AP: NEW_KEY index={} role={:?} failed: {error}",
            key.index, key.role
        );
        return false;
    }

    let seq = sock.next_seq();
    let Some(default) = default_key_message(family, seq, &key) else {
        return true;
    };
    if let Err(error) = sock.request_ack(default) {
        eprintln!(
            "netlink AP: SET_KEY index={} role={:?} failed: {error}",
            key.index, key.role
        );
        return false;
    }
    true
}

pub(super) fn get_key_message(family: u16, seq: u32, ifindex: u32, index: u8) -> GenlMessage {
    // driver_nl80211 uses the legacy, top-level KEY_IDX for GET_KEY. This is
    // intentionally different from NEW_KEY/SET_KEY, whose key attributes live
    // inside NL80211_ATTR_KEY.
    GenlMessage::new(family, NL80211_CMD_GET_KEY, msg::NLM_F_ACK, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_KEY_IDX, index))
}

/// Read the driver's current 48-bit packet number for one group key.
///
/// Linux returns NL80211_ATTR_KEY_SEQ as PN0..PN5. Querying the AP_VLAN rather
/// than the base AP is important: every dynamic VLAN owns an independent WPA
/// group and therefore an independent GTK/IGTK sequence space.
pub(super) fn nl_get_key_sequence(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    index: u8,
) -> io::Result<[u8; 6]> {
    let seq = sock.next_seq();
    let message = get_key_message(family, seq, ifindex, index);
    sock.send(&message.to_bytes(sock.pid))?;

    for _ in 0..16 {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            break;
        };
        for parsed in msg::messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if let Some(code) = parsed.error_code() {
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
                // The success ACK normally follows the data reply. If a driver
                // emitted it first, keep waiting for the sequence attributes.
                continue;
            }
            if parsed.typ != family {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let sequence = msg::find_attr(&attrs, NL80211_ATTR_KEY_SEQ).or_else(|| {
                msg::find_attr(&attrs, NL80211_ATTR_KEY).and_then(|key| {
                    let nested = msg::parse_attrs(key);
                    msg::find_attr(&nested, NL80211_KEY_SEQ)
                })
            });
            let Some(sequence) = sequence else {
                continue;
            };
            if sequence.len() < 6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "nl80211 GET_KEY returned a short sequence",
                ));
            }
            let mut pn = [0u8; 6];
            pn.copy_from_slice(&sequence[..6]);
            return Ok(pn);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "nl80211 GET_KEY returned no sequence",
    ))
}

pub(super) fn kernel_object_is_absent(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT) | Some(libc::ENODEV) | Some(libc::ENOLINK)
    ) || error.to_string().contains("No such")
}

pub(super) fn del_pairwise_key_message(
    family: u16,
    seq: u32,
    ifindex: u32,
    peer: &[u8; 6],
) -> GenlMessage {
    GenlMessage::new(family, NL80211_CMD_DEL_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, peer))
        .attr(Attr::nested_unflagged(
            NL80211_ATTR_KEY,
            &[Attr::u8(NL80211_KEY_IDX, 0)],
        ))
}

pub(super) fn nl_del_pairwise_key(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    peer: &[u8; 6],
) -> io::Result<()> {
    let seq = sock.next_seq();
    match sock.request_ack(del_pairwise_key_message(family, seq, ifindex, peer)) {
        Err(error) if kernel_object_is_absent(&error) => Ok(()),
        result => result,
    }
}

#[cfg(test)]
mod key_message_tests {
    use super::*;

    #[test]
    fn new_key_material_uses_only_the_nested_key_namespace() {
        let peer = [0x02, 0, 0, 0, 0, 1];
        let material = [0x5a; 16];
        let key = KeyInstall::pairwise(12, &peer, &material, WLAN_CIPHER_SUITE_CCMP);
        let message = new_key_message(0x13, 7, &key);
        assert_eq!(
            message
                .attrs
                .iter()
                .find(|attr| attr.typ & !msg::NLA_F_NESTED == NL80211_ATTR_KEY)
                .map(|attr| attr.typ),
            Some(NL80211_ATTR_KEY),
            "driver_nl80211 leaves the top-level KEY namespace unflagged"
        );
        let wire = message.to_bytes(99);
        let parsed = msg::parse_messages(&wire);
        let top = msg::parse_attrs(parsed[0].genl_attrs());

        assert!(msg::find_attr(&top, NL80211_ATTR_KEY_DATA).is_none());
        assert!(msg::find_attr(&top, NL80211_ATTR_KEY_TYPE).is_none());
        assert_eq!(
            msg::find_attr(&top, NL80211_ATTR_MAC),
            Some(peer.as_slice())
        );
        let nested = msg::parse_attrs(
            msg::find_attr(&top, NL80211_ATTR_KEY).expect("nested key attributes"),
        );
        assert_eq!(
            msg::find_attr(&nested, NL80211_KEY_DATA),
            Some(material.as_slice())
        );
        assert_eq!(
            msg::find_attr(&nested, NL80211_KEY_CIPHER),
            Some(WLAN_CIPHER_SUITE_CCMP.to_ne_bytes().as_slice())
        );
        assert_eq!(
            msg::find_attr(&nested, NL80211_KEY_IDX),
            Some([0].as_slice())
        );
    }

    #[test]
    fn get_key_sequence_matches_driver_nl80211_shape() {
        let message = get_key_message(0x13, 7, 42, 2);
        let wire = message.to_bytes(99);
        assert_eq!(wire.len(), 36, "hostap GET_KEY request is 36 bytes");
        let parsed = msg::parse_messages(&wire);
        let top = msg::parse_attrs(parsed[0].genl_attrs());
        assert_eq!(
            msg::find_attr(&top, NL80211_ATTR_IFINDEX),
            Some(42u32.to_ne_bytes().as_slice())
        );
        assert_eq!(
            msg::find_attr(&top, NL80211_ATTR_KEY_IDX),
            Some([2].as_slice())
        );
        assert!(
            msg::find_attr(&top, NL80211_ATTR_KEY).is_none(),
            "GET_KEY uses the top-level KEY_IDX namespace"
        );
    }

    #[test]
    fn integrity_keys_are_selected_with_a_separate_set_key() {
        let material = [0x44; 16];
        let sequence = [0; 6];
        let key_without_link = KeyInstall::integrity(12, 4, &material, &sequence, None, false);
        let wire_without_link = new_key_message(0x13, 5, &key_without_link).to_bytes(99);
        assert_eq!(
            wire_without_link.len(),
            68,
            "hostap's fresh non-link IGTK NEW_KEY is 68 bytes"
        );

        let key = KeyInstall::integrity(12, 4, &material, &sequence, Some(1), false);
        let new_key = new_key_message(0x13, 6, &key);
        assert_eq!(
            new_key
                .attrs
                .iter()
                .find(|attr| attr.typ & !msg::NLA_F_NESTED == NL80211_ATTR_KEY)
                .map(|attr| attr.typ),
            Some(NL80211_ATTR_KEY)
        );
        let new_wire = new_key.to_bytes(99);
        let new_parsed = msg::parse_messages(&new_wire);
        let new_top = msg::parse_attrs(new_parsed[0].genl_attrs());
        let new_nested = msg::parse_attrs(
            msg::find_attr(&new_top, NL80211_ATTR_KEY).expect("nested key attributes"),
        );
        assert!(
            msg::find_attr(&new_nested, NL80211_KEY_SEQ).is_none(),
            "a fresh IGTK must not carry a zero receive sequence"
        );

        let message = default_key_message(0x13, 7, &key).expect("IGTK default");
        let wire = message.to_bytes(99);
        let parsed = msg::parse_messages(&wire);
        let top = msg::parse_attrs(parsed[0].genl_attrs());
        let nested = msg::parse_attrs(
            msg::find_attr(&top, NL80211_ATTR_KEY).expect("nested key attributes"),
        );
        assert_eq!(
            msg::find_attr(&nested, NL80211_KEY_DEFAULT_MGMT),
            Some([].as_slice())
        );
        let default_types = msg::parse_attrs(
            msg::find_attr(&nested, NL80211_KEY_DEFAULT_TYPES).expect("IGTK default key types"),
        );
        assert_eq!(
            msg::find_attr(&default_types, NL80211_KEY_DEFAULT_TYPE_MULTICAST),
            Some([].as_slice()),
            "driver_nl80211 marks a broadcast IGTK as multicast"
        );
    }

    #[test]
    fn vlan_offload_group_key_matches_driver_nl80211_attributes() {
        let material = [0x55; 16];
        let key = KeyInstall::group(12, 1, &material, Some(0)).with_vlan_offload(4096, true);

        for message in [
            new_key_message(0x13, 7, &key),
            default_key_message(0x13, 8, &key).expect("GTK default"),
        ] {
            assert_eq!(
                message
                    .attrs
                    .iter()
                    .find(|attr| attr.typ == NL80211_ATTR_VLAN_ID)
                    .map(|attr| attr.data.as_slice()),
                Some(4096u16.to_ne_bytes().as_slice())
            );
            let vlan_position = message
                .attrs
                .iter()
                .position(|attr| attr.typ == NL80211_ATTR_VLAN_ID)
                .expect("VLAN_ID");
            let link_position = message
                .attrs
                .iter()
                .position(|attr| attr.typ == NL80211_ATTR_MLO_LINK_ID)
                .expect("MLO_LINK_ID");
            assert!(
                vlan_position < link_position,
                "driver_nl80211 puts VLAN_ID before MLO_LINK_ID"
            );
        }
    }
}
