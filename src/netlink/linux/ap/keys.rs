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
            role: KeyRole::Group,
        }
    }

    pub(super) fn integrity(
        ifindex: u32,
        index: u8,
        material: &'a [u8],
        sequence: &'a [u8],
        link_id: Option<u8>,
        beacon: bool,
    ) -> Self {
        Self {
            ifindex,
            peer: None,
            index,
            material,
            cipher: WLAN_CIPHER_SUITE_BIP_CMAC_128,
            sequence: Some(sequence),
            link_id,
            role: if beacon {
                KeyRole::BeaconIntegrity
            } else {
                KeyRole::Integrity
            },
        }
    }
}

pub(super) fn new_key_message(family: u16, seq: u32, key: &KeyInstall<'_>) -> GenlMessage {
    let mut attributes = vec![
        Attr::bytes(NL80211_KEY_DATA, key.material),
        Attr::u32(NL80211_KEY_CIPHER, key.cipher),
        Attr::u8(NL80211_KEY_IDX, key.index),
    ];
    if let Some(sequence) = key.sequence {
        attributes.push(Attr::bytes(NL80211_KEY_SEQ, sequence));
    }

    let mut message = GenlMessage::new(family, NL80211_CMD_NEW_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, key.ifindex))
        .attr(Attr::nested(NL80211_ATTR_KEY, &attributes));
    if let Some(peer) = key.peer {
        message = message.attr(Attr::bytes(NL80211_ATTR_MAC, peer));
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
        KeyRole::Integrity => Attr::nested(
            NL80211_ATTR_KEY,
            &[
                Attr::u8(NL80211_KEY_IDX, key.index),
                Attr::bytes(NL80211_KEY_DEFAULT_MGMT, &[]),
            ],
        ),
        KeyRole::BeaconIntegrity => Attr::nested(
            NL80211_ATTR_KEY,
            &[
                Attr::u8(NL80211_KEY_IDX, key.index),
                Attr::bytes(NL80211_KEY_DEFAULT_BEACON, &[]),
            ],
        ),
    };
    let mut message = GenlMessage::new(family, NL80211_CMD_SET_KEY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, key.ifindex))
        .attr(role);
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
        .attr(Attr::nested(
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
    fn integrity_keys_are_selected_with_a_separate_set_key() {
        let material = [0x44; 16];
        let sequence = [0; 6];
        let key = KeyInstall::integrity(12, 4, &material, &sequence, Some(1), false);
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
    }
}
