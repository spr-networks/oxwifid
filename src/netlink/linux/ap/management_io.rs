use super::*;

pub(super) fn nl_get_interface_wdev(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
) -> io::Result<u64> {
    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_INTERFACE, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    sock.send(&request.to_bytes(sock.pid))?;

    for _ in 0..16 {
        let Some(buffer) = sock.recv(Duration::from_millis(500)) else {
            break;
        };
        for response in msg::parse_messages(&buffer) {
            if response.seq != seq {
                continue;
            }
            if let Some(code) = response.error_code() {
                if code != 0 {
                    return Err(io::Error::from_raw_os_error(-code));
                }
                continue;
            }
            if response.typ != family {
                continue;
            }
            let attributes = msg::parse_attrs(response.genl_attrs());
            if let Some(wdev) = msg::find_attr(&attributes, NL80211_ATTR_WDEV) {
                let bytes: [u8; 8] =
                    wdev.get(..8)
                        .and_then(|v| v.try_into().ok())
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "short nl80211 WDEV")
                        })?;
                return Ok(u64::from_ne_bytes(bytes));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "GET_INTERFACE returned no WDEV",
    ))
}

pub(super) fn register_frame_message(
    family: u16,
    seq: u32,
    wdev: u64,
    frame_type: u16,
    frame_match: &[u8],
) -> GenlMessage {
    GenlMessage::new(family, NL80211_CMD_REGISTER_FRAME, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::u16v(NL80211_ATTR_FRAME_TYPE, frame_type))
        .attr(Attr::bytes(NL80211_ATTR_FRAME_MATCH, frame_match))
}

/// Register the complete userspace AP MLME receive set on the event socket.
///
/// This runs exactly once during setup. The returned socket becomes
/// `RadioIo::events` and is never used for a synchronous request again.
pub(super) fn nl_register_ap_frames(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
) -> io::Result<()> {
    for &frame_type in &REGISTER_SUBTYPES {
        let seq = sock.next_seq();
        sock.request_ack(register_frame_message(family, seq, wdev, frame_type, &[]))?;
    }
    for &frame_match in &REGISTER_ACTION_MATCHES {
        let seq = sock.next_seq();
        sock.request_ack(register_frame_message(
            family,
            seq,
            wdev,
            0x00d0,
            frame_match,
        ))?;
    }
    Ok(())
}

pub(super) fn management_message(
    family: u16,
    seq: u32,
    wdev: u64,
    frequency: u32,
    frame: &[u8],
    link_id: Option<u8>,
) -> GenlMessage {
    let mut message = GenlMessage::new(family, NL80211_CMD_FRAME, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, frequency))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, frame));
    if let Some(link_id) = link_id {
        message = message.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    message
}

/// Queue one management frame without waiting in the radio loop.
pub(super) fn nl_send_mgmt(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    frequency: u32,
    frame: &[u8],
    link_id: Option<u8>,
) {
    let seq = sock.next_seq();
    let message = management_message(family, seq, wdev, frequency, frame, link_id);
    let _ = sock.send(&message.to_bytes(sock.pid));
}

#[cfg(test)]
mod management_io_tests {
    use super::*;

    #[test]
    fn management_and_registration_use_the_radio_wdev() {
        let wdev = 0x1234_5678_9abc_def0;
        let frame = [0xd0, 0x00, 0x00, 0x00];
        let tx = management_message(42, 7, wdev, 5180, &frame, Some(1));
        let registration = register_frame_message(42, 8, wdev, 0x00d0, &[0x08]);

        for message in [&tx, &registration] {
            assert_eq!(
                message
                    .attrs
                    .iter()
                    .find(|attribute| attribute.typ == NL80211_ATTR_WDEV)
                    .map(|attribute| attribute.data.as_slice()),
                Some(wdev.to_ne_bytes().as_slice())
            );
            assert!(message
                .attrs
                .iter()
                .all(|attribute| attribute.typ != NL80211_ATTR_IFINDEX));
        }
    }

    #[test]
    fn sa_query_registration_matches_the_action_category() {
        let message = register_frame_message(42, 8, 9, 0x00d0, &[0x08]);
        assert_eq!(
            message
                .attrs
                .iter()
                .find(|attribute| attribute.typ == NL80211_ATTR_FRAME_MATCH)
                .map(|attribute| attribute.data.as_slice()),
            Some([0x08].as_slice())
        );
    }
}
