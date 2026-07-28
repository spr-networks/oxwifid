use super::*;

/// The kernel's current global regulatory domain as an ISO alpha-2, via
/// `GET_REG`. `None` if it can't be read (treated as "unknown, set it anyway").
pub(super) fn nl_current_reg_alpha2(sock: &mut NetlinkSocket, family: u16) -> Option<[u8; 2]> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_GET_REG, 0, seq);
    sock.send(&m.to_bytes(sock.pid)).ok()?;
    for _ in 0..10 {
        let buf = sock.recv(Duration::from_millis(300))?;
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if let Some(a) = msg::find_attr(&attrs, NL80211_ATTR_REG_ALPHA2) {
                if a.len() >= 2 {
                    return Some([a[0], a[1]]);
                }
            }
        }
    }
    None
}

/// Apply the configured regulatory domain (`iw reg set <CC>`) so the kernel
/// enables that country's channels. Without it the radio stays on the default
/// world regdomain, under which 5/6 GHz AP channels are flagged no-IR ("no
/// initiating radiation") — `START_AP` then fails with `EINVAL`, often
/// intermittently depending on whether a beacon hint has arrived. barely-ap
/// previously used `country` only for the beacon Country IE and never set the
/// kernel regdomain, so a real 5 GHz AP could not reliably start.
///
/// This subscribes to the `regulatory` multicast group and waits for the
/// `REG_CHANGE` event confirming the domain applied (like reference AP), rather
/// than sleeping a fixed interval — the no-IR flags clear only once the change
/// lands. Best-effort throughout: an unset/invalid code is skipped, a duplicate
/// request for the current domain is harmless, and a bounded timeout keeps a
/// self-managed-reg driver (which emits no global `REG_CHANGE`) from stalling
/// startup.
pub(super) fn nl_set_regulatory(alpha2: &[u8; 2]) {
    if !alpha2.iter().all(u8::is_ascii_uppercase) {
        return;
    }
    let cc_str = format!("{}{}", alpha2[0] as char, alpha2[1] as char);
    let mut sock = match NetlinkSocket::open() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("netlink AP: reg socket open failed (continuing): {e}");
            return;
        }
    };
    let (family, reg_group) = match resolve_family(&mut sock, "nl80211", "regulatory") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("netlink AP: reg family resolve failed (continuing): {e}");
            return;
        }
    };
    // Already the requested domain? Then REQ_SET_REG would emit no REG_CHANGE and
    // we'd wait out the whole timeout for nothing (common: a box that boots into
    // the right country). Skip cleanly.
    if nl_current_reg_alpha2(&mut sock, family) == Some(*alpha2) {
        eprintln!("netlink AP: regulatory domain already {cc_str}");
        return;
    }
    let subscribed = reg_group
        .map(|g| sock.join_multicast(g).is_ok())
        .unwrap_or(false);

    // Send the hint. NUL-terminated alpha-2, matching iw's 3-byte attribute. We
    // don't use `request_ack` here: it would consume (and discard) the
    // REG_CHANGE broadcast while waiting for the ACK. Instead handle both the
    // ACK and the event in one recv loop below.
    let seq = sock.next_seq();
    let cc = [alpha2[0], alpha2[1], 0];
    let mut m = GenlMessage::new(family, NL80211_CMD_REQ_SET_REG, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_REG_ALPHA2, &cc));
    m.flags |= msg::NLM_F_ACK;
    if let Err(e) = sock.send(&m.to_bytes(sock.pid)) {
        eprintln!("netlink AP: REQ_SET_REG {cc_str} send failed (continuing): {e}");
        return;
    }

    // Without the multicast subscription there is no event to wait for; fall
    // back to a short settle so the async hint still lands before START_AP.
    if !subscribed {
        std::thread::sleep(Duration::from_millis(600));
        eprintln!("netlink AP: requested regulatory domain {cc_str} (no reg group; settled)");
        return;
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut acked = false;
    while Instant::now() < deadline {
        let Some(buf) = sock.recv(Duration::from_millis(300)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            // ACK / error for our own request.
            if parsed.seq == seq {
                if let Some(code) = parsed.error_code() {
                    if code != 0 {
                        eprintln!(
                            "netlink AP: REQ_SET_REG {cc_str} rejected (continuing): {}",
                            io::Error::from_raw_os_error(-code)
                        );
                        return;
                    }
                    acked = true;
                }
                continue;
            }
            // REG_CHANGE broadcast — done once the domain matches the request.
            if parsed.typ == family && parsed.genl_cmd() == Some(NL80211_CMD_REG_CHANGE) {
                let attrs = msg::parse_attrs(parsed.genl_attrs());
                let matched = msg::find_attr(&attrs, NL80211_ATTR_REG_ALPHA2)
                    .map(|a| a.len() >= 2 && a[0] == alpha2[0] && a[1] == alpha2[1])
                    .unwrap_or(false);
                if matched {
                    eprintln!("netlink AP: regulatory domain {cc_str} applied");
                    return;
                }
            }
        }
    }
    if acked {
        eprintln!(
            "netlink AP: regulatory domain {cc_str} requested (no REG_CHANGE within 3s; continuing)"
        );
    } else {
        eprintln!("netlink AP: regulatory domain {cc_str} not acknowledged (continuing)");
    }
}
