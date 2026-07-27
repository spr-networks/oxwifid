use super::*;

/// Split a bare 802.11 beacon into the head (through the IEs preceding the TIM)
/// and the tail (IEs after the TIM). The kernel inserts its own TIM between them.
pub(super) fn split_beacon_at_tim(beacon: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 36; // 24-byte MAC header + timestamp(8) + interval(2) + capability(2)
    while i + 2 <= beacon.len() {
        let len = beacon[i + 1] as usize;
        if i + 2 + len > beacon.len() {
            break;
        }
        if beacon[i] == 5 {
            return (&beacon[..i], &beacon[i + 2 + len..]);
        }
        i += 2 + len;
    }
    (beacon, &[])
}

pub(super) fn nl_add_link(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    link_id: u8,
    link_mac: &[u8; 6],
) -> io::Result<()> {
    let seq = sock.next_seq();
    let m = GenlMessage::new(family, NL80211_CMD_ADD_LINK, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id))
        .attr(Attr::bytes(NL80211_ATTR_MAC, link_mac));
    sock.request_ack(m)
}

/// Complete AP bring-up with the SET_BSS operation reference AP issues after every
/// successful START_AP/SET_BEACON. ath12k can acknowledge START_AP and expose
/// the MLD links through `iw` while transmitting no beacons until these
/// per-link BSS parameters have been installed.
pub(super) fn set_bss_message(
    family: u16,
    seq: u32,
    ifindex: u32,
    link_id: Option<u8>,
    channel: u8,
    ht_enabled: bool,
    isolate: bool,
) -> GenlMessage {
    // nl80211 expresses rates in 500-kbps units. The 2.4-GHz ERP default uses
    // the four basic CCK rates; 5/6 GHz use mandatory OFDM 6/12/24 Mbps.
    const BASIC_RATES_2GHZ: [u8; 4] = [0x02, 0x04, 0x0b, 0x16];
    const BASIC_RATES_OFDM: [u8; 3] = [0x0c, 0x18, 0x30];
    let is_2ghz = channel <= 14;
    let basic_rates = if is_2ghz {
        BASIC_RATES_2GHZ.as_slice()
    } else {
        BASIC_RATES_OFDM.as_slice()
    };
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_BSS, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_BSS_CTS_PROT, 0))
        // Guest BSS: mac80211 stops intra-BSS station-to-station bridging
        // (reference AP `ap_isolate`).
        .attr(Attr::u8(NL80211_ATTR_AP_ISOLATE, isolate as u8))
        .attr(Attr::bytes(NL80211_ATTR_BSS_BASIC_RATES, basic_rates));
    if is_2ghz {
        m = m
            .attr(Attr::u8(NL80211_ATTR_BSS_SHORT_PREAMBLE, 1))
            .attr(Attr::u8(NL80211_ATTR_BSS_SHORT_SLOT_TIME, 1));
    }
    if ht_enabled {
        m = m.attr(Attr::u16v(NL80211_ATTR_BSS_HT_OPMODE, 0));
    }
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    m
}

pub(super) fn nl_set_bss(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    link_id: Option<u8>,
    channel: u8,
    ht_enabled: bool,
    isolate: bool,
) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(set_bss_message(
        family, seq, ifindex, link_id, channel, ht_enabled, isolate,
    ))
}

/// Queue an EAPOL payload to `dst` over the nl80211 control port (unencrypted,
/// pre-key). The kernel wraps it into an 802.11 data frame to the station.
///
/// Request an ACK, but do not wait for it here. This socket is owned by the
/// EAPOL worker, which drains ACK/error responses independently. Waiting in
/// `request_ack()` serializes every station behind one delayed kernel response;
/// its normal command timeout can hold the entire radio's EAPOL queue for up to
/// eight seconds.
pub(super) fn nl_queue_eapol(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    dst: &[u8; 6],
    eapol: &[u8],
    link_id: Option<u8>,
) -> io::Result<u32> {
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_CONTROL_PORT_FRAME, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, dst))
        .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
        .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, &[]))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, eapol));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    m.flags |= msg::NLM_F_ACK;
    sock.send(&m.to_bytes(sock.pid))?;
    if crate::util::netlink_debug_enabled() {
        let ki = if eapol.len() >= 7 {
            u16::from_be_bytes([eapol[5], eapol[6]])
        } else {
            0
        };
        // (The TX-STATUS event is multicast to the mlme group — the main recv
        // loop logs it as "EAPOL TX-STATUS acked=..".)
        eprintln!(
            "netlink AP: TX EAPOL ifindex={ifindex} to {} len={} key_info=0x{ki:04x} queued seq={seq}",
            crate::util::bytes_to_mac(dst),
            eapol.len(),
        );
    }
    Ok(seq)
}

/// 500-kbps-unit OFDM rates (6..54 Mbps), no basic-rate bit — the format
/// NL80211_ATTR_STA_SUPPORTED_RATES expects (not the beacon IE format).
pub(super) const STA_OFDM_RATES: [u8; 8] = [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];

/// 8-byte nl80211_sta_flag_update { mask, set } (host byte order).
pub(super) fn sta_flags(mask: u32, set: u32) -> Vec<u8> {
    let mut v = mask.to_ne_bytes().to_vec();
    v.extend_from_slice(&set.to_ne_bytes());
    v
}

/// Add a station to the kernel in the *unassociated* state. hwsim lacks
/// `FULL_AP_CLIENT_STATE`, so — like reference AP's "UNASSOC_STA workaround" — the
/// station must be added with AUTH/ASSOC explicitly cleared (set=0, mask=0xa0),
/// then promoted to associated via SET_STATION.
pub(super) fn nl_new_station(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
    mld_mac: Option<&[u8; 6]>,
    link_id: Option<u8>,
) -> bool {
    // Add the station UNASSOCIATED (flags cleared). SET_STATION then marks it
    // associated AND carries the HT/VHT caps — rate control only picks caps up
    // from SET_STATION, and applying them to an already-associated station fails
    // EINVAL, so the station must start unassociated here.
    let unassoc = (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    let seq = sock.next_seq();
    // CCK (1/2/5.5/11) + OFDM (6..54), 500-kbps units, no basic bit.
    let rates: &[u8] = &[
        0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
    ];
    let _ = STA_OFDM_RATES;
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, 1))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 0))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, rates))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &sta_flags(unassoc, 0)));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Some(mld_mac) = mld_mac {
        m = m.attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac));
    }
    match sock.request_ack(m) {
        Ok(()) => {
            eprintln!(
                "netlink AP: NEW_STATION {} ok (unassoc)",
                crate::util::bytes_to_mac(sta)
            );
            true
        }
        Err(e) => {
            eprintln!(
                "netlink AP: NEW_STATION {} failed: {e}",
                crate::util::bytes_to_mac(sta)
            );
            false
        }
    }
}

/// Promote a station to the associated state (SET_STATION with the real aid,
/// capability and AUTH/ASSOC flags) once it has (re)associated.
/// Find the payload of an Element-ID-Extension IE (id 255) with extension id
/// `ext_id` (e.g. HE Capabilities = 35), excluding the ext-id byte.
pub(super) fn find_ext_ie(ies: &[u8], ext_id: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] == 255 && len >= 1 && ies[i + 2] == ext_id {
            return Some(&ies[i + 3..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

pub(super) fn station_ie<'a>(outer: &'a [u8], link: Option<&'a [u8]>, id: u8) -> Option<&'a [u8]> {
    link.and_then(|ies| dot11::find_ie(ies, id))
        .or_else(|| dot11::find_ie(outer, id))
}

pub(super) fn station_ext_ie<'a>(
    outer: &'a [u8],
    link: Option<&'a [u8]>,
    ext_id: u8,
) -> Option<&'a [u8]> {
    link.and_then(|ies| find_ext_ie(ies, ext_id))
        .or_else(|| find_ext_ie(outer, ext_id))
}

/// Attach the same station PHY capability attributes reference AP sends. A partner
/// link's Per-STA Profile overrides the outer association IEs; anything it
/// omits is inherited from the outer request.
pub(super) fn with_station_phy_capabilities(
    mut msg: GenlMessage,
    outer: &[u8],
    link: Option<&[u8]>,
) -> GenlMessage {
    if let Some(ht) = station_ie(outer, link, 45) {
        msg = msg.attr(Attr::bytes(NL80211_ATTR_HT_CAPABILITY, ht));
    }
    if let Some(vht) = station_ie(outer, link, 191) {
        msg = msg.attr(Attr::bytes(NL80211_ATTR_VHT_CAPABILITY, vht));
    }
    if std::env::var_os("RUSTAP_NO_HE_CAP").is_none() {
        if let Some(he) = station_ext_ie(outer, link, 35) {
            msg = msg.attr(Attr::bytes(NL80211_ATTR_HE_CAPABILITY, he));
        }
        if let Some(he6) = station_ext_ie(outer, link, 59) {
            msg = msg.attr(Attr::bytes(NL80211_ATTR_HE_6GHZ_CAPABILITY, he6));
        }
    }
    if let Some(eht) = station_ext_ie(outer, link, 108) {
        msg = msg.attr(Attr::bytes(NL80211_ATTR_EHT_CAPABILITY, eht));
    }
    msg
}

/// Extract the QoS Info byte from the station's WMM Information element (vendor
/// element 221, OUI 00:50:f2, OUI-type 2, subtype 0). Iterates all vendor IEs
/// since a station may carry several. Used to enable A-MPDU aggregation.
pub(super) fn find_wmm_qosinfo(ies: &[u8]) -> Option<u8> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        let body = &ies[i + 2..i + 2 + len];
        if ies[i] == 221 && body.len() >= 7 && body.starts_with(&[0x00, 0x50, 0xf2, 0x02, 0x00]) {
            return Some(body[6]);
        }
        i += 2 + len;
    }
    None
}

pub(super) fn associated_station_flags(capability: u16, wme: bool, mfp: bool) -> u32 {
    const CAPABILITY_SHORT_PREAMBLE: u16 = 1 << 5;
    let mut flags =
        (1u32 << NL80211_STA_FLAG_AUTHENTICATED) | (1u32 << NL80211_STA_FLAG_ASSOCIATED);
    if capability & CAPABILITY_SHORT_PREAMBLE != 0 {
        flags |= 1u32 << NL80211_STA_FLAG_SHORT_PREAMBLE;
    }
    if wme {
        flags |= 1u32 << NL80211_STA_FLAG_WME;
    }
    if mfp {
        flags |= 1u32 << NL80211_STA_FLAG_MFP;
    }
    flags
}

#[allow(clippy::too_many_arguments)]
pub(super) fn nl_set_station_assoc(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
    aid: u16,
    listen_interval: u16,
    capability: u16,
    assoc_ies: Option<&[u8]>,
    mld_mac: Option<&[u8; 6]>,
    link_id: Option<u8>,
    eml_capability: Option<u16>,
    force_wme: bool,
    mfp: bool,
) -> bool {
    let seq = sock.next_seq();
    // Real supported rates from the assoc request (Supported Rates id 1 + Extended
    // Rates id 50), basic-rate bits preserved, like reference AP; fall back to OFDM.
    let mut rates: Vec<u8> = Vec::new();
    if let Some(ies) = assoc_ies {
        if let Some(sr) = dot11::find_ie(ies, 1) {
            rates.extend_from_slice(sr);
        }
        if let Some(er) = dot11::find_ie(ies, 50) {
            rates.extend_from_slice(er);
        }
    }
    if rates.is_empty() {
        rates.extend_from_slice(&STA_OFDM_RATES);
    }
    let qosinfo = assoc_ies.and_then(find_wmm_qosinfo);
    let assoc = associated_station_flags(capability, force_wme || qosinfo.is_some(), mfp);
    let mut m = GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            listen_interval,
        ))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &rates))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_FLAGS2,
            &sta_flags(assoc, assoc),
        ));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Some(mld_mac) = mld_mac {
        m = m.attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac));
    }
    if mld_mac.is_some() {
        if let Some(eml) = eml_capability.filter(|eml| *eml != 0) {
            m = m.attr(Attr::u16v(NL80211_ATTR_EML_CAPABILITY, eml));
        }
    }
    // Carry the station's HT/VHT/HE/EHT capabilities (from its Assoc Request) so the
    // driver's rate control can use MCS rates — without these it is treated as a
    // legacy station stuck on the 6 Mbps basic rate.
    if let Some(ies) = assoc_ies {
        m = with_station_phy_capabilities(m, ies, None);
        // Mark the station QoS/WMM-capable so the kernel enables A-MPDU
        // aggregation. The QoS Info byte comes from the station's WMM Information
        // element; without this nest a VHT/HE station negotiates a high MCS but
        // moves almost no data (every MPDU goes out unaggregated). reference AP sends
        // the identical nested attribute.
        if let Some(qosinfo) = qosinfo {
            m = m.attr(Attr::nested(
                NL80211_ATTR_STA_WME,
                &[
                    Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[qosinfo & 0x0f]),
                    Attr::bytes(NL80211_STA_WME_MAX_SP, &[(qosinfo >> 5) & 0x03]),
                ],
            ));
        }
    }
    if force_wme && qosinfo.is_none() {
        m = m.attr(Attr::nested(
            NL80211_ATTR_STA_WME,
            &[
                Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[0]),
                Attr::bytes(NL80211_STA_WME_MAX_SP, &[0]),
            ],
        ));
    }
    match sock.request_ack(m) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "netlink AP: SET_STATION(assoc) {} failed: {e}",
                crate::util::bytes_to_mac(sta)
            );
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn nl_add_link_station(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    mld_mac: &[u8; 6],
    link_id: u8,
    link_sta: &[u8; 6],
    aid: u16,
    listen_interval: u16,
    capability: u16,
    assoc_ies: Option<&[u8]>,
    link_ies: Option<&[u8]>,
    eml_capability: Option<u16>,
    mfp: bool,
) -> bool {
    let mut rates: Vec<u8> = Vec::new();
    if let Some(ies) = assoc_ies {
        if let Some(sr) = station_ie(ies, link_ies, 1) {
            rates.extend_from_slice(sr);
        }
        if let Some(er) = station_ie(ies, link_ies, 50) {
            rates.extend_from_slice(er);
        }
    }
    if rates.is_empty() {
        rates.extend_from_slice(&STA_OFDM_RATES);
    }
    let flags = associated_station_flags(capability, true, mfp);
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_ADD_LINK_STA, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id))
        .attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac))
        .attr(Attr::bytes(NL80211_ATTR_MAC, link_sta))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            listen_interval,
        ))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &rates))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_FLAGS2,
            &sta_flags(flags, flags),
        ))
        .attr(Attr::nested(
            NL80211_ATTR_STA_WME,
            &[
                Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[0]),
                Attr::bytes(NL80211_STA_WME_MAX_SP, &[0]),
            ],
        ));
    if let Some(ies) = assoc_ies {
        m = with_station_phy_capabilities(m, ies, link_ies);
    }
    if let Some(eml) = eml_capability.filter(|eml| *eml != 0) {
        m = m.attr(Attr::u16v(NL80211_ATTR_EML_CAPABILITY, eml));
    }
    match sock.request_ack(m) {
        Ok(()) => {
            eprintln!(
                "netlink AP: ADD_LINK_STA link_id={} mld={} link_sta={} ok",
                link_id,
                crate::util::bytes_to_mac(mld_mac),
                crate::util::bytes_to_mac(link_sta)
            );
            true
        }
        Err(e) => {
            eprintln!(
                "netlink AP: ADD_LINK_STA link_id={} link_sta={} failed: {e}",
                link_id,
                crate::util::bytes_to_mac(link_sta)
            );
            false
        }
    }
}

/// Mark a station 802.1X-authorized so the kernel forwards its data frames.
pub(super) fn authorize_station_message(
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
    seq: u32,
) -> GenlMessage {
    let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    let mut flags = bit.to_ne_bytes().to_vec(); // mask
    flags.extend_from_slice(&bit.to_ne_bytes()); // set
    GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags))
}

pub(super) fn nl_authorize(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    sta: &[u8; 6],
) -> bool {
    let seq = sock.next_seq();
    let m = authorize_station_message(family, ifindex, sta, seq);
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: SET_STATION(authorize) {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        );
        return false;
    }
    true
}

/// Reconstruct a station's uplink EAPOL into a ToDS 802.11 data frame so the
/// `Ap` state machine (which speaks raw 802.11) can process it.
pub(super) fn reconstruct_eapol(bssid: &[u8; 6], sta: &[u8; 6], eapol: &[u8]) -> Vec<u8> {
    let mut v = dot11::RADIOTAP_TX.to_vec();
    v.extend_from_slice(&[0x08, 0x01, 0x00, 0x00]); // FC: data, ToDS; duration
    v.extend_from_slice(bssid); // addr1 = RA = BSSID
    v.extend_from_slice(sta); // addr2 = TA = STA
    v.extend_from_slice(bssid); // addr3 = DA = BSSID
    v.extend_from_slice(&[0x00, 0x00]); // sequence control
    v.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]); // LLC/SNAP, EAPOL
    v.extend_from_slice(eapol);
    v
}

/// Run the AP with the kernel offloading beaconing and data-plane CCMP — the
/// nl80211 "netlink" path (vs the userspace-CCMP raw/monitor path). The 4-way
/// handshake stays in `Ap`; the interface must already be AP-type and up.
///
/// Flow: `START_AP` (kernel beacons) → register for auth/(re)assoc → for each
/// peer run the userspace MLME in `Ap`, sending responses over `CMD_FRAME`,
/// registering the station (`NEW_STATION`/`SET_STATION`), shuttling the 4-way
/// EAPOL over the nl80211 control port, then installing the PTK/GTK with
/// `NEW_KEY` and authorizing with `SET_STATION`.
///
/// STATUS: verified end-to-end against `wpa_supplicant` (`wpa_state=COMPLETED`,
/// **ping works**): beacon, auth, assoc, the two-step station add (NEW_STATION
/// unassoc → SET_STATION assoc, the reference AP "UNASSOC_STA workaround" for
/// non-`FULL_AP_CLIENT_STATE` drivers), the 4-way over the nl80211 control port,
/// PTK/GTK install (`NEW_KEY`), authorization, and CCMP data both directions.
/// See `tools/hwsim/README.md`.
/// The `NL80211_ATTR_RADAR_EVENT` value, if present.
pub(super) fn radar_event(attrs: &[(u16, &[u8])]) -> Option<u32> {
    msg::find_attr(attrs, NL80211_ATTR_RADAR_EVENT)
        .and_then(|b| b.get(..4))
        .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
}

/// Run the Channel Availability Check on a DFS channel: ask the kernel to start
/// radar detection, then block until it reports CAC finished (channel clear) —
/// the kernel won't let us `START_AP` on a radar channel before this. ~60 s.
pub(super) fn do_cac(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    freq: u32,
    chan_width: u32,
    center_freq1: u32,
) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(
        GenlMessage::new(family, NL80211_CMD_RADAR_DETECT, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
            .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, chan_width))
            .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, center_freq1)),
    )
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("DFS RADAR_DETECT rejected on {freq} MHz ({e}); the driver may not support userspace CAC"),
        )
    })?;
    eprintln!("netlink AP: DFS — running CAC (radar listen) on {freq} MHz, ~60 s...");
    // Standard DFS CAC is 60 s; ETSI weather-radar channels (120-128) take 600 s.
    // Bound the wait at ~650 s so a legitimate weather CAC completes but a missed
    // event can't hang us forever.
    for _ in 0..130 {
        let Some(buf) = sock.recv(Duration::from_secs(5)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != family || parsed.genl_cmd() != Some(NL80211_CMD_RADAR_DETECT) {
                continue;
            }
            match radar_event(&msg::parse_attrs(parsed.genl_attrs())) {
                Some(NL80211_RADAR_CAC_FINISHED) => {
                    eprintln!("netlink AP: CAC finished — channel clear, beaconing");
                    return Ok(());
                }
                Some(NL80211_RADAR_CAC_ABORTED) => {
                    return Err(io::Error::other("DFS CAC aborted"));
                }
                Some(NL80211_RADAR_DETECTED) => {
                    return Err(io::Error::other(
                        "radar detected during CAC; channel unusable",
                    ));
                }
                _ => {}
            }
        }
    }
    Err(io::Error::other("DFS CAC timed out"))
}

#[cfg(test)]
mod station_authorization_tests {
    use super::*;

    #[test]
    fn mld_authorization_uses_only_the_peer_mld_address() {
        let mld = [0x6e, 0x45, 0xbe, 0x78, 0x3b, 0xf2];
        let msg = authorize_station_message(42, 343, &mld, 7);

        assert_eq!(msg.cmd, NL80211_CMD_SET_STATION);
        assert_eq!(
            msg.attrs
                .iter()
                .find(|attr| attr.typ == NL80211_ATTR_MAC)
                .map(|attr| attr.data.as_slice()),
            Some(mld.as_slice())
        );
        assert!(
            msg.attrs
                .iter()
                .all(|attr| attr.typ != NL80211_ATTR_MLD_ADDR
                    && attr.typ != NL80211_ATTR_MLO_LINK_ID),
            "reference AP authorizes MLD state once; it does not address a link station"
        );
        let flags = msg
            .attrs
            .iter()
            .find(|attr| attr.typ == NL80211_ATTR_STA_FLAGS2)
            .expect("STA_FLAGS2");
        let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
        assert_eq!(&flags.data[..4], &bit.to_ne_bytes());
        assert_eq!(&flags.data[4..], &bit.to_ne_bytes());
    }

    #[test]
    fn bss_parameters_are_band_correct() {
        let two_ghz = set_bss_message(42, 1, 7, Some(0), 6, true, false);
        let five_ghz = set_bss_message(42, 2, 7, Some(1), 36, true, false);
        fn attr(message: &GenlMessage, kind: u16) -> Option<&[u8]> {
            message
                .attrs
                .iter()
                .find(|attribute| attribute.typ == kind)
                .map(|attribute| attribute.data.as_slice())
        }

        assert_eq!(
            attr(&two_ghz, NL80211_ATTR_BSS_BASIC_RATES),
            Some([0x02, 0x04, 0x0b, 0x16].as_slice())
        );
        assert_eq!(
            attr(&five_ghz, NL80211_ATTR_BSS_BASIC_RATES),
            Some([0x0c, 0x18, 0x30].as_slice())
        );
        assert_eq!(
            attr(&two_ghz, NL80211_ATTR_BSS_SHORT_PREAMBLE),
            Some([1].as_slice())
        );
        assert_eq!(
            attr(&two_ghz, NL80211_ATTR_BSS_SHORT_SLOT_TIME),
            Some([1].as_slice())
        );
        assert_eq!(attr(&five_ghz, NL80211_ATTR_BSS_SHORT_PREAMBLE), None);
        assert_eq!(attr(&five_ghz, NL80211_ATTR_BSS_SHORT_SLOT_TIME), None);
    }

    #[test]
    fn station_short_preamble_follows_its_association_capability() {
        let short = 1u32 << NL80211_STA_FLAG_SHORT_PREAMBLE;
        assert_eq!(associated_station_flags(0, false, false) & short, 0);
        assert_eq!(
            associated_station_flags(1 << 5, false, false) & short,
            short
        );
    }
}
