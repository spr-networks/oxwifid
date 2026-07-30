use super::*;

pub(super) fn nl80211_ap_wpa_version(mode: dot11::SecurityMode) -> u32 {
    match mode {
        dot11::SecurityMode::Wpa2 | dot11::SecurityMode::Wpa2PskSha256 => NL80211_WPA_VERSION_2,
        dot11::SecurityMode::Wpa3Sae
        | dot11::SecurityMode::Transition
        | dot11::SecurityMode::Owe => NL80211_WPA_VERSION_3,
    }
}

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
#[derive(Clone, Copy)]
pub(super) struct BssParameters {
    pub(super) link_id: Option<u8>,
    pub(super) channel: u8,
    pub(super) short_preamble: bool,
    pub(super) ht_opmode: Option<u16>,
    pub(super) isolate: bool,
}

pub(super) fn set_bss_message(
    family: u16,
    seq: u32,
    ifindex: u32,
    parameters: BssParameters,
) -> GenlMessage {
    let BssParameters {
        link_id,
        channel,
        short_preamble,
        ht_opmode,
        isolate,
    } = parameters;
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
        .attr(Attr::u8(
            NL80211_ATTR_BSS_SHORT_PREAMBLE,
            short_preamble as u8,
        ))
        // Guest BSS: mac80211 stops intra-BSS station-to-station bridging
        // (reference AP `ap_isolate`).
        .attr(Attr::u8(NL80211_ATTR_AP_ISOLATE, isolate as u8))
        .attr(Attr::bytes(NL80211_ATTR_BSS_BASIC_RATES, basic_rates));
    if is_2ghz {
        m = m.attr(Attr::u8(NL80211_ATTR_BSS_SHORT_SLOT_TIME, 1));
    }
    if let Some(ht_opmode) = ht_opmode {
        m = m.attr(Attr::u16v(NL80211_ATTR_BSS_HT_OPMODE, ht_opmode));
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
    parameters: BssParameters,
) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(set_bss_message(family, seq, ifindex, parameters))
}

/// Queue an EAPOL payload to `dst` over the nl80211 control port (unencrypted,
/// pre-key). The kernel wraps it into an 802.11 data frame to the station.
///
/// Request an ACK, but do not wait for it here. This socket is owned by the
/// EAPOL worker, which drains ACK/error responses independently. Waiting in
/// `request_ack()` serializes every station behind one delayed kernel response;
/// its normal command timeout can hold the entire radio's EAPOL queue for up to
/// eight seconds.
pub(super) fn control_port_eapol_message(
    family: u16,
    seq: u32,
    ifindex: u32,
    dst: &[u8; 6],
    eapol: &[u8],
    encrypt: bool,
    link_id: Option<u8>,
) -> GenlMessage {
    let mut m = GenlMessage::new(family, NL80211_CMD_CONTROL_PORT_FRAME, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, dst))
        .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
        .attr(Attr::bytes(NL80211_ATTR_FRAME, eapol));
    // Pass no_encrypt only before a PTK exists. Group-key handshakes and
    // authenticator-initiated PTK rekeys run under the installed pairwise key
    // and must be protected on air.
    if !encrypt {
        m = m.attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, &[]));
    }
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    m
}

pub(super) fn nl_queue_eapol(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    dst: &[u8; 6],
    eapol: &[u8],
    encrypt: bool,
    link_id: Option<u8>,
) -> io::Result<u32> {
    let seq = sock.next_seq();
    let mut m = control_port_eapol_message(family, seq, ifindex, dst, eapol, encrypt, link_id);
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
            "netlink AP: TX EAPOL ifindex={ifindex} to {} len={} key_info=0x{ki:04x} encrypt={encrypt} queued seq={seq}",
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

pub(super) fn new_unassociated_station_message(
    family: u16,
    seq: u32,
    wdev: u64,
    sta: &[u8; 6],
    mld_mac: Option<&[u8; 6]>,
    link_id: Option<u8>,
) -> GenlMessage {
    // Seed the pre-authentication peer with the BSS basic rates and explicitly
    // clear AUTHENTICATED/ASSOCIATED. WME is not known until the Association
    // Request and must not be projected onto
    // the firmware peer early.
    let authenticated = 1u32 << NL80211_STA_FLAG_AUTHENTICATED;
    let associated = 1u32 << NL80211_STA_FLAG_ASSOCIATED;
    let mut m = GenlMessage::new(family, NL80211_CMD_NEW_STATION, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_SUPPORTED_RATES,
            &[0x0c, 0x18, 0x30],
        ))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, 0))
        .attr(Attr::u8(
            NL80211_ATTR_STA_SUPPORT_P2P_PS,
            NL80211_P2P_PS_UNSUPPORTED,
        ))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, 1))
        .attr(Attr::u16v(NL80211_ATTR_STA_LISTEN_INTERVAL, 0))
        .attr(Attr::bytes(
            NL80211_ATTR_STA_FLAGS2,
            &sta_flags(authenticated | associated, 0),
        ))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta));
    if let Some(link_id) = link_id {
        m = m.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id));
    }
    if let Some(mld_mac) = mld_mac {
        m = m.attr(Attr::bytes(NL80211_ATTR_MLD_ADDR, mld_mac));
    }
    m
}

pub(super) fn reset_station_message(
    family: u16,
    seq: u32,
    wdev: u64,
    sta: &[u8; 6],
) -> GenlMessage {
    GenlMessage::new(family, NL80211_CMD_DEL_STATION, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
}

/// Clear any driver peer incarnation before publishing the unassociated
/// FULL_AP_CLIENT_STATE station. Send this targeted DEL_STATION even when
/// userspace believes the peer is absent; mt7996 may retain firmware TX lookup
/// state after the previous AP_VLAN has gone away.
pub(super) fn nl_reset_station(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
) -> bool {
    let seq = sock.next_seq();
    match sock.request_ack(reset_station_message(family, seq, wdev, sta)) {
        Ok(()) => true,
        Err(error) if kernel_object_is_absent(&error) => true,
        Err(error) => {
            eprintln!(
                "netlink AP: DEL_STATION(pre-add) {} failed: {error}",
                crate::util::bytes_to_mac(sta),
            );
            false
        }
    }
}

/// Add a station to the kernel in the *unassociated* state. hwsim lacks
/// `FULL_AP_CLIENT_STATE`, so — like reference AP's "UNASSOC_STA workaround" — the
/// station must be added with AUTH/ASSOC explicitly cleared while retaining its
/// WME peer state, then promoted to associated via SET_STATION.
pub(super) fn nl_new_station(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    mld_mac: Option<&[u8; 6]>,
    link_id: Option<u8>,
) -> bool {
    let seq = sock.next_seq();
    let _ = STA_OFDM_RATES;
    let m = new_unassociated_station_message(family, seq, wdev, sta, mld_mac, link_id);
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

pub(super) fn multicast_to_unicast_message(family: u16, seq: u32, ifindex: u32) -> GenlMessage {
    GenlMessage::new(family, NL80211_CMD_SET_MULTICAST_TO_UNICAST, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
}

pub(super) fn nl_enable_multicast_to_unicast(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
) -> bool {
    let seq = sock.next_seq();
    if let Err(error) = sock.request_ack(multicast_to_unicast_message(family, seq, ifindex)) {
        eprintln!("netlink AP: SET_MULTICAST_TO_UNICAST failed: {error}");
        return false;
    }
    true
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

pub(super) fn station_supported_rates(
    outer: &[u8],
    link: Option<&[u8]>,
    include_extended: bool,
) -> Vec<u8> {
    let mut rates = station_ie(outer, link, 1)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    // Publish only the lowest negotiated OFDM rate for a 5/6-GHz station.
    // Extended Supported Rates is a 2.4-GHz compatibility mechanism and is
    // merged only there.
    if include_extended {
        if let Some(extended) = station_ie(outer, link, 50) {
            for rate in extended {
                if !rates.iter().any(|existing| existing & 0x7f == rate & 0x7f) {
                    rates.push(*rate);
                }
            }
        }
    } else {
        rates.truncate(1);
    }
    rates
}

/// Negotiate a station's VHT capability word using directional
/// beamformer/beamformee rules.
///
/// A plain bitwise intersection is incorrect for directional capabilities:
/// the station's beamformer bit is usable when the AP is a beamformee, and
/// vice versa. On mt7996 that incorrect bitmap is consumed by firmware rate
/// control for ordinary unicast data, while control-port EAPOL still succeeds
/// at a basic rate.
pub(super) fn negotiate_station_vht_capability(station: &mut [u8], ap: &[u8]) {
    if station.len() < 4 || ap.len() < 4 {
        return;
    }

    const SHORT_GI_80: u32 = 1 << 5;
    const SHORT_GI_160: u32 = 1 << 6;
    const TX_STBC: u32 = 1 << 7;
    const RX_STBC_MASK: u32 = (1 << 8) | (1 << 9) | (1 << 10);
    const SU_BEAMFORMER: u32 = 1 << 11;
    const SU_BEAMFORMEE: u32 = 1 << 12;
    const BEAMFORMEE_STS_MASK: u32 = (1 << 13) | (1 << 14) | (1 << 15);
    const SOUNDING_DIMENSION_MASK: u32 = (1 << 16) | (1 << 17) | (1 << 18);
    const MU_BEAMFORMER: u32 = 1 << 19;
    const MU_BEAMFORMEE: u32 = 1 << 20;
    const WIDTH_160: u32 = 1 << 2;
    const WIDTH_160_80P80: u32 = 1 << 3;
    const WIDTH_MASK: u32 = WIDTH_160 | WIDTH_160_80P80;

    let mut capability =
        u32::from_le_bytes(station[..4].try_into().expect("four station VHT bytes"));
    let own = u32::from_le_bytes(ap[..4].try_into().expect("four AP VHT bytes"));

    let symmetric = SHORT_GI_80 | SHORT_GI_160;
    capability &= !symmetric | (own & symmetric);

    if own & SU_BEAMFORMER == 0 {
        capability &= !(SU_BEAMFORMEE | BEAMFORMEE_STS_MASK);
    }
    if own & SU_BEAMFORMEE == 0 {
        capability &= !(SU_BEAMFORMER | SOUNDING_DIMENSION_MASK);
    }
    if own & MU_BEAMFORMER == 0 {
        capability &= !MU_BEAMFORMEE;
    }
    if own & MU_BEAMFORMEE == 0 {
        capability &= !MU_BEAMFORMER;
    }

    match own & WIDTH_MASK {
        WIDTH_160_80P80 => {}
        WIDTH_160 => {
            if capability & WIDTH_160_80P80 != 0 {
                capability &= !WIDTH_160_80P80;
                capability |= WIDTH_160;
            }
        }
        _ => capability &= !WIDTH_MASK,
    }
    if capability & WIDTH_MASK == 0 {
        capability &= !SHORT_GI_160;
    }

    // TX and RX STBC are directional in the same way as beamforming.
    if own & RX_STBC_MASK == 0 {
        capability &= !TX_STBC;
    }
    if own & TX_STBC == 0 {
        capability &= !RX_STBC_MASK;
    }

    station[..4].copy_from_slice(&capability.to_le_bytes());
}

/// Attach the same station PHY capability attributes reference AP sends. A partner
/// link's Per-STA Profile overrides the outer association IEs; anything it
/// omits is inherited from the outer request.
pub(super) fn with_station_phy_capabilities(
    mut msg: GenlMessage,
    outer: &[u8],
    link: Option<&[u8]>,
    ap_caps: Option<&WiphyCapabilities>,
) -> GenlMessage {
    if let Some(ht) = station_ie(outer, link, 45) {
        let mut negotiated = ht.to_vec();
        if let Some(ap_ht) = ap_caps.and_then(|caps| caps.ht.as_deref()) {
            for (station, ap) in negotiated.iter_mut().zip(ap_ht).take(2) {
                *station &= *ap;
            }
        }
        msg = msg.attr(Attr::bytes(NL80211_ATTR_HT_CAPABILITY, &negotiated));
    }
    if let Some(vht) = station_ie(outer, link, 191) {
        let mut negotiated = vht.to_vec();
        if let Some(ap_vht) = ap_caps.and_then(|caps| caps.vht.as_deref()) {
            negotiate_station_vht_capability(&mut negotiated, ap_vht);
        }
        msg = msg.attr(Attr::bytes(NL80211_ATTR_VHT_CAPABILITY, &negotiated));
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
fn nl_publish_associated_station(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
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
    new_station: bool,
    ap_caps: Option<&WiphyCapabilities>,
    include_extended_rates: bool,
) -> bool {
    let seq = sock.next_seq();
    // Real supported rates from the assoc request (Supported Rates id 1 + Extended
    // Rates id 50), basic-rate bits preserved, like reference AP; fall back to OFDM.
    let mut rates = assoc_ies
        .map(|ies| station_supported_rates(ies, None, include_extended_rates))
        .unwrap_or_default();
    if rates.is_empty() {
        rates.extend_from_slice(&STA_OFDM_RATES);
    }
    let qosinfo = assoc_ies.and_then(find_wmm_qosinfo);
    let assoc = associated_station_flags(capability, force_wme || qosinfo.is_some(), mfp);
    let command = if new_station {
        NL80211_CMD_NEW_STATION
    } else {
        NL80211_CMD_SET_STATION
    };
    // Preserve driver_nl80211's attribute order. nl80211 attributes are
    // nominally unordered, but this also makes the station publication
    // byte-for-byte comparable with the known-good mt7996 path.
    let mut m = GenlMessage::new(family, command, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::bytes(NL80211_ATTR_STA_SUPPORTED_RATES, &rates))
        .attr(Attr::u16v(NL80211_ATTR_STA_CAPABILITY, capability));
    if let Some(ies) = assoc_ies {
        m = with_station_phy_capabilities(m, ies, None, ap_caps);
    }
    m = m
        .attr(Attr::u8(
            NL80211_ATTR_STA_SUPPORT_P2P_PS,
            NL80211_P2P_PS_UNSUPPORTED,
        ))
        .attr(Attr::u16v(NL80211_ATTR_STA_AID, aid))
        .attr(Attr::u16v(
            NL80211_ATTR_STA_LISTEN_INTERVAL,
            listen_interval,
        ))
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
    // Carry the station's negotiated WME values after the PHY capabilities and
    // state attributes, as driver_nl80211 does.
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
    if force_wme && qosinfo.is_none() {
        m = m.attr(Attr::nested(
            NL80211_ATTR_STA_WME,
            &[
                Attr::bytes(NL80211_STA_WME_UAPSD_QUEUES, &[0]),
                Attr::bytes(NL80211_STA_WME_MAX_SP, &[0]),
            ],
        ));
    }
    m = m.attr(Attr::bytes(NL80211_ATTR_MAC, sta));
    match sock.request_ack(m) {
        Ok(()) => {
            if new_station {
                eprintln!(
                    "netlink AP: NEW_STATION {} ok (associated, full client state)",
                    crate::util::bytes_to_mac(sta)
                );
            }
            true
        }
        Err(e) => {
            let operation = if new_station {
                "NEW_STATION(assoc)"
            } else {
                "SET_STATION(assoc)"
            };
            eprintln!(
                "netlink AP: {operation} {} failed: {e}",
                crate::util::bytes_to_mac(sta)
            );
            false
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn nl_add_associated_station(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    aid: u16,
    listen_interval: u16,
    capability: u16,
    assoc_ies: Option<&[u8]>,
    mfp: bool,
    ap_caps: Option<&WiphyCapabilities>,
    include_extended_rates: bool,
) -> bool {
    nl_publish_associated_station(
        sock,
        family,
        wdev,
        sta,
        aid,
        listen_interval,
        capability,
        assoc_ies,
        None,
        None,
        None,
        false,
        mfp,
        true,
        ap_caps,
        include_extended_rates,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn nl_set_station_assoc(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
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
    ap_caps: Option<&WiphyCapabilities>,
    include_extended_rates: bool,
) -> bool {
    nl_publish_associated_station(
        sock,
        family,
        wdev,
        sta,
        aid,
        listen_interval,
        capability,
        assoc_ies,
        mld_mac,
        link_id,
        eml_capability,
        force_wme,
        mfp,
        false,
        ap_caps,
        include_extended_rates,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn nl_add_link_station(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
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
    ap_caps: Option<&WiphyCapabilities>,
    include_extended_rates: bool,
) -> bool {
    let mut rates = assoc_ies
        .map(|ies| station_supported_rates(ies, link_ies, include_extended_rates))
        .unwrap_or_default();
    if rates.is_empty() {
        rates.extend_from_slice(&STA_OFDM_RATES);
    }
    let flags = associated_station_flags(capability, true, mfp);
    let seq = sock.next_seq();
    let mut m = GenlMessage::new(family, NL80211_CMD_ADD_LINK_STA, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
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
        .attr(Attr::u8(
            NL80211_ATTR_STA_SUPPORT_P2P_PS,
            NL80211_P2P_PS_UNSUPPORTED,
        ))
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
        m = with_station_phy_capabilities(m, ies, link_ies, ap_caps);
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

fn station_flags_message(
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
    mask: u32,
    set: u32,
    seq: u32,
) -> GenlMessage {
    // Match driver_nl80211's backwards-compatible STA_FLAGS nest exactly.
    // Modern kernels consume STA_FLAGS2 first, but FullMAC stacks may still
    // inspect the legacy copy when applying station state to firmware.
    let mut legacy = Vec::new();
    for station_flag in [
        NL80211_STA_FLAG_AUTHORIZED,
        NL80211_STA_FLAG_WME,
        NL80211_STA_FLAG_SHORT_PREAMBLE,
        NL80211_STA_FLAG_MFP,
    ] {
        if total_flags & (1u32 << station_flag) != 0 {
            legacy.push(Attr::bytes(station_flag as u16, &[]));
        }
    }
    let flags = sta_flags(mask, set);
    GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::nested(NL80211_ATTR_STA_FLAGS, &legacy))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags))
}

/// Refresh the mutable pre-association flags after queuing a successful
/// Authentication response.
///
/// Issue this SET_STATION for a FULL_AP_CLIENT_STATE peer that was added
/// unassociated before the Authentication response. At this point it clears
/// all four mutable flags; WME is enabled only by the later associated
/// SET_STATION after the station has actually negotiated it.
pub(super) fn pre_assoc_station_flags_message(
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    seq: u32,
) -> GenlMessage {
    let mutable = (1u32 << NL80211_STA_FLAG_AUTHORIZED)
        | (1u32 << NL80211_STA_FLAG_SHORT_PREAMBLE)
        | (1u32 << NL80211_STA_FLAG_WME)
        | (1u32 << NL80211_STA_FLAG_MFP);
    let flags = sta_flags(mutable, 0);
    GenlMessage::new(family, NL80211_CMD_SET_STATION, 0, seq)
        .attr(Attr::bytes(NL80211_ATTR_WDEV, &wdev.to_ne_bytes()))
        .attr(Attr::bytes(NL80211_ATTR_MAC, sta))
        .attr(Attr::bytes(NL80211_ATTR_STA_FLAGS2, &flags))
}

pub(super) fn nl_refresh_pre_assoc_station_flags(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
) -> bool {
    let seq = sock.next_seq();
    let message = pre_assoc_station_flags_message(family, wdev, sta, seq);
    if let Err(error) = sock.request_ack(message) {
        eprintln!(
            "netlink AP: SET_STATION(pre-assoc flags) {} failed: {error}",
            crate::util::bytes_to_mac(sta),
        );
        return false;
    }
    true
}

/// Re-apply the MLD-level station flags after SET_STA_VLAN.
///
/// Do this after the successful Association Response TX status and AP_VLAN
/// binding, but before starting WPA. The `set_flags` mask covers exactly these
/// four mutable driver flags; AUTHENTICATED
/// and ASSOCIATED were already set by the station-add operation.
pub(super) fn refresh_associated_station_flags_message(
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
    seq: u32,
) -> GenlMessage {
    let mask = (1u32 << NL80211_STA_FLAG_AUTHORIZED)
        | (1u32 << NL80211_STA_FLAG_WME)
        | (1u32 << NL80211_STA_FLAG_SHORT_PREAMBLE)
        | (1u32 << NL80211_STA_FLAG_MFP);
    station_flags_message(
        family,
        wdev,
        sta,
        total_flags,
        mask,
        total_flags & mask,
        seq,
    )
}

pub(super) fn nl_refresh_associated_station_flags(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
) -> bool {
    let seq = sock.next_seq();
    let m = refresh_associated_station_flags_message(family, wdev, sta, total_flags, seq);
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: SET_STATION(post-assoc flags) {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        );
        return false;
    }
    true
}

/// Keep the controlled port closed after AP_VLAN binding and pairwise-key
/// cleanup. The second post-bind SET_STATION updates only AUTHORIZED
/// (`mask=AUTHORIZED, set=0`); repeating the broader WME/MFP/preamble update
/// here can make a FullMAC driver rebuild peer
/// state between the VLAN move and the four-way handshake.
pub(super) fn clear_authorized_station_message(
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
    seq: u32,
) -> GenlMessage {
    let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    station_flags_message(family, wdev, sta, total_flags, bit, 0, seq)
}

pub(super) fn nl_clear_authorized(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
) -> bool {
    let seq = sock.next_seq();
    let m = clear_authorized_station_message(family, wdev, sta, total_flags, seq);
    if let Err(e) = sock.request_ack(m) {
        eprintln!(
            "netlink AP: SET_STATION(clear authorized) {} failed: {e}",
            crate::util::bytes_to_mac(sta)
        );
        return false;
    }
    true
}

/// Mark a station 802.1X-authorized so the kernel forwards its data frames.
pub(super) fn authorize_station_message(
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
    seq: u32,
) -> GenlMessage {
    let bit = 1u32 << NL80211_STA_FLAG_AUTHORIZED;
    station_flags_message(family, wdev, sta, total_flags, bit, bit, seq)
}

pub(super) fn nl_authorize(
    sock: &mut NetlinkSocket,
    family: u16,
    wdev: u64,
    sta: &[u8; 6],
    total_flags: u32,
) -> bool {
    let seq = sock.next_seq();
    let m = authorize_station_message(family, wdev, sta, total_flags, seq);
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

pub(super) fn pre_cac_scan_message(
    family: u16,
    seq: u32,
    ifindex: u32,
    frequencies: &[u32],
) -> GenlMessage {
    let frequencies = frequencies
        .iter()
        .enumerate()
        .map(|(index, frequency)| Attr::u32((index + 1) as u16, *frequency))
        .collect::<Vec<_>>();
    GenlMessage::new(family, NL80211_CMD_TRIGGER_SCAN, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::nested(NL80211_ATTR_SCAN_FREQUENCIES, &frequencies))
        // The interface is already in AP mode but is not beaconing yet.
        .attr(Attr::u32(NL80211_ATTR_SCAN_FLAGS, NL80211_SCAN_FLAG_AP))
}

/// Perform the passive HT40 coexistence scan the reference AP runs before
/// enabling a wide channel. Some full-MAC drivers reject DFS CAC until this
/// pre-beacon AP scan has initialized their channel context.
pub(super) fn do_pre_cac_scan(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    primary_frequency: u32,
    secondary_frequency: u32,
) -> io::Result<()> {
    fn consume_results(sock: &mut NetlinkSocket, family: u16, ifindex: u32) -> io::Result<()> {
        // Match the reference AP's GET_SCAN after NEW_SCAN_RESULTS. Besides
        // applying the coexistence check in userspace, this request/response is
        // a driver serialization barrier: ath12k can emit the multicast event
        // just before its scan channel context is ready for RADAR_DETECT.
        let seq = sock.next_seq();
        sock.send(
            &GenlMessage::new(family, NL80211_CMD_GET_SCAN, msg::NLM_F_DUMP, seq)
                .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                .to_bytes(sock.pid),
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let Some(buf) = sock.recv(Duration::from_millis(500)) else {
                continue;
            };
            for parsed in msg::parse_messages(&buf) {
                if parsed.seq != seq {
                    continue;
                }
                if parsed.typ == msg::NLMSG_DONE {
                    return Ok(());
                }
                if let Some(code) = parsed.error_code() {
                    if code == 0 {
                        continue;
                    }
                    return Err(io::Error::from_raw_os_error(-code));
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "pre-CAC scan result dump did not complete",
        ))
    }

    let frequencies = [primary_frequency, secondary_frequency];
    let seq = sock.next_seq();
    match sock.request_ack(pre_cac_scan_message(family, seq, ifindex, &frequencies)) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {}
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!("pre-CAC coexistence scan rejected: {error}"),
            ))
        }
    }

    eprintln!(
        "netlink AP: DFS — passive coexistence scan on {primary_frequency}/{secondary_frequency} MHz"
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != family {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let event_ifindex = msg::find_attr(&attrs, NL80211_ATTR_IFINDEX)
                .and_then(|value| value.get(..4))
                .map(|value| u32::from_ne_bytes(value.try_into().unwrap()));
            if event_ifindex != Some(ifindex) {
                continue;
            }
            match parsed.genl_cmd() {
                Some(NL80211_CMD_NEW_SCAN_RESULTS) => {
                    return consume_results(sock, family, ifindex)
                }
                Some(NL80211_CMD_SCAN_ABORTED) => {
                    return Err(io::Error::other("pre-CAC coexistence scan aborted"))
                }
                _ => {}
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "pre-CAC coexistence scan did not complete",
    ))
}

pub(super) fn radar_detect_message(
    family: u16,
    seq: u32,
    ifindex: u32,
    freq: u32,
    chan_width: u32,
    center_freq1: u32,
    link_id: Option<u8>,
) -> GenlMessage {
    let message = GenlMessage::new(family, NL80211_CMD_RADAR_DETECT, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, freq))
        .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, chan_width))
        .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, center_freq1));
    match link_id {
        Some(link_id) => message.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link_id)),
        None => message,
    }
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
    link_id: Option<u8>,
) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(radar_detect_message(
        family,
        seq,
        ifindex,
        freq,
        chan_width,
        center_freq1,
        link_id,
    ))
    .map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("DFS RADAR_DETECT rejected on {freq} MHz link={link_id:?} ({e})"),
        )
    })?;
    eprintln!(
        "netlink AP: DFS — running CAC (radar listen) on {freq} MHz link={link_id:?}, ~60 s..."
    );
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
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let event_link = msg::find_attr(&attrs, NL80211_ATTR_MLO_LINK_ID)
                .and_then(|value| value.first())
                .copied();
            if link_id.is_some() && event_link.is_some() && event_link != link_id {
                continue;
            }
            match radar_event(&attrs) {
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

    fn attr(message: &GenlMessage, kind: u16) -> Option<&[u8]> {
        message
            .attrs
            .iter()
            .find(|attribute| attribute.typ & 0x3fff == kind)
            .map(|attribute| attribute.data.as_slice())
    }

    #[test]
    fn transition_ap_uses_the_wpa3_nl80211_version() {
        assert_eq!(
            nl80211_ap_wpa_version(dot11::SecurityMode::Transition),
            NL80211_WPA_VERSION_3
        );
        assert_eq!(
            nl80211_ap_wpa_version(dot11::SecurityMode::Wpa2),
            NL80211_WPA_VERSION_2
        );
    }

    #[test]
    fn unassociated_station_has_clean_pre_auth_state() {
        let sta = [0x56, 0x45, 0x5b, 0xec, 0xa4, 0xc7];
        let message = new_unassociated_station_message(42, 9, 343, &sta, None, None);

        assert_eq!(message.cmd, NL80211_CMD_NEW_STATION);
        assert_eq!(
            attr(&message, NL80211_ATTR_STA_SUPPORTED_RATES),
            Some([0x0c, 0x18, 0x30].as_slice())
        );
        let flags = attr(&message, NL80211_ATTR_STA_FLAGS2).expect("STA_FLAGS2");
        let authenticated = 1u32 << NL80211_STA_FLAG_AUTHENTICATED;
        let associated = 1u32 << NL80211_STA_FLAG_ASSOCIATED;
        assert_eq!(&flags[..4], &(authenticated | associated).to_ne_bytes());
        assert_eq!(&flags[4..], &0u32.to_ne_bytes());
        assert_eq!(attr(&message, NL80211_ATTR_STA_WME), None);
    }

    #[test]
    fn pre_add_station_reset_has_clean_shape() {
        let sta = [0x56, 0x45, 0x5b, 0xec, 0xa4, 0xc7];
        let message = reset_station_message(42, 9, 343, &sta);
        assert_eq!(message.cmd, NL80211_CMD_DEL_STATION);
        assert_eq!(
            attr(&message, NL80211_ATTR_WDEV),
            Some(343u64.to_ne_bytes().as_slice())
        );
        assert_eq!(attr(&message, NL80211_ATTR_MAC), Some(sta.as_slice()));
        assert_eq!(message.to_bytes(7).len(), 44);
    }

    #[test]
    fn multicast_to_unicast_has_expected_shape() {
        let message = multicast_to_unicast_message(42, 9, 7);
        assert_eq!(message.cmd, NL80211_CMD_SET_MULTICAST_TO_UNICAST);
        assert_eq!(
            attr(&message, NL80211_ATTR_IFINDEX),
            Some(7u32.to_ne_bytes().as_slice())
        );
        assert_eq!(message.to_bytes(8).len(), 28);
    }

    #[test]
    fn pre_assoc_refresh_has_clean_flags() {
        let sta = [0x56, 0x45, 0x5b, 0xec, 0xa4, 0xc7];
        let message = pre_assoc_station_flags_message(42, 343, &sta, 9);
        let flags = attr(&message, NL80211_ATTR_STA_FLAGS2).expect("STA_FLAGS2");

        assert_eq!(message.cmd, NL80211_CMD_SET_STATION);
        assert_eq!(u32::from_ne_bytes(flags[..4].try_into().unwrap()), 0x1e);
        assert_eq!(u32::from_ne_bytes(flags[4..].try_into().unwrap()), 0);
        assert_eq!(attr(&message, NL80211_ATTR_STA_FLAGS), None);
    }

    #[test]
    fn station_ht_vht_flags_are_negotiated_with_ap_capabilities() {
        let mut ht = vec![0u8; 26];
        ht[..2].copy_from_slice(&[0xe7, 0x19]);
        let mut vht = vec![0u8; 12];
        vht[..4].copy_from_slice(&[0xf6, 0x79, 0x89, 0x33]);
        let mut ies = vec![45, ht.len() as u8];
        ies.extend_from_slice(&ht);
        ies.extend_from_slice(&[191, vht.len() as u8]);
        ies.extend_from_slice(&vht);
        let caps = WiphyCapabilities {
            ht: Some({
                let mut bytes = vec![0xff; 26];
                bytes[..2].copy_from_slice(&[0xff, 0xef]);
                bytes
            }),
            vht: Some({
                let mut bytes = vec![0xff; 12];
                // Reference AP advertises MU beamformer, but not MU
                // beamformee. The station advertises the reciprocal role.
                bytes[..4].copy_from_slice(&[0xf6, 0x79, 0x8a, 0x33]);
                bytes
            }),
            ..Default::default()
        };
        let message = with_station_phy_capabilities(
            GenlMessage::new(42, NL80211_CMD_SET_STATION, 0, 9),
            &ies,
            None,
            Some(&caps),
        );

        assert_eq!(
            attr(&message, NL80211_ATTR_HT_CAPABILITY).unwrap()[..2],
            [0xe7, 0x09]
        );
        assert_eq!(
            attr(&message, NL80211_ATTR_VHT_CAPABILITY).unwrap()[..4],
            [0xf6, 0x79, 0x81, 0x33]
        );
    }

    #[test]
    fn extended_station_rates_are_used_only_on_2ghz() {
        let ies = [
            1, 1, 0x0c, 50, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
        ];

        assert_eq!(station_supported_rates(&ies, None, false), [0x0c]);
        assert_eq!(
            station_supported_rates(&ies, None, true),
            [0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]
        );

        let full_supported = [1, 8, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c];
        assert_eq!(
            station_supported_rates(&full_supported, None, false),
            [0x0c]
        );
    }

    #[test]
    fn mld_radar_detection_is_scoped_to_the_link() {
        let mld = radar_detect_message(42, 7, 343, 5500, NL80211_CHAN_WIDTH_80, 5530, Some(1));
        assert_eq!(
            mld.cmd, 94,
            "nl80211 command numbers are a stable userspace ABI"
        );
        assert_eq!(
            attr(&mld, NL80211_ATTR_IFINDEX),
            Some(343u32.to_ne_bytes().as_slice())
        );
        assert_eq!(
            attr(&mld, NL80211_ATTR_WIPHY_FREQ),
            Some(5500u32.to_ne_bytes().as_slice())
        );
        assert_eq!(attr(&mld, NL80211_ATTR_MLO_LINK_ID), Some([1].as_slice()));

        let legacy = radar_detect_message(42, 8, 343, 5500, NL80211_CHAN_WIDTH_80, 5530, None);
        assert_eq!(attr(&legacy, NL80211_ATTR_MLO_LINK_ID), None);
    }

    #[test]
    fn pre_cac_scan_is_passive_ap_scan_on_the_ht40_pair() {
        let scan = pre_cac_scan_message(42, 9, 343, &[5500, 5520]);
        assert_eq!(scan.cmd, NL80211_CMD_TRIGGER_SCAN);
        assert_eq!(attr(&scan, NL80211_ATTR_SCAN_SSIDS), None);
        assert_eq!(
            attr(&scan, NL80211_ATTR_SCAN_FLAGS),
            Some(NL80211_SCAN_FLAG_AP.to_ne_bytes().as_slice())
        );
        let frequencies = msg::parse_attrs(attr(&scan, NL80211_ATTR_SCAN_FREQUENCIES).unwrap());
        assert_eq!(
            frequencies,
            [
                (1, 5500u32.to_ne_bytes().as_slice()),
                (2, 5520u32.to_ne_bytes().as_slice())
            ]
        );
    }

    #[test]
    fn mld_authorization_uses_only_the_peer_mld_address() {
        let mld = [0x6e, 0x45, 0xbe, 0x78, 0x3b, 0xf2];
        let total_flags =
            associated_station_flags(1 << 5, true, true) | (1u32 << NL80211_STA_FLAG_AUTHORIZED);
        let msg = authorize_station_message(42, 343, &mld, total_flags, 7);

        assert_eq!(msg.cmd, NL80211_CMD_SET_STATION);
        assert_eq!(
            attr(&msg, NL80211_ATTR_WDEV),
            Some(343u64.to_ne_bytes().as_slice())
        );
        assert_eq!(attr(&msg, NL80211_ATTR_IFINDEX), None);
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

        let legacy =
            msg::parse_attrs(attr(&msg, NL80211_ATTR_STA_FLAGS).expect("legacy STA_FLAGS"));
        assert_eq!(
            legacy.iter().map(|(typ, _)| *typ).collect::<Vec<_>>(),
            vec![
                NL80211_STA_FLAG_AUTHORIZED as u16,
                NL80211_STA_FLAG_WME as u16,
                NL80211_STA_FLAG_SHORT_PREAMBLE as u16,
                NL80211_STA_FLAG_MFP as u16,
            ],
            "legacy authorization flags and order match driver_nl80211"
        );
    }

    #[test]
    fn post_assoc_flags_match_callback_update() {
        let mld = [0x6e, 0x45, 0xbe, 0x78, 0x3b, 0xf2];
        let total_flags = associated_station_flags(1 << 5, true, true);
        let msg = refresh_associated_station_flags_message(42, 343, &mld, total_flags, 8);

        assert_eq!(
            attr(&msg, NL80211_ATTR_WDEV),
            Some(343u64.to_ne_bytes().as_slice())
        );
        assert_eq!(attr(&msg, NL80211_ATTR_IFINDEX), None);
        assert_eq!(attr(&msg, NL80211_ATTR_MAC), Some(mld.as_slice()));
        assert_eq!(attr(&msg, NL80211_ATTR_MLO_LINK_ID), None);
        let flags = attr(&msg, NL80211_ATTR_STA_FLAGS2).expect("STA_FLAGS2");
        let mutable = (1u32 << NL80211_STA_FLAG_AUTHORIZED)
            | (1u32 << NL80211_STA_FLAG_WME)
            | (1u32 << NL80211_STA_FLAG_SHORT_PREAMBLE)
            | (1u32 << NL80211_STA_FLAG_MFP);
        assert_eq!(&flags[..4], &mutable.to_ne_bytes());
        assert_eq!(&flags[4..], &(total_flags & mutable).to_ne_bytes());
        assert_eq!(
            msg::parse_attrs(attr(&msg, NL80211_ATTR_STA_FLAGS).expect("legacy STA_FLAGS"))
                .iter()
                .map(|(typ, _)| *typ)
                .collect::<Vec<_>>(),
            vec![
                NL80211_STA_FLAG_WME as u16,
                NL80211_STA_FLAG_SHORT_PREAMBLE as u16,
                NL80211_STA_FLAG_MFP as u16,
            ]
        );
    }

    #[test]
    fn post_vlan_key_cleanup_only_clears_authorized() {
        let sta = [0xd6, 0x76, 0x9d, 0x35, 0xfa, 0x7c];
        let total_flags = associated_station_flags(1 << 5, true, true);
        let msg = clear_authorized_station_message(42, 343, &sta, total_flags, 9);
        let flags = attr(&msg, NL80211_ATTR_STA_FLAGS2).expect("STA_FLAGS2");
        let authorized = 1u32 << NL80211_STA_FLAG_AUTHORIZED;

        assert_eq!(&flags[..4], &authorized.to_ne_bytes());
        assert_eq!(&flags[4..], &0u32.to_ne_bytes());
        assert_eq!(
            msg::parse_attrs(attr(&msg, NL80211_ATTR_STA_FLAGS).expect("legacy STA_FLAGS"))
                .iter()
                .map(|(typ, _)| *typ)
                .collect::<Vec<_>>(),
            vec![
                NL80211_STA_FLAG_WME as u16,
                NL80211_STA_FLAG_SHORT_PREAMBLE as u16,
                NL80211_STA_FLAG_MFP as u16,
            ],
            "preserve legacy flags while changing only AUTHORIZED in STA_FLAGS2"
        );
    }

    #[test]
    fn bss_parameters_are_band_correct() {
        let two_ghz = set_bss_message(
            42,
            1,
            7,
            BssParameters {
                link_id: Some(0),
                channel: 6,
                short_preamble: true,
                ht_opmode: Some(0),
                isolate: false,
            },
        );
        let five_ghz = set_bss_message(
            42,
            2,
            7,
            BssParameters {
                link_id: Some(1),
                channel: 36,
                short_preamble: true,
                ht_opmode: Some(0),
                isolate: false,
            },
        );

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
        assert_eq!(
            attr(&five_ghz, NL80211_ATTR_BSS_SHORT_PREAMBLE),
            Some([1].as_slice())
        );
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

    #[test]
    fn control_port_eapol_is_unencrypted_only_before_ptk_installation() {
        let sta = [0x02, 0, 0, 0, 0, 2];
        let eapol = [2, 3, 0, 0];
        let before_ptk = control_port_eapol_message(42, 1, 7, &sta, &eapol, false, None);
        let after_ptk = control_port_eapol_message(42, 2, 7, &sta, &eapol, true, None);

        assert_eq!(
            attr(&before_ptk, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT),
            Some([].as_slice())
        );
        assert_eq!(
            attr(&after_ptk, NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT),
            None,
            "group-key and PTK-rekey EAPOL is protected under the installed PTK"
        );
    }
}
