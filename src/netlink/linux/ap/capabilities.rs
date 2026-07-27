use super::*;

/// The interface's own MAC as the kernel reports it (`/sys/class/net/<if>/address`).
pub(super) fn read_iface_mac(iface: &str) -> io::Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let s = std::fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("read {path}: {e}")))?;
    crate::util::try_mac_to_bytes(s.trim()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{path} does not contain a valid MAC address"),
        )
    })
}

/// Capability element payloads derived from this radio's nl80211 GET_WIPHY
/// response. reference AP builds its beacon/response capability IEs from the same
/// attributes. Keeping the driver's bytes is important: an internally
/// inconsistent synthetic HE/EHT advertisement is tolerated by some Linux
/// scanners but rejected by stricter clients (notably macOS).
#[derive(Default, Debug)]
pub(super) struct WiphyCapabilities {
    pub(super) ht: Option<Vec<u8>>,
    pub(super) vht: Option<Vec<u8>>,
    pub(super) he: Option<Vec<u8>>,
    pub(super) eht: Option<Vec<u8>>,
    pub(super) eml: Option<u16>,
    pub(super) mld: Option<u16>,
}

impl WiphyCapabilities {
    pub(super) fn phy_capabilities(&self) -> dot11::PhyCapabilities {
        dot11::PhyCapabilities {
            ht: self.ht.clone(),
            vht: self.vht.clone(),
            he: self.he.clone(),
            eht: self.eht.clone(),
        }
    }
}

// `enum nl80211_band` values from linux/nl80211.h. Keep these named: band 4
// is S1GHz, not 6 GHz, and querying it silently yields no HE/EHT capabilities.
pub(super) const NL80211_BAND_2GHZ: u16 = 0;
pub(super) const NL80211_BAND_5GHZ: u16 = 1;
pub(super) const NL80211_BAND_6GHZ: u16 = 3;

pub(super) fn he_ppe_len(header: u8, phy: &[u8]) -> usize {
    if phy.get(6).copied().unwrap_or(0) & 0x80 == 0 {
        return 0;
    }
    let ru_count = ((header >> 3) & 0x0f).count_ones() as usize;
    let nss = 1 + (header & 0x07) as usize;
    (7 + 6 * ru_count * nss).div_ceil(8)
}

pub(super) fn build_he_capability(attrs: &[(u16, &[u8])]) -> Option<Vec<u8>> {
    let mac = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC)?;
    let raw_phy = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY)?;
    let mcs = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET)?;
    if mac.len() < 6 || raw_phy.len() < 11 {
        return None;
    }
    let mut phy = raw_phy[..11].to_vec();
    // RustAP does not currently configure SU/MU beamforming. Match reference AP's
    // default mask so we advertise only features enabled by the AP, not every
    // feature the radio could support under a different configuration.
    phy[3] &= !0x80; // SU beamformer
    phy[4] &= !(0x01 | 0x02); // SU beamformee + MU beamformer
                              // Base <=80 MHz RX/TX maps are four bytes. 160 and 80+80 each add four,
                              // based on the channel-width bits in HE PHY capability octet zero.
    let mut mcs_len = 4;
    if phy[0] & 0x10 != 0 {
        mcs_len += 4;
    }
    if phy[0] & 0x08 != 0 {
        mcs_len += 4;
    }
    if mcs.len() < mcs_len {
        return None;
    }
    let ppe = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE).unwrap_or(&[]);
    let ppe_len = ppe.first().map_or(0, |header| he_ppe_len(*header, &phy));
    if ppe.len() < ppe_len {
        return None;
    }
    let mut out = Vec::with_capacity(6 + 11 + mcs_len + ppe_len);
    out.extend_from_slice(&mac[..6]);
    out.extend_from_slice(&phy);
    out.extend_from_slice(&mcs[..mcs_len]);
    out.extend_from_slice(&ppe[..ppe_len]);
    Some(out)
}

pub(super) fn eht_ppe_len(header: u16, phy: &[u8]) -> usize {
    if phy.get(5).copied().unwrap_or(0) & 0x08 == 0 {
        return 0;
    }
    let ru_count = ((header >> 4) & 0x1f).count_ones() as usize;
    let nss = 1 + (header & 0x0f) as usize;
    (9 + 6 * ru_count * nss).div_ceil(8)
}

pub(super) fn build_eht_capability(
    attrs: &[(u16, &[u8])],
    he: &[u8],
    band: u16,
) -> Option<Vec<u8>> {
    let mac = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC)?;
    let raw_phy = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY)?;
    let mcs = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET)?;
    if mac.len() < 2 || raw_phy.len() < 9 || he.len() < 17 {
        return None;
    }
    let he_width = he[6]; // HE body = MAC[6] || PHY[11] || optional fields
    let mut phy = raw_phy[..9].to_vec();
    let mcs_len = if band == 0 && he_width & 0x02 == 0 {
        4 // 20 MHz-only encoding
    } else {
        let mut len = 3; // <=80 MHz
        if band != NL80211_BAND_2GHZ && he_width & (0x08 | 0x10) != 0 {
            len += 3; // 160/80+80 MHz
        }
        if band == NL80211_BAND_6GHZ && phy[0] & 0x02 != 0 {
            len += 3; // 320 MHz in 6 GHz
        }
        len
    };
    if mcs.len() < mcs_len {
        return None;
    }
    // The 320 MHz bit is meaningful only in the 6 GHz band; reference AP clears it
    // in lower-band beacons even when the same radio supports 320 MHz elsewhere.
    if band != NL80211_BAND_6GHZ {
        phy[0] &= !0x02;
    }
    phy[0] &= !(0x20 | 0x40); // SU beamformer + SU beamformee
    phy[7] &= !(0x10 | 0x20 | 0x40); // MU beamformer at 80/160/320 MHz
    let ppe = msg::find_attr(attrs, NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE).unwrap_or(&[]);
    let ppe_header = ppe
        .get(..2)
        .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
        .unwrap_or(0);
    let ppe_len = eht_ppe_len(ppe_header, &phy);
    if ppe.len() < ppe_len {
        return None;
    }
    let mut out = Vec::with_capacity(2 + 9 + mcs_len + ppe_len);
    out.extend_from_slice(&mac[..2]);
    out.extend_from_slice(&phy);
    out.extend_from_slice(&mcs[..mcs_len]);
    out.extend_from_slice(&ppe[..ppe_len]);
    Some(out)
}

pub(super) fn parse_wiphy_capabilities(
    attrs: &[(u16, &[u8])],
    band: u16,
) -> Option<WiphyCapabilities> {
    let bands = msg::find_attr(attrs, NL80211_ATTR_WIPHY_BANDS)?;
    let band_data = msg::parse_attrs(bands)
        .into_iter()
        .find_map(|(typ, data)| (typ == band).then_some(data))?;
    let band_attrs = msg::parse_attrs(band_data);
    let types: Vec<u16> = band_attrs.iter().map(|(typ, _)| *typ).collect();
    if crate::util::netlink_debug_enabled() && (types.len() > 1 || types.first() != Some(&1)) {
        eprintln!("netlink AP: GET_WIPHY band={band} attr_types={types:?}");
    }

    // HT and VHT capabilities are band-wide. Construct their element payloads
    // from the kernel attributes instead of advertising a fixed stream count.
    let ht = (|| {
        let capa = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_CAPA)?;
        let factor = *msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_AMPDU_FACTOR)?.first()?;
        let density = *msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_AMPDU_DENSITY)?.first()?;
        let mcs = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_HT_MCS_SET)?;
        if capa.len() < 2 || mcs.len() < 16 {
            return None;
        }
        let mut body = Vec::with_capacity(26);
        body.extend_from_slice(&capa[..2]);
        body.push((factor & 0x03) | ((density & 0x07) << 2));
        body.extend_from_slice(&mcs[..16]);
        body.extend_from_slice(&[0u8; 7]); // ext caps, TXBF caps, ASEL caps
        Some(body)
    })();
    let vht = (|| {
        let capa = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_VHT_CAPA)?;
        let mcs = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_VHT_MCS_SET)?;
        if capa.len() < 4 || mcs.len() < 8 {
            return None;
        }
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&capa[..4]);
        body.extend_from_slice(&mcs[..8]);
        Some(body)
    })();

    let mut he = None;
    let mut eht = None;
    if let Some(iftypes) = msg::find_attr(&band_attrs, NL80211_BAND_ATTR_IFTYPE_DATA) {
        for (_, entry) in msg::parse_attrs(iftypes) {
            let entry_attrs = msg::parse_attrs(entry);
            if crate::util::netlink_debug_enabled() {
                let entry_types: Vec<u16> = entry_attrs.iter().map(|(typ, _)| *typ).collect();
                let iftype_types: Vec<u16> =
                    msg::find_attr(&entry_attrs, NL80211_BAND_IFTYPE_ATTR_IFTYPES)
                        .map(msg::parse_attrs)
                        .unwrap_or_default()
                        .iter()
                        .map(|(typ, _)| *typ)
                        .collect();
                eprintln!(
                    "netlink AP: GET_WIPHY iftype entry attrs={entry_types:?} iftypes={iftype_types:?}"
                );
            }
            let Some(types) = msg::find_attr(&entry_attrs, NL80211_BAND_IFTYPE_ATTR_IFTYPES) else {
                continue;
            };
            if !msg::parse_attrs(types)
                .iter()
                .any(|(typ, _)| *typ == NL80211_IFTYPE_AP as u16)
            {
                continue;
            }
            he = build_he_capability(&entry_attrs);
            eht = he
                .as_deref()
                .and_then(|he_body| build_eht_capability(&entry_attrs, he_body, band));
            break;
        }
    }
    Some(WiphyCapabilities {
        ht,
        vht,
        he,
        eht,
        eml: None,
        mld: None,
    })
}

pub(super) fn parse_wiphy_mld_capabilities(attrs: &[(u16, &[u8])]) -> Option<(u16, u16)> {
    let entries = msg::find_attr(attrs, NL80211_ATTR_IFTYPE_EXT_CAPA)?;
    for (_, entry) in msg::parse_attrs(entries) {
        let entry_attrs = msg::parse_attrs(entry);
        let iftype = msg::find_attr(&entry_attrs, NL80211_ATTR_IFTYPE)
            .and_then(|value| value.get(..4))
            .map(|value| u32::from_ne_bytes(value.try_into().unwrap()));
        if iftype != Some(NL80211_IFTYPE_AP) {
            continue;
        }
        let eml = msg::find_attr(&entry_attrs, NL80211_ATTR_EML_CAPABILITY)
            .and_then(|value| value.get(..2))
            .map(|value| u16::from_ne_bytes(value.try_into().unwrap()))?;
        let mld = msg::find_attr(&entry_attrs, NL80211_ATTR_MLD_CAPA_AND_OPS)
            .and_then(|value| value.get(..2))
            .map(|value| u16::from_ne_bytes(value.try_into().unwrap()))?;
        return Some((eml, mld));
    }
    None
}

pub(super) fn nl_get_wiphy_capabilities(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    band: u16,
) -> Option<WiphyCapabilities> {
    fn merge(dst: &mut WiphyCapabilities, mut src: WiphyCapabilities) {
        if src.ht.is_some() {
            dst.ht = src.ht.take();
        }
        if src.vht.is_some() {
            dst.vht = src.vht.take();
        }
        if src.he.is_some() {
            dst.he = src.he.take();
        }
        if src.eht.is_some() {
            dst.eht = src.eht.take();
        }
        if src.eml.is_some() {
            dst.eml = src.eml.take();
        }
        if src.mld.is_some() {
            dst.mld = src.mld.take();
        }
    }

    fn merge_mld(dst: &mut WiphyCapabilities, attrs: &[(u16, &[u8])]) {
        if let Some((eml, mld)) = parse_wiphy_mld_capabilities(attrs) {
            dst.eml = Some(eml);
            dst.mld = Some(mld);
        }
    }

    // Resolve the interface's wiphy first. The compact GET_WIPHY response also
    // carries band-wide HT/VHT data, but modern kernels intentionally omit the
    // much larger per-iftype HE/EHT nests unless userspace requests a split
    // wiphy dump.
    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_WIPHY, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    if let Err(e) = sock.send(&request.to_bytes(sock.pid)) {
        eprintln!("netlink AP: GET_WIPHY send failed: {e}");
        return None;
    }
    let mut caps = WiphyCapabilities::default();
    let mut wiphy = None;
    'compact: for _ in 0..16 {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_ERROR {
                let code = parsed.error_code().unwrap_or(-libc::EIO);
                eprintln!("netlink AP: GET_WIPHY failed: {code}");
                return None;
            }
            if parsed.typ == family {
                let attrs = msg::parse_attrs(parsed.genl_attrs());
                wiphy = msg::find_attr(&attrs, NL80211_ATTR_WIPHY)
                    .and_then(|v| v.get(..4))
                    .map(|v| u32::from_ne_bytes(v.try_into().unwrap()));
                merge_mld(&mut caps, &attrs);
                if let Some(found) = parse_wiphy_capabilities(&attrs, band) {
                    merge(&mut caps, found);
                }
                break 'compact;
            }
        }
    }
    let Some(wiphy) = wiphy else {
        eprintln!("netlink AP: GET_WIPHY timed out");
        return None;
    };

    // Ask for the split dump reference AP/iw use and merge every response belonging
    // to this wiphy. HE/EHT per-iftype data commonly arrives in a later message
    // than HT/VHT, so returning after the first multipart record drops it.
    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_WIPHY, msg::NLM_F_DUMP, seq)
        .attr(Attr::u32(NL80211_ATTR_WIPHY, wiphy))
        .attr(Attr::bytes(NL80211_ATTR_SPLIT_WIPHY_DUMP, &[]));
    if let Err(e) = sock.send(&request.to_bytes(sock.pid)) {
        eprintln!("netlink AP: split GET_WIPHY send failed: {e}");
        return Some(caps);
    }
    for _ in 0..64 {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            break;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_DONE {
                return Some(caps);
            }
            if parsed.typ == msg::NLMSG_ERROR {
                let code = parsed.error_code().unwrap_or(-libc::EIO);
                eprintln!("netlink AP: split GET_WIPHY failed: {code}");
                return Some(caps);
            }
            if parsed.typ != family {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let same_wiphy = msg::find_attr(&attrs, NL80211_ATTR_WIPHY)
                .and_then(|v| v.get(..4))
                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()) == wiphy)
                .unwrap_or(false);
            if same_wiphy {
                merge_mld(&mut caps, &attrs);
                if let Some(found) = parse_wiphy_capabilities(&attrs, band) {
                    merge(&mut caps, found);
                }
            }
        }
    }
    Some(caps)
}

pub(super) fn apply_wiphy_capabilities(frame: &mut Vec<u8>, caps: &WiphyCapabilities) {
    if frame.len() < 24 || frame[0] & 0x0c != 0 {
        return;
    }
    let ies = match frame[0] & 0xf0 {
        // Beacon and Probe Response: timestamp + interval + capabilities.
        0x80 | 0x50 => 24 + 12,
        // Association and Reassociation Response: capabilities + status + AID.
        0x10 | 0x30 => 24 + 6,
        _ => return,
    };
    dot11::apply_phy_capabilities(frame, ies, &caps.phy_capabilities());
}

/// reference AP's nl80211 flush operation: DEL_STATION without NL80211_ATTR_MAC
/// removes every station left by a previous AP instance. This must happen even
/// after SIGKILL/SIGTERM, where userspace destructors cannot be relied upon.
pub(super) fn nl_flush_stations(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
) -> io::Result<()> {
    let seq = sock.next_seq();
    sock.request_ack(
        GenlMessage::new(family, NL80211_CMD_DEL_STATION, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex)),
    )
}

/// Read the same live station measurements the reference AP exposes from `STA`
/// and `all_sta`. This runs on the telemetry worker's dedicated netlink socket,
/// so slow kernel replies cannot stall the radio event socket.
pub(super) fn nl_get_station_telemetry(
    sock: &mut NetlinkSocket,
    family: u16,
    ifindex: u32,
    mac: &[u8; 6],
) -> Option<crate::control::StationTelemetry> {
    fn rate(info: &[(u16, &[u8])], kind: u16) -> Option<u32> {
        let nested = msg::parse_attrs(msg::find_attr(info, kind)?);
        if let Some(v) = msg::find_attr(&nested, NL80211_RATE_INFO_BITRATE32) {
            return v
                .get(..4)
                .map(|v| u32::from_ne_bytes(v.try_into().unwrap()));
        }
        msg::find_attr(&nested, NL80211_RATE_INFO_BITRATE)
            .and_then(|v| v.get(..2))
            .map(|v| u16::from_ne_bytes(v.try_into().unwrap()) as u32)
    }

    let seq = sock.next_seq();
    let request = GenlMessage::new(family, NL80211_CMD_GET_STATION, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::bytes(NL80211_ATTR_MAC, mac));
    sock.send(&request.to_bytes(sock.pid)).ok()?;

    for _ in 0..4 {
        let Some(buf) = sock.recv(Duration::from_millis(100)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.seq != seq {
                continue;
            }
            if parsed.typ == msg::NLMSG_ERROR {
                return None;
            }
            if parsed.typ != family {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            let info = msg::parse_attrs(msg::find_attr(&attrs, NL80211_ATTR_STA_INFO)?);
            return Some(crate::control::StationTelemetry {
                signal: msg::find_attr(&info, NL80211_STA_INFO_SIGNAL)
                    .and_then(|v| v.first())
                    .map(|v| *v as i8),
                signal_avg: msg::find_attr(&info, NL80211_STA_INFO_SIGNAL_AVG)
                    .and_then(|v| v.first())
                    .map(|v| *v as i8),
                tx_rate_info: rate(&info, NL80211_STA_INFO_TX_BITRATE),
                rx_rate_info: rate(&info, NL80211_STA_INFO_RX_BITRATE),
            });
        }
    }
    None
}

#[cfg(test)]
mod wiphy_capability_tests {
    use super::*;

    #[test]
    fn trims_and_masks_driver_he_eht_arrays_like_reference_ap() {
        let he_mac = [0x0d, 0x00, 0x08, 0x9a, 0x40, 0x18];
        let he_phy = [
            0x0c, 0x63, 0x40, 0x88, 0xff, 0xd9, 0x9f, 0x1c, 0x11, 0x0e, 0x00,
        ];
        let he_mcs = [0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0xfa, 0xff, 0, 0, 0, 0];
        let he_ppe = [
            0x79, 0x1c, 0xc7, 0x71, 0x1c, 0xc7, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let eht_mac = [0x37, 0x00];
        let eht_phy = [0xe2, 0xff, 0xdb, 0xe0, 0x18, 0x75, 0x00, 0x7e, 0x04];
        let eht_mcs = [0x22; 9];
        let attrs = vec![
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC, he_mac.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY, he_phy.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET, he_mcs.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE, he_ppe.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC, eht_mac.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY, eht_phy.as_slice()),
            (NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET, eht_mcs.as_slice()),
        ];

        let he = build_he_capability(&attrs).expect("HE capability");
        assert_eq!(he.len(), 32, "fixed kernel arrays must be trimmed");
        assert_eq!(
            &he[6..17],
            &[0x0c, 0x63, 0x40, 0x08, 0xfc, 0xd9, 0x9f, 0x1c, 0x11, 0x0e, 0x00]
        );

        let eht = build_eht_capability(&attrs, &he, 1).expect("5 GHz EHT capability");
        assert_eq!(eht.len(), 17, "5 GHz omits the 320 MHz MCS map");
        assert_eq!(
            eht,
            [
                0x37, 0x00, 0x80, 0xff, 0xdb, 0xe0, 0x18, 0x75, 0x00, 0x0e, 0x04, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22,
            ]
        );

        let eht6 =
            build_eht_capability(&attrs, &he, NL80211_BAND_6GHZ).expect("6 GHz EHT capability");
        assert_eq!(
            eht6.len(),
            20,
            "6 GHz carries <=80, 160, and 320 MHz MCS maps"
        );
        assert_ne!(eht6[2] & 0x02, 0, "6 GHz retains the 320 MHz capability");
    }

    #[test]
    fn parses_ap_mld_capabilities_from_per_iftype_wiphy_data() {
        let entry = Attr::nested(
            1,
            &[
                Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP),
                Attr::bytes(169, &[0]),
                Attr::bytes(170, &[0]),
                Attr::u16v(NL80211_ATTR_EML_CAPABILITY, 0x406b),
                Attr::u16v(NL80211_ATTR_MLD_CAPA_AND_OPS, 0x0024),
            ],
        );
        let message = GenlMessage::new(30, NL80211_CMD_GET_WIPHY, 0, 1)
            .attr(Attr::nested(NL80211_ATTR_IFTYPE_EXT_CAPA, &[entry]))
            .to_bytes(1);
        let attrs = msg::parse_attrs(&message[20..]);
        assert_eq!(parse_wiphy_mld_capabilities(&attrs), Some((0x406b, 0x0024)));
    }
}
