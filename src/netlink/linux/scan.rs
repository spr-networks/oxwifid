use super::*;

/// One BSS returned by a kernel nl80211 scan.
#[derive(Clone, Debug, PartialEq)]
pub struct ScanResult {
    pub ssid: Vec<u8>,
    pub bssid: [u8; 6],
    pub frequency: u32,
    pub channel: u8,
    /// `"2.4"`, `"5"`, or `"6"`.
    pub band: &'static str,
    pub signal_dbm: Option<f32>,
    pub psk: bool,
    pub psk_sha256: bool,
    pub sae: bool,
    pub sae_h2e: bool,
    pub owe: bool,
    pub mld_addr: Option<[u8; 6]>,
    pub mlo_link_id: Option<u8>,
}

fn scan_frequency(freq: u32) -> Option<(u8, &'static str)> {
    match freq {
        2484 => Some((14, "2.4")),
        2412..=2472 if (freq - 2407).is_multiple_of(5) => Some((((freq - 2407) / 5) as u8, "2.4")),
        5005..=5895 if (freq - 5000).is_multiple_of(5) => Some((((freq - 5000) / 5) as u8, "5")),
        5955..=7115 if (freq - 5950).is_multiple_of(5) => Some((((freq - 5950) / 5) as u8, "6")),
        _ => None,
    }
}

fn read_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(..4)?.try_into().ok()?))
}

fn parse_scan_bss(data: &[u8]) -> Option<ScanResult> {
    let attrs = msg::parse_attrs(data);
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(msg::find_attr(&attrs, NL80211_BSS_BSSID)?.get(..6)?);
    let frequency = read_u32(msg::find_attr(&attrs, NL80211_BSS_FREQUENCY)?)?;
    let (channel, band) = scan_frequency(frequency)?;
    let information = msg::find_attr(&attrs, NL80211_BSS_INFORMATION_ELEMENTS).unwrap_or(&[]);
    let beacon = msg::find_attr(&attrs, NL80211_BSS_BEACON_IES).unwrap_or(&[]);
    let ie = |id| {
        dot11::find_ie_strict(information, id)
            .ok()
            .flatten()
            .or_else(|| dot11::find_ie_strict(beacon, id).ok().flatten())
    };
    let ssid = ie(0).unwrap_or(&[]).to_vec();
    let rsn = ie(48);
    let rsnxe = ie(244);
    let signal_dbm = msg::find_attr(&attrs, NL80211_BSS_SIGNAL_MBM)
        .and_then(read_u32)
        .map(|raw| (raw as i32) as f32 / 100.0);
    let mld_addr = msg::find_attr(&attrs, NL80211_BSS_MLD_ADDR).and_then(|raw| {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(raw.get(..6)?);
        Some(mac)
    });
    Some(ScanResult {
        ssid,
        bssid,
        frequency,
        channel,
        band,
        signal_dbm,
        psk: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 2)),
        psk_sha256: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 6)),
        sae: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 8)),
        sae_h2e: rsnxe.is_some_and(dot11::rsnxe_has_sae_h2e),
        owe: rsn.is_some_and(|body| dot11::rsn_has_akm(body, 18)),
        mld_addr,
        mlo_link_id: msg::find_attr(&attrs, NL80211_BSS_MLO_LINK_ID)
            .and_then(|raw| raw.first().copied()),
    })
}

fn dump_scan(
    sock: &mut NetlinkSocket,
    family_id: u16,
    ifindex: u32,
) -> io::Result<Vec<ScanResult>> {
    let seq = sock.next_seq();
    let request = GenlMessage::new(family_id, NL80211_CMD_GET_SCAN, msg::NLM_F_DUMP, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex));
    sock.send(&request.to_bytes(sock.pid))?;
    let mut results = Vec::new();
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
                return Ok(results);
            }
            if let Some(code) = parsed.error_code() {
                if code == 0 {
                    continue;
                }
                return Err(io::Error::from_raw_os_error(-code));
            }
            if parsed.typ != family_id || parsed.genl_cmd() != Some(NL80211_CMD_NEW_SCAN_RESULTS) {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if let Some(bss) = msg::find_attr(&attrs, NL80211_ATTR_BSS).and_then(parse_scan_bss) {
                results.push(bss);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "nl80211 scan dump timed out",
    ))
}

fn trigger_scan(
    sock: &mut NetlinkSocket,
    family_id: u16,
    ifindex: u32,
    ssids: &[Vec<u8>],
) -> io::Result<()> {
    let nested = if ssids.is_empty() {
        vec![Attr::bytes(1, &[])]
    } else {
        ssids
            .iter()
            .enumerate()
            .map(|(index, ssid)| Attr::bytes((index + 1) as u16, ssid))
            .collect()
    };
    let seq = sock.next_seq();
    let request = GenlMessage::new(family_id, NL80211_CMD_TRIGGER_SCAN, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::nested(NL80211_ATTR_SCAN_SSIDS, &nested));
    match sock.request_ack(request) {
        Ok(()) => {}
        // Another local scan may already be running. Since this socket joined
        // the scan group first, wait for it and consume its fresh cache.
        Err(error)
            if error.raw_os_error() == Some(libc::EBUSY)
                || error
                    .to_string()
                    .contains(&format!("os error {}", libc::EBUSY)) => {}
        Err(error) => return Err(error),
    }

    let deadline = Instant::now() + Duration::from_secs(45);
    while Instant::now() < deadline {
        let Some(buf) = sock.recv(Duration::from_millis(500)) else {
            continue;
        };
        for parsed in msg::parse_messages(&buf) {
            if parsed.typ != family_id {
                continue;
            }
            let attrs = msg::parse_attrs(parsed.genl_attrs());
            if msg::find_attr(&attrs, NL80211_ATTR_IFINDEX).and_then(read_u32) != Some(ifindex) {
                continue;
            }
            match parsed.genl_cmd() {
                Some(NL80211_CMD_NEW_SCAN_RESULTS) => return Ok(()),
                Some(NL80211_CMD_SCAN_ABORTED) => {
                    return Err(io::Error::other("nl80211 scan aborted"))
                }
                _ => {}
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "nl80211 scan did not complete",
    ))
}

/// Perform an active scan on a managed interface. Supplying SSIDs generates
/// directed probes, which is required for a manually entered hidden network.
/// The kernel/driver performs channel iteration; this function never invokes
/// `iw` and never modifies addresses or routes.
pub fn scan_interface(iface: &str, directed_ssids: &[Vec<u8>]) -> io::Result<Vec<ScanResult>> {
    // A down managed interface cannot trigger a scan. This changes link state
    // only; addresses, DHCP, policy routing, and default routes remain SPR's.
    iface_set_up(iface)?;
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sock = NetlinkSocket::open()?;
    let (family_id, scan_group) = resolve_family(&mut sock, "nl80211", "scan")?;
    let group = scan_group
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "nl80211 scan group missing"))?;
    sock.join_multicast(group)?;

    // Conservative batching works on radios that expose only four probe SSID
    // slots. Visible BSSes are still collected from every directed scan.
    let batches: Vec<&[Vec<u8>]> = if directed_ssids.is_empty() {
        vec![&[]]
    } else {
        directed_ssids.chunks(4).collect()
    };
    let mut all = Vec::new();
    for batch in batches {
        trigger_scan(&mut sock, family_id, ifindex, batch)?;
        for result in dump_scan(&mut sock, family_id, ifindex)? {
            if let Some(existing) = all.iter_mut().find(|old: &&mut ScanResult| {
                old.bssid == result.bssid && old.frequency == result.frequency
            }) {
                if result.signal_dbm > existing.signal_dbm {
                    *existing = result;
                }
            } else {
                all.push(result);
            }
        }
    }
    all.sort_by(|a, b| {
        b.signal_dbm
            .partial_cmp(&a.signal_dbm)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.ssid.cmp(&b.ssid))
            .then_with(|| a.bssid.cmp(&b.bssid))
    });
    Ok(all)
}

/// Tune an interface to a scan result's primary frequency. The normal client
/// arrangement calls this on the monitor VIF after scanning with its managed
/// sibling on the same wiphy.
pub fn set_interface_frequency(iface: &str, frequency: u32) -> io::Result<()> {
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sock = NetlinkSocket::open()?;
    let (family_id, _) = resolve_family(&mut sock, "nl80211", "")?;
    let seq = sock.next_seq();
    let request = GenlMessage::new(family_id, NL80211_CMD_SET_CHANNEL, 0, seq)
        .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
        .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, frequency));
    sock.request_ack(request)
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    #[test]
    fn parses_sae_h2e_six_ghz_scan_result() {
        let mut ies = vec![0, 7];
        ies.extend_from_slice(b"testnet");
        ies.extend_from_slice(&dot11::RSN_WPA3);
        ies.extend_from_slice(&dot11::RSNXE_H2E);
        let signal = (-4325i32).to_ne_bytes();
        let nested = Attr::nested(
            1,
            &[
                Attr::bytes(NL80211_BSS_BSSID, &[2, 0, 0, 0, 0, 1]),
                Attr::u32(NL80211_BSS_FREQUENCY, 6135),
                Attr::bytes(NL80211_BSS_INFORMATION_ELEMENTS, &ies),
                Attr::bytes(NL80211_BSS_SIGNAL_MBM, &signal),
                Attr::u8(NL80211_BSS_MLO_LINK_ID, 1),
                Attr::bytes(NL80211_BSS_MLD_ADDR, &[2, 0, 0, 0, 0, 9]),
            ],
        );
        let result = parse_scan_bss(&nested.data).unwrap();
        assert_eq!(result.ssid, b"testnet");
        assert_eq!(result.channel, 37);
        assert_eq!(result.band, "6");
        assert_eq!(result.signal_dbm, Some(-43.25));
        assert!(result.sae);
        assert!(result.sae_h2e);
        assert!(!result.psk);
        assert_eq!(result.mlo_link_id, Some(1));
        assert_eq!(result.mld_addr, Some([2, 0, 0, 0, 0, 9]));
    }

    #[test]
    fn rejects_scan_frequencies_outside_supported_wifi_bands() {
        assert_eq!(scan_frequency(2412), Some((1, "2.4")));
        assert_eq!(scan_frequency(5180), Some((36, "5")));
        assert_eq!(scan_frequency(5955), Some((1, "6")));
        assert_eq!(scan_frequency(58320), None);
    }
}
