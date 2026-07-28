use super::*;
use std::collections::HashMap;

pub(super) struct StartedRadio {
    pub(super) ap: crate::ap::Ap,
    pub(super) events: NetlinkSocket,
    pub(super) family: u16,
    pub(super) topology: RadioTopology,
    pub(super) bssid: [u8; 6],
}

/// Configure one interface and leave it ready for the nonblocking radio loop.
pub(super) fn start_radio(
    mut ap: crate::ap::Ap,
    iface: &str,
    channel: u8,
) -> io::Result<StartedRadio> {
    let mut sock = NetlinkSocket::open()?;
    let (family_id, mlme_group) = resolve_family(&mut sock, "nl80211", "mlme")?;
    let ifindex =
        unsafe { libc::if_nametoindex(format!("{iface}\0").as_ptr() as *const libc::c_char) };
    if ifindex == 0 {
        return Err(io::Error::last_os_error());
    }
    // Set the regulatory domain BEFORE touching channels/START_AP, and wait for
    // the change to land so the 5/6 GHz no-IR flags clear before beaconing.
    nl_set_regulatory(&ap.country);
    // The kernel forces an MLD's AP address to the interface netdev MAC, so adopt
    // it (a config placeholder would mismatch what the client authenticates
    // against) and fill in any affiliated-link BSSIDs left unspecified. Both must
    // happen before the links are snapshotted below for the beacon and ADD_LINK.
    if ap.mld {
        let configured_mld_mac = ap.mld_mac;
        let hw = read_iface_mac(iface).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot resolve required MLD address for {iface}: {e}"),
            )
        })?;
        if hw != configured_mld_mac {
            eprintln!(
                "netlink AP: adopting interface MAC {} as MLD address (config was {})",
                crate::util::bytes_to_mac(&hw),
                crate::util::bytes_to_mac(&configured_mld_mac)
            );
        }
        resolve_mld_addresses(&mut ap, hw)?;
    }
    let mld_links = ap.active_mld_links();
    let needs_pre_cac_scan = mld_links.iter().any(|link| {
        !link.band6
            && link.width >= 40
            && chandef_is_dfs(
                dot11::center_channel(link.channel, link.width, false),
                link.width,
            )
    });
    let scan_group = if needs_pre_cac_scan {
        let (_, group) = resolve_family(&mut sock, "nl80211", "scan")?;
        Some(group.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "nl80211 scan multicast group missing",
            )
        })?)
    } else {
        None
    };
    // Primary frequency: 6 GHz is 5950 + 5*chan, otherwise the 2.4/5 GHz table.
    let band6 = ap.band6();
    // nl80211 reports HE/EHT capability blobs per band. An MLD spanning 5 and
    // 6 GHz must not reuse the primary link's 5 GHz blob for its 6 GHz beacon
    // or Association Response: strict clients then classify that link as HE/AX.
    let mut wiphy_caps_by_link: HashMap<u8, WiphyCapabilities> = HashMap::new();
    for link in &mld_links {
        let nl_band = if link.band6 {
            NL80211_BAND_6GHZ
        } else if dot11::is_5ghz(link.channel) {
            NL80211_BAND_5GHZ
        } else {
            NL80211_BAND_2GHZ
        };
        let caps =
            nl_get_wiphy_capabilities(&mut sock, family_id, ifindex, nl_band).unwrap_or_default();
        eprintln!(
            "netlink AP: link_id={} {} GHz capabilities HT={} VHT={} HE={} EHT={} bytes",
            link.link_id,
            if link.band6 {
                "6"
            } else if dot11::is_5ghz(link.channel) {
                "5"
            } else {
                "2.4"
            },
            caps.ht.as_ref().map_or(0, Vec::len),
            caps.vht.as_ref().map_or(0, Vec::len),
            caps.he.as_ref().map_or(0, Vec::len),
            caps.eht.as_ref().map_or(0, Vec::len),
        );
        ap.set_mld_link_phy_capabilities(link.link_id, caps.phy_capabilities());
        wiphy_caps_by_link.insert(link.link_id, caps);
    }
    if ap.mld {
        if let Some((eml, mld)) = wiphy_caps_by_link
            .values()
            .find_map(|caps| caps.eml.zip(caps.mld))
        {
            ap.set_mld_driver_capabilities(eml, mld);
            eprintln!("netlink AP: AP MLD driver capabilities EML=0x{eml:04x} MLD=0x{mld:04x}");
        }
    }
    let freq: u32 = if band6 {
        5950 + 5 * channel as u32
    } else {
        msg::freq_for_channel(channel)
    };
    // In kernel-offload mode the on-air BSSID is the interface's own MAC:
    // mac80211 stamps addr2/addr3 of the beacon and only forwards management
    // frames whose addr1 == the interface MAC. A non-MLD AP must therefore key
    // its address filter *and* the SAE/PTK addressing off the actual interface
    // MAC, not the config default (02:00:00:00:00:00). On mac80211_hwsim the
    // first radio happens to be 02:00:00:00:00:00, which coincidentally matched
    // the default and hid this bug on virtual radios; on a real card (mt7915,
    // ath12k) the mismatch made the AP silently drop every STA's Authentication
    // frame, so clients saw "unable to join" / auth timeout. For an MLD AP,
    // `ap.mac` is deliberately the association-link MAC (set via ADD_LINK) and
    // `ap.mld_mac` is the interface MAC, so leave the addressing untouched.
    if !ap.mld {
        if let Ok(hw) = read_iface_mac(iface) {
            if hw != ap.mac {
                eprintln!(
                    "netlink AP: adopting interface MAC {} as BSSID (config was {})",
                    crate::util::bytes_to_mac(&hw),
                    crate::util::bytes_to_mac(&ap.mac)
                );
                ap.mac = hw;
                ap.mld_mac = hw;
            }
        }
    }
    let bssid = ap.mac;
    // SAE PWE derivation and scalar multiplication are CPU-heavy. Keep them on
    // a bounded worker so a burst of commits cannot delay management/EAPOL
    // reception on this radio.
    ap.enable_async_sae();

    // NL80211_CMD_SET_INTERFACE is not a best-effort hint: START_AP requires an
    // NL80211_IFTYPE_AP netdev. Linux rejects a type change while the interface
    // is UP (the exact EOPNOTSUPP seen when SPR renamed an active managed wlan1
    // to wlan3), so mirror `ip link down; iw set type __ap; ip link up` and fail
    // at the real operation if the driver cannot provide AP mode.
    iface_set_state(iface, false)?;
    let seq = sock.next_seq();
    if let Err(e) = sock.request_ack(
        GenlMessage::new(family_id, NL80211_CMD_SET_INTERFACE, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP)),
    ) {
        let _ = iface_set_state(iface, true);
        return Err(io::Error::other(format!(
            "set {iface} type __ap failed: {e}"
        )));
    }
    iface_set_state(iface, true)?;
    eprintln!("netlink AP: {iface} set type __ap and brought up");
    // Match reference AP's i802_flush(): remove every kernel station left by a
    // previous process before bringing up a new BSS. Without this, a client can
    // remain associated to the old SSID while this BSSID advertises a new one.
    match nl_flush_stations(&mut sock, family_id, ifindex) {
        Ok(()) => eprintln!("netlink AP: flushed stale kernel stations"),
        Err(e) => eprintln!("netlink AP: station flush failed (continuing): {e}"),
    }
    // Registration is owned by this socket for its entire lifetime. Complete it
    // once, before START_AP, then hand the socket to the receive-only radio loop.
    let wdev = nl_get_interface_wdev(&mut sock, family_id, ifindex)?;
    nl_register_ap_frames(&mut sock, family_id, wdev)?;
    // Derive the nl80211 auth type + RSN AKM suite(s) from the AP's configured
    // security mode, instead of hardcoding open-system + WPA2-PSK. The AKM suite
    // list distinguishes the modes; Transition advertises BOTH PSK and SAE AKMs so
    // WPA2 and WPA3 clients can each pick their AKM.
    //
    // AUTH_TYPE for START_AP must stay OPEN_SYSTEM for every mode here: barely-ap
    // runs the SAE/OWE exchange in *userspace* (the kernel hands auth frames up via
    // REGISTER_FRAME), so it never offloads SAE to the driver. Passing
    // NL80211_AUTHTYPE_SAE asserts driver SAE-offload (NL80211_EXT_FEATURE_SAE_-
    // OFFLOAD_AP); a driver without it (e.g. mac80211_hwsim) rejects START_AP with
    // EINVAL. This is what blocked WPA3-SAE — and therefore the PMF-protected EHT
    // (--phy be) config that 802.11be mandates — on the netlink path.
    let (auth_type, akm_suites): (u32, Vec<u8>) = match ap.security_mode() {
        dot11::SecurityMode::Wpa2 => (
            NL80211_AUTHTYPE_OPEN_SYSTEM,
            WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec(),
        ),
        dot11::SecurityMode::Wpa2PskSha256 => {
            // Beacon RSNE (RSN_PSK_SHA256_MIXED) advertises both PSK and
            // PSK-SHA256, so START_AP must offer the same pair for either to be
            // selectable. AKM 6 does not require PMF, so mfp_required omits it.
            const WLAN_AKM_SUITE_PSK_SHA256: u32 = 0x000f_ac06;
            let mut a = WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec();
            a.extend_from_slice(&WLAN_AKM_SUITE_PSK_SHA256.to_ne_bytes());
            (NL80211_AUTHTYPE_OPEN_SYSTEM, a)
        }
        dot11::SecurityMode::Wpa3Sae => (
            NL80211_AUTHTYPE_OPEN_SYSTEM,
            WLAN_AKM_SUITE_SAE.to_ne_bytes().to_vec(),
        ),
        dot11::SecurityMode::Transition => {
            let mut a = WLAN_AKM_SUITE_PSK.to_ne_bytes().to_vec();
            a.extend_from_slice(&WLAN_AKM_SUITE_SAE.to_ne_bytes());
            (NL80211_AUTHTYPE_OPEN_SYSTEM, a)
        }
        dot11::SecurityMode::Owe => (
            NL80211_AUTHTYPE_OPEN_SYSTEM,
            WLAN_AKM_SUITE_OWE.to_ne_bytes().to_vec(),
        ),
    };
    // Management Frame Protection is required for SAE and OWE, and mandatory on
    // 6 GHz regardless of AKM.
    let mfp_required = ap.band6()
        || matches!(
            ap.security_mode(),
            dot11::SecurityMode::Wpa3Sae
                | dot11::SecurityMode::Owe
                | dot11::SecurityMode::Transition
        );

    // START_AP: the kernel beacons + (after NEW_KEY) does data CCMP. We keep the
    // 802.1X control port in userspace, delivered over nl80211. The kernel
    // repeats this one beacon, so it must NOT carry a fixed-IPN BIP MME (it would
    // replay forever) — build it without the MME and, when Beacon Protection is
    // on, install the BIGTK so mac80211 generates + increments the per-beacon MME.
    // Join the MLME multicast group first so we receive radar/CAC events, then —
    // on a DFS channel — run the CAC before the kernel will let us beacon.
    if let Some(g) = mlme_group {
        let _ = sock.join_multicast(g);
    }
    if let Some(g) = scan_group {
        sock.join_multicast(g)?;
    }
    // Create the complete MLD topology before installing any beacon template.
    // Every template contains the other affiliated link's profile, and ath12k
    // can accept START_AP while silently suppressing that beacon if its partner
    // link does not exist yet.
    if ap.mld {
        for link in &mld_links {
            nl_add_link(&mut sock, family_id, ifindex, link.link_id, &link.mac).map_err(|e| {
                io::Error::other(format!(
                    "ADD_LINK link_id={} mac={} failed: {e}",
                    link.link_id,
                    crate::util::bytes_to_mac(&link.mac)
                ))
            })?;
            eprintln!(
                "netlink AP: ADD_LINK link_id={} mac={} ok",
                link.link_id,
                crate::util::bytes_to_mac(&link.mac)
            );
        }
    }
    // Match the reference AP's HT40 coexistence scan before starting CAC.
    // Restrict this to wide DFS links: it is required before CAC on drivers
    // such as ath12k, while narrow DFS and non-DFS startup need no scan delay.
    for link in &mld_links {
        let center_channel = dot11::center_channel(link.channel, link.width, link.band6);
        if link.band6 || link.width < 40 || !chandef_is_dfs(center_channel, link.width) {
            continue;
        }
        let secondary_channel = if link.channel % 8 == 4 {
            link.channel + 4
        } else {
            link.channel - 4
        };
        do_pre_cac_scan(
            &mut sock,
            family_id,
            ifindex,
            msg::freq_for_channel(link.channel),
            msg::freq_for_channel(secondary_channel),
        )?;
    }
    for link in &mld_links {
        let link_band6 = link.band6;
        let link_caps = wiphy_caps_by_link
            .get(&link.link_id)
            .expect("capabilities collected for every active link");
        let link_freq: u32 = if link_band6 {
            5950 + 5 * link.channel as u32
        } else {
            msg::freq_for_channel(link.channel)
        };
        let link_width = link.width;
        let link_chan_width = match link_width {
            40 => NL80211_CHAN_WIDTH_40,
            80 => NL80211_CHAN_WIDTH_80,
            160 => NL80211_CHAN_WIDTH_160,
            320 => NL80211_CHAN_WIDTH_320,
            _ => NL80211_CHAN_WIDTH_20,
        };
        let link_center_freq1: u32 = if link_width >= 40 {
            dot11::channel_to_center_freq(
                dot11::center_channel(link.channel, link_width, link_band6),
                link_band6,
            )
        } else {
            link_freq
        };
        let link_center_chan = if link_width >= 40 {
            dot11::center_channel(link.channel, link_width, link_band6)
        } else {
            link.channel
        };
        if !link_band6 && chandef_is_dfs(link_center_chan, link_width) {
            if link_caps.dfs_offload {
                eprintln!(
                    "netlink AP: DFS offload — driver owns CAC and radar handling on {link_freq} MHz link={:?}",
                    ap.mld.then_some(link.link_id)
                );
            } else {
                do_cac(
                    &mut sock,
                    family_id,
                    ifindex,
                    link_freq,
                    link_chan_width,
                    link_center_freq1,
                    ap.mld.then_some(link.link_id),
                )?;
            }
        }
        let beacon_rt = if ap.mld {
            ap.beacon_frame_unprotected_for_link(link)
        } else {
            ap.beacon_frame_unprotected()
        };
        let mut beacon = dot11::strip_radiotap(&beacon_rt)
            .map(<[u8]>::to_vec)
            .unwrap_or(beacon_rt);
        apply_wiphy_capabilities(&mut beacon, link_caps);
        if ap.mld {
            eprintln!(
                "netlink AP: link_id={} beacon template MLE partner_info={} bytes",
                link.link_id,
                dot11::basic_mle_link_info_len(&beacon[36..]).unwrap_or(0)
            );
        }
        let (head, tail) = split_beacon_at_tim(&beacon);
        let seq = sock.next_seq();
        let mut start = GenlMessage::new(family_id, NL80211_CMD_START_AP, 0, seq)
            .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
            .attr(Attr::bytes(NL80211_ATTR_BEACON_HEAD, head))
            .attr(Attr::bytes(NL80211_ATTR_BEACON_TAIL, tail))
            .attr(Attr::u32(NL80211_ATTR_BEACON_INTERVAL, 100))
            .attr(Attr::u32(NL80211_ATTR_DTIM_PERIOD, 2))
            .attr(Attr::bytes(NL80211_ATTR_SSID, &ap.ssid))
            .attr(Attr::u32(NL80211_ATTR_HIDDEN_SSID, 0))
            .attr(Attr::u32(NL80211_ATTR_AUTH_TYPE, auth_type))
            .attr(Attr::bytes(NL80211_ATTR_PRIVACY, &[]))
            .attr(Attr::u32(NL80211_ATTR_WPA_VERSIONS, NL80211_WPA_VERSION_2))
            .attr(Attr::bytes(
                NL80211_ATTR_CIPHER_SUITES_PAIRWISE,
                &ap.pairwise_cipher().suite_selector().to_ne_bytes(),
            ))
            .attr(Attr::u32(
                NL80211_ATTR_CIPHER_SUITE_GROUP,
                WLAN_CIPHER_SUITE_CCMP,
            ))
            .attr(Attr::bytes(NL80211_ATTR_AKM_SUITES, &akm_suites))
            .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT, &[]))
            .attr(Attr::u16v(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, ETH_P_PAE))
            .attr(Attr::bytes(NL80211_ATTR_CONTROL_PORT_OVER_NL80211, &[]))
            .attr(Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]))
            .attr(Attr::u32(NL80211_ATTR_WIPHY_FREQ, link_freq))
            .attr(Attr::u32(NL80211_ATTR_CHANNEL_WIDTH, link_chan_width))
            .attr(Attr::u32(NL80211_ATTR_CENTER_FREQ1, link_center_freq1));
        if mfp_required {
            start = start.attr(Attr::u32(NL80211_ATTR_USE_MFP, NL80211_MFP_REQUIRED));
        }
        if ap.mld {
            start = start.attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link.link_id));
        }
        sock.request_ack(start)?;
        nl_set_bss(
            &mut sock,
            family_id,
            ifindex,
            ap.mld.then_some(link.link_id),
            link.channel,
            !link.band6,
            ap.guest(),
        )?;
        eprintln!(
            "netlink AP: START_AP + SET_BSS ok — kernel beaconing {:?} link_id={} on {} MHz (ifindex {ifindex})",
            String::from_utf8_lossy(&ap.ssid),
            link.link_id,
            link_freq
        );
        // reference AP follows its pre-start station flush with a broadcast Deauth
        // once the new beacon is live. The flush removes stale AP-side state;
        // this frame makes clients that survived the restart immediately leave
        // their old association instead of caching the previous SSID on this
        // BSSID until an inactivity timeout.
        const WLAN_REASON_PREV_AUTH_NOT_VALID: u16 = 2;
        let broadcast = [0xff; 6];
        let tx_bssid = if ap.mld { link.mac } else { bssid };
        let deauth = dot11::build_deauth(&tx_bssid, &broadcast, WLAN_REASON_PREV_AUTH_NOT_VALID);
        nl_send_mgmt(
            &mut sock,
            family_id,
            wdev,
            link_freq,
            &deauth,
            ap.mld.then_some(link.link_id),
        );
        eprintln!("netlink AP: broadcast Deauth sent after BSS restart");
    }
    // reference AP updates every affiliated link's beacon after all links have
    // reached START_AP. During the first START_AP the partner link is not yet
    // active, so mac80211/ath12k retains only the Basic MLE Common Info and
    // drops the Per-STA Profile that references that inactive link. Re-submit
    // the complete templates now that every affiliated link exists.
    if ap.mld && mld_links.len() > 1 {
        for link in &mld_links {
            let beacon_rt = ap.beacon_frame_unprotected_for_link(link);
            let mut beacon = dot11::strip_radiotap(&beacon_rt)
                .map(<[u8]>::to_vec)
                .unwrap_or(beacon_rt);
            let link_caps = wiphy_caps_by_link
                .get(&link.link_id)
                .expect("capabilities collected for every active link");
            apply_wiphy_capabilities(&mut beacon, link_caps);
            let partner_info = dot11::basic_mle_link_info_len(&beacon[36..]).unwrap_or(0);
            let (head, tail) = split_beacon_at_tim(&beacon);
            let seq = sock.next_seq();
            sock.request_ack(
                GenlMessage::new(family_id, NL80211_CMD_SET_BEACON, 0, seq)
                    .attr(Attr::u32(NL80211_ATTR_IFINDEX, ifindex))
                    .attr(Attr::bytes(NL80211_ATTR_BEACON_HEAD, head))
                    .attr(Attr::bytes(NL80211_ATTR_BEACON_TAIL, tail))
                    .attr(Attr::u8(NL80211_ATTR_MLO_LINK_ID, link.link_id)),
            )?;
            nl_set_bss(
                &mut sock,
                family_id,
                ifindex,
                Some(link.link_id),
                link.channel,
                !link.band6,
                ap.guest(),
            )?;
            eprintln!(
                "netlink AP: SET_BEACON + SET_BSS link_id={} with MLE partner_info={} bytes",
                link.link_id, partner_info
            );
        }
    }
    if ap.mld {
        eprintln!(
            "netlink AP: MLD canonical bssid (ap.mac) = {}",
            crate::util::bytes_to_mac(&bssid)
        );
    }
    // MLD per-link routing: each affiliated link's (BSSID, freq), and the
    // client->link_id route learned from received frames. The core `Ap` runs a
    // single-address (canonical `bssid`) state machine; we translate the wire
    // MPDU addresses at this netlink boundary — incoming link-BSSID -> canonical
    // on RX, canonical -> the client's link-BSSID on TX — and send each response
    // on the link the client is actually using. SAE/4-way crypto is unaffected
    // (it keys off the MLD MAC addresses, not the MPDU addresses).
    let links: HashMap<u8, ([u8; 6], u32)> = mld_links
        .iter()
        .map(|l| {
            (
                l.link_id,
                (
                    l.mac,
                    if l.band6 {
                        5950 + 5 * l.channel as u32
                    } else {
                        crate::netlink::msg::freq_for_channel(l.channel)
                    },
                ),
            )
        })
        .collect();
    let topology = RadioTopology {
        ifindex,
        wdev,
        channel,
        frequency: freq,
        dfs_offload: wiphy_caps_by_link
            .values()
            .any(|capabilities| capabilities.dfs_offload),
        links,
        station_links: HashMap::new(),
        capabilities: wiphy_caps_by_link,
    };
    Ok(StartedRadio {
        ap,
        events: sock,
        family: family_id,
        topology,
        bssid,
    })
}
