#[cfg(any(target_os = "linux", test))]
use super::{msg, *};

/// Whether a 5 GHz chandef (center channel + width in MHz) overlaps a DFS radar
/// channel (US: 52-64 and 100-144), so a CAC is required before beaconing. The
/// `width_mhz/20` 20 MHz subchannels are centered on `center_chan`, spaced 4
/// channels apart; any one landing in a radar range makes the whole chandef DFS.
pub fn chandef_is_dfs(center_chan: u8, width_mhz: u16) -> bool {
    let n = (width_mhz / 20).max(1) as i32;
    let lowest = center_chan as i32 - (n - 1) * 2;
    (0..n).any(|k| {
        let ch = lowest + 4 * k;
        (52..=64).contains(&ch) || (100..=144).contains(&ch)
    })
}

/// A non-DFS 5 GHz channel to recommend when radar forces us off a DFS channel:
/// UNII-1 (36) for the lower band, UNII-3 (149) for the upper. Both are
/// radar-free, so an AP restarted there needs no CAC.
pub fn fallback_channel(current: u8) -> u8 {
    if current <= 96 {
        36
    } else {
        149
    }
}

/// Build the nested SET_KEY payload that selects an installed GTK as the
/// multicast default key. nl80211 deliberately separates adding a key
/// (NEW_KEY) from selecting its TX role (SET_KEY).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn default_multicast_key_attr(idx: u8) -> msg::Attr {
    msg::Attr::nested_unflagged(
        NL80211_ATTR_KEY,
        &[
            msg::Attr::u8(NL80211_KEY_IDX, idx),
            msg::Attr::bytes(NL80211_KEY_DEFAULT, &[]),
            msg::Attr::nested(
                NL80211_KEY_DEFAULT_TYPES,
                &[msg::Attr::bytes(NL80211_KEY_DEFAULT_TYPE_MULTICAST, &[])],
            ),
        ],
    )
}

/// Return reference AP's lowest-free per-station VIF id.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn first_free_per_sta_vlan_id(used: impl IntoIterator<Item = u32>) -> Option<u32> {
    let used: std::collections::HashSet<u32> = used.into_iter().collect();
    (PER_STA_VLAN_ID_START..=u32::MAX).find(|id| !used.contains(id))
}

/// Expand reference AP's wildcard `<base>.#` convention for a per-station VIF.
/// Linux interface names are limited to IFNAMSIZ-1 (15) bytes.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn per_sta_vif_name(base: &str, vlan_id: u32) -> Result<String, String> {
    let name = format!("{base}.{vlan_id}");
    if name.len() > 15 {
        return Err(format!(
            "per-station VIF name {name:?} exceeds Linux's 15-byte interface-name limit"
        ));
    }
    Ok(name)
}

/// Address an AP_VLAN must inherit so mac80211 can attach it to the right BSS.
///
/// Reference AP uses the BSSID for a conventional AP and the interface MLD
/// address for an MLD AP. Omitting this from NEW_INTERFACE can leave the
/// AP_VLAN orphaned; attempting to bring that netdev up then fails with ENOLINK.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn ap_vlan_parent_addr(ap: &crate::ap::Ap) -> [u8; 6] {
    if ap.mld {
        ap.mld_mac
    } else {
        ap.mac
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn ap_vlan_create_message(
    family: u16,
    seq: u32,
    ap_wdev: u64,
    name: &str,
) -> msg::GenlMessage {
    msg::GenlMessage::new(family, NL80211_CMD_NEW_INTERFACE, 0, seq)
        // driver_nl80211 creates an AP_VLAN through the parent BSS's WDEV,
        // not merely its netdev ifindex. The distinction is essential for a
        // driver to attach the child to the exact AP/MLD link TX context.
        .attr(msg::Attr::bytes(NL80211_ATTR_WDEV, &ap_wdev.to_ne_bytes()))
        .attr(msg::Attr::string(NL80211_ATTR_IFNAME, name))
        .attr(msg::Attr::u32(NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP_VLAN))
        // Keep the per-station netdev process-scoped so the kernel removes it
        // when the owning command socket closes.
        .attr(msg::Attr::bytes(NL80211_ATTR_SOCKET_OWNER, &[]))
}

/// Resolve every address used by an AP MLD against the interface address the
/// kernel actually owns. This must run before active links are cloned: the clone
/// feeds ADD_LINK, beacon templates, and RX/TX link routing.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn resolve_mld_addresses(
    ap: &mut crate::ap::Ap,
    interface_mac: [u8; 6],
) -> std::io::Result<()> {
    if interface_mac == [0u8; 6] || interface_mac[0] & 0x01 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "interface MLD address {} is not a valid unicast MAC",
                crate::util::bytes_to_mac(&interface_mac)
            ),
        ));
    }

    ap.mld_mac = interface_mac;
    ap.derive_missing_mld_link_macs();

    let links = ap.active_mld_links();
    let mut seen = std::collections::HashSet::new();
    for link in &links {
        if link.mac == [0u8; 6] || link.mac[0] & 0x01 != 0 || link.mac == ap.mld_mac {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "MLD link {} has invalid BSSID {} for MLD address {}",
                    link.link_id,
                    crate::util::bytes_to_mac(&link.mac),
                    crate::util::bytes_to_mac(&ap.mld_mac)
                ),
            ));
        }
        if !seen.insert(link.mac) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "MLD link {} duplicates BSSID {}",
                    link.link_id,
                    crate::util::bytes_to_mac(&link.mac)
                ),
            ));
        }
    }

    ap.mac = ap.mld_link_mac(ap.link_id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "MLD association link_id {} is not present in active links",
                ap.link_id
            ),
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn set_default_multicast_key_uses_nested_set_key_layout() {
        let key_attr = default_multicast_key_attr(1);
        assert_eq!(
            key_attr.typ, NL80211_ATTR_KEY,
            "driver_nl80211 leaves the top-level KEY namespace unflagged"
        );
        let wire = msg::GenlMessage::new(0x13, NL80211_CMD_SET_KEY, 0, 7)
            .attr(msg::Attr::u32(NL80211_ATTR_IFINDEX, 12))
            .attr(key_attr)
            .to_bytes(99);

        let messages = msg::parse_messages(&wire);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].genl_cmd(), Some(NL80211_CMD_SET_KEY));

        let top = msg::parse_attrs(messages[0].genl_attrs());
        assert!(msg::find_attr(&top, NL80211_ATTR_KEY_DEFAULT).is_none());
        let key = msg::find_attr(&top, NL80211_ATTR_KEY).expect("nested key attribute");
        let key_attrs = msg::parse_attrs(key);
        assert_eq!(msg::find_attr(&key_attrs, NL80211_KEY_IDX), Some(&[1][..]));
        assert_eq!(
            msg::find_attr(&key_attrs, NL80211_KEY_DEFAULT),
            Some(&[][..])
        );

        let default_types = msg::find_attr(&key_attrs, NL80211_KEY_DEFAULT_TYPES)
            .expect("nested default-key traffic types");
        let types = msg::parse_attrs(default_types);
        assert_eq!(
            msg::find_attr(&types, NL80211_KEY_DEFAULT_TYPE_MULTICAST),
            Some(&[][..])
        );
        assert!(msg::find_attr(&types, NL80211_KEY_DEFAULT_TYPE_UNICAST).is_none());
    }

    #[test]
    fn per_sta_vif_ids_and_names_match_reference_ap() {
        assert_eq!(first_free_per_sta_vlan_id([]), Some(4096));
        assert_eq!(first_free_per_sta_vlan_id([4096, 4098, 4100]), Some(4097));
        assert_eq!(per_sta_vif_name("wlan3", 4096).unwrap(), "wlan3.4096");
        assert!(per_sta_vif_name("interface-long", 4096).is_err());
    }

    #[test]
    fn ap_vlan_create_request_matches_reference_creation_order() {
        let parent_wdev = 0x1_0000_0001u64;
        let wire = ap_vlan_create_message(30, 77, parent_wdev, "wlan2.4096").to_bytes(99);
        let messages = msg::parse_messages(&wire);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].genl_cmd(), Some(NL80211_CMD_NEW_INTERFACE));

        let attrs = msg::parse_attrs(messages[0].genl_attrs());
        assert_eq!(
            msg::find_attr(&attrs, NL80211_ATTR_WDEV),
            Some(parent_wdev.to_ne_bytes().as_slice())
        );
        assert!(msg::find_attr(&attrs, NL80211_ATTR_IFINDEX).is_none());
        assert!(msg::find_attr(&attrs, NL80211_ATTR_MAC).is_none());
        assert_eq!(
            msg::find_attr(&attrs, NL80211_ATTR_SOCKET_OWNER),
            Some(&[][..])
        );
    }

    #[test]
    fn ap_vlan_uses_bssid_for_legacy_and_mld_address_for_mlo() {
        let legacy = Config::from_json(
            r#"{
                "ssid":"legacy", "passphrase":"password1234",
                "mode":"stdio", "mac":"02:00:00:00:aa:01"
            }"#,
        )
        .expect("legacy config")
        .build_ap();
        assert_eq!(ap_vlan_parent_addr(&legacy), legacy.mac);

        let mld = Config::from_json(
            r#"{
                "ssid":"mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"stdio",
                "mld":true, "mac":"02:00:00:00:bb:00",
                "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {
                        "link_id":0, "mac":"02:00:00:00:bb:01",
                        "band":5, "channel":36, "width":80
                    }
                ]
            }"#,
        )
        .expect("MLD config")
        .build_ap();
        assert_eq!(ap_vlan_parent_addr(&mld), mld.mld_mac);
        assert_ne!(ap_vlan_parent_addr(&mld), mld.mac);
    }

    #[test]
    fn fallback_is_always_non_dfs() {
        for ch in [52u8, 60, 64, 100, 120, 132, 144] {
            let fb = fallback_channel(ch);
            assert!(
                !chandef_is_dfs(fb, 20),
                "fallback {fb} for {ch} must be non-DFS"
            );
        }
        assert_eq!(fallback_channel(52), 36); // lower DFS -> UNII-1
        assert_eq!(fallback_channel(132), 149); // upper DFS -> UNII-3
    }

    #[test]
    fn dfs_channel_detection() {
        // Non-DFS 5 GHz channels (UNII-1 / UNII-3).
        assert!(!chandef_is_dfs(36, 20));
        assert!(!chandef_is_dfs(48, 20));
        assert!(!chandef_is_dfs(149, 20));
        assert!(!chandef_is_dfs(165, 20));
        // DFS channels (UNII-2 / UNII-2-extended) need a CAC.
        assert!(chandef_is_dfs(52, 20));
        assert!(chandef_is_dfs(64, 20));
        assert!(chandef_is_dfs(100, 20));
        assert!(chandef_is_dfs(144, 20));
    }

    #[test]
    fn wide_chandef_dfs_when_any_subchannel_is_radar() {
        // 80 MHz on ch36 spans 36-48 — all non-DFS.
        assert!(!chandef_is_dfs(42, 80));
        // 160 MHz on ch36 spans 36-64, pulling in DFS channels 52-64.
        assert!(chandef_is_dfs(50, 160));
        // 80 MHz on ch100 spans 100-112 — all DFS.
        assert!(chandef_is_dfs(106, 80));
        // 80 MHz on ch149 spans 149-161 — all non-DFS.
        assert!(!chandef_is_dfs(155, 80));
    }

    fn interface_mld_mac() -> [u8; 6] {
        [0x04, 0xf0, 0x21, 0xc9, 0x1e, 0xff]
    }

    fn assert_reference_mld_link_mac(mac: [u8; 6]) {
        assert_eq!(
            &mac[..3],
            &[0x06, 0xf0, 0x21],
            "link address retains the MLD OUI and sets the local bit"
        );
        assert_eq!(mac[0] & 0x01, 0, "link address is unicast");
    }

    #[test]
    fn omitted_mld_link_macs_resolve_before_the_runtime_snapshot() {
        let cfg = Config::from_json(
            r#"{
                "ssid":"derived-mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "mac":"02:00:00:00:00:00",
                "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {"link_id":0,"band":5,"channel":36,"width":80},
                    {"link_id":1,"band":6,"channel":37,"width":160}
                ]
            }"#,
        )
        .expect("MLD config parses");
        cfg.validate().expect("MLD config validates");
        let mut ap = cfg.build_ap();
        assert!(ap
            .active_mld_links()
            .iter()
            .all(|link| link.mac == [0u8; 6]));

        resolve_mld_addresses(&mut ap, interface_mld_mac()).expect("runtime addresses resolve");
        let snapshot = ap.active_mld_links();
        assert_eq!(ap.mld_mac, interface_mld_mac());
        assert_reference_mld_link_mac(snapshot[0].mac);
        assert_reference_mld_link_mac(snapshot[1].mac);
        assert_ne!(snapshot[0].mac, snapshot[1].mac);
        assert_ne!(snapshot[0].mac, ap.mld_mac);
        assert_ne!(snapshot[1].mac, ap.mld_mac);
        assert_eq!(ap.mac, snapshot[0].mac);
    }

    #[test]
    fn single_mld_link_fallback_randomizes_the_interface_mld_mac_oui() {
        let cfg = Config::from_json(
            r#"{
                "ssid":"single-mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "band":5, "channel":36, "width":80, "link_id":0
            }"#,
        )
        .expect("single-link MLD config parses");
        cfg.validate().expect("single-link MLD config validates");
        let mut ap = cfg.build_ap();

        resolve_mld_addresses(&mut ap, interface_mld_mac()).expect("runtime addresses resolve");
        let snapshot = ap.active_mld_links();
        assert_eq!(snapshot.len(), 1);
        assert_reference_mld_link_mac(snapshot[0].mac);
        assert_eq!(ap.mac, snapshot[0].mac);
        assert_ne!(ap.mac, ap.mld_mac);
    }

    #[test]
    fn explicit_mld_link_mac_is_not_randomized() {
        let configured = [0x0a, 0, 0, 0, 0xaa, 1];
        let cfg = Config::from_json(
            r#"{
                "ssid":"explicit-mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "band":5, "channel":36, "width":80, "link_id":0,
                "mld_links":[
                    {
                        "link_id":0, "mac":"0a:00:00:00:aa:01",
                        "band":5, "channel":36, "width":80
                    }
                ]
            }"#,
        )
        .expect("explicit MLD config parses");
        let mut ap = cfg.build_ap();

        resolve_mld_addresses(&mut ap, interface_mld_mac()).expect("runtime addresses resolve");
        assert_eq!(ap.active_mld_links()[0].mac, configured);
        assert_eq!(ap.mac, configured);
    }

    #[test]
    fn invalid_interface_mld_mac_is_rejected() {
        let cfg = Config::from_json(
            r#"{
                "ssid":"single-mld", "passphrase":"password1234",
                "key_mgmt":"sae", "phy":"be", "mode":"netlink",
                "mld":true, "band":5, "channel":36, "width":80
            }"#,
        )
        .expect("single-link MLD config parses");
        let mut ap = cfg.build_ap();
        assert!(resolve_mld_addresses(&mut ap, [0u8; 6]).is_err());
        assert!(resolve_mld_addresses(&mut ap, [0x01, 0, 0, 0, 0, 1]).is_err());
    }
}
