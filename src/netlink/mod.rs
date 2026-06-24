//! WPA3-capable nl80211 (generic netlink) transport.
//!
//! This is an alternative to the [`crate::raw_frames::af_packet`] monitor-mode
//! socket: instead of a raw `AF_PACKET` socket it talks to the kernel's
//! `cfg80211`/`mac80211` over generic netlink (the same interface hostapd uses).
//! It configures the radio (interface type + channel) and injects/receives
//! management frames via `NL80211_CMD_FRAME`.
//!
//! The message-encoding layer ([`msg`]) is platform independent and unit
//! tested; the socket/[`Link`] layer is Linux-only.
//!
//! Scope: management-frame TX/RX + radio setup. Because `NL80211_CMD_FRAME`
//! only carries management frames, userspace-encrypted CCMP **data** frames
//! still require the monitor (`af_packet`) path — this transport is intended for
//! the management/handshake plane. It is Linux-only and not exercised on
//! non-Linux hosts.

pub mod msg;

// nl80211 generic-netlink commands (resolved from the kernel header).
pub const NL80211_CMD_NEW_KEY: u8 = 11;
pub const NL80211_CMD_DEL_KEY: u8 = 12;
pub const NL80211_CMD_START_AP: u8 = 15;
pub const NL80211_CMD_STOP_AP: u8 = 17;
pub const NL80211_CMD_RADAR_DETECT: u8 = 99;
pub const NL80211_CMD_CHANNEL_SWITCH: u8 = 107;
pub const NL80211_ATTR_RADAR_EVENT: u16 = 168;
// nl80211_radar_event values.
pub const NL80211_RADAR_DETECTED: u32 = 0;
pub const NL80211_RADAR_CAC_FINISHED: u32 = 1;
pub const NL80211_RADAR_CAC_ABORTED: u32 = 2;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;
pub const NL80211_CMD_SET_INTERFACE: u8 = 6;
pub const NL80211_CMD_SET_STATION: u8 = 18;
pub const NL80211_CMD_NEW_STATION: u8 = 19;
pub const NL80211_CMD_DEL_STATION: u8 = 20;
pub const NL80211_CMD_REGISTER_FRAME: u8 = 58;
pub const NL80211_CMD_FRAME: u8 = 59;
pub const NL80211_CMD_SET_CHANNEL: u8 = 65;
pub const NL80211_CMD_CONTROL_PORT_FRAME: u8 = 129;

// nl80211 attributes.
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
/// ifindex of the VLAN interface to move a station into (per-STA VIF).
pub const NL80211_ATTR_STA_VLAN: u16 = 20;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY_DATA: u16 = 7;
pub const NL80211_ATTR_KEY_IDX: u16 = 8;
pub const NL80211_ATTR_KEY_CIPHER: u16 = 9;
pub const NL80211_ATTR_KEY_SEQ: u16 = 10;
pub const NL80211_ATTR_KEY_DEFAULT: u16 = 11;
/// Make this key the default management key (the IGTK used to TX/validate
/// BIP-protected robust management frames).
pub const NL80211_ATTR_KEY_DEFAULT_MGMT: u16 = 28;
/// Nested attribute selecting which traffic a default key applies to
/// (unicast/multicast), so a group key becomes the multicast default.
pub const NL80211_ATTR_KEY_DEFAULT_TYPES: u16 = 88;
pub const NL80211_KEY_DEFAULT_TYPE_UNICAST: u16 = 1;
pub const NL80211_KEY_DEFAULT_TYPE_MULTICAST: u16 = 2;
pub const NL80211_ATTR_BEACON_INTERVAL: u16 = 12;
pub const NL80211_ATTR_DTIM_PERIOD: u16 = 13;
pub const NL80211_ATTR_BEACON_HEAD: u16 = 14;
pub const NL80211_ATTR_BEACON_TAIL: u16 = 15;
pub const NL80211_ATTR_STA_AID: u16 = 16;
pub const NL80211_ATTR_STA_FLAGS: u16 = 17;
pub const NL80211_ATTR_STA_LISTEN_INTERVAL: u16 = 18;
pub const NL80211_ATTR_STA_SUPPORTED_RATES: u16 = 19;
// Per-station PHY capabilities, handed to the driver on association so its rate
// control can use HT/VHT/HE MCS rates instead of the legacy basic rate.
pub const NL80211_ATTR_HT_CAPABILITY: u16 = 31;
pub const NL80211_ATTR_VHT_CAPABILITY: u16 = 157;
pub const NL80211_ATTR_HE_CAPABILITY: u16 = 269;
// Per-station WMM/QoS info (nested). Without it mac80211 treats the station as
// non-QoS and never sets up A-MPDU aggregation, so a VHT/HE station negotiates a
// high MCS but moves almost no data. The inner attrs carry the QoS Info byte from
// the station's WMM Information element.
pub const NL80211_ATTR_STA_WME: u16 = 129;
pub const NL80211_STA_WME_UAPSD_QUEUES: u16 = 1;
pub const NL80211_STA_WME_MAX_SP: u16 = 2;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_FRAME: u16 = 51;
pub const NL80211_ATTR_SSID: u16 = 52;
pub const NL80211_ATTR_AUTH_TYPE: u16 = 53;
pub const NL80211_ATTR_STA_FLAGS2: u16 = 67;
pub const NL80211_ATTR_PRIVACY: u16 = 70;
pub const NL80211_ATTR_CONTROL_PORT: u16 = 68;
pub const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 73;
pub const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 74;
pub const NL80211_ATTR_WPA_VERSIONS: u16 = 75;
pub const NL80211_ATTR_AKM_SUITES: u16 = 76;
pub const NL80211_ATTR_FRAME_MATCH: u16 = 91;
pub const NL80211_ATTR_FRAME_TYPE: u16 = 101;
pub const NL80211_ATTR_HIDDEN_SSID: u16 = 126;
pub const NL80211_ATTR_KEY_TYPE: u16 = 55;
pub const NL80211_ATTR_STA_CAPABILITY: u16 = 171;
pub const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
pub const NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT: u16 = 103;
pub const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
pub const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
pub const NL80211_ATTR_SOCKET_OWNER: u16 = 204;
pub const NL80211_ATTR_CONTROL_PORT_OVER_NL80211: u16 = 264;
pub const NL80211_CHAN_WIDTH_20: u32 = 1;
// nl80211_chan_width values: the narrow widths (_5/_10/_1/_2/_4/_8/_16) sit
// between _160 and _320 in the enum, so _320 is 13, not 6. Verified against the
// kernel header (do NOT count by position past _160).
pub const NL80211_CHAN_WIDTH_40: u32 = 2;
pub const NL80211_CHAN_WIDTH_80: u32 = 3;
pub const NL80211_CHAN_WIDTH_160: u32 = 5;
pub const NL80211_CHAN_WIDTH_320: u32 = 13;
pub const NL80211_ATTR_CENTER_FREQ2: u16 = 161;
pub const NL80211_KEYTYPE_GROUP: u32 = 0;
pub const NL80211_KEYTYPE_PAIRWISE: u32 = 1;
pub const ETH_P_PAE: u16 = 0x888e; // 802.1X / EAPOL ethertype

// interface types.
pub const NL80211_IFTYPE_AP: u32 = 3;
pub const NL80211_IFTYPE_AP_VLAN: u32 = 4;
pub const NL80211_IFTYPE_MONITOR: u32 = 6;

// auth type + WPA versions + cipher/AKM suite selectors.
pub const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
pub const NL80211_AUTHTYPE_SAE: u32 = 4;
pub const NL80211_WPA_VERSION_2: u32 = 2;
pub const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000f_ac04;
pub const WLAN_CIPHER_SUITE_BIP_CMAC_128: u32 = 0x000f_ac06;
pub const WLAN_AKM_SUITE_PSK: u32 = 0x000f_ac02;
pub const WLAN_AKM_SUITE_SAE: u32 = 0x000f_ac08;
pub const WLAN_AKM_SUITE_OWE: u32 = 0x000f_ac12;
// Management frame protection (802.11w), required for SAE/OWE and on 6 GHz.
pub const NL80211_ATTR_USE_MFP: u16 = 66;
pub const NL80211_MFP_REQUIRED: u32 = 1;
// per-STA flag bits (NL80211_STA_FLAG_*).
pub const NL80211_STA_FLAG_AUTHORIZED: u32 = 1;
pub const NL80211_STA_FLAG_AUTHENTICATED: u32 = 5;
pub const NL80211_STA_FLAG_ASSOCIATED: u32 = 7;

/// Management frame-control type+subtype values to register for, matching the
/// frames the AP handles (probe req, auth, (re)assoc req).
pub const REGISTER_SUBTYPES: [u16; 4] = [
    0x0040, // probe request  (subtype 4)
    0x00b0, // authentication (subtype 11)
    0x0000, // association request
    0x0020, // reassociation request
];

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

#[cfg(test)]
mod tests {
    use super::{chandef_is_dfs, fallback_channel};

    #[test]
    fn fallback_is_always_non_dfs() {
        for ch in [52u8, 60, 64, 100, 120, 132, 144] {
            let fb = fallback_channel(ch);
            assert!(!chandef_is_dfs(fb, 20), "fallback {fb} for {ch} must be non-DFS");
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
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{run_offload_ap, run_offload_aps, NetlinkLink};
