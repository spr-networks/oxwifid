// nl80211 generic-netlink commands (resolved from the kernel header).
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_SET_KEY: u8 = 10;
pub const NL80211_CMD_NEW_KEY: u8 = 11;
pub const NL80211_CMD_DEL_KEY: u8 = 12;
pub const NL80211_CMD_SET_BEACON: u8 = 14;
pub const NL80211_CMD_START_AP: u8 = 15;
pub const NL80211_CMD_STOP_AP: u8 = 16;
pub const NL80211_CMD_GET_STATION: u8 = 17;
pub const NL80211_CMD_RADAR_DETECT: u8 = 94;
pub const NL80211_CMD_CH_SWITCH_NOTIFY: u8 = 88;
pub const NL80211_CMD_CH_SWITCH_STARTED_NOTIFY: u8 = 110;
pub const NL80211_CMD_CHANNEL_SWITCH: u8 = 102;
pub const NL80211_ATTR_RADAR_EVENT: u16 = 168;
// nl80211_radar_event values.
pub const NL80211_RADAR_DETECTED: u32 = 0;
pub const NL80211_RADAR_CAC_FINISHED: u32 = 1;
pub const NL80211_RADAR_CAC_ABORTED: u32 = 2;
pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
/// 802.11be MLO: add/remove an affiliated link on an AP-mode interface.
pub const NL80211_CMD_ADD_LINK: u8 = 148;
pub const NL80211_CMD_REMOVE_LINK: u8 = 149;
pub const NL80211_CMD_ADD_LINK_STA: u8 = 150;
pub const NL80211_CMD_MODIFY_LINK_STA: u8 = 151;
pub const NL80211_CMD_REMOVE_LINK_STA: u8 = 152;
pub const NL80211_CMD_DEL_INTERFACE: u8 = 8;
pub const NL80211_CMD_SET_INTERFACE: u8 = 6;
pub const NL80211_CMD_SET_STATION: u8 = 18;
pub const NL80211_CMD_NEW_STATION: u8 = 19;
pub const NL80211_CMD_DEL_STATION: u8 = 20;
pub const NL80211_CMD_SET_BSS: u8 = 25;
/// User-space regulatory hint: request the given ISO/IEC 3166-1 alpha-2 country
/// so the kernel applies that regdomain (enabling 5 GHz AP channels that are
/// no-IR under the default world domain). Equivalent to `iw reg set <CC>`.
pub const NL80211_CMD_REQ_SET_REG: u8 = 27;
/// Query the current regulatory domain; the reply carries [`NL80211_ATTR_REG_ALPHA2`].
pub const NL80211_CMD_GET_REG: u8 = 31;
pub const NL80211_CMD_GET_SCAN: u8 = 32;
pub const NL80211_CMD_TRIGGER_SCAN: u8 = 33;
pub const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
pub const NL80211_CMD_SCAN_ABORTED: u8 = 35;
/// Broadcast on the `regulatory` multicast group when the kernel applies a new
/// regulatory domain. Waiting for it (rather than sleeping) confirms the
/// requested country actually took effect and the 5/6 GHz no-IR flags cleared.
pub const NL80211_CMD_REG_CHANGE: u8 = 36;
pub const NL80211_CMD_REGISTER_FRAME: u8 = 58;
pub const NL80211_CMD_FRAME: u8 = 59;
pub const NL80211_CMD_FRAME_TX_STATUS: u8 = 60;
pub const NL80211_CMD_SET_CHANNEL: u8 = 65;
pub const NL80211_CMD_CONTROL_PORT_FRAME: u8 = 129;
pub const NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS: u8 = 139;

// nl80211 attributes.
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_WDEV: u16 = 153;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
/// ifindex of the VLAN interface to move a station into (per-STA VIF).
pub const NL80211_ATTR_STA_VLAN: u16 = 20;
pub const NL80211_ATTR_STA_INFO: u16 = 21;
pub const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
/// 802.11be MLO attributes: per-link id (u8), the MLD MAC address (6 bytes), the
/// nested link array, and the wiphy MLO-support flag.
pub const NL80211_ATTR_MLO_LINKS: u16 = 312;
pub const NL80211_ATTR_MLO_LINK_ID: u16 = 313;
pub const NL80211_ATTR_MLD_ADDR: u16 = 314;
pub const NL80211_ATTR_MLO_SUPPORT: u16 = 315;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_KEY_DATA: u16 = 7;
pub const NL80211_ATTR_KEY_IDX: u16 = 8;
pub const NL80211_ATTR_KEY_CIPHER: u16 = 9;
pub const NL80211_ATTR_KEY_SEQ: u16 = 10;
pub const NL80211_ATTR_KEY_DEFAULT: u16 = 11;
/// Nested key configuration used by NL80211_CMD_SET_KEY.
pub const NL80211_ATTR_KEY: u16 = 80;
/// Make this key the default management key (the IGTK used to TX/validate
/// BIP-protected robust management frames). Kernel value is 40 (28 is a
/// different attribute, which the kernel rejected on policy validation, so the
/// IGTK install silently failed and kernel-side BIP was never enforced).
pub const NL80211_ATTR_KEY_DEFAULT_MGMT: u16 = 40;
// Attributes nested inside NL80211_ATTR_KEY. These are a distinct enum from
// the legacy top-level NL80211_ATTR_KEY_* values used by NEW_KEY.
pub const NL80211_KEY_DATA: u16 = 1;
pub const NL80211_KEY_IDX: u16 = 2;
pub const NL80211_KEY_CIPHER: u16 = 3;
pub const NL80211_KEY_SEQ: u16 = 4;
pub const NL80211_KEY_DEFAULT: u16 = 5;
pub const NL80211_KEY_DEFAULT_MGMT: u16 = 6;
pub const NL80211_KEY_TYPE: u16 = 7;
pub const NL80211_KEY_DEFAULT_TYPES: u16 = 8;
pub const NL80211_KEY_DEFAULT_BEACON: u16 = 10;
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
pub const NL80211_ATTR_HE_6GHZ_CAPABILITY: u16 = 293;
pub const NL80211_ATTR_EHT_CAPABILITY: u16 = 310;
pub const NL80211_ATTR_EML_CAPABILITY: u16 = 317;
pub const NL80211_ATTR_MLD_CAPA_AND_OPS: u16 = 318;
pub const NL80211_ATTR_IFTYPE_EXT_CAPA: u16 = 230;
pub const NL80211_ATTR_EXT_FEATURES: u16 = 217;
/// Bit index in `NL80211_ATTR_EXT_FEATURES`: firmware owns CAC, radar response,
/// and the resulting channel switch.
pub const NL80211_EXT_FEATURE_DFS_OFFLOAD: usize = 25;
// BSS parameters reference AP submits immediately after every START_AP/SET_BEACON.
pub const NL80211_ATTR_BSS_CTS_PROT: u16 = 28;
pub const NL80211_ATTR_BSS_SHORT_PREAMBLE: u16 = 29;
pub const NL80211_ATTR_BSS_SHORT_SLOT_TIME: u16 = 30;
pub const NL80211_ATTR_BSS_BASIC_RATES: u16 = 36;
pub const NL80211_ATTR_AP_ISOLATE: u16 = 96;
pub const NL80211_ATTR_BSS_HT_OPMODE: u16 = 109;
pub const NL80211_ATTR_SCAN_FREQUENCIES: u16 = 44;
pub const NL80211_ATTR_SCAN_SSIDS: u16 = 45;
pub const NL80211_ATTR_SCAN_FLAGS: u16 = 158;
pub const NL80211_SCAN_FLAG_AP: u32 = 1 << 2;
pub const NL80211_ATTR_BSS: u16 = 47;

// NL80211_ATTR_BSS nested scan-result attributes.
pub const NL80211_BSS_BSSID: u16 = 1;
pub const NL80211_BSS_FREQUENCY: u16 = 2;
pub const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
pub const NL80211_BSS_SIGNAL_MBM: u16 = 7;
pub const NL80211_BSS_BEACON_IES: u16 = 11;
pub const NL80211_BSS_MLO_LINK_ID: u16 = 21;
pub const NL80211_BSS_MLD_ADDR: u16 = 22;

// NL80211_ATTR_STA_INFO nested attributes used by reference AP's STA control reply.
pub const NL80211_STA_INFO_SIGNAL: u16 = 7;
pub const NL80211_STA_INFO_TX_BITRATE: u16 = 8;
pub const NL80211_STA_INFO_SIGNAL_AVG: u16 = 13;
pub const NL80211_STA_INFO_RX_BITRATE: u16 = 14;
pub const NL80211_RATE_INFO_BITRATE: u16 = 1;
pub const NL80211_RATE_INFO_BITRATE32: u16 = 5;

// Nested NL80211_ATTR_WIPHY_BANDS attributes. These are the radio capabilities
// reference AP uses to construct HT/VHT/HE/EHT capability elements; advertising the
// driver's bytes avoids internally inconsistent, synthetic beacon capabilities.
pub const NL80211_BAND_ATTR_HT_MCS_SET: u16 = 3;
pub const NL80211_BAND_ATTR_HT_CAPA: u16 = 4;
pub const NL80211_BAND_ATTR_HT_AMPDU_FACTOR: u16 = 5;
pub const NL80211_BAND_ATTR_HT_AMPDU_DENSITY: u16 = 6;
pub const NL80211_BAND_ATTR_VHT_MCS_SET: u16 = 7;
pub const NL80211_BAND_ATTR_VHT_CAPA: u16 = 8;
pub const NL80211_BAND_ATTR_IFTYPE_DATA: u16 = 9;
pub const NL80211_BAND_IFTYPE_ATTR_IFTYPES: u16 = 1;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MAC: u16 = 2;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PHY: u16 = 3;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_MCS_SET: u16 = 4;
pub const NL80211_BAND_IFTYPE_ATTR_HE_CAP_PPE: u16 = 5;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MAC: u16 = 8;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PHY: u16 = 9;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_MCS_SET: u16 = 10;
pub const NL80211_BAND_IFTYPE_ATTR_EHT_CAP_PPE: u16 = 11;
// Per-station WMM/QoS info (nested). Without it mac80211 treats the station as
// non-QoS and never sets up A-MPDU aggregation, so a VHT/HE station negotiates a
// high MCS but moves almost no data. The inner attrs carry the QoS Info byte from
// the station's WMM Information element.
pub const NL80211_ATTR_STA_WME: u16 = 129;
pub const NL80211_STA_WME_UAPSD_QUEUES: u16 = 1;
pub const NL80211_STA_WME_MAX_SP: u16 = 2;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
/// ISO/IEC 3166-1 alpha-2 country code for [`NL80211_CMD_REQ_SET_REG`].
pub const NL80211_ATTR_REG_ALPHA2: u16 = 33;
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
pub const NL80211_ATTR_ACK: u16 = 92;
pub const NL80211_ATTR_FRAME_TYPE: u16 = 101;
pub const NL80211_ATTR_HIDDEN_SSID: u16 = 126;
pub const NL80211_ATTR_KEY_TYPE: u16 = 55;
pub const NL80211_ATTR_STA_CAPABILITY: u16 = 171;
pub const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
pub const NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT: u16 = 103;
pub const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
pub const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
pub const NL80211_ATTR_SPLIT_WIPHY_DUMP: u16 = 174;
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

/// reference AP allocates per-station VIF ids above the 802.1Q VLAN range. With
/// `MAX_VLAN_ID` 4094, its first dynamic id is 4096.
pub const PER_STA_VLAN_ID_START: u32 = 4096;

// auth type + WPA versions + cipher/AKM suite selectors.
pub const NL80211_AUTHTYPE_OPEN_SYSTEM: u32 = 0;
pub const NL80211_AUTHTYPE_SAE: u32 = 4;
pub const NL80211_WPA_VERSION_2: u32 = 2;
pub const WLAN_CIPHER_SUITE_CCMP: u32 = 0x000f_ac04;
pub const WLAN_CIPHER_SUITE_GCMP: u32 = 0x000f_ac08;
pub const WLAN_CIPHER_SUITE_GCMP_256: u32 = 0x000f_ac09;
pub const WLAN_CIPHER_SUITE_CCMP_256: u32 = 0x000f_ac0a;
pub const WLAN_CIPHER_SUITE_BIP_CMAC_128: u32 = 0x000f_ac06;
pub const WLAN_AKM_SUITE_PSK: u32 = 0x000f_ac02;
pub const WLAN_AKM_SUITE_SAE: u32 = 0x000f_ac08;
pub const WLAN_AKM_SUITE_OWE: u32 = 0x000f_ac12;
// Management frame protection (802.11w), required for SAE/OWE and on 6 GHz.
pub const NL80211_ATTR_USE_MFP: u16 = 66;
pub const NL80211_MFP_REQUIRED: u32 = 1;
// per-STA flag bits (NL80211_STA_FLAG_*).
pub const NL80211_STA_FLAG_AUTHORIZED: u32 = 1;
pub const NL80211_STA_FLAG_SHORT_PREAMBLE: u32 = 2;
pub const NL80211_STA_FLAG_WME: u32 = 3;
pub const NL80211_STA_FLAG_MFP: u32 = 4;
pub const NL80211_STA_FLAG_AUTHENTICATED: u32 = 5;
pub const NL80211_STA_FLAG_ASSOCIATED: u32 = 7;

/// Management frame-control type+subtype values to register for, matching
/// reference AP's AP MLME subscription. Deauth and disassoc are essential both for
/// PMF validation and for promptly removing a station that leaves.
pub const REGISTER_SUBTYPES: [u16; 6] = [
    0x0040, // probe request  (subtype 4)
    0x00b0, // authentication (subtype 11)
    0x0000, // association request
    0x0020, // reassociation request
    0x00a0, // disassociation (subtype 10)
    0x00c0, // deauthentication (subtype 12)
];

/// Action categories consumed by the AP state machine. The match begins at the
/// category byte immediately after the management header.
pub const REGISTER_ACTION_MATCHES: [&[u8]; 4] = [
    &[0x05], // Radio Measurement
    &[0x08], // SA Query
    &[0x0a], // WNM / BTM
    &[0x17], // S1G / TWT
];
