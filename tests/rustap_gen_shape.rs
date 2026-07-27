use barely_ap::config::Config;

#[test]
fn generator_shaped_config_parses() {
    let text = r#"{
      "mode": "netlink",
      "country": "US",
      "key_mgmt": "sae-transition",
      "wpa_psk_file": "/configs/wifi/wpa2pskfile",
      "sae_psk_file": "/configs/wifi/sae_passwords",
      "per_sta_vif": true,
      "wmm": true,
      "spr_api_socket": "/state/wifi/apisock",
      "spr_dhcp_helper": "/hostap_dhcp_helper",
      "radios": [
        {
          "iface": "wlan2",
          "ssid": "s5210",
          "channel": 36,
          "band": 5,
          "width": 80,
          "phy": "ac",
          "ctrl_path": "/state/wifi/control_wlan2/wlan2",
          "bss": [
            {"ssid": "guest", "mac": "06:0c:43:26:60:10", "key_mgmt": "sae", "passphrase": "guestpass123", "disable_isolation": true}
          ]
        },
        {
          "iface": "wlan1",
          "ssid": "s5210",
          "channel": 6,
          "band": 2.4,
          "width": 20,
          "phy": "ac",
          "ctrl_path": "/state/wifi/control_wlan1/wlan1"
        }
      ]
    }"#;
    match Config::from_json(text) {
        Ok(cfg) => {
            assert_eq!(cfg.radios.len(), 2);
        }
        Err(e) => panic!("generator-shaped config rejected: {e}"),
    }
}

#[test]
fn spr_single_radio_config_derives_reference_control_socket() {
    let text = r#"{
      "ssid": "rustaptest",
      "mode": "netlink",
      "key_mgmt": "sae",
      "passphrase": "password1234",
      "iface": "wlan3",
      "band": 5,
      "channel": 36,
      "width": 80,
      "phy": "be",
      "spr_api_socket": "/state/wifi/apisock",
      "spr_dhcp_helper": "/hostap_dhcp_helper"
    }"#;
    let cfg = Config::from_json(text).expect("SPR single-radio config parses");

    assert_eq!(
        cfg.effective_ctrl_path().as_deref(),
        Some("/state/wifi/control_wlan3/wlan3")
    );
}

#[test]
fn explicit_control_socket_wins_over_spr_default() {
    let text = r#"{
      "ssid": "rustaptest",
      "mode": "netlink",
      "key_mgmt": "sae",
      "passphrase": "password1234",
      "iface": "wlan3",
      "band": 5,
      "channel": 36,
      "width": 80,
      "phy": "be",
      "ctrl_path": "/run/custom/control",
      "spr_api_socket": "/state/wifi/apisock"
    }"#;
    let cfg = Config::from_json(text).expect("config with explicit control path parses");

    assert_eq!(
        cfg.effective_ctrl_path().as_deref(),
        Some("/run/custom/control")
    );
}
