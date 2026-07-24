use barely_ap::config::Config;

#[test]
fn generator_shaped_config_parses() {
    let text = r#"{
      "mode": "netlink",
      "country": "US",
      "key_mgmt": "sae-transition",
      "psk_file": "/configs/wifi/sae_passwords",
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
