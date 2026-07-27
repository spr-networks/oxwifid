use super::model::{Band, Config, KeyMgmt, RadioConfig};
use super::values::validate_band_channel;
use crate::structures::DataCipher;

impl Config {
    /// Validate the configuration for consistency before use. Catches the
    /// silent-misconfiguration footguns: a too-short/empty passphrase that would
    /// still derive a (weak) PMK, and security modes the chosen transport can't
    /// actually deliver.
    pub fn validate(&self) -> Result<(), String> {
        if !self.radios.is_empty() {
            let mut ifaces = Vec::new();
            let mut macs = Vec::new();
            let mut control_paths: Vec<&str> = Vec::new();
            for (index, radio) in self.radios.iter().enumerate() {
                if self.mode != "netlink" {
                    return Err(format!(
                        "radios[{index}] ({}) requires top-level mode \"netlink\"",
                        radio.iface,
                    ));
                }
                let resolved = self.for_radio(radio);
                resolved
                    .validate_radio()
                    .map_err(|e| format!("radios[{index}] ({}): {e}", radio.iface))?;
                if radio.iface.is_empty() {
                    return Err(format!("radios[{index}] requires iface"));
                }
                if ifaces.contains(&radio.iface) {
                    return Err(format!("duplicate radio iface {:?}", radio.iface));
                }
                ifaces.push(radio.iface.clone());
                // Only dup-check explicit BSSIDs. An adopted (implicit) radio MAC
                // comes from its interface, which is already unique per radio.
                let radio_macs = radio
                    .mac_explicit
                    .then_some(&radio.mac)
                    .into_iter()
                    .chain(radio.bss.iter().map(|bss| &bss.mac));
                for mac in radio_macs {
                    if macs.contains(mac) {
                        return Err(format!(
                            "duplicate BSSID {} across radios",
                            crate::util::bytes_to_mac(mac)
                        ));
                    }
                    macs.push(*mac);
                }
                if radio.ctrl_path.is_empty() {
                    return Err(format!("radios[{index}] requires a non-empty ctrl_path"));
                }
                if control_paths.contains(&radio.ctrl_path.as_str()) {
                    return Err(format!("duplicate radio ctrl_path {:?}", radio.ctrl_path));
                }
                control_paths.push(&radio.ctrl_path);
            }
            return Ok(());
        }
        self.validate_radio()
    }

    /// Resolve shared policy plus one physical radio into the existing
    /// single-radio runtime representation.
    pub fn for_radio(&self, radio: &RadioConfig) -> Config {
        let mut resolved = self.clone();
        resolved.radios.clear();
        resolved.iface = radio.iface.clone();
        resolved.mac = radio.mac;
        if let Some(ssid) = &radio.ssid {
            resolved.ssid = ssid.clone();
        }
        resolved.band = radio.band;
        resolved.channel = radio.channel;
        resolved.width = radio.width;
        resolved.phy = radio.phy;
        resolved.ctrl_path = Some(radio.ctrl_path.clone());
        resolved.punct_bitmap = radio.punct_bitmap;
        resolved.mld = radio.mld;
        resolved.link_id = radio.link_id;
        resolved.mld_links = radio.mld_links.clone();
        resolved.mld_default_links = radio.mld_default_links.clone();
        resolved.bss = radio.bss.clone();
        resolved
    }

    /// Runtime control socket path, including the SPR-compatible default.
    ///
    /// SPR's route reconciler discovers active Wi-Fi stations through this
    /// control interface. A generated single-radio config that enables the SPR
    /// API but omits `ctrl_path` must still expose the socket in the shared
    /// state directory; otherwise DHCP succeeds but no per-station route is
    /// installed.
    pub fn effective_ctrl_path(&self) -> Option<String> {
        if let Some(path) = self.ctrl_path.as_ref() {
            return Some(path.clone());
        }
        if self.iface.is_empty() || self.iface.contains('/') {
            return None;
        }
        let state_dir = std::path::Path::new(self.spr_api_socket.as_deref()?).parent()?;
        Some(
            state_dir
                .join(format!("control_{0}/{0}", self.iface))
                .to_string_lossy()
                .into_owned(),
        )
    }

    fn validate_radio(&self) -> Result<(), String> {
        // WPA2-PSK / WPA3-SAE passphrases are 8..=63 characters; OWE has none.
        if self.key_mgmt != KeyMgmt::Owe && !(self.passphrase.is_empty() && self.psk_file.is_some())
        {
            let n = self.passphrase.len();
            if !(8..=63).contains(&n) {
                return Err(format!(
                    "PSK/SAE requires passphrase (8..=63 characters) or psk_file (got {n})"
                ));
            }
        }
        // 6 GHz is Wi-Fi 6E/7 only and mandates WPA3 (SAE) or OWE — WPA2-PSK is
        // not permitted on 6 GHz in any mode.
        if self.band.is_6ghz() && matches!(self.key_mgmt, KeyMgmt::Psk | KeyMgmt::PskSha256) {
            return Err("6 GHz mandates WPA3/SAE or OWE, not WPA2-PSK".to_string());
        }
        if self.pairwise_cipher != DataCipher::Ccmp128 && self.mld {
            return Err("non-default pairwise ciphers are not yet supported with MLO".to_string());
        }
        // Channel width.
        if !matches!(self.width, 20 | 40 | 80 | 160 | 320) {
            return Err(format!(
                "width must be one of 20/40/80/160/320 MHz (got {})",
                self.width
            ));
        }
        if self.width == 320 && !self.band.is_6ghz() {
            return Err("320 MHz is 6 GHz / 802.11be only (set band to 6)".to_string());
        }
        if self.width >= 80 && self.band == Band::Ghz2_4 {
            return Err("80/160 MHz require a 5 or 6 GHz channel".to_string());
        }
        validate_band_channel(self.band, self.channel, "primary")?;
        if !self.mld_links.is_empty() {
            if !self.mld {
                return Err("mld_links requires mld=true".to_string());
            }
            if self.mode != "netlink" {
                return Err("multi-link MLD AP requires netlink mode".to_string());
            }
            let mut ids = Vec::new();
            let mut macs = Vec::new();
            for link in &self.mld_links {
                if link.link_id > 15 {
                    return Err(format!("mld link_id {} out of range", link.link_id));
                }
                if ids.contains(&link.link_id) {
                    return Err(format!("duplicate mld link_id {}", link.link_id));
                }
                if let Some(mac) = link.mac {
                    if macs.contains(&mac) {
                        return Err(format!(
                            "duplicate mld link MAC {}",
                            crate::util::bytes_to_mac(&mac)
                        ));
                    }
                    macs.push(mac);
                }
                let width = link.width.unwrap_or(self.width);
                let band = link.band.unwrap_or(self.band);
                let band6 = band.is_6ghz();
                if !matches!(width, 20 | 40 | 80 | 160 | 320) {
                    return Err(format!(
                        "mld link {} width must be one of 20/40/80/160/320 MHz",
                        link.link_id
                    ));
                }
                if width == 320 && !band6 {
                    return Err(format!(
                        "mld link {}: 320 MHz is 6 GHz / 802.11be only (set band to 6)",
                        link.link_id
                    ));
                }
                if width >= 80 && band == Band::Ghz2_4 {
                    return Err(format!(
                        "mld link {}: 80/160 MHz require a 5 or 6 GHz channel",
                        link.link_id
                    ));
                }
                validate_band_channel(band, link.channel, &format!("mld link {}", link.link_id))?;
                ids.push(link.link_id);
            }
            if !ids.contains(&self.link_id) {
                return Err(format!(
                    "mld_links must include the association link_id {}",
                    self.link_id
                ));
            }
        }
        if let Some(default_links) = &self.mld_default_links {
            if !self.mld {
                return Err("mld_default_links requires mld=true".to_string());
            }
            if default_links.is_empty() {
                return Err("mld_default_links must contain at least one Link ID".to_string());
            }
            let configured_links: Vec<u8> = if self.mld_links.is_empty() {
                vec![self.link_id]
            } else {
                self.mld_links.iter().map(|link| link.link_id).collect()
            };
            let mut seen = Vec::new();
            for link_id in default_links {
                if *link_id > 15 {
                    return Err(format!("mld_default_links Link ID {link_id} out of range"));
                }
                if seen.contains(link_id) {
                    return Err(format!("duplicate Link ID {link_id} in mld_default_links"));
                }
                if !configured_links.contains(link_id) {
                    return Err(format!(
                        "mld_default_links Link ID {link_id} is not present in mld_links"
                    ));
                }
                seen.push(*link_id);
            }
        }
        // Additional BSSes need per-BSS netdevs, which only the netlink transport
        // creates.
        if !self.bss.is_empty() && self.mode != "netlink" {
            return Err("multiple BSSes (bss) require netlink mode".to_string());
        }
        // Additional BSSes: same passphrase rules, and each must have a BSSID
        // distinct from the primary and every other BSS (one radio, many MACs).
        let mut macs = vec![self.mac];
        for b in &self.bss {
            // A BSS without its own (static guest) passphrase may instead ride
            // on the primary's authoritative credential file.
            let uses_device_db = !b.own_passphrase && self.psk_file.is_some();
            if b.key_mgmt != KeyMgmt::Owe
                && !uses_device_db
                && !(8..=63).contains(&b.passphrase.len())
            {
                return Err(format!(
                    "bss {:?} passphrase must be 8..=63 characters",
                    b.ssid
                ));
            }
            if self.band.is_6ghz() && matches!(b.key_mgmt, KeyMgmt::Psk | KeyMgmt::PskSha256) {
                return Err(format!(
                    "bss {:?}: 6 GHz mandates WPA3/SAE or OWE, not WPA2-PSK",
                    b.ssid
                ));
            }
            if macs.contains(&b.mac) {
                return Err(format!(
                    "bss {:?} BSSID {} duplicates another BSS on this radio",
                    b.ssid,
                    crate::util::bytes_to_mac(&b.mac)
                ));
            }
            macs.push(b.mac);
        }
        Ok(())
    }

    /// The key-management mode the AP will actually advertise after applying
    /// the 6 GHz security mandate.
    ///
    /// EHT/802.11be by itself does not remove legacy AKMs on 2.4 or 5 GHz. In
    /// particular, a reference AP MLD can advertise SAE transition mode with
    /// PMF optional so non-EHT WPA2 clients can use an affiliated link. Only
    /// 6 GHz removes PSK AKMs and forces SAE.
    pub fn effective_key_mgmt(&self) -> KeyMgmt {
        if self.band.is_6ghz()
            && matches!(
                self.key_mgmt,
                KeyMgmt::Psk | KeyMgmt::PskSha256 | KeyMgmt::SaeTransition
            )
        {
            KeyMgmt::Sae
        } else {
            self.key_mgmt
        }
    }
}
