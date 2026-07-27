use super::credentials::parse_psk_file;
use super::model::{BssConfig, Config, KeyMgmt};
use crate::ap::{Ap, MldLink};
use zeroize::Zeroize;

impl Config {
    /// Construct and fully configure an [`Ap`] from this configuration.
    pub fn build_ap(&self) -> Ap {
        let mut ap = if self.passphrase.is_empty() {
            Ap::new_without_credential(&self.ssid, self.mac, self.channel)
        } else {
            Ap::new(&self.ssid, &self.passphrase, self.mac, self.channel)
        };
        ap.set_country(self.country);
        ap.set_width(self.width);
        ap.punct = self.punct_bitmap;
        if self.mld {
            ap.mld = true;
            // The kernel's AP-MLD address is the interface's own address (the
            // links get their own addresses via ADD_LINK). It must equal the MLD
            // MAC barely-ap advertises + uses for SAE/4-way crypto, otherwise the
            // kernel does not recognize (and silently drops) EAPOL the client
            // sends to the advertised MLD address. So the MLD MAC IS the primary
            // interface `mac`; the affiliated links use the `mld_links` BSSIDs.
            ap.mld_mac = self.mac;
            ap.link_id = self.link_id;
            let links = self.resolved_mld_links();
            ap.set_mld_links(links);
            // Netlink mode must derive omitted link BSSIDs only after it has read
            // the kernel's actual interface/MLD address. Other transports have no
            // runtime address adoption step, so resolve against the configured
            // MLD address now.
            if self.mode != "netlink" {
                ap.derive_missing_mld_link_macs();
            }
            // Anchor the management plane (auth/assoc/EAPOL) on the association
            // link's BSSID: the client authenticates to that link address, so the
            // AP's responses must originate from it (not the MLD address). In
            // netlink mode this can temporarily be the zero sentinel; bring-up
            // resolves it before any link snapshot or frame construction.
            if let Some(assoc) = ap.mld_link_mac(self.link_id) {
                ap.mac = assoc;
            }
            if let Some(default_links) = &self.mld_default_links {
                let mask = default_links
                    .iter()
                    .fold(0u16, |mask, link_id| mask | (1u16 << link_id));
                ap.set_mld_default_link_mask(mask);
            }
        }
        ap.set_phy(self.phy);
        ap.set_pairwise_cipher(self.pairwise_cipher);
        ap.set_wmm(self.wmm);
        ap.set_group_rekey(self.group_rekey);
        ap.set_strict_rekey(self.strict_rekey);
        apply_security(&mut ap, self.effective_key_mgmt());
        if self.ocv {
            ap.enable_ocv();
        }
        if self.btm {
            ap.enable_btm();
        }
        if self.rnr {
            ap.enable_rnr_6ghz(37);
        }
        if self.band.is_6ghz() {
            ap.enable_band6();
            ap.enable_sae(); // 6 GHz mandates WPA3
        }
        if self.per_sta_vif {
            ap.enable_per_sta_vif();
        }
        if self.guest {
            ap.enable_guest();
        }
        load_credential_files(&mut ap, self);
        ap
    }

    pub fn resolved_mld_links(&self) -> Vec<MldLink> {
        if self.mld_links.is_empty() {
            vec![MldLink {
                link_id: self.link_id,
                // The top-level MAC is the AP MLD address, not an affiliated
                // link BSSID. Use the same unresolved sentinel as an omitted
                // mld_links[].mac so the two valid configuration forms follow
                // one derivation path.
                mac: [0u8; 6],
                channel: self.channel,
                width: self.width,
                band6: self.band.is_6ghz(),
            }]
        } else {
            self.mld_links
                .iter()
                .map(|l| MldLink {
                    link_id: l.link_id,
                    mac: l.mac.unwrap_or([0u8; 6]),
                    channel: l.channel,
                    width: l.width.unwrap_or(self.width),
                    band6: l.band.unwrap_or(self.band).is_6ghz(),
                })
                .collect()
        }
    }

    /// Build an [`Ap`] for an additional BSS: the primary's radio parameters
    /// (channel, width, country, band) with the BSS's own SSID/BSSID/security.
    pub fn build_bss_ap(&self, bss: &BssConfig) -> Ap {
        let mut ap = if bss.passphrase.is_empty() {
            Ap::new_without_credential(&bss.ssid, bss.mac, self.channel)
        } else {
            Ap::new(&bss.ssid, &bss.passphrase, bss.mac, self.channel)
        };
        ap.set_country(self.country);
        ap.set_width(self.width);
        ap.set_phy(self.phy);
        ap.set_pairwise_cipher(self.pairwise_cipher);
        ap.set_wmm(self.wmm);
        ap.set_group_rekey(self.group_rekey);
        ap.set_strict_rekey(self.strict_rekey);
        // 6 GHz removes PSK AKMs. EHT on 2.4/5 GHz does not: a transition-mode
        // BSS must remain available to legacy WPA2 clients.
        let km = if self.band.is_6ghz()
            && matches!(
                bss.key_mgmt,
                KeyMgmt::Psk | KeyMgmt::PskSha256 | KeyMgmt::SaeTransition
            ) {
            KeyMgmt::Sae
        } else {
            bss.key_mgmt
        };
        apply_security(&mut ap, km);
        if self.ocv {
            ap.enable_ocv();
        }
        if self.band.is_6ghz() {
            ap.enable_band6();
            ap.enable_sae();
        }
        // SPR ExtraBSS semantics: extra BSSes are guest networks by default —
        // client isolation (ap_isolate) + a per-station VIF/GTK — unless the
        // entry opts out with `disable_isolation`.
        if bss.guest && !bss.disable_isolation {
            ap.enable_guest();
            ap.enable_per_sta_vif();
        }
        // Credentials, SPR ExtraBSS semantics: an entry with its own passphrase
        // is a static guest password the device credential database must never
        // override (reference AP: `wpa_psk_file=/dev/null` + `wpa_passphrase`).
        // Without one, the BSS authenticates against the same separate WPA2 and
        // SAE databases as the primary.
        if bss.own_passphrase {
            ap.set_static_credential();
        } else {
            load_credential_files(&mut ap, self);
        }
        ap
    }
}

fn load_credential_files(ap: &mut Ap, config: &Config) {
    if let Some(path) = &config.wpa_psk_file {
        // Mark each configured domain authoritative before I/O so a missing or
        // malformed file fails closed instead of falling back to a passphrase.
        ap.set_wpa_psk_file(&[]);
        match parse_psk_file(path) {
            Ok(mut entries) => {
                ap.set_wpa_psk_file(&entries);
                zeroize_entries(&mut entries);
            }
            Err(error) => eprintln!("barely-ap: wpa_psk_file {path:?}: {error}"),
        }
    }
    if let Some(path) = &config.sae_psk_file {
        ap.set_sae_password_file(&[]);
        match parse_psk_file(path) {
            Ok(mut entries) => {
                ap.set_sae_password_file(&entries);
                zeroize_entries(&mut entries);
            }
            Err(error) => eprintln!("barely-ap: sae_psk_file {path:?}: {error}"),
        }
    }
}

fn zeroize_entries(entries: &mut [(Option<[u8; 6]>, String)]) {
    for (_, password) in entries {
        password.zeroize();
    }
}

/// Apply a key-management mode to an AP (shared by the primary + extra BSSes).
fn apply_security(ap: &mut Ap, km: KeyMgmt) {
    match km {
        KeyMgmt::Psk => {}
        KeyMgmt::PskSha256 => ap.enable_psk_sha256(),
        KeyMgmt::Sae => ap.enable_sae(),
        KeyMgmt::SaeTransition => {
            ap.enable_sae();
            ap.enable_transition();
        }
        KeyMgmt::Owe => ap.enable_owe(),
    }
}
