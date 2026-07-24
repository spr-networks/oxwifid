//! Read-only session/key accessors and protected-frame verification helpers.

use super::*;

impl Client {
    pub fn bssid(&self) -> Option<[u8; 6]> {
        self.bssid
    }

    /// The IGTK installed via PMF (EAPOL message 3), if any.
    pub fn igtk(&self) -> Option<[u8; 16]> {
        self.igtk
    }

    /// The currently installed GTK (test/inspection helper).
    pub fn gtk(&self) -> [u8; 16] {
        self.gtk
    }

    /// The BIGTK installed via Beacon Protection (EAPOL message 3), if any.
    pub fn bigtk(&self) -> Option<[u8; 16]> {
        self.bigtk
    }

    /// Verify a beacon's BIP Management MIC Element against the installed BIGTK
    /// (Beacon Protection). Returns true if protected and valid.
    pub fn verify_beacon(&self, radiotap_frame: &[u8]) -> bool {
        let Some(bigtk) = self.bigtk else {
            return false;
        };
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return false;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return false;
        };
        dot11::bip_verify(
            &bigtk,
            frame.fc0,
            frame.fc1,
            &frame.addr1,
            &frame.addr2,
            &frame.addr3,
            &frame.body,
        )
    }

    /// Verify a received BIP-protected group-addressed management frame against
    /// the installed IGTK.
    pub fn verify_group_mgmt(&self, radiotap_frame: &[u8]) -> bool {
        let Some(igtk) = self.igtk else { return false };
        let Some(body) = dot11::strip_radiotap(radiotap_frame) else {
            return false;
        };
        let Some(frame) = dot11::Dot11::parse(body) else {
            return false;
        };
        dot11::bip_verify(
            &igtk,
            frame.fc0,
            frame.fc1,
            &frame.addr1,
            &frame.addr2,
            &frame.addr3,
            &frame.body,
        )
    }
}
