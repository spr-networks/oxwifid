//! Multi-Link key-data encapsulation.

pub fn mac_addr_kde(mac: &[u8; 6]) -> Vec<u8> {
    let mut v = vec![0xdd, 4 + 6, 0x00, 0x0f, 0xac, 0x03];
    v.extend_from_slice(mac);
    v
}

/// Extract a MAC Address KDE (00-0F-AC:3) from EAPOL key data.
pub fn parse_mac_addr_kde(key_data: &[u8]) -> Option<[u8; 6]> {
    let mut i = 0;
    while i + 2 <= key_data.len() {
        let id = key_data[i];
        let len = key_data[i + 1] as usize;
        if i + 2 + len > key_data.len() {
            break;
        }
        let body = &key_data[i + 2..i + 2 + len];
        if id == 0xdd && len >= 4 + 6 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == 0x03 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&body[4..10]);
            return Some(mac);
        }
        i += 2 + len;
    }
    None
}

/// The GTK key-data encapsulation (KDE) wrapped inside message 3:
/// `DD len 00-0F-AC 01 <KeyID/Tx byte> <reserved> <GTK>` (IEEE 802.11 Fig 12-45).
///
/// Note: the reference `ap.py` appends a stray zero-length `DD 00` vendor
/// element after the GTK; that is non-standard cruft and is intentionally not
/// reproduced here.
pub fn mlo_link_kde(link_id: u8, link_mac: &[u8; 6], link_rsne: &[u8]) -> Vec<u8> {
    let mut has_rsne = false;
    let mut has_rsnxe = false;
    let mut i = 0;
    while i + 2 <= link_rsne.len() {
        let id = link_rsne[i];
        let len = link_rsne[i + 1] as usize;
        if i + 2 + len > link_rsne.len() {
            break;
        }
        has_rsne |= id == 48;
        has_rsnxe |= id == 0xf4;
        i += 2 + len;
    }

    let mut v = Vec::new();
    v.push(0xdd);
    v.push((4 + 1 + 6 + link_rsne.len()) as u8);
    v.extend_from_slice(&[0x00, 0x0f, 0xac, 0x13]);
    let mut link_info = link_id & 0x0f;
    if has_rsne {
        link_info |= 0x10;
    }
    if has_rsnxe {
        link_info |= 0x20;
    }
    v.push(link_info);
    v.extend_from_slice(link_mac);
    v.extend_from_slice(link_rsne);
    v
}
