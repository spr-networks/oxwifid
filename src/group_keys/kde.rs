//! GTK key-data encapsulation and parsing.

pub(super) fn find_vendor_kde(key_data: &[u8], kde_type: u8) -> Option<&[u8]> {
    let mut offset = 0;
    while offset + 2 <= key_data.len() {
        let id = key_data[offset];
        let len = key_data[offset + 1] as usize;
        let end = offset.checked_add(2 + len)?;
        if end > key_data.len() {
            return None;
        }
        let body = &key_data[offset + 2..end];
        if id == 0xdd && body.len() >= 4 && body[..3] == [0x00, 0x0f, 0xac] && body[3] == kde_type {
            return Some(body);
        }
        offset = end;
    }
    None
}

/// Encode a GTK KDE (00-0F-AC:1).
pub fn gtk_kde(key_id: u8, gtk: &[u8]) -> Vec<u8> {
    let mut kde = Vec::with_capacity(8 + gtk.len());
    kde.push(0xdd);
    kde.push((gtk.len() + 6) as u8);
    kde.extend_from_slice(&[0x00, 0x0f, 0xac, 0x01]);
    kde.extend_from_slice(&[key_id & 0x03, 0x00]);
    kde.extend_from_slice(gtk);
    kde
}

/// Encode an MLO GTK KDE (00-0F-AC:16) with a zero packet number.
pub fn mlo_gtk_kde(link_id: u8, key_id: u8, gtk: &[u8]) -> Vec<u8> {
    mlo_gtk_kde_with_pn(link_id, key_id, &[0; 6], gtk)
}

/// Encode an MLO GTK KDE (00-0F-AC:16).
pub fn mlo_gtk_kde_with_pn(link_id: u8, key_id: u8, pn: &[u8; 6], gtk: &[u8]) -> Vec<u8> {
    let mut kde = Vec::with_capacity(13 + gtk.len());
    kde.push(0xdd);
    kde.push((11 + gtk.len()) as u8);
    kde.extend_from_slice(&[0x00, 0x0f, 0xac, 0x10]);
    kde.push((key_id & 0x03) | ((link_id & 0x0f) << 4));
    kde.extend_from_slice(pn);
    kde.extend_from_slice(gtk);
    kde
}

/// Extract a GTK from EAPOL key data.
pub fn parse_gtk_kde(key_data: &[u8]) -> Option<Vec<u8>> {
    parse_gtk_kde_full(key_data).map(|(_, gtk)| gtk)
}

/// Extract the key ID and GTK from EAPOL key data.
pub fn parse_gtk_kde_full(key_data: &[u8]) -> Option<(u8, Vec<u8>)> {
    let body = find_vendor_kde(key_data, 0x01)?;
    if body.len() < 22 {
        return None;
    }
    Some((body[4] & 0x03, body[6..].to_vec()))
}

/// Extract link ID, key ID, packet number, and GTK from an MLO GTK KDE.
pub fn parse_mlo_gtk_kde_full(key_data: &[u8]) -> Option<(u8, u8, [u8; 6], Vec<u8>)> {
    let body = find_vendor_kde(key_data, 0x10)?;
    if body.len() < 12 {
        return None;
    }
    let mut pn = [0u8; 6];
    pn.copy_from_slice(&body[5..11]);
    Some((
        (body[4] >> 4) & 0x0f,
        body[4] & 0x03,
        pn,
        body[11..].to_vec(),
    ))
}
