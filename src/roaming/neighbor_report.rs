//! 802.11k neighbor-report and reduced-neighbor-report support.

use crate::frames::ie;

pub const ACTION_CATEGORY_RADIO_MEAS: u8 = 5;
pub const RADIO_MEAS_NEIGHBOR_REPORT_RESP: u8 = 5;

/// Build an 802.11k Neighbor Report element (ID 52).
pub fn neighbor_report_element(bssid: &[u8; 6], operating_class: u8, channel: u8) -> Vec<u8> {
    let mut information = bssid.to_vec();
    information.extend_from_slice(&0u32.to_le_bytes());
    information.push(operating_class);
    information.push(channel);
    information.push(0x09);
    crate::frames::ie(52, &information)
}

/// Build a CCMP-protected Neighbor Report Response.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_neighbor_report(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    neighbors: &[u8],
    sc: u16,
    pn: u64,
    tk: &[u8],
) -> Vec<u8> {
    build_protected_neighbor_report_sec(bssid, sta, dialog, neighbors, sc, pn, tk, None)
}

/// Build a protected Neighbor Report Response with optional MLO security addresses.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_neighbor_report_sec(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    neighbors: &[u8],
    sc: u16,
    pn: u64,
    tk: &[u8],
    security_addresses: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    build_protected_neighbor_report_for_cipher_sec(
        crate::frames::DataCipher::Ccmp128,
        bssid,
        sta,
        dialog,
        neighbors,
        sc,
        pn,
        tk,
        security_addresses,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_protected_neighbor_report_for_cipher_sec(
    cipher: crate::frames::DataCipher,
    bssid: &[u8; 6],
    sta: &[u8; 6],
    dialog: u8,
    neighbors: &[u8],
    sc: u16,
    pn: u64,
    tk: &[u8],
    security_addresses: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    let mut body = vec![
        ACTION_CATEGORY_RADIO_MEAS,
        RADIO_MEAS_NEIGHBOR_REPORT_RESP,
        dialog,
    ];
    body.extend_from_slice(neighbors);
    crate::frames::build_protected_mgmt_sec(
        cipher,
        crate::frames::SUBTYPE_ACTION,
        sta,
        bssid,
        bssid,
        security_addresses,
        0,
        sc,
        pn,
        0,
        tk,
        &body,
    )
}

pub fn reduced_neighbor_report(neighbor_bssid: &[u8; 6], op_class: u8, channel: u8) -> Vec<u8> {
    // TBTT Information Header: field type 0, count 0 (1 TBTT info), length 13;
    // then operating class, channel, and the TBTT Information field's offset.
    let mut d = vec![0x00, 13, op_class, channel, 0xff];
    d.extend_from_slice(neighbor_bssid); // BSSID
    d.extend_from_slice(&[0, 0, 0, 0]); // Short SSID
    d.push(0x00); // BSS Parameters
    d.push(0x00); // 20 MHz PSD
    ie(201, &d)
}

/// IEEE CRC-32 used for the 6 GHz Short SSID field.
///
/// This is the same CRC (initial value and final complement included) that
/// reference AP exposes as `ieee80211_crc32()`.
pub fn short_ssid(ssid: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in ssid {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320u32 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

/// Reduced Neighbor Report for an affiliated AP of the same MLD.
///
/// MLO discovery uses the 16-byte TBTT Information form: the normal 13-byte
/// neighbor data followed by MLD ID, Link ID and the full BSS Parameters Change
/// Count. `mld_id` is zero for matching a transmitted BSSID profile (the normal
/// non-MBSSID case).
#[allow(clippy::too_many_arguments)]
pub fn mld_reduced_neighbor_report(
    neighbor_bssid: &[u8; 6],
    ssid: &[u8],
    op_class: u8,
    channel: u8,
    mld_id: u8,
    link_id: u8,
    bss_change_count: u8,
) -> Vec<u8> {
    mld_reduced_neighbor_report_with_disabled(
        neighbor_bssid,
        ssid,
        op_class,
        channel,
        mld_id,
        link_id,
        bss_change_count,
        false,
    )
}

/// MLD Reduced Neighbor Report with the Link Disabled bit available for an
/// affiliated link excluded by the currently advertised TID-to-link mapping.
#[allow(clippy::too_many_arguments)]
pub fn mld_reduced_neighbor_report_with_disabled(
    neighbor_bssid: &[u8; 6],
    ssid: &[u8],
    op_class: u8,
    channel: u8,
    mld_id: u8,
    link_id: u8,
    bss_change_count: u8,
    disabled: bool,
) -> Vec<u8> {
    // TBTT Information Header: type 0, count 0 (one entry), 16-byte MLD form.
    let mut d = vec![0x00, 16, op_class, channel, 0xff];
    d.extend_from_slice(neighbor_bssid);
    d.extend_from_slice(&short_ssid(ssid).to_le_bytes());
    // Same SSID + co-located. The partner is an affiliated BSS of this MLD.
    d.push((1 << 1) | (1 << 6));
    d.push(127); // reference AP's RNR_20_MHZ_PSD_MAX_TXPOWER (unknown/max encoding)
    d.push(mld_id);
    d.push((link_id & 0x0f) | ((bss_change_count & 0x0f) << 4));
    let mut param2 = (bss_change_count >> 4) & 0x0f;
    if disabled {
        param2 |= 0x20;
    }
    d.push(param2);
    ie(201, &d)
}
