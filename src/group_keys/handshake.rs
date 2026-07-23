//! EAPOL group-key handshake and protected group deauthentication.

use crate::auth::crypto;
use crate::frames::*;
use crate::group_keys::{gtk_kde, igtk_kde, mlo_bigtk_kde, mlo_gtk_kde, mlo_igtk_kde};
use crate::structures::security::{KeyInfo, KeyMic};
use zeroize::Zeroize;

pub fn build_group_key_msg1(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    kck: &[u8],
    kek: &[u8],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    replay: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    let mut plain = gtk_kde(gtk_key_id, gtk);
    if let Some((kid, ipn, ik)) = igtk {
        plain.extend_from_slice(&igtk_kde(kid, &ipn, &ik));
    }
    let mut padded = crypto::pad_key_data(plain);
    let keydata = crypto::aes_wrap(kek, &padded);
    padded.zeroize();
    let ki = KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_ack: true,
        install: false,
        key_type: false, // group key
        key_descriptor_type_version: mic.version(),
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 16, replay, &zero_nonce, &[0u8; 16], &keydata);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 16, replay, &zero_nonce, &mic, &keydata);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Group Key Handshake message 1 for an MLD station. The reference AP uses the MLO
/// group-key KDEs for every negotiated link during a rekey; legacy GTK/IGTK
/// KDEs are not valid substitutes for an MLD peer.
#[allow(clippy::too_many_arguments)]
pub fn build_group_key_msg1_mld(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    kck: &[u8],
    kek: &[u8],
    link_ids: &[u8],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    replay: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    let mut plain = Vec::new();
    for link_id in link_ids {
        plain.extend_from_slice(&mlo_gtk_kde(*link_id, gtk_key_id, gtk));
    }
    if let Some((key_id, ipn, ik)) = igtk {
        for link_id in link_ids {
            plain.extend_from_slice(&mlo_igtk_kde(*link_id, key_id, &ipn, &ik));
        }
    }
    if let Some((key_id, ipn, bk)) = bigtk {
        for link_id in link_ids {
            plain.extend_from_slice(&mlo_bigtk_kde(*link_id, key_id, &ipn, &bk));
        }
    }
    let mut padded = crypto::pad_key_data(plain);
    let keydata = crypto::aes_wrap(kek, &padded);
    padded.zeroize();
    let ki = KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_ack: true,
        install: false,
        key_type: false,
        key_descriptor_type_version: mic.version(),
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 16, replay, &zero_nonce, &[0u8; 16], &keydata);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 16, replay, &zero_nonce, &mic, &keydata);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Group Key Handshake message 2 (STA -> AP): acknowledges the new GTK.
pub fn build_group_key_msg2(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    kck: &[u8],
    replay: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    let ki = KeyInfo {
        secure: true,
        has_key_mic: true,
        key_type: false, // group key
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    let zero_nonce = [0u8; 32];
    let body0 = build_eapol_key_body(ki, 0, replay, &zero_nonce, &[0u8; 16], &[]);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 0, replay, &zero_nonce, &mic, &[]);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// Build a BIP-protected, group-addressed Deauthentication frame (PMF). The
/// management body is `reason`, with a trailing Management MIC Element.
pub fn build_group_deauth_bip(
    bssid: &[u8; 6],
    igtk: &[u8; 16],
    key_id: u16,
    ipn: &[u8; 6],
    reason: u16,
    sc: u16,
) -> Vec<u8> {
    let bcast = [0xffu8; 6];
    let hdr = dot11_header(TYPE_MGMT, SUBTYPE_DEAUTH, 0, &bcast, bssid, bssid, sc);
    let (fc0, fc1) = (hdr[0], hdr[1]);
    let body = bip_protect(
        igtk,
        key_id,
        ipn,
        fc0,
        fc1,
        &bcast,
        bssid,
        bssid,
        &reason.to_le_bytes(),
    );
    let mut frame = hdr;
    frame.extend_from_slice(&body);
    frame
}
