//! EAPOL-Key encoding and the pairwise four-way handshake.

use crate::auth::crypto;
use crate::frames::*;
use crate::structures::security::{KeyInfo, KeyMic};
use zeroize::Zeroize;

pub fn build_eapol_key_body(
    key_info: KeyInfo,
    key_length: u16,
    key_replay_counter: u64,
    key_nonce: &[u8; 32],
    key_mic: &[u8; 16],
    key_data: &[u8],
) -> Vec<u8> {
    build_eapol_key_body_with_rsc(
        key_info,
        key_length,
        key_replay_counter,
        key_nonce,
        0,
        key_mic,
        key_data,
    )
}

/// Build an EAPOL-Key body with an explicit receive sequence counter.
///
/// `key_rsc` is the highest 48-bit group packet number already transmitted
/// under the GTK carried by this key message. A joining station seeds its group
/// replay window from this authenticated value.
pub fn build_eapol_key_body_with_rsc(
    key_info: KeyInfo,
    key_length: u16,
    key_replay_counter: u64,
    key_nonce: &[u8; 32],
    key_rsc: u64,
    key_mic: &[u8; 16],
    key_data: &[u8],
) -> Vec<u8> {
    debug_assert!(key_rsc <= 0x0000_ffff_ffff_ffff);
    let mut v = Vec::new();
    v.push(0x02); // key_descriptor_type = RSN
    v.extend_from_slice(&key_info.to_u16().to_be_bytes());
    v.extend_from_slice(&key_length.to_be_bytes());
    v.extend_from_slice(&key_replay_counter.to_be_bytes());
    v.extend_from_slice(key_nonce);
    v.extend_from_slice(&[0u8; 16]); // key_iv
    v.extend_from_slice(&key_rsc.to_le_bytes()); // key_rsc: PN0..PN5, then zero
    v.extend_from_slice(&[0u8; 8]); // key_id
    v.extend_from_slice(key_mic);
    v.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    v.extend_from_slice(key_data);
    v
}

/// Wrap an EAPOL-Key body in the EAPOL header (version 802.1X-2004, type Key).
pub(crate) fn eapol_wrap(body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + body.len());
    v.push(0x02); // version 802.1X-2004
    v.push(0x03); // type EAPOL-Key
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

pub(crate) fn eapol_data_header(bssid: &[u8; 6], sta: &[u8; 6], sc: u16) -> Vec<u8> {
    // Data frame, subtype 0, from-DS, addr1=sta addr2=bssid addr3=bssid
    let mut v = dot11_header(TYPE_DATA, 0, FC_FROMDS, sta, bssid, bssid, sc);
    v.extend_from_slice(&llc_snap(ETHERTYPE_EAPOL));
    v
}

pub(crate) fn eapol_data_header_tods(bssid: &[u8; 6], sta: &[u8; 6], sc: u16) -> Vec<u8> {
    // Data frame, subtype 0, to-DS, addr1=bssid addr2=sta addr3=bssid
    let mut v = dot11_header(TYPE_DATA, 0, FC_TODS, bssid, sta, bssid, sc);
    v.extend_from_slice(&llc_snap(ETHERTYPE_EAPOL));
    v
}

// ---------------------------------------------------------------------------
// Station-side management & EAPOL frames (uplink / to-DS)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // Parameters map directly to EAPOL-Key fields.
pub fn build_eapol_m2(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    snonce: &[u8; 32],
    kck: &[u8],
    supp_rsn: &[u8],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    oci: Option<(u8, u8)>,
) -> Vec<u8> {
    let ki = KeyInfo {
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    // m2's key data echoes the exact RSN(E + RSNXE) the STA sent in its
    // (re)association request; an AP rejects a mismatch (e.g. SAE expects the
    // SAE RSN, not WPA2-PSK).
    let mut key_data = supp_rsn.to_vec();
    if let Some((oc, ch)) = oci {
        key_data.extend_from_slice(&oci_kde(oc, ch)); // OCV
    }
    let body0 = build_eapol_key_body(ki, 0, replay_counter, snonce, &[0u8; 16], &key_data);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 0, replay_counter, snonce, &mic, &key_data);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// EAPOL message 4 (STA -> AP): the handshake ack, MIC'd with the KCK.
pub fn build_eapol_m4(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    kck: &[u8],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    build_eapol_m4_mld(bssid, sta, kck, replay_counter, sc, mic, None)
}

/// EAPOL message 4 with an optional STA MLD MAC address (802.11be).
///
/// For an MLD association the AP requires m4 to carry the STA's MLD MAC in a
/// MAC Address KDE (00-0F-AC:3) — the same KDE m2 carries — otherwise it rejects
/// the handshake with "Mismatching or missing MLD address in EAPOL-Key msg 4/4"
/// and never authorizes the port, so all uplink data is dropped as "not
/// associated". `None` keeps the legacy empty-key-data m4 for non-MLD links.
pub fn build_eapol_m4_mld(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    kck: &[u8],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    mld_mac: Option<&[u8; 6]>,
) -> Vec<u8> {
    let ki = KeyInfo {
        // The Secure bit MUST be set in message 4 (it is clear in message 2):
        // reference AP's MLD 4-way uses it to tell m4 from m2, and without it treats
        // our m4 as a stray m2 ("invalid state - dropped") and never finishes.
        secure: true,
        has_key_mic: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    let zero_nonce = [0u8; 32];
    let key_data: Vec<u8> = match mld_mac {
        Some(mld) => {
            let mut kd = vec![0xdd, 0x0a, 0x00, 0x0f, 0xac, 0x03];
            kd.extend_from_slice(mld);
            kd
        }
        None => Vec::new(),
    };
    let body0 = build_eapol_key_body(ki, 0, replay_counter, &zero_nonce, &[0u8; 16], &key_data);
    let mic = mic.compute(kck, &eapol_wrap(&body0));
    let body = build_eapol_key_body(ki, 0, replay_counter, &zero_nonce, &mic, &key_data);
    let mut frame = eapol_data_header_tods(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// EAPOL message 1 of the four-way handshake.
pub fn build_eapol_m1(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    build_eapol_m1_for_key_length(bssid, sta, anonce, replay_counter, sc, mic, 16)
}

/// EAPOL message 1 with the negotiated pairwise temporal-key length.
pub fn build_eapol_m1_for_key_length(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    key_length: u16,
) -> Vec<u8> {
    build_eapol_m1_with_key_data(bssid, sta, anonce, replay_counter, sc, mic, key_length, &[])
}

/// EAPOL message 1 for an MLD association: carries the AP MLD MAC Address KDE
/// (00-0F-AC:3), matching reference AP's MLD 4-way framing.
pub fn build_eapol_m1_mld(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    ap_mld_mac: &[u8; 6],
) -> Vec<u8> {
    build_eapol_m1_with_key_data(
        bssid,
        sta,
        anonce,
        replay_counter,
        sc,
        mic,
        16,
        &mac_addr_kde(ap_mld_mac),
    )
}

#[allow(clippy::too_many_arguments)] // Parameters map directly to EAPOL-Key fields.
fn build_eapol_m1_with_key_data(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    key_length: u16,
    key_data: &[u8],
) -> Vec<u8> {
    let ki = KeyInfo {
        key_ack: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
        ..Default::default()
    };
    let body = build_eapol_key_body(ki, key_length, replay_counter, anonce, &[0u8; 16], key_data);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// MAC Address KDE (00-0F-AC:3), used by 802.11be MLD EAPOL-Key messages to
/// carry the AP or STA MLD MAC address.
#[allow(clippy::too_many_arguments)] // Parameters map directly to EAPOL-Key fields/KDEs.
pub fn build_eapol_m3(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_rsn: &[u8],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    build_eapol_m3_for_key_length(
        bssid,
        sta,
        anonce,
        kck,
        kek,
        ap_rsn,
        gtk_key_id,
        gtk,
        igtk,
        bigtk,
        oci,
        replay_counter,
        sc,
        mic,
        16,
    )
}

/// EAPOL message 3 with the negotiated pairwise temporal-key length.
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3_for_key_length(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_rsn: &[u8],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    key_length: u16,
) -> Vec<u8> {
    build_eapol_m3_for_key_length_with_rsc(
        bssid,
        sta,
        anonce,
        kck,
        kek,
        ap_rsn,
        gtk_key_id,
        gtk,
        igtk,
        bigtk,
        oci,
        0,
        replay_counter,
        sc,
        mic,
        key_length,
    )
}

/// EAPOL message 3 with explicit pairwise key length and group Key RSC.
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3_for_key_length_with_rsc(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_rsn: &[u8],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    key_rsc: u64,
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
    key_length: u16,
) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.extend_from_slice(ap_rsn);
    plain.extend_from_slice(&gtk_kde(gtk_key_id, gtk));
    if let Some((key_id, ipn, ik)) = igtk {
        plain.extend_from_slice(&igtk_kde(key_id, &ipn, &ik));
    }
    if let Some((key_id, ipn, bk)) = bigtk {
        plain.extend_from_slice(&bigtk_kde(key_id, &ipn, &bk));
    }
    if let Some((oc, ch)) = oci {
        plain.extend_from_slice(&oci_kde(oc, ch)); // OCV
    }
    if crate::util::netlink_debug_enabled() {
        eprintln!(
            "AP: m3 plaintext KDEs ({}B)={}",
            plain.len(),
            plain.iter().map(|x| format!("{x:02x}")).collect::<String>()
        );
    }
    let mut padded = crypto::pad_key_data(plain);
    let keydata = crypto::aes_wrap(kek, &padded);
    padded.zeroize();

    let ki = KeyInfo {
        encrypted_key_data: true,
        secure: true,
        has_key_mic: true,
        key_ack: true,
        install: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
    };

    // Build once with a zero MIC, compute the MIC over the EAPOL frame, rebuild.
    let body0 = build_eapol_key_body_with_rsc(
        ki,
        key_length,
        replay_counter,
        anonce,
        key_rsc,
        &[0u8; 16],
        &keydata,
    );
    let mic = mic.compute(kck, &eapol_wrap(&body0));

    let body = build_eapol_key_body_with_rsc(
        ki,
        key_length,
        replay_counter,
        anonce,
        key_rsc,
        &mic,
        &keydata,
    );
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}

/// EAPOL message 3 for an MLD station with one affiliated link.
///
/// Kept as a convenience wrapper for tests and single-link MLD peers. Real
/// multi-link associations use [`build_eapol_m3_mld_links`] so every negotiated
/// link receives its MLO Link and group-key KDEs, matching reference AP.
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3_mld(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_mld_mac: &[u8; 6],
    link_id: u8,
    link_mac: &[u8; 6],
    link_rsne: &[u8],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    build_eapol_m3_mld_links(
        bssid,
        sta,
        anonce,
        kck,
        kek,
        ap_mld_mac,
        &[(link_id, *link_mac, link_rsne)],
        gtk_key_id,
        gtk,
        igtk,
        bigtk,
        oci,
        replay_counter,
        sc,
        mic,
    )
}

/// EAPOL message 3 for an MLD station. The encrypted key data follows reference AP's
/// AP-MLD layout: AP MLD MAC, an MLO Link KDE for every negotiated link, then
/// MLO GTK/IGTK/BIGTK KDEs for every such link. Supplying only the association
/// link leaves partner links without their group-key context and can keep an
/// EMLSR client pinned to that association link.
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3_mld_links(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_mld_mac: &[u8; 6],
    links: &[(u8, [u8; 6], &[u8])],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    build_eapol_m3_mld_links_with_rsc(
        bssid,
        sta,
        anonce,
        kck,
        kek,
        ap_mld_mac,
        links,
        gtk_key_id,
        gtk,
        igtk,
        bigtk,
        oci,
        0,
        replay_counter,
        sc,
        mic,
    )
}

/// MLD EAPOL message 3 with an explicit group Key RSC/per-link GTK PN.
#[allow(clippy::too_many_arguments)]
pub fn build_eapol_m3_mld_links_with_rsc(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    anonce: &[u8; 32],
    kck: &[u8],
    kek: &[u8],
    ap_mld_mac: &[u8; 6],
    links: &[(u8, [u8; 6], &[u8])],
    gtk_key_id: u8,
    gtk: &[u8],
    igtk: Option<(u16, [u8; 6], [u8; 16])>,
    bigtk: Option<(u16, [u8; 6], [u8; 16])>,
    oci: Option<(u8, u8)>,
    key_rsc: u64,
    replay_counter: u64,
    sc: u16,
    mic: KeyMic,
) -> Vec<u8> {
    let mut plain = Vec::new();
    if let Some((oc, ch)) = oci {
        plain.extend_from_slice(&oci_kde(oc, ch));
    }
    plain.extend_from_slice(&mac_addr_kde(ap_mld_mac));
    for (link_id, link_mac, link_rsne) in links {
        plain.extend_from_slice(&mlo_link_kde(*link_id, link_mac, link_rsne));
    }
    let rsc_bytes = key_rsc.to_le_bytes();
    let mut group_pn = [0u8; 6];
    group_pn.copy_from_slice(&rsc_bytes[..6]);
    for (link_id, _, _) in links {
        plain.extend_from_slice(&mlo_gtk_kde_with_pn(*link_id, gtk_key_id, &group_pn, gtk));
    }
    if let Some((key_id, ipn, ik)) = igtk {
        for (link_id, _, _) in links {
            plain.extend_from_slice(&mlo_igtk_kde(*link_id, key_id, &ipn, &ik));
        }
    }
    if let Some((key_id, ipn, bk)) = bigtk {
        for (link_id, _, _) in links {
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
        install: true,
        key_type: true,
        key_descriptor_type_version: mic.version(),
    };

    let body0 = build_eapol_key_body_with_rsc(
        ki,
        16,
        replay_counter,
        anonce,
        key_rsc,
        &[0u8; 16],
        &keydata,
    );
    let mic = mic.compute(kck, &eapol_wrap(&body0));

    let body =
        build_eapol_key_body_with_rsc(ki, 16, replay_counter, anonce, key_rsc, &mic, &keydata);
    let mut frame = eapol_data_header(bssid, sta, sc);
    frame.extend_from_slice(&eapol_wrap(&body));
    frame
}
