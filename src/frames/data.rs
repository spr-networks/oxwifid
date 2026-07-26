//! 802.11 data protection, CCMP, and protected management payloads.

use crate::auth::crypto;
use crate::frames::*;
use crate::structures::common::Dot11;
use crate::structures::security::DataCipher;

pub fn pn2bin(pn: u64) -> [u8; 6] {
    let b = pn.to_be_bytes(); // 8 bytes
    let mut out = [0u8; 6];
    out.copy_from_slice(&b[2..]);
    out
}

/// Little-endian per-octet PN, as stored in the CCMP header (`pn2bytes`).
pub fn pn2bytes(pn: u64) -> [u8; 6] {
    let mut out = [0u8; 6];
    let mut v = pn;
    for o in out.iter_mut() {
        *o = (v & 0xFF) as u8;
        v >>= 8;
    }
    out
}

/// CCM nonce = priority(1) || addr(6) || PN(6, big-endian).
pub fn ccmp_get_nonce(priority: u8, addr: &[u8; 6], pn: u64) -> [u8; 13] {
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(addr);
    nonce[7..13].copy_from_slice(&pn2bin(pn));
    nonce
}

/// GCM nonce = transmitter address(6) || PN(6, big-endian).
pub fn gcmp_get_nonce(addr: &[u8; 6], pn: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..6].copy_from_slice(addr);
    nonce[6..].copy_from_slice(&pn2bin(pn));
    nonce
}

/// CCM additional authenticated data, mirroring `ccmp_get_aad`.
pub fn ccmp_get_aad(
    fc0: u8,
    fc1: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sc: u16,
    qos_tid: Option<u16>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(22);
    // FC octet 0: per IEEE 802.11 / mac80211, the Subtype bits (b4-b6) are masked
    // to 0 for Data frames only; for Management frames the full octet (incl.
    // subtype) is covered, so Deauth vs Disassoc vs Action can't be swapped.
    let is_data = (fc0 >> 2) & 0x03 == TYPE_DATA;
    aad.push(if is_data { fc0 & 0x8F } else { fc0 });
    aad.push(fc1 & 0xC7);
    aad.extend_from_slice(a1);
    aad.extend_from_slice(a2);
    aad.extend_from_slice(a3);
    aad.extend_from_slice(&(sc & 0xF).to_le_bytes());
    if let Some(tid) = qos_tid {
        aad.extend_from_slice(&tid.to_le_bytes());
    }
    aad
}

/// CCMP header: PN0 PN1 rsvd keyflags PN2 PN3 PN4 PN5.
fn ccmp_header(pn: u64, key_id: u8) -> [u8; 8] {
    let p = pn2bytes(pn);
    let mut h = [0u8; 8];
    h[0] = p[0];
    h[1] = p[1];
    h[2] = 0x00; // reserved
    h[3] = (key_id << 6) | 0x20; // ext_iv = 1
    h[4] = p[2];
    h[5] = p[3];
    h[6] = p[4];
    h[7] = p[5];
    h
}

fn encrypt_data_payload(
    cipher: DataCipher,
    tk: &[u8],
    priority: u8,
    transmitter: &[u8; 6],
    pn: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    if tk.len() != cipher.key_len() {
        return None;
    }
    match cipher {
        DataCipher::Ccmp128 | DataCipher::Ccmp256 => {
            let nonce = ccmp_get_nonce(priority, transmitter, pn);
            let tag_len = if cipher == DataCipher::Ccmp128 { 8 } else { 16 };
            Some(crypto::run_ccmp_encrypt_with_tag(
                tk, &nonce, aad, plaintext, tag_len,
            ))
        }
        DataCipher::Gcmp128 | DataCipher::Gcmp256 => {
            let nonce = gcmp_get_nonce(transmitter, pn);
            crypto::run_gcmp_encrypt(tk, &nonce, aad, plaintext)
                .map(|(encrypted, tag)| (encrypted, tag.to_vec()))
        }
    }
}

struct DataDecryptParams<'a> {
    cipher: DataCipher,
    tk: &'a [u8],
    priority: u8,
    transmitter: &'a [u8; 6],
    pn: u64,
    aad: &'a [u8],
    ciphertext: &'a [u8],
    tag: &'a [u8],
}

fn decrypt_data_payload(params: DataDecryptParams<'_>) -> Option<Vec<u8>> {
    let DataDecryptParams {
        cipher,
        tk,
        priority,
        transmitter,
        pn,
        aad,
        ciphertext,
        tag,
    } = params;
    if tk.len() != cipher.key_len() {
        return None;
    }
    match cipher {
        DataCipher::Ccmp128 | DataCipher::Ccmp256 => {
            let nonce = ccmp_get_nonce(priority, transmitter, pn);
            let tag_len = if cipher == DataCipher::Ccmp128 { 8 } else { 16 };
            let (plaintext, valid) =
                crypto::run_ccmp_decrypt_with_tag(tk, &nonce, aad, ciphertext, tag, tag_len);
            valid.then_some(plaintext)
        }
        DataCipher::Gcmp128 | DataCipher::Gcmp256 => {
            let nonce = gcmp_get_nonce(transmitter, pn);
            crypto::run_gcmp_decrypt(tk, &nonce, aad, ciphertext, tag)
        }
    }
}

/// Build an encrypted CCMP data frame carrying an L3 payload.
///
/// `flags` selects direction (`FC_FROMDS|FC_PROTECTED` downlink, etc.). The
/// inner payload is the bytes *after* the Ethernet header; `ethertype` is the
/// SNAP code. Mirrors `encrypt_ccmp`.
#[allow(clippy::too_many_arguments)]
pub fn build_ccmp_data(
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    flags: u8,
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    ethertype: u16,
    inner_payload: &[u8],
    qos_tid: Option<u8>,
) -> Vec<u8> {
    // Non-MLD: the CCMP security addresses are the MAC-header addresses.
    build_ccmp_data_sec(
        a1,
        a2,
        a3,
        a1,
        a2,
        a3,
        flags,
        sc,
        pn,
        key_id,
        tk,
        ethertype,
        inner_payload,
        qos_tid,
    )
}

/// Like [`build_ccmp_data`], but with the CCMP *security* addresses
/// (`sec_a1`/`sec_a2`/`sec_a3` — used for the nonce A2 and the AAD) decoupled
/// from the MAC-header addresses (`a1`/`a2`/`a3`).
///
/// This is the 802.11be (MLO) rule: a data frame on a link carries the **link
/// addresses** in the MAC header so it can traverse that physical link, but the
/// CCMP nonce and AAD — and hence the AP's STA lookup — hinge on the **MLD
/// addresses**, consistent with the PTK derivation (which also uses the MLD
/// addresses). For a non-MLD association the two sets are identical.
#[allow(clippy::too_many_arguments)]
pub fn build_ccmp_data_sec(
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sec_a1: &[u8; 6],
    sec_a2: &[u8; 6],
    sec_a3: &[u8; 6],
    flags: u8,
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    ethertype: u16,
    inner_payload: &[u8],
    qos_tid: Option<u8>,
) -> Vec<u8> {
    build_protected_data_sec(
        DataCipher::Ccmp128,
        a1,
        a2,
        a3,
        sec_a1,
        sec_a2,
        sec_a3,
        flags,
        sc,
        pn,
        key_id,
        tk,
        ethertype,
        inner_payload,
        qos_tid,
    )
}

/// Build a CCMP/GCMP-protected data frame with explicit security addresses.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_data_sec(
    data_cipher: DataCipher,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sec_a1: &[u8; 6],
    sec_a2: &[u8; 6],
    sec_a3: &[u8; 6],
    flags: u8,
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    ethertype: u16,
    inner_payload: &[u8],
    qos_tid: Option<u8>,
) -> Vec<u8> {
    // QoS Data (WMM) when a TID is given, else a plain Data frame.
    let subtype = if qos_tid.is_some() {
        SUBTYPE_QOS_DATA
    } else {
        0
    };
    let mut frame = dot11_header(TYPE_DATA, subtype, flags, a1, a2, a3, sc);
    if let Some(tid) = qos_tid {
        // QoS Control: TID (bits 0-3), normal ack, A-MSDU bit clear.
        frame.push(tid & 0x0F);
        frame.push(0x00);
    }

    let fc_bytes = (frame[0], frame[1]);
    let prio = qos_tid.unwrap_or(0);
    // CCMP nonce A2 and AAD use the *security* (MLD) addresses, not the
    // link addresses carried in the MAC header.
    let aad = ccmp_get_aad(
        fc_bytes.0,
        fc_bytes.1,
        sec_a1,
        sec_a2,
        sec_a3,
        sc,
        qos_tid.map(|t| (t & 0x0F) as u16),
    );

    let mut plaintext = Vec::with_capacity(8 + inner_payload.len());
    plaintext.extend_from_slice(&llc_snap(ethertype));
    plaintext.extend_from_slice(inner_payload);

    let (encrypted, tag) =
        encrypt_data_payload(data_cipher, tk, prio, sec_a2, pn, &aad, &plaintext)
            .expect("validated pairwise cipher/key length");

    frame.extend_from_slice(&ccmp_header(pn, key_id));
    frame.extend_from_slice(&encrypted);
    frame.extend_from_slice(&tag);
    frame
}

/// Scan EAPOL key data for the IGTK KDE (00-0F-AC type 9) and extract
/// `(key_id, IPN, IGTK)`.
pub fn decrypt_ccmp(frame: &Dot11, tk: &[u8], from_ap: bool) -> Option<Vec<u8>> {
    decrypt_ccmp_sec(frame, tk, from_ap, None)
}

/// Like [`decrypt_ccmp`], but with optional 802.11be (MLO) *security* addresses.
///
/// `sec_addrs = Some((sec_a1, sec_a2, sec_a3))` supplies the MLD addresses used
/// for the CCMP nonce A2 and the AAD, while the MAC header keeps its link
/// addresses (mirroring the AP/mac80211, which CCMP-protects MLD downlink with
/// the MLD addresses even though the frame carries link addresses over the air).
/// `None` falls back to the MAC-header addresses (non-MLD).
pub fn decrypt_ccmp_sec(
    frame: &Dot11,
    tk: &[u8],
    from_ap: bool,
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Option<Vec<u8>> {
    decrypt_protected_data_sec(DataCipher::Ccmp128, frame, tk, from_ap, sec_addrs)
}

/// Decrypt a CCMP/GCMP-protected data frame.
pub fn decrypt_protected_data_sec(
    data_cipher: DataCipher,
    frame: &Dot11,
    tk: &[u8],
    from_ap: bool,
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Option<Vec<u8>> {
    let pn = frame.ccmp_pn()?;
    let qos_tid = frame.qos.map(|_| frame.priority());
    let (sa1, sa2, sa3) = sec_addrs.unwrap_or((frame.addr1, frame.addr2, frame.addr3));
    let aad = ccmp_get_aad(frame.fc0, frame.fc1, &sa1, &sa2, &sa3, frame.sc, qos_tid);

    let data = frame.ccmp_data()?;
    let tag_len = match data_cipher {
        DataCipher::Ccmp128 => 8,
        _ => 16,
    };
    if data.len() < tag_len {
        return None;
    }
    let (payload, tag) = data.split_at(data.len() - tag_len);
    let plaintext = decrypt_data_payload(DataDecryptParams {
        cipher: data_cipher,
        tk,
        priority: frame.priority() as u8,
        transmitter: &sa2,
        pn,
        aad: &aad,
        ciphertext: payload,
        tag,
    })?;
    if plaintext.len() < 8 {
        return None;
    }
    // Require an RFC 1042 LLC/SNAP header (AA-AA-03-00-00-00) before trusting
    // the EtherType. Without this, a decrypted payload that isn't SNAP-framed
    // (e.g. a crafted A-MSDU subframe list) would be decapsulated with an
    // attacker-chosen EtherType/destination — the A-MSDU/aggregation FragAttack.
    if plaintext[..6] != [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00] {
        return None;
    }
    // LLC/SNAP: skip 6 bytes, ethertype at [6..8], L3 follows
    let ethertype = [plaintext[6], plaintext[7]];
    let l3 = &plaintext[8..];

    let (da, sa) = if from_ap {
        (frame.addr1, frame.addr3)
    } else {
        (frame.addr3, frame.addr2)
    };

    let mut eth = Vec::with_capacity(14 + l3.len());
    eth.extend_from_slice(&da);
    eth.extend_from_slice(&sa);
    eth.extend_from_slice(&ethertype);
    eth.extend_from_slice(l3);
    Some(eth)
}

// ---------------------------------------------------------------------------
// Protected (CCMP) management frames — robust unicast mgmt under PMF
// ---------------------------------------------------------------------------

/// CCMP-encrypt a management frame body (no LLC/SNAP — management frames carry
/// their fixed fields directly). Used to protect robust unicast management
/// frames (Deauth/Disassoc/Action) under PMF.
#[allow(clippy::too_many_arguments)]
pub fn build_ccmp_mgmt(
    subtype: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    body: &[u8],
) -> Vec<u8> {
    build_ccmp_mgmt_sec(subtype, a1, a2, a3, None, 0, sc, pn, key_id, tk, body)
}

/// Like [`build_ccmp_mgmt`], but allows 802.11be MLD security addresses to be
/// supplied separately from the link-addressed MAC header. `extra_flags` is for
/// DS bits such as STA->AP SA Query; the Protected bit is always set here.
#[allow(clippy::too_many_arguments)]
pub fn build_ccmp_mgmt_sec(
    subtype: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
    extra_flags: u8,
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    body: &[u8],
) -> Vec<u8> {
    build_protected_mgmt_sec(
        DataCipher::Ccmp128,
        subtype,
        a1,
        a2,
        a3,
        sec_addrs,
        extra_flags,
        sc,
        pn,
        key_id,
        tk,
        body,
    )
}

/// Build a robust unicast management frame using the negotiated pairwise suite.
#[allow(clippy::too_many_arguments)]
pub fn build_protected_mgmt_sec(
    data_cipher: DataCipher,
    subtype: u8,
    a1: &[u8; 6],
    a2: &[u8; 6],
    a3: &[u8; 6],
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
    extra_flags: u8,
    sc: u16,
    pn: u64,
    key_id: u8,
    tk: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let mut frame = dot11_header(
        TYPE_MGMT,
        subtype,
        extra_flags | FC_PROTECTED,
        a1,
        a2,
        a3,
        sc,
    );
    let (fc0, fc1) = (frame[0], frame[1]);
    let (sa1, sa2, sa3) = sec_addrs.unwrap_or((*a1, *a2, *a3));
    let aad = ccmp_get_aad(fc0, fc1, &sa1, &sa2, &sa3, sc, None);
    let (encrypted, tag) = encrypt_data_payload(data_cipher, tk, 0, &sa2, pn, &aad, body)
        .expect("validated pairwise cipher/key length");
    frame.extend_from_slice(&ccmp_header(pn, key_id));
    frame.extend_from_slice(&encrypted);
    frame.extend_from_slice(&tag);
    frame
}

/// Decrypt a CCMP-protected management frame, returning the plaintext body, or
/// `None` if the MIC does not verify.
pub fn decrypt_ccmp_mgmt(frame: &Dot11, tk: &[u8]) -> Option<Vec<u8>> {
    decrypt_ccmp_mgmt_sec(frame, tk, None)
}

/// Like [`decrypt_ccmp_mgmt`], but verifies with optional MLD security addresses
/// instead of the link addresses carried in the MAC header.
pub fn decrypt_ccmp_mgmt_sec(
    frame: &Dot11,
    tk: &[u8],
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Option<Vec<u8>> {
    decrypt_protected_mgmt_sec(DataCipher::Ccmp128, frame, tk, sec_addrs)
}

pub fn decrypt_protected_mgmt_sec(
    data_cipher: DataCipher,
    frame: &Dot11,
    tk: &[u8],
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Option<Vec<u8>> {
    let pn = frame.ccmp_pn()?;
    let (sa1, sa2, sa3) = sec_addrs.unwrap_or((frame.addr1, frame.addr2, frame.addr3));
    let aad = ccmp_get_aad(
        frame.fc0,
        frame.fc1,
        &sa1,
        &sa2,
        &sa3,
        frame.sc,
        frame.qos.map(|_| frame.priority()),
    );
    let data = frame.ccmp_data()?;
    let tag_len = match data_cipher {
        DataCipher::Ccmp128 => 8,
        _ => 16,
    };
    if data.len() < tag_len {
        return None;
    }
    let (payload, tag) = data.split_at(data.len() - tag_len);
    decrypt_data_payload(DataDecryptParams {
        cipher: data_cipher,
        tk,
        priority: frame.priority() as u8,
        transmitter: &sa2,
        pn,
        aad: &aad,
        ciphertext: payload,
        tag,
    })
}

/// Build a CCMP-protected unicast Deauthentication frame (AP -> STA under PMF).
pub fn build_protected_deauth(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    reason: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
) -> Vec<u8> {
    build_protected_deauth_sec(bssid, sta, reason, sc, pn, tk, None)
}

pub fn build_protected_deauth_sec(
    bssid: &[u8; 6],
    sta: &[u8; 6],
    reason: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    build_protected_deauth_for_cipher_sec(
        DataCipher::Ccmp128,
        bssid,
        sta,
        reason,
        sc,
        pn,
        tk,
        sec_addrs,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_protected_deauth_for_cipher_sec(
    cipher: DataCipher,
    bssid: &[u8; 6],
    sta: &[u8; 6],
    reason: u16,
    sc: u16,
    pn: u64,
    tk: &[u8],
    sec_addrs: Option<([u8; 6], [u8; 6], [u8; 6])>,
) -> Vec<u8> {
    build_protected_mgmt_sec(
        cipher,
        SUBTYPE_DEAUTH,
        sta,
        bssid,
        bssid,
        sec_addrs,
        0,
        sc,
        pn,
        0,
        tk,
        &reason.to_le_bytes(),
    )
}

// 802.11v WNM and 802.11k Radio Measurement action categories.
