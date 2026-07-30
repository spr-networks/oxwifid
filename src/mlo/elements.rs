//! 802.11be Multi-Link elements and per-link profiles.

use crate::frames::*;
use crate::structures::wifi7::MldLinkProfile;

pub fn tid_to_link_mapping_same_set(link_mask: u16) -> Vec<u8> {
    let mut data = Vec::with_capacity(18);
    data.push(2); // both downlink and uplink
    data.push(0xff); // mappings for TIDs 0..7 are present
    for _ in 0..8 {
        data.extend_from_slice(&link_mask.to_le_bytes());
    }
    ext_ie(109, &data)
}

/// Emit an element (id `id`) whose body may exceed 255 octets, using 802.11
/// element fragmentation: the first element carries length 255, each subsequent
/// Fragment element (id 254) up to 255, and the sequence ends with a fragment of
/// length < 255 (adding a terminating zero-length fragment when the body is an
/// exact multiple of 255). Bodies that fit in one element are emitted unchanged.
pub(crate) fn fragmented_element(id: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + body.len());
    if body.len() <= 255 {
        v.push(id);
        v.push(body.len() as u8);
        v.extend_from_slice(body);
        return v;
    }
    v.push(id);
    v.push(255);
    v.extend_from_slice(&body[..255]);
    let mut rest = &body[255..];
    loop {
        let n = rest.len().min(255);
        v.push(254);
        v.push(n as u8);
        v.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
        if n < 255 {
            break;
        }
        if rest.is_empty() {
            v.push(254);
            v.push(0);
            break;
        }
    }
    v
}

/// HE Capabilities element (ext ID 35): 6 MAC + 11 PHY capability octets and the
/// supported HE-MCS/NSS set. Byte-golden from a `mac80211_hwsim` HE AP beacon.
/// PHY generation advertised in beacons/responses. Cumulative and ordered:
/// `Ht` (802.11n) < `Vht` (ac) < `He` (ax) < `Eht` (be) — `He` emits HT+VHT+HE.
pub fn multi_link_basic(mld_mac: &[u8; 6]) -> Vec<u8> {
    let mut data = Vec::new();
    // Multi-Link Control (2 octets, little-endian): bits 0-2 Type = 0 (Basic),
    // bits 4-15 Presence Bitmap = 0 (only the always-present MLD MAC).
    data.extend_from_slice(&[0x00, 0x00]);
    // Common Info: length (incl. itself) + MLD MAC Address.
    data.push(7);
    data.extend_from_slice(mld_mac);
    ext_ie(107, &data)
}

/// AP-side Basic Multi-Link element (ext 107) for a beacon / probe / assoc
/// response: advertises the AP's MLD MAC address, this link's Link ID, and the
/// BSS Parameters Change Count, marking the BSS as an affiliated AP of an
/// 802.11be MLD. `link_info` is the Link Info field — zero or more Per-STA
/// Profile subelements (one per *other* affiliated link, from [`per_sta_profile`]);
/// pass `&[]` for a beacon that only announces MLD membership + this link's id.
pub fn multi_link_ap_basic(
    mld_mac: &[u8; 6],
    link_id: u8,
    bss_change_count: u8,
    max_simultaneous_links_minus_one: u8,
    link_info: &[u8],
) -> Vec<u8> {
    multi_link_ap_basic_capabilities(
        mld_mac,
        link_id,
        bss_change_count,
        0,
        u16::from(max_simultaneous_links_minus_one.min(0x0f)),
        link_info,
    )
}

/// AP-side Basic Multi-Link element using the EML and MLD capabilities exposed
/// by the driver. reference AP obtains these from the per-interface-type
/// `GET_WIPHY` attributes and advertises them in every affiliated link.
pub fn multi_link_ap_basic_capabilities(
    mld_mac: &[u8; 6],
    link_id: u8,
    bss_change_count: u8,
    eml_capability: u16,
    mld_capability: u16,
    link_info: &[u8],
) -> Vec<u8> {
    let mut data = Vec::new();
    // Multi-Link Control (2 octets, LE): Type = 0 (Basic, bits 0-2). Presence
    // Bitmap occupies bits 4-15: presence bit0 (control bit4) = Link ID Info,
    // bit1 (control bit5) = BSS Parameters Change Count, bit3 (control bit7)
    // = EML Capabilities, bit4 (control bit8) = MLD Capabilities. This is the
    // 0x01b0 common-field shape reference AP emits for an AP MLD.
    let control: u16 = 0x01b0;
    data.extend_from_slice(&control.to_le_bytes());
    // Common Info: Length (incl. itself) + MLD MAC + Link ID Info + BSS Change
    // + EML Capabilities + MLD Capabilities.
    data.push(1 + 6 + 1 + 1 + 2 + 2);
    data.extend_from_slice(mld_mac);
    // Link ID Info: Link ID in bits 0-3.
    data.push(link_id & 0x0f);
    // BSS Parameters Change Count.
    data.push(bss_change_count);
    // EML Capabilities.
    data.extend_from_slice(&eml_capability.to_le_bytes());
    // MLD Capabilities and Operations. Bits 0-3 use N-1 encoding for the
    // maximum number of simultaneously active links.
    data.extend_from_slice(&mld_capability.to_le_bytes());
    // Link Info: Per-STA Profile subelements for the other affiliated links.
    data.extend_from_slice(link_info);
    ext_ie(107, &data)
}

/// Extract the MLD MAC address from a Basic Multi-Link element (ext 107) inside
/// an IE block (e.g. a station's (Re)Assoc Request). The MLD MAC is the first 6
/// octets of the Common Info field (always present in a Basic ML element),
/// immediately after the 2-octet Multi-Link Control and the 1-octet Common Info
/// Length. Returns `None` when there is no (well-formed) Basic ML element.
pub fn parse_mld_mac(ies: &[u8]) -> Option<[u8; 6]> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        // Element 255 (extension), ext id 107 (Multi-Link), Type = Basic (0).
        if ies[i] == 255 && len >= 1 + 2 + 1 + 6 && ies[i + 2] == 107 {
            let body = &ies[i + 3..i + 2 + len];
            // body: Multi-Link Control(2) + Common Info Length(1) + MLD MAC(6)...
            let control_type = u16::from_le_bytes([body[0], body[1]]) & 0x07;
            let common_len = body[2] as usize;
            // Common Info Length includes its own octet, but not the two-octet
            // Multi-Link Control. A Basic MLE always carries the six-octet MLD
            // MAC. Do not promote bytes outside a truncated Common Info field
            // into an authenticated MLD identity.
            if control_type == 0
                && common_len > 6
                && 2usize
                    .checked_add(common_len)
                    .is_some_and(|end| end <= body.len())
            {
                let mut mld = [0u8; 6];
                mld.copy_from_slice(&body[3..9]);
                return Some(mld);
            }
        }
        i += 2 + len;
    }
    None
}

/// Whether an IE block contains a Basic Multi-Link element, including one whose
/// internal Common Info is malformed. This lets an AP distinguish a legacy
/// single-link association (no MLE) from a malformed MLD association that must
/// be rejected.
pub fn has_basic_multi_link_element(ies: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        let Some(end) = i.checked_add(2 + len) else {
            return false;
        };
        if end > ies.len() {
            return false;
        }
        if ies[i] == 255 && len > 2 && ies[i + 2] == 107 {
            let control = u16::from_le_bytes([ies[i + 3], ies[i + 4]]);
            if control & 0x07 == 0 {
                return true;
            }
        }
        i = end;
    }
    false
}

/// Number of Link Info octets carried by the first fragment of a Basic
/// Multi-Link element. This is primarily a beacon-template diagnostic: zero
/// means the element has only Common Info and advertises no partner profiles.
pub fn basic_mle_link_info_len(ies: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] == 255 && len > 1 + 2 && ies[i + 2] == 107 {
            let data = &ies[i + 3..i + 2 + len];
            let common_len = data[2] as usize;
            return Some(data.len().saturating_sub(2 + common_len));
        }
        i += 2 + len;
    }
    None
}

/// Per-STA Profile subelement (subelement id 0) for the Link Info field of a
/// Basic Multi-Link element: carries one affiliated link's Link ID, Complete
/// Profile flag, MAC address, and (optionally) that link's inheritable element
/// body (`inner`). This is how a beacon on one link advertises the parameters of
/// the AP's other link(s) so a client can set up all links from one scan.
pub fn per_sta_profile(link_id: u8, link_mac: &[u8; 6], inner: &[u8]) -> Vec<u8> {
    per_sta_profile_inner(link_id, link_mac, inner, None)
}

/// (Re)Association Response variant of [`per_sta_profile`]: in addition to the
/// beacon timing fields, a per-STA profile in an association response carries a
/// BSS Parameters Change Count (STA Control bit 11 `PRES_BSS_PARAM_COUNT` + one
/// STA Info octet). 
pub fn per_sta_profile_assoc(
    link_id: u8,
    link_mac: &[u8; 6],
    inner: &[u8],
    bss_param_change_count: u8,
) -> Vec<u8> {
    per_sta_profile_inner(link_id, link_mac, inner, Some(bss_param_change_count))
}

fn per_sta_profile_inner(
    link_id: u8,
    link_mac: &[u8; 6],
    inner: &[u8],
    bss_param_change_count: Option<u8>,
) -> Vec<u8> {
    // STA Control (2 octets, LE): bits 0-3 Link ID, bit 4 Complete Profile,
    // bit 5 MAC Address Present, plus Beacon Interval, TSF Offset, and DTIM
    // Info. hostapd includes all four AP-link timing fields; a (Re)Assoc
    // Response additionally sets bit 11 (BSS Parameters Change Count present).
    let mut sta_control: u16 =
        (link_id as u16 & 0x0f) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8);
    if bss_param_change_count.is_some() {
        sta_control |= 1 << 11;
    }
    let mut body = Vec::new();
    body.extend_from_slice(&sta_control.to_le_bytes());
    // STA Info: Length (incl. itself) + MAC Address + Beacon Interval + TSF
    // Offset + DTIM Count/Period (+ BSS Params Change Count for assoc). RustAP
    // uses a 100-TU beacon and DTIM period 2.
    let info_len = 1 + 6 + 2 + 8 + 2 + bss_param_change_count.map_or(0, |_| 1);
    body.push(info_len as u8);
    body.extend_from_slice(link_mac);
    body.extend_from_slice(&BEACON_INTERVAL_TU.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());
    body.extend_from_slice(&[0, 2]);
    if let Some(count) = bss_param_change_count {
        body.push(count);
    }
    // STA Profile: the link's link-specific (inheritable) element bytes.
    body.extend_from_slice(inner);
    // Per-STA Profile subelement (id 0), fragmented (id 254 fragments) when the
    // profile body exceeds 255 octets.
    fragmented_element(0, &body)
}

/// STA Profile body for an affiliated AP link inside an AP Basic Multi-Link
/// element. This is the link's fixed Capability Info followed by the same
/// response IEs a client would learn from that link directly, without nesting
/// another Multi-Link element.
#[allow(clippy::too_many_arguments)]
pub fn ap_mld_profile_inner(
    ssid: &[u8],
    channel: u8,
    country: &[u8; 2],
    width: u16,
    band6: bool,
    wmm: bool,
    phy: PhyMode,
    security: SecurityMode,
    punct: u16,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ap_capability(channel, band6));
    let tail = security_tail(security);
    let ies = resp_ies(ssid, channel, country, width, band6, wmm, phy, &tail, punct);
    append_mld_profile_ies(&mut v, &ies);
    v
}

fn append_mld_profile_ies(v: &mut Vec<u8>, ies: &[u8]) {
    // IEEE 802.11be inheritance rules forbid SSID in a transmitted AP's
    // Per-STA Profile. reference AP's is_restricted_eid_in_sta_profile() also drops
    // TIM, BSS Max Idle, Multiple BSSID, RNR, and Neighbor Report; resp_ies()
    // does not contain those beacon-only elements, so SSID is the only one to
    // remove here.
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] != 0 {
            v.extend_from_slice(&ies[i..i + 2 + len]);
        }
        i += 2 + len;
    }
}

/// The (base element IDs, extension element IDs) present in an IE block, in
/// order. Used to diff a reporting link against a reported partner link for the
/// Non-Inheritance element.
pub fn element_id_sets(ies: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut base = Vec::new();
    let mut ext = Vec::new();
    let mut i = 0;
    while i + 2 <= ies.len() {
        let id = ies[i];
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if id == 255 {
            if len >= 1 {
                ext.push(ies[i + 2]);
            }
        } else {
            base.push(id);
        }
        i += 2 + len;
    }
    (base, ext)
}

/// Non-Inheritance element (element 255, ext id 56) for an MLO Per-STA Profile.
///
/// A non-AP MLD interprets a reported link's Per-STA Profile relative to the
/// reporting link (the frame's main body): any element present in the reporting
/// link but absent from the profile is *inherited*. When a 5 GHz association
/// link reports a 2.4 GHz partner, band-specific elements (VHT Capabilities /
/// Operation) would be wrongly inherited onto the 2.4 GHz link — mac80211
/// rejects the association with "VHT capabilities mismatch". This element lists
/// the reporting-link element IDs (base + extension) that the reported link does
/// NOT have, so they are not inherited. Empty when the reported link is a
/// superset (e.g. a 5 GHz partner of a 2.4 GHz association link).
pub fn non_inheritance_element(reporting: (&[u8], &[u8]), reported: (&[u8], &[u8])) -> Vec<u8> {
    let base: Vec<u8> = reporting
        .0
        .iter()
        .copied()
        .filter(|id| !reported.0.contains(id))
        .collect();
    let ext: Vec<u8> = reporting
        .1
        .iter()
        .copied()
        .filter(|id| !reported.1.contains(id))
        .collect();
    if base.is_empty() && ext.is_empty() {
        return Vec::new();
    }
    let mut body = Vec::with_capacity(3 + base.len() + ext.len());
    body.push(56); // WLAN_EID_EXT_NON_INHERITANCE
    body.push(base.len() as u8);
    body.extend_from_slice(&base);
    body.push(ext.len() as u8);
    body.extend_from_slice(&ext);
    let mut out = vec![255u8, body.len() as u8];
    out.extend_from_slice(&body);
    out
}

/// STA Profile body for a partner link in an AP's (Re)Association Response.
///
/// Unlike a beacon/probe-response profile, an association-response profile has
/// a Status Code immediately after Capability Information. A zero status tells
/// the non-AP MLD that this requested partner link was accepted. Omitting these
/// two octets makes the first IE header look like a non-zero rejection status.
#[allow(clippy::too_many_arguments)]
pub fn ap_mld_assoc_profile_inner(
    ssid: &[u8],
    channel: u8,
    country: &[u8; 2],
    width: u16,
    band6: bool,
    wmm: bool,
    phy: PhyMode,
    punct: u16,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ap_capability(channel, band6));
    v.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
    // Match a normal Association Response: RSN parameters were negotiated in
    // the request and are inherited from the association link, so they are not
    // repeated in this successful partner-link response profile.
    let ies = resp_ies(ssid, channel, country, width, band6, wmm, phy, &[], punct);
    append_mld_profile_ies(&mut v, &ies);
    v
}

pub fn parse_mld_link_profiles(ies: &[u8]) -> Vec<MldLinkProfile> {
    parse_mld_link_profiles_checked(ies).unwrap_or_default()
}

/// Strict form of [`parse_mld_link_profiles`]. `None` distinguishes a malformed
/// Basic MLE from a valid element with no partner-link profiles, allowing the AP
/// association path to fail closed instead of silently accepting a truncated
/// or internally inconsistent Link Info field.
pub fn parse_mld_link_profiles_checked(ies: &[u8]) -> Option<Vec<MldLinkProfile>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            return None;
        }
        if ies[i] == 255 && len >= 1 + 2 + 1 + 6 && ies[i + 2] == 107 {
            let body = &ies[i + 3..i + 2 + len];
            let control = u16::from_le_bytes([body[0], body[1]]);
            if control & 0x07 == 0 && body.len() >= 3 {
                let common_len = body[2] as usize;
                if common_len > 6 && common_len <= body.len().saturating_sub(2) {
                    let mut p = 2 + common_len;
                    while p < body.len() {
                        if p + 2 > body.len() {
                            return None;
                        }
                        let sid = body[p];
                        let slen = body[p + 1] as usize;
                        if p + 2 + slen > body.len() {
                            return None;
                        }
                        let sub = &body[p + 2..p + 2 + slen];
                        if sid == 0 {
                            if sub.len() < 3 {
                                return None;
                            }
                            // STA Control(2) + STA Info Length(1) minimum
                            let sta_control = u16::from_le_bytes([sub[0], sub[1]]);
                            let link_id = (sta_control & 0x0f) as u8;
                            let complete_profile = sta_control & (1 << 4) != 0;
                            let mac_present = sta_control & (1 << 5) != 0;
                            let sta_info_len = sub[2] as usize;
                            if !complete_profile
                                || !mac_present
                                || sta_info_len < 7
                                || 2 + sta_info_len > sub.len()
                            {
                                return None;
                            }
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&sub[3..9]);
                            let profile = &sub[2 + sta_info_len..];
                            if profile.len() < 2 {
                                return None;
                            }
                            let capability = Some(u16::from_le_bytes([profile[0], profile[1]]));
                            let profile_ies = profile[2..].to_vec();
                            if !validate_mld_profile_ies(&profile_ies) {
                                return None;
                            }
                            out.push(MldLinkProfile {
                                link_id,
                                mac,
                                capability,
                                ies: profile_ies,
                            });
                        }
                        p += 2 + slen;
                    }
                    return Some(out);
                }
                return None;
            }
        }
        i += 2 + len;
    }
    None
}

/// Validate the IE stream inside an MLD Per-STA Profile, including the internal
/// two-list shape of the Non-Inheritance extension element. A generic IE length
/// walk alone is insufficient: `ff 02 38 00` is externally well-framed but is
/// missing the Extension Element ID list length and reference AP rejects it.
fn validate_mld_profile_ies(ies: &[u8]) -> bool {
    let mut pos = 0;
    while pos < ies.len() {
        if ies.len() - pos < 2 {
            return false;
        }
        let len = ies[pos + 1] as usize;
        let Some(end) = pos.checked_add(2 + len) else {
            return false;
        };
        if end > ies.len() {
            return false;
        }
        if ies[pos] == 255 && len >= 1 && ies[pos + 2] == 56 {
            let payload = &ies[pos + 3..end];
            let Some(&element_count) = payload.first() else {
                return false;
            };
            let extension_count_pos = 1 + element_count as usize;
            let Some(&extension_count) = payload.get(extension_count_pos) else {
                return false;
            };
            if extension_count_pos + 1 + extension_count as usize != payload.len() {
                return false;
            }
        }
        pos = end;
    }
    true
}

/// Backwards-compatible address-only view used by AP-side validation.
pub fn parse_mld_link_macs(ies: &[u8]) -> Vec<(u8, [u8; 6])> {
    parse_mld_link_profiles(ies)
        .into_iter()
        .map(|profile| (profile.link_id, profile.mac))
        .collect()
}

/// Strict address-only view used by AP-side association validation.
pub fn parse_mld_link_macs_checked(ies: &[u8]) -> Option<Vec<(u8, [u8; 6])>> {
    Some(
        parse_mld_link_profiles_checked(ies)?
            .into_iter()
            .map(|profile| (profile.link_id, profile.mac))
            .collect(),
    )
}

/// Extract the optional EML and MLD Capabilities fields from a Basic MLE
/// Common Info field.
fn parse_mld_common_capabilities(ies: &[u8]) -> Option<(Option<u16>, Option<u16>)> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let len = ies[i + 1] as usize;
        if i + 2 + len > ies.len() {
            break;
        }
        if ies[i] == 255 && len >= 1 + 2 + 1 + 6 && ies[i + 2] == 107 {
            let body = &ies[i + 3..i + 2 + len];
            let control = u16::from_le_bytes([body[0], body[1]]);
            if control & 0x07 != 0 {
                return None;
            }
            let common_len = body[2] as usize;
            if common_len < 7 || 2 + common_len > body.len() {
                return None;
            }
            let mut pos = 3 + 6;
            if control & 0x0010 != 0 {
                pos += 1;
            }
            if control & 0x0020 != 0 {
                pos += 1;
            }
            if control & 0x0040 != 0 {
                pos += 2;
            }
            let common_end = 2 + common_len;
            let eml = if control & 0x0080 != 0 {
                if pos + 2 > common_end {
                    return None;
                }
                let value = u16::from_le_bytes([body[pos], body[pos + 1]]);
                pos += 2;
                Some(value)
            } else {
                None
            };
            let mld = if control & 0x0100 != 0 {
                if pos + 2 > common_end {
                    return None;
                }
                Some(u16::from_le_bytes([body[pos], body[pos + 1]]))
            } else {
                None
            };
            return Some((eml, mld));
        }
        i += 2 + len;
    }
    None
}

/// Extract the EML Capabilities field from a Basic MLE Common Info field.
pub fn parse_mld_eml_capability(ies: &[u8]) -> Option<u16> {
    parse_mld_common_capabilities(ies).and_then(|(eml, _)| eml)
}

/// Extract the MLD Capabilities and Operations field from a Basic MLE Common
/// Info field. Bits 0-3 encode the maximum number of simultaneous links minus
/// one, which distinguishes a partner link from one usable concurrently.
pub fn parse_mld_capability(ies: &[u8]) -> Option<u16> {
    parse_mld_common_capabilities(ies).and_then(|(_, mld)| mld)
}
