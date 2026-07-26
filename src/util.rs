//! Small shared helpers.

/// Whether verbose nl80211/frame diagnostics were requested at process start.
///
/// This is read from several receive and handshake hot paths. Environment
/// lookup allocates an `OsString` and takes the process-environment lock, so
/// resolve it once instead of paying that cost for every frame.
pub fn netlink_debug_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("RUSTAP_NL_DEBUG").is_some())
}

/// Encode bytes as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Decode a hex string (ignoring ASCII whitespace) into bytes.
pub fn from_hex(s: &str) -> Vec<u8> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert!(
        cleaned.len().is_multiple_of(2),
        "hex string must have even length"
    );
    cleaned
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).expect("valid hex digit");
            let lo = (pair[1] as char).to_digit(16).expect("valid hex digit");
            (hi * 16 + lo) as u8
        })
        .collect()
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC into 6 bytes.
pub fn mac_to_bytes(mac: &str) -> [u8; 6] {
    let mut out = [0u8; 6];
    for (i, part) in mac.split(':').enumerate() {
        assert!(i < 6, "MAC has too many octets: {mac}");
        out[i] = u8::from_str_radix(part, 16).expect("valid MAC octet");
    }
    out
}

/// Parse a MAC without panicking: returns `None` for malformed input (wrong
/// octet count or a non-hex octet). Use this on any untrusted string (e.g. the
/// control-socket command arguments), where `mac_to_bytes`'s panic would be a
/// denial of service.
pub fn try_mac_to_bytes(mac: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0usize;
    for part in mac.split(':') {
        if n >= 6 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

/// Format 6 bytes as a lowercase colon-separated MAC.
pub fn bytes_to_mac(b: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

/// `true` for the all-ones broadcast address.
pub fn is_broadcast(mac: &str) -> bool {
    mac.eq_ignore_ascii_case("ff:ff:ff:ff:ff:ff")
}

/// `true` if the group bit (LSB of the first octet) is set.
pub fn is_multicast(mac: &str) -> bool {
    let first = mac.split(':').next().unwrap_or("00");
    u8::from_str_radix(first, 16)
        .map(|v| v & 0x1 == 1)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_mac_to_bytes_rejects_malformed_without_panicking() {
        assert_eq!(
            try_mac_to_bytes("02:00:00:00:00:01"),
            Some([2, 0, 0, 0, 0, 1])
        );
        // Malformed inputs must return None, never panic (untrusted control input).
        assert_eq!(try_mac_to_bytes(""), None);
        assert_eq!(try_mac_to_bytes("zz:zz:zz:zz:zz:zz"), None);
        assert_eq!(try_mac_to_bytes("02:00:00"), None); // too few octets
        assert_eq!(try_mac_to_bytes("02:00:00:00:00:00:00"), None); // too many
        assert_eq!(try_mac_to_bytes("0200000000 01"), None);
        assert_eq!(try_mac_to_bytes("02:00:00:00:00:1ff"), None); // out-of-range octet
    }
}
