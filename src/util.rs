//! Small shared helpers.

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
    assert!(cleaned.len().is_multiple_of(2), "hex string must have even length");
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
    u8::from_str_radix(first, 16).map(|v| v & 0x1 == 1).unwrap_or(false)
}
