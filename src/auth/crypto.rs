//! Cryptographic primitives shared by the authentication protocols.
//!
//! These mirror the reference Python *exactly* (including its hand-rolled
//! CCM* construction) so that the wire output is byte-for-byte identical and a
//! real WPA2/CCMP station will accept it.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

/// AES-128 single block ECB encrypt.
pub fn aes128_ecb_encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut b = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

fn aes_ecb_encrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let mut b = *GenericArray::from_slice(block);
    match key.len() {
        16 => Aes128::new(GenericArray::from_slice(key)).encrypt_block(&mut b),
        32 => Aes256::new(GenericArray::from_slice(key)).encrypt_block(&mut b),
        _ => panic!("AES data-protection key must be 16 or 32 bytes"),
    }
    b.into()
}

/// AES-128 single block ECB decrypt.
pub fn aes128_ecb_decrypt_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut b = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut b);
    b.into()
}

/// HMAC-SHA1, truncated to `n` bytes (WPA uses the first 16 for the key MIC).
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Plain SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// HMAC-SHA256 (full 32-byte tag).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// IEEE 802.11 KDF (sha256_prf_bits): `out_len` bytes from
/// `HMAC-SHA256(key, i_le16 || label || context || (out_len*8)_le16)`.
pub fn sha256_prf(key: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let bits_le = ((out_len * 8) as u16).to_le_bytes();
    let mut counter: u16 = 1;
    while out.len() < out_len {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
        mac.update(&counter.to_le_bytes());
        mac.update(label);
        mac.update(context);
        mac.update(&bits_le);
        let mut block = mac.finalize().into_bytes();
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        block.zeroize();
        counter += 1;
    }
    out
}

/// Derive the PTK for SHA-256 AKMs (e.g. SAE): 48 bytes = KCK(16)||KEK(16)||TK(16).
/// Context is `Min(aa,spa) || Max(aa,spa) || Min(anonce,snonce) || Max(anonce,snonce)`.
pub fn derive_ptk_sha256(
    pmk: &[u8],
    aa: &[u8; 6],
    spa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
) -> [u8; 48] {
    let mut bytes = derive_ptk_sha256_len(pmk, aa, spa, anonce, snonce, 48);
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    out
}

/// Derive a SHA-256 PTK of an explicit length.
///
/// CCMP/GCMP-128 use 48 bytes (KCK16 || KEK16 || TK16); CCMP/GCMP-256
/// use 64 bytes (KCK16 || KEK16 || TK32).
pub fn derive_ptk_sha256_len(
    pmk: &[u8],
    aa: &[u8; 6],
    spa: &[u8; 6],
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    out_len: usize,
) -> Vec<u8> {
    assert!(
        matches!(out_len, 48 | 64),
        "supported SHA-256 PTK lengths are 48 and 64 bytes"
    );
    let (mac_lo, mac_hi) = if aa <= spa { (aa, spa) } else { (spa, aa) };
    let (n_lo, n_hi): (&[u8], &[u8]) = if anonce <= snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    let mut ctx = Vec::with_capacity(76);
    ctx.extend_from_slice(mac_lo);
    ctx.extend_from_slice(mac_hi);
    ctx.extend_from_slice(n_lo);
    ctx.extend_from_slice(n_hi);
    sha256_prf(pmk, b"Pairwise key expansion", &ctx, out_len)
}

/// AES-128-CMAC (RFC 4493), returning the full 16-byte tag. BIP-CMAC-128 uses
/// the first 8 bytes.
pub fn aes_cmac(key: &[u8], msg: &[u8]) -> [u8; 16] {
    const RB: u8 = 0x87;
    fn shl1(b: &[u8; 16]) -> ([u8; 16], u8) {
        let mut out = [0u8; 16];
        let mut carry = 0u8;
        for i in (0..16).rev() {
            out[i] = (b[i] << 1) | carry;
            carry = b[i] >> 7;
        }
        (out, carry)
    }
    // Subkeys
    let l = aes128_ecb_encrypt_block(key, &[0u8; 16]);
    let (mut k1, c1) = shl1(&l);
    if c1 != 0 {
        k1[15] ^= RB;
    }
    let (mut k2, c2) = shl1(&k1);
    if c2 != 0 {
        k2[15] ^= RB;
    }

    let n = msg.len().div_ceil(16).max(1);
    let complete = !msg.is_empty() && msg.len().is_multiple_of(16);

    let mut last = [0u8; 16];
    let last_start = (n - 1) * 16;
    if complete {
        last.copy_from_slice(&msg[last_start..]);
        for i in 0..16 {
            last[i] ^= k1[i];
        }
    } else {
        let rem = &msg[last_start..];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x80;
        for i in 0..16 {
            last[i] ^= k2[i];
        }
    }

    let mut x = [0u8; 16];
    for i in 0..n - 1 {
        let block = &msg[i * 16..i * 16 + 16];
        for j in 0..16 {
            x[j] ^= block[j];
        }
        x = aes128_ecb_encrypt_block(key, &x);
    }
    for j in 0..16 {
        x[j] ^= last[j];
    }
    aes128_ecb_encrypt_block(key, &x)
}

/// Constant-time comparison (mirrors `hmac.compare_digest`).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// PBKDF2-HMAC-SHA1, used to derive the PMK from the passphrase/SSID.
pub fn pbkdf2_pmk(psk: &str, ssid: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(psk.as_bytes(), ssid.as_bytes(), 4096, &mut out);
    out
}

// ---------------------------------------------------------------------------
// CCM* (RFC 3610) as implemented by ccmp.py: M=8, L=2, 13-byte nonce
// ---------------------------------------------------------------------------

fn ctr_keystream_block(key: &[u8], a0: &[u8; 16], j: u128) -> [u8; 16] {
    let c = u128::from_be_bytes(*a0).wrapping_add(j);
    aes_ecb_encrypt_block(key, &c.to_be_bytes())
}

fn a0_block(nonce: &[u8; 13]) -> [u8; 16] {
    // flags = q-1 = L-1 = 1, then nonce, then a 2-byte counter starting at 0
    let mut a0 = [0u8; 16];
    a0[0] = 0x01;
    a0[1..14].copy_from_slice(nonce);
    a0
}

/// CTR-mode keystream applied to `data`, starting at counter block A_1
/// (block A_0 is reserved for the tag), exactly like `CCMPCrypto.ctr_encrypt`.
pub fn ctr_encrypt(key: &[u8], nonce: &[u8; 13], data: &[u8]) -> Vec<u8> {
    let a0 = a0_block(nonce);
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let ks = ctr_keystream_block(key, &a0, (i as u128) + 1);
        for (b, k) in chunk.iter().zip(ks.iter()) {
            out.push(b ^ k);
        }
    }
    out
}

/// CBC-MAC over the CCM* formatted blocks, finalised against S_0. Mirrors
/// `CCMPCrypto.cbc_mac` with the default `mac_len = 8`.
pub fn cbc_mac(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    nonce: &[u8; 13],
    mac_len: usize,
) -> Vec<u8> {
    // CCM permits even authentication-tag lengths from 4 through 16 octets.
    // Reject an invalid public input before computing (mac_len - 2).
    if !(4..=16).contains(&mac_len) || !mac_len.is_multiple_of(2) {
        return Vec::new();
    }
    let has_aad = !aad.is_empty();
    let mp = (mac_len - 2) / 2;
    let flags = 64 * (has_aad as usize) + 8 * mp + 1; // q - 1 == 1

    let mut blocks: Vec<u8> = Vec::new();
    // B_0
    blocks.push(flags as u8);
    blocks.extend_from_slice(nonce);
    blocks.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());

    // AAD length-prefixed, zero-padded to a block boundary
    let mut a: Vec<u8> = Vec::new();
    a.extend_from_slice(&(aad.len() as u16).to_be_bytes());
    a.extend_from_slice(aad);
    while !a.len().is_multiple_of(16) {
        a.push(0);
    }
    blocks.extend_from_slice(&a);

    // plaintext, zero-padded to a block boundary
    blocks.extend_from_slice(plaintext);
    while !blocks.len().is_multiple_of(16) {
        blocks.push(0);
    }

    let mut prev = [0u8; 16];
    for chunk in blocks.chunks(16) {
        let mut inb = [0u8; 16];
        for i in 0..16 {
            inb[i] = chunk[i] ^ prev[i];
        }
        prev = aes_ecb_encrypt_block(key, &inb);
    }

    // T = first M bytes of (S_0 xor CBC-MAC), where S_0 = E(A_0)
    let s0 = aes_ecb_encrypt_block(key, &a0_block(nonce));
    (0..mac_len).map(|i| s0[i] ^ prev[i]).collect()
}

/// Encrypt `plaintext`, returning `(ciphertext, tag)`.
pub fn run_ccmp_encrypt(
    key: &[u8],
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    run_ccmp_encrypt_with_tag(key, nonce, aad, plaintext, 8)
}

pub fn run_ccmp_encrypt_with_tag(
    key: &[u8],
    nonce: &[u8; 13],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) {
        return (Vec::new(), Vec::new());
    }
    let tag = cbc_mac(key, plaintext, aad, nonce, tag_len);
    let encrypted = ctr_encrypt(key, nonce, plaintext);
    (encrypted, tag)
}

/// Decrypt `ciphertext`, returning `(plaintext, tag_valid)`.
pub fn run_ccmp_decrypt(
    key: &[u8],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
    known_tag: &[u8],
) -> (Vec<u8>, bool) {
    run_ccmp_decrypt_with_tag(key, nonce, aad, ciphertext, known_tag, 8)
}

pub fn run_ccmp_decrypt_with_tag(
    key: &[u8],
    nonce: &[u8; 13],
    aad: &[u8],
    ciphertext: &[u8],
    known_tag: &[u8],
    tag_len: usize,
) -> (Vec<u8>, bool) {
    let plaintext = ctr_encrypt(key, nonce, ciphertext);
    if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) || known_tag.len() != tag_len {
        return (plaintext, false);
    }
    let tag = cbc_mac(key, &plaintext, aad, nonce, tag_len);
    let valid = constant_time_eq(&tag, known_tag);
    (plaintext, valid)
}

/// GCMP authenticated encryption using RustCrypto AES-GCM.
pub fn run_gcmp_encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Option<(Vec<u8>, [u8; 16])> {
    let mut ciphertext = plaintext.to_vec();
    let tag = match key.len() {
        16 => Aes128Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut ciphertext)
            .ok()?,
        32 => Aes256Gcm::new(GenericArray::from_slice(key))
            .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, &mut ciphertext)
            .ok()?,
        _ => return None,
    };
    Some((ciphertext, tag.into()))
}

/// GCMP authenticated decryption using RustCrypto AES-GCM.
pub fn run_gcmp_decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    let tag: &[u8; 16] = tag.try_into().ok()?;
    let mut plaintext = ciphertext.to_vec();
    match key.len() {
        16 => Aes128Gcm::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                aad,
                &mut plaintext,
                GenericArray::from_slice(tag),
            )
            .ok()?,
        32 => Aes256Gcm::new(GenericArray::from_slice(key))
            .decrypt_in_place_detached(
                Nonce::from_slice(nonce),
                aad,
                &mut plaintext,
                GenericArray::from_slice(tag),
            )
            .ok()?,
        _ => return None,
    };
    Some(plaintext)
}

// ---------------------------------------------------------------------------
// AES key wrap (RFC 3394) — used to wrap the GTK KDE in EAPOL message 3
// ---------------------------------------------------------------------------

const KEY_WRAP_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;

pub fn aes_wrap(kek: &[u8], plain: &[u8]) -> Vec<u8> {
    let n = plain.len() / 8;
    let mut a: u64 = KEY_WRAP_IV;
    let mut r: Vec<[u8; 8]> = (0..n)
        .map(|i| {
            let mut blk = [0u8; 8];
            blk.copy_from_slice(&plain[i * 8..i * 8 + 8]);
            blk
        })
        .collect();

    for j in 0..6u64 {
        for i in 1..=n {
            let mut inb = [0u8; 16];
            inb[..8].copy_from_slice(&a.to_be_bytes());
            inb[8..].copy_from_slice(&r[i - 1]);
            let mut b = aes128_ecb_encrypt_block(kek, &inb);
            let mut hi = [0u8; 8];
            hi.copy_from_slice(&b[..8]);
            a = u64::from_be_bytes(hi) ^ (n as u64 * j + i as u64);
            r[i - 1].copy_from_slice(&b[8..]);
            inb.zeroize();
            b.zeroize();
            hi.zeroize();
        }
    }

    let mut out = Vec::with_capacity(8 * (n + 1));
    out.extend_from_slice(&a.to_be_bytes());
    for blk in &r {
        out.extend_from_slice(blk);
    }
    r.zeroize();
    out
}

pub fn aes_unwrap(kek: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    // AES Key Wrap (RFC 3394) input must be a multiple of 8 and at least two
    // blocks (64-bit IV + >=1 data block). Reject anything else up front, or the
    // `len/8 - 1` below underflows and `wrapped[..8]` panics on a short, valid-MIC
    // key-data field from a malicious peer.
    if wrapped.len() < 16 || wrapped.len() & 7 != 0 {
        return None;
    }
    let n = (wrapped.len() / 8) - 1;
    let mut a = {
        let mut hi = [0u8; 8];
        hi.copy_from_slice(&wrapped[..8]);
        u64::from_be_bytes(hi)
    };
    // r is 1-indexed in the RFC; element 0 is unused
    let mut r: Vec<[u8; 8]> = vec![[0u8; 8]; n + 1];
    for i in 1..=n {
        r[i].copy_from_slice(&wrapped[i * 8..i * 8 + 8]);
    }

    for j in (0..6u64).rev() {
        for i in (1..=n).rev() {
            let mut inb = [0u8; 16];
            inb[..8].copy_from_slice(&(a ^ (n as u64 * j + i as u64)).to_be_bytes());
            inb[8..].copy_from_slice(&r[i]);
            let mut b = aes128_ecb_decrypt_block(kek, &inb);
            let mut hi = [0u8; 8];
            hi.copy_from_slice(&b[..8]);
            a = u64::from_be_bytes(hi);
            r[i].copy_from_slice(&b[8..]);
            inb.zeroize();
            b.zeroize();
            hi.zeroize();
        }
    }

    if a != KEY_WRAP_IV {
        r.zeroize();
        return None;
    }
    let mut out = Vec::with_capacity(8 * n);
    for blk in &r[1..] {
        out.extend_from_slice(blk);
    }
    r.zeroize();
    Some(out)
}

/// Pad to an 8-byte boundary with `0xdd`, like `pad_key_data`.
pub fn pad_key_data(mut plain: Vec<u8>) -> Vec<u8> {
    // IEEE 802.11-2016 §12.7.2: pad the Key Data with a single 0xDD octet
    // followed by 0x00 octets to the next 8-octet boundary (NOT all 0xDD, which
    // a real supplicant rejects as a malformed KDE during parsing).
    if !plain.len().is_multiple_of(8) {
        plain.push(0xdd);
        while !plain.len().is_multiple_of(8) {
            plain.push(0x00);
        }
    }
    plain
}

/// The IEEE 802.11i PRF-512 used to expand the PMK into the PTK.
///
/// `B = sorted(amac, smac) || sorted(anonce, snonce)` (lexicographic), exactly
/// like `customPRF512`.
pub fn custom_prf512(
    key: &[u8],
    amac: &[u8],
    smac: &[u8],
    anonce: &[u8],
    snonce: &[u8],
) -> [u8; 64] {
    let a = b"Pairwise key expansion";

    let (mac_lo, mac_hi) = if amac <= smac {
        (amac, smac)
    } else {
        (smac, amac)
    };
    let (nonce_lo, nonce_hi) = if anonce <= snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };

    let mut b = Vec::with_capacity(mac_lo.len() + mac_hi.len() + nonce_lo.len() + nonce_hi.len());
    b.extend_from_slice(mac_lo);
    b.extend_from_slice(mac_hi);
    b.extend_from_slice(nonce_lo);
    b.extend_from_slice(nonce_hi);

    let mut r = Vec::with_capacity(80);
    // ceil((64*8 + 159) / 160) == 4 iterations
    for i in 0..4u8 {
        let mut buf = Vec::with_capacity(a.len() + 1 + b.len() + 1);
        buf.extend_from_slice(a);
        buf.push(0x00);
        buf.extend_from_slice(&b);
        buf.push(i);
        let mut block = hmac_sha1(key, &buf);
        r.extend_from_slice(&block);
        block.zeroize();
    }

    let mut out = [0u8; 64];
    out.copy_from_slice(&r[..64]);
    r.zeroize();
    out
}
