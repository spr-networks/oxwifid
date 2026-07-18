//! WPA3-SAE (Simultaneous Authentication of Equals) with Hash-to-Element (H2E),
//! ECC group 19 (NIST P-256). Ported from hostap's `src/common/sae.c` and
//! `dragonfly.c`, and cross-checked against the IEEE 802.11-2020 Annex J.10 test
//! vectors.
//!
//! Scope: group 19 only, H2E PWE derivation. The SAE protocol (commit/confirm,
//! shared secret k, KCK/PMK/PMKID derivation) is independent of the PWE method.

use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use p256::{
    elliptic_curve::{
        array::Array,
        consts::U48,
        ops::Reduce,
        sec1::{FromSec1Point, ToSec1Point},
        Group, PrimeField,
    },
    hash2curve::MapToCurve,
    AffinePoint as P256AffinePoint, FieldBytes, NistP256, ProjectivePoint as P256ProjectivePoint,
    Scalar as P256Scalar,
};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const PRIME_LEN: usize = 32;
pub const SAE_GROUP_19: u16 = 19;

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// HKDF-Extract (RFC 5869): PRK = HMAC-Hash(salt, IKM).
fn hkdf_extract(salt: &[u8], ikm: &[&[u8]]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869) with a SHA-256 PRF.
fn hkdf_expand(prk: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut block = hmac_sha256(prk, &[&t, info, &[counter]]);
        t.zeroize();
        t = block.to_vec();
        out.extend_from_slice(&t);
        block.zeroize();
        counter += 1;
    }
    t.zeroize();
    out.truncate(out_len);
    out
}

/// IEEE 802.11 KDF (sha256_prf_bits) producing `out_len` bytes.
fn sha256_prf(key: &[u8], label: &[u8], context: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let bits = (out_len * 8) as u16;
    let bits_le = bits.to_le_bytes();
    let mut counter: u16 = 1;
    while out.len() < out_len {
        let mut block = hmac_sha256(key, &[&counter.to_le_bytes(), label, context, &bits_le]);
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        block.zeroize();
        counter += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// P-256 (group 19) field & point arithmetic over num-bigint
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine(BigUint, BigUint),
}

fn point_to_p256(point: &Point) -> Option<P256ProjectivePoint> {
    match point {
        Point::Infinity => Some(P256ProjectivePoint::IDENTITY),
        Point::Affine(x, y) => {
            let mut sec1 = [0u8; 1 + 2 * PRIME_LEN];
            sec1[0] = 0x04;
            sec1[1..1 + PRIME_LEN].copy_from_slice(&scalar_pad(x, PRIME_LEN));
            sec1[1 + PRIME_LEN..].copy_from_slice(&scalar_pad(y, PRIME_LEN));
            P256AffinePoint::from_sec1_bytes(&sec1)
                .ok()
                .map(P256ProjectivePoint::from)
        }
    }
}

fn point_from_p256(point: P256ProjectivePoint) -> Point {
    if bool::from(point.is_identity()) {
        return Point::Infinity;
    }
    let encoded = point.to_affine().to_sec1_point(false);
    let bytes = encoded.as_bytes();
    Point::Affine(
        BigUint::from_bytes_be(&bytes[1..1 + PRIME_LEN]),
        BigUint::from_bytes_be(&bytes[1 + PRIME_LEN..]),
    )
}

fn scalar_to_p256(value: &BigUint, modulus: &BigUint) -> P256Scalar {
    let reduced = value % modulus;
    let mut bytes = FieldBytes::default();
    bytes.copy_from_slice(&scalar_pad(&reduced, PRIME_LEN));
    Option::<P256Scalar>::from(P256Scalar::from_repr(bytes)).expect("scalar reduced modulo n")
}

fn scalar_from_p256(value: &P256Scalar) -> BigUint {
    let bytes: FieldBytes = value.into();
    BigUint::from_bytes_be(&bytes)
}

pub struct Curve {
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub n: BigUint, // group order
}

fn bn(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid hex")
}

impl Curve {
    pub fn p256() -> Curve {
        Curve {
            p: bn("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            a: bn("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
            b: bn("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            n: bn("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        }
    }

    pub fn on_curve(&self, pt: &Point) -> bool {
        point_to_p256(pt).is_some()
    }

    pub fn negate(&self, pt: &Point) -> Point {
        point_from_p256(-point_to_p256(pt).expect("validated P-256 point"))
    }

    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        let p1 = point_to_p256(p1).expect("validated P-256 point");
        let p2 = point_to_p256(p2).expect("validated P-256 point");
        point_from_p256(p1 + p2)
    }

    pub fn scalar_mul(&self, k: &BigUint, pt: &Point) -> Point {
        let point = point_to_p256(pt).expect("validated P-256 point");
        point_from_p256(point * scalar_to_p256(k, &self.n))
    }

    /// Serialize an affine point as x||y (big-endian, prime_len each).
    pub fn point_to_bin(&self, pt: &Point) -> Option<Vec<u8>> {
        match pt {
            Point::Infinity => None,
            Point::Affine(x, y) => {
                let mut out = vec![0u8; 2 * PRIME_LEN];
                let xb = x.to_bytes_be();
                let yb = y.to_bytes_be();
                out[PRIME_LEN - xb.len()..PRIME_LEN].copy_from_slice(&xb);
                out[2 * PRIME_LEN - yb.len()..].copy_from_slice(&yb);
                Some(out)
            }
        }
    }

    /// Parse x||y, validating the point is on the curve.
    pub fn point_from_bin(&self, data: &[u8]) -> Option<Point> {
        if data.len() != 2 * PRIME_LEN {
            return None;
        }
        let mut sec1 = Vec::with_capacity(1 + data.len());
        sec1.push(0x04);
        sec1.extend_from_slice(data);
        let affine = P256AffinePoint::from_sec1_bytes(&sec1).ok()?;
        Some(point_from_p256(P256ProjectivePoint::from(affine)))
    }

    /// Serialize a point in SEC1 compressed form (0x02/0x03 || X), as OWE and
    /// most EC protocols exchange public keys.
    pub fn point_to_compressed(&self, pt: &Point) -> Option<Vec<u8>> {
        match pt {
            Point::Infinity => None,
            Point::Affine(x, y) => {
                let mut out = Vec::with_capacity(1 + PRIME_LEN);
                out.push(if y.bit(0) { 0x03 } else { 0x02 });
                out.extend_from_slice(&scalar_pad(x, PRIME_LEN));
                Some(out)
            }
        }
    }

    /// Parse a SEC1 compressed point (0x02/0x03 || X), recovering Y. P-256 has
    /// p ≡ 3 (mod 4), so the square root is `v^((p+1)/4) mod p`.
    pub fn point_from_compressed(&self, data: &[u8]) -> Option<Point> {
        let affine = P256AffinePoint::from_sec1_bytes(data).ok()?;
        Some(point_from_p256(P256ProjectivePoint::from(affine)))
    }
}

// RustCrypto's P-256 hash-to-curve implementation uses the same RFC 9380
// Simplified SWU map and z=-10 parameter required by SAE group 19. SAE supplies
// its own HKDF-expanded 48-byte field input, then delegates both reduction and
// mapping to the constant-time library implementation.
fn sswu_from_okm(okm: &[u8]) -> Point {
    debug_assert_eq!(okm.len(), 48);
    let mut uniform = Array::<u8, U48>::default();
    uniform.copy_from_slice(okm);
    let element =
        <<NistP256 as MapToCurve>::FieldElement as Reduce<Array<u8, U48>>>::reduce(&uniform);
    let point = point_from_p256(NistP256::map_to_curve(element));
    uniform.zeroize();
    point
}

// ---------------------------------------------------------------------------
// H2E password element derivation
// ---------------------------------------------------------------------------

fn max_min_addr<'a>(a1: &'a [u8; 6], a2: &'a [u8; 6]) -> ([u8; 6], [u8; 6]) {
    if a1 >= a2 {
        (*a1, *a2)
    } else {
        (*a2, *a1)
    }
}

/// Derive the H2E PT (password token) for group 19.
pub fn derive_pt(c: &Curve, ssid: &[u8], password: &[u8], identifier: Option<&[u8]>) -> Point {
    // pwd-seed = HKDF-Extract(ssid, password [|| identifier])
    let mut pwd_seed = match identifier {
        Some(id) => hkdf_extract(ssid, &[password, id]),
        None => hkdf_extract(ssid, &[password]),
    };

    // len = olen(p) + ceil(olen(p)/2) = 32 + 16
    let pwd_value_len = PRIME_LEN + PRIME_LEN.div_ceil(2);

    let mut pv1 = hkdf_expand(&pwd_seed, b"SAE Hash to Element u1 P1", pwd_value_len);
    let p1 = sswu_from_okm(&pv1);
    pv1.zeroize();

    let mut pv2 = hkdf_expand(&pwd_seed, b"SAE Hash to Element u2 P2", pwd_value_len);
    let p2 = sswu_from_okm(&pv2);
    pv2.zeroize();
    pwd_seed.zeroize();

    c.add(&p1, &p2)
}

/// Legacy hunting-and-pecking PWE derivation (IEEE 802.11 12.4.4.3.2), the
/// non-H2E method. Iterates a counter until a valid x with a QR y^2 is found.
pub fn derive_pwe_hunting_pecking(
    c: &Curve,
    password: &[u8],
    addr1: &[u8; 6],
    addr2: &[u8; 6],
) -> Option<Point> {
    let (max, min) = max_min_addr(addr1, addr2);
    let mut salt = [0u8; 12];
    salt[..6].copy_from_slice(&max);
    salt[6..].copy_from_slice(&min);
    let prime_bytes = scalar_pad(&c.p, PRIME_LEN);

    // Run a FIXED number of iterations regardless of when (or whether) a valid
    // PWE is found: perform the quadratic-residue test every iteration and never
    // break early. This removes the Dragonblood (CVE-2019-9494) timing/cache
    // oracle — the loop's running time no longer depends on which counter first
    // yields a valid point, i.e. on the password. 40 iterations leaves only a
    // ~2^-40 chance of not finding a PWE, and the *first* valid counter is still
    // the one selected, so the derived PWE is unchanged.
    const ITERATIONS: u8 = 40;
    let mut found: Option<Point> = None;
    for counter in 1u8..=ITERATIONS {
        // pwd-seed = HMAC-SHA256(MAX||MIN, password || counter)
        let mut pwd_seed = hmac_sha256(&salt, &[password, &[counter]]);
        // pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
        let mut pwd_value = sha256_prf(
            &pwd_seed,
            b"SAE Hunting and Pecking",
            &prime_bytes,
            PRIME_LEN,
        );
        let x = BigUint::from_bytes_be(&pwd_value);
        // Always ask RustCrypto to decompress a candidate point (using a fixed
        // in-range dummy X when x >= p), so every iteration executes the same
        // constant-time P-256 square-root/validation path.
        let mut candidate_x = if x < c.p {
            scalar_pad(&x, PRIME_LEN)
        } else {
            scalar_pad(&BigUint::one(), PRIME_LEN)
        };
        let mut compressed = Vec::with_capacity(1 + PRIME_LEN);
        compressed.push(if pwd_seed[31] & 0x01 == 1 { 0x03 } else { 0x02 });
        compressed.extend_from_slice(&candidate_x);
        let candidate = c.point_from_compressed(&compressed);
        let is_pwe = x < c.p && candidate.is_some();
        if is_pwe && found.is_none() {
            found = candidate;
        }
        compressed.zeroize();
        candidate_x.zeroize();
        pwd_value.zeroize();
        pwd_seed.zeroize();
    }
    found
}

/// Derive PWE from PT for a specific pair of MAC addresses.
pub fn derive_pwe_from_pt(c: &Curve, pt: &Point, addr1: &[u8; 6], addr2: &[u8; 6]) -> Point {
    let (max, min) = max_min_addr(addr1, addr2);
    let salt = [0u8; 32];
    let val_hash = hkdf_extract(&salt, &[&max, &min]);
    // val = (val mod (n-1)) + 1
    let val = (BigUint::from_bytes_be(&val_hash) % (&c.n - 1u32)) + 1u32;
    c.scalar_mul(&val, pt)
}

// ---------------------------------------------------------------------------
// SAE state machine (one side of the exchange)
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum SaeError {
    BadGroup,
    BadFormat,
    BadRejectedGroups,
    BadElement,
    BadScalar,
    NotReady,
    BadConfirm,
}

pub struct Sae {
    pub curve: Curve,
    pub pwe: Point,
    rand: SecretScalar,
    pub commit_scalar: BigUint,
    pub commit_element: Point,
    peer_scalar: Option<BigUint>,
    peer_element: Option<Point>,
    /// H2E Rejected Groups element payloads. IEEE 802.11 includes these in
    /// address order as the HKDF salt for KCK/PMK derivation. Omitting a peer's
    /// list makes the commit parse successfully but guarantees that Confirm
    /// verification fails.
    own_rejected_groups: Option<Vec<u8>>,
    peer_rejected_groups: Option<Vec<u8>>,
    own_addr_higher: bool,
    pub kck: Vec<u8>,
    pub pmk: Vec<u8>,
    pub pmkid: Vec<u8>,
    send_confirm: u16,
}

impl Drop for Sae {
    fn drop(&mut self) {
        self.kck.zeroize();
        self.pmk.zeroize();
    }
}

/// A private P-256 scalar stored in a fixed-size zeroizing buffer rather than
/// `BigUint` (whose heap limbs are not cleared on drop).
pub struct SecretScalar([u8; 32]);

impl SecretScalar {
    fn zero() -> Self {
        Self([0u8; 32])
    }

    fn random() -> Self {
        // Rejection-sample uniformly in [2, n-1]. RustCrypto performs the range
        // check; unlike `% n`, this introduces no modulo bias.
        loop {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).expect("OS RNG");
            let not_zero_or_one = bytes[..31].iter().any(|byte| *byte != 0) || bytes[31] > 1;
            if not_zero_or_one
                && Option::<P256Scalar>::from(P256Scalar::from_repr(FieldBytes::from(bytes)))
                    .is_some()
            {
                return Self(bytes);
            }
            bytes.zeroize();
        }
    }

    fn from_biguint(value: &BigUint, modulus: &BigUint) -> Self {
        let bytes: [u8; 32] = scalar_pad(&(value % modulus), PRIME_LEN)
            .try_into()
            .expect("P-256 scalar length");
        Self(bytes)
    }

    fn scalar(&self) -> P256Scalar {
        Option::<P256Scalar>::from(P256Scalar::from_repr(FieldBytes::from(self.0)))
            .expect("validated private scalar")
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Sae {
    /// Create an SAE instance for H2E group 19 with the PWE for this addr pair.
    pub fn new_h2e(
        ssid: &[u8],
        password: &[u8],
        identifier: Option<&[u8]>,
        addr1: &[u8; 6],
        addr2: &[u8; 6],
    ) -> Sae {
        let curve = Curve::p256();
        let pt = derive_pt(&curve, ssid, password, identifier);
        let pwe = derive_pwe_from_pt(&curve, &pt, addr1, addr2);
        Sae {
            curve,
            pwe,
            rand: SecretScalar::zero(),
            commit_scalar: BigUint::zero(),
            commit_element: Point::Infinity,
            peer_scalar: None,
            peer_element: None,
            own_rejected_groups: None,
            peer_rejected_groups: None,
            own_addr_higher: addr1 > addr2,
            kck: Vec::new(),
            pmk: Vec::new(),
            pmkid: Vec::new(),
            send_confirm: 0,
        }
    }

    /// Generate the commit scalar and element. With `fixed` set (tests), use the
    /// given rand/mask instead of fresh randomness.
    pub fn prepare_commit(&mut self, fixed: Option<(BigUint, BigUint)>) {
        let (rand, mask) = match fixed {
            Some((rand, mask)) => (
                SecretScalar::from_biguint(&rand, &self.curve.n),
                SecretScalar::from_biguint(&mask, &self.curve.n),
            ),
            None => (SecretScalar::random(), SecretScalar::random()),
        };
        let commit_scalar = rand.scalar() + mask.scalar();
        self.rand = rand;
        self.commit_scalar = scalar_from_p256(&commit_scalar);
        // COMMIT-ELEMENT = inverse(mask * PWE) == -(mask * PWE)
        let mp = point_from_p256(
            point_to_p256(&self.pwe).expect("validated P-256 point") * mask.scalar(),
        );
        self.commit_element = self.curve.negate(&mp);
    }

    /// Serialize the commit body: group(LE) || scalar || element.x || element.y.
    pub fn write_commit(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + 3 * PRIME_LEN);
        v.extend_from_slice(&SAE_GROUP_19.to_le_bytes());
        v.extend_from_slice(&scalar_to_bin(&self.commit_scalar));
        v.extend_from_slice(
            &self
                .curve
                .point_to_bin(&self.commit_element)
                .expect("finite element"),
        );
        if let Some(groups) = self.own_rejected_groups.as_deref() {
            // Extension IE 92: Rejected Groups. The payload is a sequence of
            // little-endian group identifiers.
            v.push(255);
            v.push((1 + groups.len()) as u8);
            v.push(92);
            v.extend_from_slice(groups);
        }
        v
    }

    /// Parse a peer commit body and validate group/scalar/element.
    pub fn parse_peer_commit(&mut self, body: &[u8]) -> Result<(), SaeError> {
        if body.len() < 2 + 3 * PRIME_LEN {
            return Err(SaeError::BadFormat);
        }
        let group = u16::from_le_bytes([body[0], body[1]]);
        if group != SAE_GROUP_19 {
            return Err(SaeError::BadGroup);
        }
        let scalar = BigUint::from_bytes_be(&body[2..2 + PRIME_LEN]);
        if scalar <= BigUint::one() || scalar >= self.curve.n {
            return Err(SaeError::BadScalar);
        }
        let element = self
            .curve
            .point_from_bin(&body[2 + PRIME_LEN..2 + 3 * PRIME_LEN])
            .ok_or(SaeError::BadElement)?;
        let mut rejected_groups = None;
        let mut pos = 2 + 3 * PRIME_LEN;
        while pos < body.len() {
            if body.len() - pos < 2 {
                return Err(SaeError::BadFormat);
            }
            let len = body[pos + 1] as usize;
            let end = pos
                .checked_add(2 + len)
                .filter(|end| *end <= body.len())
                .ok_or(SaeError::BadFormat)?;
            if body[pos] == 255 && len >= 1 && body[pos + 2] == 92 {
                if rejected_groups.is_some() {
                    return Err(SaeError::BadRejectedGroups);
                }
                let groups = &body[pos + 3..end];
                if groups.is_empty() || !groups.len().is_multiple_of(2) {
                    return Err(SaeError::BadRejectedGroups);
                }
                if groups
                    .chunks_exact(2)
                    .any(|g| u16::from_le_bytes([g[0], g[1]]) == SAE_GROUP_19)
                {
                    // A peer cannot reject the group it selected for this
                    // commit.
                    return Err(SaeError::BadRejectedGroups);
                }
                rejected_groups = Some(groups.to_vec());
            }
            pos = end;
        }
        self.peer_scalar = Some(scalar);
        self.peer_element = Some(element);
        self.peer_rejected_groups = rejected_groups;
        Ok(())
    }

    /// Advertise groups rejected while selecting this H2E commit group.
    pub fn set_rejected_groups(&mut self, groups: &[u16]) -> Result<(), SaeError> {
        if groups.is_empty() {
            self.own_rejected_groups = None;
            return Ok(());
        }
        if groups.contains(&SAE_GROUP_19) || groups.len() > 127 {
            return Err(SaeError::BadRejectedGroups);
        }
        self.own_rejected_groups = Some(groups.iter().flat_map(|g| g.to_le_bytes()).collect());
        Ok(())
    }

    pub fn peer_rejected_groups(&self) -> Vec<u16> {
        self.peer_rejected_groups
            .as_deref()
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|g| u16::from_le_bytes([g[0], g[1]]))
            .collect()
    }

    /// True if the peer's commit reflects our own scalar AND element — an SAE
    /// reflection attack (IEEE 802.11 12.4.5.4). Call after `prepare_commit`.
    pub fn is_reflection(&self) -> bool {
        self.peer_scalar.as_ref() == Some(&self.commit_scalar)
            && self.peer_element.as_ref() == Some(&self.commit_element)
    }

    /// Compute the shared secret and derive KCK/PMK/PMKID.
    pub fn process_commit(&mut self) -> Result<(), SaeError> {
        let peer_scalar = self.peer_scalar.clone().ok_or(SaeError::NotReady)?;
        let peer_element = self.peer_element.clone().ok_or(SaeError::NotReady)?;

        // K = rand * (peer_scalar*PWE + peer_element)
        let k1 = self.curve.scalar_mul(&peer_scalar, &self.pwe);
        let k2 = self.curve.add(&k1, &peer_element);
        let big_k = point_from_p256(
            point_to_p256(&k2).expect("validated P-256 point") * self.rand.scalar(),
        );
        let mut k = match &big_k {
            Point::Infinity => return Err(SaeError::BadElement),
            Point::Affine(x, _) => scalar_pad(x, PRIME_LEN),
        };

        self.derive_keys(&k, &peer_scalar);
        k.zeroize();
        Ok(())
    }

    fn derive_keys(&mut self, k: &[u8], peer_scalar: &BigUint) {
        // H2E normally uses 0^hash-length as the HKDF salt. If either peer
        // advertised a Rejected Groups list, the salt is instead the two lists
        // concatenated in descending MAC-address order.
        let mut rejected_groups = Vec::new();
        if self.own_addr_higher {
            if let Some(own) = self.own_rejected_groups.as_deref() {
                rejected_groups.extend_from_slice(own);
            }
            if let Some(peer) = self.peer_rejected_groups.as_deref() {
                rejected_groups.extend_from_slice(peer);
            }
        } else {
            if let Some(peer) = self.peer_rejected_groups.as_deref() {
                rejected_groups.extend_from_slice(peer);
            }
            if let Some(own) = self.own_rejected_groups.as_deref() {
                rejected_groups.extend_from_slice(own);
            }
        }
        let zero_salt = [0u8; 32];
        let salt = if rejected_groups.is_empty() {
            zero_salt.as_slice()
        } else {
            rejected_groups.as_slice()
        };
        let mut keyseed = hkdf_extract(salt, &[k]);

        // context = (commit_scalar + peer_scalar) mod n, left-padded to order_len
        let sum = scalar_from_p256(
            &(scalar_to_p256(&self.commit_scalar, &self.curve.n)
                + scalar_to_p256(peer_scalar, &self.curve.n)),
        );
        let context = scalar_pad(&sum, PRIME_LEN);

        // KCK || PMK = KDF-Hash(keyseed, "SAE KCK and PMK", context), 32 + 32
        let mut keys = sha256_prf(&keyseed, b"SAE KCK and PMK", &context, 64);
        self.kck.zeroize();
        self.pmk.zeroize();
        self.kck = keys[..32].to_vec();
        self.pmk = keys[32..64].to_vec();
        self.pmkid = context[..16].to_vec();
        keys.zeroize();
        keyseed.zeroize();
    }

    fn cn_confirm(
        &self,
        sc: u16,
        scalar1: &BigUint,
        elem1: &Point,
        scalar2: &BigUint,
        elem2: &Point,
    ) -> [u8; 32] {
        let s1 = scalar_to_bin(scalar1);
        let e1 = self.curve.point_to_bin(elem1).expect("finite");
        let s2 = scalar_to_bin(scalar2);
        let e2 = self.curve.point_to_bin(elem2).expect("finite");
        hmac_sha256(&self.kck, &[&sc.to_le_bytes(), &s1, &e1, &s2, &e2])
    }

    /// Build our confirm message: send-confirm(LE) || confirm(32).
    pub fn write_confirm(&mut self) -> Vec<u8> {
        self.send_confirm = self.send_confirm.saturating_add(1);
        let sc = self.send_confirm;
        let peer_scalar = self.peer_scalar.clone().expect("peer scalar");
        let peer_element = self.peer_element.clone().expect("peer element");
        let confirm = self.cn_confirm(
            sc,
            &self.commit_scalar,
            &self.commit_element,
            &peer_scalar,
            &peer_element,
        );
        let mut v = Vec::with_capacity(2 + 32);
        v.extend_from_slice(&sc.to_le_bytes());
        v.extend_from_slice(&confirm);
        v
    }

    /// Verify a peer confirm message (send-confirm(LE) || confirm(32)).
    pub fn check_confirm(&self, data: &[u8]) -> Result<(), SaeError> {
        if data.len() < 2 + 32 {
            return Err(SaeError::BadFormat);
        }
        let sc = u16::from_le_bytes([data[0], data[1]]);
        let peer_scalar = self.peer_scalar.clone().ok_or(SaeError::NotReady)?;
        let peer_element = self.peer_element.clone().ok_or(SaeError::NotReady)?;
        // verifier = CN(KCK, peer-sc, peer-scalar, peer-element, own-scalar, own-element)
        let verifier = self.cn_confirm(
            sc,
            &peer_scalar,
            &peer_element,
            &self.commit_scalar,
            &self.commit_element,
        );
        if crate::crypto::constant_time_eq(&verifier, &data[2..2 + 32]) {
            Ok(())
        } else {
            Err(SaeError::BadConfirm)
        }
    }

    // -- test hooks --------------------------------------------------------

    /// Create an SAE instance using the legacy hunting-and-pecking PWE.
    pub fn new_hunting_pecking(password: &[u8], addr1: &[u8; 6], addr2: &[u8; 6]) -> Option<Sae> {
        let curve = Curve::p256();
        let pwe = derive_pwe_hunting_pecking(&curve, password, addr1, addr2)?;
        Some(Sae {
            curve,
            pwe,
            rand: SecretScalar::zero(),
            commit_scalar: BigUint::zero(),
            commit_element: Point::Infinity,
            peer_scalar: None,
            peer_element: None,
            own_rejected_groups: None,
            peer_rejected_groups: None,
            own_addr_higher: addr1 > addr2,
            kck: Vec::new(),
            pmk: Vec::new(),
            pmkid: Vec::new(),
            send_confirm: 0,
        })
    }

    /// Override the PWE directly (for IEEE J.10 protocol vectors).
    pub fn set_pwe(&mut self, pwe: Point) {
        self.pwe = pwe;
    }

    /// Construct directly from a known PWE (skips H2E derivation).
    pub fn with_pwe(pwe: Point) -> Sae {
        Sae {
            curve: Curve::p256(),
            pwe,
            rand: SecretScalar::zero(),
            commit_scalar: BigUint::zero(),
            commit_element: Point::Infinity,
            peer_scalar: None,
            peer_element: None,
            own_rejected_groups: None,
            peer_rejected_groups: None,
            own_addr_higher: false,
            kck: Vec::new(),
            pmk: Vec::new(),
            pmkid: Vec::new(),
            send_confirm: 0,
        }
    }
}

/// Modular inverse mod n (n prime), via Fermat.
pub fn mod_inverse(a: &BigUint, n: &BigUint) -> BigUint {
    (a % n).modpow(&(n - 2u32), n)
}

// ---------------------------------------------------------------------------
// OWE - Opportunistic Wireless Encryption (RFC 8110), group 19
// ---------------------------------------------------------------------------

/// The P-256 base point G.
pub fn generator() -> Point {
    Point::Affine(
        bn("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        bn("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    )
}

/// Generate an OWE Diffie-Hellman key pair: private scalar and public key as the
/// bare X-coordinate (`prime_len` bytes). OWE (and hostapd) exchange only X; the
/// receiver recovers a Y, and the ECDH shared X is independent of Y's parity.
pub fn owe_keypair() -> (SecretScalar, Vec<u8>) {
    let priv_k = SecretScalar::random();
    let pubk =
        point_from_p256(point_to_p256(&generator()).expect("P-256 generator") * priv_k.scalar());
    let x = match pubk {
        Point::Affine(x, _) => scalar_pad(&x, PRIME_LEN),
        Point::Infinity => unreachable!("k*G is finite for k in [1,n)"),
    };
    (priv_k, x)
}

/// Reconstruct a curve point from a bare X-coordinate (recovering an even Y).
fn point_from_x(curve: &Curve, x_bytes: &[u8]) -> Option<Point> {
    let mut compressed = Vec::with_capacity(1 + x_bytes.len());
    compressed.push(0x02); // even Y; ECDH shared X is parity-independent
    compressed.extend_from_slice(x_bytes);
    curve.point_from_compressed(&compressed)
}

/// Derive the OWE PMK and PMKID (RFC 8110 §4.4). `sta_pub`/`ap_pub` are the
/// public keys as exchanged (bare X-coordinates); `peer_pub_bytes` is the
/// *other* party's X. Both sides compute the same result.
pub fn owe_derive(
    priv_k: &SecretScalar,
    peer_pub_bytes: &[u8],
    sta_pub: &[u8],
    ap_pub: &[u8],
    group: u16,
) -> Option<([u8; 32], [u8; 16])> {
    let curve = Curve::p256();
    let peer_pub = point_from_x(&curve, peer_pub_bytes)?;
    let shared =
        point_from_p256(point_to_p256(&peer_pub).expect("validated P-256 point") * priv_k.scalar());
    let mut z = match shared {
        Point::Affine(x, _) => scalar_pad(&x, PRIME_LEN),
        Point::Infinity => return None,
    };
    // prk = HKDF-Extract(C | A | group, z)  (C = STA pubkey, A = AP pubkey)
    let mut salt = Vec::new();
    salt.extend_from_slice(sta_pub);
    salt.extend_from_slice(ap_pub);
    salt.extend_from_slice(&group.to_le_bytes());
    let mut prk = hkdf_extract(&salt, &[&z]);
    // PMK = HKDF-Expand(prk, "OWE Key Generation", 32)
    let mut pmk_v = hkdf_expand(&prk, b"OWE Key Generation", 32);
    // PMKID = Truncate-128(SHA-256(C | A))
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(sta_pub);
    hasher.update(ap_pub);
    let digest = hasher.finalize();
    let mut pmk = [0u8; 32];
    pmk.copy_from_slice(&pmk_v);
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&digest[..16]);
    z.zeroize();
    prk.zeroize();
    pmk_v.zeroize();
    Some((pmk, pmkid))
}

/// Left-pad a scalar to `len` bytes, big-endian.
fn scalar_pad(v: &BigUint, len: usize) -> Vec<u8> {
    let b = v.to_bytes_be();
    let mut out = vec![0u8; len];
    if b.len() <= len {
        out[len - b.len()..].copy_from_slice(&b);
    } else {
        out.copy_from_slice(&b[b.len() - len..]);
    }
    out
}

fn scalar_to_bin(v: &BigUint) -> Vec<u8> {
    scalar_pad(v, PRIME_LEN)
}
