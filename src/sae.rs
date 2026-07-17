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
use sha2::Sha256;

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
        let block = hmac_sha256(prk, &[&t, info, &[counter]]);
        t = block.to_vec();
        out.extend_from_slice(&t);
        counter += 1;
    }
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
        let block = hmac_sha256(key, &[&counter.to_le_bytes(), label, context, &bits_le]);
        let take = (out_len - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
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

    fn fmul(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a * b) % &self.p
    }
    fn fadd(&self, a: &BigUint, b: &BigUint) -> BigUint {
        (a + b) % &self.p
    }
    fn fsub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        // (a - b) mod p, avoiding negatives
        let am = a % &self.p;
        let bm = b % &self.p;
        (&am + &self.p - bm) % &self.p
    }
    fn finv(&self, a: &BigUint) -> BigUint {
        // Fermat: a^(p-2) mod p
        a.modpow(&(&self.p - 2u32), &self.p)
    }
    /// sqrt for p == 3 (mod 4): a^((p+1)/4) mod p.
    pub fn fsqrt(&self, a: &BigUint) -> BigUint {
        let exp = (&self.p + 1u32) >> 2;
        a.modpow(&exp, &self.p)
    }
    /// Legendre-style: returns true if a is a quadratic residue (or zero).
    fn is_qr(&self, a: &BigUint) -> bool {
        if a.is_zero() {
            return true;
        }
        let exp = (&self.p - 1u32) >> 1;
        a.modpow(&exp, &self.p).is_one()
    }

    /// Strict quadratic-residue test (non-zero square), for hunting-and-pecking.
    fn is_quadratic_residue(&self, a: &BigUint) -> bool {
        !a.is_zero() && {
            let exp = (&self.p - 1u32) >> 1;
            a.modpow(&exp, &self.p).is_one()
        }
    }

    /// y^2 = x^3 + a*x + b mod p.
    fn y_sqr(&self, x: &BigUint) -> BigUint {
        let x3 = self.fmul(&self.fmul(x, x), x);
        self.fadd(&self.fadd(&x3, &self.fmul(&self.a, x)), &self.b)
    }

    pub fn on_curve(&self, pt: &Point) -> bool {
        match pt {
            Point::Infinity => true,
            Point::Affine(x, y) => {
                let lhs = self.fmul(y, y);
                let x3 = self.fmul(&self.fmul(x, x), x);
                let ax = self.fmul(&self.a, x);
                let rhs = self.fadd(&self.fadd(&x3, &ax), &self.b);
                lhs == rhs
            }
        }
    }

    pub fn negate(&self, pt: &Point) -> Point {
        match pt {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => Point::Affine(x.clone(), (&self.p - y) % &self.p),
        }
    }

    fn double(&self, pt: &Point) -> Point {
        match pt {
            Point::Infinity => Point::Infinity,
            Point::Affine(x, y) => {
                if y.is_zero() {
                    return Point::Infinity;
                }
                // lambda = (3x^2 + a) / (2y)
                let three_x2 = self.fmul(&BigUint::from(3u32), &self.fmul(x, x));
                let num = self.fadd(&three_x2, &self.a);
                let den = self.finv(&self.fmul(&BigUint::from(2u32), y));
                let lam = self.fmul(&num, &den);
                let x3 = self.fsub(&self.fmul(&lam, &lam), &self.fmul(&BigUint::from(2u32), x));
                let y3 = self.fsub(&self.fmul(&lam, &self.fsub(x, &x3)), y);
                Point::Affine(x3, y3)
            }
        }
    }

    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        match (p1, p2) {
            (Point::Infinity, _) => p2.clone(),
            (_, Point::Infinity) => p1.clone(),
            (Point::Affine(x1, y1), Point::Affine(x2, y2)) => {
                if x1 == x2 {
                    if y1 == y2 {
                        return self.double(p1);
                    }
                    return Point::Infinity; // p1 == -p2
                }
                let lam = self.fmul(&self.fsub(y2, y1), &self.finv(&self.fsub(x2, x1)));
                let x3 = self.fsub(&self.fsub(&self.fmul(&lam, &lam), x1), x2);
                let y3 = self.fsub(&self.fmul(&lam, &self.fsub(x1, &x3)), y1);
                Point::Affine(x3, y3)
            }
        }
    }

    pub fn scalar_mul(&self, k: &BigUint, pt: &Point) -> Point {
        let mut result = Point::Infinity;
        let bits = k.bits();
        for i in (0..bits).rev() {
            result = self.double(&result);
            if k.bit(i) {
                result = self.add(&result, pt);
            }
        }
        result
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
        let x = BigUint::from_bytes_be(&data[..PRIME_LEN]);
        let y = BigUint::from_bytes_be(&data[PRIME_LEN..]);
        if x >= self.p || y >= self.p {
            return None;
        }
        let pt = Point::Affine(x, y);
        if !self.on_curve(&pt) {
            return None;
        }
        Some(pt)
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
        if data.len() != 1 + PRIME_LEN || (data[0] != 0x02 && data[0] != 0x03) {
            return None;
        }
        let x = BigUint::from_bytes_be(&data[1..]);
        if x >= self.p {
            return None;
        }
        let p = &self.p;
        // rhs = x^3 + a*x + b mod p
        let rhs = (&x * &x % p * &x % p + &self.a * &x % p + &self.b) % p;
        let exp = (p + BigUint::one()) >> 2; // (p+1)/4
        let mut y = rhs.modpow(&exp, p);
        if &y * &y % p != rhs {
            return None; // x is not on the curve
        }
        if y.bit(0) != (data[0] == 0x03) {
            y = p - &y;
        }
        let pt = Point::Affine(x, y);
        if !self.on_curve(&pt) {
            return None;
        }
        Some(pt)
    }
}

// ---------------------------------------------------------------------------
// SSWU (Simplified SWU) map for group 19 (z = -10), per hostap sswu()
// ---------------------------------------------------------------------------

fn sswu(c: &Curve, u: &BigUint) -> Point {
    let p = &c.p;
    let z = (p - 10u32) % p; // z = -10 mod p
    let one = BigUint::one();

    // m = z^2*u^4 + z*u^2  (t1 = z*u^2 ; m = t1 + t1^2)
    let u2 = c.fmul(u, u);
    let t1 = c.fmul(&z, &u2);
    let t2 = c.fmul(&t1, &t1);
    let m = c.fadd(&t1, &t2);
    let m_is_zero = m.is_zero();

    // t = m^(p-2) (inverse, or 0 if m==0)
    let t = m.modpow(&(p - 2u32), p);

    // x1a = b / (z*a)
    let x1a = c.fmul(&c.b, &c.finv(&c.fmul(&z, &c.a)));
    // x1b = (-b/a) * (1 + t)
    let neg_b = c.fsub(&BigUint::zero(), &c.b);
    let neg_b_over_a = c.fmul(&neg_b, &c.finv(&c.a));
    let x1b = c.fmul(&neg_b_over_a, &c.fadd(&one, &t));

    let x1 = if m_is_zero { x1a } else { x1b };

    // gx1 = x1^3 + a*x1 + b
    let gx1 = c.fadd(
        &c.fadd(&c.fmul(&c.fmul(&x1, &x1), &x1), &c.fmul(&c.a, &x1)),
        &c.b,
    );
    // x2 = z*u^2*x1
    let x2 = c.fmul(&c.fmul(&z, &u2), &x1);
    // gx2 = x2^3 + a*x2 + b
    let gx2 = c.fadd(
        &c.fadd(&c.fmul(&c.fmul(&x2, &x2), &x2), &c.fmul(&c.a, &x2)),
        &c.b,
    );

    let gx1_is_qr = c.is_qr(&gx1);
    let v = if gx1_is_qr { gx1.clone() } else { gx2.clone() };
    let x = if gx1_is_qr { x1 } else { x2 };

    let mut y = c.fsqrt(&v);

    // y has the same LSB as u
    let u_odd = u.bit(0);
    let y_odd = y.bit(0);
    if u_odd != y_odd {
        y = (p - &y) % p;
    }

    Point::Affine(x, y)
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
    let pwd_seed = match identifier {
        Some(id) => hkdf_extract(ssid, &[password, id]),
        None => hkdf_extract(ssid, &[password]),
    };

    // len = olen(p) + ceil(olen(p)/2) = 32 + 16
    let pwd_value_len = PRIME_LEN + PRIME_LEN.div_ceil(2);

    let pv1 = hkdf_expand(&pwd_seed, b"SAE Hash to Element u1 P1", pwd_value_len);
    let u1 = BigUint::from_bytes_be(&pv1) % &c.p;
    let p1 = sswu(c, &u1);

    let pv2 = hkdf_expand(&pwd_seed, b"SAE Hash to Element u2 P2", pwd_value_len);
    let u2 = BigUint::from_bytes_be(&pv2) % &c.p;
    let p2 = sswu(c, &u2);

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
    let mut found: Option<(BigUint, bool)> = None;
    for counter in 1u8..=ITERATIONS {
        // pwd-seed = HMAC-SHA256(MAX||MIN, password || counter)
        let pwd_seed = hmac_sha256(&salt, &[password, &[counter]]);
        // pwd-value = KDF-256(pwd-seed, "SAE Hunting and Pecking", p)
        let pwd_value = sha256_prf(
            &pwd_seed,
            b"SAE Hunting and Pecking",
            &prime_bytes,
            PRIME_LEN,
        );
        let x = BigUint::from_bytes_be(&pwd_value);
        // Always run the QR test (on a fixed in-range dummy when x >= p) so the
        // expensive modular exponentiation happens every iteration.
        let cand = if x < c.p { x.clone() } else { BigUint::one() };
        let is_pwe = x < c.p && c.is_quadratic_residue(&c.y_sqr(&cand));
        if is_pwe && found.is_none() {
            found = Some((x, pwd_seed[31] & 0x01 == 1));
        }
    }

    let (x, seed_odd) = found?;
    let y2 = c.y_sqr(&x);
    let mut y = c.fsqrt(&y2);
    // pick the root whose LSB matches the pwd-seed's LSB
    if y.bit(0) != seed_odd {
        y = (&c.p - &y) % &c.p;
    }
    Some(Point::Affine(x, y))
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
    BadElement,
    BadScalar,
    NotReady,
    BadConfirm,
}

pub struct Sae {
    pub curve: Curve,
    pub pwe: Point,
    rand: BigUint,
    pub commit_scalar: BigUint,
    pub commit_element: Point,
    peer_scalar: Option<BigUint>,
    peer_element: Option<Point>,
    pub kck: Vec<u8>,
    pub pmk: Vec<u8>,
    pub pmkid: Vec<u8>,
    send_confirm: u16,
}

fn rand_scalar(n: &BigUint) -> BigUint {
    // random in [2, n-1]
    loop {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("OS RNG");
        let v = BigUint::from_bytes_be(&buf) % n;
        if v > BigUint::one() {
            return v;
        }
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
            rand: BigUint::zero(),
            commit_scalar: BigUint::zero(),
            commit_element: Point::Infinity,
            peer_scalar: None,
            peer_element: None,
            kck: Vec::new(),
            pmk: Vec::new(),
            pmkid: Vec::new(),
            send_confirm: 0,
        }
    }

    /// Generate the commit scalar and element. With `fixed` set (tests), use the
    /// given rand/mask instead of fresh randomness.
    pub fn prepare_commit(&mut self, fixed: Option<(BigUint, BigUint)>) {
        let (rand, mask) =
            fixed.unwrap_or_else(|| (rand_scalar(&self.curve.n), rand_scalar(&self.curve.n)));
        self.rand = rand.clone();
        self.commit_scalar = (&rand + &mask) % &self.curve.n;
        // COMMIT-ELEMENT = inverse(mask * PWE) == -(mask * PWE)
        let mp = self.curve.scalar_mul(&mask, &self.pwe);
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
        self.peer_scalar = Some(scalar);
        self.peer_element = Some(element);
        Ok(())
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
        let big_k = self.curve.scalar_mul(&self.rand, &k2);
        let k = match &big_k {
            Point::Infinity => return Err(SaeError::BadElement),
            Point::Affine(x, _) => scalar_pad(x, PRIME_LEN),
        };

        self.derive_keys(&k, &peer_scalar);
        Ok(())
    }

    fn derive_keys(&mut self, k: &[u8], peer_scalar: &BigUint) {
        // keyseed = HKDF-Extract(0^32, k)   (H2E, no rejected groups)
        let salt = [0u8; 32];
        let keyseed = hkdf_extract(&salt, &[k]);

        // context = (commit_scalar + peer_scalar) mod n, left-padded to order_len
        let sum = (&self.commit_scalar + peer_scalar) % &self.curve.n;
        let context = scalar_pad(&sum, PRIME_LEN);

        // KCK || PMK = KDF-Hash(keyseed, "SAE KCK and PMK", context), 32 + 32
        let keys = sha256_prf(&keyseed, b"SAE KCK and PMK", &context, 64);
        self.kck = keys[..32].to_vec();
        self.pmk = keys[32..64].to_vec();
        self.pmkid = context[..16].to_vec();
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
            rand: BigUint::zero(),
            commit_scalar: BigUint::zero(),
            commit_element: Point::Infinity,
            peer_scalar: None,
            peer_element: None,
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
            rand: BigUint::zero(),
            commit_scalar: BigUint::zero(),
            commit_element: Point::Infinity,
            peer_scalar: None,
            peer_element: None,
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
pub fn owe_keypair() -> (BigUint, Vec<u8>) {
    let curve = Curve::p256();
    let priv_k = rand_scalar(&curve.n);
    let pubk = curve.scalar_mul(&priv_k, &generator());
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
    priv_k: &BigUint,
    peer_pub_bytes: &[u8],
    sta_pub: &[u8],
    ap_pub: &[u8],
    group: u16,
) -> Option<([u8; 32], [u8; 16])> {
    let curve = Curve::p256();
    let peer_pub = point_from_x(&curve, peer_pub_bytes)?;
    let shared = curve.scalar_mul(priv_k, &peer_pub);
    let z = match shared {
        Point::Affine(x, _) => scalar_pad(&x, PRIME_LEN),
        Point::Infinity => return None,
    };
    // prk = HKDF-Extract(C | A | group, z)  (C = STA pubkey, A = AP pubkey)
    let mut salt = Vec::new();
    salt.extend_from_slice(sta_pub);
    salt.extend_from_slice(ap_pub);
    salt.extend_from_slice(&group.to_le_bytes());
    let prk = hkdf_extract(&salt, &[&z]);
    // PMK = HKDF-Expand(prk, "OWE Key Generation", 32)
    let pmk_v = hkdf_expand(&prk, b"OWE Key Generation", 32);
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
