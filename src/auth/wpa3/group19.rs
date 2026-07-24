//! SAE/OWE finite cyclic group 19 backed by RustCrypto's `p256` crate.
//!
//! `BigUint` is used only at the IEEE 802.11 byte/scalar boundary so the
//! published test vectors remain easy to compare. Point validation, addition,
//! negation, scalar multiplication, SEC1 decoding, inversion, and the
//! simplified-SWU map are delegated to `p256`.

use num_bigint::BigUint;
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
use zeroize::Zeroize;

pub(crate) const PRIME_LEN: usize = 32;
pub const SAE_GROUP_19: u16 = 19;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine(BigUint, BigUint),
}

pub(crate) fn point_to_p256(point: &Point) -> Option<P256ProjectivePoint> {
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

pub(crate) fn point_from_p256(point: P256ProjectivePoint) -> Point {
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

pub(crate) fn scalar_to_p256(value: &BigUint, modulus: &BigUint) -> P256Scalar {
    let reduced = value % modulus;
    let mut bytes = FieldBytes::default();
    bytes.copy_from_slice(&scalar_pad(&reduced, PRIME_LEN));
    Option::<P256Scalar>::from(P256Scalar::from_repr(bytes)).expect("scalar reduced modulo n")
}

pub(crate) fn scalar_from_p256(value: &P256Scalar) -> BigUint {
    let bytes: FieldBytes = value.into();
    BigUint::from_bytes_be(&bytes)
}

/// Group-19 parameters exposed at the scalar/field serialization boundary.
pub struct Curve {
    /// P-256 field modulus, used as the SAE hunting-and-pecking KDF context.
    pub p: BigUint,
    /// P-256 group order.
    pub n: BigUint,
}

fn bn(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("valid P-256 parameter")
}

impl Curve {
    pub fn p256() -> Curve {
        Curve {
            p: bn("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            n: bn("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        }
    }

    pub fn on_curve(&self, point: &Point) -> bool {
        point_to_p256(point).is_some()
    }

    pub fn negate(&self, point: &Point) -> Point {
        point_from_p256(-point_to_p256(point).expect("validated P-256 point"))
    }

    pub fn add(&self, left: &Point, right: &Point) -> Point {
        let left = point_to_p256(left).expect("validated P-256 point");
        let right = point_to_p256(right).expect("validated P-256 point");
        point_from_p256(left + right)
    }

    pub fn scalar_mul(&self, scalar: &BigUint, point: &Point) -> Point {
        let point = point_to_p256(point).expect("validated P-256 point");
        point_from_p256(point * scalar_to_p256(scalar, &self.n))
    }

    /// Serialize an affine point as x||y, 32-byte big-endian coordinates.
    pub fn point_to_bin(&self, point: &Point) -> Option<Vec<u8>> {
        match point {
            Point::Infinity => None,
            Point::Affine(x, y) => {
                let mut out = vec![0u8; 2 * PRIME_LEN];
                out[..PRIME_LEN].copy_from_slice(&scalar_pad(x, PRIME_LEN));
                out[PRIME_LEN..].copy_from_slice(&scalar_pad(y, PRIME_LEN));
                Some(out)
            }
        }
    }

    /// Parse x||y and let `p256` validate that it is a group-19 point.
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

    pub fn point_to_compressed(&self, point: &Point) -> Option<Vec<u8>> {
        let point = point_to_p256(point)?;
        if bool::from(point.is_identity()) {
            return None;
        }
        Some(point.to_affine().to_sec1_point(true).as_bytes().to_vec())
    }

    pub fn point_from_compressed(&self, data: &[u8]) -> Option<Point> {
        let affine = P256AffinePoint::from_sec1_bytes(data).ok()?;
        Some(point_from_p256(P256ProjectivePoint::from(affine)))
    }
}

/// Map SAE's already-expanded 48-byte field input with RustCrypto's RFC 9380
/// simplified-SWU implementation for P-256.
pub(crate) fn sswu_from_okm(okm: &[u8]) -> Point {
    debug_assert_eq!(okm.len(), 48);
    let mut uniform = Array::<u8, U48>::default();
    uniform.copy_from_slice(okm);
    let element =
        <<NistP256 as MapToCurve>::FieldElement as Reduce<Array<u8, U48>>>::reduce(&uniform);
    let point = point_from_p256(NistP256::map_to_curve(element));
    uniform.zeroize();
    point
}

/// A private scalar stored in a fixed-size zeroizing buffer.
pub struct SecretScalar(pub(crate) [u8; 32]);

impl SecretScalar {
    pub(crate) fn zero() -> Self {
        Self([0u8; 32])
    }

    pub(crate) fn random() -> Self {
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

    pub(crate) fn from_biguint(value: &BigUint, modulus: &BigUint) -> Self {
        let bytes: [u8; 32] = scalar_pad(&(value % modulus), PRIME_LEN)
            .try_into()
            .expect("P-256 scalar length");
        Self(bytes)
    }

    pub(crate) fn scalar(&self) -> P256Scalar {
        Option::<P256Scalar>::from(P256Scalar::from_repr(FieldBytes::from(self.0)))
            .expect("validated private scalar")
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Modular inverse in the group-19 scalar field, delegated to `p256`.
pub fn mod_inverse(value: &BigUint, modulus: &BigUint) -> BigUint {
    assert_eq!(
        modulus,
        &Curve::p256().n,
        "group19 inverse requires the P-256 group order"
    );
    let scalar = scalar_to_p256(value, modulus);
    let inverse = Option::<P256Scalar>::from(scalar.invert()).expect("non-zero scalar");
    scalar_from_p256(&inverse)
}

/// The P-256 base point supplied by `p256`, converted to the public wire type.
pub fn generator() -> Point {
    point_from_p256(P256ProjectivePoint::GENERATOR)
}

pub(crate) fn scalar_pad(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; len];
    if bytes.len() <= len {
        out[len - bytes.len()..].copy_from_slice(&bytes);
    } else {
        out.copy_from_slice(&bytes[bytes.len() - len..]);
    }
    out
}

pub(crate) fn scalar_to_bin(value: &BigUint) -> Vec<u8> {
    scalar_pad(value, PRIME_LEN)
}
