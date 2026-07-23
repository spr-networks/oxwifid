#!/usr/bin/env python3
"""
Independent Python implementation of WPA3-SAE (group 19 / P-256) for
cross-validating the Rust implementation over the wire.

This is deliberately written from scratch (pure-Python P-256, separate from the
Rust num-bigint code) and self-checks against the IEEE 802.11-2020 Annex J.10
test vectors, so agreement between Rust and Python on random handshakes is a
genuine independent cross-check (not two copies of the same code).

Covers: H2E and hunting-and-pecking PWE, the Dragonfly commit/confirm exchange,
KCK/PMK/PMKID derivation, the SHA-256 PTK, and the SHA-256 EAPOL-Key MIC.
"""
import hashlib
import hmac
import os

# ---------------------------------------------------------------------------
# NIST P-256 (group 19)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
PRIME_LEN = 32


def inv(a, m=P):
    return pow(a, m - 2, m)


def sqrt_mod(a):
    # p == 3 (mod 4)
    return pow(a, (P + 1) // 4, P)


def is_quadratic_residue(a):
    if a == 0:
        return False
    return pow(a, (P - 1) // 2, P) == 1


# Point = None (infinity) or (x, y)
def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mul(k, pt):
    result = None
    addend = pt
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def y_sqr(x):
    return (x * x * x + A * x + B) % P


def point_to_bin(pt):
    x, y = pt
    return x.to_bytes(PRIME_LEN, "big") + y.to_bytes(PRIME_LEN, "big")


def point_from_bin(data):
    if len(data) != 2 * PRIME_LEN:
        return None
    x = int.from_bytes(data[:PRIME_LEN], "big")
    y = int.from_bytes(data[PRIME_LEN:], "big")
    if x >= P or y >= P:
        return None
    pt = (x, y)
    return pt if on_curve(pt) else None


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------
def hkdf_extract(salt, *ikm):
    h = hmac.new(salt, b"".join(ikm), hashlib.sha256)
    return h.digest()


def hkdf_expand(prk, info, length):
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def sha256_prf(key, label, context, out_len):
    out = b""
    counter = 1
    bits = (out_len * 8).to_bytes(2, "little")
    while len(out) < out_len:
        out += hmac.new(key, counter.to_bytes(2, "little") + label + context + bits, hashlib.sha256).digest()
        counter += 1
    return out[:out_len]


# ---------------------------------------------------------------------------
# SSWU + H2E PWE
# ---------------------------------------------------------------------------
def sswu(u):
    z = (P - 10) % P
    u2 = u * u % P
    t1 = z * u2 % P
    m = (t1 + t1 * t1) % P
    t = pow(m, P - 2, P)
    x1a = B * inv(z * A % P) % P
    x1b = (P - B) * inv(A) % P * ((1 + t) % P) % P
    x1 = x1a if m == 0 else x1b
    gx1 = (pow(x1, 3, P) + A * x1 + B) % P
    x2 = z * u2 % P * x1 % P
    gx2 = (pow(x2, 3, P) + A * x2 + B) % P
    if is_quadratic_residue(gx1) or gx1 == 0:
        v, x = gx1, x1
    else:
        v, x = gx2, x2
    y = sqrt_mod(v)
    if (u & 1) != (y & 1):
        y = (P - y) % P
    return (x, y)


def max_min(a1, a2):
    return (a1, a2) if a1 >= a2 else (a2, a1)


def derive_pt(ssid, password, identifier=None):
    if identifier:
        pwd_seed = hkdf_extract(ssid, password, identifier)
    else:
        pwd_seed = hkdf_extract(ssid, password)
    plen = PRIME_LEN + (PRIME_LEN + 1) // 2
    u1 = int.from_bytes(hkdf_expand(pwd_seed, b"SAE Hash to Element u1 P1", plen), "big") % P
    u2 = int.from_bytes(hkdf_expand(pwd_seed, b"SAE Hash to Element u2 P2", plen), "big") % P
    return point_add(sswu(u1), sswu(u2))


def derive_pwe_from_pt(pt, addr1, addr2):
    mx, mn = max_min(addr1, addr2)
    val = int.from_bytes(hkdf_extract(b"\x00" * 32, mx, mn), "big") % (N - 1) + 1
    return scalar_mul(val, pt)


def derive_pwe_hunting_pecking(password, addr1, addr2):
    mx, mn = max_min(addr1, addr2)
    salt = mx + mn
    prime_bytes = P.to_bytes(PRIME_LEN, "big")
    for counter in range(1, 201):
        pwd_seed = hmac.new(salt, password + bytes([counter]), hashlib.sha256).digest()
        pwd_value = sha256_prf(pwd_seed, b"SAE Hunting and Pecking", prime_bytes, PRIME_LEN)
        x = int.from_bytes(pwd_value, "big")
        if x < P and is_quadratic_residue(y_sqr(x)):
            y = sqrt_mod(y_sqr(x))
            if (y & 1) != (pwd_seed[31] & 1):
                y = (P - y) % P
            return (x, y)
    return None


# ---------------------------------------------------------------------------
# SAE state machine
# ---------------------------------------------------------------------------
SAE_GROUP_19 = 19


class Sae:
    def __init__(self, pwe):
        self.pwe = pwe
        self.rand = 0
        self.commit_scalar = 0
        self.commit_element = None
        self.peer_scalar = None
        self.peer_element = None
        self.kck = b""
        self.pmk = b""
        self.pmkid = b""
        self.send_confirm = 0

    @classmethod
    def h2e(cls, ssid, password, addr1, addr2, identifier=None):
        return cls(derive_pwe_from_pt(derive_pt(ssid, password, identifier), addr1, addr2))

    @classmethod
    def hunting_pecking(cls, password, addr1, addr2):
        pwe = derive_pwe_hunting_pecking(password, addr1, addr2)
        return cls(pwe) if pwe else None

    def prepare_commit(self, rand=None, mask=None):
        self.rand = rand if rand is not None else (int.from_bytes(os.urandom(32), "big") % N)
        mask = mask if mask is not None else (int.from_bytes(os.urandom(32), "big") % N)
        self.commit_scalar = (self.rand + mask) % N
        mp = scalar_mul(mask, self.pwe)
        self.commit_element = (mp[0], (P - mp[1]) % P)  # inverse(mask*PWE)

    def write_commit(self):
        return (
            SAE_GROUP_19.to_bytes(2, "little")
            + self.commit_scalar.to_bytes(PRIME_LEN, "big")
            + point_to_bin(self.commit_element)
        )

    def parse_peer_commit(self, body):
        if len(body) < 2 + 3 * PRIME_LEN:
            return False
        if int.from_bytes(body[:2], "little") != SAE_GROUP_19:
            return False
        scalar = int.from_bytes(body[2 : 2 + PRIME_LEN], "big")
        if scalar <= 1 or scalar >= N:
            return False
        element = point_from_bin(body[2 + PRIME_LEN : 2 + 3 * PRIME_LEN])
        if element is None:
            return False
        self.peer_scalar = scalar
        self.peer_element = element
        return True

    def process_commit(self):
        k1 = scalar_mul(self.peer_scalar, self.pwe)
        k2 = point_add(k1, self.peer_element)
        big_k = scalar_mul(self.rand, k2)
        if big_k is None:
            return False
        k = big_k[0].to_bytes(PRIME_LEN, "big")
        keyseed = hkdf_extract(b"\x00" * 32, k)
        context = ((self.commit_scalar + self.peer_scalar) % N).to_bytes(PRIME_LEN, "big")
        keys = sha256_prf(keyseed, b"SAE KCK and PMK", context, 64)
        self.kck = keys[:32]
        self.pmk = keys[32:64]
        self.pmkid = context[:16]
        return True

    def _cn(self, sc, s1, e1, s2, e2):
        data = sc.to_bytes(2, "little") + s1.to_bytes(PRIME_LEN, "big") + point_to_bin(e1) + s2.to_bytes(PRIME_LEN, "big") + point_to_bin(e2)
        return hmac.new(self.kck, data, hashlib.sha256).digest()

    def write_confirm(self):
        self.send_confirm = min(self.send_confirm + 1, 0xFFFF)
        confirm = self._cn(self.send_confirm, self.commit_scalar, self.commit_element, self.peer_scalar, self.peer_element)
        return self.send_confirm.to_bytes(2, "little") + confirm

    def check_confirm(self, data):
        if len(data) < 2 + 32:
            return False
        sc = int.from_bytes(data[:2], "little")
        verifier = self._cn(sc, self.peer_scalar, self.peer_element, self.commit_scalar, self.commit_element)
        return hmac.compare_digest(verifier, data[2 : 2 + 32])


def derive_ptk_sha256(pmk, aa, spa, anonce, snonce):
    mlo, mhi = (aa, spa) if aa <= spa else (spa, aa)
    nlo, nhi = (anonce, snonce) if anonce <= snonce else (snonce, anonce)
    ctx = mlo + mhi + nlo + nhi
    return sha256_prf(pmk, b"Pairwise key expansion", ctx, 48)


def eapol_mic_sha256(kck, frame):
    # WPA3-SAE (AKM 00-0F-AC:8, Key Descriptor Version 0) computes the EAPOL-Key
    # MIC with AES-128-CMAC over the frame, NOT HMAC-SHA-256. (reference AP: "EAPOL-Key
    # MIC using AES-CMAC (AKM-defined - SAE)".)
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms

    c = cmac.CMAC(algorithms.AES(bytes(kck)))
    c.update(bytes(frame))
    return c.finalize()[:16]


# ---------------------------------------------------------------------------
# Self-test against IEEE 802.11-2020 Annex J.10
# ---------------------------------------------------------------------------
def _selftest():
    addr1 = bytes.fromhex("4d3f2fffe387")
    addr2 = bytes.fromhex("a5d8aa958e3c")
    addr1b = bytes.fromhex("00095b66ec1e")
    addr2b = bytes.fromhex("000b6bd90246")
    pwe19_x = "c93049b9e64000f848201649e999f2b5c22dea69b5632c9df4d633b8aa1f6c1e"
    pwe19_y = "73634e94b53d82e7383a8d258199d9dc1a5ee8269d060382ccbf33e614ff59a0"
    # H2E PWE
    pt = derive_pt(b"byteme", b"mekmitasdigoat", b"psk4internet")
    pwe = derive_pwe_from_pt(pt, addr1b, addr2b)
    assert pwe[0].to_bytes(32, "big").hex() == pwe19_x, "H2E PWE.x"
    assert pwe[1].to_bytes(32, "big").hex() == pwe19_y, "H2E PWE.y"

    # Hunting-and-pecking + protocol
    rand = int.from_bytes(bytes.fromhex("992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94"), "big")
    mask = int.from_bytes(bytes.fromhex("9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322"), "big")
    hnp = derive_pwe_hunting_pecking(b"mekmitasdigoat", addr1, addr2)
    sae = Sae(hnp)
    sae.prepare_commit(rand, mask)
    local_commit = "13002e2c0f0db52440ad146d967114ce005ce1eab0aa2c2e5c2871b774f6c2575c65d5ad9e00829707aa36ba8b859738fc961d08243505f47c035376d7ac4bc8d7b95083bf43827d0fc31ed778dd3671fd21a46d1091d64b6f9a1e1272621325dbe1"
    assert sae.write_commit().hex() == local_commit, "H&P commit"
    peer_commit = "1300591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2"
    assert sae.parse_peer_commit(bytes.fromhex(peer_commit)), "parse peer"
    assert sae.process_commit(), "process"
    assert sae.kck.hex() == "1e733f6d9bd53256287304338831b09a39406d121017073a5c30db36f36cb81a", "KCK"
    assert sae.pmk.hex() == "4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59", "PMK"
    assert sae.pmkid.hex() == "8747a600eea3f9f22475df58ca1e5498", "PMKID"
    return True


if __name__ == "__main__":
    print("J.10 self-test:", _selftest())
