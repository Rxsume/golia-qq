"""secp192k1 ECDH, ported from Lagrange.Core/Utility/Cryptography/EcdhProvider.cs.

Curve (from the C# source; byte arrays there are little-endian):
  P = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37
  A = 0, B = 3
  Gx = 7D6CE0EAB1D1A51D34F4B780027DB026AEE957C00EF14FDB
  Gy = 9D2F5ED988AA82403486BE15D0634184A728569C6D2F2F9B
  N = 8DFDDE746A46690F17FCF226FEFFFFFFFFFFFFFFFFFFFFFF
  Size = 24 bytes, PackSize = 24
"""
from __future__ import annotations

import hashlib
import secrets

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37
A = 0
B = 3
Gx = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D
Gy = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
N = 0xFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
SIZE = 24
PACK_SIZE = 24


def _mod(a: int) -> int:
    r = a % P
    return r + P if r < 0 else r


def _modinv(a: int) -> int:
    # Extended Euclidean Algorithm (mirrors EcdhProvider.ModInverse)
    a = a % P
    t, new_t = 0, 1
    r, new_r = P, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r > 1:
        raise ValueError("inverse does not exist")
    return t + P if t < 0 else t


def _jac_double(pt):
    x, y, z = pt
    if z == 0:
        return pt
    yy = _mod(y * y)
    s = _mod(4 * x * yy)
    m = _mod(3 * x * x + A * z * z * z * z)
    x3 = _mod(m * m - 2 * s)
    y3 = _mod(m * (s - x3) - 8 * yy * yy)
    z3 = _mod(2 * y * z)
    return (x3, y3, z3)


def _jac_add(p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    z1z1 = _mod(p1[2] * p1[2])
    z2z2 = _mod(p2[2] * p2[2])
    u1 = _mod(p1[0] * z2z2)
    u2 = _mod(p2[0] * z1z1)
    s1 = _mod(p1[1] * p2[2] * z2z2)
    s2 = _mod(p2[1] * p1[2] * z1z1)
    if u1 == u2:
        if s1 == s2:
            return _jac_double(p1)
        return (0, 1, 0)  # point at infinity
    h = _mod(u2 - u1)
    hh = _mod(h * h)
    hhh = _mod(h * hh)
    r = _mod(s2 - s1)
    v = _mod(u1 * hh)
    x3 = _mod(r * r - hhh - 2 * v)
    y3 = _mod(r * (v - x3) - s1 * hhh)
    z3 = _mod(p1[2] * p2[2] * h)
    return (x3, y3, z3)


def _jac_to_affine(pt):
    x, y, z = pt
    if z == 0:
        return (0, 0)
    z_inv = _modinv(z)
    z_inv2 = _mod(z_inv * z_inv)
    z_inv3 = _mod(z_inv2 * z_inv)
    return (_mod(x * z_inv2), _mod(y * z_inv3))


def _scalar_mult(k: int, point) -> tuple[int, int]:
    if k % N == 0 or point == (0, 0):
        return (0, 0)
    if k < 0:
        return _scalar_mult(-k, point)
    pr = (0, 1, 0)  # infinity
    pa = (point[0], point[1], 1)
    while k > 0:
        if k & 1:
            pr = _jac_add(pr, pa)
        pa = _jac_double(pa)
        k >>= 1
    return _jac_to_affine(pr)


def _check_on(point) -> bool:
    x, y = point
    return (y * y - x * x * x - A * x - B) % P == 0


def _unpack_public(pub: bytes) -> tuple[int, int]:
    if len(pub) not in (SIZE * 2 + 1, SIZE + 1):
        raise ValueError("public key length does not match")
    if pub[0] == 0x04:
        x = int.from_bytes(pub[1:SIZE + 1], "big")
        y = int.from_bytes(pub[SIZE + 1:], "big")
        return (x, y)
    # compressed: recover y from y^2 = x^3 + ax + b
    px = int.from_bytes(pub[1:], "big")
    right = (px * px * px + A * px + B) % P
    py = pow(right, (P + 1) >> 2, P)
    if not ((py % 2 == 0 and pub[0] == 0x02) or (py % 2 == 1 and pub[0] == 0x03)):
        py = P - py
    return (px, py)


class Ecdh:
    """secp192k1 key pair + ECDH, mirroring EcdhProvider."""

    def __init__(self, secret: int | None = None):
        if secret is None:
            while True:
                secret = int.from_bytes(secrets.token_bytes(SIZE), "big")
                if 1 <= secret < N:
                    break
        self.secret = secret
        self.public = _scalar_mult(secret, (Gx, Gy))

    def key_exchange(self, peer_pub: bytes, is_hash: bool = True) -> bytes:
        shared = _scalar_mult(self.secret, _unpack_public(peer_pub))
        x = shared[0].to_bytes(SIZE, "big")
        if not is_hash:
            return x
        return hashlib.md5(x[:PACK_SIZE]).digest()

    def pack_public(self, compress: bool = True) -> bytes:
        x, y = self.public
        if compress:
            prefix = 0x02 if y % 2 == 0 else 0x03
            return bytes([prefix]) + x.to_bytes(SIZE, "big")
        return b"\x04" + x.to_bytes(SIZE, "big") + y.to_bytes(SIZE, "big")
