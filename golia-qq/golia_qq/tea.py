"""QQ TEA (block cipher with random padding), ported from
Lagrange.Core/Utility/Cryptography/TeaProvider.cs.

This is the "QQ TEA" variant: 16 rounds, CBC-like chaining with a
random fill prefix. Cipher length = fill + data + 7 where
fill = 10 - ((len(data) + 1) & 7).
"""
from __future__ import annotations

import os
import struct

_DELTA_ROUNDS = (
    0x9E3779B9, 0x3C6EF372, 0xDAA66D2B, 0x78DDE6E4,
    0x1715609D, 0xB54CDA56, 0x5384540F, 0xF1BBCDC8,
    0x8FF34781, 0x2E2AC13A, 0xCC623AF3, 0x6A99B4AC,
    0x08D12E65, 0xA708A81E, 0x454021D7, 0xE3779B90,
)

_MASK = 0xFFFFFFFF


def _u32(x: int) -> int:
    return x & _MASK


def get_cipher_length(data_len: int) -> int:
    return (10 - ((data_len + 1) & 7)) + data_len + 7


def _tea_encrypt_block(x: int, y: int, a: int, b: int, c: int, d: int) -> tuple[int, int]:
    for delta in _DELTA_ROUNDS:
        x = _u32(x + (_u32(y + delta) ^ _u32((y << 4) + a) ^ _u32((y >> 5) + b)))
        y = _u32(y + (_u32(x + delta) ^ _u32((x << 4) + c) ^ _u32((x >> 5) + d)))
    return x, y


def _tea_decrypt_block(x: int, y: int, a: int, b: int, c: int, d: int) -> tuple[int, int]:
    for delta in reversed(_DELTA_ROUNDS):
        y = _u32(y - (_u32(x + delta) ^ _u32((x << 4) + c) ^ _u32((x >> 5) + d)))
        x = _u32(x - (_u32(y + delta) ^ _u32((y << 4) + a) ^ _u32((y >> 5) + b)))
    return x, y


def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt with QQ TEA. key must be 16 bytes."""
    assert len(key) == 16
    a, b, c, d = struct.unpack(">IIII", key)
    fill = 10 - ((len(data) + 1) & 7)
    length = fill + len(data) + 7
    dest = bytearray(os.urandom(fill)) + bytearray(data) + b"\x00" * 7
    dest[0] = (fill - 3) | 0xF8
    dest = dest[:length]

    plain_xor = 0
    prev_xor = 0
    for i in range(0, length, 8):
        plain = struct.unpack(">Q", dest[i:i + 8])[0] ^ plain_xor
        x = (plain >> 32) & _MASK
        y = plain & _MASK
        x, y = _tea_encrypt_block(x, y, a, b, c, d)
        plain_xor = (((x << 32) | y) ^ prev_xor) & 0xFFFFFFFFFFFFFFFF
        prev_xor = plain
        struct.pack_into(">Q", dest, i, plain_xor)
    return bytes(dest)


def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt QQ TEA, stripping the random fill and trailing zeros."""
    assert len(key) == 16
    a, b, c, d = struct.unpack(">IIII", key)
    dest = bytearray(data)
    plain_xor = 0
    prev_xor = 0
    for i in range(0, len(dest), 8):
        block = struct.unpack(">Q", dest[i:i + 8])[0]
        plain_xor ^= block
        x = (plain_xor >> 32) & _MASK
        y = plain_xor & _MASK
        x, y = _tea_decrypt_block(x, y, a, b, c, d)
        plain_xor = ((x << 32) | y) & 0xFFFFFFFFFFFFFFFF
        struct.pack_into(">Q", dest, i, plain_xor ^ prev_xor)
        prev_xor = block
    # fill is encoded in the DECRYPTED first byte (not the ciphertext)
    fill = (dest[0] & 7) + 3
    return bytes(dest[fill:-7])


def decrypt_raw(data: bytes, key: bytes) -> bytes:
    """Decrypt in place and return the full buffer (fill + plain + zeros).

    Mirrors TeaProvider.Decrypt(span, span, key) + CreateDecryptSpan:
    the caller strips [(first_byte & 7) + 3:] itself.
    """
    assert len(key) == 16
    a, b, c, d = struct.unpack(">IIII", key)
    dest = bytearray(data)
    plain_xor = 0
    prev_xor = 0
    for i in range(0, len(dest), 8):
        block = struct.unpack(">Q", dest[i:i + 8])[0]
        plain_xor ^= block
        x = (plain_xor >> 32) & _MASK
        y = plain_xor & _MASK
        x, y = _tea_decrypt_block(x, y, a, b, c, d)
        plain_xor = ((x << 32) | y) & 0xFFFFFFFFFFFFFFFF
        struct.pack_into(">Q", dest, i, plain_xor ^ prev_xor)
        prev_xor = block
    return bytes(dest)


def strip_fill(decrypted: bytes) -> bytes:
    """Strip the random fill prefix (and keep the rest, incl. trailing zeros)."""
    return decrypted[((decrypted[0] & 7) + 3):]
