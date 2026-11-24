"""SSO + Service packet framing, ported from Lagrange.Core.

Reference:
- Lagrange.Core/Internal/Packets/Struct/SsoPacker.cs
- Lagrange.Core/Internal/Packets/Struct/ServicePacker.cs
- Lagrange.Core/Internal/Context/ServiceContext.cs (sequence)
"""
from __future__ import annotations

import random
import secrets
import string
import zlib

from . import proto, tea
from .binary import Packet, P_INT16, P_INT32, P_WITH_PREFIX
from .wtlogin import SUB_APP_ID, CURRENT_VERSION

ZERO_KEY = bytes(16)

_HEX = "0123456789abcdef"


def _trace_parent() -> str:
    rand = lambda n: "".join(secrets.choice(_HEX) for _ in range(n))
    return f"01-{rand(32)}-{rand(16)}-01"


def _sso_reserve_fields(uid: str = "", sec_info: bytes | None = None) -> bytes:
    fields: dict[int, object] = {15: _trace_parent()}
    if uid:
        fields[16] = uid
    if sec_info is not None:
        fields[24] = sec_info
    return proto.encode_message(fields)


def build_sso12(sequence: int, command: str, data: bytes, guid: bytes,
                uid: str = "", sec_info: bytes | None = None) -> bytes:
    """Build SSO protocol-12 packet (head + payload, each int32-prefixed)."""
    head = Packet()
    head.write_u32(sequence)
    head.write_u32(SUB_APP_ID)
    head.write_u32(2052)
    head.write(bytes([0x02]) + bytes(11))  # 12-byte field, first byte 0x02 (Lagrange SsoPacker)
    head.write_bytes_prefixed(b"", P_INT32 | P_WITH_PREFIX)  # A2 (tgt)
    head.write_str(command, P_INT32 | P_WITH_PREFIX)
    head.write_bytes_prefixed(b"", P_INT32 | P_WITH_PREFIX)  # message_cookies
    head.write_str(guid.hex(), P_INT32 | P_WITH_PREFIX)
    head.write_bytes_prefixed(b"", P_INT32 | P_WITH_PREFIX)
    head.write_str(CURRENT_VERSION, P_INT16 | P_WITH_PREFIX)
    head.enter_barrier(4)
    head.write(_sso_reserve_fields(uid, sec_info))
    head.exit_barrier(include_prefix=True)
    head_span = head.bytes()

    out = Packet()
    out.write_bytes_prefixed(head_span, P_INT32 | P_WITH_PREFIX)
    out.write_bytes_prefixed(data, P_INT32 | P_WITH_PREFIX)
    return out.bytes()


def parse_sso(data: bytes) -> dict:
    """Parse an SSO packet -> {command, sequence, ret_code, extra, payload}."""
    r = Packet(data)
    head = r.read_bytes_prefixed(P_INT32 | P_WITH_PREFIX)
    body = r.read_bytes_prefixed(P_INT32 | P_WITH_PREFIX)
    h = Packet(head)
    sequence = h.read_i32()
    ret_code = h.read_i32()
    extra = h.read_str_prefixed(P_INT32 | P_WITH_PREFIX)
    command = h.read_str_prefixed(P_INT32 | P_WITH_PREFIX)
    h.read_bytes_prefixed(P_INT32 | P_WITH_PREFIX)  # msgCookie
    data_flag = h.read_i32()
    h.read_bytes_prefixed(P_INT32 | P_WITH_PREFIX)  # reserveField
    if data_flag in (0, 4):
        payload = bytes(body)
    elif data_flag == 1:
        payload = zlib.decompress(bytes(body))
    else:
        raise ValueError(f"unknown sso data_flag {data_flag}")
    return {
        "command": command,
        "sequence": sequence,
        "ret_code": ret_code,
        "extra": extra,
        "payload": payload,
    }


def build_service12(sso: bytes, uin: int = 0) -> bytes:
    """Wrap an SSO packet in the Service protocol-12 frame (EncryptEmpty).

    This output is the complete TCP frame (4-byte length prefix included).
    """
    cipher = tea.encrypt(sso, ZERO_KEY)
    w = Packet()
    w.enter_barrier(4)
    w.write_u32(12)
    w.write_u8(2)  # EncryptType.EncryptEmpty (Lagrange enum: 0=NoEncrypt, 1=D2Key, 2=Empty)
    w.write_u32(4)
    w.write_u8(0)
    w.write_str(str(uin), P_INT32 | P_WITH_PREFIX)
    w.write(cipher)
    w.exit_barrier(include_prefix=True)
    return w.bytes()


def parse_service(data: bytes, d2_key: bytes | None = None) -> bytes:
    """Parse a Service frame -> decrypted SSO packet bytes.

    Auth flag enum (Lagrange.Core BotSsoPacket.EncryptType, live-verified
    2026-11-24: the TransEmp31 reply comes back with flag 2):
    0 = NoEncrypt, 1 = EncryptD2Key (TEA with the session D2Key),
    2 = EncryptEmpty (TEA with the 16 zero bytes).
    """
    r = Packet(data)
    r.read_u32()  # length
    protocol = r.read_i32()
    if protocol != 12:
        raise ValueError(f"unexpected service protocol {protocol}")
    auth_flag = r.read_u8()
    r.read_u8()  # dummy
    uin_len = r.read_i32()
    r.read_bytes(uin_len - 4)  # uin string
    rest = r.read_rest()
    if auth_flag == 0:
        return rest
    if auth_flag == 2:  # EncryptEmpty
        return tea.decrypt(rest, ZERO_KEY)
    if auth_flag == 1:  # EncryptD2Key
        if not d2_key:
            raise ValueError("service flag 1 needs a D2Key, none set yet")
        return tea.decrypt(rest, d2_key)
    raise ValueError(f"unsupported service auth flag {auth_flag}")


class SeqGen:
    """SSO sequence: random start in [5000000, 9900000), +1, wrap."""

    def __init__(self):
        self._seq = random.randint(5000000, 9900000)

    def next(self) -> int:
        self._seq += 1
        if self._seq >= 9900000:
            self._seq = 5000000
        return self._seq
