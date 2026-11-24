"""QQ WtLogin packet builder/parser, ported from Lagrange.Core.

Reference (read-only):
- Lagrange.Core/Internal/Packets/Login/WtLogin.cs
- Lagrange.Core/Internal/Packets/Login/TlvQrCode.cs
- Lagrange.Core/Internal/Packets/Login/QrLoginExtInfo.cs
- Lagrange.Core/Common/BotAppInfo.cs (Windows protocol)
- Lagrange.Core/Common/BotKeystore.cs
- Lagrange.Core/Utility/ProtocolHelper.cs (TlvUnPack)

Protocol: Windows (PC) — AppId 1600001604.
"""
from __future__ import annotations

import hashlib
import os
import random
import struct
import time

from . import proto, tea
from .binary import Packet, P_INT8, P_INT16, P_INT32, P_LENGTH_ONLY, P_WITH_PREFIX
from .ecdh import Ecdh

# ---- Protocol AppInfo profiles (Lagrange.Core/Common/BotAppInfo.cs) ----
# Windows (PC) is Lagrange's default but the project is "out of updating"
# and its 9.9.19 QR login is rejected by Tencent ("扫码授权失败" on both
# VM and router, 2026-11-24). Lagrange itself recommends the Linux
# protocol (its sign server only implements Linux). Linux profile:
# AppId 1600001615, SubAppId 537345891, 3.2.26-46494, SsoVersion 19.
from dataclasses import dataclass


@dataclass(frozen=True)
class Proto:
    name: str
    app_id: int
    sub_app_id: int
    sso_version: int
    current_version: str
    pt_version: str
    package_name: str
    misc_bitmap: int
    app_client_version: int
    os_name: str


PROTOCOLS: dict[str, Proto] = {
    "windows": Proto(
        name="windows",
        app_id=1600001604,
        sub_app_id=537291048,
        sso_version=23,
        current_version="9.9.19-35184",
        pt_version="2.0.0",
        package_name="com.tencent.qq",
        misc_bitmap=12058620,
        app_client_version=35184,
        os_name="Windows",
    ),
    "linux": Proto(
        name="linux",
        app_id=1600001615,
        sub_app_id=537345891,
        sso_version=19,
        current_version="3.2.26-46494",
        pt_version="2.0.0",
        package_name="com.tencent.qq",
        misc_bitmap=32764,
        app_client_version=46494,
        os_name="Linux",
    ),
}

# Default profile (Windows) kept for compatibility; webui/fetch_qr default to Linux.
APP_ID = PROTOCOLS["windows"].app_id
SUB_APP_ID = PROTOCOLS["windows"].sub_app_id
SSO_VERSION = PROTOCOLS["windows"].sso_version
CURRENT_VERSION = PROTOCOLS["windows"].current_version
PT_VERSION = PROTOCOLS["windows"].pt_version
PACKAGE_NAME = PROTOCOLS["windows"].package_name
MISC_BITMAP = PROTOCOLS["windows"].misc_bitmap
APP_CLIENT_VERSION = PROTOCOLS["windows"].app_client_version
OS_NAME = PROTOCOLS["windows"].os_name

# QQ server ECDH public key (uncompressed, from WtLogin.cs)
SERVER_PUBKEY = bytes([
    0x04, 0x92, 0x8D, 0x88, 0x50, 0x67, 0x30, 0x88, 0xB3, 0x43, 0x26, 0x4E,
    0x0C, 0x6B, 0xAC, 0xB8, 0x49, 0x6D, 0x69, 0x77, 0x99, 0xF3, 0x72, 0x11,
    0xDE, 0xB2, 0x5B, 0xB7, 0x39, 0x06, 0xCB, 0x08, 0x9F, 0xEA, 0x96, 0x39,
    0xB4, 0xE0, 0x26, 0x04, 0x98, 0xB5, 0x1A, 0x99, 0x2D, 0x50, 0x81, 0x3D,
    0xA8,
])

EM_ST = 0x45
EM_ECDH = 0x07
EM_ECDH_ST = 0x87


class Keystore:
    """Minimal keystore: device identity + session keys."""

    def __init__(self, device_name: str | None = None, protocol: str = "windows"):
        self.proto: Proto = PROTOCOLS[protocol]
        self.uin: int = 0
        self.uid: str = ""
        self.guid: bytes = os.urandom(16)
        self.device_name = device_name or f"Golia-{random.randint(0, 0xFFFFFF):06X}"
        self.random_key: bytes = os.urandom(16)
        self.ecdh = Ecdh()
        self.share_key: bytes = self.ecdh.key_exchange(SERVER_PUBKEY, True)
        # WLogin sigs (filled after login)
        self.a2: bytes = b""
        self.a2_key: bytes = bytes(16)
        self.d2: bytes = b""
        self.d2_key: bytes = bytes(16)
        self.a1: bytes = b""
        self.no_pic_sig: bytes = b""
        self.tgtgt_key: bytes = b""
        self.st_key: bytes = b""
        self.st: bytes = b""
        self.wt_session_ticket: bytes = b""
        self.wt_session_ticket_key: bytes = b""
        self.qr_sig: bytes | None = None


def tlv_unpack(reader: Packet) -> dict[int, bytes]:
    count = reader.read_u16()
    out: dict[int, bytes] = {}
    for _ in range(count):
        tag = reader.read_u16()
        length = reader.read_u16()
        out[tag] = reader.read_bytes(length)
    return out


class _TlvQrCode:
    """TLV builder for QR login (mirrors TlvQrCode)."""

    def __init__(self, ks: Keystore):
        self._ks = ks
        self._w = Packet()
        self._w.skip(2)  # room for count
        self._count = 0

    def _start(self, tag: int) -> None:
        self._w.write_u16(tag)
        self._w.enter_barrier(2)
        self._count += 1

    def _end(self) -> None:
        self._w.exit_barrier(include_prefix=False)

    def tlv16(self) -> None:
        p = self._ks.proto
        self._start(0x16)
        self._w.write_u32(0)
        self._w.write_u32(p.app_id)
        self._w.write_u32(p.sub_app_id)
        self._w.write(self._ks.guid)
        self._w.write_str(p.package_name, P_INT16 | P_LENGTH_ONLY)
        self._w.write_str(p.pt_version, P_INT16 | P_LENGTH_ONLY)
        self._w.write_str(p.package_name, P_INT16 | P_LENGTH_ONLY)
        self._end()

    def tlv1b(self) -> None:
        self._start(0x1B)
        for v in (0, 0, 3, 4, 72, 2, 2):
            self._w.write_u32(v)
        self._w.write_u16(0)
        self._end()

    def tlv1d(self) -> None:
        p = self._ks.proto
        self._start(0x1D)
        self._w.write_u8(1)
        self._w.write_u32(p.misc_bitmap)
        self._w.write_u32(0)
        self._w.write_u8(0)
        self._end()

    def tlv33(self) -> None:
        self._start(0x33)
        self._w.write(self._ks.guid)
        self._end()

    def tlv35(self) -> None:
        self._start(0x35)
        self._w.write_u32(self._ks.proto.sso_version)
        self._end()

    def tlv66(self) -> None:
        self._start(0x66)
        self._w.write_u32(self._ks.proto.sso_version)
        self._end()

    def tlv_d1(self) -> None:
        p = self._ks.proto
        self._start(0xD1)
        qr_ext = proto.encode_message({
            1: {1: p.os_name, 2: self._ks.device_name},
            4: {6: 1},
        })
        self._w.write(qr_ext)
        self._end()

    def build(self) -> bytes:
        self._w.write_at_u16(self._count, 0)
        return self._w.bytes()


class WtLogin:
    def __init__(self, ks: Keystore):
        self.ks = ks

    # ---- builders ----
    def build_trans_emp31(self, unusual_sig: bytes | None = None) -> bytes:
        w = Packet()
        w.write_u16(0)
        w.write_u32(self.ks.proto.app_id)
        w.write_u64(0)
        w.write(b"")  # TGT
        w.write_u8(0)
        w.write_bytes_prefixed(b"", P_INT16 | P_LENGTH_ONLY)
        tlvs = _TlvQrCode(self.ks)
        tlvs.tlv16()
        tlvs.tlv1b()
        tlvs.tlv1d()
        tlvs.tlv33()
        tlvs.tlv35()
        tlvs.tlv66()
        tlvs.tlv_d1()
        w.write(tlvs.build())
        return self._build_code2d(0x31, w.bytes(), EM_ECDH_ST)

    def build_trans_emp12(self) -> bytes:
        w = Packet()
        w.write_u16(0)
        w.write_u32(self.ks.proto.app_id)
        w.write_bytes_prefixed(self.ks.qr_sig or b"", P_INT16 | P_LENGTH_ONLY)
        w.write_u64(0)
        w.write(b"")  # TGT
        w.write_u8(0)
        w.write_bytes_prefixed(b"", P_INT16 | P_LENGTH_ONLY)
        w.write_u16(0)  # tlv count = 0
        return self._build_code2d(0x12, w.bytes(), EM_ECDH_ST)

    def _build_code2d(self, command: int, tlv: bytes, method: int,
                      encrypt: bool = False) -> bytes:
        req = Packet()
        req.write_u32(int(time.time()))
        req.write_u8(2)
        req.enter_barrier(2)
        req.write_u16(command)
        req.skip(21)
        req.write_u8(3)
        req.write_u16(0)
        req.write_u16(0x32)
        req.write_u32(0)
        req.write_u64(self.ks.uin)
        req.write(tlv)
        req.write_u8(3)
        req.exit_barrier(include_prefix=True, addition=1)
        req_span = req.bytes()
        if encrypt:
            req_span = tea.encrypt(req_span, self.ks.st_key)
        w = Packet()
        w.write_u8(1 if encrypt else 0)
        w.write_u16(len(req_span))
        w.write_u32(self.ks.proto.app_id)
        w.write_u32(0x72)
        w.write_bytes_prefixed(self.ks.st if encrypt else b"", P_INT16 | P_LENGTH_ONLY)
        w.write_bytes_prefixed(b"", P_INT8 | P_LENGTH_ONLY)
        w.write(req_span)
        return self._build_packet(0x812, w.bytes(), method)

    def _build_packet(self, command: int, payload: bytes, method: int) -> bytes:
        if method in (EM_ECDH, EM_ECDH_ST):
            key = self.ks.share_key
        elif method == EM_ST:
            key = self.ks.random_key
        else:
            raise ValueError(f"unknown encrypt method {method:#x}")
        cipher = tea.encrypt(payload, key)
        w = Packet()
        w.write_u8(2)
        w.enter_barrier(2)
        w.write_u16(8001)
        w.write_u16(command)
        w.write_u16(0)  # sequence
        w.write_u32(self.ks.uin)
        w.write_u8(3)
        w.write_u8(method)
        w.write_u32(0)
        w.write_u8(2)
        w.write_u16(0)  # insId
        w.write_u16(self.ks.proto.app_client_version)
        w.write_u32(0)  # retryTime
        # encrypt head (no wt session)
        w.write_u8(1)
        w.write_u8(1)
        w.write(self.ks.random_key)
        w.write_u16(0x102)
        w.write_bytes_prefixed(self.ks.ecdh.pack_public(True), P_INT16 | P_LENGTH_ONLY)
        w.write(cipher)
        w.write_u8(3)
        w.exit_barrier(include_prefix=True, addition=1)
        return w.bytes()

    # ---- parsers ----
    def parse(self, data: bytes) -> tuple[bytes, int]:
        """Parse an OICQ packet. Returns (decrypted body, command)."""
        r = Packet(data)
        r.read_u8()  # header
        r.read_u16()  # length
        r.read_u16()  # version
        command = r.read_u16()
        r.read_u16()  # sequence
        r.read_u32()  # uin
        r.read_u8()  # flag
        encrypt_type = r.read_u8()
        state = r.read_u8()
        encrypted = r.read_rest()[:-1]  # drop trailing 0x03
        if encrypt_type == 0:
            key = self.ks.random_key if state == 180 else self.ks.share_key
        elif encrypt_type == 3:
            key = self.ks.wt_session_ticket_key
        elif encrypt_type == 4:
            # EM_ECDH_ST: outer TEA (share_key) -> [server ECDH pubkey][inner TEA].
            # tea.decrypt strips the fill prefix AND the 7 trailing zeros
            # (Lagrange TeaProvider.Decrypt does the same); using decrypt_raw
            # here leaves the 7 trailing zeros in, breaking the inner length.
            raw = tea.decrypt(encrypted, self.ks.share_key)
            raw_r = Packet(raw)
            pub = raw_r.read_bytes_prefixed(P_INT16 | P_LENGTH_ONLY)
            key = self.ks.ecdh.key_exchange(pub, True)
            encrypted = raw_r.read_rest()
        else:
            raise ValueError(f"unknown encrypt type {encrypt_type}")
        plain = tea.decrypt(encrypted, key)
        return plain, command

    def parse_code2d(self, data: bytes) -> tuple[bytes, int]:
        """Parse the code2d wrapper. Returns (inner body, command)."""
        encrypt = data[1]
        layer = struct.unpack(">H", data[2:4])[0]
        span = data[5:5 + layer]
        if encrypt == 1:
            span = tea.decrypt(span, self.ks.st_key)
        r = Packet(span)
        r.read_u8()  # header
        r.read_u16()  # length
        command = r.read_u16()
        r.skip(21)
        r.read_u8()  # flag
        r.read_u16()  # retryTime
        r.read_u16()  # version
        r.read_u32()  # sequence
        r.read_u64()  # uin
        return r.read_rest(), command


def parse_trans_emp31(body: bytes) -> dict:
    """Parse TransEmp31 response body -> {url, image, qr_sig, ret_code}."""
    r = Packet(body)
    r.read_i16()  # dummy
    r.read_i32()  # appId
    ret_code = r.read_u8()
    sig = r.read_bytes_prefixed(P_INT16 | P_LENGTH_ONLY)
    tlvs = tlv_unpack(r)
    qr_url = ""
    if 0xD1 in tlvs:
        d1 = proto.decode_message(tlvs[0xD1])
        qr_url = proto.get_str(d1, 2)
    return {
        "ret_code": ret_code,
        "qr_sig": bytes(sig),
        "qr_url": qr_url,
        "image": bytes(tlvs.get(0x17, b"")),
    }


def parse_trans_emp12(body: bytes) -> dict:
    """Parse TransEmp12 response body -> {ret_code/state, uin, tgtgt_key, no_pic_sig, temp_pw}.

    Returns both "ret_code" and "state" (same value) — callers use either key.
    """
    r = Packet(body)
    r.read_i16()  # dummy
    r.read_i32()  # appId
    ret_code = r.read_u8()
    if ret_code != 0:
        return {"ret_code": ret_code, "state": ret_code, "uin": 0}
    uin = r.read_i64()
    r.read_i32()  # retry
    tlvs = tlv_unpack(r)
    return {
        "ret_code": ret_code,
        "state": ret_code,
        "uin": uin,
        "tgtgt_key": bytes(tlvs.get(0x1E, b"")),
        "no_pic_sig": bytes(tlvs.get(0x19, b"")),
        "temp_password": bytes(tlvs.get(0x18, b"")),
    }
