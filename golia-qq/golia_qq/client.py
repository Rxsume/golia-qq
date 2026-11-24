"""golia-qq: minimal QQ protocol client (own implementation).

Milestone 1: fetch the login QR code (TransEmp31) and save it as PNG.
"""
from __future__ import annotations

import logging

from . import sso, wtlogin
from .transport import Transport
from .wtlogin import Keystore, WtLogin

log = logging.getLogger("golia-qq")

COMMAND_TRANS_EMP = "wtlogin.trans_emp"


class QQClient:
    def __init__(self, keystore: Keystore | None = None, timeout: float = 20.0):
        self.ks = keystore or Keystore()
        self.wt = WtLogin(self.ks)
        self.seq = sso.SeqGen()
        self.transport = Transport(timeout=timeout)
        self.server = ""

    def connect(self) -> str:
        self.server = self.transport.connect()
        log.info("connected to SSO server %s:8080", self.server)
        return self.server

    def close(self) -> None:
        self.transport.close()

    def _roundtrip(self, command: str, oicq_body: bytes) -> bytes:
        """Send one OICQ body wrapped in SSO+Service, return the OICQ body."""
        seq = self.seq.next()
        sso_packet = sso.build_sso12(seq, command, oicq_body, self.ks.guid,
                                     uid=self.ks.uid)
        frame = sso.build_service12(sso_packet, uin=self.ks.uin)
        log.debug("-> %s seq=%d frame=%dB oicq=%dB", command, seq, len(frame), len(oicq_body))
        self.transport.send(frame)
        raw = self.transport.recv_frame()
        log.debug("<- frame %dB", len(raw))
        sso_bytes = sso.parse_service(raw, d2_key=self.ks.d2_key)
        parsed = sso.parse_sso(sso_bytes)
        if parsed["ret_code"] != 0:
            raise RuntimeError(
                f"SSO {command} ret={parsed['ret_code']} extra={parsed['extra']!r}")
        if parsed["sequence"] != seq:
            log.warning("sequence mismatch: sent %d got %d", seq, parsed["sequence"])
        body, cmd = self.wt.parse(parsed["payload"])
        log.debug("<- oicq cmd=%#x body=%dB", cmd, len(body))
        return body

    def fetch_qr(self) -> dict:
        """TransEmp31: get login QR code. Returns parse_trans_emp31 dict."""
        oicq = self.wt.build_trans_emp31()
        body = self._roundtrip(COMMAND_TRANS_EMP, oicq)
        inner, cmd = self.wt.parse_code2d(body)
        if cmd != 0x31:
            raise RuntimeError(f"unexpected trans_emp command {cmd:#x}")
        result = wtlogin.parse_trans_emp31(inner)
        if result["qr_sig"]:
            self.ks.qr_sig = result["qr_sig"]
        return result

    def poll_qr(self) -> dict:
        """TransEmp12: poll QR scan state."""
        oicq = self.wt.build_trans_emp12()
        body = self._roundtrip(COMMAND_TRANS_EMP, oicq)
        inner, cmd = self.wt.parse_code2d(body)
        if cmd != 0x12:
            raise RuntimeError(f"unexpected trans_emp command {cmd:#x}")
        return wtlogin.parse_trans_emp12(inner)
