"""TCP transport to QQ SSO servers.

The VM's local DNS returns fake 198.18.x.x IPs for msfwifi.3g.qq.com,
so we resolve the real IPs via DNS-over-HTTPS (Cloudflare / Google)
and fall back to the system resolver.
"""
from __future__ import annotations

import json
import socket
import struct
import urllib.request

HOST = "msfwifi.3g.qq.com"
PORT = 8080

_DOH_URLS = [
    "https://cloudflare-dns.com/dns-query?name={host}&type=A",
    "https://dns.google/resolve?name={host}&type=A",
]


def resolve_real_ips(host: str = HOST) -> list[str]:
    ips: list[str] = []
    for url in _DOH_URLS:
        try:
            req = urllib.request.Request(
                url.format(host=host),
                headers={"Accept": "application/dns-json"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
            for ans in data.get("Answer", []):
                if ans.get("type") == 1 and ans.get("data"):
                    ips.append(ans["data"])
            if ips:
                return sorted(set(ips))
        except Exception:
            continue
    # fallback: system resolver
    try:
        infos = socket.getaddrinfo(host, PORT, socket.AF_INET, socket.SOCK_STREAM)
        return sorted({i[4][0] for i in infos})
    except Exception:
        return []


class Transport:
    def __init__(self, timeout: float = 15.0):
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.server: str = ""

    def connect(self) -> str:
        ips = resolve_real_ips()
        last_err: Exception | None = None
        for ip in ips:
            try:
                s = socket.create_connection((ip, PORT), timeout=self.timeout)
                s.settimeout(self.timeout)
                self.sock = s
                self.server = ip
                return ip
            except Exception as e:
                last_err = e
        raise ConnectionError(f"could not connect to any SSO server {ips}: {last_err}")

    def send(self, frame: bytes) -> None:
        assert self.sock is not None
        self.sock.sendall(frame)

    def recv_frame(self) -> bytes:
        """Read one length-prefixed frame (length includes the 4 header bytes)."""
        assert self.sock is not None
        header = self._recv_exact(4)
        total = struct.unpack(">I", header)[0]
        if total < 4 or total > 64 * 1024 * 1024:
            raise ValueError(f"bad frame length {total}")
        rest = self._recv_exact(total - 4)
        return header + rest

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock is not None
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed by server")
            buf += chunk
        return bytes(buf)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
