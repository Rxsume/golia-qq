#!/usr/bin/env python3
"""Simple web panel for golia-qq QR login. Pure stdlib, no dependencies.

Run on the router:  python3 webui.py [--port 6198] [--host 0.0.0.0]
Then open http://192.168.31.2:6198/ on the LAN and scan the QR with QQ.

Endpoints:
  GET  /            -> HTML page (QR + status + refresh button)
  GET  /qr.png      -> current QR PNG (no-cache)
  GET  /api/status  -> JSON {state, message, uin, qr_age}
  POST /api/refresh -> fetch a new QR in the background

States: idle, fetching, waiting, scanned, confirmed, expired, timeout, error
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from golia_qq.client import QQClient  # noqa: E402

LOG = logging.getLogger("webui")

# Shared state, guarded by LOCK.
LOCK = threading.Lock()
STATE = {
    "state": "idle",      # idle/fetching/waiting/scanned/confirmed/expired/timeout/error
    "message": "点“刷新二维码”取一个新码",
    "uin": None,
    "qr_age": None,       # seconds since the current QR was fetched
    "qr_ready": False,
}
QR_IMAGE: bytes | None = None
QR_FETCHED_AT: float | None = None
GEN = 0  # generation counter: refresh bumps it, old workers stop


def set_state(state: str, message: str, uin=None):
    with LOCK:
        STATE["state"] = state
        STATE["message"] = message
        STATE["uin"] = uin
        STATE["qr_age"] = (
            round(time.time() - QR_FETCHED_AT, 1) if QR_FETCHED_AT else None
        )
        STATE["qr_ready"] = QR_IMAGE is not None


def qr_worker(gen: int, timeout: int = 115):
    """Fetch one QR, save its PNG, then poll TransEmp12 until an end state."""
    global QR_IMAGE, QR_FETCHED_AT
    client = QQClient()
    try:
        set_state("fetching", "正在取二维码…")
        server = client.connect()
        LOG.info("SSO server: %s:8080", server)
        result = client.fetch_qr()
        if result.get("ret_code") != 0 or not result.get("image"):
            set_state("error", f"取码失败 ret_code={result.get('ret_code')}")
            return
        with LOCK:
            QR_IMAGE = result["image"]
            QR_FETCHED_AT = time.time()
        set_state("waiting", "请用手机 QQ 扫码（2 分钟内有效）")
        LOG.info("QR ready (%d bytes)", len(result["image"]))

        deadline = time.time() + timeout
        last = None
        while time.time() < deadline:
            if gen != GEN:
                LOG.info("worker gen %d superseded, stopping", gen)
                return
            time.sleep(2)
            try:
                st = client.poll_qr()
            except Exception as e:  # noqa: BLE001 - keep polling on transient errors
                LOG.warning("poll error: %s", e)
                continue
            code = st.get("ret_code")
            if code != last:
                LOG.info("poll ret_code=%s uin=%s", code, st.get("uin"))
                last = code
            if code == 0:
                set_state("confirmed", "扫码成功，QQ 已登录", uin=st.get("uin"))
                LOG.info("CONFIRMED uin=%s", st.get("uin"))
                return
            if code == 14:
                # 14 = scanned, waiting for the user to confirm on the phone
                set_state("scanned", "已扫码，请在手机 QQ 上点确认登录")
                continue
            if code in (17, 19, 20, 21, 22, 23, 24, 25):
                set_state("expired", f"二维码已失效（ret_code={code}），请点刷新重取")
                return
        set_state("timeout", "二维码超时未扫，请点刷新重取")
    except Exception as e:  # noqa: BLE001 - surface any failure in the UI
        LOG.exception("qr_worker failed")
        set_state("error", f"取码出错：{e}")
    finally:
        client.close()


def start_fetch():
    """Bump generation and start a fresh QR worker thread."""
    global GEN
    GEN += 1
    t = threading.Thread(target=qr_worker, args=(GEN,), daemon=True)
    t.start()
    return GEN


PAGE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Golia QQ 登录</title>
<style>
body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:420px;margin:0 auto;padding:24px 16px;text-align:center;color:#222}
h1{font-size:20px;margin:8px 0 4px}
.sub{color:#888;font-size:13px;margin-bottom:16px}
#qr{width:260px;height:260px;border:1px solid #ddd;border-radius:8px;object-fit:contain;background:#fff}
#qr-wrap{min-height:260px;display:flex;align-items:center;justify-content:center}
#status{margin:16px 0 8px;font-size:15px}
#status.ok{color:#07c160}#status.bad{color:#e64340}
button{font-size:16px;padding:10px 28px;border:0;border-radius:8px;background:#07c160;color:#fff;cursor:pointer}
button:disabled{background:#aaa}
.hint{color:#999;font-size:12px;margin-top:14px;line-height:1.6}
</style>
</head>
<body>
<h1>Golia QQ 登录</h1>
<div class="sub">扫码登录个人 QQ（940737939）</div>
<div id="qr-wrap"><img id="qr" alt="二维码加载中…"></div>
<div id="status">加载中…</div>
<button id="refresh" onclick="refreshQR()">刷新二维码</button>
<div class="hint">二维码 2 分钟内有效，过期点刷新重取。<br>扫码后在手机 QQ 上点确认登录。</div>
<script>
let lastState = "";
async function tick(){
  try{
    const r = await fetch("/api/status");
    const s = await r.json();
    const el = document.getElementById("status");
    el.textContent = s.message + (s.uin ? "（QQ：" + s.uin + "）" : "");
    el.className = s.state === "confirmed" ? "ok" : (s.state === "expired" || s.state === "timeout" || s.state === "error" ? "bad" : "");
    document.getElementById("refresh").disabled = (s.state === "fetching");
    if(s.qr_ready && lastState !== s.state){
      document.getElementById("qr").src = "/qr.png?t=" + Date.now();
    }
    lastState = s.state;
  }catch(e){}
}
async function refreshQR(){
  document.getElementById("refresh").disabled = true;
  await fetch("/api/refresh", {method: "POST"});
  lastState = "";
  tick();
}
tick();
setInterval(tick, 2000);
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path.startswith("/qr.png"):
            with LOCK:
                img = QR_IMAGE
            if img:
                self._send(200, img, "image/png")
            else:
                self._send(404, b"no qr yet", "text/plain")
        elif self.path == "/api/status":
            with LOCK:
                st = dict(STATE)
                st["qr_age"] = (
                    round(time.time() - QR_FETCHED_AT, 1) if QR_FETCHED_AT else None
                )
            self._send(200, json.dumps(st, ensure_ascii=False).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if self.path == "/api/refresh":
            start_fetch()
            self._send(200, b'{"ok": true}', "application/json")
        else:
            self._send(404, b"not found", "text/plain")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=6198)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    LOG.info("web panel at http://%s:%d/ (LAN: http://192.168.31.2:%d/)", args.host, args.port, args.port)
    start_fetch()  # fetch the first QR on startup
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
