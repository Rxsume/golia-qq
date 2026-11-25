#!/usr/bin/env python3
# Local ddddocr service compatible with yuhua market plugins.
# Endpoints (matching author's ddddocr.250666.xyz API as used by plugins):
#   POST /capcode    {"slidingImage": b64, "backImage": b64, "simpleTarget": true}
#                    -> {"result": <x offset float>}
#   POST /calculate  {"image": b64}
#                    -> {"result": "<computed value or ocr text>"}
#   POST /ocr        {"image": b64} -> {"result": "<text>"}
#   GET  /           -> "ddddocr-local ok"
import base64
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ddddocr

_ocr = ddddocr.DdddOcr(show_ad=False)
_slide = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)


def _b64decode(s):
    if not s:
        return b""
    if "," in s and s.strip().startswith("data:"):
        s = s.split(",", 1)[1]
    return base64.b64decode(s)


def _calc(text):
    """OCR text like '3+5=' -> '8'; fall back to raw text."""
    t = re.sub(r"[^0-9+\-*/().]", "", text or "")
    if t and re.search(r"[+\-*/]", t):
        try:
            val = eval(t, {"__builtins__": {}}, {})
            if isinstance(val, float) and val.is_integer():
                val = int(val)
            return str(val)
        except Exception:
            pass
    return (text or "").strip()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = b"ddddocr-local ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._send({"error": "bad json"}, 400)
            return
        try:
            if self.path.startswith("/capcode"):
                slide = _b64decode(data.get("slidingImage") or data.get("slide") or "")
                back = _b64decode(data.get("backImage") or data.get("bg") or "")
                res = _slide.slide_match(slide, back, simple_target=bool(data.get("simpleTarget", True)))
                x = res.get("target", [0])[0] if isinstance(res, dict) else res
                self._send({"result": x})
            elif self.path.startswith("/calculate"):
                img = _b64decode(data.get("image") or "")
                text = _ocr.classification(img)
                self._send({"result": _calc(text)})
            elif self.path.startswith("/classification"):
                img = _b64decode(data.get("image") or "")
                self._send({"result": _ocr.classification(img)})
            elif self.path.startswith("/ocr"):
                img = _b64decode(data.get("image") or "")
                self._send({"result": _ocr.classification(img)})
            else:
                self._send({"error": "unknown path"}, 404)
        except Exception as e:
            self._send({"error": str(e)}, 500)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9898
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
