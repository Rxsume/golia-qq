#!/usr/bin/env python3
"""Milestone 1: fetch the QQ login QR code and save it as a PNG.

Usage: python3 fetch_qr.py [--out PATH] [--debug]
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from golia_qq.client import QQClient  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/home/hatch/workspace/your_files/golia-qq-qr-940737939.png")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--protocol", choices=["linux", "windows"], default="linux",
                    help="QQ protocol profile (default linux)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    client = QQClient(protocol=args.protocol)
    try:
        t0 = time.time()
        server = client.connect()
        print(f"SSO server: {server}:8080")
        result = client.fetch_qr()
        print(f"ret_code={result['ret_code']}  qr_url={result['qr_url']!r}")
        print(f"qr_sig={result['qr_sig'].hex() if result['qr_sig'] else ''}")
        img = result["image"]
        print(f"image bytes: {len(img)}  magic: {img[:8].hex()}")
        if not img:
            print("ERROR: server returned no QR image (TLV 0x17 empty)")
            return 2
        with open(args.out, "wb") as f:
            f.write(img)
        print(f"QR saved: {args.out}  ({len(img)} bytes, {time.time() - t0:.1f}s)")
        return 0
    except Exception as e:
        logging.exception("fetch_qr failed")
        print(f"FAILED: {e}")
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
