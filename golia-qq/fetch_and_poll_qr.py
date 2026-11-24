#!/usr/bin/env python3
"""Fetch QQ login QR + poll TransEmp12 until scanned/confirmed/expired.

Usage: python3 fetch_and_poll_qr.py [--out PATH] [--timeout SECONDS]
Prints the QR path immediately, then polls every 2s and prints the final state.
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
    ap.add_argument("--timeout", type=int, default=110)
    ap.add_argument("--protocol", choices=["linux", "windows", "macos"], default="macos",
                    help="QQ protocol profile (default linux)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    client = QQClient(protocol=args.protocol)
    try:
        t0 = time.time()
        server = client.connect()
        print(f"SSO server: {server}:8080", flush=True)
        result = client.fetch_qr()
        print(f"ret_code={result['ret_code']} qr_sig={result['qr_sig'].hex() if result['qr_sig'] else ''}", flush=True)
        img = result["image"]
        if not img:
            print("ERROR: server returned no QR image", flush=True)
            return 2
        with open(args.out, "wb") as f:
            f.write(img)
        print(f"QR saved: {args.out} ({len(img)} bytes, {time.time() - t0:.1f}s)", flush=True)

        # Poll TransEmp12 every 2s until confirmed / expired / timeout.
        deadline = t0 + args.timeout
        last_state = None
        while time.time() < deadline:
            time.sleep(2)
            try:
                st = client.poll_qr()
            except Exception as e:
                print(f"poll error: {e}", flush=True)
                continue
            state = st.get("ret_code")
            if state != last_state:
                print(f"poll state: ret_code={state} uin={st.get('uin')} detail={st}", flush=True)
                last_state = state
            if state == 0:
                print(f"CONFIRMED uin={st.get('uin')}", flush=True)
                print(f"RESULT: confirmed uin={st.get('uin')}", flush=True)
                return 0
            if state in (17, 19, 20, 21, 22, 23, 24, 25):
                # expired / cancelled codes (exact mapping varies by server)
                print(f"RESULT: qr ended ret_code={state}", flush=True)
                return 3
        print("RESULT: timeout, no scan confirmed", flush=True)
        return 4
    except Exception as e:
        logging.exception("fetch_and_poll failed")
        print(f"FAILED: {e}", flush=True)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
