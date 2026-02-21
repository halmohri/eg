#!/usr/bin/env python3
"""
Minimal server-side connection probe observer using nginx stub_status.
"""
from __future__ import annotations

import argparse
import time
from typing import Dict
import urllib.request

DEFAULT_STATUS_URL = "http://127.0.0.1/nginx_status"


def read_stub_status(url: str, timeout_s: float = 0.5) -> Dict[str, int] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as handle:
            body = handle.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    active = reading = writing = waiting = None
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("Active connections:"):
            parts = line.split(":")
            if len(parts) >= 2:
                try:
                    active = int(parts[1].strip())
                except ValueError:
                    active = None
        elif line.startswith("Reading:"):
            parts = line.replace(":", "").split()
            try:
                reading = int(parts[1])
                writing = int(parts[3])
                waiting = int(parts[5])
            except (IndexError, ValueError):
                pass
    if active is None and reading is None and writing is None and waiting is None:
        return None
    return {
        "active": active or 0,
        "reading": reading or 0,
        "writing": writing or 0,
        "waiting": waiting or 0,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Observe nginx stub_status and estimate max connections.")
    ap.add_argument("--url", default=DEFAULT_STATUS_URL, help="stub_status URL")
    ap.add_argument("--interval", type=float, default=1.0, help="Seconds between samples")
    ap.add_argument("--iterations", type=int, default=60, help="Number of samples")
    args = ap.parse_args()

    max_active = 0
    max_reading = 0
    max_writing = 0
    max_waiting = 0

    for idx in range(args.iterations):
        data = read_stub_status(args.url)
        if data is None:
            print("[error] stub_status not available")
        else:
            max_active = max(max_active, data["active"])
            max_reading = max(max_reading, data["reading"])
            max_writing = max(max_writing, data["writing"])
            max_waiting = max(max_waiting, data["waiting"])
            print(
                f"[sample] {idx+1}/{args.iterations} "
                f"active={data['active']} reading={data['reading']} "
                f"writing={data['writing']} waiting={data['waiting']}"
            )
        time.sleep(max(0.1, args.interval))

    print(
        "[estimate] max_active={active} max_reading={reading} "
        "max_writing={writing} max_waiting={waiting}".format(
            active=max_active,
            reading=max_reading,
            writing=max_writing,
            waiting=max_waiting,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
