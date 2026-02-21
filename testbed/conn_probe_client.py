#!/usr/bin/env python3
"""
Minimal client-side connection producer for nginx capacity probing.
"""
from __future__ import annotations

import argparse
import socket
import time
from typing import List


def open_conn(host: str, port: int, timeout_s: float) -> socket.socket | None:
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return sock
    except Exception:
        return None


def send_keepalive(sock: socket.socket) -> bool:
    try:
        sock.sendall(b"X-keepalive: 1\r\n")
        return True
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Open many TCP connections to a target.")
    ap.add_argument("target", help="Host or IP")
    ap.add_argument("--port", type=int, default=443, help="Target port")
    ap.add_argument("--total", type=int, default=1000, help="Total connections to open")
    ap.add_argument("--step", type=int, default=100, help="Connections per step")
    ap.add_argument("--interval", type=float, default=1.0, help="Seconds between steps")
    ap.add_argument("--timeout", type=float, default=2.0, help="Connect timeout")
    ap.add_argument("--hold", type=float, default=30.0, help="Seconds to hold connections")
    ap.add_argument(
        "--keepalive", type=float, default=0.0, help="Seconds between keepalive writes"
    )
    args = ap.parse_args()

    conns: List[socket.socket] = []
    opened = 0
    failed = 0

    while opened < args.total:
        batch = min(args.step, args.total - opened)
        for _ in range(batch):
            sock = open_conn(args.target, args.port, args.timeout)
            if sock is None:
                failed += 1
            else:
                conns.append(sock)
                opened += 1
        print(f"[client] opened={opened} failed={failed}")
        time.sleep(max(0.1, args.interval))

    start = time.time()
    last_keep = start
    while time.time() - start < args.hold:
        if args.keepalive > 0 and (time.time() - last_keep) >= args.keepalive:
            alive = []
            for sock in conns:
                if send_keepalive(sock):
                    alive.append(sock)
                else:
                    try:
                        sock.close()
                    except Exception:
                        pass
            conns = alive
            last_keep = time.time()
            print(f"[client] keepalive sent, alive={len(conns)}")
        time.sleep(0.5)

    for sock in conns:
        try:
            sock.close()
        except Exception:
            pass
    print(f"[client] closed={len(conns)} failed={failed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
