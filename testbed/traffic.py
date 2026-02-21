#!/usr/bin/env python3
"""
Traffic generator wrapper for wrk2/wrk, k6, and slowhttptest.
"""
from __future__ import annotations

import argparse
import json
import math
import shlex
import shutil
import subprocess
import sys
import tempfile
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Adjust import path so this runs from anywhere
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEFAULT_PATTERN = "steady"
DEFAULT_PERIOD = 60
DEFAULT_THREADS = 4
DEFAULT_CONNECTIONS = 10
DEFAULT_RATE = 20
DEFAULT_AMPLITUDE = 10
DEFAULT_DURATION = 300
DEFAULT_STEP = 5
DEFAULT_ENGINE = "k6"


@dataclass
class TrafficConfig:
    target: str
    pattern: str
    period: int
    duration: int
    threads: int
    connections: int
    rate: int
    amplitude: int
    step: int
    engine: str
    slowhttptest_args: list[str]


class Traffic:
    def __init__(self, config: TrafficConfig) -> None:
        self.config = config
        self.binary = None
        self.supports_rate = False

    def run(self) -> int:
        engine = self._resolve_engine()
        if engine == "k6":
            return self._run_k6()
        if engine == "wrk":
            return self._run_wrk_or_wrk2()
        if engine == "slowhttptest":
            return self._run_slowhttptest()
        print("[error] No supported traffic engine found")
        return 1

    def _resolve_engine(self) -> str | None:
        if self.config.engine == "slowhttptest":
            return "slowhttptest" if shutil.which("slowhttptest") else None
        if self.config.engine == "k6":
            return "k6" if shutil.which("k6") else None
        if self.config.engine in {"wrk", "wrk2"}:
            return "wrk" if self._resolve_wrk_binary() else None
        if shutil.which("k6"):
            return "k6"
        return "wrk" if self._resolve_wrk_binary() else None

    def _resolve_wrk_binary(self) -> str | None:
        if shutil.which("wrk2") is not None:
            self.binary = "wrk2"
            self.supports_rate = True
            return self.binary
        if shutil.which("wrk") is not None:
            self.binary = "wrk"
            self.supports_rate = False
            return self.binary
        return None

    def _run_wrk_or_wrk2(self) -> int:
        if self.binary is None and self._resolve_wrk_binary() is None:
            print("[error] wrk2 or wrk not found in PATH")
            return 1

        if self.config.pattern == "steady":
            return self._run_wrk(self.config.rate, self.config.duration)
        if self.config.pattern == "sine":
            if not self.supports_rate:
                print("[warn] wrk does not support fixed rate; falling back to steady")
                return self._run_wrk(self.config.rate, self.config.duration)
            return self._run_sine_wrk()

        print(f"[error] Unsupported pattern: {self.config.pattern}")
        return 1

    def _run_wrk(self, rate: int, duration: int) -> int:
        cmd = [
            self.binary,
            "-t",
            str(self.config.threads),
            "-c",
            str(self.config.connections),
            "-d",
            f"{duration}s",
            self.config.target,
        ]
        if self.supports_rate:
            cmd.insert(6, "-R")
            cmd.insert(7, str(rate))
        print("[traffic]", " ".join(cmd))
        result = subprocess.run(cmd)
        return result.returncode

    def _run_sine_wrk(self) -> int:
        steps = max(1, int(self.config.duration / self.config.step))
        for idx in range(steps):
            t = idx * self.config.step
            phase = (2 * math.pi * t) / max(1, self.config.period)
            rate = self.config.rate + int(round(self.config.amplitude * math.sin(phase)))
            rate = max(1, rate)
            rc = self._run_wrk(rate, self.config.step)
            if rc != 0:
                return rc
        return 0

    def _run_k6(self) -> int:
        if shutil.which("k6") is None:
            print("[error] k6 not found in PATH")
            return 1
        if self.config.pattern == "steady":
            return self._run_k6_step(self.config.rate, self.config.duration)
        if self.config.pattern == "sine":
            return self._run_sine_k6()
        print(f"[error] Unsupported pattern: {self.config.pattern}")
        return 1

    def _run_sine_k6(self) -> int:
        steps = max(1, int(self.config.duration / self.config.step))
        for idx in range(steps):
            t = idx * self.config.step
            phase = (2 * math.pi * t) / max(1, self.config.period)
            rate = self.config.rate + int(round(self.config.amplitude * math.sin(phase)))
            rate = max(1, rate)
            rc = self._run_k6_step(rate, self.config.step)
            if rc != 0:
                return rc
        return 0

    def _run_k6_step(self, rate: int, duration: int) -> int:
        script = HERE / "traffic_k6.js"
        with tempfile.NamedTemporaryFile(prefix="k6-summary-", suffix=".json", delete=False) as tmp:
            summary_path = Path(tmp.name)
        cmd = [
            "k6",
            "run",
            str(script),
            "--summary-export",
            str(summary_path),
            "--env",
            f"TARGET={self.config.target}",
            "--env",
            f"DURATION={duration}",
            "--env",
            f"RATE={rate}",
            "--env",
            f"VUS={self.config.connections}",
        ]
        print("[traffic]", " ".join(cmd))
        result = subprocess.run(cmd)
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text())
                http_reqs = summary.get("metrics", {}).get("http_reqs", {})
                rps = http_reqs.get("rate")
                if rps is None:
                    rps = http_reqs.get("values", {}).get("rate")
                if rps is not None:
                    print(f"[traffic_rate] actual_rps={float(rps):.2f}")
            except Exception:
                pass
            try:
                summary_path.unlink()
            except Exception:
                pass
        return result.returncode

    def _run_slowhttptest(self) -> int:
        if shutil.which("slowhttptest") is None:
            print("[error] slowhttptest not found in PATH")
            return 1
        if not self.config.slowhttptest_args:
            print("[error] slowhttptest_args required in profile or CLI")
            return 1
        args = []
        skip_next = False
        for arg in self.config.slowhttptest_args:
            if skip_next:
                skip_next = False
                continue
            if arg in ("-l", "--length"):
                skip_next = True
                continue
            args.append(arg)
        args.extend(["-l", str(self.config.duration)])
        cmd = ["slowhttptest", "-u", self.config.target]
        cmd.extend(args)
        print("[traffic]", " ".join(cmd))

        log_path = None

        current: dict[str, int | str] = {}
        status_second: int | None = None

        def flush_record() -> None:
            if not current or log_path is None:
                return
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "second": status_second,
                **current,
            }
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")
            current.clear()

        import pty

        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            cmd,
            stdout=slave_fd,
            stderr=slave_fd,
            text=False,
        )
        os.close(slave_fd)
        buffer = ""
        while True:
            try:
                data = os.read(master_fd, 1024)
            except OSError:
                break
            if not data:
                if proc.poll() is not None:
                    break
                continue
            try:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except Exception:
                pass
            text = data.decode("utf-8", errors="replace")
            for ch in text:
                if ch in {"\n", "\r"}:
                    line = buffer.strip()
                    buffer = ""
                    if not line:
                        continue
                    if "slow HTTP test status on" in line:
                        flush_record()
                        try:
                            status_second = int(
                                line.split("on", 1)[1].split("th", 1)[0].strip()
                            )
                        except Exception:
                            status_second = None
                        continue
                    if ":" not in line:
                        continue
                    key, rest = line.split(":", 1)
                    key = key.strip().lower()
                    val = rest.strip()
                    if key in {"initializing", "pending", "connected", "error", "closed"}:
                        try:
                            current[key] = int(val)
                        except ValueError:
                            continue
                    elif key.startswith("service available"):
                        current["service_available"] = val
                        flush_record()
                    continue
                buffer += ch
        os.close(master_fd)
        proc.wait()

        proc.wait()
        flush_record()
        return proc.returncode


def _parse_slowhttptest_args(value: str | list[str] | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return shlex.split(str(value))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate traffic using wrk2/wrk, k6, or slowhttptest.")
    parser.add_argument("target", help="Target URL (e.g., http://127.0.0.1:8080/")
    parser.add_argument(
        "--profile",
        help="Path to YAML profile to override CLI args",
    )
    parser.add_argument(
        "--engine",
        choices=["auto", "wrk", "wrk2", "k6", "slowhttptest"],
        default=DEFAULT_ENGINE,
        help="Traffic engine (default: k6)",
    )
    parser.add_argument(
        "--pattern",
        choices=["steady", "sine"],
        default=DEFAULT_PATTERN,
        help="Traffic pattern (default: steady)",
    )
    parser.add_argument(
        "--period",
        type=int,
        default=DEFAULT_PERIOD,
        help="Sine wave period in seconds (default: 60)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=DEFAULT_DURATION,
        help="Total duration in seconds (default: 300)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help="wrk2 threads (default: 4)",
    )
    parser.add_argument(
        "--connections",
        type=int,
        default=DEFAULT_CONNECTIONS,
        help="wrk2 connections / k6 VUs (default: 10)",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=DEFAULT_RATE,
        help="Base request rate (RPS) for steady/sine (default: 20)",
    )
    parser.add_argument(
        "--amplitude",
        type=int,
        default=DEFAULT_AMPLITUDE,
        help="Sine amplitude in RPS (default: 10)",
    )
    parser.add_argument(
        "--step",
        type=int,
        default=DEFAULT_STEP,
        help="Sine step interval in seconds (default: 5)",
    )
    parser.add_argument(
        "--slowhttptest-args",
        help="Extra args for slowhttptest (string or list in profile)",
    )
    args = parser.parse_args()

    if args.profile:
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError as exc:
            print("[error] PyYAML is required: pip install pyyaml")
            raise SystemExit(1) from exc
        profile_path = Path(args.profile)
        if not profile_path.exists():
            print(f"[error] Profile not found: {profile_path}")
            raise SystemExit(1)
        with profile_path.open("r", encoding="utf-8") as handle:
            profile = yaml.safe_load(handle) or {}
        for key, value in profile.items():
            if hasattr(args, key) and value is not None:
                setattr(args, key, value)

    cfg = TrafficConfig(
        target=args.target,
        pattern=args.pattern,
        period=args.period,
        duration=args.duration,
        threads=args.threads,
        connections=args.connections,
        rate=args.rate,
        amplitude=args.amplitude,
        step=args.step,
        engine=args.engine,
        slowhttptest_args=_parse_slowhttptest_args(args.slowhttptest_args),
    )

    traffic = Traffic(cfg)
    raise SystemExit(traffic.run())
