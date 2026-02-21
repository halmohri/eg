#!/usr/bin/env python3
import argparse
import datetime
import math
import os
import time
import re
import urllib.request
from typing import Any
from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent / "health_check.log"
DEFAULT_ACCESS_LOG = Path("/var/log/nginx/access.log")
DEFAULT_INTERVAL = 1.0
DEFAULT_REQ_RATE_TARGET = 1000.0
DEFAULT_NET_SCALE_MBPS = 100.0
DEFAULT_HEALTH_K = 1.0
DEFAULT_MIN_REQ_RATE = 1.0
DEFAULT_CONN_SCALE = 200.0
DEFAULT_MIN_CONN = 10.0
DEFAULT_CONN_HEALTH_K = 0.002772588722239781  # ln(2)/250
DEFAULT_STUB_STATUS_URL = "http://127.0.0.1/nginx_status"


def read_cpu_times() -> tuple[int, int]:
    with Path("/proc/stat").open("r", encoding="utf-8") as handle:
        first = handle.readline().strip()
    parts = first.split()
    if len(parts) < 5 or parts[0] != "cpu":
        raise RuntimeError("Unexpected /proc/stat format")
    values = [int(v) for v in parts[1:]]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def read_meminfo() -> tuple[int, int]:
    total_kb = None
    avail_kb = None
    with Path("/proc/meminfo").open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                total_kb = int(line.split()[1])
            elif line.startswith("MemAvailable:"):
                avail_kb = int(line.split()[1])
            if total_kb is not None and avail_kb is not None:
                break
    if total_kb is None or avail_kb is None:
        raise RuntimeError("Unable to read /proc/meminfo")
    used_kb = total_kb - avail_kb
    return total_kb, used_kb


def check_root() -> bool:
    if os.name != "posix":
        return True
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[error] Root privileges are required. Try: sudo ...")
        return False
    return True


def detect_default_interface() -> str | None:
    route_path = Path("/proc/net/route")
    if route_path.exists():
        with route_path.open("r", encoding="utf-8") as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    return None


def fallback_interface() -> str | None:
    with Path("/proc/net/dev").open("r", encoding="utf-8") as handle:
        lines = handle.readlines()[2:]
    for line in lines:
        iface = line.split(":")[0].strip()
        if iface != "lo":
            return iface
    return None


def read_net_bytes(interface: str) -> tuple[int, int]:
    with Path("/proc/net/dev").open("r", encoding="utf-8") as handle:
        lines = handle.readlines()[2:]
    for line in lines:
        name, data = line.split(":", 1)
        if name.strip() == interface:
            fields = data.split()
            if len(fields) < 16:
                break
            rx_bytes = int(fields[0])
            tx_bytes = int(fields[8])
            return rx_bytes, tx_bytes
    raise RuntimeError(f"Interface not found: {interface}")


def _count_tcp_conns(path: Path, ports: set[int]) -> int:
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        next(handle, None)
        for line in handle:
            parts = line.strip().split()
            if len(parts) < 4:
                continue
            local = parts[1]
            try:
                _, port_hex = local.split(":")
                port = int(port_hex, 16)
            except ValueError:
                continue
            if port in ports:
                count += 1
    return count


def read_connection_count(ports: list[int]) -> int:
    port_set = set(ports)
    return _count_tcp_conns(Path("/proc/net/tcp"), port_set) + _count_tcp_conns(
        Path("/proc/net/tcp6"), port_set
    )


def parse_timing_line(line: str) -> tuple[float, float, int | None] | None:
    parts = line.strip().split()
    if len(parts) < 2:
        return None
    status = None
    if len(parts) >= 3:
        try:
            status = int(parts[0])
            parts = parts[1:]
        except ValueError:
            status = None
    try:
        return float(parts[0]), float(parts[1]), status
    except ValueError:
        return None


def _parse_numeric_value(value: Any, py_type: str | None) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if value is None:
        return None
    if isinstance(value, str):
        match = re.search(r"(-?\\d+\\.?\\d*)", value)
        if not match:
            return None
        try:
            num = float(match.group(1))
        except ValueError:
            return None
        if py_type == "int":
            return float(int(round(num)))
        return num
    return None


def load_param_specs(settings_path: Path) -> dict[str, dict[str, Any]]:
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError("PyYAML is required: pip install pyyaml") from exc

    with settings_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}

    nginx = data.get("nginx") or {}
    configs = nginx.get("configs") or {}
    specs: dict[str, dict[str, Any]] = {}

    for name, cfg in configs.items():
        if not isinstance(cfg, dict):
            continue
        if "min" not in cfg or "max" not in cfg:
            continue
        py_type = cfg.get("py_type")
        value = _parse_numeric_value(cfg.get("learner_value"), py_type)
        if value is None:
            value = _parse_numeric_value(cfg.get("value"), py_type)
        if value is None:
            continue
        specs[str(name)] = {
            "value": value,
            "min": float(cfg["min"]),
            "max": float(cfg["max"]),
            "py_type": py_type,
        }
    return specs


def prepare_learner_config(
    param_specs: dict[str, dict[str, Any]],
    current_values: dict[str, dict[str, Any]],
) -> dict[str, float]:
    config_dict: dict[str, float] = {}
    for name, spec in param_specs.items():
        current = current_values.get(name, {})
        raw_value = current.get("value", spec.get("value"))
        value = _parse_numeric_value(raw_value, spec.get("py_type"))
        if value is None:
            value = _parse_numeric_value(
                spec.get("learner_value", spec.get("value")), spec.get("py_type")
            )
        if value is None:
            value = 0.0
        config_dict[name] = value
    return config_dict


def get_attack_context() -> tuple[str, float]:
    return ("normal", 0.0)


def read_log_slice(path: Path, start: int) -> tuple[str, int]:
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        end = handle.tell()
        if end < start:
            start = 0
        handle.seek(start)
        data = handle.read()
    return data.decode("utf-8", errors="replace"), end


def read_stub_status(url: str, timeout_s: float = 0.5) -> dict[str, int] | None:
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as handle:
            body = handle.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    active = None
    reading = None
    writing = None
    waiting = None
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
            match = re.search(
                r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", line
            )
            if match:
                reading = int(match.group(1))
                writing = int(match.group(2))
                waiting = int(match.group(3))
    if active is None and reading is None and writing is None and waiting is None:
        return None
    return {
        "active": active or 0,
        "reading": reading or 0,
        "writing": writing or 0,
        "waiting": waiting or 0,
    }


class HealthOracle:
    def __init__(
        self,
        access_log: Path,
        interface: str,
        interval: float,
        stub_status_url: str = DEFAULT_STUB_STATUS_URL,
    ) -> None:
        self.access_log = access_log
        self.interface = interface
        self.interval = interval
        self.stub_status_url = stub_status_url
        self.req_rate_target = DEFAULT_REQ_RATE_TARGET
        self.net_scale_mbps = DEFAULT_NET_SCALE_MBPS
        self.health_k = DEFAULT_HEALTH_K
        self.min_req_rate = DEFAULT_MIN_REQ_RATE
        self.conn_scale = DEFAULT_CONN_SCALE
        self.min_conn = DEFAULT_MIN_CONN
        self.conn_health_k = DEFAULT_CONN_HEALTH_K
        self._last_total: int | None = None
        self._last_idle: int | None = None
        self._last_rx: int | None = None
        self._last_tx: int | None = None
        self._last_log_pos: int | None = None
        self._last_ts: float | None = None

    def prime(self) -> None:
        # Initialize internal counters; caller controls sampling interval via sleep.
        total, idle = read_cpu_times()
        rx, tx = read_net_bytes(self.interface)
        log_pos = self.access_log.stat().st_size if self.access_log.exists() else 0
        self._last_total = total
        self._last_idle = idle
        self._last_rx = rx
        self._last_tx = tx
        self._last_log_pos = log_pos
        self._last_ts = time.monotonic()

    def sample_raw(self) -> dict[str, str]:
        # Stateless callers should sleep between prime() and sample_raw() calls.
        interval = max(0.0, self.interval)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        total2, idle2 = read_cpu_times()
        rx2, tx2 = read_net_bytes(self.interface)
        conn_count = read_connection_count([80, 443])
        stub = read_stub_status(self.stub_status_url) if self.stub_status_url else None
        log_text = ""
        log_start = self._last_log_pos or 0
        log_end = log_start
        if self.access_log.exists():
            log_text, log_end = read_log_slice(self.access_log, log_start)

        now = time.monotonic()
        if self._last_ts is None:
            elapsed = interval if interval > 0 else 0.0
        else:
            elapsed = max(0.0, now - self._last_ts)

        if self._last_total is None or self._last_idle is None:
            total1, idle1 = total2, idle2
        else:
            total1, idle1 = self._last_total, self._last_idle

        if self._last_rx is None or self._last_tx is None:
            rx1, tx1 = rx2, tx2
        else:
            rx1, tx1 = self._last_rx, self._last_tx

        total_delta = total2 - total1
        idle_delta = idle2 - idle1
        if total_delta <= 0:
            cpu = 0.0
        else:
            cpu = max(0.0, min(100.0, (1 - idle_delta / total_delta) * 100))

        mem_total_kb, mem_used_kb = read_meminfo()
        mem_percent = (mem_used_kb / mem_total_kb) * 100

        rate_interval = elapsed if elapsed > 0 else 1.0
        rx_bps = (rx2 - rx1) / rate_interval
        tx_bps = (tx2 - tx1) / rate_interval
        net_bps = rx_bps + tx_bps

        req_count = 0
        err_count = 0
        req_sum = 0.0
        upstream_sum = 0.0
        for line in log_text.splitlines():
            parsed = parse_timing_line(line)
            if parsed is None:
                continue
            req_time, upstream_time, status = parsed
            req_sum += req_time
            upstream_sum += upstream_time
            req_count += 1
            if status is not None and status >= 400:
                err_count += 1

        if req_count == 0:
            req_avg = "na"
            upstream_avg = "na"
            req_rate = "0.0"
            err_rate = "0.0"
        else:
            req_avg = f"{(req_sum / req_count):.4f}"
            upstream_avg = f"{(upstream_sum / req_count):.4f}"
            req_rate = f"{(req_count / rate_interval):.2f}"
            err_rate = f"{(err_count / req_count):.4f}"

        self._last_total = total2
        self._last_idle = idle2
        self._last_rx = rx2
        self._last_tx = tx2
        self._last_log_pos = log_end
        self._last_ts = now

        metrics = {
            "timestamp": timestamp,
            "interval": f"{rate_interval:.2f}",
            "cpu": f"{cpu:.2f}",
            "mem_used_kb": str(mem_used_kb),
            "mem_total_kb": str(mem_total_kb),
            "mem": f"{mem_percent:.2f}",
            "req_avg": req_avg,
            "upstream_avg": upstream_avg,
            "req_rate": req_rate,
            "err_rate": err_rate,
            "net_bps": f"{net_bps:.2f}",
            "rx_bps": f"{rx_bps:.2f}",
            "tx_bps": f"{tx_bps:.2f}",
            "net_iface": self.interface,
            "log_bytes": str(max(0, log_end - log_start)),
            "conn_count": str(conn_count),
        }
        if stub is None:
            metrics["stub_active"] = "na"
            metrics["stub_reading"] = "na"
            metrics["stub_writing"] = "na"
            metrics["stub_waiting"] = "na"
        else:
            metrics["stub_active"] = str(stub["active"])
            metrics["stub_reading"] = str(stub["reading"])
            metrics["stub_writing"] = str(stub["writing"])
            metrics["stub_waiting"] = str(stub["waiting"])
        return metrics

    def calculate_health_score(self, raw: dict[str, str]) -> list[float]:
        cpu_pct = float(raw.get("cpu", "0.0")) / 100.0
        mem_pct = float(raw.get("mem", "0.0")) / 100.0
        net_bps = float(raw.get("net_bps", "0.0"))
        req_rate = float(raw.get("req_rate", "0.0"))
        latency_raw = raw.get("req_avg", "na")
        latency = float(latency_raw) if latency_raw != "na" else 0.0

        cpu_health = math.exp(-self.health_k * cpu_pct)
        mem_health = math.exp(-self.health_k * mem_pct)

        net_mbps = net_bps / 1_000_000.0
        net_pressure = net_mbps / max(self.net_scale_mbps, 1e-6)
        net_health = math.exp(-self.health_k * net_pressure)

        if latency_raw == "na":
            tp_health = 1.0
        else:
            # Higher request rate reduces TP health; keep it > 0 with exp floor.
            rate_scale = max(self.req_rate_target, 1e-6)
            tp_health = math.exp(-self.health_k * (req_rate / rate_scale))
            tp_health = max(tp_health, 1e-6)

        stub_active_raw = raw.get("stub_active", "na")
        if stub_active_raw != "na":
            try:
                conn_load = float(stub_active_raw)
            except (TypeError, ValueError):
                conn_load = float(raw.get("conn_count", "0") or 0.0)
        else:
            conn_load = float(raw.get("conn_count", "0") or 0.0)
        conn_health = math.exp(-self.conn_health_k * conn_load)
        conn_health = max(conn_health, 1e-6)

        return [cpu_health, mem_health, net_health, tp_health, conn_health]

    def summary_health_score(self, health_scores: list[float]) -> float:
        return min(health_scores) if health_scores else 0.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Log system CPU/memory usage and nginx latency averages."
    )
    parser.add_argument(
        "--access-log",
        default=str(DEFAULT_ACCESS_LOG),
        help="Path to nginx access log (default: /var/log/nginx/access.log)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="Seconds between samples (default: 1.0)",
    )
    parser.add_argument(
        "--interface",
        help="Network interface name (default: detect active interface)",
    )
    return parser.parse_args()


def log_usage(oracle: HealthOracle) -> None:
    oracle.prime()
    time.sleep(max(0.1, oracle.interval))
    metrics = oracle.sample_raw()
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        handle.write(
            f"{metrics['timestamp']} cpu={metrics['cpu']}% "
            f"mem_used_kb={metrics['mem_used_kb']} mem_total_kb={metrics['mem_total_kb']} "
            f"mem={metrics['mem']}% "
            f"req_avg={metrics['req_avg']} upstream_avg={metrics['upstream_avg']} "
            f"req_rate={metrics['req_rate']} "
            f"net_bps={metrics['net_bps']} rx_bps={metrics['rx_bps']} tx_bps={metrics['tx_bps']} "
            f"net_iface={metrics['net_iface']} interval={metrics['interval']} "
            f"stub_active={metrics['stub_active']} stub_reading={metrics['stub_reading']} "
            f"stub_writing={metrics['stub_writing']} stub_waiting={metrics['stub_waiting']}"
            f"\n"
        )


if __name__ == "__main__":
    try:
        args = parse_args()
        if not check_root():
            raise SystemExit(1)
        iface = args.interface or detect_default_interface() or fallback_interface()
        if iface is None:
            print("[error] Unable to detect active network interface")
            raise SystemExit(1)
        oracle = HealthOracle(Path(args.access_log), iface, args.interval)
        log_usage(oracle)
    except Exception as exc:  # pragma: no cover - CLI guardrail
        print(f"[error] {exc}")
        raise SystemExit(1)
