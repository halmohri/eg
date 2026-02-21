#!/usr/bin/env python3
from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple


DEFAULT_NORMAL_PROFILE = Path("testbed/traffic_normal.yaml")
DEFAULT_FLOOD_PROFILE = Path("testbed/traffic_http_flood.yaml")
DEFAULT_SLOW_PROFILE = Path("testbed/traffic_slowloris.yaml")


def _load_profile(path: Path) -> dict:
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        return {}
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


@dataclass
class AttackSignal:
    normal_profile: Path = DEFAULT_NORMAL_PROFILE
    flood_profile: Path = DEFAULT_FLOOD_PROFILE
    slow_profile: Path = DEFAULT_SLOW_PROFILE

    def __post_init__(self) -> None:
        normal = _load_profile(self.normal_profile)
        flood = _load_profile(self.flood_profile)
        slow = _load_profile(self.slow_profile)

        normal_rate = float(normal.get("rate", 0.0))
        flood_rate = float(flood.get("rate", 0.0))
        slow_rate = float(slow.get("rate", 0.0))
        if flood_rate <= 0:
            flood_rate = max(normal_rate * 5.0, 100.0)
        self.rpm_threshold = flood_rate * 60.0
        self.rpm_scale = max((flood_rate - normal_rate) * 60.0, 60.0)

        self.duration_threshold = float(slow.get("duration_threshold", 0.5))
        self.duration_scale = float(slow.get("duration_scale", 1.0))
        self.slow_rpm_threshold = slow_rate * 60.0 if slow_rate > 0 else normal_rate * 60.0

    def get_attack_context(self, metrics: dict[str, str]) -> Tuple[str, float]:
        req_rate = float(metrics.get("req_rate", "0") or 0.0)
        rpm = req_rate * 60.0
        req_avg_raw = metrics.get("req_avg", "na")
        req_avg = float(req_avg_raw) if req_avg_raw != "na" else 0.0
        conn_count = float(metrics.get("conn_count", "0") or 0.0)

        flood_conf = 0.0
        if rpm > self.rpm_threshold:
            flood_conf = 1.0 - math.exp(-(rpm - self.rpm_threshold) / self.rpm_scale)

        semantic_conf = 0.0
        if req_avg > self.duration_threshold:
            semantic_conf = 1.0 - math.exp(
                -(req_avg - self.duration_threshold) / self.duration_scale
            )
        # Slowloris: high header time (req_avg), low RPM, and many open conns.
        if rpm > 0 and rpm <= max(self.slow_rpm_threshold, 60.0) and req_avg > 0:
            semantic_conf = min(1.0, semantic_conf + 0.25)
        if conn_count > 0 and rpm <= max(self.slow_rpm_threshold, 60.0):
            conn_conf = 1.0 - math.exp(-conn_count / 200.0)
            semantic_conf = max(semantic_conf, min(conn_conf, 1.0))

        if flood_conf >= semantic_conf and flood_conf > 0:
            return ("http_flood", float(min(flood_conf, 1.0)))
        if semantic_conf > 0:
            return ("slowloris", float(min(semantic_conf, 1.0)))
        return ("normal", 0.0)
