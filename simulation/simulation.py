#!/usr/bin/env python3
"""
Base simulator class with common functionality for attack simulation.
"""
from __future__ import annotations

import math
import random
import sys
import time
from typing import List, Dict, Any
from pathlib import Path
import json

# Adjust import path so this runs from anywhere
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oracle.oracle import AttackOracle
from inspector.inspector import ConfigInspector
from inspector.signals import AdvancedSignals, Signal


class BaseSimulator:
    """Base class for attack simulators with common functionality."""

    def __init__(
        self,
        oracle: AttackOracle,
        pattern: str = "linear",
        attack_type: str = "slowloris",
        steps: int = 20,
        check_interval: int = 5,
        output: Path | None = None,
        health_threshold: float = 0.9,
        attack_threshold: float = 0.6,
        adaptive_checkpoints: bool = False,
        improve_configs: bool = True, 
    ) -> None:
        self.oracle = oracle
        self.pattern = pattern
        self.attack_type = attack_type
        self.steps = steps
        self.check_interval = check_interval
        self._base_check_interval = check_interval
        self.adaptive_checkpoints = adaptive_checkpoints
        self.signals: List[Dict[str, Any]] = []  # each entry: {"type": ..., "data": {...}}
        self.last_profile: Dict[str, Any] | None = None
        self.output = output or Path("simulation_results.json")
        self._last_ratio = 0.0
        self.attack_counts: List[int] = []
        self.conf_series: Dict[str, List[float]] = {p.name: [] for p in oracle.profiles}
        self.current_conf: Dict[str, float] = {p.name: 0.0 for p in oracle.profiles}
        # allow limiting profiles (default: single attack_type)
        self.active_profiles = [p for p in oracle.profiles if p.name == attack_type] or oracle.profiles
        self._prefix = "[sim]"
        self.health_threshold = health_threshold
        self.attack_threshold = attack_threshold
        self.inspector = ConfigInspector()
        self.learner = None  # To be set by subclasses
        #self._potentials = self.inspector.generate_potential_configs()
        self._iteration_records: List[Dict[str, Any]] = []
        self._health_history: List[Dict[str, Any]] = []
        self.improve_configs = improve_configs 
        self._timings: Dict[str, List[float]] = {
            "simulate_signal": [],
            "profile_attack": [],
            "calculate_health_score": [],
            "zone_check": [],
        }
        self._pattern_ratios: List[float] = []
        self._step_health: List[Dict[str, Any]] = []

    def pattern_ratio(self, step_idx: int) -> float:
        x = step_idx / max(1, self.steps - 1)
        if self.pattern == "linear":
            base = x
        elif self.pattern == "exponential":
            base = min((math.exp(x) - 1) / (math.e - 1), 1.0)
        elif self.pattern == "sine":
            base = (1 - math.cos(math.pi * x)) / 2.0
        elif self.pattern == "bell":
            sigma = 0.2
            base = math.exp(-((x - 0.5) ** 2) / (2 * sigma * sigma))
        elif self.pattern == "triple_bell":
            # three bell pulses: low, high, medium with small intensity noise
            centers = [1.0 / 6.0, 0.5, 5.0 / 6.0]
            amplitudes = [0.35, 0.95, 0.65]
            sigma = 0.07
            pulses = []
            for c, a in zip(centers, amplitudes):
                amp = max(0.0, min(1.0, a + random.uniform(-0.05, 0.05)))
                pulses.append(amp * math.exp(-((x - c) ** 2) / (2 * sigma * sigma)))
            base = max(pulses) if pulses else 0.0
        else:
            base = x
        noise = random.uniform(-0.05, 0.05)
        ratio = max(0.0, min(1.0, base + noise))
        if self.pattern not in ("bell", "triple_bell"):
            ratio = max(self._last_ratio, ratio)  # keep non-decreasing for a smooth rise
            self._last_ratio = ratio
        return ratio

    def _log(self, msg: str) -> None:
        print(f"{self._prefix} {msg}")

    def _log_current_configs(self) -> None:
        defaults = self.inspector.get_attack_param_specs()
        #self._log("initial configs:")
        for k, v in defaults.items():
            self._log(f"  {k}: {v['value']}")

    def _log_signal(self, idx: int, signal_type: str, sig: Dict[str, Any]) -> None:
        """Pretty-print a generated signal. sig is dict of Signal objects."""
        attack_keys = [k for k in sig.keys() if k not in ("cpu_usage", "memory_usage", "latency", "goodput")]
        health_keys = [k for k in ("cpu_usage", "memory_usage", "latency", "goodput") if k in sig]
        attack_str = ", ".join(f"{k}:{sig[k].value:.3f}" for k in attack_keys)
        health_str = ", ".join(f"{k}:{sig[k].value:.3f}" for k in health_keys)
        self._log(
            f"signal {idx+1:02}/{self.steps}: type={signal_type:<9}\n"
            f"attack={{ {attack_str} }}\n"
            #f"health={{ {health_str} }}\n"
            f"====="
        )

    def run(self) -> Dict[str, Any]:
        total_attacks = 0
        self._log_current_configs()

        #Simulates steps iterations of live attack monitoring.
        for i in range(self.steps):
            #Decide which attack signal to produce according to schedule.
            ratio = self.pattern_ratio(i)
            signal_type = self.attack_type if random.random() < ratio else "normal"
            self._pattern_ratios.append(ratio)
            #Get the attack signals
            configurations = self.inspector.get_attack_param_specs()
            t0 = time.perf_counter()
            sig = self.oracle.signals.simulate_signal(configurations,signal_type)
            self._timings["simulate_signal"].append(time.perf_counter() - t0)
            self.signals.append({"type": signal_type, "data": sig})
            self._log_signal(i, signal_type, sig)

            # record iteration data: configs, full signal, and health slice
            cfg_snapshot = {k: v["value"] for k, v in self.inspector.get_attack_param_specs().items()}
            health_slice = self.oracle.signals.filter_health(sig)
            self._iteration_records.append(
                {
                    "step": i + 1,
                    "signal_type": signal_type,
                    "signal": sig,
                    "health": health_slice,
                    "configs": cfg_snapshot,
                    "pattern_ratio": ratio,
                }
            )
            # per-step health (includes goodput if present) to observe drop/recovery
            try:
                attack_conf = max(self.current_conf.values()) if self.current_conf else 0.0
                step_health = self.oracle.calculate_health_score(sig, attack_conf=attack_conf)
                self._step_health.append({"step": i + 1, "health": step_health})
            except Exception:
                pass

            #Collect signal statistics.
            if signal_type != "normal":
                total_attacks += 1
            self.attack_counts.append(total_attacks)

            #Check point to revise the parameters and learn.
            if (i + 1) % self.check_interval == 0:
                self._checkpoint(i + 1)


            for name in self.conf_series.keys():
                self.conf_series[name].append(self.current_conf.get(name, 0.0))

        print("FINAL CONFIGURATIONS:")
        self._log_current_configs()
        return self.last_profile or {}

    def _checkpoint(self, step: int) -> None:
        #Get the window data.
        window = [s["data"] for s in self.signals[-self.check_interval :]]
        #Get attack profile and confidence.
        t0 = time.perf_counter()
        profile = self.oracle.profile_attack(window, self.last_profile, profiles=self.active_profiles)
        self._timings["profile_attack"].append(time.perf_counter() - t0)
        attacks = profile.get("attacks", [])
        attack_conf = max((float(a.get("confidence", 0.0)) for a in attacks), default=0.0)

        #Compute health score using the Oracle's function for each event in the window.
        t0 = time.perf_counter()
        health_raw = [self.oracle.calculate_health_score(win, attack_conf=attack_conf) for win in window]
        self._timings["calculate_health_score"].append(time.perf_counter() - t0)
        #print(f"===============RAW: {health_raw}")
        #Now collapse scores into one 
        health_scores = self.oracle.fused_health_columns(health_raw, alpha=0.7)
        self.last_profile = profile
        seen = {a.get("attack_profile"): a.get("confidence", 0.0) for a in profile.get("attacks", [])}
        for name in self.current_conf.keys():
            self.current_conf[name] = float(seen.get(name, 0.0))
        self._log_checkpoint(step, profile, health_scores, 0.0)

        # record current config snapshot
        self._record_config_snapshot(step)

        # attach raw health per event into recent iteration records for output
        recent_records = self._iteration_records[-len(window) :] if hasattr(self, "_iteration_records") else []
        rounded_health = [float(round(h, 3)) for h in (health_scores.tolist() if hasattr(health_scores, "tolist") else health_scores)]
        for rec in recent_records:
            rec["health"] = rounded_health

        # record fused health scores for output
        if hasattr(health_scores, "tolist"):
            health_entry = health_scores.tolist()
        else:
            health_entry = health_scores
        self._health_history.append({"step": step, "health": health_entry})

        
        #Learn from the cycle
        if self.improve_configs: 
            self._learn_from_cycle(profile, health_scores.tolist())
            #Recalibrate system parameters if needed
            self._maybe_recalibrate(health_scores.tolist(), profile)
            # annotate recent iteration records with attack profile info
            self._annotate_recent_records(profile)

    def _log_checkpoint(self, step: int, profile: Dict[str, Any], health_scores: List[float], avg_health: float) -> None:
        self._log("-" * 60)
        self._log(f"checkpoint {step:02} (interval={self.check_interval})")
        self._log(f"  attacks: {profile}")
        self._log(f"  health : {[float(round(h,3)) for h in health_scores]}")
        self._log("-" * 60)

    def _build_input_vector(self, profile: Dict[str, Any]):
        """Build input vector for learner. Must be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement _build_input_vector()")

    def _learn_from_cycle(self, profile: Dict[str, Any], health_scores: List[float]) -> None:
        """Pass observation to the learner. Must be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement _learn_from_cycle()")

    def _did_improve(self, avg_stress: float, prev_stress: float, tolerance: float = 0.05) -> bool:
        """
        Compare current stress to last checkpoint; revert configs on worsening.
        Returns True if we should proceed to zone-based recalibration.
        """
        if prev_stress is None:
            return True
        delta = avg_stress - prev_stress
        if abs(delta) <= tolerance:
            trend = "unchanged"
        elif delta > 0:
            trend = "worsened"
        else:
            trend = "improved"
        self._log(f"  stress trend vs last checkpoint (tolerance: {tolerance}): {trend} ({avg_stress:.3f} vs {prev_stress:.3f})")
        if trend == "worsened":
            return False
        return True

    def _reverse_configs(self):
        prev_cfgs = getattr(self, "_last_configs", None)
        if prev_cfgs:
            try:
                self.inspector.modify_configs({k: {"value": v} for k, v in prev_cfgs.items()})
                self._log("  reverted to previous configs due to worsening stress")
                self._last_checkpoint_stress = None
                self._last_configs = None
            except Exception as exc:
                self._log(f"  failed to revert configs: {exc}")
        return True

    def _explore_strategy(self, profile, avg_stress):
        if getattr(self, "adaptive_checkpoints", False):
            self.check_interval = 1

    def _zone_check(self, avg_stress: float, profile: Dict[str, Any]) -> None:
        """
        Control Logic: Decides optimization strategy based on system stress zones.
        """
        t0 = time.perf_counter()
        modified = True
        # ZONE A: CRISIS (Saturation > 90%)
        if avg_stress > 0.9:
            print(f"CRISIS DETECTED ({avg_stress:.2f}). Triggering Aggressive Exploration.")
            self._recalibrate_system_params(
                profile,
                avg_stress,
                beta=2.0,
                stability_lambda=0.5
            )
            if getattr(self, "adaptive_checkpoints", False):
                self.check_interval = max(1, math.ceil(self._base_check_interval / 3))

        # ZONE B: STRESS (Saturation > 50%)
        elif avg_stress > 0.6:
            print(f"STRESS DETECTED ({avg_stress:.2f}). Triggering Stabilization/Lock-Down.")
            self._recalibrate_system_params(
                profile,
                avg_stress,
                beta=0.1,
                stability_lambda=1.0
            )
            if getattr(self, "adaptive_checkpoints", False):
                self.check_interval = max(1, math.ceil(self._base_check_interval / 3))

        # ZONE C: SAFE (Saturation < 50%)
        else:
            modified = False
            print(f"System Stable ({avg_stress:.2f}). No Action.")
            if getattr(self, "adaptive_checkpoints", False):
                self.check_interval = self._base_check_interval
        self._timings["zone_check"].append(time.perf_counter() - t0)
        return modified

    def _maybe_recalibrate(self, health_signals: List[Dict[str, Any]], profile: Dict[str, Any]) -> None:
        if not health_signals:
            return

        # 1. Calculate Stress Level (Bottleneck Detection)
        avg_stress = self._compute_avg_stress(health_signals)
        prev_stress = getattr(self, "_last_checkpoint_stress", None)
        # Improvement/worsening logic; proceed to zones only if not improved.
        improved = self._did_improve(avg_stress, prev_stress)

        # if not improved and prev_stress < 0.95:
        #     self._reverse_configs()
        #     self._explore_strategy(profile, avg_stress)
        #     return
        # else:
        #     self._zone_check(avg_stress, profile)

        self._zone_check(avg_stress, profile)

        # remember current configs for next checkpoint
        self._last_configs = {k: v["value"] for k, v in self.inspector.get_attack_param_specs().items()}
        self._last_checkpoint_stress = avg_stress

    def _compute_avg_stress(self, health_signals: List[Dict[str, Any]]) -> float:
        """
        Compute average stress across a window of health signals using max(cpu, mem) per signal.
        """
        if not health_signals:
            return 0.0
        # stress_scores = []
        # for sig in health_signals:
        #     cpu = float(sig.get("cpu_usage", 0.0)) / 100.0
        #     mem = float(sig.get("memory_usage", 0.0)) / 100.0
        #     stress_scores.append(max(cpu, mem))
        # return sum(stress_scores) / len(stress_scores)
        stress = 1-min(health_signals)
        #print(f"Stress is {stress}.")
        return stress 


    def _recalibrate_system_params(
        self,
        profile: Dict[str, Any],
        avg_cpu_mem: float,
        beta: float = 1.96,
        stability_lambda: float = 0.1,
    ) -> None:
        """Adjust system parameters based on optimizer recommendation. Must be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement _recalibrate_system_params()")

    def _record_config_snapshot(self, step: int) -> None:
        defaults = self.inspector.get_attack_param_specs()
        snap = getattr(self, "_config_snapshots", [])
        snap.append({"step": step, "configs": {k: defaults[k]["value"] for k in defaults}})
        self._config_snapshots = snap

    def _annotate_recent_records(self, profile: Dict[str, Any]) -> None:
        if not hasattr(self, "_iteration_records") or not self._iteration_records:
            return
        attacks = profile.get("attacks", [])
        if attacks:
            best = max(attacks, key=lambda a: float(a.get("confidence", 0.0)))
            attack_profile = best.get("attack_profile", "generic_attack")
            attack_conf = float(best.get("confidence", 0.0))
        else:
            attack_profile = "generic_attack"
            attack_conf = 0.0
        window = self._iteration_records[-self.check_interval :]
        for rec in window:
            rec["attack_profile"] = attack_profile
            rec["attack_confidence"] = attack_conf

    def save_results(self) -> None:
        def _serialize_signal_dict(d: Dict[str, Any]) -> Dict[str, Any]:
            out = {}
            for k, v in d.items():
                if hasattr(v, "value"):
                    out[k] = v.value
                else:
                    out[k] = v
            return out

        serialized_signals = []
        for s in self.signals:
            data = s.get("data", {})
            serialized_signals.append({"type": s.get("type"), "data": _serialize_signal_dict(data)})

        serialized_checkpoints = []
        for rec in getattr(self, "_iteration_records", []):
            rec_copy = dict(rec)
            if "signal" in rec_copy:
                rec_copy["signal"] = _serialize_signal_dict(rec_copy["signal"])
            if "health" in rec_copy:
                if isinstance(rec_copy["health"], list):
                    rec_copy["health"] = rec_copy["health"]
                else:
                    rec_copy["health"] = _serialize_signal_dict(rec_copy["health"])
            serialized_checkpoints.append(rec_copy)

        payload = {
            "pattern": self.pattern,
            "attack_type": self.attack_type,
            "steps": self.steps,
            "check_interval": self.check_interval,
            "attack_counts": self.attack_counts,
            "confidence_by_attack": self.conf_series,
            "configs": getattr(self, "_config_snapshots", []),
            "signals": serialized_signals,
            "checkpoints": serialized_checkpoints,
            "health_scores": getattr(self, "_health_history", []),
            "timings": {k: [float(x) for x in v] for k, v in getattr(self, "_timings", {}).items()},
            "pattern_ratios": self._pattern_ratios,
            "step_health": self._step_health,
        }
        self.output.write_text(json.dumps(payload, indent=2))
        self._log(f"saved results JSON: {self.output}")

    @staticmethod
    def load_config_dict(path: str):
        """Load configuration from JSON file (old dict-based format)."""
        p = Path(path)
        if not p.is_absolute():
            candidate = ROOT / p
            if candidate.exists():
                p = candidate
            else:
                alt = HERE / p
                if alt.exists():
                    p = alt
        data = json.loads(p.read_text())
        signal_ranges = {}
        for name, meta in data.get("metadata", {}).get("signals", {}).items():
            rng = meta.get("normal_range")
            if rng and len(rng) == 2:
                signal_ranges[name] = (float(rng[0]), float(rng[1]))
        attack_map: dict[str, list[str]] = {}
        cfg_signal_map: dict[str, list[str]] = {}
        cfg_ranges: dict[str, tuple[float, float]] = {}
        param_specs: dict[str, dict] = {}
        for conf in data.get("configurations", []):
            attacks = conf.get("dos_attacks", [])
            sigs = conf.get("signals", [])
            c_min, c_max = conf.get("range", [None, None])
            if c_min is not None and c_max is not None:
                cfg_ranges[conf.get("variable")] = (float(c_min), float(c_max))
            cfg_signal_map[conf.get("variable")] = list(set(sigs))
            for atk in attacks:
                attack_map.setdefault(atk, [])
                for s in sigs:
                    if s not in attack_map[atk]:
                        attack_map[atk].append(s)
            if c_min is not None and c_max is not None:
                param_specs[conf["variable"]] = {
                    "value": conf.get("default"),
                    "min": float(c_min),
                    "max": float(c_max),
                    "component": conf.get("package"),
                    "py_type": conf.get("py_type"),
                }
        return signal_ranges, attack_map, cfg_signal_map, cfg_ranges, param_specs

    @staticmethod
    def load_config(path: str):
        """
        Load configuration from JSON file and construct Signal objects.
        Returns signal objects dict alongside other config data.
        """
        p = Path(path)
        if not p.is_absolute():
            candidate = ROOT / p
            if candidate.exists():
                p = candidate
            else:
                alt = HERE / p
                if alt.exists():
                    p = alt
        data = json.loads(p.read_text())

        # Build Signal objects with metadata
        signal_objects = {}
        for name, meta in data.get("metadata", {}).get("signals", {}).items():
            rng = meta.get("normal_range")
            if rng and len(rng) == 2:
                # Calculate baseline as midpoint if not specified
                baseline = meta.get("normal_baseline", (rng[0] + rng[1]) / 2.0)
                signal_objects[name] = Signal(
                    name=name,
                    description=meta.get("description", ""),
                    normal_range=(float(rng[0]), float(rng[1])),
                    normal_baseline=float(baseline)
                )

        # Build other config data (same as original load_config)
        attack_map: dict[str, list[str]] = {}
        cfg_signal_map: dict[str, list[str]] = {}
        cfg_ranges: dict[str, tuple[float, float]] = {}
        param_specs: dict[str, dict] = {}

        for conf in data.get("configurations", []):
            attacks = conf.get("dos_attacks", [])
            sigs = conf.get("signals", [])
            c_min, c_max = conf.get("range", [None, None])
            if c_min is not None and c_max is not None:
                cfg_ranges[conf.get("variable")] = (float(c_min), float(c_max))
            cfg_signal_map[conf.get("variable")] = list(set(sigs))
            for atk in attacks:
                attack_map.setdefault(atk, [])
                for s in sigs:
                    if s not in attack_map[atk]:
                        attack_map[atk].append(s)
            if c_min is not None and c_max is not None:
                param_specs[conf["variable"]] = {
                    "value": conf.get("default"),
                    "min": float(c_min),
                    "max": float(c_max),
                    "component": conf.get("package"),
                    "py_type": conf.get("py_type"),
                    "signals": conf.get("signals")
                }

        return signal_objects, attack_map, cfg_signal_map, cfg_ranges, param_specs
