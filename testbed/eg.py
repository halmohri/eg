#!/usr/bin/env python3
"""
Elastic Guard main loop that runs health metrics on an interval.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
import json
from typing import Any

# Adjust import path so this runs from anywhere
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

def _add_repo_root() -> None:
    for base in [HERE] + list(HERE.parents):
        if (base / "optimizer").is_dir():
            resolved = base.resolve()
            if str(resolved) not in sys.path:
                sys.path.insert(0, str(resolved))
            return
    resolved = ROOT.resolve()
    if str(resolved) not in sys.path:
        sys.path.insert(0, str(resolved))

_add_repo_root()

import datetime

from testbed import health_check
from testbed.health_check import HealthOracle
from testbed.attacks import AttackSignal
from testbed.inspector import NginxConfigInspector
from testbed.apply_config import NginxConfigApplier
from optimizer.PhysicsGuidedLearner import PhysicsGuidedLearner


DEFAULT_INTERVAL = 10.0
DEFAULT_ITERATIONS = 10


class ElasticGuardUtility:
    @staticmethod
    def resolve_iterations(value: str) -> int | None:
        if value.lower() in {"inf", "infinite", "forever"}:
            return None
        return int(value)

    @staticmethod
    def format_metrics(metrics: dict[str, str]) -> str:
        keys = [
            "timestamp",
            "cpu",
            "mem",
            "cpu_health",
            "mem_health",
            "net_health",
            "tp_health",
            "conn_health",
            "req_rate",
            "conn_count",
            "stub_active",
            "stub_reading",
            "stub_writing",
            "stub_waiting",
            "req_avg",
            "upstream_avg",
            "net_bps",
            "rx_bps",
            "tx_bps",
            "net_iface",
        ]
        parts = []
        for key in keys:
            val = metrics.get(key, "na")
            if key in {"cpu", "mem"}:
                parts.append(f"{key}={val}%")
            else:
                parts.append(f"{key}={val}")
        return " ".join(parts)


class ElasticGuard:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.iface = (
            args.interface
            or health_check.detect_default_interface()
            or health_check.fallback_interface()
        )
        self.run_id = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.log_path = Path(self.args.log_file)
        self.inspector = NginxConfigInspector(Path(self.args.settings))
        self.oracle: HealthOracle | None = None
        self.learner: PhysicsGuidedLearner | None = None
        self.param_specs = health_check.load_param_specs(Path(self.args.settings))
        self.attack_signal = AttackSignal()
        self.applier = NginxConfigApplier(Path(self.args.settings))
        self.model_path = self.args.model_path

    def run(self) -> int:
        if not health_check.check_root():
            return 1
        if self.iface is None:
            print("[error] Unable to detect active network interface")
            return 1
        self._clear_log()
        self._apply_baseline()
        self.oracle = HealthOracle(Path(self.args.access_log), self.iface, self.args.interval)
        self.oracle.prime()
        self._init_learner()

        iterations = ElasticGuardUtility.resolve_iterations(self.args.iterations)
        count = 0
        while True:
            time.sleep(max(0.1, self.args.interval))
            metrics = self._health_snapshot(count + 1)
            line = ElasticGuardUtility.format_metrics(metrics)
            print(line)
            self._checkpoint(count + 1, metrics)
            self._log_line(metrics)
            count += 1
            if iterations is not None and count >= iterations:
                break

        return 0

    def _clear_log(self) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.write_text("", encoding="utf-8")
        except Exception as exc:
            print(f"[log] clear skipped: {exc}")

    def _apply_baseline(self) -> None:
        try:
            result = self.applier.apply(
                dry_run=self.args.dry_run,
                reload_only=self.args.reload_only,
            )
        except Exception as exc:
            print(f"[baseline_apply] failed: {exc}")
            return
        code = result.get("code", 1)
        if code == 0:
            print("[baseline_apply] applied baseline settings")
        else:
            print(f"[baseline_apply] apply returned code={code}")

    def _init_learner(self) -> None:
        self.learner = PhysicsGuidedLearner(self.param_specs)
        if self.args.load_model:
            try:
                self.learner.load_into(self.model_path)
                print(f"[learner] loaded model from {self.model_path}")
            except Exception as exc:
                print(f"[learner] load skipped: {exc}")

    def save_model(self) -> None:
        if self.learner is None or not self.args.save_model:
            return
        try:
            self.learner.save(self.model_path)
            print(f"[learner] saved model to {self.model_path}")
        except Exception as exc:
            print(f"[learner] save skipped: {exc}")

    def _health_snapshot(self, iteration: int) -> dict[str, str]:
        if self.oracle is None:
            raise RuntimeError("Health oracle is not initialized")
        metrics = self.oracle.sample_raw()
        scores = self.oracle.calculate_health_score(metrics)
        if len(scores) == 4:
            metrics["cpu_health"] = f"{scores[0]:.4f}"
            metrics["mem_health"] = f"{scores[1]:.4f}"
            metrics["net_health"] = f"{scores[2]:.4f}"
            metrics["tp_health"] = f"{scores[3]:.4f}"
        elif len(scores) == 5:
            metrics["cpu_health"] = f"{scores[0]:.4f}"
            metrics["mem_health"] = f"{scores[1]:.4f}"
            metrics["net_health"] = f"{scores[2]:.4f}"
            metrics["tp_health"] = f"{scores[3]:.4f}"
            metrics["conn_health"] = f"{scores[4]:.4f}"
        metrics["run_id"] = self.run_id
        metrics["iteration"] = str(iteration)
        return metrics

    def _checkpoint(self, step: int, metrics: dict[str, str]) -> None:
        configs = self.inspector.get_current_values()
        print("[checkpoint]", ElasticGuardUtility.format_metrics(metrics))
        for name, info in configs.items():
            print(f"[checkpoint_config] {name}={info['value']}")
        attack_info = self.attack_signal.get_attack_context(metrics)
        metrics["attack_profile"] = attack_info[0]
        metrics["attack_confidence"] = f"{attack_info[1]:.4f}"
        self._update_learner(metrics, configs, attack_info)
        zone_info = self._zone_check(metrics, attack_info)
        metrics.update(zone_info)
        if not self.args.no_recommend and zone_info.get("recommendation"):
            metrics["recommendation"] = zone_info["recommendation"]
            applied = self._apply_config(zone_info["recommendation"])
            if applied is not None:
                metrics["applied"] = applied
        print(f"[checkpoint_attack] {attack_info[0]} conf={attack_info[1]:.2f}")
        return

    def _log_line(self, metrics: dict[str, str]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(metrics, sort_keys=True) + "\n")

    def _zone_check(
        self, metrics: dict[str, str], attack_info: tuple[str, float]
    ) -> dict[str, Any]:
        if self.oracle is None:
            return {}
        health_scores = self.oracle.calculate_health_score(metrics)
        if not health_scores:
            return {}
        stress = 1.0 - min(health_scores)
        if stress > 0.85:
            print(f"[checkpoint_zone] crisis stress={stress:.2f}")
            if self.args.no_recommend:
                return {"zone": "crisis", "stress": f"{stress:.4f}"}
            recommended = self._recalibrate_system_params(
                beta=2.0, attack_info=attack_info
            )
            return {
                "zone": "crisis",
                "stress": f"{stress:.4f}",
                "recommendation": recommended,
            }
        elif stress > 0.5:
            print(f"[checkpoint_zone] stress stress={stress:.2f}")
            if self.args.no_recommend:
                return {"zone": "stress", "stress": f"{stress:.4f}"}
            recommended = self._recalibrate_system_params(
                beta=0.1, attack_info=attack_info
            )
            return {
                "zone": "stress",
                "stress": f"{stress:.4f}",
                "recommendation": recommended,
            }
        print(f"[checkpoint_zone] safe stress={stress:.2f}")
        return {"zone": "safe", "stress": f"{stress:.4f}"}

    def _recalibrate_system_params(
        self, beta: float, attack_info: tuple[str, float]
    ) -> dict[str, float]:
        if self.learner is None:
            return {}
        candidates = self.learner.generate_random_candidates(n_samples=500)
        if not candidates:
            return {}
        try:
            best = self.learner.select_best_config(attack_info, candidates, beta=beta)
        except Exception as exc:
            print(f"[learner] select skipped: {exc}")
            return {}
        if best:
            best_casted = self._cast_config_values(best)
            print(f"[checkpoint_recommendation] {best_casted}")
            return best_casted
        return {}

    def _apply_config(self, recommended: dict[str, float]) -> dict[str, Any] | None:
        try:
            result = self.applier.apply(
                overrides=recommended,
                dry_run=self.args.dry_run,
                reload_only=self.args.reload_only,
            )
        except Exception as exc:
            print(f"[checkpoint_apply] failed: {exc}")
            return
        code = result.get("code", 1)
        if code == 0:
            applied = result.get("applied", {})
            print(f"[checkpoint_apply] applied {applied}")
            return applied
        else:
            print(f"[checkpoint_apply] apply returned code={code}")
        return None

    def _update_learner(
        self,
        metrics: dict[str, str],
        current_configs: dict[str, dict[str, Any]],
        attack_info: tuple[str, float],
    ) -> None:
        if self.learner is None:
            return
        health_scores = self.oracle.calculate_health_score(metrics) if self.oracle else []
        if not health_scores:
            return
        config_dict = health_check.prepare_learner_config(
            self.param_specs, current_configs
        )
        if not config_dict:
            return
        config_dict = self._cast_config_values(config_dict)
        health = self.oracle.summary_health_score(health_scores) if self.oracle else 0.0
        try:
            self.learner.update_model(attack_info, config_dict, health)
        except Exception as exc:
            print(f"[learner] update skipped: {exc}")

    def _cast_config_values(self, config_dict: dict[str, float]) -> dict[str, float]:
        casted: dict[str, float] = {}
        for name, value in config_dict.items():
            spec = self.param_specs.get(name, {})
            py_type = spec.get("py_type")
            if py_type == "int":
                casted[name] = int(round(value))
            else:
                casted[name] = float(value)
        return casted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Elastic Guard health loop.")
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="Seconds between health checks (default: 10)",
    )
    parser.add_argument(
        "--iterations",
        default=str(DEFAULT_ITERATIONS),
        help="Number of iterations to run or 'inf' (default: 10)",
    )
    parser.add_argument(
        "--access-log",
        default=str(health_check.DEFAULT_ACCESS_LOG),
        help="Path to nginx access log (default: /var/log/nginx/access.log)",
    )
    parser.add_argument(
        "--interface",
        help="Network interface name (default: detect active interface)",
    )
    parser.add_argument(
        "--settings",
        default="testbed/workload_settings.yaml",
        help="Path to nginx settings YAML (default: testbed/workload_settings.yaml)",
    )
    parser.add_argument(
        "--log-file",
        default="eg_health_metrics.log",
        help="Path to JSONL log file (default: eg_health_metrics.log)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and plan config changes but skip reload/restart",
    )
    parser.add_argument(
        "--reload-only",
        action="store_true",
        help="Reload nginx but skip restart",
    )
    parser.add_argument(
        "--no-recommend",
        action="store_true",
        help="Disable recommendation selection and application",
    )
    parser.add_argument(
        "--model-path",
        default="learner_state.pkl",
        help="Path to save/load learner model state",
    )
    parser.add_argument(
        "--load-model",
        action="store_true",
        help="Load learner model state at startup",
    )
    parser.add_argument(
        "--save-model",
        action="store_true",
        help="Save learner model state on exit",
    )
    return parser


def run_with_args(args: argparse.Namespace) -> tuple[int, ElasticGuard]:
    guard = ElasticGuard(args)
    return guard.run(), guard


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    code, _ = run_with_args(args)
    return code


if __name__ == "__main__":
    guard: ElasticGuard | None = None
    code: int | None = None
    try:
        parser = build_parser()
        args = parser.parse_args()
        code, guard = run_with_args(args)
        if guard is not None:
            guard.save_model()
        raise SystemExit(code)
    except KeyboardInterrupt:
        print("[info] interrupted; shutting down")
        if guard is not None:
            guard.save_model()
        raise SystemExit(130)
    except Exception as exc:  # pragma: no cover - CLI guardrail
        print(f"[error] {exc}")
        if guard is not None:
            guard.save_model()
        raise SystemExit(1)
