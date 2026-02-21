#!/usr/bin/env python3
"""
Search simulator using ResilienceLearner (standard GP-UCB).
"""
from __future__ import annotations

import sys
from typing import Dict, Any, List
from pathlib import Path
import numpy as np
from pprint import pprint 

# Adjust import path so this runs from anywhere
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from simulation.simulation import BaseSimulator
from oracle.oracle import AttackOracle
from inspector.inspector import ConfigInspector
from inspector.signals import AdvancedSignals
from optimizer.GP_learner import ResilienceLearner


class SearchSimulator(BaseSimulator):
    """Simulator using standard GP-UCB learner (ResilienceLearner)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.learner = ResilienceLearner()

    def _build_input_vector(self, profile: Dict[str, Any]):
        defaults = self.inspector.get_attack_param_specs()
        attacks = profile.get("attacks", [])
        attack_info = ("normal", 0.0)
        if attacks:
            best = max(attacks, key=lambda a: float(a.get("confidence", 0.0)))
            best_conf = float(best.get("confidence", 0.0))
            attack_info = (best.get("attack_profile", "normal"), best_conf)
        
        vec = ResilienceLearner.build_input_vector(attack_info, defaults)
        return attack_info, vec

    def _log_input_vector(self, attack_info, vec) -> None:
        self._log(f"  input_vector: attack={attack_info} vec={vec.tolist()}")

    def _learn_from_cycle(self, profile: Dict[str, Any], health_scores: List[float]) -> None:
        """
        Pass observation to the GP learner: attack context + config -> health.
        """
        if not health_scores:
            return
        attack_info, vec = self._build_input_vector(profile)
        #self._log_input_vector(attack_info, vec)
        if vec is None or vec.size == 0:
            return
        X_vector = vec[0, :].tolist()
        try:
            #health = sum(health_scores) / len(health_scores)
            health = min(health_scores)
            self.learner.update_model(X_vector, health)
        except Exception as exc:
            self._log(f"learning skipped due to error: {exc}")

    def _recalibrate_system_params(
        self,
        profile: Dict[str, Any],
        avg_cpu_mem: float,
        beta: float = 1.96,
        stability_lambda: float = 0.1,
    ) -> None:
        
        print("RECALIBRATING... ")
        
        """Adjust system parameters based on optimizer recommendation."""
        potentials = self._potentials
        defaults = self.inspector.get_attack_param_specs()
        attack = profile.get("attacks", [])
        attack_info = ("normal", 0.0)
        if attack:
            best = max(attack, key=lambda a: float(a.get("confidence", 0.0)))
            attack_info = (best.get("attack_profile", "normal"), float(best.get("confidence", 0.0)))
        try:
            best_cfg = self.learner.select_best_config(
                attack_info,
                potentials,
                defaults,
                beta=beta,
                stability_lambda=stability_lambda,
            )
        except Exception as exc:
            self._log(f"config selection skipped due to error: {exc}")
            return
        # apply recommended values to inspector specs
        updates = {}
        applied_cfg = {}
        for k, v in best_cfg.items():
            if k not in defaults:
                continue
            py_t = defaults[k].get("py_type")
            if py_t == "int":
                v = int(round(v))
            updates[k] = {"value": v}
            applied_cfg[k] = v
        prev = {k: defaults[k]["value"] for k in defaults}
        if updates:
            self.inspector.modify_configs(updates)
        self._log("  recalibration applied:")
        for k in defaults:
            new_val = applied_cfg.get(k, prev[k])
            self._log(f"    {k}: {prev[k]} -> {new_val}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run attack signal simulator.")
    parser.add_argument("--pattern", choices=["linear", "exponential", "sine", "bell", "triple_bell"], default="bell")
    parser.add_argument("--attack-type", choices=["normal", "slowloris", "http_flood", "simple"], default="slowloris")
    parser.add_argument("--steps", type=int, default=20)
    parser.add_argument("--check-interval", type=int, default=5)
    parser.add_argument("--output", default="simulation_results.json")
    parser.add_argument("--attack-threshold", type=float, default=0.6, help="minimum confidence to treat as attack")
    parser.add_argument("--config-path", default="simulation/config_nodes_compact.json", help="path to config/signal metadata")
    parser.add_argument("--adaptive-checkpoints", action="store_true", help="shrink checkpoint interval when recalibrating")
    parser.add_argument("--static", action="store_true", help="disable learning and recalibration")
    parser.add_argument("--improve-off", action="store_true", help="disable config improvement/recalibration logic")
    args = parser.parse_args()

    signal_specs, atk_map, cfg_sig_map, cfg_ranges, param_specs = BaseSimulator.load_config(args.config_path)

    inspector = ConfigInspector(param_specs=param_specs)
    signals = AdvancedSignals(
        signal_specs=signal_specs,
        attack_signals=atk_map,
        config_signal_map=cfg_sig_map,
        config_ranges=cfg_ranges,
        config_provider=inspector.get_attack_param_specs,
    )
    oracle = AttackOracle(signals=signals)

    sim = SearchSimulator(
        oracle,
        pattern=args.pattern,
        attack_type=args.attack_type,
        steps=args.steps,
        check_interval=args.check_interval,
        output=Path(args.output),
        attack_threshold=args.attack_threshold,
        adaptive_checkpoints=args.adaptive_checkpoints,
        improve_configs=not args.improve_off,
    )
    sim.inspector = inspector
    sim._potentials = inspector.generate_potential_configs()
    sim.run()
    sim.save_results()
