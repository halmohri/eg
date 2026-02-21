#!/usr/bin/env python3
"""
Guided simulator using PhysicsGuidedLearner (physics-informed GP).
"""
from __future__ import annotations

import sys
import random
from typing import Dict, Any, List
from pathlib import Path

# Adjust import path so this runs from anywhere
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from simulation.simulation import BaseSimulator
from oracle.oracle import AttackOracle
from inspector.inspector import ConfigInspector
from inspector.signals import AdvancedSignals
from optimizer.PhysicsGuidedLearner import PhysicsGuidedLearner


class GuidedSimulator(BaseSimulator):
    """Simulator using physics-guided GP learner (PhysicsGuidedLearner)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Learner is initialized after the real inspector (with specs) is attached in main.
        self.learner = None

    def _build_input_vector(self, profile: Dict[str, Any]):
        defaults = self.inspector.get_attack_param_specs()
        attacks = profile.get("attacks", [])
        attack_info = ("normal", 0.0)
        if attacks:
            best = max(attacks, key=lambda a: float(a.get("confidence", 0.0)))
            best_conf = float(best.get("confidence", 0.0))
            attack_info = (best.get("attack_profile", "normal"), best_conf)
        config_vals = {k: spec["value"] for k, spec in defaults.items()}
        return attack_info, config_vals

    def _learn_from_cycle(self, profile: Dict[str, Any], health_scores: List[float]) -> None:
        """
        Pass observation to the GP learner: attack context + config -> health.
        """
        if not health_scores:
            return
        attack_info, vec = self._build_input_vector(profile)
        #self._log(f"  input_vector: attack={attack_info}")
        try:
            #health = sum(health_scores) / len(health_scores)
            health = min(health_scores)
            self.learner.update_model(attack_info, vec, health)
        except Exception as exc:
            self._log(f"learning skipped due to error: {exc}")

    def _recalibrate_system_params(
        self,
        profile: Dict[str, Any],
        avg_cpu_mem: float,
        beta: float = 1.96,
        stability_lambda: float = 0.1,
    ) -> None:
        """Adjust system parameters based on optimizer recommendation."""
        potentials = self._potentials
        defaults = self.inspector.get_attack_param_specs()
        attack = profile.get("attacks", [])
        attack_info = ("normal", 0.0)
        if attack:
            best = max(attack, key=lambda a: float(a.get("confidence", 0.0)))
            attack_info = (best.get("attack_profile", "normal"), float(best.get("confidence", 0.0)))
        try:
            # build candidate list with sampling to avoid combinatorial explosion
            keys = list(defaults.keys())
            value_lists = [potentials.get(k, []) for k in keys]
            candidates = []
            if any(len(v) == 0 for v in value_lists):
                self._log("config selection skipped: no candidates")
                return
            sample_size = 5000
            total = 1
            for vals in value_lists:
                total *= max(1, len(vals))
                if total > sample_size:
                    break
            if total <= sample_size:
                import itertools
                for vals in itertools.product(*value_lists):
                    candidates.append(dict(zip(keys, vals)))
            else:
                seen = set()
                attempts = 0
                max_attempts = sample_size * 10
                while len(candidates) < sample_size and attempts < max_attempts:
                    attempts += 1
                    choice = tuple(random.choice(vals) for vals in value_lists)
                    if choice in seen:
                        continue
                    seen.add(choice)
                    candidates.append(dict(zip(keys, choice)))
            best_cfg = self.learner.select_best_config(attack_info, candidates, beta=beta)
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
    args = parser.parse_args()

    signal_specs, atk_map, cfg_sig_map, cfg_ranges, param_specs = BaseSimulator.load_config(args.config_path)

    print("PArameters: ")
    print(f"{param_specs}")
    inspector = ConfigInspector(param_specs=param_specs)
    signals = AdvancedSignals(
        signal_specs=signal_specs,
        attack_signals=atk_map,
        config_signal_map=cfg_sig_map,
        config_ranges=cfg_ranges,
        config_provider=inspector.get_attack_param_specs,
    )
    oracle = AttackOracle(signals=signals)

    print(f"{inspector.param_specs}")

    sim = GuidedSimulator(
        oracle,
        pattern=args.pattern,
        attack_type=args.attack_type,
        steps=args.steps,
        check_interval=args.check_interval,
        output=Path(args.output),
        attack_threshold=args.attack_threshold,
        adaptive_checkpoints=args.adaptive_checkpoints,
    )
    sim.inspector = inspector
    sim.learner = PhysicsGuidedLearner(inspector.get_attack_param_specs())
    sim._potentials = inspector.generate_potential_configs()
    sim.run()
    sim.save_results()
