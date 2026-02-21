from copy import deepcopy
import random


class ConfigInspector:

    def __init__(self, param_specs: dict | None = None):
        self.param_specs = deepcopy(param_specs) 

    def get_attack_param_specs(self) -> dict:
        """Return current attack-related parameter specs."""
        return deepcopy(self.param_specs)

    def modify_configs(self, updates: dict) -> dict:
        """
        Apply updates to current specs. Expects the same shape as param specs.
        Only updates keys present in the existing spec unless the update contains full fields.
        """
        for key, new_spec in updates.items():
            if key not in self.param_specs:
                if {"value", "min", "max"}.issubset(new_spec.keys()):
                    self.param_specs[key] = deepcopy(new_spec)
                continue
            merged = self.param_specs[key].copy()
            merged.update({k: v for k, v in new_spec.items() if k in {"value", "min", "max", "component", "py_type"}})
            self.param_specs[key] = merged
        return self.get_attack_param_specs()

    def generate_potential_configs(self, k: int = 1000) -> dict:
        """
        Generate k candidate values per parameter, sampled across the allowed range.
        The range is split into k segments; one random draw per segment.
        Returns a dict {param: [candidates...]}. Stores the last generation on self.potentials.
        """
        potentials = {}
        for key, spec in self.param_specs.items():
            lo, hi = float(spec["min"]), float(spec["max"])
            if k <= 0 or lo >= hi:
                potentials[key] = [spec["value"]]
                continue
            step = (hi - lo) / k
            choices = []
            for i in range(k):
                seg_lo = lo + i * step
                seg_hi = lo + (i + 1) * step
                val = random.uniform(seg_lo, seg_hi)
                if spec.get("py_type") == "int":
                    val = int(round(val))
                choices.append(val)
            potentials[key] = choices
        self.potentials = potentials
        return potentials

    def graph_filter(self, potentials: dict) -> dict:
        """
        Placeholder filter; returns the potentials unchanged.
        """
        return potentials
