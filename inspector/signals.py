from __future__ import annotations
import random
import json
from pathlib import Path
import numpy as np 

class Signal:
    def __init__(self, name: str, description: str, normal_range: tuple[float, float], normal_baseline: float, value: float = 0.0):
        self.name = name
        self.description = description
        self.normal_range = normal_range  # (min, max)
        self.normal_baseline = normal_baseline
        self.value = value

class Configuration:
    def __init__(self):
        pass


class Signals:
    """
    Encapsulate signal generation and health computation based on hardware and configs.
    """

    def __init__(
        self,
        mem_gb: float = 8.0,
        cpu_cores: int = 4,
        net_mbps: float = 100.0,
        config: dict | None = None,
        config_provider=None,
        config_signal_map: dict | None = None,
        config_ranges: dict | None = None,
    ) -> None:
        self.mem_gb = mem_gb
        self.cpu_cores = cpu_cores
        self.net_mbps = net_mbps
        self.config = config or {}
        #self.config_provider = config_provider
        self.config_signal_map = config_signal_map or {}
        self.config_ranges = config_ranges or {}

    def simulate_signal(self, cfgs, signal_type: str = "normal") -> dict:
        sims = {
            "normal": self._simulate_normal,
            "slowloris": self._simulate_slowloris,
            "http_flood": self._simulate_flood,
            "simple": self._simulate_simple_attack,
        }

        func = sims.get(signal_type, self._simulate_normal)
        attack_sig = func()
        attack_sig = self._apply_config_constraints(cfgs,attack_sig)
        # health_sig = self.health_check(attack_sig)
        # attack_sig.update(health_sig)
        return attack_sig

    def filter_health(self, signal: dict) -> dict:
        """Filter to health signals only. signal is dict of Signal objects."""
        keys = {"cpu_usage", "memory_usage", "latency", "goodput"}
        return {k: signal[k] for k in signal if k in keys}

    def filter_attack(self, signal: dict) -> dict:
        """Filter to attack signals only. signal is dict of Signal objects."""
        health_keys = {"cpu_usage", "memory_usage", "latency"}
        return {k: v for k, v in signal.items() if k not in health_keys}

    @staticmethod
    def get_signals(attack_sig): 
        conn_util = attack_sig.get("connection_utilization")
        req_rate = attack_sig.get("request_rate")
        err_rate = attack_sig.get("error_rate")
        timeout_act = attack_sig.get("timeout_activity")
        queue_depth = attack_sig.get("queue_depth")
        rate_limit = attack_sig.get("rate_limit_activity")
        socket_state = attack_sig.get("socket_state")
        worker_sat = attack_sig.get("worker_saturation")
        return conn_util, req_rate, err_rate, timeout_act, queue_depth, rate_limit, socket_state, worker_sat

    @staticmethod
    def get_signal_values(attack_sig):
        """
        Return numeric values for attack signals, unwrapping Signal objects when present.
        """
        (
            conn_util,
            req_rate,
            err_rate,
            timeout_act,
            queue_depth,
            rate_limit,
            socket_state,
            worker_sat,
        ) = Signals.get_signals(attack_sig)

        def _val(x):
            return float(x.value) if isinstance(x, Signal) else float(x or 0)

        return (
            _val(conn_util),
            _val(req_rate),
            _val(err_rate),
            _val(timeout_act),
            _val(queue_depth),
            _val(rate_limit),
            _val(socket_state),
            _val(worker_sat),
        )

    def health_check(self, attack_sig: dict) -> dict:
        pass

    # def _get_config(self) -> dict:
    #     return self.config_provider()

    def _apply_config_constraints(self, sig: dict) -> dict:
        pass

    def _simulate_normal(self) -> dict:
        pass

    def _simulate_slowloris(self) -> dict:
        pass

    def _simulate_flood(self) -> dict:
        pass

    def _simulate_simple_attack(self) -> dict: 
        pass 


class AdvancedSignals(Signals):
    """
    Placeholder for advanced signal modeling; extends Signals.
    Expects signal_ranges to be provided explicitly.
    """

    def __init__(
        self,
        signal_specs: dict | None = None,
        attack_signals: dict | None = None,
        config_signal_map: dict | None = None,
        config_ranges: dict | None = None,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.signal_specs = signal_specs or {}  # dict[str, Signal]
        # attack_signals maps attack -> list of signal names (from config metadata)
        self.attack_signals = attack_signals or {}
        self.config_signal_map = config_signal_map or {}
        self.config_ranges = config_ranges or {}

    def _simulate_normal(self) -> dict:
        """
        Generate attack-facing signals based on ranges from the config metadata.
        Returns dict of Signal objects with updated values.
        """
        if not self.signal_specs:
            return super()._simulate_normal()
        sig = {}
        for name, signal in self.signal_specs.items():
            lo, hi = signal.normal_range
            value = random.uniform(lo, hi)*.3
            sig[name] = Signal(
                name=signal.name,
                description=signal.description,
                normal_range=signal.normal_range,
                normal_baseline=signal.normal_baseline,
                value=value
            )
        return sig

    def _simulate_slowloris(self) -> dict:
        """
        Generate slowloris-like signals by amplifying relevant metrics relative to normal ranges.
        Uses fuzzy keyword matching to decide which signals to amplify.
        """
        if not self.signal_specs:
            return super()._simulate_slowloris()
        sig = self._simulate_normal()
        relevant = ['connection_utilization','timeout_activity','socket_state','worker_saturation']
        for name in relevant:
            if name not in self.signal_specs:
                continue
            signal_spec = self.signal_specs[name]
            lo, hi = signal_spec.normal_range
            span = hi - lo
            
            new_lo = lo * 5  # push toward high
            new_hi = hi + span * 25
            value = random.uniform(new_lo, new_hi)*1000

            print(f"SIGNAL {name}: {value}")
            
            sig[name] = Signal(
                name=signal_spec.name,
                description=signal_spec.description,
                normal_range=signal_spec.normal_range,
                normal_baseline=signal_spec.normal_baseline,
                value=value
            )
        return sig

    def _simulate_flood(self) -> dict:
        """
        Generate simple flood attack signals by amplifying some signals.
        """
        if not self.signal_specs:
            return super()._simulate_simple_attack()
        sig = self._simulate_normal()
        relevant = ["request_rate","connection_utilization","worker_saturation"]
        for name in relevant:
            if name not in self.signal_specs:
                continue
            signal_spec = self.signal_specs[name]
            lo, hi = signal_spec.normal_range
            span = hi - lo
            new_lo = lo + span * 5   # push toward high
            new_hi = hi + span * 55
            value = random.uniform(new_lo, new_hi)
            
            sig[name] = Signal(
                name=signal_spec.name,
                description=signal_spec.description,
                normal_range=signal_spec.normal_range,
                normal_baseline=signal_spec.normal_baseline,
                value=value
            )
        return sig
    
    def _simulate_simple_attack(self) -> dict:
        """
        Generate simple attack signals by amplifying request_rate metric.
        """
        if not self.signal_specs:
            return super()._simulate_simple_attack()
        sig = self._simulate_normal()
        relevant = ["request_rate","connection_utilization","worker_saturation"]
        for name in relevant:
            if name not in self.signal_specs:
                continue
            signal_spec = self.signal_specs[name]
            lo, hi = signal_spec.normal_range
            span = hi - lo
            new_lo = lo + span * 5   # push toward high
            new_hi = hi + span * 55
            value = random.uniform(new_lo, new_hi)
            
            sig[name] = Signal(
                name=signal_spec.name,
                description=signal_spec.description,
                normal_range=signal_spec.normal_range,
                normal_baseline=signal_spec.normal_baseline,
                value=value
            )
        return sig

    def _attack_signal_names(self, attack: str) -> list[str]:
        key = "http_flood" if attack == "flood" else attack
        return self.attack_signals.get(key, [])




    # def health_check(self, attack_sig: dict) -> dict:
    #     """
    #     Advanced health model based on config_nodes_compact signals.
    #     Includes Dynamic Timeout Penalty to distinguish 'Shedding' from 'Failing'.
    #     attack_sig is now a dict of Signal objects.
    #     """
    #     (
    #         conn_util,
    #         req_rate,
    #         err_rate,
    #         timeout_act,
    #         queue_depth,
    #         rate_limit,
    #         socket_state,
    #         worker_sat,
    #     ) = self.get_signal_values(attack_sig)

    #     cpu = (
    #         worker_sat * 100
    #         + conn_util * 60
    #         + (req_rate / max(1.0, self.cpu_cores * 100.0)) * 100
    #         + err_rate * 200
    #     )
    #     cpu = max(0.0, min(cpu, 200.0))

    #     mem = queue_depth * 150 + (socket_state / 100.0) * 50 + worker_sat * 40
    #     mem = max(0.0, min(mem, 200.0))

    #     # --- DYNAMIC TIMEOUT LOGIC ---
    #     # If workers are unsaturated (low load), timeouts are "Good Shedding".
    #     # If workers are saturated (high load), timeouts are "Bad Service Failure".
    #     # We scale the penalty by worker_sat.
    #     timeout_impact = timeout_act * worker_sat * 1000.0

    #     net_factor = (req_rate + rate_limit) / max(1.0, self.net_mbps)
        
    #     latency = (
    #         30.0
    #         + timeout_impact       # Replaces static 'timeout_act * 500'
    #         + conn_util * 200
    #         + rate_limit * 50
    #         + net_factor * 100
    #     )
    #     latency = max(0.0, min(latency, 2000.0))

    #     return {
    #         "cpu_usage": Signal("cpu_usage", "CPU usage percentage", (0, 200), 50.0, cpu),
    #         "memory_usage": Signal("memory_usage", "Memory usage percentage", (0, 200), 50.0, mem),
    #         "latency": Signal("latency", "Request latency in ms", (0, 2000), 30.0, latency),
    #     }

    def _processed_rate(self,rate, limit, beta=0.1):
        return rate * (limit / (limit + beta * rate))

    def _worker_saturation(self, processed_rate, workers, cap_per_worker=50.0, gamma=1.0):
        """
        processed_rate: effective admitted requests/sec
        workers: number of worker processes
        cap_per_worker: "comfortable" req/sec per worker
        gamma: controls how sharply saturation approaches 1
        """
        workers = max(1, workers)
        per_worker_load = processed_rate / workers      # load per worker

        # Normalize load vs capacity and squash to (0,1)
        x = per_worker_load / cap_per_worker           # dimensionless
        return x / (x + gamma)                         # smooth, in (0,1)


    def _apply_config_constraints(self, cfgs, sig: dict) -> dict:
        """
        Apply config constraints to Signal objects.
        sig is a dict of Signal objects.
        """
        # apply limit_req_rate limits to request_rate
        limit = cfgs["limit_req_rate"]["value"]
        workers = cfgs["workers"]["value"]
        timeout = cfgs["timeout"]["value"]
        keepalive_timeout = cfgs["keepalive_timeout"]["value"]

        rate_obj = sig["request_rate"]
        error_obj = sig["error_rate"]
        worker_obj = sig["worker_saturation"]
        timeout_obj = sig["timeout_activity"]
        conn_util_obj = sig["connection_utilization"]

        # Limit error rate
        error_obj.value = self._processed_rate(error_obj.value, limit, beta=0.1)

        # Limit request rate
        old_rate = rate_obj.value
        processed_rate = self._processed_rate(old_rate, limit, beta=0.1)
        rate_obj.value = processed_rate
        
        # Limit worker saturation 
        worker_obj.value = self._worker_saturation(processed_rate, workers)

        # 3. Timeout activity (keepalive dominates)
        gamma_T = 3.0  # smoothing, in seconds
        base = timeout_obj.value  # whatever your model already computed
        scale = timeout / (timeout + gamma_T)  # → 0 as timeout→0, →1 as timeout→∞

        timeout_obj.value = base * scale

        
        print(f"timeout: {timeout_obj.value}")

        # 4. Connection utilization
        c, d = 1.0, 0.2
        W_eff = c * keepalive_timeout + d * timeout
        C_conn = 2000.0
        gamma_conn = 1.0

        x = (processed_rate * W_eff) / C_conn
        conn_util_obj.value = x / (x + gamma_conn)

        return sig 
