from __future__ import annotations
from typing import Dict, Any, List
import pandas as pd
from inspector.signals import AdvancedSignals
import numpy as np

class BaseAttackProfile:
    name: str = "generic"

    def __init__(self) -> None:
        self.last_conf: float = 0.0

    @staticmethod
    def normalize(value: float, method: str = "ratio", min_val: float = 0.0, max_val: float = 1.0) -> float:
        """
        Normalize a value to [0,1] using simple schemes:
          - ratio: value / max_val
          - invert_ratio: 1 - (value / max_val)
          - minmax: (value - min_val) / (max_val - min_val)
        Always clipped to [0,1].
        """
        try:
            val = float(value)
        except Exception:
            return 0.0

        if method == "ratio":
            denom = max_val if max_val not in (None, 0) else 1.0
            norm = val / denom
        elif method == "invert_ratio":
            denom = max_val if max_val not in (None, 0) else 1.0
            norm = 1.0 - (val / denom)
        elif method == "minmax":
            if max_val is None or min_val is None or max_val == min_val:
                norm = 0.0
            else:
                norm = (val - min_val) / (max_val - min_val)
        else:
            norm = 0.0

        return max(0.0, min(norm, 1.0))

    def detect(self, signal: Dict[str, Any]) -> float:
        """
        Return confidence in [0,1] for this attack type based on the signal.
        Must be overridden by subclasses.
        """
        raise NotImplementedError
    
    @staticmethod
    def anomaly_score(signal, alpha=0.2, beta=0.3):
        x = signal.value
        lo, hi = signal.normal_range
        """
        Compute anomaly score given:
        - x: value or numpy array
        - lo, hi: normal range bounds
        - alpha: max score inside normal range (0 to alpha)
        - beta: controls exponential growth above hi

        Returns score in [0, 1].
        """

        x = np.asarray(x)

        # Case 1: x <= lo → score = 0
        score = np.zeros_like(x, dtype=float)

        # Case 2: lo < x <= hi → linear ramp to alpha
        mask_normal = (x > lo) & (x <= hi)
        score[mask_normal] = alpha * (x[mask_normal] - lo) / (hi - lo)

        # Case 3: x > hi → exponential growth toward 1
        mask_high = x > hi
        r = (x[mask_high] - hi) / (hi - lo)
        score[mask_high] = alpha + (1 - alpha) * (1 - np.exp(-beta * r))

        return float(score)
    
    import numpy as np

    def majority_fusion(self, scores, threshold=None):
        """
        Majority-based fusion of anomaly scores using the top-k mean rule.

        Parameters
        ----------
        scores : array-like of floats in [0,1]
            The anomaly scores from different signals.
        threshold : float in [0,1], optional
            If provided, also compute a hard-majority flag:
            flag = 1 if the k-th largest score >= threshold else 0

        Returns
        -------
        soft_score : float
            The average of the top-k scores, where k = ceil(n/2)
            (the majority).
        flag : int (0 or 1), only if threshold is provided
            Hard majority decision.
        """

        scores = np.asarray(scores, dtype=float)
        n = len(scores)
        if n == 0:
            raise ValueError("scores must be non-empty")

        # Sort scores descending
        sorted_scores = np.sort(scores)[::-1]

        # k = majority count
        k = (n + 1) // 2     # equivalent to ceil(n/2)

        # Soft majority score: mean of the top-k scores
        soft_score = float(np.mean(sorted_scores[:k]))

        # Hard majority flag (optional)
        if threshold is not None:
            flag = 1 if sorted_scores[k-1] >= threshold else 0
            return soft_score, flag

        return soft_score

    @staticmethod
    def boost(conf: float, alpha: float = 0.4, beta: float = 4.0) -> float:
        """
        Exponential-ish boost: low confidences get a small nudge, higher ones accelerate.
        tuned so 0.1 -> ~0.12, 0.3 -> ~0.58 with defaults.
        """
        if conf <= 0:
            return 0.0
        factor = 1.0 + alpha * (pow(2.718281828459045, beta * conf) - 1.0)
        return max(0.0, min(1.0, conf * factor))


class SlowlorisProfile(BaseAttackProfile):
    name = "slowloris"

    def detect_absolute(self, signal: Dict[str, Any]) -> float:
        """signal is now dict of Signal objects."""
        if not signal:
            return 0.0
        
        conn_util,req_rate,err_rate,timeout_act,queue_depth,rate_limit,socket_state,worker_sat = AdvancedSignals.get_signals(signal)
        timeout_act = self.anomaly_score(req_rate,alpha=0.2,beta=1)
        conn_score = self.anomaly_score(conn_util,alpha=0.2,beta=1)
        worker_score = self.anomaly_score(worker_sat,alpha=0.2,beta=1)
        socket_score = self.anomaly_score(worker_sat,alpha=0.2,beta=1)
        
        return self.majority_fusion((timeout_act,socket_score))
        
    def detect(self, signal: Dict[str, Any], baseline: Dict[str, Any] | None = None) -> float:
        #print("PROFILE SIMPLE ATTACK.")
        return self.detect_absolute(signal)


class HttpFloodProfile(BaseAttackProfile):
    name = "http_flood"

    
class SimpleProfile(BaseAttackProfile):
    name = "simple"

    def detect_absolute(self, signal: Dict[str, Any]) -> float:
        """signal is now dict of Signal objects."""
        if not signal:
            return 0.0
        
        conn_util,req_rate,err_rate,timeout_act,queue_depth,rate_limit,socket_state,worker_sat = AdvancedSignals.get_signals(signal)
        rate_score = self.anomaly_score(req_rate,alpha=0.2,beta=1)
        conn_score = self.anomaly_score(conn_util,alpha=0.2,beta=1)
        worker_score = self.anomaly_score(worker_sat,alpha=0.2,beta=1)
        
        return self.majority_fusion((rate_score,conn_score,worker_score))
        
    def detect(self, signal: Dict[str, Any], baseline: Dict[str, Any] | None = None) -> float:
        #print("PROFILE SIMPLE ATTACK.")
        return self.detect_absolute(signal)


from dataclasses import dataclass

@dataclass
class HardwareCapacity:
    """
    Minimal hardware specification for computing resource health scores.
    Capacities are given in natural units so demand/capacity produces a ratio.
    """

    # ---- CPU Capacity ----
    num_cores: int = 2
    service_rate_per_core: float = 1.0
    # Effective CPU capacity in "normalized work units per second"
    @property
    def cpu_capacity(self) -> float:
        return self.num_cores * self.service_rate_per_core

    # ---- Memory Capacity ----
    memory_bytes: int = 16 * 1024 * 1024 * 1024   # 16 GB

    # ---- Network Capacity ----
    network_bytes_per_sec: float = 1_000_000_000 / 8   # 1 Gbps ≈ 125 MB/s

    # ---- Latency Budget ----
    # A "capacity" meaning: latency_health = demand / latency_budget
    # If demand > budget → latency problems
    latency_budget: float = 1.0     # unitless "acceptable latency load"

    # ---- Goodput Capacity ----
    # Maximum ideal throughput (req/s or normalized units)
    goodput_capacity: float = 10_000.0



class AttackOracle:
    """
    Oracle for generating attack signals and profiling attacks.

    Interfaces:
      - get_attack_signal(server_data: pd.DataFrame, signal_type: str) -> Dict[str, Any]
      - get_health_signals(server_data: pd.DataFrame, signal_type: str) -> Dict[str, Any]
      - profile_attack(signals: List[Dict[str, Any]], last_profile: Dict[str, Any], profiles: List[BaseAttackProfile]) -> Dict[str, Any]
    """

    def __init__(self, signals: AdvancedSignals | None = None) -> None:
        self.profiles: List[BaseAttackProfile] = [
            SlowlorisProfile(),
            HttpFloodProfile(),
            SimpleProfile(),
        ]
        self.signals = signals

    @property
    def signal_specs(self):
        """Access signal specs from the signals object."""
        return self.signals.signal_specs if self.signals else {}

    def simulate_signal(self, signal_type: str = "normal") -> Dict[str, Any]:
        return self.signals.simulate_signal(signal_type)

    def profile_attack(
        self,
        signals: List[Dict[str, Any]],
        last_profile: Dict[str, Any] = None,
        profiles: List[BaseAttackProfile] | None = None,
        recent_weight: float = 0.8,
        history_weight: float = 0.2,
    ) -> Dict[str, Any]:
        """
        Receive a batch of attack signals and return an attack profile dict.
        Uses last_profile (if provided) to smooth confidence.
        """
        attacks = []
        active_profiles = profiles if profiles is not None else self.profiles
        attack_only = [self.signals.filter_attack(sig) for sig in signals if sig]
        for profile in active_profiles:
            confs = [profile.detect(sig) for sig in attack_only if sig]
            if confs:
                weights = list(range(1, len(confs) + 1))  # favor recent signals
                conf = sum(c * w for c, w in zip(confs, weights)) / sum(weights)
            else:
                conf = 0.0
            if conf > 0:
                prev = getattr(profile, "last_conf", 0.0)
                # favor current window while retaining a bit of history
                conf = recent_weight * conf + history_weight * float(prev)
                profile.last_conf = conf
                attacks.append({"attack_profile": profile.name, "confidence": conf})
        if not attacks:
            attacks.append({"attack_profile": "generic_attack", "confidence": 1.0})
        return {"attacks": attacks}
    

    
    
    
    def _compute_latent_factors(
            self,
            conn_util,
            req_rate,
            err_rate,
            timeout_act,
            queue_depth,
            rate_limit,
            socket_state,
            worker_sat,
        ):
        "Producing three factors out of 9 signals."
        "This can be extended to include more signals"
        "when needed."

        primary = max(req_rate, conn_util)
        secondary = (queue_depth + 0.5 * rate_limit * timeout_act) / 3.0

        traffic_pressure = 0.7 * primary + 0.3 * secondary

        reliability_signals = [
            err_rate,
            timeout_act,
            socket_state * 0.5,  # supporting signal
        ]
        reliability_risk = sum(reliability_signals) / len(reliability_signals)

        worker_signals = [
            worker_sat,
            queue_depth * 0.7,   # partial effect
            conn_util * 0.7,     # partial effect
        ]
        worker_pressure = sum(worker_signals) / len(worker_signals)

        return traffic_pressure, reliability_risk, worker_pressure

    def reciprocal_inverse(self,value): 
        inverse = 1.0 / (1.0 + value)
        return inverse 
    def exp_inverse(self,h, k=3.0):
        return np.exp(-k * h)

    def _compute_resource_health(self,z_T, z_C, z_I, hw, attack_conf = 0.5):
        """
        Compute resource health ratios from latent factors and hardware capacity.

        Inputs
        ------
        z_T : float   # traffic_pressure  in [0,1]
        z_C : float   # concurrency/worker_pressure in [0,1]
        z_I : float   # instability/reliability_risk in [0,1]
        hw  : HardwareCapacity

        Returns
        -------
        cpu_health, mem_health, net_health, latency_health : floats
            Ratios (demand / capacity). Values > 1 mean over-capacity / poor health.
        """

        # ---- CPU demand and health ----
        # Mostly driven by concurrency, with traffic and instability contributing.
        # Units: "normalized CPU work units per second".
        D_cpu = 8.0 * z_C + 4.0 * z_T + 2.0 * z_I     # max ≈ 14 for z_* = 1
        cpu_health = D_cpu / hw.cpu_capacity          # hw.cpu_capacity = num_cores * service_rate_per_core

        # ---- Memory demand and health ----
        # Driven by concurrency (per-request state) and traffic (queues/buffers).
        # Convert memory capacity to GiB so demand lives on a similar numeric scale.
        mem_capacity_gib = hw.memory_bytes / (1024 ** 3)  # e.g., 16 for 16 GiB
        D_mem = 8.0 * z_C + 8.0 * z_T                    # max ≈ 16 when z_C=z_T=1
        mem_health = D_mem / mem_capacity_gib

        # ---- Network demand and health ----
        # Primarily driven by traffic.
        # Convert capacity to MB/s to match demand scale.
        net_capacity_mbps = hw.network_bytes_per_sec / 1_000_000.0  # e.g., ~125 for 1 Gbps
        eps = 1e-6
        pressure = z_T / (1.0 - z_T + eps)  # grows fast near z_T=1
        D_net = 125.0 * pressure            # MB/s
        net_health = D_net / net_capacity_mbps

        # ---- Latency "badness" / health ----
        # All three factors hurt latency: traffic, concurrency, and instability.
        # D_lat is a unitless "latency load"; hw.latency_budget rescales it.
        D_lat = 0.5 + 1.0 * z_T + 1.0 * z_C + 1.5 * z_I
        latency_load = D_lat / hw.latency_budget


        #Now Goodput 

        g_benign = max(0.0, 1.0 - attack_conf*.3)
        O = (
            max(cpu_health - 1.0, 0.0) +
            max(mem_health - 1.0, 0.0) +
            max(net_health - 1.0, 0.0)
        )

        alpha = 1.0  # sensitivity to overload
        g_health = 1.0 / (1.0 + alpha * O)

        goodput_score = z_T * g_benign * g_health

        #Take the inverse of values
        cpu_health = self.exp_inverse(cpu_health,k=1)
        mem_health = self.exp_inverse(mem_health,k=1)
        net_health = self.exp_inverse(net_health,k=1)
        latency_health = self.exp_inverse(latency_load, k=1.0)
        #goodput_score = self.exp_inverse(net_health,k=1)

        return cpu_health, mem_health, net_health, goodput_score, latency_health

    def _estimate_throughput_health(self, req_rate_obj, latency_health: float) -> float:
        """
        Calculates Throughput Health normalized to [0, 1].
        
        Math: Score = (1 - e^(-Rate / Target)) * LatencyHealth
        """
        import math
        
        # 1. Get Dynamic Target (Upper bound of normal config)
        #    Default to 1000.0 if config is missing to prevent div/0
        target = float(req_rate_obj.normal_range[1]) if hasattr(req_rate_obj, "normal_range") else 1000.0
        
        # 2. Extract Raw Rate
        val = float(req_rate_obj.value) if hasattr(req_rate_obj, "value") else float(req_rate_obj)
        
        # 3. Normalize Volume (Asymptotic Squash)
        #    If val == target:  Score is ~0.63
        #    If val == 2*target: Score is ~0.86
        #    If val >> target:  Score approaches 1.0
        volume_score = 1.0 - math.exp(-val / target)
        
        # 4. Combine with Quality (Latency)
        return volume_score * latency_health

    

    def calculate_health_score(self, signal, attack_conf=0.5) -> list[float]:
        signals = AdvancedSignals.get_signals(signal)
        
        # [Existing] Anomaly Scoring
        normal_signals = [BaseAttackProfile.anomaly_score(x, alpha=0.2, beta=1) for x in signals]
        (conn_util, req_rate_anom, err_rate, timeout_act, queue_depth, rate_limit, socket_state, worker_sat) = normal_signals 

        # [Existing] Latent Factors
        (traffic_pressure, reliability_risk, worker_pressure) = self._compute_latent_factors(
            conn_util, req_rate_anom, err_rate, timeout_act, queue_depth, rate_limit, socket_state, worker_sat
        )
        hw = HardwareCapacity()
        
        # [Existing] Resource Health (getting Latency Health as 5th return)
        cpu, mem, net, _, latency_health = self._compute_resource_health(
            traffic_pressure, worker_pressure, reliability_risk, hw, attack_conf
        )
        
        # --- NEW DYNAMIC CALCULATION ---
        # Pass the whole object so we can read its .normal_range
        req_rate_obj = signals[1] 
        tp_health = self._estimate_throughput_health(req_rate_obj, latency_health)
        
        return [cpu, mem, net, tp_health]

    def calculate_health_score(
        self,
        signal,
        attack_conf = 0.5
    ) -> float:
        
        raw_req = signal.get("request_rate", 0.0)
        
        signals = AdvancedSignals.get_signals(signal)
        
        #batch produce anomaly scores 
        normal_signals = [] 
        for x in signals: 
            n = BaseAttackProfile.anomaly_score(x,alpha=0.2,beta=1)
            normal_signals.append(n) 
        (
            conn_util,
            req_rate,
            err_rate,
            timeout_act,
            queue_depth,
            rate_limit,
            socket_state,
            worker_sat
        ) = normal_signals 

        (
            traffic_pressure,
            reliability_risk, 
            worker_pressure
        ) = self._compute_latent_factors(
            conn_util,
            req_rate,
            err_rate,
            timeout_act,
            queue_depth,
            rate_limit,
            socket_state,
            worker_sat
        )
        hw = HardwareCapacity()
        cpu, mem, net, _, latency = self._compute_resource_health(traffic_pressure,worker_pressure,reliability_risk,hw,attack_conf)
        
        tp = self._estimate_throughput_health(raw_req, latency) 

        return [cpu, mem, net, tp]#, goodput]
    
    def fused_health_columns(self,matrix, alpha=0.7):
        """
        Apply fused health scoring column-wise.
        
        Parameters
        ----------
        matrix : 2D array (num_events x num_metrics)
            Health values for multiple metrics over many events.
        alpha : float
            Weight for max vs majority fusion.

        Returns
        -------
        fused : 1D array (num_metrics,)
            Fused health value for each metric/column.
        """

        M = np.asarray(matrix, dtype=float)
        if M.ndim != 2:
            raise ValueError("Input must be a 2D array")

        num_rows, num_cols = M.shape
        k = (num_rows + 1) // 2   # majority count

        fused = np.zeros(num_cols, dtype=float)

        for j in range(num_cols):
            col = M[:, j]

            h_max = col.max()
            sorted_col = np.sort(col)[::-1]
            h_maj = sorted_col[:k].mean()

            fused[j] = alpha * h_max + (1 - alpha) * h_maj

        return fused


 