import numpy as np
import random
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import Matern, WhiteKernel
from sklearn.exceptions import ConvergenceWarning
import itertools
import warnings

class ResilienceLearner:
    # Simple Integer Encoding for Attack Type; keep stable.
    ATTACK_MAP = {'normal': 0, 'slowloris': 1, 'flood': 2, 'resource_exhaustion': 3}

    def __init__(self):
        """
        Initializes the GP with a kernel suitable for system control.
        No metadata needed here anymore.
        """
        self.X_history = [] 
        self.Y_history = []
        
        # Kernel: Matern (smooths control) + WhiteKernel (absorbs noise)
        kernel = Matern(length_scale=1.0) + WhiteKernel(noise_level=0.1)
        self.gp_model = GaussianProcessRegressor(kernel=kernel, n_restarts_optimizer=5)
        self.is_fitted = False

    def update_model(self, X_vector, health_score, k: int = 500):
        """
        Pure Learning Step.
        
        Args:
            X_vector (np.array): The exact vector used at T-1. e.g. [1.0, 0.9, 0.2, 0.5]
            health_score (float): The result observed at T. e.g. 0.85
            k (int): maximum history length (rolling window)
            
        Returns:
            model: The updated sklearn GP object.
        """
        
        # 1. Update History
        # Ensure it's a flat list/array for storage
        self.X_history.append(X_vector)
        self.Y_history.append(health_score)
        if k and k > 0 and len(self.X_history) > k:
            self.X_history.pop(0)
            self.Y_history.pop(0)
        
        # 2. Re-Train (Fit)
        X_train = np.array(self.X_history)
        y_train = np.array(self.Y_history)
        
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=ConvergenceWarning)
            self.gp_model.fit(X_train, y_train)
        self.is_fitted = True
        fitted = self.gp_model.kernel_.get_params()
        print(f"[Learner] Refitted on {len(X_train)} events.")
        #print(f"[Learner] fitted parameters: {fitted}")
        return self.gp_model
    

    def select_best_config(self, attack_info, potential_configs, param_specs, 
                        beta=1.96, sample_size: int = 10000, stability_lambda: float = 0.1):
        """
        Selects the optimal configuration using GP-UCB with Stability Penalty.
        
        Args:
            stability_lambda (float): Penalty weight for changing configs. 
                                    Higher = stickier (prefers current config).
                                    Lower = more volatile. 
        """
        if not potential_configs or not param_specs:
            return {}

        # 1. Expand the Grid (Cartesian Product or Random Sampling)
        keys = list(param_specs.keys())
        value_lists = [potential_configs.get(k, []) for k in keys]
        if any(len(v) == 0 for v in value_lists):
            return {}

        total_candidates = 1
        for vals in value_lists:
            total_candidates *= max(1, len(vals))
            if total_candidates > sample_size:
                break

        if total_candidates <= sample_size:
            candidate_tuples = list(itertools.product(*value_lists))
        else:
            # Random Sampling logic
            candidate_tuples = []
            seen = set()
            max_attempts = sample_size * 10 if sample_size > 0 else 0
            attempts = 0
            while len(candidate_tuples) < sample_size and attempts < max_attempts:
                attempts += 1
                choice = tuple(random.choice(vals) for vals in value_lists)
                if choice in seen: continue
                seen.add(choice)
                candidate_tuples.append(choice)

        if not candidate_tuples:
            return {}

        X_batch = []

        # 2. Build Input Vectors
        for cand_tuple in candidate_tuples:
            cand_dict = dict(zip(keys, cand_tuple))
            cand_specs = {k: {**param_specs[k], "value": cand_dict[k]} for k in keys}
            full_vector = self.build_input_vector(attack_info, cand_specs)[0].tolist()
            X_batch.append(full_vector)

        X_batch = np.array(X_batch)

        # 3. Handle Cold Start
        if not self.is_fitted:
            return dict(zip(keys, candidate_tuples[0]))

        # 4. Batch Prediction
        means, stds = self.gp_model.predict(X_batch, return_std=True)
        
        # A. Get the vector for the CURRENT configuration
        # param_specs holds the *current* values by default 
        current_vec_2d = self.build_input_vector(attack_info, param_specs)
        current_vec_flat = current_vec_2d[0] # Flatten to 1D array

        # B. Calculate Euclidean Distance (Vectorized)
        # Norm of (Candidate - Current). 
        # Note: The 'Attack Context' part subtracts to 0, so we measure only config distance.
        distances = np.linalg.norm(X_batch - current_vec_flat, axis=1)

        # C. Apply Penalized UCB
        # Score = Gain + Exploration - SwitchingCost
        ucb_scores = means + (beta * stds) - (stability_lambda * distances)

        # 5. Selection
        best_idx = np.argmax(ucb_scores)
        best_values = candidate_tuples[best_idx]

        return dict(zip(keys, best_values))

    @classmethod
    def build_input_vector(cls, attack_info, param_specs):
        """
        Constructs the X vector: [Context (Attack) | Action (Config)].

        Args:
            attack_info (tuple): (attack_label_str, confidence_float)
            param_specs (dict): Ordered mapping {param: {'value': X, 'min': A, 'max': B, ...}}
                                Order of keys defines the encoding order.

        Returns:
            np.array: A 2D array (1 sample) ready for the GP. e.g., [[1, 0.9, 0.5, 0.2]]
        """
        attack_label, confidence = attack_info
        attack_id = cls.ATTACK_MAP.get(attack_label, -1)  # -1 for unknown

        vector = [float(attack_id), float(confidence)]
        normed = cls._normalize_config({k: spec["value"] for k, spec in param_specs.items()}, param_specs)
        vector.extend(normed)
        return np.array([vector])

    @classmethod
    def _normalize_config(cls, config_dict: dict, param_specs: dict) -> list:
        """
        Helper: Converts a raw config dict to a normalized list based on the given param specs.
        Handles edge cases like min == max (to avoid division by zero).
        """
        normalized_vec = []

        for key, meta in param_specs.items():
            raw_val = config_dict.get(key)
            py_t = meta.get("py_type")
            if py_t == "int":
                try:
                    raw_val = int(round(raw_val))
                except Exception:
                    pass
            p_min = float(meta['min'])
            p_max = float(meta['max'])

            # Avoid division by zero if a param is constant (min == max)
            if p_max == p_min:
                norm_val = 0.0
            else:
                norm_val = (raw_val - p_min) / (p_max - p_min)
                
            normalized_vec.append(norm_val)
            
        return normalized_vec
