import numpy as np
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import Matern, WhiteKernel
import random
import warnings
from sklearn.exceptions import ConvergenceWarning
import pickle

class PhysicsGuidedLearner:
    """
    A Grey-Box Gaussian Process Learner that uses Physics-Informed Priors
    to accelerate convergence. It combines Domain Knowledge (Priors) with
    Data-Driven Learning (Residual Correction).
    """
    def __init__(self, param_specs):
        """
        Args:
            param_specs (dict): Configuration metadata in the format:
                                {'param_name': {'min': 0, 'max': 100, 'value': 50}}
        """
        self.param_specs = param_specs
        # Strict ordering of keys to ensure vector consistency
        self.param_order = list(param_specs.keys())
        
        # History buffers
        self.X_history = []
        self.Y_residuals = [] 
        self.Y_actuals = []   
        
        # Gaussian Process Setup
        # Matern kernel handles non-linearities well. WhiteKernel handles noise.
        kernel = Matern(length_scale=1.0, nu=2.5, length_scale_bounds=(1e-5, 1e5)) + WhiteKernel(noise_level=0.1, noise_level_bounds=(1e-6, 1e3))
        self.gp_model = GaussianProcessRegressor(kernel=kernel, n_restarts_optimizer=2, alpha=1e-6, normalize_y=True)
        self.is_fitted = False

    def _normalize_value(self, key, value):
        """Normalizes a configuration value to [0, 1] based on specs."""
        spec = self.param_specs[key]
        p_min = float(spec['min'])
        p_max = float(spec['max'])
        if p_max == p_min: return 0.0
        return (float(value) - p_min) / (p_max - p_min)

    # ==========================================
    # DOMAIN KNOWLEDGE (THE PHYSICS PRIORS)
    # ==========================================

    def _prior_slowloris(self, config):
        """
        Physics Logic for Slowloris:
        - Starve connections (Lower limit_conn)
        - Shorten wait times (Lower timeouts)
        - Drop idle sockets (Lower keepalive)
        """
        score = 0.5 # Start neutral
        
        # 1. Connection Limits (Critical)
        lim = float(config.get('limit_conn', 500))
        if lim > 200:
            score -= min(0.8, lim / 800.0)
            
        # 2. Timeouts (Critical)
        body_tout = float(config.get('client_body_timeout', 30))
        if body_tout > 10:
            score -= min(0.4, body_tout / 40.0)
        header_tout = float(config.get('client_header_timeout', 10))
        if header_tout > 5:
            score -= min(0.4, header_tout / 40.0)
        send_tout = float(config.get('send_timeout', 60))
        if send_tout > 10:
            score -= min(0.4, send_tout / 40.0)
            
        # 3. Keepalive (Secondary)
        ka = float(config.get('keepalive_timeout', 65))
        if ka > 5:
            score -= min(0.3, ka / 30.0)
        kr = float(config.get('keepalive_requests', 10000))
        if kr > 1000:
            score -= min(0.3, kr / 4000.0)
        cms = float(config.get('client_max_body_size', 100))
        if cms > 50:
            score -= min(0.3, cms / 300.0)
            
        return score

    def _prior_http_flood(self, config):
        """
        Physics Logic for HTTP Flood:
        - Throttle request rate (Low Rate Limit)
        - Maximize worker throughput (High Workers)
        - Connection limits matter less than Rate limits
        """
        score = 0.5
        
        # 1. Rate Limiting (Critical)
        rr = float(config.get('limit_req_zone', 2000))
        if rr > 500: 
            score -= (rr / 10000.0) 
        burst = float(config.get('limit_req', 1000))
        if burst > 1000:
            score -= (burst / 20000.0)
            
        # 2. Workers (Beneficial)
        wp = float(config.get('worker_processes', 4))
        wc = float(config.get('worker_connections', 4096))
        score += min(0.3, wp / 16.0) 
        score += min(0.3, wc / 20000.0)
        
        # 3. Connection Limits (Secondary)
        # We don't want infinite connections, but we don't need to starve them like Slowloris
        lim = float(config.get('limit_conn', 500))
        if lim > 2000:
            score -= 0.1
            
        return score

    def _prior_normal(self, config):
        """
        Physics Logic for Normal Traffic:
        - Maximize Availability (High Limits)
        - Reduce False Positives
        """
        score = 0.5
        
        # Reward capacity
        lim = float(config.get('limit_conn', 500))
        # Mild reward for having capacity > 500
        score += min(0.2, lim / 5000.0)
        rr = float(config.get('limit_req_zone', 2000))
        score += min(0.2, rr / 10000.0)
        wc = float(config.get('worker_connections', 4096))
        score += min(0.2, wc / 20000.0)
        
        return score

    def _calculate_prior_score(self, attack_info, config_dict):
        """
        Dispatcher: Selects the correct Physics Model based on the Oracle's label.
        """
        # Parse attack info which might be a tuple ('slowloris', 0.8) or string
        label = attack_info[0] if isinstance(attack_info, (list, tuple)) else str(attack_info)
        conf = attack_info[1] if isinstance(attack_info, (list, tuple)) and len(attack_info) > 1 else 0.0
        label = str(label).lower()
        if conf < 0.25:
            label = "normal"

        if 'slow' in label:
            return self._prior_slowloris(config_dict)
        elif 'flood' in label:
            return self._prior_http_flood(config_dict)
        else:
            return self._prior_normal(config_dict)

    # ==========================================
    # CORE LOGIC (VECTOR & TRAINING)
    # ==========================================

    def build_input_vector(self, attack_info, config_dict):
        """
        Constructs the feature vector [AttackID, Confidence, Config1, Config2...]
        """
        label = attack_info[0] if isinstance(attack_info, (list, tuple)) else str(attack_info)
        
        # One-Hot-ish encoding for Attack Type
        if 'slow' in str(label).lower(): 
            atk_id = 1.0
        elif 'flood' in str(label).lower():
            atk_id = 2.0
        else:
            atk_id = 0.0
            
        confidence = attack_info[1] if isinstance(attack_info, (list, tuple)) else 0.0
        
        vector = [atk_id, float(confidence)]

        # Append normalized config values in strict order
        for k in self.param_order:
            val = config_dict.get(k, self.param_specs[k]['value'])
            vector.append(self._normalize_value(k, val))
            
        return np.array([vector])

    def update_model(self, attack_info, config_dict, actual_health_score):
        """
        TRAINING: Trains the GP to predict the RESIDUAL (Error) between Physics and Reality.
        Target = Actual - Prior.
        """
        # 1. Build Vector
        X_vec = self.build_input_vector(attack_info, config_dict)[0]
        
        # 2. Calculate what Physics thought (The Prior)
        prior = self._calculate_prior_score(attack_info, config_dict)
        
        # 3. Calculate the Residual (The Correction)
        # If Prior=0.4 and Actual=0.6, Residual=+0.2.
        # This means "The system is 0.2 better than theory predicted."
        residual = actual_health_score - prior
        
        # 4. Update History
        self.X_history.append(X_vec)
        self.Y_residuals.append(residual)
        self.Y_actuals.append(actual_health_score)
        
        # 5. Sliding Window (Performance Optimization)
        # Keep GP fast by forgetting old data (>500 steps)
        window_size = 500
        if len(self.X_history) > window_size:
            self.X_history = self.X_history[-window_size:]
            self.Y_residuals = self.Y_residuals[-window_size:]
        
        # 6. Fit GP
        X_train = np.array(self.X_history)
        y_train = np.array(self.Y_residuals)
        
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=ConvergenceWarning)
            self.gp_model.fit(X_train, y_train)
        self.is_fitted = True
        
        return self.gp_model

    # ==========================================
    # PREDICTION & SELECTION
    # ==========================================

    def select_best_config(self, attack_info, candidates, beta=1.96, sample_size: int = 5000):
        """
        PREDICTION:
        Final Score = Prior(x) + GP_Mean(x) + Beta * GP_Std(x)
        """
        # Allow passing a potentials dict {param: [values]} or a list of config dicts.
        if isinstance(candidates, dict):
            keys = list(candidates.keys())
            value_lists = [candidates.get(k, []) for k in keys]
            if any(len(v) == 0 for v in value_lists):
                return {}
            total = 1
            for vals in value_lists:
                total *= max(1, len(vals))
                if total > sample_size:
                    break
            import random, itertools
            cand_list = []
            if total <= sample_size:
                for vals in itertools.product(*value_lists):
                    cand_list.append(dict(zip(keys, vals)))
            else:
                seen = set()
                attempts = 0
                max_attempts = sample_size * 10
                while len(cand_list) < sample_size and attempts < max_attempts:
                    attempts += 1
                    choice = tuple(random.choice(vals) for vals in value_lists)
                    if choice in seen:
                        continue
                    seen.add(choice)
                    cand_list.append(dict(zip(keys, choice)))
            candidates = cand_list
        if not candidates:
            return {}
        
        X_batch = []
        priors = []
        
        # 1. Batch Process Candidates
        for cand in candidates:
            # Vector for GP
            vec = self.build_input_vector(attack_info, cand)[0]
            X_batch.append(vec)
            
            # Prior Score (Pure Math)
            priors.append(self._calculate_prior_score(attack_info, cand))
            
        X_batch = np.array(X_batch)
        priors = np.array(priors)

        # 2. GP Inference
        if not self.is_fitted:
            # Cold Start: Trust Physics 100%
            final_scores = priors
        else:
            # Predict the Residual
            means, stds = self.gp_model.predict(X_batch, return_std=True)
            
            # Combine: Theory + Learned Correction + Exploration Bonus
            final_scores = priors + means + (beta * stds)

        # 3. Select Winner
        best_idx = np.argmax(final_scores)
        return candidates[best_idx]

    def generate_random_candidates(self, n_samples=200):
        """
        Generates random configurations within the min/max bounds.
        """
        candidates = []
        for _ in range(n_samples):
            cand = {}
            for k in self.param_order:
                spec = self.param_specs[k]
                p_min = spec['min']
                p_max = spec['max']
                
                # Integer vs Float handling
                if isinstance(spec['value'], int) and p_max > 1:
                    val = random.randint(int(p_min), int(p_max))
                else:
                    val = random.uniform(p_min, p_max)
                
                cand[k] = val
            candidates.append(cand)
        return candidates

    def save(self, path: str) -> None:
        payload = {
            "param_specs": self.param_specs,
            "param_order": self.param_order,
            "X_history": self.X_history,
            "Y_residuals": self.Y_residuals,
            "Y_actuals": self.Y_actuals,
            "gp_model": self.gp_model,
            "is_fitted": self.is_fitted,
        }
        with open(path, "wb") as handle:
            pickle.dump(payload, handle)

    def load_into(self, path: str) -> None:
        with open(path, "rb") as handle:
            payload = pickle.load(handle)
        self.param_specs = payload.get("param_specs", self.param_specs)
        self.param_order = payload.get("param_order", self.param_order)
        self.X_history = payload.get("X_history", [])
        self.Y_residuals = payload.get("Y_residuals", [])
        self.Y_actuals = payload.get("Y_actuals", [])
        self.gp_model = payload.get("gp_model", self.gp_model)
        self.is_fitted = payload.get("is_fitted", False)

    def generate_candidates_from_potentials(self, potentials, sample_size: int = 5000):
        """
        Generate candidate configs from a potentials dict {param: [values]}.
        Uses full Cartesian product when small, otherwise random sampling.
        """
        if not potentials:
            return []
        keys = list(potentials.keys())
        value_lists = [potentials.get(k, []) for k in keys]
        if any(len(v) == 0 for v in value_lists):
            return []

        total = 1
        for vals in value_lists:
            total *= max(1, len(vals))
            if total > sample_size:
                break

        import itertools
        candidates = []
        if total <= sample_size:
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
        return candidates
