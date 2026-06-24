"""
MAFS Ensemble
=============
Reconstructs the 10-agent Multi-Agent Feature Selection ensemble from the
trained joblib artifact.

Why the joblib (not the .keras files)?
    - The .keras files are the GNN-DQN agents that performed feature selection
      during training. Their FINAL decision (which 226 of 430 features to keep)
      is already baked into `selected_feature_indices` inside the joblib.
    - Loading the .keras files at inference time would re-derive the same set,
      and is impractical here because of TF version drift.
    - This loader therefore reads the joblib's selected indices as ground truth
      and partitions the 430-feature space across 10 agents so we can show
      per-agent contributions for any input.

Per-agent decomposition
    Agent i owns features [i * 43 .. (i + 1) * 43).
    For each input the agent reports:
      - kept[]          : indices in its slice that survive MAFS
      - dropped[]       : indices in its slice that MAFS rejected
      - active_kept[]   : kept indices with non-zero activation on this input
      - activation_score: importance-weighted sum over active_kept
"""

import os
import logging
from typing import Dict, List, Optional

import numpy as np


logger = logging.getLogger('mafs-ensemble')


class MAFSEnsemble:
    NUM_AGENTS = 10

    def __init__(self, joblib_payload: dict):
        """
        joblib_payload : the dict returned by joblib.load(xss_classifier.joblib)
        """
        self.classifier = joblib_payload.get('classifier')
        self.feature_extractor = joblib_payload.get('feature_extractor')
        self.all_feature_names: List[str] = list(joblib_payload.get('all_feature_names') or [])
        self.selected_indices: List[int] = list(joblib_payload.get('selected_feature_indices') or [])
        self.selected_names: List[str] = list(joblib_payload.get('selected_feature_names') or [])
        self.importance_list: List[float] = list(joblib_payload.get('feature_importances') or [])

        self.total_features = len(self.all_feature_names) or 430
        self.features_per_agent = self.total_features // self.NUM_AGENTS  # 43 for 430/10

        self._selected_set = set(self.selected_indices)
        self._importance_by_index: Dict[int, float] = {
            idx: float(w)
            for idx, w in zip(self.selected_indices, self.importance_list)
        }

        self.agent_slices: List[List[int]] = []
        for i in range(self.NUM_AGENTS):
            lo = i * self.features_per_agent
            hi = self.total_features if i == self.NUM_AGENTS - 1 \
                else (i + 1) * self.features_per_agent
            self.agent_slices.append(list(range(lo, hi)))

        self._validate()

    def _validate(self) -> None:
        if self.classifier is None:
            raise ValueError("joblib missing 'classifier'")
        if self.feature_extractor is None:
            raise ValueError("joblib missing 'feature_extractor'")
        if not self.selected_indices:
            raise ValueError("joblib missing 'selected_feature_indices'")

        logger.info(
            "MAFSEnsemble ready: %d agents · %d features/agent · %d / %d selected",
            self.NUM_AGENTS, self.features_per_agent,
            len(self.selected_indices), self.total_features,
        )

    def extract_features(self, text: str) -> np.ndarray:
        feats, _, _ = self.feature_extractor.extract_all_features([text], fit=False)
        arr = np.asarray(feats[0], dtype=np.float32).flatten()
        if arr.size < self.total_features:
            padded = np.zeros(self.total_features, dtype=np.float32)
            padded[:arr.size] = arr
            return padded
        return arr[:self.total_features]

    def agent_decisions(self, features_430: np.ndarray) -> List[Dict]:
        out: List[Dict] = []
        for agent_id, slice_idx in enumerate(self.agent_slices):
            kept, dropped, active_kept = [], [], []
            activation_score = 0.0
            for idx in slice_idx:
                if idx in self._selected_set:
                    kept.append(idx)
                    val = float(features_430[idx])
                    if val != 0.0:
                        active_kept.append(idx)
                        activation_score += val * self._importance_by_index.get(idx, 0.0)
                else:
                    dropped.append(idx)

            keep_rate = len(kept) / max(len(slice_idx), 1)
            active_rate = len(active_kept) / max(len(kept), 1)

            out.append({
                'agent_id':         agent_id,
                'slice_start':      slice_idx[0],
                'slice_end':        slice_idx[-1],
                'slice_size':       len(slice_idx),
                'kept':             kept,
                'dropped_count':    len(dropped),
                'kept_count':       len(kept),
                'active_kept':      active_kept,
                'active_count':     len(active_kept),
                'keep_rate':        round(keep_rate, 4),
                'active_rate':      round(active_rate, 4),
                'activation_score': round(activation_score, 6),
                'vote':             1 if activation_score > 0 else 0,
            })
        return out

    def classify_with_selected(self, features_430: np.ndarray) -> Dict:
        selected_vec = features_430[self.selected_indices].reshape(1, -1)
        if hasattr(self.classifier, 'predict_proba'):
            proba = self.classifier.predict_proba(selected_vec)[0]
            score = float(proba[1]) if len(proba) > 1 else float(proba[0])
        else:
            pred = self.classifier.predict(selected_vec)[0]
            score = float(pred)

        return {
            'score':  score,
            'is_xss': score >= 0.5,
        }

    def predict(self, text: str) -> Dict:
        features_430 = self.extract_features(text)
        decisions = self.agent_decisions(features_430)
        cls = self.classify_with_selected(features_430)

        active_votes = sum(d['vote'] for d in decisions)
        ensemble_activation = sum(d['activation_score'] for d in decisions)

        return {
            'is_xss':              cls['is_xss'],
            'score':               cls['score'],
            'agents':              decisions,
            'active_votes':        active_votes,
            'ensemble_activation': round(ensemble_activation, 6),
            'selected_total':      len(self.selected_indices),
            'features_total':      self.total_features,
        }


def build_from_joblib(joblib_path: str) -> Optional[MAFSEnsemble]:
    import joblib
    if not os.path.exists(joblib_path):
        logger.error("joblib not found at %s", joblib_path)
        return None
    payload = joblib.load(joblib_path)
    if not isinstance(payload, dict):
        logger.error("joblib payload is not a dict (got %s)", type(payload).__name__)
        return None
    return MAFSEnsemble(payload)
