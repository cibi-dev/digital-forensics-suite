"""High-performance Intrusion Detection Engine combining IsolationForest and Multivariable Z-Score."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
from pydantic import BaseModel, ConfigDict, Field
from sklearn.ensemble import IsolationForest
from sklearn.ensemble._iforest import _average_path_length
from sklearn.tree import ExtraTreeRegressor
from sklearn.tree._tree import Tree

from detector.features import FEATURE_NAMES, FeatureVector


def _c_factor(n: int) -> float:
    """Average path length of unsuccessful search in Binary Search Tree (BST)."""
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    euler = 0.5772156649015328606065120900824024310421
    return 2.0 * (math.log(n - 1.0) + euler) - (2.0 * (n - 1.0) / float(n))


class EngineConfig(BaseModel):
    """Configuration hyper-parameters for the IntrusionEngine."""
    model_config = ConfigDict(frozen=True)

    n_estimators: int = 15
    max_samples: Union[int, float] = 128
    contamination: float = 0.01
    iso_weight: float = 0.50
    zscore_weight: float = 0.50
    anomaly_threshold: float = 0.75
    covariance_regularization: float = 0.05
    random_state: int = 42


class AnomalyScoreResult(BaseModel):
    """Detection result for a single sample or batch."""
    model_config = ConfigDict(frozen=True)

    anomaly_score: float
    iso_score: float
    z_score: float
    is_anomaly: bool
    feature_contributions: Dict[str, float] = Field(default_factory=dict)


class SerializedTree(BaseModel):
    """Safe schema for a single decision tree in the forest (CWE-502 Safe)."""
    model_config = ConfigDict(frozen=True)

    max_depth: int
    node_count: int
    children_left: List[int]
    children_right: List[int]
    feature: List[int]
    threshold: List[float]
    impurity: List[float]
    n_node_samples: List[int]
    weighted_n_node_samples: List[float]
    missing_go_to_left: Optional[List[int]] = None
    values: List[List[List[float]]]


class ModelArtifact(BaseModel):
    """Safe serialized model representation using pure JSON (CWE-502 Safe)."""
    model_config = ConfigDict(frozen=True)

    version: str = "0.1.0"
    config: EngineConfig
    feature_names: List[str]
    mean: List[float]
    std: List[float]
    cov_inv: List[List[float]]
    mahalanobis_center: List[float]
    mahalanobis_threshold: float
    iso_max_samples: int
    offset: float
    trees: List[SerializedTree]


def _compute_node_depths(tree_obj: Tree) -> np.ndarray:
    """Compute 1-indexed node depths for fast sklearn decision path lengths."""
    depths = np.zeros(tree_obj.node_count, dtype=np.int32)
    left = tree_obj.children_left
    right = tree_obj.children_right
    stack = [(0, 1)]
    while stack:
        node, d = stack.pop()
        depths[node] = d
        if left[node] != -1:
            stack.append((left[node], d + 1))
        if right[node] != -1:
            stack.append((right[node], d + 1))
    return depths


class IntrusionEngine:
    """Enterprise unsupervised intrusion engine with IsolationForest + Multivariable Z-Score."""

    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        self.config = config or EngineConfig()
        self.feature_names: List[str] = list(FEATURE_NAMES)
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None
        self.cov_inv_: Optional[np.ndarray] = None
        self.mahalanobis_center_: Optional[np.ndarray] = None
        self.mahalanobis_threshold_: float = 12.0
        self.iso_max_samples_: int = 128
        self.offset_: float = -0.50
        self._is_fitted: bool = False
        self._sklearn_forest: Optional[IsolationForest] = None

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def fit(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> IntrusionEngine:
        """Fit the hybrid model on baseline normal / background feature vectors."""
        if X.ndim != 2:
            raise ValueError(f"Expected 2D array, got shape {X.shape}")
        if X.shape[0] < 5:
            raise ValueError(f"Need at least 5 samples to fit, got {X.shape[0]}")

        if feature_names:
            self.feature_names = list(feature_names)
        else:
            self.feature_names = list(FEATURE_NAMES)

        X_clean = np.nan_to_num(X.astype(np.float64), nan=0.0, posinf=1e9, neginf=-1e9)
        n_samples, n_features = X_clean.shape

        # 1. Robust Scaling Parameters (Median & MAD with fallback to Std)
        median_vec = np.median(X_clean, axis=0)
        mad_vec = np.median(np.abs(X_clean - median_vec), axis=0)
        std_vec = np.std(X_clean, axis=0)

        # 1.4826 converts MAD to normal-equivalent scale
        scale_vec = np.where(mad_vec > 1e-4, mad_vec * 1.4826, np.where(std_vec > 1e-4, std_vec, 1.0))
        scale_vec[scale_vec < 1e-6] = 1.0

        self.mean_ = median_vec
        self.std_ = scale_vec

        X_norm = (X_clean - self.mean_) / self.std_

        # 2. Multivariable Regularized Covariance & Mahalanobis Center
        cov = np.cov(X_norm, rowvar=False)
        if cov.ndim == 0 or cov.size == 1:
            cov = np.eye(n_features)

        cov_reg = cov + self.config.covariance_regularization * np.eye(n_features)
        try:
            self.cov_inv_ = np.linalg.pinv(cov_reg)
        except Exception:
            self.cov_inv_ = np.eye(n_features)

        self.mahalanobis_center_ = np.median(X_norm, axis=0)

        # Baseline Mahalanobis distances
        diff = X_norm - self.mahalanobis_center_
        dists = np.sqrt(np.maximum(np.sum((diff @ self.cov_inv_) * diff, axis=1), 0.0))
        p99_dist = float(np.percentile(dists, 99.0))
        self.mahalanobis_threshold_ = max(p99_dist * 1.5, 10.0)

        # 3. Isolation Forest Fitting
        max_samples_val = min(self.config.max_samples, n_samples)
        self.iso_max_samples_ = int(max_samples_val)

        forest = IsolationForest(
            n_estimators=self.config.n_estimators,
            max_samples=self.iso_max_samples_,
            contamination=self.config.contamination,
            random_state=self.config.random_state,
            n_jobs=1,
        )
        forest.fit(X_clean)
        self._sklearn_forest = forest
        self.offset_ = float(forest.offset_)
        self._is_fitted = True
        return self

    def _compute_isolation_scores(self, X: np.ndarray) -> np.ndarray:
        """Compute Isolation Forest anomaly scores in [0, 1]."""
        if self._sklearn_forest is None:
            return np.zeros(X.shape[0], dtype=np.float64)

        # Scikit-learn score_samples: returns - E(h)/c(n)
        raw_scores = - self._sklearn_forest.score_samples(X)
        # raw_scores: ~0.40 (very normal) to ~0.70+ (severe anomaly)
        # Calibrated: [0.40, 0.70] -> [0.0, 1.0]
        calibrated = (raw_scores - 0.40) / 0.30
        return np.asarray(np.clip(calibrated, 0.0, 1.0), dtype=np.float64)

    def _compute_mahalanobis_scores(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Compute multivariable Z-scores and normalized anomaly probabilities."""
        if self.mean_ is None or self.std_ is None or self.cov_inv_ is None or self.mahalanobis_center_ is None:
            return np.zeros(X.shape[0]), np.zeros(X.shape[0])

        X_norm = (X - self.mean_) / self.std_
        diff = X_norm - self.mahalanobis_center_

        # Vectorized SIMD matrix multiplication: (diff @ cov_inv * diff).sum(axis=1)
        dists = np.sqrt(np.maximum(np.sum((diff @ self.cov_inv_) * diff, axis=1), 0.0))

        # Exponential tail distribution calibrated on threshold
        scale = max(self.mahalanobis_threshold_, 1.0)
        norm_scores = 1.0 - np.exp(-0.5 * np.square(dists / scale))
        return dists, np.clip(norm_scores, 0.0, 1.0)

    def predict_scores(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Batch compute (hybrid_scores, iso_scores, mahalanobis_dists, z_scores)."""
        if not self._is_fitted:
            raise RuntimeError("IntrusionEngine must be fitted before predict_scores.")

        X_clean = np.nan_to_num(X.astype(np.float64), nan=0.0, posinf=1e9, neginf=-1e9)
        iso_scores = self._compute_isolation_scores(X_clean)
        m_dists, z_scores = self._compute_mahalanobis_scores(X_clean)

        # Hybrid Score fusion
        w_iso = self.config.iso_weight
        w_z = self.config.zscore_weight
        blended = (w_iso * iso_scores) + (w_z * z_scores)
        # Soft maximum boost for extreme anomalies
        hybrid_scores = np.maximum(blended, 0.85 * np.maximum(iso_scores, z_scores))
        hybrid_scores = np.clip(hybrid_scores, 0.0, 1.0)

        return hybrid_scores, iso_scores, m_dists, z_scores

    def detect(self, feature_vector: Union[FeatureVector, np.ndarray]) -> AnomalyScoreResult:
        """Run single vector detection with feature attribution."""
        if isinstance(feature_vector, FeatureVector):
            X = feature_vector.to_numpy().reshape(1, -1)
        else:
            X = np.array(feature_vector, dtype=np.float64).reshape(1, -1)

        hybrid_scores, iso_scores, m_dists, z_scores = self.predict_scores(X)
        score = float(hybrid_scores[0])
        iso_sc = float(iso_scores[0])
        z_sc = float(z_scores[0])
        is_anom = bool(score >= self.config.anomaly_threshold)

        # Compute individual feature contributions
        contributions: Dict[str, float] = {}
        if self.mean_ is not None and self.std_ is not None:
            norm_dev = np.abs((X[0] - self.mean_) / self.std_)
            total_dev = float(np.sum(norm_dev)) + 1e-6
            for idx, feat_name in enumerate(self.feature_names):
                contributions[feat_name] = round(float(norm_dev[idx] / total_dev), 4)

        return AnomalyScoreResult(
            anomaly_score=round(score, 4),
            iso_score=round(iso_sc, 4),
            z_score=round(z_sc, 4),
            is_anomaly=is_anom,
            feature_contributions=contributions,
        )

    def evaluate(self, X: np.ndarray, y_true: np.ndarray) -> Dict[str, float]:
        """Evaluate precision, recall, f1, and accuracy against ground truth."""
        hybrid_scores, _, _, _ = self.predict_scores(X)
        y_pred = (hybrid_scores >= self.config.anomaly_threshold).astype(int)
        y_true_int = np.array(y_true, dtype=int)

        tp = int(np.sum((y_pred == 1) & (y_true_int == 1)))
        fp = int(np.sum((y_pred == 1) & (y_true_int == 0)))
        fn = int(np.sum((y_pred == 0) & (y_true_int == 1)))
        tn = int(np.sum((y_pred == 0) & (y_true_int == 0)))

        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = float((tp + tn) / max(len(y_true_int), 1))

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
        }

    # =========================================================================
    # SAFE SERIALIZATION (CWE-502: ZERO PICKLE)
    # =========================================================================

    def to_artifact(self) -> ModelArtifact:
        """Export model parameters into safe Pydantic ModelArtifact."""
        if not self._is_fitted or self.mean_ is None or self.std_ is None or self.cov_inv_ is None or self.mahalanobis_center_ is None or self._sklearn_forest is None:
            raise RuntimeError("Cannot serialize unfitted IntrusionEngine.")

        serialized_trees: List[SerializedTree] = []
        for est in self._sklearn_forest.estimators_:
            tree = est.tree_
            st = tree.__getstate__()
            nodes_arr = st["nodes"]
            values_arr = st["values"]

            missing_left = (
                nodes_arr["missing_go_to_left"].tolist()
                if "missing_go_to_left" in nodes_arr.dtype.names
                else None
            )

            serialized_trees.append(SerializedTree(
                max_depth=int(tree.max_depth),
                node_count=int(tree.node_count),
                children_left=nodes_arr["left_child"].tolist(),
                children_right=nodes_arr["right_child"].tolist(),
                feature=nodes_arr["feature"].tolist(),
                threshold=[float(v) for v in nodes_arr["threshold"]],
                impurity=[float(v) for v in nodes_arr["impurity"]],
                n_node_samples=nodes_arr["n_node_samples"].tolist(),
                weighted_n_node_samples=[float(v) for v in nodes_arr["weighted_n_node_samples"]],
                missing_go_to_left=missing_left,
                values=values_arr.tolist(),
            ))

        return ModelArtifact(
            version="0.1.0",
            config=self.config,
            feature_names=self.feature_names,
            mean=[float(v) for v in self.mean_],
            std=[float(v) for v in self.std_],
            cov_inv=[[float(c) for c in row] for row in self.cov_inv_],
            mahalanobis_center=[float(v) for v in self.mahalanobis_center_],
            mahalanobis_threshold=float(self.mahalanobis_threshold_),
            iso_max_samples=int(self.iso_max_samples_),
            offset=float(self.offset_),
            trees=serialized_trees,
        )

    def save_json(self, path: Union[str, Path]) -> None:
        """Save model parameters as pure JSON file (CWE-502 safe)."""
        artifact = self.to_artifact()
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(artifact.model_dump_json(indent=2))

    @classmethod
    def from_artifact(cls, artifact: ModelArtifact) -> IntrusionEngine:
        """Reconstruct IntrusionEngine from validated ModelArtifact."""
        engine = cls(config=artifact.config)
        engine.feature_names = list(artifact.feature_names)
        engine.mean_ = np.array(artifact.mean, dtype=np.float64)
        engine.std_ = np.array(artifact.std, dtype=np.float64)
        engine.cov_inv_ = np.array(artifact.cov_inv, dtype=np.float64)
        engine.mahalanobis_center_ = np.array(artifact.mahalanobis_center, dtype=np.float64)
        engine.mahalanobis_threshold_ = float(artifact.mahalanobis_threshold)
        engine.iso_max_samples_ = int(artifact.iso_max_samples)
        engine.offset_ = float(artifact.offset)

        n_features = len(artifact.feature_names)
        estimators: List[ExtraTreeRegressor] = []
        d_paths: List[np.ndarray] = []
        avg_paths: List[np.ndarray] = []

        # Get exact compiled Tree node dtype from runtime sklearn
        sample_tree = Tree(n_features, np.array([1], dtype=np.intp), 1)
        node_dtype = sample_tree.__getstate__()["nodes"].dtype

        for st in artifact.trees:
            n_nodes = st.node_count
            nodes_arr = np.empty(n_nodes, dtype=node_dtype)
            nodes_arr["left_child"] = st.children_left
            nodes_arr["right_child"] = st.children_right
            nodes_arr["feature"] = st.feature
            nodes_arr["threshold"] = st.threshold
            nodes_arr["impurity"] = st.impurity
            nodes_arr["n_node_samples"] = st.n_node_samples
            nodes_arr["weighted_n_node_samples"] = st.weighted_n_node_samples
            if "missing_go_to_left" in node_dtype.names:
                if st.missing_go_to_left is not None:
                    nodes_arr["missing_go_to_left"] = st.missing_go_to_left
                else:
                    nodes_arr["missing_go_to_left"] = 0

            values_arr = np.array(st.values, dtype=np.float64)

            new_tree = Tree(n_features, np.array([1], dtype=np.intp), 1)
            new_tree.__setstate__({
                "max_depth": st.max_depth,
                "node_count": st.node_count,
                "nodes": nodes_arr,
                "values": values_arr,
            })

            new_reg = ExtraTreeRegressor()
            new_reg.tree_ = new_tree
            new_reg.n_features_in_ = n_features
            estimators.append(new_reg)

            d_paths.append(_compute_node_depths(new_tree))
            avg_paths.append(_average_path_length(new_tree.n_node_samples))

        forest = IsolationForest(
            n_estimators=len(artifact.trees),
            max_samples=artifact.iso_max_samples,
            random_state=artifact.config.random_state,
        )
        forest.estimators_ = estimators
        forest.estimators_features_ = [np.arange(n_features) for _ in range(len(artifact.trees))]
        forest.max_samples_ = artifact.iso_max_samples
        forest._max_samples = artifact.iso_max_samples
        forest._max_features = n_features
        forest.n_features_in_ = n_features
        forest.offset_ = float(artifact.offset)
        forest.verbose = 0
        forest._decision_path_lengths = tuple(d_paths)
        forest._average_path_length_per_tree = tuple(avg_paths)

        engine._sklearn_forest = forest
        engine._is_fitted = True
        return engine

    @classmethod
    def load_json(cls, path: Union[str, Path]) -> IntrusionEngine:
        """Load model from pure JSON without pickle (CWE-502 safe)."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)
            artifact = ModelArtifact.model_validate(raw_data)
            return cls.from_artifact(artifact)
        except Exception as e:
            raise ValueError(f"Failed to safely deserialize model JSON from {path}: {e}") from e
