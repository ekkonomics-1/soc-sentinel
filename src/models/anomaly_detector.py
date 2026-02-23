import numpy as np
import pandas as pd
import joblib
from typing import Dict, List, Optional, Tuple
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, precision_recall_fscore_support
import warnings
warnings.filterwarnings('ignore')


class AnomalyDetector:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            max_samples="auto",
            random_state=random_state,
            n_jobs=-1
        )
        self.scaler = None
        self.feature_names = []
        self.threshold = 0.7

    def fit(self, X: np.ndarray, feature_names: List[str]) -> "AnomalyDetector":
        self.feature_names = feature_names
        self.isolation_forest.fit(X)
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        predictions = self.isolation_forest.predict(X)
        return np.where(predictions == -1, 1, 0)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        scores = self.isolation_forest.score_samples(X)
        normalized_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        return normalized_scores

    def detect(self, X: np.ndarray) -> List[Dict]:
        proba = self.predict_proba(X)
        predictions = self.predict(X)

        results = []
        for i in range(len(X)):
            results.append({
                "is_anomaly": bool(predictions[i]),
                "anomaly_score": float(proba[i]),
                "severity": self._get_severity(proba[i]),
                "confidence": float(abs(proba[i] - 0.5) * 2)
            })
        return results

    def _get_severity(self, score: float) -> str:
        if score > 0.95:
            return "CRITICAL"
        elif score > 0.85:
            return "HIGH"
        elif score > 0.70:
            return "MEDIUM"
        else:
            return "LOW"

    def save(self, path: str) -> None:
        joblib.dump({
            "model": self.isolation_forest,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "threshold": self.threshold,
            "contamination": self.contamination
        }, path)

    def load(self, path: str) -> "AnomalyDetector":
        data = joblib.load(path)
        self.isolation_forest = data["model"]
        self.scaler = data["scaler"]
        self.feature_names = data["feature_names"]
        self.threshold = data["threshold"]
        self.contamination = data["contamination"]
        return self


class SupervisedClassifier:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=random_state,
            n_jobs=-1
        )
        self.feature_names = []
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> "SupervisedClassifier":
        self.feature_names = feature_names
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=self.random_state, stratify=y
        )
        self.model.fit(X_train, y_train)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        return self.model.predict_proba(X)[:, 1]

    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict:
        y_pred = self.predict(X)
        y_proba = self.predict_proba(X)

        precision, recall, f1, _ = precision_recall_fscore_support(y, y_pred, average='binary')

        return {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "classification_report": classification_report(y, y_pred)
        }

    def get_feature_importance(self) -> Dict[str, float]:
        if not self.is_fitted:
            return {}
        importance = self.model.feature_importances_
        return {name: float(imp) for name, imp in zip(self.feature_names, importance)}

    def save(self, path: str) -> None:
        joblib.dump({
            "model": self.model,
            "feature_names": self.feature_names
        }, path)

    def load(self, path: str) -> "SupervisedClassifier":
        data = joblib.load(path)
        self.model = data["model"]
        self.feature_names = data["feature_names"]
        self.is_fitted = True
        return self


class EnsembleDetector:
    def __init__(self, contamination: float = 0.05):
        self.anomaly_detector = AnomalyDetector(contamination=contamination)
        self.classifier = SupervisedClassifier()
        self.is_trained = False

    def fit_unsupervised(self, X: np.ndarray, feature_names: List[str]) -> "EnsembleDetector":
        self.anomaly_detector.fit(X, feature_names)
        return self

    def fit_supervised(self, X: np.ndarray, y: np.ndarray, feature_names: List[str]) -> "EnsembleDetector":
        self.classifier.fit(X, y, feature_names)
        self.is_trained = True
        return self

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        unsupervised_scores = self.anomaly_detector.predict_proba(X)
        unsupervised_pred = self.anomaly_detector.predict(X)

        if self.is_trained:
            supervised_proba = self.classifier.predict_proba(X)
            supervised_pred = self.classifier.predict(X)

            ensemble_proba = (unsupervised_scores + supervised_proba) / 2
            ensemble_pred = ((ensemble_proba > 0.5).astype(int))
        else:
            ensemble_proba = unsupervised_scores
            ensemble_pred = unsupervised_pred

        return ensemble_pred, ensemble_proba

    def detect(self, X: np.ndarray) -> List[Dict]:
        pred, proba = self.predict(X)
        results = []

        for i in range(len(X)):
            results.append({
                "is_anomaly": bool(pred[i]),
                "anomaly_score": float(proba[i]),
                "severity": self._get_severity(proba[i]),
                "model_agreement": self._get_model_agreement(X, i)
            })
        return results

    def _get_severity(self, score: float) -> str:
        if score > 0.95:
            return "CRITICAL"
        elif score > 0.85:
            return "HIGH"
        elif score > 0.70:
            return "MEDIUM"
        else:
            return "LOW"

    def _get_model_agreement(self, X: np.ndarray, idx: int) -> str:
        if not self.is_trained:
            return "unsupervised_only"
        return "ensemble"


def get_anomaly_detector(contamination: float = 0.05) -> AnomalyDetector:
    return AnomalyDetector(contamination=contamination)


def get_ensemble_detector(contamination: float = 0.05) -> EnsembleDetector:
    return EnsembleDetector(contamination=contamination)
