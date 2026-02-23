import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple
import shap
from sklearn.ensemble import RandomForestClassifier
import warnings
warnings.filterwarnings('ignore')


class AlertExplainer:
    def __init__(self):
        self.explainer = None
        self.background_data = None
        self.feature_names = []
        self.is_initialized = False

    def initialize(self, X_train: np.ndarray, feature_names: List[str]) -> "AlertExplainer":
        self.feature_names = feature_names
        self.background_data = shap.sample(X_train, min(100, X_train.shape[0]), random_state=42)
        self.explainer = shap.TreeExplainer(RandomForestClassifier(n_estimators=10, random_state=42))
        self.is_initialized = True
        return self

    def explain(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> List[Dict]:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized. Call initialize() first.")

        names = feature_names or self.feature_names

        try:
            shap_values = self.explainer.shap_values(X)
            if isinstance(shap_values, list):
                shap_values = shap_values[1]
        except Exception as e:
            return self._fallback_explain(X, names)

        explanations = []
        for i in range(len(X)):
            contributions = {names[j]: float(shap_values[i, j]) for j in range(len(names))}
            sorted_contrib = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)

            explanations.append({
                "alert_id": i,
                "shap_values": contributions,
                "top_features": sorted_contrib[:5],
                "explanation": self._generate_natural_language(sorted_contrib[:5])
            })

        return explanations

    def _fallback_explain(self, X: np.ndarray, feature_names: List[str]) -> List[Dict]:
        explanations = []
        for i in range(len(X)):
            feature_values = {feature_names[j]: float(X[i, j]) for j in range(len(feature_names))}
            sorted_features = sorted(feature_values.items(), key=lambda x: abs(x[1]), reverse=True)

            explanations.append({
                "alert_id": i,
                "feature_values": feature_values,
                "top_features": sorted_features[:5],
                "explanation": self._generate_natural_language(sorted_features[:5])
            })
        return explanations

    def _generate_natural_language(self, top_features: List[Tuple[str, float]]) -> str:
        if not top_features:
            return "No significant features found."

        explanations = []
        for feature, value in top_features[:3]:
            direction = "elevated" if value > 0 else "depressed"
            if "failure" in feature.lower() or "error" in feature.lower():
                explanations.append(f"{feature} is {direction} ({abs(value):.2f} std)")
            elif "rate" in feature.lower() or "count" in feature.lower():
                explanations.append(f"{feature} is {direction}")
            elif "time" in feature.lower():
                explanations.append(f"response {direction}")
            else:
                explanations.append(f"{feature}: {direction}")

        if len(explanations) >= 2:
            return f"This alert fired because: {', '.join(explanations[:2])}"
        return f"This alert fired because: {explanations[0]}" if explanations else "Analysis inconclusive."

    def get_force_plot_data(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> Dict:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized")

        names = feature_names or self.feature_names
        try:
            shap_values = self.explainer.shap_values(X)
            if isinstance(shap_values, list):
                shap_values = shap_values[1]
        except:
            shap_values = np.zeros_like(X)

        return {
            "base_value": float(self.explainer.expected_value[1]) if isinstance(self.explainer.expected_value, list) else 0.0,
            "shap_values": shap_values[0].tolist() if len(shap_values) > 0 else [],
            "feature_names": names,
            "feature_values": X[0].tolist() if len(X) > 0 else []
        }

    def get_summary_plot_data(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> Dict:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized")

        names = feature_names or self.feature_names

        try:
            shap_values = self.explainer.shap_values(X)
            if isinstance(shap_values, list):
                shap_values = shap_values[1]
        except:
            shap_values = np.zeros_like(X)

        mean_abs_shap = np.abs(shap_values).mean(axis=0)
        importance = {names[i]: float(mean_abs_shap[i]) for i in range(len(names))}
        sorted_importance = sorted(importance.items(), key=lambda x: x[1], reverse=True)

        return {
            "feature_importance": importance,
            "top_features": sorted_importance[:10],
            "shap_values": shap_values.tolist() if len(shap_values) > 0 else []
        }


def get_explainer() -> AlertExplainer:
    return AlertExplainer()
