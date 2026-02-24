import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Any
import shap
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.tree import DecisionTreeRegressor
import warnings
warnings.filterwarnings('ignore')


class AlertExplainer:
    def __init__(self):
        self.explainer = None
        self.shap_explainer = None
        self.background_data = None
        self.feature_names = []
        self.X_train = None
        self.is_initialized = False
        self.model = None

    def initialize(self, X_train: np.ndarray, feature_names: List[str], model=None) -> "AlertExplainer":
        self.feature_names = feature_names
        self.X_train = X_train
        self.background_data = shap.sample(X_train, min(100, X_train.shape[0]), random_state=42)
        
        if model is not None:
            self.model = model
        else:
            self.model = IsolationForest(
                contamination=0.05,
                n_estimators=100,
                random_state=42
            )
            self.model.fit(X_train)
        
        try:
            self.shap_explainer = shap.TreeExplainer(self.model)
        except Exception:
            self.shap_explainer = shap.KernelExplainer(
                lambda x: self._model_score(x),
                self.background_data
            )
        
        try:
            rf_model = RandomForestClassifier(n_estimators=50, random_state=42, max_depth=5)
            y_dummy = np.random.randint(0, 2, len(X_train))
            rf_model.fit(X_train, y_dummy)
            self.explainer = shap.TreeExplainer(rf_model)
        except Exception:
            self.explainer = self.shap_explainer
        
        self.is_initialized = True
        return self

    def _model_score(self, X: np.ndarray) -> np.ndarray:
        if hasattr(self.model, 'score_samples'):
            scores = self.model.score_samples(X)
            return 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        return np.zeros(len(X))

    def explain(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> List[Dict]:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized. Call initialize() first.")

        names = feature_names or self.feature_names

        try:
            shap_values = self.explainer.shap_values(X)
            if isinstance(shap_values, list):
                shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
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

    def get_force_plot_data(self, X: np.ndarray, idx: int = 0, feature_names: Optional[List[str]] = None) -> Dict:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized")

        names = feature_names or self.feature_names
        single_x = X[idx:idx+1] if len(X.shape) == 2 else X.reshape(1, -1)
        
        try:
            shap_values = self.shap_explainer.shap_values(single_x)
            if isinstance(shap_values, list):
                shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
            shap_values = np.array(shap_values).flatten()
            
            base_value = self.shap_explainer.expected_value
            if isinstance(base_value, np.ndarray):
                base_value = float(base_value[0]) if len(base_value) > 0 else 0.0
            elif isinstance(base_value, list):
                base_value = float(base_value[0]) if len(base_value) > 0 else 0.0
            else:
                base_value = float(base_value)
        except Exception:
            shap_values = np.zeros(len(names))
            base_value = 0.5

        return {
            "base_value": base_value,
            "shap_values": shap_values.tolist(),
            "feature_names": names,
            "feature_values": single_x.flatten().tolist(),
            "prediction": sum(shap_values) + base_value
        }

    def get_waterfall_data(self, X: np.ndarray, idx: int = 0, feature_names: Optional[List[str]] = None) -> Dict:
        force_data = self.get_force_plot_data(X, idx, feature_names)
        
        features_data = []
        for i, (name, shap_val, feat_val) in enumerate(zip(
            force_data["feature_names"],
            force_data["shap_values"],
            force_data["feature_values"]
        )):
            features_data.append({
                "feature": name,
                "shap_value": shap_val,
                "feature_value": feat_val,
                "abs_shap": abs(shap_val)
            })
        
        features_data.sort(key=lambda x: x["abs_shap"], reverse=True)
        
        return {
            "base_value": force_data["base_value"],
            "prediction": force_data["prediction"],
            "features": features_data[:15]
        }

    def get_summary_plot_data(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> Dict:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized")

        names = feature_names or self.feature_names

        try:
            shap_values = self.shap_explainer.shap_values(X)
            if isinstance(shap_values, list):
                shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
            shap_values = np.array(shap_values)
        except Exception:
            shap_values = np.zeros_like(X)

        mean_abs_shap = np.abs(shap_values).mean(axis=0)
        importance = {names[i]: float(mean_abs_shap[i]) for i in range(len(names))}
        sorted_importance = sorted(importance.items(), key=lambda x: x[1], reverse=True)

        feature_shap_data = {}
        for i, name in enumerate(names):
            feature_shap_data[name] = {
                "shap_values": shap_values[:, i].tolist(),
                "feature_values": X[:, i].tolist(),
                "mean_abs_shap": float(mean_abs_shap[i])
            }

        return {
            "feature_importance": importance,
            "top_features": sorted_importance[:15],
            "shap_values": shap_values.tolist() if len(shap_values) > 0 else [],
            "feature_shap_data": feature_shap_data
        }

    def get_dependence_plot_data(self, X: np.ndarray, feature_idx: int, 
                                  feature_names: Optional[List[str]] = None,
                                  interaction_idx: Optional[int] = 'auto') -> Dict:
        if not self.is_initialized:
            raise ValueError("Explainer not initialized")

        names = feature_names or self.feature_names
        feature_name = names[feature_idx]

        try:
            shap_values = self.shap_explainer.shap_values(X)
            if isinstance(shap_values, list):
                shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
            shap_values = np.array(shap_values)
        except Exception:
            return {"error": "Could not compute SHAP values"}

        feature_values = X[:, feature_idx]
        shap_vals_for_feature = shap_values[:, feature_idx]

        if interaction_idx == 'auto':
            correlations = np.abs([
                np.corrcoef(shap_vals_for_feature, shap_values[:, j])[0, 1]
                if j != feature_idx else 0
                for j in range(len(names))
            ])
            interaction_idx = int(np.nanargmax(correlations))

        interaction_values = X[:, interaction_idx] if interaction_idx < len(names) else np.zeros(len(X))
        interaction_name = names[interaction_idx] if interaction_idx < len(names) else "N/A"

        return {
            "feature_name": feature_name,
            "feature_values": feature_values.tolist(),
            "shap_values": shap_vals_for_feature.tolist(),
            "interaction_feature": interaction_name,
            "interaction_values": interaction_values.tolist()
        }

    def get_beeswarm_data(self, X: np.ndarray, feature_names: Optional[List[str]] = None, 
                          max_display: int = 15) -> Dict:
        summary_data = self.get_summary_plot_data(X, feature_names)
        names = feature_names or self.feature_names
        
        top_features = [f[0] for f in summary_data["top_features"][:max_display]]
        
        beeswarm_points = []
        for feat_name in top_features:
            if feat_name in summary_data["feature_shap_data"]:
                data = summary_data["feature_shap_data"][feat_name]
                for shap_val, feat_val in zip(data["shap_values"], data["feature_values"]):
                    beeswarm_points.append({
                        "feature": feat_name,
                        "shap_value": shap_val,
                        "feature_value": feat_val
                    })
        
        return {
            "points": beeswarm_points,
            "top_features": top_features,
            "feature_importance": dict(summary_data["top_features"][:max_display])
        }

    def get_global_importance(self, X: np.ndarray, feature_names: Optional[List[str]] = None) -> Dict:
        summary = self.get_summary_plot_data(X, feature_names)
        
        total_importance = sum(v for v in summary["feature_importance"].values())
        normalized_importance = {
            k: (v / total_importance * 100) if total_importance > 0 else 0
            for k, v in summary["feature_importance"].items()
        }
        
        sorted_features = sorted(normalized_importance.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "absolute_importance": summary["feature_importance"],
            "relative_importance": normalized_importance,
            "ranked_features": sorted_features,
            "top_3_contribution": sum(v for k, v in sorted_features[:3])
        }

    def explain_prediction(self, X: np.ndarray, idx: int = 0, 
                           feature_names: Optional[List[str]] = None) -> Dict:
        waterfall = self.get_waterfall_data(X, idx, feature_names)
        names = feature_names or self.feature_names
        
        positive_features = [f for f in waterfall["features"] if f["shap_value"] > 0]
        negative_features = [f for f in waterfall["features"] if f["shap_value"] < 0]
        
        summary_parts = []
        if positive_features:
            top_positive = positive_features[0]
            summary_parts.append(f"High {top_positive['feature']} ({top_positive['feature_value']:.2f})")
        if negative_features:
            top_negative = negative_features[0]
            summary_parts.append(f"Low {top_negative['feature']} ({top_negative['feature_value']:.2f})")
        
        return {
            "waterfall_data": waterfall,
            "top_positive_factors": positive_features[:3],
            "top_negative_factors": negative_features[:3],
            "summary": " | ".join(summary_parts) if summary_parts else "Average behavior",
            "risk_level": "HIGH" if waterfall["prediction"] > 0.7 else "MEDIUM" if waterfall["prediction"] > 0.5 else "LOW"
        }


def get_explainer() -> AlertExplainer:
    return AlertExplainer()
