import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from sklearn.preprocessing import StandardScaler


class FeaturePipeline:
    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_names = [
            "login_failure_count", "login_success_count", "unique_ips",
            "request_rate", "avg_response_time", "error_rate", "bytes_sent",
            "hour_of_day", "is_business_hours", "day_of_week", "is_weekend",
            "geo_countries_accessed", "geo_velocity", "ip_reputation_score"
        ]
        self.fitted = False

    def compute_login_features(self, df: pd.DataFrame, window_minutes: int = 15) -> pd.DataFrame:
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")

        df["time_window"] = df["timestamp"].dt.floor(f"{window_minutes}T")

        login_features = df.groupby(["user", "time_window"]).agg({
            "status": lambda x: (x == "FAILURE").sum(),
            "ip_address": "nunique",
            "country": "nunique",
            "timestamp": "count"
        }).reset_index()

        login_features.columns = ["user", "time_window", "login_failure_count", "unique_ips", "geo_countries_accessed", "login_success_count"]
        login_features["login_success_count"] = login_features["login_success_count"] - login_features["login_failure_count"]

        return login_features

    def compute_network_features(self, df: pd.DataFrame, window_minutes: int = 5) -> pd.DataFrame:
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp")

        df["time_window"] = df["timestamp"].dt.floor(f"{window_minutes}T")

        network_features = df.groupby(["src_ip", "time_window"]).agg({
            "requests_count": "sum",
            "bytes_sent": "sum",
            "latency_ms": "mean",
            "status_code": lambda x: ((x >= 400) & (x < 600)).mean(),
            "timestamp": "count"
        }).reset_index()

        network_features.columns = ["src_ip", "time_window", "request_rate", "bytes_sent", "avg_response_time", "error_rate", "request_count"]
        network_features["request_rate"] = network_features["request_rate"] / window_minutes

        return network_features

    def compute_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            df["hour_of_day"] = df["timestamp"].dt.hour
            df["is_business_hours"] = ((df["hour_of_day"] >= 9) & (df["hour_of_day"] < 17)).astype(int)
            df["day_of_week"] = df["timestamp"].dt.dayofweek
            df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        return df

    def compute_geo_velocity(self, df: pd.DataFrame) -> pd.DataFrame:
        country_distances = {
            ("US", "CA"): 1, ("US", "GB"): 1, ("US", "DE"): 1,
            ("CA", "US"): 1, ("GB", "US"): 1, ("DE", "US"): 1,
        }

        df = df.sort_values(["user", "timestamp"])
        df["prev_country"] = df.groupby("user")["country"].shift(1)
        df["geo_velocity"] = df.apply(
            lambda row: country_distances.get((row["country"], row["prev_country"]), 0)
            if pd.notna(row["prev_country"]) else 0,
            axis=1
        )
        return df

    def compute_ip_reputation(self, df: pd.DataFrame, threat_client) -> pd.DataFrame:
        df = df.copy()
        if "ip_address" in df.columns:
            unique_ips = df["ip_address"].unique()
            ip_scores = {}
            for ip in unique_ips:
                threat_info = threat_client.check_ip(ip)
                ip_scores[ip] = 100 - threat_info.get("abuse_confidence_score", 0)
            df["ip_reputation_score"] = df["ip_address"].map(ip_scores)
        return df

    def extract_features(self, df: pd.DataFrame, threat_client=None) -> pd.DataFrame:
        df = self.compute_temporal_features(df)

        if "status" in df.columns:
            df = self.compute_login_features(df)

        if "src_ip" in df.columns:
            df = self.compute_network_features(df)

        if "country" in df.columns and "user" in df.columns:
            df = self.compute_geo_velocity(df)

        if threat_client and "ip_address" in df.columns:
            df = self.compute_ip_reputation(df, threat_client)

        feature_cols = [col for col in self.feature_names if col in df.columns]
        return df[feature_cols] if feature_cols else pd.DataFrame()

    def fit_transform(self, df: pd.DataFrame, threat_client=None) -> np.ndarray:
        features = self.extract_features(df, threat_client)
        if features.empty:
            return np.array([])

        self.scaler.fit(features)
        self.fitted = True
        return self.scaler.transform(features)

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise ValueError("Pipeline not fitted. Call fit_transform first.")

        features = self.extract_features(df)
        if features.empty:
            return np.array([])

        return self.scaler.transform(features)

    def get_feature_importance(self, feature_names: List[str]) -> Dict[str, float]:
        return {name: 1.0 / len(feature_names) if feature_names else 0 for name in feature_names}


def get_feature_pipeline() -> FeaturePipeline:
    return FeaturePipeline()
