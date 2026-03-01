"""
Data Preprocessing Module for Network Intrusion Detection
Handles loading and preprocessing of CICIDS2017 dataset
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from typing import Tuple, List, Dict, Optional
import os
import warnings
warnings.filterwarnings('ignore')


ATTACK_TYPES = {
    'BENIGN': 0,
    'DoS Hulk': 1,
    'DoS GoldenEye': 2,
    'DoS slowloris': 3,
    'DoS Slowhttptest': 4,
    'Heartbleed': 5,
    'Web Attack Brute Force': 6,
    'Web Attack XSS': 7,
    'Web Attack SqlInjection': 8,
    'Infiltration': 9,
    'Bot': 10,
    'PortScan': 11,
    'DDoS': 12,
    'FTP-Patator': 13,
    'SSH-Patator': 14
}

ATTACK_CATEGORIES = {
    'BENIGN': 'Normal',
    'DoS Hulk': 'DoS',
    'DoS GoldenEye': 'DoS',
    'DoS slowloris': 'DoS',
    'DoS Slowhttptest': 'DoS',
    'Heartbleed': 'DoS',
    'Web Attack Brute Force': 'Web Attack',
    'Web Attack XSS': 'Web Attack',
    'Web Attack SqlInjection': 'Web Attack',
    'Infiltration': 'Infiltration',
    'Bot': 'Botnet',
    'PortScan': 'Reconnaissance',
    'DDoS': 'DDoS',
    'FTP-Patator': 'Brute Force',
    'SSH-Patator': 'Brute Force'
}

SEVERITY_MAP = {
    'BENIGN': 'LOW',
    'DoS Hulk': 'CRITICAL',
    'DoS GoldenEye': 'HIGH',
    'DoS slowloris': 'HIGH',
    'DoS Slowhttptest': 'HIGH',
    'Heartbleed': 'CRITICAL',
    'Web Attack Brute Force': 'MEDIUM',
    'Web Attack XSS': 'HIGH',
    'Web Attack SqlInjection': 'CRITICAL',
    'Infiltration': 'HIGH',
    'Bot': 'HIGH',
    'PortScan': 'MEDIUM',
    'DDoS': 'CRITICAL',
    'FTP-Patator': 'HIGH',
    'SSH-Patator': 'HIGH'
}


class DataPreprocessor:
    """Preprocess network flow data for ML model training/inference"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_names = []
        self.is_fitted = False
        self.categorical_cols = ['protocol_type', 'service', 'flag']
        self.numeric_cols = []
        
    def load_csv(self, filepath: str, sample_size: Optional[int] = None) -> pd.DataFrame:
        """Load network flow data from CSV file"""
        print(f"Loading data from {filepath}...")
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Data file not found: {filepath}")
        
        df = pd.read_csv(filepath, low_memory=False)
        print(f"Loaded {len(df)} records")
        
        if sample_size and sample_size < len(df):
            df = df.sample(n=sample_size, random_state=42)
            print(f"Sampled {sample_size} records")
        
        return df
    
    def preprocess(self, df: pd.DataFrame, fit: bool = True) -> np.ndarray:
        """Preprocess the dataframe"""
        df = df.copy()
        
        if 'Label' in df.columns:
            df['Label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
        
        df = self._handle_missing_values(df)
        
        if fit:
            self._identify_features(df)
            self._fit_encoders(df)
        
        df = self._encode_categorical(df)
        df = self._select_features(df)
        
        if fit:
            self.scaler.fit(df.values)
            self.is_fitted = True
        
        scaled = self.scaler.transform(df.values)
        return scaled
    
    def _handle_missing_values(self, df: pd.DataFrame) -> pd.DataFrame:
        """Handle missing and infinite values"""
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        return df
    
    def _identify_features(self, df: pd.DataFrame):
        """Identify feature columns"""
        exclude_cols = ['Label', 'label', 'Attack', 'attack']
        self.feature_names = [col for col in df.columns if col not in exclude_cols]
        self.numeric_cols = [col for col in self.feature_names if col not in self.categorical_cols]
    
    def _fit_encoders(self, df: pd.DataFrame):
        """Fit label encoders for categorical features"""
        for col in self.categorical_cols:
            if col in df.columns:
                le = LabelEncoder()
                le.fit(df[col].astype(str))
                self.label_encoders[col] = le
    
    def _encode_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features"""
        for col in self.categorical_cols:
            if col in df.columns and col in self.label_encoders:
                le = self.label_encoders[col]
                df[col] = df[col].astype(str).apply(
                    lambda x: le.transform([x])[0] if x in le.classes_ else -1
                )
        return df
    
    def _select_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Select only known features"""
        available_features = [f for f in self.feature_names if f in df.columns]
        return df[available_features]
    
    def get_feature_names(self) -> List[str]:
        """Get preprocessed feature names"""
        return self.feature_names
    
    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform new data using fitted preprocessor"""
        if not self.is_fitted:
            raise ValueError("Preprocessor not fitted")
        
        df = df.copy()
        df = self._handle_missing_values(df)
        df = self._encode_categorical(df)
        df = self._select_features(df)
        
        return self.scaler.transform(df.values)
    
    def save(self, filepath: str):
        """Save preprocessor to file"""
        import joblib
        joblib.dump({
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
            'categorical_cols': self.categorical_cols,
            'numeric_cols': self.numeric_cols
        }, filepath)
    
    def load(self, filepath: str):
        """Load preprocessor from file"""
        import joblib
        data = joblib.load(filepath)
        self.scaler = data['scaler']
        self.label_encoders = data['label_encoders']
        self.feature_names = data['feature_names']
        self.categorical_cols = data['categorical_cols']
        self.numeric_cols = data['numeric_cols']
        self.is_fitted = True


def load_and_split_data(
    filepath: str,
    test_size: float = 0.2,
    sample_size: Optional[int] = None
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, List[str]]:
    """Load, preprocess, and split data for training"""
    
    preprocessor = DataPreprocessor()
    df = preprocessor.load_csv(filepath, sample_size)
    
    labels = df['Label'].values if 'Label' in df.columns else df['label'].values
    
    X = preprocessor.preprocess(df, fit=True)
    y = labels.astype(int)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    print(f"Attack ratio: {y.sum() / len(y) * 100:.2f}%")
    
    return X_train, X_test, y_train, y_test, preprocessor.feature_names


def get_attack_info(attack_name: str) -> Dict[str, str]:
    """Get attack category and severity info"""
    return {
        'category': ATTACK_CATEGORIES.get(attack_name, 'Unknown'),
        'severity': SEVERITY_MAP.get(attack_name, 'MEDIUM'),
        'attack_type': attack_name
    }


def get_all_attack_types() -> List[str]:
    """Get list of all attack types"""
    return list(ATTACK_TYPES.keys())
