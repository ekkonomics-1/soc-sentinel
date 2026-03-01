"""
Training Pipeline for Network Intrusion Detection Model
Trains ML models on CICIDS2017 dataset
"""

import numpy as np
import pandas as pd
import os
import sys
from typing import Tuple, Dict, Any
import joblib
import json
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ml.preprocessing import DataPreprocessor, load_and_split_data, get_attack_info
from src.models.anomaly_detector import AnomalyDetector, SupervisedClassifier, EnsembleDetector


class TrainingPipeline:
    """Complete training pipeline for network intrusion detection"""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        self.preprocessor = DataPreprocessor()
        self.ensemble = EnsembleDetector(contamination=0.05)
        self.is_trained = False
        
    def load_data(self, filepath: str, sample_size: int = 100000) -> pd.DataFrame:
        """Load and sample data from CSV"""
        print(f"Loading data from {filepath}...")
        df = pd.read_csv(filepath, low_memory=False)
        print(f"Loaded {len(df)} total records")
        
        if sample_size and sample_size < len(df):
            df = df.sample(n=sample_size, random_state=42)
            print(f"Sampled {sample_size} records")
        
        return df
    
    def prepare_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Prepare data for training"""
        print("Preprocessing data...")
        
        labels = df['Label'].values if 'Label' in df.columns else df['label'].values
        labels = np.array([0 if str(l).upper() == 'BENIGN' else 1 for l in labels])
        
        X = self.preprocessor.preprocess(df, fit=True)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, labels, test_size=0.2, random_state=42, stratify=labels
        )
        
        print(f"Training samples: {len(X_train)}")
        print(f"Test samples: {len(X_test)}")
        print(f"Attack ratio: {y_train.sum() / len(y_train) * 100:.2f}%")
        
        return X_train, X_test, y_train, y_test
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, feature_names: list) -> Dict[str, Any]:
        """Train the ensemble model"""
        print("Training models...")
        
        print("  Training unsupervised anomaly detector...")
        self.ensemble.fit_unsupervised(X_train, feature_names)
        
        print("  Training supervised classifier...")
        self.ensemble.fit_supervised(X_train, y_train, feature_names)
        
        self.is_trained = True
        
        metrics = {
            "training_date": datetime.now().isoformat(),
            "training_samples": len(X_train),
            "feature_count": len(feature_names),
            "attack_ratio": float(y_train.sum() / len(y_train))
        }
        
        return metrics
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
        """Evaluate the model"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        print("Evaluating model...")
        
        predictions, probabilities = self.ensemble.predict(X_test)
        
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score, 
            f1_score, confusion_matrix, classification_report
        )
        
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions, zero_division=0)
        recall = recall_score(y_test, predictions, zero_division=0)
        f1 = f1_score(y_test, predictions, zero_division=0)
        
        cm = confusion_matrix(y_test, predictions)
        
        results = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "confusion_matrix": cm.tolist(),
            "true_negatives": int(cm[0][0]),
            "false_positives": int(cm[0][1]),
            "false_negatives": int(cm[1][0]),
            "true_positives": int(cm[1][1])
        }
        
        print(f"\nModel Performance:")
        print(f"  Accuracy:  {results['accuracy']:.4f}")
        print(f"  Precision: {results['precision']:.4f}")
        print(f"  Recall:    {results['recall']:.4f}")
        print(f"  F1 Score:  {results['f1_score']:.4f}")
        
        return results
    
    def save(self, model_name: str = "nids_model") -> str:
        """Save the trained model and preprocessor"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        model_path = os.path.join(self.model_dir, f"{model_name}_{timestamp}.joblib")
        
        save_data = {
            "ensemble": self.ensemble,
            "preprocessor": self.preprocessor,
            "is_trained": self.is_trained,
            "saved_date": datetime.now().isoformat()
        }
        
        joblib.dump(save_data, model_path)
        print(f"Model saved to {model_path}")
        
        latest_path = os.path.join(self.model_dir, f"{model_name}_latest.joblib")
        joblib.dump(save_data, latest_path)
        print(f"Latest model also saved to {latest_path}")
        
        return model_path
    
    def load(self, model_path: str):
        """Load a trained model"""
        print(f"Loading model from {model_path}")
        data = joblib.load(model_path)
        
        self.ensemble = data["ensemble"]
        self.preprocessor = data["preprocessor"]
        self.is_trained = data["is_trained"]
        
        print("Model loaded successfully")
    
    def predict(self, df: pd.DataFrame) -> list:
        """Predict anomalies on new data"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        X = self.preprocessor.transform(df)
        return self.ensemble.detect(X)


def train_model(data_path: str, sample_size: int = 100000) -> Dict[str, Any]:
    """Main training function"""
    pipeline = TrainingPipeline()
    
    df = pipeline.load_data(data_path, sample_size)
    
    X_train, X_test, y_train, y_test = pipeline.prepare_data(df)
    
    feature_names = pipeline.preprocessor.get_feature_names()
    metrics = pipeline.train(X_train, y_train, feature_names)
    
    eval_results = pipeline.evaluate(X_test, y_test)
    metrics.update(eval_results)
    
    pipeline.save("nids_model")
    
    return metrics


def download_dataset() -> str:
    """Download CICIDS2017 dataset"""
    import kaggle
    
    print("Downloading CICIDS2017 dataset from Kaggle...")
    
    os.makedirs("data/raw", exist_ok=True)
    
    try:
        from kaggle.api.kaggle_api_extended import KaggleApi
        api = KaggleApi()
        api.authenticate()
        api.dataset_download_files(
            'chethuhn/network-intrusion-dataset',
            path='data/raw',
            unzip=True
        )
        print("Dataset downloaded successfully!")
        return "data/raw"
    except Exception as e:
        print(f"Kaggle download failed: {e}")
        print("\nAlternative: Download manually from:")
        print("  https://www.unb.ca/cic/datasets/ids-2017.html")
        print("  or")
        print("  https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset")
        return None


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Train Network Intrusion Detection Model")
    parser.add_argument("--data", type=str, default="data/raw/CICIDS2017.csv", help="Path to dataset")
    parser.add_argument("--sample", type=int, default=100000, help="Sample size for training")
    parser.add_argument("--download", action="store_true", help="Download dataset first")
    
    args = parser.parse_args()
    
    if args.download:
        download_dataset()
    
    if os.path.exists(args.data):
        metrics = train_model(args.data, args.sample)
        print("\n!")
        print(jsonTraining complete.dumps(metrics, indent=2))
    else:
        print(f"Data file not found: {args.data}")
        print("Use --download to fetch dataset from Kaggle")
