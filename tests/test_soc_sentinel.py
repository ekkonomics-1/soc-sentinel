import pytest
import pandas as pd
import numpy as np
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.data_simulator import SOCDataSimulator, get_simulator
from src.ingestion.threat_client import ThreatIntelClient
from src.models.anomaly_detector import AnomalyDetector, get_anomaly_detector
from src.alerts.alert_manager import AlertManager, Alert, AlertSeverity, AlertStatus


class TestDataSimulator:
    def test_get_simulator_returns_instance(self):
        simulator = get_simulator()
        assert isinstance(simulator, SOCDataSimulator)

    def test_generate_combined_events_shape(self):
        simulator = get_simulator()
        df = simulator.generate_combined_events(n=100)
        assert df.shape[0] == 100
        assert 'is_anomaly' in df.columns
        assert 'timestamp' in df.columns

    def test_generate_combined_events_has_anomalies(self):
        simulator = get_simulator()
        df = simulator.generate_combined_events(n=500)
        anomaly_count = df['is_anomaly'].sum()
        assert anomaly_count > 0, "Should generate some anomalies"

    def test_generate_auth_logs(self):
        simulator = get_simulator()
        df = simulator.generate_auth_logs(n=100)
        assert 'status' in df.columns
        assert 'user' in df.columns
        assert 'ip_address' in df.columns

    def test_generate_network_logs(self):
        simulator = get_simulator()
        df = simulator.generate_network_logs(n=100)
        assert 'src_ip' in df.columns
        assert 'bytes_sent' in df.columns


class TestAnomalyDetector:
    def test_detector_initialization(self):
        detector = get_anomaly_detector(contamination=0.05)
        assert detector.contamination == 0.05

    def test_detector_fit_and_predict(self):
        detector = get_anomaly_detector(contamination=0.1)
        X = np.random.randn(100, 5)
        feature_names = ['f1', 'f2', 'f3', 'f4', 'f5']
        
        detector.fit(X, feature_names)
        predictions = detector.predict(X)
        
        assert len(predictions) == 100
        assert all(p in [0, 1] for p in predictions)

    def test_detector_detect_returns_results(self):
        detector = get_anomaly_detector(contamination=0.1)
        X = np.random.randn(50, 3)
        feature_names = ['a', 'b', 'c']
        
        detector.fit(X, feature_names)
        results = detector.detect(X)
        
        assert len(results) == 50
        assert 'is_anomaly' in results[0]
        assert 'anomaly_score' in results[0]
        assert 'severity' in results[0]

    def test_detector_detects_extreme_values(self):
        detector = get_anomaly_detector(contamination=0.05)
        
        X_normal = np.random.randn(90, 3)
        X_anomaly = np.random.randn(10, 3) * 10
        X = np.vstack([X_normal, X_anomaly])
        
        feature_names = ['a', 'b', 'c']
        detector.fit(X, feature_names)
        results = detector.detect(X)
        
        anomaly_count = sum(1 for r in results if r['is_anomaly'])
        assert anomaly_count > 0


class TestAlertManager:
    def test_create_alert(self):
        manager = AlertManager()
        alert = manager.create_alert(
            severity="HIGH",
            title="Test Alert",
            description="Test description"
        )
        assert alert.severity == "HIGH"
        assert alert.title == "Test Alert"
        assert len(manager.alerts) == 1

    def test_get_alerts(self):
        manager = AlertManager()
        manager.create_alert("HIGH", "Alert 1", "Desc 1")
        manager.create_alert("LOW", "Alert 2", "Desc 2")
        
        alerts = manager.get_alerts()
        assert len(alerts) == 2

    def test_get_alerts_by_severity(self):
        manager = AlertManager()
        manager.create_alert("HIGH", "Alert 1", "Desc 1")
        manager.create_alert("LOW", "Alert 2", "Desc 2")
        manager.create_alert("HIGH", "Alert 3", "Desc 3")
        
        high_alerts = manager.get_alerts(severity="HIGH")
        assert len(high_alerts) == 2

    def test_update_alert_status(self):
        manager = AlertManager()
        alert = manager.create_alert("HIGH", "Test", "Desc")
        
        success = manager.update_status(alert.alert_id, "RESOLVED")
        assert success is True
        assert manager.alerts[0].status == "RESOLVED"

    def test_alert_to_dict(self):
        alert = Alert(
            alert_id="TEST-001",
            severity="HIGH",
            title="Test",
            description="Test desc"
        )
        data = alert.to_dict()
        
        assert data['alert_id'] == "TEST-001"
        assert data['severity'] == "HIGH"
        assert 'timestamp' in data

    def test_alert_statistics(self):
        manager = AlertManager()
        manager.create_alert("CRITICAL", "A1", "D1")
        manager.create_alert("HIGH", "A2", "D2")
        manager.create_alert("HIGH", "A3", "D3")
        
        stats = manager.get_statistics()
        assert stats['total_alerts'] == 3
        assert stats['by_severity']['CRITICAL'] == 1
        assert stats['by_severity']['HIGH'] == 2


class TestThreatClient:
    def test_mock_ip_check(self):
        client = ThreatIntelClient(abuseipdb_api_key=None)
        result = client.check_ip("192.168.1.1")
        
        assert 'ip' in result
        assert 'abuse_confidence_score' in result
        assert result['ip'] == "192.168.1.1"

    def test_check_private_ip(self):
        client = ThreatIntelClient(abuseipdb_api_key=None)
        result = client.check_ip("10.0.0.1")
        
        assert result['is_whitelisted'] is True
        assert result['abuse_confidence_score'] == 0


class TestEndToEnd:
    def test_full_pipeline(self):
        simulator = get_simulator()
        df = simulator.generate_combined_events(n=200)
        
        feature_cols = ['login_failure_count', 'unique_ips', 'request_rate', 
                        'avg_response_time', 'error_rate', 'bytes_sent']
        X = df[feature_cols].values
        
        detector = get_anomaly_detector(contamination=0.05)
        detector.fit(X, feature_cols)
        results = detector.detect(X)
        
        alert_manager = AlertManager()
        for i, r in enumerate(results):
            if r['is_anomaly']:
                alert_manager.create_alert(
                    severity=r['severity'],
                    title=f"Anomaly {i}",
                    description=f"Score: {r['anomaly_score']:.2f}"
                )
        
        assert len(results) == 200
        assert len(alert_manager.alerts) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
