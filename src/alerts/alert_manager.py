import json
from datetime import datetime
from typing import Dict, List, Optional
from enum import Enum


class AlertSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertStatus(Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class Alert:
    def __init__(
        self,
        alert_id: str,
        severity: str,
        title: str,
        description: str,
        timestamp: Optional[datetime] = None,
        source: str = "anomaly_detector",
        metadata: Optional[Dict] = None
    ):
        self.alert_id = alert_id
        self.severity = severity
        self.title = title
        self.description = description
        self.timestamp = timestamp or datetime.now()
        self.source = source
        self.metadata = metadata or {}
        self.status = AlertStatus.NEW.value
        self.explanation = None
        self.shap_values = None

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "timestamp": self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else self.timestamp,
            "source": self.source,
            "metadata": self.metadata,
            "status": self.status,
            "explanation": self.explanation,
            "shap_values": self.shap_values
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "Alert":
        alert = cls(
            alert_id=data.get("alert_id", ""),
            severity=data.get("severity", "MEDIUM"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            metadata=data.get("metadata", {})
        )
        alert.status = data.get("status", AlertStatus.NEW.value)
        alert.explanation = data.get("explanation")
        alert.shap_values = data.get("shap_values")
        if isinstance(data.get("timestamp"), str):
            alert.timestamp = datetime.fromisoformat(data["timestamp"])
        return alert


class AlertManager:
    def __init__(self):
        self.alerts: List[Alert] = []
        self.alert_counter = 0

    def create_alert(
        self,
        severity: str,
        title: str,
        description: str,
        source: str = "anomaly_detector",
        metadata: Optional[Dict] = None
    ) -> Alert:
        self.alert_counter += 1
        alert_id = f"ALERT-{self.alert_counter:06d}-{datetime.now().strftime('%Y%m%d')}"

        alert = Alert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            description=description,
            source=source,
            metadata=metadata
        )

        self.alerts.append(alert)
        return alert

    def add_explanation(self, alert_id: str, explanation: str, shap_values: Optional[Dict] = None) -> bool:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.explanation = explanation
                alert.shap_values = shap_values
                return True
        return False

    def get_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        filtered = self.alerts

        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        if status:
            filtered = [a for a in filtered if a.status == status]

        filtered = sorted(filtered, key=lambda x: x.timestamp, reverse=True)
        return [a.to_dict() for a in filtered[:limit]]

    def update_status(self, alert_id: str, status: str) -> bool:
        for alert in self.alerts:
            if alert.alert_id == alert_id:
                alert.status = status
                return True
        return False

    def get_statistics(self) -> Dict:
        total = len(self.alerts)
        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_status = {status.value: 0 for status in AlertStatus}

        for alert in self.alerts:
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            by_status[alert.status] = by_status.get(alert.status, 0) + 1

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "unresolved": by_status.get(AlertStatus.NEW.value, 0) + by_status.get(AlertStatus.INVESTIGATING.value, 0)
        }

    def export_json(self, filepath: str) -> None:
        with open(filepath, 'w') as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2, default=str)

    def import_json(self, filepath: str) -> None:
        with open(filepath, 'r') as f:
            data = json.load(f)
            self.alerts = [Alert.from_dict(d) for d in data]


def get_alert_manager() -> AlertManager:
    return AlertManager()
