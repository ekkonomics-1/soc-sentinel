import os
import requests
import pandas as pd
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import time


class ThreatIntelClient:
    def __init__(self, abuseipdb_api_key: Optional[str] = None):
        self.abuseipdb_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}
        self.cache_duration = timedelta(hours=1)

    def check_ip(self, ip: str) -> Dict:
        if ip in self.cache:
            cached = self.cache[ip]
            if datetime.now() - cached["timestamp"] < self.cache_duration:
                return cached["data"]

        if not self.abuseipdb_key:
            return self._mock_ip_check(ip)

        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }

        try:
            response = requests.get(f"{self.base_url}/check", headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get("data", {})
                result = {
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "country_code": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "domain": data.get("domain", ""),
                    "usage_type": data.get("usageType", ""),
                    "last_reported_at": data.get("lastReportedAt", ""),
                }
                self.cache[ip] = {"data": result, "timestamp": datetime.now()}
                return result
        except Exception as e:
            print(f"Error checking IP {ip}: {e}")

        return self._mock_ip_check(ip)

    def _mock_ip_check(self, ip: str) -> Dict:
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {
                    "ip": ip,
                    "abuse_confidence_score": 0,
                    "is_whitelisted": True,
                    "total_reports": 0,
                    "num_distinct_users": 0,
                    "country_code": "US",
                    "isp": "Private Network",
                    "domain": "local",
                    "usage_type": "Reserved",
                    "last_reported_at": None,
                }
        except:
            pass

        return {
            "ip": ip,
            "abuse_confidence_score": 0,
            "is_whitelisted": False,
            "total_reports": 0,
            "num_distinct_users": 0,
            "country_code": "XX",
            "isp": "Unknown",
            "domain": "unknown",
            "usage_type": "Unknown",
            "last_reported_at": None,
        }

    def get_recent_reports(self, limit: int = 100) -> List[Dict]:
        if not self.abuseipdb_key:
            return self._mock_recent_reports(limit)

        headers = {
            "Key": self.abuseipdb_key,
            "Accept": "application/json"
        }
        params = {
            "limit": limit,
            "confidenceMinimum": 50
        }

        try:
            response = requests.get(f"{self.base_url}/reports", headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json().get("data", [])
        except Exception as e:
            print(f"Error fetching reports: {e}")

        return self._mock_recent_reports(limit)

    def _mock_recent_reports(self, limit: int) -> List[Dict]:
        return [
            {
                "ip": "192.168.1.100",
                "countryCode": "US",
                "reportedAt": datetime.now().isoformat(),
                "categories": [18, 22],
                "comment": "SSH brute force"
            }
        ] * min(limit, 5)


def get_threat_client() -> ThreatIntelClient:
    return ThreatIntelClient()
