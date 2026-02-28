import os
import requests
import pandas as pd
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import time
import random


class ThreatIntelClient:
    def __init__(self, abuseipdb_api_key: Optional[str] = None, virustotal_api_key: Optional[str] = None):
        self.abuseipdb_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY")
        self.virustotal_key = virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2"
        self.virustotal_url = "https://www.virustotal.com/api/v3"
        self.cache = {}
        self.cache_duration = timedelta(hours=1)
        
        self.malicious_ips = [
            "185.220.101.1", "185.220.101.2", "185.220.101.3",
            "45.33.32.156", "23.129.64.130", "104.244.76.13",
            "171.25.193.77", "86.105.227.228", "192.99.144.128",
            "91.236.75.18", "62.210.105.116", "103.253.145.28",
            "194.26.29.102", "212.192.241.23", "45.142.122.100",
            "194.187.251.45", "91.234.56.78", "185.220.101.10",
            "195.154.181.163", "163.172.51.225"
        ]

    def check_ip(self, ip: str) -> Dict:
        if ip in self.cache:
            cached = self.cache[ip]
            if datetime.now() - cached["timestamp"] < self.cache_duration:
                return cached["data"]

        if self.virustotal_key:
            result = self._check_virustotal(ip)
            if result:
                self.cache[ip] = {"data": result, "timestamp": datetime.now()}
                return result

        if self.abuseipdb_key:
            result = self._check_abuseipdb(ip)
            if result:
                self.cache[ip] = {"data": result, "timestamp": datetime.now()}
                return result

        return self._simulated_ip_check(ip)

    def _check_virustotal(self, ip: str) -> Optional[Dict]:
        if not self.virustotal_key:
            return None
            
        headers = {"x-apikey": self.virustotal_key}
        
        try:
            response = requests.get(
                f"{self.virustotal_url}/ip_addresses/{ip}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())
                threat_score = malicious + suspicious
                confidence = int((threat_score / total * 100) if total > 0 else 0)
                
                return {
                    "ip": ip,
                    "abuse_confidence_score": confidence,
                    "is_whitelisted": data.get("whois", "") != "",
                    "total_reports": malicious + suspicious,
                    "num_distinct_users": malicious,
                    "country_code": data.get("country", ""),
                    "isp": data.get("asn_owner", "Unknown"),
                    "domain": data.get("network", ""),
                    "usage_type": data.get("type", "Unknown"),
                    "last_reported_at": data.get("last_analysis_date", ""),
                    "virustotal_stats": stats
                }
        except Exception as e:
            print(f"VirusTotal error for {ip}: {e}")
        
        return None

    def _check_abuseipdb(self, ip: str) -> Optional[Dict]:
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
            response = requests.get(f"{self.abuseipdb_url}/check", headers=headers, params=params, timeout=10)
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
                return result
        except Exception as e:
            print(f"AbuseIPDB error for {ip}: {e}")

        return None

    def _simulated_ip_check(self, ip: str) -> Dict:
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

        if ip in self.malicious_ips:
            countries = ["RU", "CN", "KP", "IR", "SY", "UA", "NL", "DE", "FR"]
            isps = ["Hostinger", "DigitalOcean", "OVH", "Hetzner", "Linode", "Cloudflare", "LeaseWeb"]
            report_count = random.randint(10, 500)
            return {
                "ip": ip,
                "abuse_confidence_score": random.randint(60, 100),
                "is_whitelisted": False,
                "total_reports": report_count,
                "num_distinct_users": random.randint(5, 50),
                "country_code": random.choice(countries),
                "isp": random.choice(isps),
                "domain": f"{ip.split('.')[2]}.example.com",
                "usage_type": "Hosting",
                "last_reported_at": (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
            }

        benign_countries = ["US", "CA", "GB", "DE", "FR", "JP", "AU", "BR"]
        benign_isps = ["Google", "Microsoft", "Amazon", "Cloudflare", "Facebook", "Apple", "Netflix"]
        
        return {
            "ip": ip,
            "abuse_confidence_score": random.randint(0, 5),
            "is_whitelisted": False,
            "total_reports": random.randint(0, 3),
            "num_distinct_users": random.randint(0, 2),
            "country_code": random.choice(benign_countries),
            "isp": random.choice(benign_isps),
            "domain": "unknown",
            "usage_type": "ISP",
            "last_reported_at": None,
        }

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


def get_threat_client(virustotal_api_key: str = None) -> ThreatIntelClient:
    return ThreatIntelClient(virustotal_api_key=virustotal_api_key)
