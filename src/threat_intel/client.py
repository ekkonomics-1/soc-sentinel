"""
Threat Intelligence API Integration
Integrates with AbuseIPDB and other threat intelligence sources
"""

import requests
import time
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import json
import hashlib


ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted"
}


class ThreatIntelligenceClient:
    """Client for threat intelligence APIs"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.cache = {}
        self.cache_ttl = 3600
        
    def _make_request(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """Make API request with rate limiting"""
        if not self.api_key:
            return None
            
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }
        
        url = f"{self.base_url}/{endpoint}"
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 429:
                print("Rate limited, waiting...")
                time.sleep(60)
                return self._make_request(endpoint, params)
            
            if response.status_code == 200:
                return response.json()
            else:
                print(f"API Error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"Request failed: {e}")
            return None
    
    def _get_cache(self, key: str) -> Optional[Dict]:
        """Get cached result"""
        if key in self.cache:
            cached, timestamp = self.cache[key]
            if time.time() - timestamp < self.cache_ttl:
                return cached
        return None
    
    def _set_cache(self, key: str, value: Dict):
        """Set cache result"""
        self.cache[key] = (value, time.time())
    
    def check_ip(self, ip_address: str, max_age_days: int = 30) -> Optional[Dict]:
        """Check IP reputation from AbuseIPDB"""
        cache_key = f"check_{ip_address}"
        
        cached = self._get_cache(cache_key)
        if cached:
            return cached
        
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days,
            "verbose": ""
        }
        
        data = self._make_request("check", params)
        
        if data and "data" in data:
            result = self._parse_ip_response(data["data"])
            self._set_cache(cache_key, result)
            return result
        
        return None
    
    def _parse_ip_response(self, data: Dict) -> Dict:
        """Parse AbuseIPDB response"""
        return {
            "ip_address": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "is_whitelisted": data.get("isWhitelisted"),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "num_unique_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "categories": [ABUSEIPDB_CATEGORIES.get(c, f"Category {c}") 
                          for c in data.get("categories", [])],
            "reported_at": data.get("reports", [])[:5] if data.get("reports") else [],
            "is_malicious": data.get("abuseConfidenceScore", 0) > 50,
            "threat_level": self._get_threat_level(data.get("abuseConfidenceScore", 0)),
            "timestamp": datetime.now().isoformat()
        }
    
    def _get_threat_level(self, score: int) -> str:
        """Convert confidence score to threat level"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "SAFE"
    
    def get_report(self, ip_address: str, page: int = 1) -> Optional[List[Dict]]:
        """Get detailed reports for an IP"""
        params = {
            "ipAddress": ip_address,
            "page": page,
            "perPage": 25
        }
        
        data = self._make_request("reports", params)
        
        if data and "data" in data:
            return [
                {
                    "reported_at": report.get("reportedAt"),
                    "categories": [ABUSEIPDB_CATEGORIES.get(c, f"Category {c}") 
                                 for c in report.get("categories", [])],
                    "comment": report.get("comment"),
                    "reporter_id": report.get("reporterId")
                }
                for report in data["data"]
            ]
        
        return None
    
    def get_blacklist(self, confidence_min: int = 50, limit: int = 10000) -> Optional[List[Dict]]:
        """Get blacklist of malicious IPs"""
        params = {
            "confidenceMinimum": confidence_min,
            "limit": min(limit, 10000),
            "format": "json"
        }
        
        data = self._make_request("blacklist", params)
        
        if data and "data" in data:
            return [
                {
                    "ip_address": entry.get("ipAddress"),
                    "abuse_confidence_score": entry.get("abuseConfidenceScore"),
                    "country_code": entry.get("countryCode"),
                    "isp": entry.get("isp"),
                    "domain": entry.get("domain"),
                    "num_reports": entry.get("numReports"),
                    "last_reported": entry.get("lastReportedAt")
                }
                for entry in data["data"]
            ]
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get API statistics"""
        data = self._make_request("statistics")
        
        if data and "data" in data:
            return {
                "total_reports": data["data"].get("totalReports", 0),
                "total_unique_ips": data["data"].get("totalUniqueIPs", 0),
                "average_score": data["data"].get("averageDaily", 0),
                "categories": data["data"].get("categoryUsage", {})
            }
        
        return {}


class MockThreatIntelligence:
    """Mock threat intelligence for demo/testing"""
    
    def __init__(self):
        self.sample_ips = self._generate_sample_data()
    
    def _generate_sample_data(self) -> Dict:
        """Generate sample threat data"""
        return {
            "185.220.101.1": {
                "ip_address": "185.220.101.1",
                "abuse_confidence_score": 95,
                "country_code": "DE",
                "country_name": "Germany",
                "isp": "Tor Exit Node",
                "categories": ["Tor Exit Node", "SSH Brute-Force"],
                "total_reports": 15420,
                "is_malicious": True,
                "threat_level": "CRITICAL"
            },
            "45.33.32.156": {
                "ip_address": "45.33.32.156",
                "abuse_confidence_score": 78,
                "country_code": "US",
                "country_name": "United States",
                "isp": "Linode",
                "categories": ["Port Scan", "Web Spam"],
                "total_reports": 3420,
                "is_malicious": True,
                "threat_level": "HIGH"
            },
            "23.129.64.130": {
                "ip_address": "23.129.64.130",
                "abuse_confidence_score": 100,
                "country_code": "US",
                "country_name": "United States",
                "isp": "Northrop Grumman",
                "categories": ["DDoS", "Botnet"],
                "total_reports": 45000,
                "is_malicious": True,
                "threat_level": "CRITICAL"
            }
        }
    
    def check_ip(self, ip_address: str) -> Optional[Dict]:
        """Check IP - returns sample or generates random"""
        if ip_address in self.sample_ips:
            return self._add_timestamp(self.sample_ips[ip_address])
        
        import random
        
        score = random.randint(0, 100)
        countries = ["CN", "RU", "US", "IR", "KP", "DE", "BR", "IN", "VN", "NL"]
        isps = ["China Telecom", "Rostelecom", "AWS", "DigitalOcean", "OVH"]
        
        result = {
            "ip_address": ip_address,
            "abuse_confidence_score": score,
            "country_code": random.choice(countries),
            "country_name": "Country",
            "isp": random.choice(isp),
            "categories": random.choice([
                ["Port Scan", "SSH Brute-Force"],
                ["Web Spam", "Email Spam"],
                ["DDoS", "Botnet"],
                ["SQL Injection", "Web Attack"]
            ]),
            "total_reports": random.randint(10, 10000),
            "is_malicious": score > 50,
            "threat_level": self._get_threat_level(score),
            "timestamp": datetime.now().isoformat()
        }
        
        return result
    
    def _add_timestamp(self, data: Dict) -> Dict:
        """Add timestamp to result"""
        result = data.copy()
        result["timestamp"] = datetime.now().isoformat()
        return result
    
    def _get_threat_level(self, score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "SAFE"
    
    def get_statistics(self) -> Dict:
        return {
            "total_reports": 250000,
            "total_unique_ips": 45000,
            "average_daily": 1500
        }


def get_threat_client(api_key: Optional[str] = None) -> Any:
    """Factory function to get threat intelligence client"""
    if api_key:
        return ThreatIntelligenceClient(api_key)
    else:
        print("Warning: No API key provided, using mock data")
        return MockThreatIntelligence()
