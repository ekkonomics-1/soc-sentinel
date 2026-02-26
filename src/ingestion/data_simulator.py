import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Generator
import random
import hashlib
import time


class SOCDataSimulator:
    def __init__(self, seed: int = 42):
        np.random.seed(seed)
        random.seed(seed)
        self.seed = seed

        # Normal users
        self.users = [
            "john.smith", "sarah.jones", "mike.wilson", "emma.davis",
            "alex.brown", "lisa.taylor", "david.lee", "jennifer.white",
            "chris.garcia", "maria.martinez", "admin", "root", "service_account",
            "james.wilson", "patricia.taylor", "robert.anderson", "michael.thomas"
        ]

        # Internal (safe) IPs
        self.ips_internal = [
            "10.0.1.10", "10.0.1.15", "10.0.1.20", "10.0.2.5",
            "10.0.2.10", "10.0.3.50", "192.168.1.100", "192.168.1.105",
            "10.10.0.5", "10.10.0.10", "172.16.0.50"
        ]

        # Suspicious/malicious IPs (known bad actors - will show on VirusTotal)
        self.ips_malicious = [
            "185.220.101.1",    # Tor exit node
            "185.220.101.2",    # Tor exit node
            "45.33.32.156",     # Known scanner
            "23.129.64.130",    # Malware C2
            "104.244.76.13",    # Tor relay
            "171.25.193.77",    # Tor exit
            "86.105.227.228",   # Suspicious
            "192.99.144.128",   # Bad reputation
            "91.236.75.18",    # Botnet
            "62.210.105.116",   # Scanning
        ]

        # External legitimate IPs
        self.ips_external = [
            "8.8.8.8", "1.1.1.1", "142.250.185.46", "151.101.1.140",
            "104.16.249.249", "13.107.42.14", "52.84.223.111",
            "208.67.222.222", "208.67.220.220"
        ]

        self.countries = ["US", "CA", "GB", "DE", "FR", "JP", "AU", "BR", "RU", "CN", "IN"]

        self.user_agents_normal = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0",
        ]

        self.user_agents_suspicious = [
            "python-requests/2.31.0",
            "curl/7.81.0",
            "wget/1.21",
            "nikto/2.1.6",
            "sqlmap/1.6",
            "nmap/7.93",
            "scapy/2.5.0",
        ]

        self.endpoints = [
            "/api/v1/login", "/api/v1/users", "/api/v1/orders",
            "/api/v1/products", "/api/v1/search", "/api/v1/profile",
            "/api/v1/admin", "/api/v1/reports", "/api/v1/export",
            "/api/v1/auth", "/login", "/admin", "/wp-admin"
        ]

        # SQL injection patterns
        self.sqli_patterns = [
            "' OR '1'='1", "'; DROP TABLE", "UNION SELECT",
            "1' AND '1'='1", "admin'--", "1' ORDER BY",
            "<script>alert(1)</script>", "' OR 1=1--"
        ]

        # XSS patterns
        self.xss_patterns = [
            "<script>alert('XSS')</script>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "';alert(String.fromCharCode(88,83,83))//"
        ]

        # Attack types with MITRE mapping
        self.attack_types = {
            "brute_force": {
                "mitre": "T1110",
                "name": "Brute Force",
                "severity": "HIGH",
                "indicators": ["multiple_failed_logins", "password_spray"]
            },
            "sql_injection": {
                "mitre": "T1190",
                "name": "SQL Injection",
                "severity": "CRITICAL",
                "indicators": ["sqli_pattern", "database_error"]
            },
            "xss": {
                "mitre": "T1189",
                "name": "Cross-Site Scripting",
                "severity": "HIGH",
                "indicators": ["xss_pattern", "script_tag"]
            },
            "port_scan": {
                "mitre": "T1595",
                "name": "Port Scanning",
                "severity": "MEDIUM",
                "indicators": ["multiple_ports", "quick_succession"]
            },
            "credential_stuffing": {
                "mitre": "T1110",
                "name": "Credential Stuffing",
                "severity": "HIGH",
                "indicators": ["many_users", "same_password"]
            },
            "malware_c2": {
                "mitre": "T1071",
                "name": "Malware C2 Communication",
                "severity": "CRITICAL",
                "indicators": ["beaconing", "odd_intervals", "suspicious_port"]
            },
            "ddos": {
                "mitre": "T1498",
                "name": "Denial of Service",
                "severity": "HIGH",
                "indicators": ["high_volume", "single_target"]
            },
            "lateral_movement": {
                "mitre": "T1021",
                "name": "Lateral Movement",
                "severity": "CRITICAL",
                "indicators": ["unusual_access", "privilege_escalation"]
            },
            "data_exfiltration": {
                "mitre": "T1041",
                "name": "Data Exfiltration",
                "severity": "CRITICAL",
                "indicators": ["large_outbound", "unusual_hours"]
            }
        }

    def _get_attack_type(self) -> tuple:
        """Returns attack type and its metadata"""
        attack = random.choice(list(self.attack_types.keys()))
        return attack, self.attack_types[attack]

    def generate_combined_events(self, n: int = 5000, attack_rate: float = 0.18) -> pd.DataFrame:
        """
        Generate realistic SOC events for the last 24 hours.
        
        Args:
            n: Number of events to generate
            attack_rate: Percentage of events that should be attacks (0.0 - 1.0)
        """
        records = []
        start_time = datetime.now() - timedelta(hours=24)
        
        # Track for correlation (port scan detection)
        recent_ips = {}
        
        for i in range(n):
            is_attack = random.random() < attack_rate
            
            # Time distribution - more attacks at night
            timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
            hour = timestamp.hour
            
            # Higher attack chance during off-hours (8pm - 6am)
            if hour < 6 or hour > 20:
                is_attack = is_attack or (random.random() < 0.25)
            
            if is_attack:
                attack_type, attack_meta = self._get_attack_type()
                
                # Select malicious IP for attack
                ip = random.choice(self.ips_malicious)
                user = random.choice(["admin", "root", "service_account", "unknown"])
                country = random.choice(["RU", "CN", "KP", "IR", "SY"])
                
                # Attack-specific values
                if attack_type == "brute_force":
                    login_failures = random.randint(15, 50)
                    unique_ips = random.randint(1, 3)
                    request_rate = random.randint(10, 100)
                    error_rate = random.uniform(0.8, 0.99)
                    status_code = random.choice([401, 403, 404, 500])
                    
                elif attack_type == "sql_injection":
                    login_failures = random.randint(0, 5)
                    unique_ips = 1
                    request_rate = random.randint(50, 200)
                    error_rate = random.uniform(0.3, 0.7)
                    status_code = random.choice([500, 502, 503])
                    
                elif attack_type == "xss":
                    login_failures = random.randint(0, 3)
                    unique_ips = 1
                    request_rate = random.randint(20, 80)
                    error_rate = random.uniform(0.1, 0.4)
                    status_code = random.choice([200, 400, 403])
                    
                elif attack_type == "port_scan":
                    login_failures = 0
                    unique_ips = 1
                    request_rate = random.randint(100, 500)
                    error_rate = random.uniform(0.9, 0.99)
                    status_code = random.choice([401, 403, 404, 503])
                    
                elif attack_type == "credential_stuffing":
                    login_failures = random.randint(30, 100)
                    unique_ips = random.randint(10, 50)
                    request_rate = random.randint(200, 500)
                    error_rate = random.uniform(0.9, 0.99)
                    status_code = random.choice([401, 403])
                    
                elif attack_type == "malware_c2":
                    login_failures = random.randint(0, 2)
                    unique_ips = 1
                    request_rate = random.randint(5, 30)  # Beaconing pattern
                    error_rate = random.uniform(0, 0.1)
                    status_code = random.choice([200, 404, 403])
                    
                elif attack_type == "ddos":
                    login_failures = 0
                    unique_ips = random.randint(1, 10)
                    request_rate = random.randint(1000, 5000)
                    error_rate = random.uniform(0.5, 0.9)
                    status_code = random.choice([429, 503, 504])
                    
                elif attack_type == "lateral_movement":
                    login_failures = random.randint(5, 20)
                    unique_ips = random.randint(3, 10)
                    request_rate = random.randint(50, 200)
                    error_rate = random.uniform(0.2, 0.5)
                    status_code = random.choice([200, 401, 403])
                    
                elif attack_type == "data_exfiltration":
                    login_failures = random.randint(0, 3)
                    unique_ips = 1
                    request_rate = random.randint(10, 50)
                    error_rate = random.uniform(0, 0.1)
                    status_code = random.choice([200, 201])
                    
            else:
                # Normal traffic
                attack_type = "normal"
                attack_meta = {"mitre": "N/A", "name": "Normal", "severity": "LOW", "indicators": []}
                
                ip = random.choice(self.ips_internal + self.ips_external)
                user = random.choice(self.users)
                country = "US"
                
                login_failures = random.randint(0, 2)
                unique_ips = random.randint(1, 2)
                request_rate = random.randint(1, 30)
                error_rate = random.uniform(0, 0.05)
                status_code = random.choice([200, 200, 200, 201, 301, 400])
            
            # Common fields
            is_business_hours = 9 <= hour < 17
            
            record = {
                # Core identification
                "timestamp": timestamp,
                "event_id": f"EVT_{i:06d}",
                
                # User info
                "user": user,
                "user_agent": random.choice(self.user_agents_normal) if attack_type == "normal" 
                             else random.choice(self.user_agents_suspicious),
                
                # Network info
                "ip_address": ip,
                "src_ip": ip,
                "dst_ip": random.choice(self.ips_internal),
                "port": random.choice([80, 443, 22, 3306, 8080, 53]),
                "protocol": random.choice(["TCP", "HTTP", "HTTPS", "DNS"]),
                "country": country,
                
                # Request info
                "endpoint": random.choice(self.endpoints),
                "status_code": status_code,
                "request_method": random.choice(["GET", "POST", "PUT", "DELETE"]),
                
                # Behavioral metrics
                "login_failure_count": login_failures,
                "login_success_count": random.randint(0, 20) if attack_type == "normal" else 0,
                "unique_ips": unique_ips,
                "request_rate": request_rate,
                "avg_response_time": np.random.exponential(50) if attack_type == "normal" else np.random.exponential(300),
                "error_rate": error_rate,
                "bytes_sent": random.randint(1000, 10000) if attack_type == "normal" else random.randint(50000, 500000),
                "bytes_received": random.randint(500, 5000),
                
                # Geographic
                "geo_countries_accessed": random.randint(1, 2) if attack_type == "normal" else random.randint(3, 8),
                
                # Time context
                "hour_of_day": hour,
                "is_business_hours": 1 if is_business_hours else 0,
                "day_of_week": timestamp.weekday(),
                "is_weekend": 1 if timestamp.weekday() >= 5 else 0,
                
                # Attack metadata
                "attack_type": attack_type,
                "attack_severity": attack_meta["severity"],
                "mitre_id": attack_meta["mitre"],
                "mitre_name": attack_meta["name"],
                "threat_indicators": ",".join(attack_meta["indicators"]) if attack_meta["indicators"] else "none",
                
                # Label
                "is_anomaly": 1 if is_attack else 0
            }
            
            records.append(record)

        df = pd.DataFrame(records)
        
        # Sort by timestamp
        df = df.sort_values("timestamp").reset_index(drop=True)
        
        # Add sequence number
        df["event_sequence"] = range(len(df))
        
        return df

    def generate_auth_logs(self, n: int = 1000, anomaly_rate: float = 0.15) -> pd.DataFrame:
        """Generate authentication logs with attack patterns"""
        records = []
        start_time = datetime.now() - timedelta(hours=24)

        for i in range(n):
            is_attack = random.random() < anomaly_rate
            timestamp = start_time + timedelta(seconds=random.randint(0, 86400))

            if is_attack:
                attack_type, attack_meta = self._get_attack_type()
                
                if attack_type == "brute_force":
                    user = random.choice(["admin", "root"])
                    ip = random.choice(self.ips_malicious)
                    status = "FAILURE"
                    country = random.choice(["RU", "CN", "KP"])
                    
                elif attack_type == "credential_stuffing":
                    user = random.choice(self.users)
                    ip = random.choice(self.ips_malicious)
                    status = "FAILURE"
                    country = random.choice(["RU", "CN"])
                    
                else:
                    user = random.choice(self.users)
                    ip = random.choice(self.ips_malicious)
                    status = "FAILURE"
                    country = random.choice(self.countries)
            else:
                user = random.choice(self.users)
                ip = random.choice(self.ips_internal + self.ips_external)
                status = "SUCCESS" if random.random() < 0.95 else "FAILURE"
                country = "US"

            records.append({
                "timestamp": timestamp,
                "event_id": f"AUTH_{i:06d}",
                "user": user,
                "ip_address": ip,
                "country": country,
                "status": status,
                "endpoint": random.choice(["/login", "/api/auth", "/admin"]),
                "user_agent": random.choice(self.user_agents_normal),
                "response_time_ms": np.random.exponential(50) if not is_attack else np.random.exponential(300),
                "attack_type": attack_type if is_attack else "normal",
                "is_anomaly": 1 if is_attack else 0
            })

        df = pd.DataFrame(records)
        return df.sort_values("timestamp").reset_index(drop=True)

    def generate_network_logs(self, n: int = 3000, attack_rate: float = 0.12) -> pd.DataFrame:
        """Generate network logs with attack patterns"""
        records = []
        start_time = datetime.now() - timedelta(hours=24)

        for i in range(n):
            is_attack = random.random() < attack_rate
            timestamp = start_time + timedelta(seconds=random.randint(0, 86400))

            if is_attack:
                attack_type, attack_meta = self._get_attack_type()
                
                if attack_type == "port_scan":
                    src_ip = random.choice(self.ips_malicious)
                    dst_ip = "10.0.0.5"
                    bytes_sent = random.randint(1000, 5000)
                    requests_count = random.randint(100, 500)
                    status_code = random.choice([401, 403, 404])
                    
                elif attack_type == "ddos":
                    src_ip = random.choice(self.ips_malicious)
                    dst_ip = "10.0.0.5"
                    bytes_sent = random.randint(100000, 1000000)
                    requests_count = random.randint(5000, 20000)
                    status_code = random.choice([429, 503])
                    
                elif attack_type == "malware_c2":
                    src_ip = random.choice(self.ips_malicious)
                    dst_ip = random.choice(self.ips_internal)
                    bytes_sent = random.randint(100, 1000)
                    requests_count = random.randint(5, 20)
                    status_code = random.choice([200, 404])
                    
                else:
                    src_ip = random.choice(self.ips_malicious)
                    dst_ip = random.choice(self.ips_internal)
                    bytes_sent = random.randint(5000, 50000)
                    requests_count = random.randint(50, 200)
                    status_code = random.choice([401, 403, 404])
            else:
                src_ip = random.choice(self.ips_internal)
                dst_ip = random.choice(self.ips_internal)
                bytes_sent = random.randint(100, 5000)
                requests_count = random.randint(1, 20)
                status_code = random.choice([200, 200, 200, 201, 301])

            records.append({
                "timestamp": timestamp,
                "event_id": f"NET_{i:06d}",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 3306, 8080]),
                "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"]),
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_sent // 2,
                "requests_count": requests_count,
                "status_code": status_code,
                "latency_ms": np.random.exponential(30) if not is_attack else np.random.exponential(200),
                "attack_type": attack_type if is_attack else "normal",
                "is_anomaly": 1 if is_attack else 0
            })

        df = pd.DataFrame(records)
        return df.sort_values("timestamp").reset_index(drop=True)

    def stream_events(self, interval_seconds: float = 1.0) -> Generator[Dict, None, None]:
        """Generate continuous real-time events"""
        while True:
            is_attack = random.random() < 0.15
            timestamp = datetime.now()
            hour = timestamp.hour
            
            if is_attack:
                attack_type, attack_meta = self._get_attack_type()
                ip = random.choice(self.ips_malicious)
                user = random.choice(["admin", "root", "unknown"])
            else:
                attack_type = "normal"
                ip = random.choice(self.ips_internal)
                user = random.choice(self.users)

            event = {
                "timestamp": timestamp.isoformat(),
                "event_id": hashlib.md5(f"{timestamp}".encode()).hexdigest()[:12].upper(),
                "user": user,
                "ip_address": ip,
                "hour_of_day": hour,
                "is_business_hours": 1 if 9 <= hour < 17 else 0,
                "day_of_week": timestamp.weekday(),
                "login_failure_count": random.randint(15, 50) if is_attack else random.randint(0, 2),
                "login_success_count": random.randint(0, 5),
                "unique_ips": random.randint(8, 20) if is_attack else random.randint(1, 3),
                "request_rate": random.randint(300, 1500) if is_attack else random.randint(5, 40),
                "avg_response_time": random.uniform(300, 800) if is_attack else random.uniform(10, 80),
                "error_rate": random.uniform(0.4, 0.9) if is_attack else random.uniform(0, 0.1),
                "bytes_sent": random.randint(60000, 200000) if is_attack else random.randint(1000, 10000),
                "geo_countries_accessed": random.randint(5, 10) if is_attack else random.randint(1, 2),
                "attack_type": attack_type,
                "is_anomaly": 1 if is_attack else 0
            }

            yield event
            time.sleep(interval_seconds)


def get_simulator() -> SOCDataSimulator:
    return SOCDataSimulator()
