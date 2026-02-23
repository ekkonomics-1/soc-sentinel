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

        self.users = [
            "john.smith", "sarah.jones", "mike.wilson", "emma.davis",
            "alex.brown", "lisa.taylor", "david.lee", "jennifer.white",
            "chris.garcia", "maria.martinez", "admin", "root", "service_account"
        ]

        self.ips_internal = [
            "10.0.1.10", "10.0.1.15", "10.0.1.20", "10.0.2.5",
            "10.0.2.10", "10.0.3.50", "192.168.1.100", "192.168.1.105"
        ]

        self.ips_external = [
            "8.8.8.8", "1.1.1.1", "142.250.185.46", "151.101.1.140",
            "104.16.249.249", "13.107.42.14", "52.84.223.111"
        ]

        self.countries = ["US", "CA", "GB", "DE", "FR", "JP", "AU", "BR"]
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0",
            "python-requests/2.31.0",
            "curl/7.81.0"
        ]

        self.endpoints = [
            "/api/v1/login", "/api/v1/users", "/api/v1/orders",
            "/api/v1/products", "/api/v1/search", "/api/v1/profile",
            "/api/v1/admin", "/api/v1/reports", "/api/v1/export"
        ]

    def generate_auth_logs(self, n: int = 1000, anomaly_rate: float = 0.05) -> pd.DataFrame:
        records = []
        start_time = datetime.now() - timedelta(hours=24)

        for i in range(n):
            is_anomaly = random.random() < anomaly_rate
            timestamp = start_time + timedelta(seconds=i * 86)

            if is_anomaly:
                user = random.choice(["admin", "root", "service_account"])
                ip = random.choice(self.ips_external)
                country = random.choice(self.countries[:4])
                status = "FAILURE"
                if random.random() < 0.7:
                    status = "SUCCESS"
            else:
                user = random.choice(self.users[:-3])
                ip = random.choice(self.ips_internal)
                country = "US"
                status = "SUCCESS" if random.random() < 0.95 else "FAILURE"

            records.append({
                "timestamp": timestamp,
                "event_id": f"AUTH_{i:06d}",
                "user": user,
                "ip_address": ip,
                "country": country,
                "status": status,
                "endpoint": random.choice(self.endpoints),
                "user_agent": random.choice(self.user_agents),
                "response_time_ms": np.random.exponential(50) if not is_anomaly else np.random.exponential(500),
                "is_anomaly": 1 if is_anomaly else 0
            })

        df = pd.DataFrame(records)
        df = df.sort_values("timestamp").reset_index(drop=True)
        return df

    def generate_network_logs(self, n: int = 5000, attack_rate: float = 0.03) -> pd.DataFrame:
        records = []
        start_time = datetime.now() - timedelta(hours=24)

        for i in range(n):
            is_attack = random.random() < attack_rate
            timestamp = start_time + timedelta(seconds=i * 17)

            if is_attack:
                src_ip = random.choice(self.ips_external)
                dst_ip = "10.0.0.5"
                bytes_sent = random.randint(10000, 50000)
                requests_count = random.randint(500, 2000)
                status_code = random.choice([401, 403, 404, 500])
            else:
                src_ip = random.choice(self.ips_internal)
                dst_ip = random.choice(["10.0.0.5", "10.0.0.10", "10.0.0.15"])
                bytes_sent = random.randint(100, 5000)
                requests_count = random.randint(1, 20)
                status_code = random.choice([200, 200, 200, 201, 301, 400, 404])

            records.append({
                "timestamp": timestamp,
                "event_id": f"NET_{i:06d}",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 3306, 8080]),
                "protocol": random.choice(["TCP", "UDP", "HTTP"]),
                "bytes_sent": bytes_sent,
                "bytes_received": bytes_sent // 2,
                "requests_count": requests_count,
                "status_code": status_code,
                "latency_ms": np.random.exponential(30) if not is_attack else np.random.exponential(200),
                "is_anomaly": 1 if is_attack else 0
            })

        df = pd.DataFrame(records)
        df = df.sort_values("timestamp").reset_index(drop=True)
        return df

    def generate_user_behavior(self, n: int = 500) -> pd.DataFrame:
        records = []
        start_date = datetime.now() - timedelta(days=30)

        for user in self.users:
            for day in range(30):
                date = start_date + timedelta(days=day)
                is_weekend = date.weekday() >= 5
                business_hours = random.random() < (0.3 if is_weekend else 0.7)

                if business_hours:
                    login_count = random.randint(5, 30)
                    unique_ips = random.randint(1, 3)
                else:
                    login_count = random.randint(0, 5)
                    unique_ips = random.randint(1, 2)

                records.append({
                    "date": date,
                    "user": user,
                    "login_count": login_count,
                    "failed_logins": random.randint(0, max(1, login_count // 5)),
                    "unique_ips": unique_ips,
                    "countries_accessed": random.randint(1, 2),
                    "total_requests": random.randint(100, 5000),
                    "after_hours_activity": 0 if business_hours else 1,
                    "is_weekend": 1 if is_weekend else 0
                })

        df = pd.DataFrame(records)
        return df

    def generate_combined_events(self, n: int = 2000) -> pd.DataFrame:
        records = []
        start_time = datetime.now() - timedelta(hours=24)

        for i in range(n):
            is_anomaly = random.random() < 0.05
            timestamp = start_time + timedelta(seconds=i * 43)

            user = random.choice(self.users)
            hour = timestamp.hour
            is_business_hours = 9 <= hour < 17

            if is_anomaly:
                login_failures = random.randint(10, 50)
                unique_ips = random.randint(5, 15)
                request_rate = random.randint(200, 1000)
                countries = random.randint(3, 8)
            else:
                login_failures = random.randint(0, 3)
                unique_ips = random.randint(1, 3)
                request_rate = random.randint(5, 50)
                countries = random.randint(1, 2)

            records.append({
                "timestamp": timestamp,
                "event_id": f"EVENT_{i:06d}",
                "user": user,
                "hour_of_day": hour,
                "is_business_hours": 1 if is_business_hours else 0,
                "day_of_week": timestamp.weekday(),
                "is_weekend": 1 if timestamp.weekday() >= 5 else 0,
                "login_failure_count": login_failures,
                "login_success_count": random.randint(0, 20),
                "unique_ips": unique_ips,
                "request_rate": request_rate,
                "avg_response_time": np.random.exponential(50) if not is_anomaly else np.random.exponential(500),
                "error_rate": random.uniform(0, 0.1) if not is_anomaly else random.uniform(0.3, 0.8),
                "bytes_sent": random.randint(1000, 50000) if not is_anomaly else random.randint(50000, 200000),
                "geo_countries_accessed": countries,
                "country": random.choice(self.countries),
                "is_anomaly": 1 if is_anomaly else 0
            })

        df = pd.DataFrame(records)
        return df

    def stream_events(self, interval_seconds: float = 1.0) -> Generator[Dict, None, None]:
        while True:
            is_anomaly = random.random() < 0.08
            timestamp = datetime.now()
            hour = timestamp.hour

            event = {
                "timestamp": timestamp.isoformat(),
                "event_id": hashlib.md5(f"{timestamp}".encode()).hexdigest()[:12].upper(),
                "user": random.choice(self.users),
                "ip_address": random.choice(self.ips_external if is_anomaly else self.ips_internal),
                "hour_of_day": hour,
                "is_business_hours": 1 if 9 <= hour < 17 else 0,
                "day_of_week": timestamp.weekday(),
                "login_failure_count": random.randint(15, 50) if is_anomaly else random.randint(0, 2),
                "login_success_count": random.randint(0, 5),
                "unique_ips": random.randint(8, 20) if is_anomaly else random.randint(1, 3),
                "request_rate": random.randint(300, 1500) if is_anomaly else random.randint(5, 40),
                "avg_response_time": random.uniform(300, 800) if is_anomaly else random.uniform(10, 80),
                "error_rate": random.uniform(0.4, 0.9) if is_anomaly else random.uniform(0, 0.1),
                "bytes_sent": random.randint(60000, 200000) if is_anomaly else random.randint(1000, 10000),
                "geo_countries_accessed": random.randint(5, 10) if is_anomaly else random.randint(1, 2),
                "is_anomaly": 1 if is_anomaly else 0
            }

            yield event
            time.sleep(interval_seconds)


def get_simulator() -> SOCDataSimulator:
    return SOCDataSimulator()
