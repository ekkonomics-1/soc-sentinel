# SOC Anomaly Detection & Explainable Alerts - Specification

## Project Overview
- **Project Name**: SOC Sentinel - Anomaly Detection System
- **Type**: Real-time Security Operations Center (SOC) Analytics Platform
- **Core Functionality**: Detect security anomalies from network traffic/auth logs, explain alerts using SHAP, provide actionable insights
- **Target Users**: SOC Analysts, Security Engineers, Blue Team members

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOC SENTINEL ARCHITECTURE                         │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │  Threat      │     │  Auth        │     │  Network     │
    │  Intel Feeds │     │  Logs        │     │  Traffic     │
    │  (APIs)      │     │  (Simulated) │     │  (Simulated) │
    └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
           │                    │                    │
           └──────────┬─────────┴─────────┬──────────┘
                      │                     │
                      ▼                     ▼
           ┌──────────────────────────────────────────┐
           │         DATA INGESTION LAYER            │
           │   (src/ingestion/ threat_client.py)      │
           └──────────────────┬─────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │       FEATURE ENGINEERING LAYER          │
           │   (src/features/ feature_pipeline.py)   │
           │   • Login failure frequency              │
           │   • Request rate anomalies               │
           │   • Geographic velocity                  │
           │   • Time-based patterns                  │
           └──────────────────┬─────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │           ML MODEL LAYER                 │
           │   (src/models/ anomaly_detector.py)       │
           │   • Isolation Forest (unsupervised)      │
           │   • XGBoost (supervised)                 │
           └──────────────────┬─────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │        EXPLAINABILITY LAYER             │
           │   (src/explainability/ explainer.py)     │
           │   • SHAP values per alert                │
           │   • Feature contribution breakdown       │
           │   • Natural language explanations        │
           └──────────────────┬─────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   ALERT        │ │  DASHBOARD     │ │  API/CLI       │
│   SYSTEM       │ │  (Streamlit)   │ │  ENDPOINT      │
│   (src/alerts) │ │  (src/dash)    │ │                │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## Data Sources

### 1. Real Threat Intelligence (APIs)
- **AbuseIPDB**: Real malicious IP addresses
- **AlienVault OTX**: Threat pulses
- **GitHub Security Advisories**: CVE data

### 2. Simulated SOC Data (for demo/training)
- Authentication logs (login success/failure patterns)
- Network traffic (request rates, byte counts)
- User behavior (hourly activity patterns)

---

## Features

### Feature Categories

1. **Authentication Features**
   - `login_failure_count`: Failed logins in time window
   - `login_success_count`: Successful logins
   - `unique_ips`: Unique IP addresses used
   - `geo_velocity`: Geographic distance traveled

2. **Network Features**
   - `request_rate`: Requests per minute
   - `avg_response_time`: Average response latency
   - `error_rate`: Percentage of 4xx/5xx responses
   - `bytes_sent`: Total bytes outbound

3. **Temporal Features**
   - `hour_of_day`: Time-based patterns
   - `is_business_hours`: 9-5 indicator
   - `day_of_week`: Day pattern
   - `is_weekend`: Weekend indicator

---

## ML Models

### Model 1: Isolation Forest (Unsupervised)
- Purpose: Detect outliers/anomalies without labeled data
- Use case: Novel attack detection

### Model 2: XGBoost (Supervised)
- Purpose: Classify known attack patterns
- Use case: Brute force, privilege escalation detection

---

## Explainability (SHAP)

Each alert includes:
- **SHAP Force Plot**: Visual feature contribution
- **Top Contributing Features**: What triggered the alert
- **Natural Language Explanation**: "This alert fired because..."

---

## Dashboard (Streamlit)

Pages:
1. **Overview**: Key metrics, recent alerts
2. **Live Monitor**: Real-time anomaly detection
3. **Investigation**: Drill into specific alerts with SHAP explanations
4. **Model Performance**: Precision/recall, feature importance

---

## Alert Severity Levels

| Severity | Threshold | Action |
|----------|-----------|--------|
| CRITICAL | Anomaly score > 0.95 | Immediate response |
| HIGH | Anomaly score > 0.85 | Investigate within 1 hour |
| MEDIUM | Anomaly score > 0.70 | Review daily |
| LOW | Anomaly score > 0.50 | Log for pattern analysis |

---

## API Endpoints (FastAPI)

- `POST /analyze` - Analyze a single event
- `GET /alerts` - List recent alerts
- `GET /alerts/{id}/explain` - Get SHAP explanation
- `GET /health` - Health check

---

## Deployment

- **Local**: Docker Compose (Streamlit + Redis + API)
- **Cloud**: AWS Lambda + DynamoDB + CloudWatch
- **Demo**: Streamlit Cloud (free hosting)

---

## Success Metrics

- Detect brute force attacks with >90% precision
- Provide explanations for 100% of alerts
- Dashboard loads in <2 seconds
- Zero false positives on normal traffic (after tuning)

---

## Portfolio Highlights

This project demonstrates:
1. **Security Domain Knowledge**: Understanding SOC workflows
2. **ML Engineering**: Model training, evaluation, deployment
3. **Explainable AI**: SHAP, interpretability
4. **Full-Stack Development**: API, Dashboard, Ingestion
5. **Real Data Integration**: Threat intel APIsDocumentation**: Architecture, README, deployment guides
6. **
