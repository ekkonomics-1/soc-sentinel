# SOC Anomaly Detection & Explainable Alerts - Specification

## Project Overview
- **Project Name**: SOC Sentinel - Anomaly Detection System
- **Type**: Real-time Security Operations Center (SOC) Analytics Platform
- **Core Functionality**: Detect security anomalies from network traffic/auth logs, explain alerts using SHAP, provide actionable insights
- **Target Users**: SOC Analysts, Security Engineers, Blue Team members
- **Tech Stack**: Flask (Backend) + HTML/JS (Frontend) + Plotly (Charts)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SOC SENTINEL ARCHITECTURE                         │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │  Threat      │     │  Auth        │     │  Network     │
    │  Intel Feeds │     │  Logs        │     │  Traffic     │
    │  (VirusTotal)│     │  (Simulated)│     │  (Simulated) │
    └──────┬───────┘     └──────┬───────┘     └──────┬───────┘
           │                    │                    │
           └──────────┬─────────┴─────────┬──────────┘
                      │                     │
                      ▼                     ▼
           ┌──────────────────────────────────────────┐
           │         DATA INGESTION LAYER            │
           │   (src/ingestion/)                       │
           │   • threat_client.py (VirusTotal API)   │
           │   • data_simulator.py (SOC data gen)    │
           └──────────────────┬─────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │       FEATURE ENGINEERING LAYER          │
           │   (src/features/ feature_pipeline.py)   │
           │   • Login failure frequency              │
           │   • Request rate anomalies               │
           │   • Geographic velocity                   │
           │   • Time-based patterns                  │
           └──────────────────┬─────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │           ML MODEL LAYER                 │
           │   (src/models/ anomaly_detector.py)     │
           │   • Isolation Forest (unsupervised)      │
           │   • Random Forest (supervised)           │
           └──────────────────┬─────────────────────┘
                              │
                              ▼
           ┌──────────────────────────────────────────┐
           │        EXPLAINABILITY LAYER             │
           │   (src/explainability/ explainer.py)   │
           │   • SHAP values per alert               │
           │   • Feature contribution breakdown       │
           │   • Natural language explanations       │
           └──────────────────┬─────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   ALERT        │ │  FLASK API     │ │   FRONTEND     │
│   SYSTEM       │ │  (app.py)      │ │   (static/)    │
│   (src/alerts) │ │  REST API      │ │   HTML/JS      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

---

## Technology Stack

### Backend
- **Flask**: Python web framework
- **Flask-CORS**: Cross-origin support
- **Scikit-learn**: ML models (Isolation Forest, Random Forest)
- **SHAP**: Explainable AI

### Frontend
- **HTML5/CSS3**: Modern dark-themed UI
- **JavaScript (Vanilla)**: Interactive dashboard
- **Plotly.js**: Interactive charts

### APIs
- **VirusTotal**: Threat intelligence enrichment

---

## Data Sources

### 1. Real Threat Intelligence (APIs)
- **VirusTotal**: Real malicious IP detection with 70+ security vendors
- Provides: abuse confidence score, country, ISP, total reports

### 2. Simulated SOC Data (for demo/training)
- Authentication logs (login success/failure patterns)
- Network traffic (request rates, byte counts)
- User behavior (hourly activity patterns)
- Attack types: brute force, SQL injection, XSS, port scan, credential stuffing, malware C2, DDoS, lateral movement, data exfiltration

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
- Parameters: contamination=0.05, n_estimators=200

### Model 2: Random Forest (Supervised)
- Purpose: Classify known attack patterns
- Use case: Brute force, privilege escalation detection

---

## Explainability (SHAP)

Each alert includes:
- **Waterfall Data**: Feature contribution breakdown
- **Global Importance**: Which features matter most across all data
- **Force Plot Data**: Visual feature contribution

---

## Dashboard Pages (Flask + HTML/JS)

1. **Overview**: Key metrics, severity distribution, hourly chart, recent alerts
2. **Detected Threats**: Table of all anomalies with severity, user, IP, score
3. **Investigate**: Deep dive into specific threats with SHAP explanations
4. **Detection Rules**: Sigma-style rules mapped to MITRE ATT&CK
5. **SHAP Analysis**: Feature importance visualization
6. **Threat Intel**: IP lookup with VirusTotal enrichment (real API data)
7. **Alerts**: Alert management with status tracking
8. **Timeline**: Chronological view of security events
9. **Statistics**: Attack type distribution, top users, geographic distribution

---

## API Endpoints (Flask)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serve frontend |
| `/api/detect` | POST | Run anomaly detection |
| `/api/alerts` | GET | List alerts with filters |
| `/api/alerts/<id>` | PUT | Update alert status |
| `/api/explain/<index>` | GET | Get SHAP explanation |
| `/api/threat-intel/<ip>` | GET | VirusTotal IP lookup |
| `/api/statistics` | GET | Analytics data |
| `/api/detection-rules` | GET | Sigma rules list |
| `/api/config` | POST | Configure API keys |
| `/api/health` | GET | Health check |

---

## Alert Severity Levels

| Severity | Threshold | Action |
|----------|-----------|--------|
| CRITICAL | Anomaly score > 0.95 | Immediate response |
| HIGH | Anomaly score > 0.85 | Investigate within 1 hour |
| MEDIUM | Anomaly score > 0.70 | Review daily |
| LOW | Anomaly score > 0.50 | Log for pattern analysis |

---

## Detection Rules (MITRE ATT&CK)

| Rule ID | Title | Severity | MITRE |
|---------|-------|----------|-------|
| SOC-001 | Brute Force Attack Detection | HIGH | T1110 |
| SOC-002 | Suspicious IP Spread | HIGH | T1078 |
| SOC-003 | High Request Rate | MEDIUM | T1498 |
| SOC-004 | Data Exfiltration | CRITICAL | T1041 |
| SOC-005 | After Hours Activity | MEDIUM | T1078 |
| SOC-006 | Geographic Anomaly | HIGH | T1078 |
| SOC-007 | High Error Rate | MEDIUM | T1494 |
| SOC-008 | Slow Response Attack | LOW | T1499 |

---

## Deployment

### Local Development
```bash
pip install -r requirements.txt
python app.py
```
Access: http://localhost:5000

### Requirements
- Python 3.11+
- Flask 3.0+
- Flask-CORS
- scikit-learn
- SHAP
- Plotly

---

## Success Metrics

- Detect brute force attacks with >90% precision
- Provide explanations for 100% of alerts
- Dashboard loads in <2 seconds
- Zero false positives on normal traffic (after tuning)

---

## Portfolio Highlights

This project demonstrates:
1. **Security Domain Knowledge**: Understanding SOC workflows, MITRE ATT&CK
2. **ML Engineering**: Model training, evaluation, deployment
3. **Explainable AI**: SHAP, interpretability
4. **Full-Stack Development**: Flask API, HTML/JS Dashboard
5. **Real Data Integration**: VirusTotal API integration
6. **Modern UI/UX**: Dark theme, interactive charts, responsive design

---

## File Structure

```
soc-anomaly-detector/
├── app.py                    # Flask API backend
├── requirements.txt          # Python dependencies
├── SPEC.md                  # This specification
├── README.md                # Project documentation
├── static/
│   └── index.html           # Frontend dashboard
└── src/
    ├── ingestion/
    │   ├── data_simulator.py    # SOC data generator
    │   └── threat_client.py     # VirusTotal API client
    ├── features/
    │   └── feature_pipeline.py   # Feature engineering
    ├── models/
    │   └── anomaly_detector.py  # ML models
    ├── explainability/
    │   └── explainer.py          # SHAP explanations
    └── alerts/
        └── alert_manager.py      # Alert management
```
