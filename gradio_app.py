import gradio as gr
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import json
import base64
from datetime import datetime
from io import StringIO
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.ingestion.data_simulator import get_simulator
from src.features.feature_pipeline import get_feature_pipeline
from src.models.anomaly_detector import get_anomaly_detector
from src.explainability.explainer import get_explainer


FEATURE_COLUMNS = [
    "login_failure_count", "login_success_count", "unique_ips",
    "request_rate", "avg_response_time", "error_rate", "bytes_sent",
    "hour_of_day", "is_business_hours", "day_of_week", "is_weekend",
    "geo_countries_accessed"
]

FEATURE_LABELS = {
    "login_failure_count": "Login Failures",
    "login_success_count": "Successful Logins",
    "unique_ips": "Unique IP Addresses",
    "request_rate": "Request Rate",
    "avg_response_time": "Response Time",
    "error_rate": "Error Rate",
    "bytes_sent": "Data Transferred",
    "hour_of_day": "Hour of Day",
    "is_business_hours": "Business Hours",
    "day_of_week": "Day of Week",
    "is_weekend": "Weekend Activity",
    "geo_countries_accessed": "Countries Accessed"
}

simulator = get_simulator()
feature_pipeline = get_feature_pipeline()
detector = get_anomaly_detector(contamination=0.05)
explainer = get_explainer()

global_state = {
    "events_df": None,
    "results": [],
    "X_scaled": None,
    "available_features": [],
    "shap_initialized": False
}


def run_detection(n_events, contamination):
    global global_state
    
    events_df = simulator.generate_combined_events(n=int(n_events))
    global_state["events_df"] = events_df
    
    available_features = [col for col in FEATURE_COLUMNS if col in events_df.columns]
    
    if not available_features:
        return "No features found", None, None, None
    
    X = events_df[available_features].values.astype(float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    global_state["X_scaled"] = X_scaled
    global_state["available_features"] = available_features
    
    detector.contamination = float(contamination) / 100
    detector.fit(X_scaled, available_features)
    results = detector.detect(X_scaled)
    
    global_state["results"] = results
    
    if not global_state["shap_initialized"]:
        explainer.initialize(X_scaled, available_features, detector.isolation_forest)
        global_state["shap_initialized"] = True
    
    return f"Detection complete! Analyzed {len(events_df)} events, found {sum(1 for r in results if r['is_anomaly'])} anomalies.", events_df, results, X_scaled


def get_overview_tab(n_events, contamination):
    msg, df, results, _ = run_detection(n_events, contamination)
    
    if df is None or not results:
        return msg, None, None, None, None, None
    
    detected_anomalies = [(i, r) for i, r in enumerate(results) if r['is_anomaly']]
    anomaly_count = len(detected_anomalies)
    critical = sum(1 for r in results if r.get('severity') == 'CRITICAL')
    high = sum(1 for r in results if r.get('severity') == 'HIGH')
    medium = sum(1 for r in results if r.get('severity') == 'MEDIUM')
    
    df_anomalies = df.iloc[[x[0] for x in detected_anomalies]]
    
    severity_chart = go.Figure(go.Bar(
        x=['Critical', 'High', 'Medium', 'Low'],
        y=[critical, high, medium, anomaly_count - critical - high - medium],
        marker_color=['#f85149', '#d29922', '#58a6ff', '#3fb950']
    ))
    severity_chart.update_layout(
        title="Anomalies by Severity",
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': '#c9d1d9'},
        height=300
    )
    
    if 'hour_of_day' in df.columns:
        hourly = df.groupby('hour_of_day').size().reset_index(name='count')
        activity_chart = px.line(hourly, x='hour_of_day', y='count', title="Events by Hour")
        activity_chart.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': '#c9d1d9'},
            height=300
        )
    else:
        activity_chart = None
    
    if 'country' in df.columns:
        country_counts = df['country'].value_counts().head(10)
        geo_chart = px.bar(x=country_counts.values, y=country_counts.index, orientation='h', title="Top Countries")
        geo_chart.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': '#c9d1d9'},
            height=300
        )
    else:
        geo_chart = None
    
    summary = f"""## Security Overview

**Total Events Analyzed:** {len(df):,}
**Anomalies Detected:** {anomaly_count}

| Severity | Count |
|----------|-------|
| 🔴 Critical | {critical} |
| 🟠 High | {high} |
| 🔵 Medium | {medium} |
| 🟢 Low | {anomaly_count - critical - high - medium} |

*Detection completed successfully using Isolation Forest with contamination rate: {contamination}%*"""
    
    return summary, severity_chart, activity_chart, geo_chart, df_anomalies, detected_anomalies


def get_anomalies_tab():
    global global_state
    df = global_state.get("events_df")
    results = global_state.get("results", [])
    
    if df is None or not results:
        return "Run detection first", None, None
    
    detected_anomalies = [(i, r) for i, r in enumerate(results) if r['is_anomaly']]
    
    if not detected_anomalies:
        return "No anomalies detected", None, None
    
    anomaly_data = []
    for orig_idx, r in detected_anomalies[:20]:
        row = df.iloc[orig_idx]
        anomaly_data.append({
            "User": row.get('user', 'Unknown'),
            "IP": row.get('ip_address', 'N/A'),
            "Country": row.get('country', 'Unknown'),
            "Score": round(r['anomaly_score'], 3),
            "Severity": r.get('severity', 'MEDIUM'),
            "Failures": row.get('login_failure_count', 0),
            "Request Rate": row.get('request_rate', 0)
        })
    
    df_anomalies = pd.DataFrame(anomaly_data)
    
    chart = px.scatter(
        df_anomalies, x='Score', y='Request Rate', 
        color='Severity', size='Failures',
        color_discrete_map={'CRITICAL': '#f85149', 'HIGH': '#d29922', 'MEDIUM': '#58a6ff', 'LOW': '#3fb950'},
        title="Anomaly Score vs Request Rate"
    )
    chart.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': '#c9d1d9'},
        height=400
    )
    
    summary = f"## Detected Anomalies\n\nFound **{len(detected_anomalies)}** suspicious activities. Showing top 20:"
    
    return summary, df_anomalies, chart


def get_shap_tab():
    global global_state
    
    if not global_state["shap_initialized"] or global_state["X_scaled"] is None:
        return "Run detection first to enable SHAP analysis", None, None
    
    try:
        global_imp = explainer.get_global_importance(
            global_state["X_scaled"], global_state["available_features"]
        )
        ranked = global_imp.get("ranked_features", [])[:10]
        
        fig = go.Figure(go.Bar(
            x=[v for k, v in ranked],
            y=[FEATURE_LABELS.get(k, k) for k, v in ranked],
            orientation='h',
            marker=dict(color='#58a6ff')
        ))
        fig.update_layout(
            title="SHAP Feature Importance",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': '#c9d1d9'},
            height=400
        )
        
        top_features = "\n".join([f"{i+1}. **{FEATURE_LABELS.get(k, k)}**: {v:.3f}" for i, (k, v) in enumerate(ranked[:5])])
        
        summary = f"""## SHAP Explainability

Top contributing features to anomaly detection:

{top_features}

**Total explanation:** The Isolation Forest model uses these features to identify unusual behavior patterns.
"""
        
        return summary, fig, ranked
    except Exception as e:
        return f"Error: {str(e)}", None, None


def get_demo_tab():
    scenarios = {
        "Brute Force Attack": {
            "description": "Attacker tries many passwords to guess correct credentials",
            "steps": [
                {"title": "Reconnaissance", "content": "Attacker scans for valid usernames"},
                {"title": "Password Spraying", "content": "Common passwords tried across accounts"},
                {"title": "Detection Trigger", "content": "High login_failure_count triggers alert"},
                {"title": "SHAP Explanation", "content": "login_failure_count is top feature"}
            ]
        },
        "Credential Stuffing": {
            "description": "Using stolen credentials from other breaches",
            "steps": [
                {"title": "Credential Match", "content": "Stolen credentials tried on your system"},
                {"title": "Multiple IPs", "content": "Same user logging from different IPs"},
                {"title": "Detection", "content": "unique_ips feature flags anomaly"},
                {"title": "Investigation", "content": "Check if credentials were reused"}
            ]
        },
        "Data Exfiltration": {
            "description": "Unauthorized data transfer out of the network",
            "steps": [
                {"title": "Baseline", "content": "System learns normal data transfer patterns"},
                {"title": "Anomaly", "content": "Large bytes_sent outside business hours"},
                {"title": "Severity", "content": "High anomaly score = critical alert"},
                {"title": "Response", "content": "Block external destination, preserve logs"}
            ]
        }
    }
    
    demo_html = """## 🎯 Interactive Attack Scenario Demo

Select an attack scenario to see how SOC Sentinel detects and responds to it.

### Available Scenarios:

1. **Brute Force Attack** - Password guessing attack
2. **Credential Stuffing** - Stolen credential abuse  
3. **Data Exfiltration** - Unauthorized data transfer

---
"""
    
    return demo_html, scenarios


def get_incident_tab():
    global global_state
    results = global_state.get("results", [])
    df = global_state.get("events_df")
    
    if not results:
        return "Run detection first", None
    
    detected_anomalies = [(i, r) for i, r in enumerate(results) if r['is_anomaly']]
    
    incident_html = """## 🚀 Incident Response

Escalate detected anomalies to incidents with one click.

"""
    
    if detected_anomalies:
        incident_html += f"**{len(detected_anomalies)}** anomalies ready for escalation\n\n"
        incident_html += "### Quick Actions:\n\n"
        incident_html += "- ✅ Select anomalies to escalate\n"
        incident_html += "- 📋 Generate incident report\n"
        incident_html += "- 🔍 Collect forensic evidence\n"
        incident_html += "- 📋 Apply response playbook\n\n"
        incident_html += "---\n\n"
        incident_html += "### Sample Escalated Incidents:\n\n"
        
        for i, (orig_idx, r) in enumerate(detected_anomalies[:3]):
            row = df.iloc[orig_idx]
            incident_html += f"- **{r.get('severity', 'MEDIUM')}**: {row.get('user', 'Unknown')} - {row.get('ip_address', 'N/A')}\n"
    else:
        incident_html += "No anomalies detected yet. Run detection first."
    
    return incident_html, detected_anomalies


def get_portfolio_tab():
    portfolio_html = """## 💼 Portfolio Mode

Demonstrate your SOC skills with this professional dashboard.

### Features Demonstrated:

| Skill | Feature |
|-------|---------|
| **Machine Learning** | Isolation Forest anomaly detection |
| **Explainable AI** | SHAP feature importance |
| **Threat Intel** | VirusTotal integration (configurable) |
| **Incident Response** | Escalation, evidence, playbooks |
| **Security Analysis** | MITRE ATT&CK mapping |
| **DevOps** | Docker-ready deployment |

---

### 🎨 For Your Portfolio:

1. **Screenshots**: Use Overview, SHAP Analysis, and Incident Response tabs
2. **Demo**: Walk through attack scenarios in Demo Mode
3. **Code**: This is all Python - easy to explain and extend

### 🚀 Deployment:

```bash
# Run locally
pip install -r requirements_gradio.txt
python gradio_app.py

# Docker
docker build -t soc-sentinel .
docker run -p 7860:7860 soc-sentinel
```

---
"""
    
    return portfolio_html


def create_app():
    with gr.Blocks(title="SOC Sentinel - Anomaly Detection", theme=gr.themes.Soft()) as app:
        gr.Markdown("""
        <style>
        .header {
            background: linear-gradient(90deg, #1a1a2e 0%, #16213e 100%);
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
        }
        .header h1 { color: #fff; margin: 0; }
        .header p { color: #8b949e; margin: 0; }
        </style>
        <div class="header">
            <h1>🛡️ SOC Sentinel</h1>
            <p>AI-Powered Security Operations Center</p>
        </div>
        """, elem_id="header")
        
        with gr.Row():
            # Left Sidebar - Navigation & Config
            with gr.Column(scale=1, variant="panel"):
                gr.Markdown("### 📍 Navigation")
                
                nav_buttons = []
                
                btn_overview = gr.Button("📊 Overview", size="sm", variant="secondary")
                nav_buttons.append(btn_overview)
                
                btn_anomalies = gr.Button("⚠️ Anomalies", size="sm", variant="secondary")
                nav_buttons.append(btn_anomalies)
                
                btn_shap = gr.Button("🧠 SHAP Analysis", size="sm", variant="secondary")
                nav_buttons.append(btn_shap)
                
                btn_demo = gr.Button("🎯 Demo Mode", size="sm", variant="secondary")
                nav_buttons.append(btn_demo)
                
                btn_incident = gr.Button("🚨 Incident Response", size="sm", variant="secondary")
                nav_buttons.append(btn_incident)
                
                btn_portfolio = gr.Button("💼 Portfolio", size="sm", variant="secondary")
                nav_buttons.append(btn_portfolio)
                
                gr.Markdown("---")
                
                gr.Markdown("### ⚙️ Configuration")
                n_events = gr.Slider(500, 5000, 2000, step=100, label="Events to Analyze")
                contamination = gr.Slider(1, 20, 5, step=1, label="Anomaly Threshold (%)")
                
                run_btn = gr.Button("▶ Run Detection", variant="primary", size="lg")
                
                gr.Markdown("---")
                gr.Markdown("""
                <div style="font-size: 0.75rem; color: #8b949e; text-align: center;">
                    <b>Skills Demonstrated:</b><br>
                    🤖 Machine Learning<br>
                    🔍 Threat Intelligence<br>
                    🚨 Incident Response<br>
                    🐳 DevOps
                </div>
                """)
            
            # Main Content Area
            with gr.Column(scale=4):
                # Overview Section
                with gr.Group(visible=True) as overview_section:
                    gr.Markdown("## 📊 Security Overview")
                    overview_msg = gr.Markdown("Click **Run Detection** to analyze events")
                    with gr.Row():
                        severity_chart = gr.Plot(height=280)
                        activity_chart = gr.Plot(height=280)
                    with gr.Row():
                        geo_chart = gr.Plot(height=280)
                
                # Anomalies Section  
                with gr.Group(visible=False) as anomalies_section:
                    gr.Markdown("## ⚠️ Detected Anomalies")
                    anomaly_msg = gr.Markdown("Run detection first")
                    anomaly_table = gr.DataFrame(height=200)
                    anomaly_chart = gr.Plot(height=350)
                
                # SHAP Section
                with gr.Group(visible=False) as shap_section:
                    gr.Markdown("## 🧠 SHAP Explainability")
                    shap_msg = gr.Markdown("Run detection first")
                    shap_plot = gr.Plot(height=400)
                
                # Demo Section
                with gr.Group(visible=False) as demo_section:
                    gr.Markdown("## 🎯 Interactive Attack Scenarios")
                    scenarios_dropdown = gr.Dropdown(
                        ["Brute Force Attack", "Credential Stuffing", "Data Exfiltration"],
                        label="Select Scenario",
                        value="Brute Force Attack"
                    )
                    step_slider = gr.Slider(0, 3, 0, step=1, label="Demo Step")
                    demo_content = gr.Markdown()
                
                # Incident Response Section
                with gr.Group(visible=False) as incident_section:
                    gr.Markdown("## 🚨 Incident Response")
                    incident_msg = gr.Markdown()
                    incident_table = gr.DataFrame(height=250)
                
                # Portfolio Section
                with gr.Group(visible=False) as portfolio_section:
                    portfolio_msg = gr.Markdown()
        
        # Footer
        gr.Markdown("""
        <div style="text-align: center; padding: 1rem; color: #6e7681; font-size: 0.75rem;">
            SOC Sentinel v2.0 | Built with Gradio + Isolation Forest + SHAP
        </div>
        """)
        
        # Navigation handlers
        def show_overview():
            return {overview_section: gr.update(visible=True),
                    anomalies_section: gr.update(visible=False),
                    shap_section: gr.update(visible=False),
                    demo_section: gr.update(visible=False),
                    incident_section: gr.update(visible=False),
                    portfolio_section: gr.update(visible=False)}
        
        def show_anomalies():
            return {overview_section: gr.update(visible=False),
                    anomalies_section: gr.update(visible=True),
                    shap_section: gr.update(visible=False),
                    demo_section: gr.update(visible=False),
                    incident_section: gr.update(visible=False),
                    portfolio_section: gr.update(visible=False)}
        
        def show_shap():
            return {overview_section: gr.update(visible=False),
                    anomalies_section: gr.update(visible=False),
                    shap_section: gr.update(visible=True),
                    demo_section: gr.update(visible=False),
                    incident_section: gr.update(visible=False),
                    portfolio_section: gr.update(visible=False)}
        
        def show_demo():
            msg, _ = get_demo_tab()
            return {overview_section: gr.update(visible=False),
                    anomalies_section: gr.update(visible=False),
                    shap_section: gr.update(visible=False),
                    demo_section: gr.update(visible=True),
                    incident_section: gr.update(visible=False),
                    portfolio_section: gr.update(visible=False),
                    demo_content: msg}
        
        def show_incident():
            msg, _ = get_incident_tab()
            return {overview_section: gr.update(visible=False),
                    anomalies_section: gr.update(visible=False),
                    shap_section: gr.update(visible=False),
                    demo_section: gr.update(visible=False),
                    incident_section: gr.update(visible=True),
                    portfolio_section: gr.update(visible=False),
                    incident_msg: msg}
        
        def show_portfolio():
            msg = get_portfolio_tab()
            return {overview_section: gr.update(visible=False),
                    anomalies_section: gr.update(visible=False),
                    shap_section: gr.update(visible=False),
                    demo_section: gr.update(visible=False),
                    incident_section: gr.update(visible=False),
                    portfolio_section: gr.update(visible=True),
                    portfolio_msg: msg}
        
        # Bind navigation buttons
        btn_overview.click(show_overview, inputs=[], outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section])
        btn_anomalies.click(show_anomalies, inputs=[], outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section])
        btn_shap.click(show_shap, inputs=[], outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section])
        btn_demo.click(show_demo, inputs=[], outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section, demo_content])
        btn_incident.click(show_incident, inputs=[], outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section, incident_msg])
        btn_portfolio.click(show_portfolio, inputs=[], outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section, portfolio_msg])
        
        # Run detection handler - runs all and shows overview
        def run_all(n, c):
            msg1, fig1, fig2, fig3, _, _ = get_overview_tab(n, c)
            msg2, df2, fig4 = get_anomalies_tab()
            msg3, fig5, _ = get_shap_tab()
            msg4, data5 = get_incident_tab()
            msg5 = get_portfolio_tab()
            return {
                overview_section: gr.update(visible=True),
                anomalies_section: gr.update(visible=False),
                shap_section: gr.update(visible=False),
                demo_section: gr.update(visible=False),
                incident_section: gr.update(visible=False),
                portfolio_section: gr.update(visible=False),
                overview_msg: msg1,
                severity_chart: fig1,
                activity_chart: fig2,
                geo_chart: fig3,
                anomaly_msg: msg2,
                anomaly_table: df2,
                anomaly_chart: fig4,
                shap_msg: msg3,
                shap_plot: fig5,
                incident_msg: msg4,
                incident_table: data5,
                portfolio_msg: msg5
            }
        
        run_btn.click(
            run_all,
            inputs=[n_events, contamination],
            outputs=[overview_section, anomalies_section, shap_section, demo_section, incident_section, portfolio_section,
                    overview_msg, severity_chart, activity_chart, geo_chart,
                    anomaly_msg, anomaly_table, anomaly_chart,
                    shap_msg, shap_plot, incident_msg, incident_table, portfolio_msg]
        )
        
        # Demo mode slider update
        def update_demo(scenario, step):
            scenarios = {
                "Brute Force Attack": {
                    "description": "Attacker tries many passwords to guess correct credentials",
                    "steps": [
                        {"title": "Step 1: Reconnaissance", "content": "Attacker scans for valid usernames using common patterns"},
                        {"title": "Step 2: Password Spraying", "content": "Attacker tries common passwords across multiple accounts"},
                        {"title": "Step 3: Detection Trigger", "content": "High login_failure_count triggers anomaly alert"},
                        {"title": "Step 4: SHAP Explanation", "content": "login_failure_count is the #1 contributing feature"}
                    ]
                },
                "Credential Stuffing": {
                    "description": "Using stolen credentials from other breaches",
                    "steps": [
                        {"title": "Step 1: Credential Match", "content": "Attacker uses stolen credentials from other breaches"},
                        {"title": "Step 2: Multiple IPs", "content": "Same user logging in from different IP addresses"},
                        {"title": "Step 3: Detection", "content": "unique_ips feature flags unusual behavior"},
                        {"title": "Step 4: Investigation", "content": "Check which credentials were compromised"}
                    ]
                },
                "Data Exfiltration": {
                    "description": "Unauthorized data transfer out of the network",
                    "steps": [
                        {"title": "Step 1: Baseline", "content": "System learns normal data transfer patterns per user"},
                        {"title": "Step 2: Anomaly", "content": "Large data transfer detected outside business hours"},
                        {"title": "Step 3: Severity Scoring", "content": "High anomaly score triggers critical alert"},
                        {"title": "Step 4: Response", "content": "Block destination IP, preserve logs for forensics"}
                    ]
                }
            }
            
            scenario_data = scenarios.get(scenario, scenarios["Brute Force Attack"])
            current_step = scenario_data["steps"][step]
            
            content = f"""### {scenario}

**{scenario_data['description']}**

---

#### {current_step['title']}

{current_step['content']}

---

*Step {step + 1} of 4* | Use the slider above to navigate through the attack scenario
"""
            return content
        
        scenarios_dropdown.change(
            update_demo,
            inputs=[scenarios_dropdown, step_slider],
            outputs=[demo_content]
        )
        
        step_slider.change(
            update_demo,
            inputs=[scenarios_dropdown, step_slider],
            outputs=[demo_content]
        )
    
    return app


if __name__ == "__main__":
    app = create_app()
    app.launch(server_name="0.0.0.0", server_port=7860)
