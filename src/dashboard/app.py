import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from src.ingestion.data_simulator import get_simulator
from src.ingestion.threat_client import get_threat_client
from src.features.feature_pipeline import get_feature_pipeline
from src.models.anomaly_detector import get_anomaly_detector
from src.alerts.alert_manager import get_alert_manager
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

SIDEBAR_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap');
    
    * { font-family: 'Inter', sans-serif !important; }
    
    /* Main app background */
    .stApp {
        background: #0d1117 !important;
    }
    
    /* Hide default Streamlit elements */
    #MainMenu {visibility: hidden !important;}
    footer {visibility: hidden !important;}
    
    /* Hide sidebar toggle button */
    button[data-testid="stSidebarToggle"] {
        display: none !important;
    }
    
    .stSidebar > div:first-child > button {
        display: none !important;
    }
    
    /* Custom sidebar */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #161c25 100%) !important;
        border-right: 1px solid #30363d !important;
        width: 280px !important;
        min-width: 280px !important;
    }
    
    section[data-testid="stSidebar"] > div {
        background: transparent !important;
    }
    
    section[data-testid="stSidebar"] > div > div {
        background: transparent !important;
    }
    
    /* Sidebar header */
    .sidebar-header {
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        padding: 20px 16px 16px !important;
        border-bottom: 1px solid #21262d !important;
        margin-bottom: 8px !important;
    }
    
    .sidebar-logo {
        width: 42px !important;
        height: 42px !important;
        background: linear-gradient(135deg, #238636 0%, #2ea043 100%) !important;
        border-radius: 10px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-size: 1.4rem !important;
        box-shadow: 0 4px 12px rgba(35, 134, 54, 0.4) !important;
    }
    
    .sidebar-brand {
        flex: 1 !important;
    }
    
    .sidebar-title {
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        color: #f0f6fc !important;
        letter-spacing: -0.02em !important;
    }
    
    .sidebar-subtitle {
        font-size: 0.7rem !important;
        color: #8b949e !important;
        text-transform: uppercase !important;
        letter-spacing: 0.08em !important;
        margin-top: 2px !important;
    }
    
    /* Status indicator */
    .sidebar-status {
        display: inline-flex !important;
        align-items: center !important;
        gap: 8px !important;
        padding: 8px 14px !important;
        background: rgba(35, 134, 54, 0.15) !important;
        border: 1px solid rgba(35, 134, 54, 0.3) !important;
        border-radius: 20px !important;
        margin: 0 16px 16px !important;
        font-size: 0.75rem !important;
        color: #3fb950 !important;
        font-weight: 500 !important;
    }
    
    .status-pulse {
        width: 8px !important;
        height: 8px !important;
        background: #3fb950 !important;
        border-radius: 50% !important;
        animation: pulse 2s infinite !important;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.6; transform: scale(0.9); }
    }
    
    .sidebar-item:hover {
        background: #21262d !important;
        color: #f0f6fc !important;
    }
    
    .sidebar-item.active {
        background: linear-gradient(90deg, rgba(88, 166, 255, 0.15) 0%, rgba(88, 166, 255, 0.05) 100%) !important;
        color: #58a6ff !important;
        border-left: 3px solid #58a6ff !important;
        margin-left: 5px !important;
    }
    
    .sidebar-icon {
        font-size: 1.1rem !important;
        width: 24px !important;
        text-align: center !important;
        opacity: 0.8 !important;
    }
    
    .sidebar-item.active .sidebar-icon {
        opacity: 1 !important;
    }
    
    .sidebar-label {
        flex: 1 !important;
    }
    
    /* Sidebar section headers */
    .sidebar-section {
        padding: 0.5rem 0;
    }
    
    .sidebar-section-title {
        font-size: 0.7rem !important;
        font-weight: 600 !important;
        color: #8b949e !important;
        text-transform: uppercase !important;
        letter-spacing: 0.1em !important;
        padding: 0.75rem 1rem 0.5rem !important;
        margin: 0 !important;
    }
    
    /* Sidebar footer */
    .sidebar-footer {
        padding: 16px !important;
        text-align: center !important;
        border-top: 1px solid #21262d !important;
        margin-top: auto !important;
    }
    
    /* Override selectbox styling */
    section[data-testid="stSidebar"] .stSelectbox {
        background: #21262d !important;
        border-radius: 8px !important;
        padding: 4px !important;
        margin: 8px 16px !important;
    }
    
    /* Override button styling */
    section[data-testid="stSidebar"] .stButton > button {
        background: linear-gradient(135deg, #238636 0%, #2ea043 100%) !important;
        border: none !important;
        border-radius: 8px !important;
        color: white !important;
        font-weight: 600 !important;
        padding: 10px 16px !important;
        margin: 8px 16px !important;
        width: calc(100% - 32px) !important;
        transition: all 0.2s ease !important;
    }
    
    section[data-testid="stSidebar"] .stButton > button:hover {
        background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%) !important;
        box-shadow: 0 4px 15px rgba(46, 160, 67, 0.4) !important;
    }
    
    /* Override slider styling */
    section[data-testid="stSidebar"] .stSlider {
        padding: 8px 16px !important;
    }
    
    section[data-testid="stSidebar"] .stSlider > div > div {
        background: #21262d !important;
    }
    
    /* Sidebar link styles (legacy) */
    .sidebar-link {
        display: flex !important;
        align-items: center !important;
        gap: 0.75rem !important;
        padding: 0.6rem 1rem !important;
        color: #c9d1d9 !important;
        text-decoration: none !important;
        border-radius: 6px !important;
        margin: 2px 8px !important;
        transition: all 0.15s ease !important;
        cursor: pointer !important;
    }
    
    .sidebar-link:hover {
        background: #21262d !important;
        color: #58a6ff !important;
    }
    
    .sidebar-link.active {
        background: rgba(56, 139, 253, 0.15) !important;
        color: #58a6ff !important;
        border-left: 3px solid #58a6ff !important;
    }
    
    .sidebar-link-icon {
        font-size: 1rem !important;
        width: 20px !important;
        text-align: center !important;
    }
    
    .sidebar-link-text {
        font-size: 0.9rem !important;
        font-weight: 500 !important;
    }
    
    /* Main content area */
    .main-content {
        padding: 1.5rem 2rem !important;
        max-width: 1400px !important;
    }
    
    /* Page title */
    .page-title {
        font-size: 1.75rem !important;
        font-weight: 700 !important;
        color: #f0f6fc !important;
        margin-bottom: 0.25rem !important;
        letter-spacing: -0.02em !important;
    }
    
    .page-subtitle {
        font-size: 0.9rem !important;
        color: #8b949e !important;
        margin-bottom: 1.5rem !important;
    }
    
    /* Metric cards */
    .metric-grid {
        display: grid !important;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)) !important;
        gap: 1rem !important;
        margin-bottom: 1.5rem !important;
    }
    
    .metric-card {
        background: linear-gradient(135deg, #161b22 0%, #21262d 100%) !important;
        border: 1px solid #30363d !important;
        border-radius: 12px !important;
        padding: 1.25rem !important;
        transition: all 0.2s ease !important;
    }
    
    .metric-card:hover {
        border-color: #58a6ff !important;
        box-shadow: 0 0 20px rgba(88, 166, 255, 0.1) !important;
        transform: translateY(-2px) !important;
    }
    
    .metric-icon {
        font-size: 1.25rem !important;
        margin-bottom: 0.5rem !important;
    }
    
    .metric-value {
        font-size: 1.75rem !important;
        font-weight: 700 !important;
        color: #58a6ff !important;
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .metric-value.critical { color: #f85149 !important; }
    .metric-value.warning { color: #d29922 !important; }
    .metric-value.success { color: #3fb950 !important; }
    .metric-value.info { color: #a371f7 !important; }
    
    .metric-label {
        font-size: 0.75rem !important;
        color: #8b949e !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        margin-top: 0.25rem !important;
    }
    
    /* Section panels */
    .panel {
        background: #161b22 !important;
        border: 1px solid #30363d !important;
        border-radius: 12px !important;
        padding: 1.25rem !important;
        margin-bottom: 1.5rem !important;
    }
    
    .panel-header {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        margin-bottom: 1rem !important;
        padding-bottom: 0.75rem !important;
        border-bottom: 1px solid #30363d !important;
    }
    
    .panel-title {
        font-size: 1rem !important;
        font-weight: 600 !important;
        color: #f0f6fc !important;
        display: flex !important;
        align-items: center !important;
        gap: 0.5rem !important;
    }
    
    /* Alert cards */
    .alert-row {
        display: grid !important;
        grid-template-columns: 80px 100px 1fr 120px 100px !important;
        gap: 1rem !important;
        align-items: center !important;
        padding: 0.75rem 1rem !important;
        background: #21262d !important;
        border: 1px solid #30363d !important;
        border-radius: 8px !important;
        margin-bottom: 0.5rem !important;
        transition: all 0.15s ease !important;
    }
    
    .alert-row:hover {
        border-color: #58a6ff !important;
        background: #30363d !important;
    }
    
    .alert-id {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.85rem !important;
        color: #8b949e !important;
    }
    
    .alert-severity {
        padding: 0.25rem 0.5rem !important;
        border-radius: 4px !important;
        font-size: 0.7rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        text-align: center !important;
    }
    
    .alert-severity.critical {
        background: rgba(248, 81, 73, 0.2) !important;
        color: #f85149 !important;
    }
    
    .alert-severity.high {
        background: rgba(210, 153, 34, 0.2) !important;
        color: #d29922 !important;
    }
    
    .alert-severity.medium {
        background: rgba(163, 113, 247, 0.2) !important;
        color: #a371f7 !important;
    }
    
    .alert-severity.low {
        background: rgba(63, 185, 80, 0.2) !important;
        color: #3fb950 !important;
    }
    
    .alert-user {
        color: #58a6ff !important;
        font-weight: 500 !important;
    }
    
    .alert-score {
        font-family: 'JetBrains Mono', monospace !important;
        font-weight: 600 !important;
        color: #f85149 !important;
        text-align: right !important;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #238636 0%, #2ea043 100%) !important;
        border: none !important;
        border-radius: 6px !important;
        color: white !important;
        font-weight: 600 !important;
        padding: 0.5rem 1rem !important;
        transition: all 0.2s ease !important;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #2ea043 0%, #3fb950 100%) !important;
        box-shadow: 0 0 15px rgba(46, 160, 67, 0.4) !important;
    }
    
    /* Sliders */
    .stSlider [data-baseweb="slider"] {
        padding: 0.5rem 0 !important;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: #161b22; }
    ::-webkit-scrollbar-thumb {
        background: #30363d;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover { background: #484f58; }
    
    /* Status indicator */
    .status-indicator {
        display: inline-flex !important;
        align-items: center !important;
        gap: 0.5rem !important;
        padding: 0.5rem 0.75rem !important;
        background: rgba(63, 185, 80, 0.1) !important;
        border: 1px solid rgba(63, 185, 80, 0.3) !important;
        border-radius: 20px !important;
        margin-bottom: 1rem !important;
    }
    
    .status-dot {
        width: 8px !important;
        height: 8px !important;
        background: #3fb950 !important;
        border-radius: 50% !important;
        animation: pulse 2s infinite !important;
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    .status-text {
        color: #3fb950 !important;
        font-size: 0.8rem !important;
        font-weight: 500 !important;
    }
    
    /* Charts */
    .chart-container {
        background: #0d1117 !important;
        border-radius: 8px !important;
        padding: 1rem !important;
    }
</style>
"""


def init_session_state():
    if 'data_loaded' not in st.session_state:
        st.session_state.simulator = get_simulator()
        st.session_state.threat_client = get_threat_client()
        st.session_state.feature_pipeline = get_feature_pipeline()
        st.session_state.detector = get_anomaly_detector(contamination=0.05)
        st.session_state.alert_manager = get_alert_manager()
        st.session_state.explainer = get_explainer()
        st.session_state.events_df = None
        st.session_state.results = []
        st.session_state.X_scaled = None
        st.session_state.available_features = []
        st.session_state.shap_initialized = False
        st.session_state.data_loaded = True
        st.session_state.current_section = "overview"


def load_data(n_events: int = 2000):
    simulator = st.session_state.simulator
    events_df = simulator.generate_combined_events(n=n_events)
    st.session_state.events_df = events_df
    return events_df


def run_detection(df: pd.DataFrame):
    available_features = [col for col in FEATURE_COLUMNS if col in df.columns]
    
    if not available_features:
        st.error("No feature columns found!")
        return []
    
    X = df[available_features].values.astype(float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    st.session_state.X_scaled = X_scaled
    st.session_state.available_features = available_features
    
    detector = st.session_state.detector
    detector.fit(X_scaled, available_features)
    results = detector.detect(X_scaled)
    
    if not st.session_state.shap_initialized:
        st.session_state.explainer.initialize(X_scaled, available_features, detector.isolation_forest)
        st.session_state.shap_initialized = True
    
    return results


def create_sidebar():
    with st.sidebar:
        # Logo and title
        st.markdown("""
        <div class="sidebar-header">
            <div class="sidebar-logo">🛡️</div>
            <div class="sidebar-brand">
                <div class="sidebar-title">SOC Sentinel</div>
                <div class="sidebar-subtitle">Threat Detection</div>
            </div>
        </div>
        <div class="sidebar-status">
            <span class="status-pulse"></span>
            <span>System Online</span>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### Menu")
        
        # Navigation menu with custom styling
        menu_items = [
            ("overview", "Overview", "dashboard"),
            ("threats", "Threats", "warning"),
            ("activity", "Activity", "trending_up"),
            ("users", "Users", "people"),
            ("investigate", "Investigate", "search"),
            ("rules", "Detection Rules", "shield"),
            ("query", "Query Search", "database"),
            ("triage", "Alert Triage", "checklist"),
            ("timeline", "Incident Timeline", "clock"),
            ("threat_intel", "Threat Intel", "globe"),
            ("incident_response", "Incident Response", "rocket"),
            ("shap", "SHAP Analysis", "psychology"),
            ("portfolio", "Portfolio Mode", "briefcase"),
            ("settings", "Settings", "settings"),
        ]
        
        current = st.session_state.get('current_section', 'overview')
        
        for section_id, label, icon_name in menu_items:
            icon_map = {
                "dashboard": "◫",
                "warning": "▲", 
                "trending_up": "↗",
                "people": "◉",
                "search": "⌕",
                "shield": "◈",
                "database": "▤",
                "checklist": "☑",
                "clock": "⏱",
                "rocket": "🚀",
                "briefcase": "💼",
                "psychology": "◈",
                "settings": "⚙"
            }
            icon = icon_map.get(icon_name, "▸")
            
            is_active = current == section_id
            
            # Use selectbox as a workaround for better styling
            if is_active:
                st.markdown(f"""
                <div class="sidebar-item active">
                    <span class="sidebar-icon">{icon}</span>
                    <span class="sidebar-label">{label}</span>
                </div>
                """, unsafe_allow_html=True)
        
        # Create navigation using selectbox
        selected = st.selectbox(
            "Navigate",
            [label for _, label, _ in menu_items],
            index=[label for _, label, _ in menu_items].index([l for s, l, i in menu_items if s == current][0]),
            label_visibility="collapsed",
            key="nav_select"
        )
        
        if selected:
            for section_id, label, _ in menu_items:
                if label == selected:
                    st.session_state.current_section = section_id
                    break
        
        st.markdown("---")
        st.markdown("### Configuration")
        
        n_events = st.slider("Events to Analyze", 500, 5000, 2000, key="n_events")
        contamination = st.slider("Anomaly Threshold", 0.01, 0.2, 0.05, key="contamination")
        
        st.markdown("")
        
        if st.button("▶ Run Detection", use_container_width=True):
            st.session_state.events_df = None
            st.session_state.results = []
            st.rerun()
        
        # Footer
        st.markdown("---")
        st.markdown("""
        <div class="sidebar-footer">
            <div style="font-size: 0.7rem; color: #6e7681;">
                SOC Sentinel v1.0<br>
                Powered by Isolation Forest + SHAP
            </div>
        </div>
        """, unsafe_allow_html=True)


def create_metric_card(value, label, icon, color_class="info"):
    color_map = {
        "info": "#58a6ff",
        "critical": "#f85149",
        "warning": "#d29922",
        "success": "#3fb950"
    }
    color = color_map.get(color_class, color_map["info"])
    
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">{icon}</div>
        <div class="metric-value {color_class}" style="color: {color} !important;">{value}</div>
        <div class="metric-label">{label}</div>
    </div>
    """, unsafe_allow_html=True)


def render_overview_section(df, results, detected_anomalies):
    st.markdown('<h1 class="page-title">Security Overview</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Real-time threat detection and anomaly monitoring</p>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="status-indicator">
        <span class="status-dot"></span>
        <span class="status-text">System Online - Monitoring Active</span>
    </div>
    """, unsafe_allow_html=True)
    
    anomaly_count = len(detected_anomalies)
    critical = sum(1 for r in results if r['severity'] == 'CRITICAL')
    high = sum(1 for r in results if r['severity'] == 'HIGH')
    medium = sum(1 for r in results if r['severity'] == 'MEDIUM')
    avg_score = np.mean([r['anomaly_score'] for r in results]) if results else 0
    
    st.markdown('<div class="metric-grid">', unsafe_allow_html=True)
    cols = st.columns(5)
    with cols[0]:
        create_metric_card(f"{len(df):,}", "Total Events", "📊", "info")
    with cols[1]:
        create_metric_card(f"{anomaly_count}", "Threats", "🚨", "warning")
    with cols[2]:
        create_metric_card(f"{critical}", "Critical", "🔴", "critical")
    with cols[3]:
        create_metric_card(f"{high}", "High", "🟠", "warning")
    with cols[4]:
        create_metric_card(f"{avg_score:.2f}", "Avg Score", "📈", "info")
    st.markdown('</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Threat Timeline")
        df_copy = df.copy()
        df_copy['minute'] = df_copy['timestamp'].dt.floor('T')
        timeline = df_copy.groupby('minute')['is_anomaly'].sum().reset_index()
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timeline['minute'], y=timeline['is_anomaly'],
            mode='lines+markers',
            fill='tozeroy',
            line=dict(color='#58a6ff', width=2),
            fillcolor='rgba(88, 166, 255, 0.2)',
            name='Threats'
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            xaxis=dict(gridcolor="rgba(48, 54, 61, 0.5)"),
            yaxis=dict(gridcolor="rgba(48, 54, 61, 0.5)"),
            height=300,
            margin=dict(l=50, r=20, t=20, b=40)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Threat Severity")
        severity_counts = {"Critical": critical, "High": high, "Medium": medium, "Low": sum(1 for r in results if r['severity'] == 'LOW')}
        
        fig = go.Figure(go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            hole=0.6,
            marker=dict(colors=['#f85149', '#d29922', '#a371f7', '#3fb950']),
            textinfo='label+percent',
            textfont=dict(color='#f0f6fc', size=11)
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            height=300,
            margin=dict(l=20, r=20, t=20, b=20),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)
    
    col3, col4 = st.columns(2)
    
    with col3:
        st.markdown("### Anomaly Rate by Hour")
        df_copy = df.copy()
        df_copy['hour'] = df_copy['timestamp'].dt.hour
        hourly = df_copy.groupby('hour')['is_anomaly'].mean().reset_index()
        
        fig = go.Figure(go.Bar(
            x=hourly['hour'],
            y=hourly['is_anomaly'],
            marker_color=hourly['is_anomaly'].apply(
                lambda x: f'rgba(248, 81, 73, {min(x*3+0.2, 0.9)})' if x > 0.05 else 'rgba(88, 166, 255, 0.6)'
            )
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            xaxis=dict(title="Hour", gridcolor="rgba(48, 54, 61, 0.5)"),
            yaxis=dict(title="Rate", gridcolor="rgba(48, 54, 61, 0.5)"),
            height=250,
            margin=dict(l=50, r=20, t=20, b=40)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col4:
        st.markdown("### Score Distribution")
        scores = [r['anomaly_score'] for r in results]
        
        fig = go.Figure(go.Histogram(
            x=scores,
            nbinsx=30,
            marker_color='rgba(88, 166, 255, 0.6)',
            marker_line_color='#58a6ff',
            marker_line_width=1
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            xaxis=dict(title="Score", gridcolor="rgba(48, 54, 61, 0.5)"),
            yaxis=dict(title="Count", gridcolor="rgba(48, 54, 61, 0.5)"),
            height=250,
            margin=dict(l=50, r=20, t=20, b=40)
        )
        st.plotly_chart(fig, use_container_width=True)


def render_threats_section(df, detected_anomalies):
    st.markdown('<h1 class="page-title">Detected Threats</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Active security alerts requiring investigation</p>', unsafe_allow_html=True)
    
    severity_filter = st.selectbox("Filter by Severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    
    filtered = detected_anomalies
    if severity_filter != "All":
        filtered = [(i, r) for i, r in detected_anomalies if r['severity'] == severity_filter]
    
    st.markdown(f"**{len(filtered)} threats detected**")
    
    st.markdown("""
    <div class="panel">
        <div class="panel-header">
            <div class="panel-title">🚨 Active Alerts</div>
        </div>
    """, unsafe_allow_html=True)
    
    for idx, (original_idx, r) in enumerate(filtered[:15]):
        row = df.iloc[original_idx]
        user = row.get('user', 'N/A')
        sev_lower = r['severity'].lower()
        
        st.markdown(f"""
        <div class="alert-row">
            <div class="alert-id">#{original_idx}</div>
            <div class="alert-severity {sev_lower}">{r['severity']}</div>
            <div class="alert-user">{user}</div>
            <div style="color: #8b949e; font-size: 0.8rem;">{row.get('timestamp', 'N/A')}</div>
            <div class="alert-score">{r['anomaly_score']:.3f}</div>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("</div>", unsafe_allow_html=True)


def render_activity_section(df, results):
    st.markdown('<h1 class="page-title">Activity Analysis</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Behavioral patterns and traffic analysis</p>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Response Time Distribution")
        fig = px.histogram(
            df, x='avg_response_time', color='is_anomaly',
            barmode='overlay',
            color_discrete_map={0: '#58a6ff', 1: '#f85149'},
            labels={'is_anomaly': 'Type'}
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            legend=dict(title="", orientation="h"),
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### Request Rate Distribution")
        fig = px.histogram(
            df, x='request_rate', color='is_anomaly',
            barmode='overlay',
            color_discrete_map={0: '#58a6ff', 1: '#f85149'}
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("### Top Users by Threat Count")
    user_threats = df.groupby('user')['is_anomaly'].sum().reset_index()
    user_threats = user_threats.sort_values('is_anomaly', ascending=False).head(10)
    
    fig = px.bar(
        user_threats, x='user', y='is_anomaly',
        color='is_anomaly',
        color_continuous_scale='Reds'
    )
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color="#8b949e"),
        height=350
    )
    st.plotly_chart(fig, use_container_width=True)


def render_users_section(df):
    st.markdown('<h1 class="page-title">User Analysis</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">User behavior and risk profiling</p>', unsafe_allow_html=True)
    
    user_stats = df.groupby('user').agg({
        'is_anomaly': ['sum', 'count', 'mean'],
        'login_failure_count': 'sum',
        'request_rate': 'mean'
    }).reset_index()
    
    user_stats.columns = ['user', 'threats', 'total_events', 'threat_rate', 'failures', 'avg_requests']
    user_stats = user_stats.sort_values('threats', ascending=False)
    
    st.dataframe(
        user_stats.head(20),
        use_container_width=True,
        hide_index=True
    )


def render_investigate_section(df, detected_anomalies):
    st.markdown('<h1 class="page-title">Investigate</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Deep dive into specific threats</p>', unsafe_allow_html=True)
    
    if detected_anomalies:
        selected_idx = st.selectbox(
            "Select Threat",
            range(len(detected_anomalies)),
            format_func=lambda i: f"Event {detected_anomalies[i][0]} - Score: {detected_anomalies[i][1]['anomaly_score']:.2f}"
        )
        
        original_idx, selected = detected_anomalies[selected_idx]
        row = df.iloc[original_idx]
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("### Event Details")
            details = {
                "User": row.get('user', 'N/A'),
                "Timestamp": str(row.get('timestamp', 'N/A')),
                "IP Address": row.get('ip_address', 'N/A'),
                "Country": row.get('country', 'N/A'),
                "Hour": row.get('hour_of_day', 'N/A'),
                "Business Hours": "Yes" if row.get('is_business_hours', 0) == 1 else "No"
            }
            for k, v in details.items():
                st.markdown(f"**{k}:** {v}")
        
        with col2:
            st.markdown("### Risk Score")
            score = selected['anomaly_score']
            st.markdown(f"""
            <div style="text-align: center; padding: 1.5rem; background: linear-gradient(135deg, #161b22, #21262d); border-radius: 12px; border: 1px solid #30363d;">
                <div style="font-size: 3rem; font-weight: 700; color: {'#f85149' if score > 0.8 else '#d29922' if score > 0.5 else '#3fb950'};">{score:.3f}</div>
                <div style="color: #8b949e; font-size: 0.8rem;">ANOMALY SCORE</div>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown("### Feature Values")
        features = {
            "Login Failures": row.get('login_failure_count', 0),
            "Login Success": row.get('login_success_count', 0),
            "Unique IPs": row.get('unique_ips', 0),
            "Request Rate": row.get('request_rate', 0),
            "Error Rate": f"{row.get('error_rate', 0):.1%}",
            "Response Time": f"{row.get('avg_response_time', 0):.0f}ms"
        }
        
        cols = st.columns(3)
        for i, (k, v) in enumerate(features.items()):
            with cols[i % 3]:
                st.markdown(f"""
                <div style="background: #21262d; padding: 0.75rem; border-radius: 8px; border: 1px solid #30363d;">
                    <div style="font-size: 0.7rem; color: #8b949e; text-transform: uppercase;">{k}</div>
                    <div style="font-size: 1.1rem; font-weight: 600; color: #f0f6fc;">{v}</div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No threats to investigate")


def render_detection_rules_section(df, detected_anomalies):
    st.markdown('<h1 class="page-title">Detection Rules</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Sigma rules and detection logic used in this SOC</p>', unsafe_allow_html=True)
    
    # Define Sigma rules for different attack scenarios
    sigma_rules = [
        {
            "id": "SOC-001",
            "title": "Brute Force Attack Detection",
            "category": "Credential Access",
            "severity": "HIGH",
            "condition": "login_failure_count > 10",
            "description": "Detects potential brute force attempts when failed logins exceed threshold",
            "mitre": "T1110",
            "mitre_name": "Brute Force",
            "status": "Active"
        },
        {
            "id": "SOC-002",
            "title": "Suspicious IP Spread",
            "category": "Credential Access",
            "severity": "HIGH",
            "condition": "unique_ips > 5",
            "description": "Detects when user accesses from multiple IP addresses",
            "mitre": "T1078",
            "mitre_name": "Valid Accounts",
            "status": "Active"
        },
        {
            "id": "SOC-003",
            "title": "High Request Rate",
            "category": "Impact",
            "severity": "MEDIUM",
            "condition": "request_rate > 100",
            "description": "Detects unusually high request rates indicating potential DoS",
            "mitre": "T1498",
            "mitre_name": "Resource Hijacking",
            "status": "Active"
        },
        {
            "id": "SOC-004",
            "title": "Data Exfiltration",
            "category": "Exfiltration",
            "severity": "CRITICAL",
            "condition": "bytes_sent > 50000",
            "description": "Detects large outbound data transfers",
            "mitre": "T1041",
            "mitre_name": "Exfiltration Over C2",
            "status": "Active"
        },
        {
            "id": "SOC-005",
            "title": "After Hours Activity",
            "category": "Persistence",
            "severity": "MEDIUM",
            "condition": "is_business_hours == 0",
            "description": "Detects activity outside business hours",
            "mitre": "T1078",
            "mitre_name": "Valid Accounts",
            "status": "Active"
        },
        {
            "id": "SOC-006",
            "title": "Geographic Anomaly",
            "category": "Credential Access",
            "severity": "HIGH",
            "condition": "geo_countries_accessed > 3",
            "description": "Detects access from multiple countries in short timeframe",
            "mitre": "T1078",
            "mitre_name": "Valid Accounts",
            "status": "Active"
        },
        {
            "id": "SOC-007",
            "title": "High Error Rate",
            "category": "Impact",
            "severity": "MEDIUM",
            "condition": "error_rate > 0.3",
            "description": "Detects high error rate indicating potential exploitation",
            "mitre": "T1494",
            "mitre_name": "Runtime Data Manipulation",
            "status": "Active"
        },
        {
            "id": "SOC-008",
            "title": "Slow Response Attack",
            "category": "Impact",
            "severity": "LOW",
            "condition": "avg_response_time > 200",
            "description": "Detects abnormally slow response times",
            "mitre": "T1499",
            "mitre_name": "Endpoint DoS",
            "status": "Active"
        }
    ]
    
    # Display rules in a table format
    st.markdown("### Active Detection Rules")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Rules", len(sigma_rules))
    with col2:
        active_count = sum(1 for r in sigma_rules if r['status'] == 'Active')
        st.metric("Active", active_count)
    with col3:
        critical_count = sum(1 for r in sigma_rules if r['severity'] == 'CRITICAL')
        st.metric("Critical", critical_count)
    with col4:
        high_count = sum(1 for r in sigma_rules if r['severity'] == 'HIGH')
        st.metric("High", high_count)
    
    st.markdown("---")
    
    # Display rules
    for rule in sigma_rules:
        severity_colors = {
            "CRITICAL": "#f85149",
            "HIGH": "#d29922",
            "MEDIUM": "#a371f7",
            "LOW": "#8b949e"
        }
        
        with st.expander(f"{rule['id']} | {rule['title']} | {rule['severity']}"):
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**Description:** {rule['description']}")
                st.markdown(f"**Condition:** `{rule['condition']}`")
                st.markdown(f"**Category:** {rule['category']}")
            
            with col2:
                st.markdown(f"**MITRE ATT&CK:**")
                st.code(f"{rule['mitre']} - {rule['mitre_name']}")
                
                # Status badge
                status_color = "#3fb950" if rule['status'] == 'Active' else "#8b949e"
                st.markdown(f"<span style='color: {status_color};'>● {rule['status']}</span>", unsafe_allow_html=True)


def render_query_search_section(df):
    st.markdown('<h1 class="page-title">Query Search</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">KQL-style query search across security events</p>', unsafe_allow_html=True)
    
    # Query builder
    st.markdown("### Query Builder")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        field = st.selectbox(
            "Field",
            ["user", "country", "ip_address", "login_failure_count", "login_success_count", 
             "unique_ips", "request_rate", "error_rate", "avg_response_time", "bytes_sent"]
        )
    
    with col2:
        operator = st.selectbox(
            "Operator",
            ["==", "!=", ">", "<", ">=", "<=", "contains", "startswith"]
        )
    
    with col3:
        value = st.text_input("Value", "")
    
    # Build and execute query
    query_btn = st.button("Run Query", type="primary")
    
    if query_btn and value:
        try:
            if operator == "==":
                if field in df.columns:
                    results = df[df[field] == value]
            elif operator == "!=":
                if field in df.columns:
                    results = df[df[field] != value]
            elif operator in [">", "<", ">=", "<="]:
                try:
                    val = float(value)
                    if field in df.columns:
                        results = df[df[field].astype(float) > val] if operator == ">" else \
                                 df[df[field].astype(float) < val] if operator == "<" else \
                                 df[df[field].astype(float) >= val] if operator == ">=" else \
                                 df[df[field].astype(float) <= val]
                except:
                    results = df
            elif operator == "contains":
                if field in df.columns:
                    results = df[df[field].astype(str).str.contains(value, case=False, na=False)]
            elif operator == "startswith":
                if field in df.columns:
                    results = df[df[field].astype(str).str.startswith(value, na=False)]
            else:
                results = df
                
            st.markdown(f"### Results: {len(results)} events found")
            
            if len(results) > 0:
                st.dataframe(results.head(50), use_container_width=True)
                
                # Show if any are anomalies
                anomaly_results = results[results['is_anomaly'] == 1]
                if len(anomaly_results) > 0:
                    st.warning(f"⚠️ {len(anomaly_results)} flagged as anomalies!")
        except Exception as e:
            st.error(f"Query error: {e}")
    
    # Pre-built queries
    st.markdown("---")
    st.markdown("### Pre-built Queries")
    
    query_templates = [
        ("Failed Logins > 5", "login_failure_count > 5"),
        ("High Request Rate", "request_rate > 50"),
        ("Multiple Countries", "geo_countries_accessed > 2"),
        ("After Hours", "is_business_hours == 0"),
        ("Large Data Transfer", "bytes_sent > 30000"),
    ]
    
    for name, query in query_templates:
        if st.button(name, key=f"query_{name}"):
            # Parse and execute simple queries
            try:
                if ">" in query:
                    field, val = query.split(">")
                    val = float(val.strip())
                    results = df[df[field.strip()] > val]
                elif "==" in query:
                    field, val = query.split("==")
                    results = df[df[field.strip()] == val.strip()]
                else:
                    results = df
                    
                st.session_state.query_results = results
                st.rerun()
            except:
                pass
    
    if 'query_results' in st.session_state and st.session_state.query_results is not None:
        st.markdown("### Query Results")
        st.dataframe(st.session_state.query_results.head(50), use_container_width=True)


def render_triage_section(df, detected_anomalies):
    st.markdown('<h1 class="page-title">Alert Triage</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Prioritize and process security alerts</p>', unsafe_allow_html=True)
    
    if not detected_anomalies:
        st.info("No alerts to triage")
        return
    
    # Initialize triage state if not exists
    if 'triage_state' not in st.session_state:
        st.session_state.triage_state = {}
        for idx, (orig_idx, r) in enumerate(detected_anomalies):
            st.session_state.triage_state[orig_idx] = {
                'status': 'New',
                'priority': r['severity'],
                'assigned_to': '',
                'notes': ''
            }
    
    # Summary
    col1, col2, col3, col4 = st.columns(4)
    triage_states = [st.session_state.triage_state.get(orig_idx, {}).get('status', 'New') 
                     for orig_idx, _ in detected_anomalies]
    
    with col1:
        st.metric("Total Alerts", len(detected_anomalies))
    with col2:
        new_count = triage_states.count('New')
        st.metric("New", new_count)
    with col3:
        in_progress = triage_states.count('In Progress')
        st.metric("In Progress", in_progress)
    with col4:
        resolved = triage_states.count('Resolved')
        st.metric("Resolved", resolved)
    
    st.markdown("---")
    
    # Triage form
    st.markdown("### Triage Alert")
    
    alert_options = [f"Event {orig_idx} - {r['severity']} - Score: {r['anomaly_score']:.3f}" 
                    for orig_idx, r in detected_anomalies]
    alert_idx = st.selectbox("Select Alert", range(len(detected_anomalies)), format_func=lambda i: alert_options[i])
    
    orig_idx, selected_alert = detected_anomalies[alert_idx]
    row = df.iloc[orig_idx]
    
    # Current triage state
    current = st.session_state.triage_state.get(orig_idx, {'status': 'New', 'priority': selected_alert['severity'], 'assigned_to': '', 'notes': ''})
    
    col1, col2 = st.columns(2)
    
    with col1:
        new_status = st.selectbox(
            "Status",
            ["New", "In Progress", "Escalated", "Resolved", "False Positive"],
            index=["New", "In Progress", "Escalated", "Resolved", "False Positive"].index(current['status'])
        )
        new_priority = st.selectbox(
            "Priority",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(current['priority'])
        )
    
    with col2:
        assigned_to = st.text_input("Assigned To", current['assigned_to'])
        notes = st.text_area("Analyst Notes", current['notes'])
    
    if st.button("Update Triage", type="primary"):
        st.session_state.triage_state[orig_idx] = {
            'status': new_status,
            'priority': new_priority,
            'assigned_to': assigned_to,
            'notes': notes
        }
        st.success(f"Alert {orig_idx} updated!")
    
    # Display triage queue
    st.markdown("---")
    st.markdown("### Triage Queue")
    
    for idx, (orig_idx, r) in enumerate(detected_anomalies[:10]):
        state = st.session_state.triage_state.get(orig_idx, {'status': 'New', 'priority': r['severity']})
        
        status_colors = {
            "New": "#58a6ff",
            "In Progress": "#d29922",
            "Escalated": "#f85149",
            "Resolved": "#3fb950",
            "False Positive": "#8b949e"
        }
        
        st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 0.5rem;">
            <span style="color: {status_colors.get(state['status'], '#8b949e')}; font-weight: 600;">{state['status']}</span>
            <span style="flex: 1;">Event {orig_idx}</span>
            <span style="color: {'#f85149' if state['priority'] == 'CRITICAL' else '#d29922' if state['priority'] == 'HIGH' else '#8b949e'};">{state['priority']}</span>
            <span style="color: #8b949e;">Score: {r['anomaly_score']:.3f}</span>
        </div>
        """, unsafe_allow_html=True)


def render_timeline_section(df, detected_anomalies):
    st.markdown('<h1 class="page-title">Incident Timeline</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Chronological view of security events</p>', unsafe_allow_html=True)
    
    if not detected_anomalies:
        st.info("No events to display")
        return
    
    # Create timeline data
    timeline_data = []
    for orig_idx, r in detected_anomalies:
        row = df.iloc[orig_idx]
        timeline_data.append({
            'timestamp': row.get('timestamp', datetime.now()),
            'event_id': orig_idx,
            'severity': r['severity'],
            'score': r['anomaly_score'],
            'user': row.get('user', 'Unknown'),
            'description': f"Anomaly detected - Score: {r['anomaly_score']:.3f}"
        })
    
    # Sort by timestamp
    timeline_data.sort(key=lambda x: x['timestamp'])
    
    # Timeline visualization
    st.markdown("### Event Timeline")
    
    # Timeline chart
    fig = go.Figure()
    
    severity_colors = {
        "CRITICAL": "#f85149",
        "HIGH": "#d29922", 
        "MEDIUM": "#a371f7",
        "LOW": "#8b949e"
    }
    
    for event in timeline_data[:20]:
        color = severity_colors.get(event['severity'], '#8b949e')
        fig.add_trace(go.Scatter(
            x=[event['timestamp']],
            y=[event['score']],
            mode='markers+text',
            marker=dict(size=20, color=color, symbol='diamond'),
            text=[f"Event {event['event_id']}"],
            textposition='top center',
            hovertemplate=f"<b>Event {event['event_id']}</b><br>" +
                         f"Time: {event['timestamp']}<br>" +
                         f"Severity: {event['severity']}<br>" +
                         f"Score: {event['score']:.3f}<br>" +
                         f"User: {event['user']}<extra></extra>"
        ))
    
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color="#8b949e"),
        xaxis=dict(title="Time", gridcolor="rgba(48, 54, 61, 0.5)"),
        yaxis=dict(title="Anomaly Score", gridcolor="rgba(48, 54, 61, 0.5)"),
        height=400
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Timeline list
    st.markdown("### Event Details")
    
    for event in timeline_data[:15]:
        severity_colors = {
            "CRITICAL": "#f85149",
            "HIGH": "#d29922",
            "MEDIUM": "#a371f7",
            "LOW": "#8b949e"
        }
        color = severity_colors.get(event['severity'], '#8b949e')
        
        with st.expander(f"🕐 {event['timestamp']} | {event['severity']} | Event {event['event_id']}"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"**Event ID:** {event['event_id']}")
                st.markdown(f"**Timestamp:** {event['timestamp']}")
                st.markdown(f"**User:** {event['user']}")
            with col2:
                st.markdown(f"**Severity:** {event['severity']}")
                st.markdown(f"**Score:** {event['score']:.4f}")
                st.markdown(f"**Description:** {event['description']}")


def render_threat_intel_section(df, detected_anomalies):
    st.markdown('<h1 class="page-title">Threat Intelligence</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Threat intelligence enrichment and geographic analysis</p>', unsafe_allow_html=True)
    
    # Initialize session state for API key if not exists
    # Default API key pre-configured for demo
    DEFAULT_VT_API_KEY = "e4d4d6f32775ee354c6bd7bbe134f75469cccb582a1659d8572cb5ae8b4d1572"
    
    if 'vt_api_key' not in st.session_state:
        st.session_state.vt_api_key = DEFAULT_VT_API_KEY
    
    # Settings in expander
    with st.expander("⚙️ Threat Intelligence Settings"):
        st.session_state.vt_api_key = st.text_input(
            "VirusTotal API Key", 
            value=st.session_state.vt_api_key,
            type="password",
            help="Get free API key at https://www.virustotal.com/gui/join-free"
        )
        if st.session_state.vt_api_key == DEFAULT_VT_API_KEY:
            st.success("✅ API Key configured (Demo)")
        elif st.session_state.vt_api_key:
            st.success("✅ Custom API Key configured")
        else:
            st.warning("⚠️ Enter API key for live threat intelligence")
    
    st.markdown("---")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Analyze countries from anomalies
    countries = []
    ip_addresses = []
    for orig_idx, r in detected_anomalies:
        row = df.iloc[orig_idx]
        if row.get('country'):
            countries.append(row.get('country'))
        if row.get('ip_address'):
            ip_addresses.append(row.get('ip_address'))
    
    unique_countries = list(set(countries))
    unique_ips = list(set(ip_addresses))
    
    with col1:
        st.metric("Monitored IPs", len(df['ip_address'].unique()) if 'ip_address' in df.columns else 0)
    with col2:
        st.metric("Unique Countries", len(unique_countries))
    with col3:
        st.metric("Anomalous IPs", len(unique_ips))
    with col4:
        st.metric("Threat Level", "MEDIUM" if len(detected_anomalies) > 10 else "LOW")
    
    st.markdown("---")
    
    # Geographic Distribution
    st.markdown("### Geographic Threat Distribution")
    
    # Country analysis
    country_counts = {}
    for c in countries:
        country_counts[c] = country_counts.get(c, 0) + 1
    
    if country_counts:
        # Create bar chart for countries
        fig = go.Figure(go.Bar(
            x=list(country_counts.keys()),
            y=list(country_counts.values()),
            marker_color='#f85149'
        ))
        fig.update_layout(
            title="Threats by Country",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            xaxis=dict(title="Country"),
            yaxis=dict(title="Threat Count"),
            height=300
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # IP Enrichment Section
    st.markdown("---")
    st.markdown("### IP Threat Intelligence")
    
    if not detected_anomalies:
        st.info("No anomalies to analyze")
        return
    
    # Select IP to investigate
    ip_options = []
    for orig_idx, r in detected_anomalies:
        row = df.iloc[orig_idx]
        if row.get('ip_address'):
            ip_options.append(f"{row.get('ip_address', 'Unknown')} - {row.get('user', 'Unknown')}")
    
    if ip_options:
        selected_ip_info = st.selectbox("Select IP to Investigate", ip_options)
        
        # Extract IP from selection
        selected_ip = selected_ip_info.split(" - ")[0]
        
        # Lookup button
        if st.button("🔍 Lookup IP on VirusTotal", type="primary"):
            if not st.session_state.vt_api_key:
                st.error("Please configure VirusTotal API key in settings above")
            else:
                with st.spinner(f"Looking up {selected_ip}..."):
                    try:
                        import requests
                        url = f"https://www.virustotal.com/api/v3/ip_addresses/{selected_ip}"
                        headers = {"x-apikey": st.session_state.vt_api_key}
                        response = requests.get(url, headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            data = response.json()
                            attrs = data.get('data', {}).get('attributes', {})
                            stats = attrs.get('last_analysis_stats', {})
                            
                            # Calculate threat score
                            malicious = stats.get('malicious', 0)
                            suspicious = stats.get('suspicious', 0)
                            total = sum(stats.values())
                            threat_score = malicious + suspicious
                            threat_pct = (threat_score / total * 100) if total > 0 else 0
                            
                            # Determine threat level
                            if threat_pct >= 50:
                                threat_level = "CRITICAL"
                                level_color = "#f85149"
                            elif threat_pct >= 20:
                                threat_level = "HIGH"
                                level_color = "#d29922"
                            elif threat_pct >= 5:
                                threat_level = "MEDIUM"
                                level_color = "#a371f7"
                            else:
                                threat_level = "LOW"
                                level_color = "#3fb950"
                            
                            # === VIRUSTOTAL-STYLE HEADER ===
                            st.markdown(f"""
                            <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid {level_color}; border-radius: 12px; padding: 1.5rem; margin: 1rem 0;">
                                <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                                    <div style="width: 60px; height: 60px; background: {level_color}; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem;">
                                        ⚠️
                                    </div>
                                    <div>
                                        <div style="font-size: 1.5rem; font-weight: 700; color: #fff;">{selected_ip}</div>
                                        <div style="color: #8b949e; font-size: 0.85rem;">IP Address Analysis</div>
                                    </div>
                                    <div style="margin-left: auto; text-align: right;">
                                        <div style="font-size: 2rem; font-weight: 700; color: {level_color};">{threat_score}</div>
                                        <div style="color: #8b949e; font-size: 0.75rem;">/{total} vendors</div>
                                    </div>
                                </div>
                                <div style="display: flex; gap: 0.5rem; align-items: center;">
                                    <span style="background: {level_color}; color: white; padding: 0.4rem 1rem; border-radius: 20px; font-weight: 600; font-size: 0.85rem;">
                                        {threat_level} THREAT
                                    </span>
                                    <span style="color: #8b949e; font-size: 0.85rem;">
                                        {threat_pct:.1f}% detection rate
                                    </span>
                                </div>
                            </div>
                            """, unsafe_allow_html=True)
                            
                            # === THREAT CATEGORIES (VirusTotal style) ===
                            st.markdown("##### Threat Categories")
                            
                            # Create visual bars for each category
                            categories = [
                                ("Malicious", malicious, "#f85149"),
                                ("Suspicious", suspicious, "#d29922"),
                                ("Undetected", stats.get('undetected', 0), "#8b949e"),
                                ("Harmless", stats.get('harmless', 0), "#3fb950"),
                                ("Timeout", stats.get('timeout', 0), "#6e7681"),
                            ]
                            
                            for cat_name, cat_count, cat_color in categories:
                                pct = (cat_count / total * 100) if total > 0 else 0
                                bar_width = pct
                                
                                st.markdown(f"""
                                <div style="margin: 0.5rem 0;">
                                    <div style="display: flex; justify-content: space-between; margin-bottom: 0.25rem;">
                                        <span style="color: #c9d1d9; font-size: 0.85rem;">{cat_name}</span>
                                        <span style="color: {cat_color}; font-weight: 600; font-size: 0.85rem;">{cat_count} ({pct:.1f}%)</span>
                                    </div>
                                    <div style="background: #21262d; border-radius: 4px; height: 8px; overflow: hidden;">
                                        <div style="background: {cat_color}; width: {bar_width}%; height: 100%; border-radius: 4px;"></div>
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)
                            
                            # === DETECTION VENDORS ===
                            st.markdown("##### Security Vendor Detections")
                            
                            results = attrs.get('last_analysis_results', {})
                            if results:
                                # Group by result type
                                malicious_vendors = []
                                suspicious_vendors = []
                                other_vendors = []
                                
                                for vendor, result in results.items():
                                    result_val = result.get('result', 'unrated')
                                    method = result.get('method', '')
                                    category = result.get('category', '')
                                    
                                    vendor_info = {
                                        'name': vendor,
                                        'result': result_val,
                                        'method': method,
                                        'category': category
                                    }
                                    
                                    if result_val == 'malicious':
                                        malicious_vendors.append(vendor_info)
                                    elif result_val == 'suspicious':
                                        suspicious_vendors.append(vendor_info)
                                    else:
                                        other_vendors.append(vendor_info)
                                
                                
                                # Show malicious vendors first
                                if malicious_vendors:
                                    st.markdown(f"""
                                    <div style="background: rgba(248, 81, 73, 0.1); border-left: 3px solid #f85149; padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                                        <div style="color: #f85149; font-weight: 600; margin-bottom: 0.75rem;">🚫 Malicious ({len(malicious_vendors)})</div>
                                    """, unsafe_allow_html=True)
                                    
                                    for v in malicious_vendors[:8]:
                                        st.markdown(f"""
                                        <div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid #30363d;">
                                            <span style="color: #c9d1d9;">{v['name']}</span>
                                            <span style="color: #f85149; font-weight: 500;">{v['result']}</span>
                                        </div>
                                        """, unsafe_allow_html=True)
                                    st.markdown("</div>", unsafe_allow_html=True)
                                
                                if suspicious_vendors:
                                    st.markdown(f"""
                                    <div style="background: rgba(210, 153, 34, 0.1); border-left: 3px solid #d29922; padding: 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0;">
                                        <div style="color: #d29922; font-weight: 600; margin-bottom: 0.75rem;">⚠️ Suspicious ({len(suspicious_vendors)})</div>
                                    """, unsafe_allow_html=True)
                                    
                                    for v in suspicious_vendors[:5]:
                                        st.markdown(f"""
                                        <div style="display: flex; justify-content: space-between; padding: 0.4rem 0; border-bottom: 1px solid #30363d;">
                                            <span style="color: #c9d1d9;">{v['name']}</span>
                                            <span style="color: #d29922; font-weight: 500;">{v['result']}</span>
                                        </div>
                                        """, unsafe_allow_html=True)
                                    st.markdown("</div>", unsafe_allow_html=True)
                                
                                # Network info
                                st.markdown("##### Network Information")
                                
                                raw_network = attrs.get('network', {})
                                if isinstance(raw_network, dict):
                                    network = raw_network
                                    asn = network.get('asn', 'Unknown')
                                    as_owner = network.get('as_owner', 'Unknown')
                                    network_country = network.get('country', 'Unknown')
                                else:
                                    asn = str(raw_network) if raw_network else 'Unknown'
                                    as_owner = 'Unknown'
                                    network_country = 'Unknown'
                                
                                col1, col2, col3 = st.columns(3)
                                with col1:
                                    st.metric("ASN", asn)
                                with col2:
                                    st.metric("AS Owner", as_owner[:20] if len(as_owner) > 20 else as_owner)
                                with col3:
                                    st.metric("Country", network_country)
                                
                                # Last analysis info
                                last_analysis = attrs.get('last_analysis_date', 'Unknown')
                                st.caption(f"Last analyzed: {last_analysis}")
                                
                        elif response.status_code == 404:
                            # No data - show clean "not found" UI
                            st.markdown(f"""
                            <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid #30363d; border-radius: 12px; padding: 2rem; margin: 1rem 0; text-align: center;">
                                <div style="font-size: 3rem; margin-bottom: 1rem;">🔍</div>
                                <div style="font-size: 1.25rem; font-weight: 600; color: #fff; margin-bottom: 0.5rem;">{selected_ip}</div>
                                <div style="color: #8b949e;">No security vendor flagged this IP as malicious</div>
                                <div style="color: #6e7681; font-size: 0.85rem; margin-top: 1rem;">This IP has not been observed in any malicious activity dataset</div>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.error(f"API Error: {response.status_code}")
                    except Exception as e:
                        st.error(f"Error: {str(e)}")
        else:
            st.info("No IP addresses found in anomalies")
    
    # MITRE ATT&CK Overview
    st.markdown("---")
    st.markdown("### MITRE ATT&CK Coverage")
    
    # MITRE tactics and techniques
    mitre_tactics = {
        "Reconnaissance": {"count": 0, "color": "#8b949e"},
        "Resource Development": {"count": 0, "color": "#8b949e"},
        "Initial Access": {"count": 0, "color": "#f85149"},
        "Execution": {"count": 0, "color": "#f85149"},
        "Persistence": {"count": 1, "color": "#f85149"},
        "Privilege Escalation": {"count": 1, "color": "#d29922"},
        "Defense Evasion": {"count": 0, "color": "#d29922"},
        "Credential Access": {"count": 3, "color": "#f85149"},
        "Discovery": {"count": 0, "color": "#d29922"},
        "Lateral Movement": {"count": 0, "color": "#d29922"},
        "Collection": {"count": 0, "color": "#a371f7"},
        "Command and Control": {"count": 0, "color": "#a371f7"},
        "Exfiltration": {"count": 1, "color": "#a371f7"},
        "Impact": {"count": 3, "color": "#f85149"},
    }
    
    # Create MITRE heatmap-style display
    cols = st.columns(7)
    for i, (tactic, data) in enumerate(mitre_tactics.items()):
        with cols[i % 7]:
            st.markdown(f"""
            <div style="background: {data['color']}20; border: 1px solid {data['color']}; border-radius: 8px; padding: 0.75rem; text-align: center; margin-bottom: 0.5rem;">
                <div style="font-size: 1.5rem; font-weight: 700; color: {data['color']};">{data['count']}</div>
                <div style="font-size: 0.65rem; color: #8b949e;">{tactic[:10]}</div>
            </div>
            """, unsafe_allow_html=True)
    
    # Threat indicators summary
    st.markdown("---")
    st.markdown("### Threat Indicators Summary")
    
    # Calculate counts properly
    brute_force_count = sum(1 for orig_idx, r in detected_anomalies if df.iloc[orig_idx].get('login_failure_count', 0) > 5)
    account_takeover_count = sum(1 for orig_idx, r in detected_anomalies if df.iloc[orig_idx].get('unique_ips', 0) > 3)
    exfil_count = sum(1 for orig_idx, r in detected_anomalies if df.iloc[orig_idx].get('bytes_sent', 0) > 30000)
    dos_count = sum(1 for orig_idx, r in detected_anomalies if df.iloc[orig_idx].get('request_rate', 0) > 50)
    
    # Create summary table
    threat_indicators = [
        {"Type": "Brute Force", "Count": brute_force_count, "Severity": "HIGH", "MITRE": "T1110"},
        {"Type": "Account Takeover", "Count": account_takeover_count, "Severity": "HIGH", "MITRE": "T1078"},
        {"Type": "Data Exfiltration", "Count": exfil_count, "Severity": "CRITICAL", "MITRE": "T1041"},
        {"Type": "DoS Activity", "Count": dos_count, "Severity": "MEDIUM", "MITRE": "T1498"},
    ]
    
    for indicator in threat_indicators:
        severity_color = "#f85149" if indicator['Severity'] == 'CRITICAL' else "#d29922" if indicator['Severity'] == 'HIGH' else "#a371f7"
        st.markdown(f"""
        <div style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 0.5rem;">
            <span style="color: {severity_color}; font-weight: 600; min-width: 80px;">{indicator['Severity']}</span>
            <span style="flex: 1; font-weight: 500;">{indicator['Type']}</span>
            <span style="color: #8b949e;">{indicator['Count']} events</span>
            <span style="font-family: monospace; color: #58a6ff;">{indicator['MITRE']}</span>
        </div>
        """, unsafe_allow_html=True)


def render_incident_response_section(df, detected_anomalies, results):
    st.markdown('<h1 class="page-title">Incident Response</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Escalation, evidence collection, playbooks, and reporting</p>', unsafe_allow_html=True)
    
    if 'escalated_incidents' not in st.session_state:
        st.session_state.escalated_incidents = []
    if 'evidence_collection' not in st.session_state:
        st.session_state.evidence_collection = {}
    if 'playbook_history' not in st.session_state:
        st.session_state.playbook_history = []
    
    tab1, tab2, tab3, tab4 = st.tabs([
        "🚀 One-Click Escalation", 
        "🔍 Evidence Collection", 
        "📋 Playbook Suggestions", 
        "📄 Report Generation"
    ])
    
    with tab1:
        st.markdown("### One-Click Incident Escalation")
        st.markdown("Escalate detected anomalies to incident tickets with a single click")
        
        if not detected_anomalies:
            st.info("No anomalies detected to escalate")
        else:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                incident_type = st.selectbox(
                    "Incident Type",
                    ["Suspected Breach", "Malware Detection", "Data Exfiltration", 
                     "Credential Compromise", "DDoS Attack", "Insider Threat", "Other"]
                )
            
            with col2:
                priority = st.selectbox(
                    "Priority",
                    ["P1 - Critical", "P2 - High", "P3 - Medium", "P4 - Low"]
                )
            
            st.markdown("#### Select Anomalies to Escalate")
            
            selected_incidents = []
            
            for idx, (orig_idx, r) in enumerate(detected_anomalies[:10]):
                row = df.iloc[orig_idx]
                
                col_a, col_b, col_c = st.columns([1, 4, 2])
                
                with col_a:
                    escalate = st.checkbox(
                        f"Escalate #{idx+1}",
                        key=f"escalate_{orig_idx}",
                        value=False
                    )
                
                with col_b:
                    severity_color = "#f85149" if r['severity'] == 'CRITICAL' else "#d29922" if r['severity'] == 'HIGH' else "#58a6ff"
                    st.markdown(f"""
                    <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem; background: #161b22; border-radius: 6px;">
                        <span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600;">
                            {r['severity']}
                        </span>
                        <span style="color: #c9d1d9;">
                            {row.get('user', 'Unknown')} - {row.get('ip_address', 'N/A')}
                        </span>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col_c:
                    st.caption(f"Score: {r['anomaly_score']:.3f}")
                
                if escalate:
                    selected_incidents.append({
                        'id': f"INC-{len(st.session_state.escalated_incidents) + 1:04d}",
                        'type': incident_type,
                        'priority': priority,
                        'user': row.get('user', 'Unknown'),
                        'ip': row.get('ip_address', 'N/A'),
                        'severity': r['severity'],
                        'timestamp': row.get('timestamp', datetime.now()),
                        'anomaly_score': r['anomaly_score']
                    })
            
            if st.button("🚀 Escalate Selected to Incident", type="primary", use_container_width=True):
                if selected_incidents:
                    st.session_state.escalated_incidents.extend(selected_incidents)
                    st.success(f"Successfully escalated {len(selected_incidents)} incident(s)!")
                    
                    for inc in selected_incidents:
                        st.markdown(f"""
                        <div style="background: linear-gradient(135deg, #1a3a2e 0%, #162a20 100%); border: 1px solid #238636; border-radius; padding: : 8px1rem; margin: 0.5rem 0;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span style="color: #3fb950; font-weight: 700;">{inc['id']}</span>
                                    <span style="color: #c9d1d9; margin-left: 1rem;">{inc['type']}</span>
                                </div>
                                <span style="background: #238636; color: white; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem;">
                                    {inc['priority']}
                                </span>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.warning("Select at least one anomaly to escalate")
    
    with tab2:
        st.markdown("### Evidence Collection")
        st.markdown("Collect and preserve forensic evidence with chain of custody")
        
        if not detected_anomalies:
            st.info("No anomalies detected")
        else:
            evidence_id = st.text_input("Evidence ID", value=f"EV-{datetime.now().strftime('%Y%m%d%H%M%S')}")
            
            evidence_type = st.selectbox(
                "Evidence Type",
                ["Network Traffic Log", "Authentication Log", "Endpoint Telemetry", 
                 "Memory Dump", "Disk Image", "Full PCAP", "Email Header", "API Log"]
            )
            
            st.markdown("#### Anomalies for Evidence Collection")
            
            for idx, (orig_idx, r) in enumerate(detected_anomalies[:5]):
                row = df.iloc[orig_idx]
                
                with st.expander(f"Evidence for {row.get('user', 'Unknown')} - {r['severity']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**User Activity Summary**")
                        st.markdown(f"- Username: `{row.get('user', 'Unknown')}`")
                        st.markdown(f"- IP Address: `{row.get('ip_address', 'N/A')}`")
                        st.markdown(f"- Country: `{row.get('country', 'Unknown')}`")
                        st.markdown(f"- Timestamp: `{row.get('timestamp', 'N/A')}`")
                        st.markdown(f"- Login Failures: `{row.get('login_failure_count', 0)}`")
                        st.markdown(f"- Request Rate: `{row.get('request_rate', 0)}`/min")
                    
                    with col2:
                        st.markdown("**Forensic Indicators**")
                        st.markdown(f"- Unique IPs: `{row.get('unique_ips', 0)}`")
                        st.markdown(f"- Error Rate: `{row.get('error_rate', 0):.1%}`")
                        st.markdown(f"- Bytes Sent: `{row.get('bytes_sent', 0):,}`")
                        st.markdown(f"- Business Hours: `{row.get('is_business_hours', 0)}`")
                        st.markdown(f"- Anomaly Score: `{r['anomaly_score']:.3f}`")
                    
                    preserve_evidence = st.checkbox(
                        f"Preserve evidence for {row.get('user', 'Unknown')}",
                        key=f"preserve_{orig_idx}"
                    )
                    
                    if preserve_evidence:
                        if evidence_id not in st.session_state.evidence_collection:
                            st.session_state.evidence_collection[evidence_id] = []
                        
                        st.session_state.evidence_collection[evidence_id].append({
                            'user': row.get('user', 'Unknown'),
                            'ip': row.get('ip_address', 'N/A'),
                            'timestamp': str(row.get('timestamp', 'N/A')),
                            'severity': r['severity'],
                            'type': evidence_type,
                            'collected_at': datetime.now().isoformat()
                        })
            
            st.markdown("#### Collected Evidence")
            
            if st.session_state.evidence_collection:
                for eid, items in st.session_state.evidence_collection.items():
                    st.markdown(f"""
                    <div style="background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin: 0.5rem 0;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                            <span style="color: #58a6ff; font-weight: 700; font-family: monospace;">{eid}</span>
                            <span style="color: #8b949e; font-size: 0.85rem;">{len(items)} items collected</span>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    for item in items:
                        st.markdown(f"- **{item['user']}** ({item['ip']}) - {item['severity']}", unsafe_allow_html=True)
                    
                    st.markdown("</div>", unsafe_allow_html=True)
            else:
                st.info("No evidence collected yet")

    with tab3:
        st.markdown("### Playbook Suggestions")
        st.markdown("AI-recommended response playbooks based on detected threats")
        
        playbook_templates = {
            "credential_compromise": {
                "name": "Credential Compromise Response",
                "steps": [
                    "1. Immediately revoke active sessions for affected user",
                    "2. Force password reset for compromised account",
                    "3. Enable MFA if not already active",
                    "4. Review and block IP addresses used in attack",
                    "5. Check for lateral movement from compromised credentials",
                    "6. Notify user and security team",
                    "7. Preserve authentication logs for forensics"
                ],
                "automation": ["Auto-revoke sessions", "Auto-block attacker IPs", "Auto-enable MFA"]
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Response",
                "steps": [
                    "1. Isolate affected systems from network",
                    "2. Identify data scope and sensitivity",
                    "3. Block external destinations involved",
                    "4. Preserve firewall and proxy logs",
                    "5. Engage legal/compliance team",
                    "6. Document incident timeline"
                ],
                "automation": ["Auto-isolate endpoints", "Auto-block destinations", "Auto-alert DLP"]
            },
            "malware_c2": {
                "name": "Malware C2 Response",
                "steps": [
                    "1. Block C2 communication at firewall",
                    "2. Quarantine infected endpoint",
                    "3. Capture memory for forensics",
                    "4. Scan for additional infected systems",
                    "5. Update detection rules",
                    "6. Threat intelligence sharing"
                ],
                "automation": ["Auto-block C2 domains", "Auto-quarantine endpoint", "Auto-scan network"]
            },
            "brute_force": {
                "name": "Brute Force Attack Response",
                "steps": [
                    "1. Block attacking IP addresses",
                    "2. Temporarily lock affected accounts",
                    "3. Review successful login attempts",
                    "4. Implement stricter rate limiting",
                    "5. Enable enhanced monitoring"
                ],
                "automation": ["Auto-block attackers", "Auto-lock accounts", "Auto-notify SOC"]
            },
            "ddos": {
                "name": "DDoS Mitigation",
                "steps": [
                    "1. Enable DDoS protection measures",
                    "2. Rate limit at edge firewall",
                    "3. Scale infrastructure if possible",
                    "4. Coordinate with ISP/CDN",
                    "5. Document attack patterns"
                ],
                "automation": ["Auto-enable mitigation", "Auto-scale", "Auto-notify"]
            }
        }
        
        if not detected_anomalies:
            st.info("Run detection first to get playbook suggestions")
        else:
            attack_profile = []
            
            for orig_idx, r in detected_anomalies[:10]:
                row = df.iloc[orig_idx]
                
                if row.get('login_failure_count', 0) > 5:
                    attack_profile.append("brute_force")
                if row.get('unique_ips', 0) > 3:
                    attack_profile.append("credential_compromise")
                if row.get('bytes_sent', 0) > 30000:
                    attack_profile.append("data_exfiltration")
                if row.get('request_rate', 0) > 50:
                    attack_profile.append("ddos")
            
            attack_profile = list(set(attack_profile))[:3]
            
            if not attack_profile:
                attack_profile = ["brute_force"]
            
            for attack in attack_profile:
                if attack in playbook_templates:
                    playbook = playbook_templates[attack]
                    
                    st.markdown(f"""
                    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; margin: 1rem 0;">
                        <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                            <div style="width: 50px; height: 50px; background: #238636; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem;">
                                📋
                            </div>
                            <div>
                                <div style="font-size: 1.25rem; font-weight: 700; color: #fff;">{playbook['name']}</div>
                                <div style="color: #8b949e; font-size: 0.85rem;">Recommended playbook based on detected activity</div>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("#### Response Steps")
                    for step in playbook['steps']:
                        st.markdown(f"""
                        <div style="display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.5rem 0; border-bottom: 1px solid #21262d;">
                            <span style="color: #3fb950; font-weight: 600;">▸</span>
                            <span style="color: #c9d1d9;">{step}</span>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    st.markdown("#### Available Automations")
                    for auto in playbook['automation']:
                        st.markdown(f"""
                        <span style="display: inline-block; background: #23863620; border: 1px solid #238636; color: #3fb950; padding: 4px 12px; border-radius: 16px; font-size: 0.85rem; margin: 4px;">
                            ⚡ {auto}
                        </span>
                        """, unsafe_allow_html=True)
                    
                    if st.button(f"Apply {playbook['name']}", key=f"apply_{attack}", use_container_width=True):
                        st.session_state.playbook_history.append({
                            'playbook': playbook['name'],
                            'applied_at': datetime.now().isoformat(),
                            'attack_type': attack
                        })
                        st.success(f"Playbook '{playbook['name']}' applied!")
                    
                    st.markdown("</div>", unsafe_allow_html=True)

    with tab4:
        st.markdown("### Report Generation")
        st.markdown("Generate professional incident reports for stakeholders")
        
        if 'incident_report' not in st.session_state:
            st.session_state.incident_report = {}
        
        col1, col2 = st.columns(2)
        
        with col1:
            report_type = st.selectbox(
                "Report Type",
                ["Executive Summary", "Technical Incident Report", "Threat Analysis Report", 
                 "Compliance Report", "Post-Incident Review"]
            )
        
        with col2:
            report_format = st.selectbox(
                "Format",
                ["HTML", "Markdown", "JSON", "PDF-style"]
            )
        
        include_sections = st.multiselect(
            "Include Sections",
            ["Executive Summary", "Timeline of Events", "Affected Systems", "Root Cause Analysis",
             "Impact Assessment", "MITRE ATT&CK Mapping", "Evidence Summary", "Recommendations"],
            default=["Executive Summary", "Timeline of Events", "Affected Systems", "Recommendations"]
        )
        
        if st.button("📄 Generate Report", type="primary", use_container_width=True):
            report_data = {
                'type': report_type,
                'format': report_format,
                'generated_at': datetime.now().isoformat(),
                'analyst': 'SOC Analyst',
                'total_incidents': len(detected_anomalies),
                'sections': include_sections
            }
            
            critical = sum(1 for _, r in detected_anomalies if r['severity'] == 'CRITICAL')
            high = sum(1 for _, r in detected_anomalies if r['severity'] == 'HIGH')
            
            report_content = f"""# {report_type}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Analyst: SOC Analyst

## Executive Summary
- Total Anomalies Detected: {len(detected_anomalies)}
- Critical: {critical}
- High: {high}

"""
            
            if "Timeline of Events" in include_sections:
                report_content += "## Timeline of Events\n"
                for idx, (orig_idx, r) in enumerate(detected_anomalies[:5]):
                    row = df.iloc[orig_idx]
                    report_content += f"- {row.get('timestamp', 'N/A')}: {r['severity']} - {row.get('user', 'Unknown')} from {row.get('ip_address', 'N/A')}\n"
                report_content += "\n"
            
            if "Affected Systems" in include_sections:
                report_content += "## Affected Systems\n"
                users = set()
                ips = set()
                for orig_idx, r in detected_anomalies[:10]:
                    row = df.iloc[orig_idx]
                    users.add(row.get('user', 'Unknown'))
                    ips.add(row.get('ip_address', 'N/A'))
                for u in users:
                    report_content += f"- User: {u}\n"
                for ip in ips:
                    report_content += f"- IP: {ip}\n"
                report_content += "\n"
            
            if "MITRE ATT&CK Mapping" in include_sections:
                report_content += """## MITRE ATT&CK Coverage
- T1078: Valid Accounts (Credential Access)
- T1110: Brute Force (Credential Access)
- T1048: Exfiltration Over Alternative Protocol (Exfiltration)
- T1498: Denial of Service (Impact)

"""
            
            if "Recommendations" in include_sections:
                report_content += """## Recommendations
1. Implement stricter MFA policies for high-risk users
2. Enhance monitoring for after-hours activity
3. Block known malicious IP ranges
4. Conduct security awareness training
5. Review and update detection rules

"""
            
            st.session_state.incident_report = {
                'content': report_content,
                'data': report_data
            }
        
        if st.session_state.incident_report.get('content'):
            report_content = st.session_state.incident_report['content']
            
            st.markdown("#### Generated Report Preview")
            
            escaped_content = report_content.replace('#', '<h3>').replace('\n', '<br>')
            st.markdown(f"""
            <div style="background: #ffffff; color: #1f2328; padding: 2rem; border-radius: 8px; font-family: 'JetBrains Mono', monospace; max-height: 500px; overflow-y: auto;">
                {escaped_content}
            </div>
            """, unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.download_button(
                    label="📥 Download Report",
                    data=report_content,
                    file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
            
            with col2:
                if st.button("📋 Copy to Clipboard", use_container_width=True):
                    st.success("Report copied to clipboard!")


def render_portfolio_section():
    st.markdown('<h1 class="page-title">Portfolio Mode</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Demo Mode, Tutorials, and Export for your portfolio</p>', unsafe_allow_html=True)
    
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Demo Mode", "📚 Live Tutorial", "📸 Screenshot Export", "🐳 Docker Deploy"])
    
    with tab1:
        st.markdown("### 🎯 Interactive Attack Scenario Demos")
        st.markdown("Walk through realistic attack scenarios for presentations")
        
        if 'demo_state' not in st.session_state:
            st.session_state.demo_state = {'step': 0, 'scenario': None}
        
        scenario = st.selectbox(
            "Select Attack Scenario",
            ["Brute Force Attack", "Credential Stuffing", "Data Exfiltration", "DDoS Attack", "Lateral Movement"]
        )
        
        demo_scenarios = {
            "Brute Force Attack": {
                "description": "Watch how our system detects a brute force attack in real-time",
                "steps": [
                    {"title": "Step 1: Reconnaissance", "content": "Attacker scans for valid usernames using common patterns"},
                    {"title": "Step 2: Password Spraying", "content": "Attacker tries common passwords across multiple accounts"},
                    {"title": "Step 3: Account Lockout", "content": "System detects unusual login failure patterns"},
                    {"title": "Step 4: Alert Generated", "content": "SOC Sentinel flags the activity as anomalous"},
                    {"title": "Step 5: SHAP Explanation", "content": "AI explains: 'login_failure_count' was the key indicator"}
                ]
            },
            "Credential Stuffing": {
                "description": "See how we identify credential stuffing attacks",
                "steps": [
                    {"title": "Step 1: Stolen Credentials", "content": "Attacker uses compromised credentials from data breach"},
                    {"title": "Step 2: Multi-IP Login Attempts", "content": "Same credentials tried from different IP addresses"},
                    {"title": "Step 3: Geographic Anomaly", "content": "Impossible travel - logins from distant locations"},
                    {"title": "Step 4: Anomaly Detection", "content": "Isolation Forest flags unusual user behavior"},
                    {"title": "Step 5: Threat Intel Lookup", "content": "IP checked against known malicious sources"}
                ]
            },
            "Data Exfiltration": {
                "description": "Demonstrate detection of data exfiltration attempts",
                "steps": [
                    {"title": "Step 1: Baseline Behavior", "content": "System learns normal data transfer patterns per user"},
                    {"title": "Step 2: Unusual Volume", "content": "Large data transfer detected outside business hours"},
                    {"title": "Step 3: Destination Analysis", "content": "External IP analyzed for malicious activity"},
                    {"title": "Step 4: Severity Scoring", "content": "High anomaly score triggers critical alert"},
                    {"title": "Step 5: Response Playbook", "content": "Recommended containment actions displayed"}
                ]
            },
            "DDoS Attack": {
                "description": "Watch volumetric attack detection in action",
                "steps": [
                    {"title": "Step 1: Traffic Spike", "content": "Sudden increase in request rate detected"},
                    {"title": "Step 2: Pattern Analysis", "content": "Requests show attack signature patterns"},
                    {"title": "Step 3: Geographic Distribution", "content": "Attack traffic from multiple countries"},
                    {"title": "Step 4: Auto-Escalation", "content": "Incident ticket created automatically"},
                    {"title": "Step 5: Mitigation Suggested", "content": "Rate limiting and blocking recommended"}
                ]
            },
            "Lateral Movement": {
                "description": "See detection of privilege escalation and lateral movement",
                "steps": [
                    {"title": "Step 1: Initial Access", "content": "Compromised credential used for initial login"},
                    {"title": "Step 2: Privilege Escalation", "content": "Unusual admin access attempts detected"},
                    {"title": "Step 3: Multiple System Access", "content": "User accessing systems outside normal scope"},
                    {"title": "Step 4: Behavioral Analysis", "content": "ML model identifies anomalous access patterns"},
                    {"title": "Step 5: MITRE Mapping", "content": "Attack mapped to T1021 - Lateral Movement"}
                ]
            }
        }
        
        current_demo = demo_scenarios.get(scenario, demo_scenarios["Brute Force Attack"])
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border: 1px solid #30363d; border-radius: 12px; padding: 1.5rem; margin: 1rem 0;">
            <div style="font-size: 1.1rem; font-weight: 600; color: #fff; margin-bottom: 0.5rem;">
                {scenario}
            </div>
            <div style="color: #8b949e; font-size: 0.9rem;">
                {current_demo['description']}
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        step = st.slider("Demo Step", 0, len(current_demo['steps']) - 1, st.session_state.demo_state.get('step', 0))
        st.session_state.demo_state['step'] = step
        
        current_step = current_demo['steps'][step]
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.markdown(f"""
            <div style="background: #161b22; border-left: 4px solid #58a6ff; padding: 1.5rem; border-radius: 0 8px 8px 0; margin: 1rem 0;">
                <div style="color: #58a6ff; font-weight: 700; font-size: 1.25rem; margin-bottom: 0.75rem;">
                    {current_step['title']}
                </div>
                <div style="color: #c9d1d9; font-size: 1rem; line-height: 1.6;">
                    {current_step['content']}
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div style="text-align: center; padding: 2rem 1rem;">
                <div style="font-size: 3rem; font-weight: 700; color: #58a6ff;">{step + 1}</div>
                <div style="color: #8b949e; font-size: 0.85rem;">of {len(current_demo['steps'])}</div>
            </div>
            """, unsafe_allow_html=True)
        
        col_prev, col_next = st.columns(2)
        
        with col_prev:
            if st.button("◀ Previous Step", use_container_width=True, disabled=step == 0):
                st.session_state.demo_state['step'] = step - 1
                st.rerun()
        
        with col_next:
            if st.button("Next Step ▶", use_container_width=True, disabled=step == len(current_demo['steps']) - 1):
                st.session_state.demo_state['step'] = step + 1
                st.rerun()
        
        st.markdown("---")
        
        col_full, col_end = st.columns([3, 1])
        with col_full:
            st.info("💡 **Tip for presentations**: Use the slider to navigate through each step, explaining the detection logic at each stage.")
        with col_end:
            if st.button("▶ Run Full Demo", type="primary", use_container_width=True):
                st.balloons()
                st.success("Demo mode activated! This would auto-run through all steps in presentation mode.")
    
    with tab2:
        st.markdown("### 📚 Interactive Tutorial")
        st.markdown("Learn how to use SOC Sentinel with step-by-step explanations")
        
        tutorial_sections = [
            {
                "title": "1. Dashboard Overview",
                "content": """
                The main dashboard shows real-time security metrics:
                - **Total Events**: Number of log events analyzed
                - **Anomalies Detected**: Suspicious activities flagged by AI
                - **Severity Breakdown**: Critical, High, Medium alerts
                - **Anomaly Score**: How suspicious each event is (0-1 scale)
                """,
                "icon": "📊"
            },
            {
                "title": "2. SHAP Explainability",
                "content": """
                SHAP (SHapley Additive exPlanations) explains why AI flagged an alert:
                - **Force Plots**: Visual explanation of feature contributions
                - **Waterfall Charts**: Step-by-step feature impact
                - **Feature Importance**: Which features matter most
                
                This is crucial for SOC analysts to understand and justify decisions.
                """,
                "icon": "🧠"
            },
            {
                "title": "3. Threat Intelligence",
                "content": """
                Integration with VirusTotal for IP reputation:
                - Look up any suspicious IP
                - See detection rates across 70+ vendors
                - View detailed analysis results
                - Check ASN and geographic data
                
                Skills: OSINT, threat intelligence platforms
                """,
                "icon": "🔍"
            },
            {
                "title": "4. Incident Response",
                "content": """
                Full incident response workflow:
                - **Escalation**: One-click to create incident tickets
                - **Evidence Collection**: Preserve forensic data
                - **Playbooks**: Recommended response procedures
                - **Reports**: Generate stakeholder documentation
                
                Skills: IR workflow, documentation, SOAR
                """,
                "icon": "🚨"
            },
            {
                "title": "5. MITRE ATT&CK",
                "content": """
                Threats are mapped to MITRE ATT&CK framework:
                - Understand attacker tactics and techniques
                - See coverage across kill chain stages
                - Improve detection rules based on gaps
                
                Skills: Threat modeling, defense planning
                """,
                "icon": "🎯"
            }
        ]
        
        tutorial_idx = st.radio(
            "Tutorial Sections",
            range(len(tutorial_sections)),
            format_func=lambda x: f"{tutorial_sections[x]['icon']} {tutorial_sections[x]['title']}"
        )
        
        current_tutorial = tutorial_sections[tutorial_idx]
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1a2a1a 0%, #162116 100%); border: 1px solid #238636; border-radius: 12px; padding: 2rem; margin: 1rem 0;">
            <div style="font-size: 1.5rem; font-weight: 700; color: #fff; margin-bottom: 1rem;">
                {current_tutorial['icon']} {current_tutorial['title']}
            </div>
            <div style="color: #c9d1d9; font-size: 1rem; line-height: 1.8; white-space: pre-line;">
                {current_tutorial['content']}
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        col_prev_t, col_next_t = st.columns(2)
        
        with col_prev_t:
            if st.button("◀ Previous", use_container_width=True, disabled=tutorial_idx == 0):
                st.rerun()
        
        with col_next_t:
            if st.button("Next ▶", use_container_width=True, disabled=tutorial_idx == len(tutorial_sections) - 1):
                st.rerun()
        
        st.markdown("---")
        
        st.markdown("#### 📋 Skills Demonstrated")
        
        skills = [
            ("Machine Learning", "Isolation Forest, SHAP for anomaly detection and explainability"),
            ("Threat Intelligence", "VirusTotal API integration, OSINT"),
            ("Incident Response", "Escalation workflows, evidence collection, playbooks"),
            ("Security Analysis", "MITRE ATT&CK, detection rules, KQL queries"),
            ("DevOps", "Docker deployment, CI/CD readiness"),
            ("Communication", "Report generation, stakeholder documentation")
        ]
        
        for skill, desc in skills:
            st.markdown(f"""
            <div style="display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: #161b22; border-radius: 8px; margin: 0.5rem 0;">
                <span style="color: #3fb950; font-weight: 600; min-width: 150px;">{skill}</span>
                <span style="color: #8b949e;">{desc}</span>
            </div>
            """, unsafe_allow_html=True)
    
    with tab3:
        st.markdown("### 📸 Blog-Ready Screenshots")
        st.markdown("Export clean, professional screenshots for your portfolio")
        
        st.markdown("#### Recommended Screenshots")
        
        screenshot_guide = [
            {"section": "Overview Dashboard", "description": "Shows metrics and system status", "tips": "Use 'Overview' section with high anomaly count"},
            {"section": "SHAP Analysis", "description": "Feature importance and explanations", "tips": "Use waterfall plot for blog feature"},
            {"section": "Threat Intel", "description": "VirusTotal lookup results", "tips": "Select a known malicious IP"},
            {"section": "Incident Response", "description": "Report generation preview", "tips": "Generate an executive report"},
            {"section": "MITRE ATT&CK", "description": "Coverage heatmap", "tips": "Show comprehensive coverage"}
        ]
        
        for i, shot in enumerate(screenshot_guide):
            with st.expander(f"{shot['section']}"):
                st.markdown(f"**Description**: {shot['description']}")
                st.markdown(f"**Tips**: {shot['tips']}")
                
                if st.button(f"Navigate to {shot['section']}", key=f"nav_screenshot_{i}"):
                    st.session_state.current_section = shot['section'].lower().replace(" ", "_").replace("_dashboard", "").replace("analysis", "shap").replace("threat_intel", "threat_intel").replace("incident_response", "incident_response").replace("mitre_att&ck", "threats")
                    st.rerun()
        
        st.markdown("---")
        
        st.markdown("#### 🎨 Branding Tips")
        
        st.markdown("""
        <div style="background: #161b22; border-radius: 8px; padding: 1.5rem; margin: 1rem 0;">
            <div style="color: #c9d1d9; line-height: 1.8;">
                <strong style="color: #58a6ff;">For your portfolio/blog:</strong><br><br>
                • Use dark theme screenshots (already optimized!)<br>
                • Highlight the SHAP explainability - it's unique<br>
                • Show the full workflow: detection → investigation → response<br>
                • Include MITRE ATT&CK mapping for credibility<br>
                • Demo the VirusTotal integration<br>
                <br>
                <strong style="color: #3fb950;">Recommended blog post structure:</strong><br><br>
                1. Problem: SOC analyst shortage, need automation<br>
                2. Solution: ML-based anomaly detection with SHAP<br>
                3. Architecture: Streamlit + Isolation Forest + SHAP<br>
                4. Demo: Walk through attack scenarios<br>
                5. Results: Detection rates, false positive reduction<br>
                6. Future: SIEM integration, more ML models
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("📥 Export Portfolio Summary", type="primary", use_container_width=True):
            portfolio_summary = """# SOC Sentinel - Security Operations Center Anomaly Detection

## Project Overview
AI-powered SOC anomaly detection dashboard with full explainability

## Features
- Real-time anomaly detection using Isolation Forest
- SHAP-based explainable AI
- VirusTotal threat intelligence integration
- MITRE ATT&CK framework mapping
- Incident response workflow
- Professional incident reporting

## Technical Stack
- Python/Streamlit
- Scikit-learn (Isolation Forest)
- SHAP for explainability
- VirusTotal API
- Plotly for visualizations

## Skills Demonstrated
- Machine Learning & AI
- Threat Intelligence
- Incident Response
- Security Analysis
- DevOps & Deployment
- Technical Communication

## Links
- GitHub: https://github.com/ekkonomics-1/soc-sentinel
- Live Demo: [Run locally with Docker]
"""
            st.download_button(
                label="📄 Download Portfolio Summary (Markdown)",
                data=portfolio_summary,
                file_name="SOC_Sentinel_Portfolio_Summary.md",
                mime="text/markdown",
                use_container_width=True
            )
    
    with tab4:
        st.markdown("### 🐳 Docker Deployment")
        st.markdown("Deploy SOC Sentinel with Docker - DevOps skills demonstrated")
        
        st.markdown("#### Quick Start")
        
        st.code("""# Pull and run the container
docker pull your-registry/soc-sentinel:latest
docker run -p 8501:8501 soc-sentinel:latest

# Or build from source
docker build -t soc-sentinel .
docker run -p 8501:8501 soc-sentinel""", language="bash")
        
        st.markdown("#### Docker Compose (Recommended)")
        
        st.code("""version: '3.8'
services:
  soc-sentinel:
    build: .
    ports:
      - "8501:8501"
    environment:
      - VT_API_KEY=${VT_API_KEY}
    volumes:
      - ./data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8501"]
      interval: 30s
      timeout: 10s
      retries: 3""", language="yaml")
        
        st.markdown("#### Kubernetes Deployment")
        
        st.code("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: soc-sentinel
spec:
  replicas: 2
  selector:
    matchLabels:
      app: soc-sentinel
  template:
    metadata:
      labels:
        app: soc-sentinel
    spec:
      containers:
      - name: soc-sentinel
        image: soc-sentinel:latest
        ports:
        - containerPort: 8501
        env:
        - name: VT_API_KEY
          valueFrom:
            secretKeyRef:
              name: vt-secrets
              key: api-key
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
""", language="yaml")
        
        st.markdown("#### Environment Variables")
        
        env_vars = [
            ("VT_API_KEY", "VirusTotal API key for threat intelligence"),
            ("LOG_LEVEL", "Logging level (INFO, DEBUG)"),
            ("CONTAMINATION", "Anomaly detection threshold (0.01-0.2)"),
        ]
        
        for var, desc in env_vars:
            st.markdown(f"- `{var}`: {desc}")
        
        st.markdown("#### CI/CD Pipeline Example")
        
        st.code("""# GitHub Actions
name: Deploy to Docker Hub

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker image
        run: docker build -t soc-sentinel:${{ github.sha }} .
      - name: Push to registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push soc-sentinel:${{ github.sha }}""", language="yaml")
        
        col_docker1, col_docker2 = st.columns(2)
        
        with col_docker1:
            if st.button("📦 Generate Dockerfile", use_container_width=True):
                dockerfile_content = """FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "src/dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
"""
                st.download_button(
                    label="📥 Download Dockerfile",
                    data=dockerfile_content,
                    file_name="Dockerfile",
                    mime="text/plain",
                    use_container_width=True
                )
        
        with col_docker2:
            st.info("💡 The Dockerfile is ready to use! Download and add to your project.")


def render_shap_section():
    st.markdown('<h1 class="page-title">SHAP Analysis</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Explainable AI - Why threats were detected</p>', unsafe_allow_html=True)
    
    if not st.session_state.shap_initialized or st.session_state.X_scaled is None:
        st.info("Run detection first to enable SHAP analysis")
        return
    
    try:
        global_imp = st.session_state.explainer.get_global_importance(
            st.session_state.X_scaled, st.session_state.available_features
        )
        ranked = global_imp.get("ranked_features", [])[:10]
        
        st.markdown("### Feature Importance")
        
        fig = go.Figure(go.Bar(
            x=[v for k, v in ranked],
            y=[FEATURE_LABELS.get(k, k) for k, v in ranked],
            orientation='h',
            marker=dict(color='#58a6ff')
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#8b949e"),
            xaxis=dict(title="% Contribution", gridcolor="rgba(48, 54, 61, 0.5)"),
            height=400,
            margin=dict(l=150, r=50, t=20, b=40)
        )
        st.plotly_chart(fig, use_container_width=True)
        
        st.markdown(f"**Top 3 features contribute {global_imp.get('top_3_contribution', 0):.1f}%** of detection")
        
    except Exception as e:
        st.error(f"SHAP analysis unavailable: {e}")


def render_settings_section():
    st.markdown('<h1 class="page-title">Settings</h1>', unsafe_allow_html=True)
    st.markdown('<p class="page-subtitle">Configure detection parameters</p>', unsafe_allow_html=True)
    
    st.markdown("### Model Configuration")
    
    cont = st.slider("Contamination", 0.01, 0.3, 0.05)
    trees = st.slider("Number of Trees", 50, 500, 200)
    
    st.markdown("### About")
    st.markdown("""
    **SOC Sentinel** - AI-Powered Threat Detection
    
    - Isolation Forest for anomaly detection
    - SHAP for explainable AI
    - Real-time monitoring
    """)


def create_dashboard():
    st.set_page_config(
        page_title="SOC Sentinel",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.markdown(SIDEBAR_CSS, unsafe_allow_html=True)
    init_session_state()
    
    if st.session_state.events_df is None:
        load_data(st.session_state.get('n_events', 2000))
        st.session_state.results = run_detection(st.session_state.events_df)
    
    df = st.session_state.events_df
    results = st.session_state.results
    
    if not results:
        st.error("Detection failed")
        return
    
    detected_anomalies = [(i, r) for i, r in enumerate(results) if r['is_anomaly']]
    
    create_sidebar()
    
    current = st.session_state.get('current_section', 'overview')
    
    with st.container():
        if current == "overview":
            render_overview_section(df, results, detected_anomalies)
        elif current == "threats":
            render_threats_section(df, detected_anomalies)
        elif current == "activity":
            render_activity_section(df, results)
        elif current == "users":
            render_users_section(df)
        elif current == "investigate":
            render_investigate_section(df, detected_anomalies)
        elif current == "rules":
            render_detection_rules_section(df, detected_anomalies)
        elif current == "query":
            render_query_search_section(df)
        elif current == "triage":
            render_triage_section(df, detected_anomalies)
        elif current == "timeline":
            render_timeline_section(df, detected_anomalies)
        elif current == "threat_intel":
            render_threat_intel_section(df, detected_anomalies)
        elif current == "incident_response":
            render_incident_response_section(df, detected_anomalies, results)
        elif current == "shap":
            render_shap_section()
        elif current == "portfolio":
            render_portfolio_section()
        elif current == "settings":
            render_settings_section()


if __name__ == "__main__":
    create_dashboard()
