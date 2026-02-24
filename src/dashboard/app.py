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
            ("shap", "SHAP Analysis", "psychology"),
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
        elif current == "shap":
            render_shap_section()
        elif current == "settings":
            render_settings_section()


if __name__ == "__main__":
    create_dashboard()
