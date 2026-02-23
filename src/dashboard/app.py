import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestion.data_simulator import get_simulator
from src.ingestion.threat_client import get_threat_client
from src.features.feature_pipeline import get_feature_pipeline
from src.models.anomaly_detector import get_anomaly_detector, get_ensemble_detector
from src.explainability.explainer import get_explainer
from src.alerts.alert_manager import get_alert_manager


def init_session_state():
    if 'data_loaded' not in st.session_state:
        st.session_state.simulator = get_simulator()
        st.session_state.threat_client = get_threat_client()
        st.session_state.feature_pipeline = get_feature_pipeline()
        st.session_state.detector = get_anomaly_detector(contamination=0.05)
        st.session_state.explainer = get_explainer()
        st.session_state.alert_manager = get_alert_manager()
        st.session_state.events_df = None
        st.session_state.data_loaded = True


def load_data(n_events: int = 2000):
    simulator = st.session_state.simulator
    events_df = simulator.generate_combined_events(n=n_events)
    st.session_state.events_df = events_df
    return events_df


def run_detection(df: pd.DataFrame):
    pipeline = st.session_state.feature_pipeline
    detector = st.session_state.detector

    X = pipeline.fit_transform(df)
    if len(X) == 0:
        st.warning("No features extracted")
        return []

    detector.fit(X, pipeline.feature_names)
    results = detector.detect(X)

    return results


def create_dashboard():
    st.set_page_config(
        page_title="SOC Sentinel",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    init_session_state()

    st.title("🛡️ SOC Sentinel - Anomaly Detection Dashboard")
    st.markdown("### AI-Powered Security Operations Center with Explainable Alerts")

    with st.sidebar:
        st.header("⚙️ Configuration")
        n_events = st.slider("Number of Events", 500, 5000, 2000)
        contamination = st.slider("Anomaly Threshold", 0.01, 0.2, 0.05)
        st.session_state.detector.contamination = contamination

        if st.button("🔄 Regenerate Data"):
            load_data(n_events)
            st.rerun()

        st.divider()
        st.markdown("### 📊 Quick Stats")
        if st.session_state.events_df is not None:
            total = len(st.session_state.events_df)
            anomalies = st.session_state.events_df['is_anomaly'].sum()
            st.metric("Total Events", total)
            st.metric("Detected Anomalies", f"{anomalies} ({anomalies/total*100:.1f}%)")

    if st.session_state.events_df is None:
        with st.spinner("Loading data..."):
            load_data(n_events)

    results = run_detection(st.session_state.events_df)

    if results:
        for i, r in enumerate(results):
            if r['is_anomaly']:
                st.session_state.alert_manager.create_alert(
                    severity=r['severity'],
                    title=f"Anomaly Detected - {r['severity']}",
                    description=f"Anomaly score: {r['anomaly_score']:.2f}",
                    source="anomaly_detector",
                    metadata={"event_index": i, "confidence": r['confidence']}
                )

    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🚨 Alerts", "🔍 Investigation", "📈 Analytics"])

    with tab1:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Events", len(st.session_state.events_df))

        with col2:
            anomaly_count = sum(1 for r in results if r['is_anomaly'])
            st.metric("Anomalies Detected", anomaly_count)

        with col3:
            critical = sum(1 for r in results if r['severity'] == 'CRITICAL')
            st.metric("Critical Alerts", critical)

        with col4:
            avg_score = np.mean([r['anomaly_score'] for r in results])
            st.metric("Avg Anomaly Score", f"{avg_score:.2f}")

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Events Over Time")
            df = st.session_state.events_df.copy()
            df['minute'] = df['timestamp'].dt.floor('T')
            timeline = df.groupby('minute')['is_anomaly'].sum().reset_index()
            fig = px.line(timeline, x='minute', y='is_anomaly', title="Anomalies per Minute")
            fig.update_layout(xaxis_title="Time", ytitle="Anomaly Count")
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Anomaly Score Distribution")
            scores = [r['anomaly_score'] for r in results]
            fig = px.histogram(scores, nbins=50, title="Anomaly Score Histogram")
            fig.update_layout(xlabel="Anomaly Score", ylabel="Frequency")
            st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.subheader("🚨 Recent Alerts")

        alerts = st.session_state.alert_manager.get_alerts(limit=50)

        if alerts:
            for alert in alerts[:10]:
                severity_color = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(alert['severity'], "⚪")

                with st.expander(f"{severity_color} {alert['alert_id']} - {alert['severity']}"):
                    st.write(f"**Title:** {alert['title']}")
                    st.write(f"**Description:** {alert['description']}")
                    st.write(f"**Time:** {alert['timestamp']}")
                    st.write(f"**Status:** {alert['status']}")
        else:
            st.info("No alerts yet. Run detection to generate alerts.")

    with tab3:
        st.subheader("🔍 Alert Investigation")

        alert_options = [r for r in results if r['is_anomaly']]
        if alert_options:
            selected_idx = st.selectbox(
                "Select Anomaly to Investigate",
                range(len(alert_options)),
                format_func=lambda i: f"Anomaly {i} - Score: {alert_options[i]['anomaly_score']:.2f}"
            )

            selected = alert_options[selected_idx]

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("### Alert Details")
                st.write(f"**Severity:** {selected['severity']}")
                st.write(f"**Anomaly Score:** {selected['anomaly_score']:.4f}")
                st.write(f"**Confidence:** {selected['confidence']:.2f}")

            with col2:
                st.markdown("### Feature Values")
                event = st.session_state.events_df.iloc[selected.get('event_index', 0)] if 'event_index' in selected else st.session_state.events_df.iloc[0]
                feature_cols = ['login_failure_count', 'login_success_count', 'unique_ips',
 'request_rate', 'avg_response_time', 'error_rate                              ', 'bytes_sent']
                for col in feature_cols:
                    if col in event.index:
                        st.write(f"**{col}:** {event[col]}")

            st.divider()
            st.markdown("### 💡 Explanation")
            if selected.get('explanation'):
                st.success(selected['explanation'])
            else:
                st.info("This alert was triggered due to unusual pattern detection in the analyzed features.")
        else:
            st.info("No anomalies to investigate")

    with tab4:
        st.subheader("📈 Analytics")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Anomalies by Hour")
            df = st.session_state.events_df.copy()
            df['hour'] = df['timestamp'].dt.hour
            hourly = df.groupby('hour')['is_anomaly'].mean().reset_index()
            fig = px.bar(hourly, x='hour', y='is_anomaly', title="Anomaly Rate by Hour")
            fig.update_layout(xaxis_title="Hour of Day", ytitle="Anomaly Rate")
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("### Top Users by Anomaly Count")
            user_anomalies = st.session_state.events_df.groupby('user')['is_anomaly'].sum().reset_index()
            user_anomalies = user_anomalies.sort_values('is_anomaly', ascending=False).head(10)
            fig = px.bar(user_anomalies, x='user', y='is_anomaly', title="Top Users with Anomalies")
            fig.update_layout(xaxis_title="User", ytitle="Anomaly Count")
            st.plotly_chart(fig, use_container_width=True)

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Response Time Distribution")
            fig = px.histogram(
                st.session_state.events_df,
                x='avg_response_time',
                color='is_anomaly',
                title="Response Time by Anomaly Status",
                barmode='overlay'
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("### Request Rate Distribution")
            fig = px.histogram(
                st.session_state.events_df,
                x='request_rate',
                color='is_anomaly',
                title="Request Rate by Anomaly Status",
                barmode='overlay'
            )
            st.plotly_chart(fig, use_container_width=True)

    st.divider()
    st.markdown("---")
    st.markdown("**SOC Sentinel** - AI-Powered Anomaly Detection System")


if __name__ == "__main__":
    create_dashboard()
