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


FEATURE_COLUMNS = [
    "login_failure_count", "login_success_count", "unique_ips",
    "request_rate", "avg_response_time", "error_rate", "bytes_sent",
    "hour_of_day", "is_business_hours", "day_of_week", "is_weekend",
    "geo_countries_accessed"
]


def init_session_state():
    if 'data_loaded' not in st.session_state:
        st.session_state.simulator = get_simulator()
        st.session_state.threat_client = get_threat_client()
        st.session_state.feature_pipeline = get_feature_pipeline()
        st.session_state.detector = get_anomaly_detector(contamination=0.05)
        st.session_state.alert_manager = get_alert_manager()
        st.session_state.events_df = None
        st.session_state.results = []
        st.session_state.X_scaled = None
        st.session_state.data_loaded = True


def load_data(n_events: int = 2000):
    simulator = st.session_state.simulator
    events_df = simulator.generate_combined_events(n=n_events)
    st.session_state.events_df = events_df
    return events_df


def run_detection(df: pd.DataFrame):
    available_features = [col for col in FEATURE_COLUMNS if col in df.columns]
    
    if not available_features:
        st.error("No feature columns found in data!")
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
    
    return results


def generate_explanation(row, anomaly_score):
    reasons = []
    
    if row.get('login_failure_count', 0) > 10:
        reasons.append(f"High login failures ({row['login_failure_count']})")
    if row.get('unique_ips', 0) > 5:
        reasons.append(f"Multiple unique IPs ({row['unique_ips']})")
    if row.get('request_rate', 0) > 100:
        reasons.append(f"Elevated request rate ({row['request_rate']})")
    if row.get('error_rate', 0) > 0.3:
        reasons.append(f"High error rate ({row['error_rate']:.1%})")
    if row.get('avg_response_time', 0) > 200:
        reasons.append(f"Slow response time ({row['avg_response_time']:.0f}ms)")
    if row.get('bytes_sent', 0) > 50000:
        reasons.append(f"Large data transfer ({row['bytes_sent']})")
    if row.get('is_business_hours', 1) == 0:
        reasons.append("Activity outside business hours")
    
    if reasons:
        return "Alert triggered by: " + ", ".join(reasons[:3])
    return f"Anomaly detected with score {anomaly_score:.2f}"


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
        
        if st.button("🔄 Regenerate Data & Detect"):
            st.session_state.events_df = None
            st.session_state.results = []
            st.rerun()

        st.divider()
        st.markdown("### 📊 Quick Stats")
        if st.session_state.events_df is not None:
            total = len(st.session_state.events_df)
            anomalies = st.session_state.events_df['is_anomaly'].sum()
            st.metric("Total Events", total)
            st.metric("True Anomalies", f"{anomalies} ({anomalies/total*100:.1f}%)")
            
            if st.session_state.results:
                detected = sum(1 for r in st.session_state.results if r['is_anomaly'])
                st.metric("Detected Anomalies", detected)

    if st.session_state.events_df is None:
        with st.spinner("Generating SOC data and running anomaly detection..."):
            load_data(n_events)
            st.session_state.results = run_detection(st.session_state.events_df)

    df = st.session_state.events_df
    results = st.session_state.results

    if not results:
        st.error("Detection failed. Check logs.")
        return

    tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🚨 Alerts", "🔍 Investigation", "📈 Analytics"])

    with tab1:
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("Total Events", len(df))

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
            st.subheader("Anomalies Over Time")
            df_copy = df.copy()
            df_copy['minute'] = df_copy['timestamp'].dt.floor('T')
            timeline = df_copy.groupby('minute')['is_anomaly'].sum().reset_index()
            fig = px.line(timeline, x='minute', y='is_anomaly', title="True Anomalies per Minute")
            fig.update_layout(xaxis_title="Time", yaxis_title="Anomaly Count")
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("Anomaly Score Distribution")
            scores = [r['anomaly_score'] for r in results]
            fig = px.histogram(x=scores, nbins=50, title="Model Anomaly Scores")
            fig.update_layout(xaxis_title="Anomaly Score", yaxis_title="Frequency")
            st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.subheader("🚨 Detected Alerts")

        detected_anomalies = [(i, r) for i, r in enumerate(results) if r['is_anomaly']]
        
        col1, col2 = st.columns([1, 3])
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )

        filtered_anomalies = detected_anomalies
        if severity_filter != "All":
            filtered_anomalies = [(i, r) for i, r in detected_anomalies if r['severity'] == severity_filter]

        if filtered_anomalies:
            st.write(f"Showing {len(filtered_anomalies)} alerts")
            
            for idx, (original_idx, r) in enumerate(filtered_anomalies[:20]):
                severity_color = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠",
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(r['severity'], "⚪")

                row = df.iloc[original_idx]
                
                with st.expander(f"{severity_color} Event {original_idx} - {r['severity']} (Score: {r['anomaly_score']:.2f})"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Alert Details:**")
                        st.write(f"- Severity: {r['severity']}")
                        st.write(f"- Anomaly Score: {r['anomaly_score']:.4f}")
                        st.write(f"- Confidence: {r['confidence']:.2f}")
                        st.write(f"- User: {row.get('user', 'N/A')}")
                        st.write(f"- Time: {row.get('timestamp', 'N/A')}")
                    
                    with col2:
                        st.markdown("**Key Features:**")
                        st.write(f"- Login Failures: {row.get('login_failure_count', 0)}")
                        st.write(f"- Unique IPs: {row.get('unique_ips', 0)}")
                        st.write(f"- Request Rate: {row.get('request_rate', 0)}")
                        st.write(f"- Error Rate: {row.get('error_rate', 0):.1%}")
                    
                    st.divider()
                    st.markdown("**💡 Explanation:**")
                    explanation = generate_explanation(row, r['anomaly_score'])
                    st.info(explanation)
        else:
            st.info(f"No alerts with severity: {severity_filter}")

    with tab3:
        st.subheader("🔍 Deep Investigation")

        if detected_anomalies:
            col1, col2 = st.columns([1, 2])
            
            with col1:
                selected_idx = st.selectbox(
                    "Select Anomaly Event",
                    range(len(detected_anomalies)),
                    format_func=lambda i: f"Event {detected_anomalies[i][0]} - Score: {detected_anomalies[i][1]['anomaly_score']:.2f}"
                )

            original_idx, selected = detected_anomalies[selected_idx]
            row = df.iloc[original_idx]

            with col2:
                st.metric("Anomaly Score", f"{selected['anomaly_score']:.4f}")
                st.metric("Severity", selected['severity'])

            st.divider()
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 📋 Event Details")
                for col in ['user', 'timestamp', 'hour_of_day', 'is_business_hours']:
                    if col in row.index:
                        st.write(f"**{col}:** {row[col]}")

            with col2:
                st.markdown("### 📊 Feature Values")
                for col in ['login_failure_count', 'login_success_count', 'unique_ips', 
                           'request_rate', 'avg_response_time', 'error_rate', 'bytes_sent']:
                    if col in row.index:
                        st.write(f"**{col}:** {row[col]}")

            st.divider()
            st.markdown("### 💡 AI Explanation")
            explanation = generate_explanation(row, selected['anomaly_score'])
            st.success(explanation)
            
            st.markdown("### 🔎 Feature Comparison (Event vs Average)")
            if st.session_state.X_scaled is not None:
                feature_avg = np.mean(st.session_state.X_scaled, axis=0)
                event_features = st.session_state.X_scaled[original_idx]
                
                comparison_df = pd.DataFrame({
                    'Feature': st.session_state.available_features,
                    'Event Value': event_features,
                    'Average': feature_avg,
                    'Deviation': event_features - feature_avg
                }).sort_values('Deviation', key=abs, ascending=False)
                
                st.dataframe(comparison_df.head(10), use_container_width=True)

        else:
            st.info("No anomalies detected to investigate")

    with tab4:
        st.subheader("📈 Analytics Dashboard")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Anomaly Rate by Hour")
            df_copy = df.copy()
            df_copy['hour'] = df_copy['timestamp'].dt.hour
            hourly = df_copy.groupby('hour')['is_anomaly'].agg(['mean', 'count']).reset_index()
            fig = px.bar(hourly, x='hour', y='mean', title="Anomaly Rate by Hour",
                        labels={'mean': 'Anomaly Rate', 'hour': 'Hour of Day'})
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("### Detection by Severity")
            severity_counts = {}
            for r in results:
                if r['is_anomaly']:
                    severity_counts[r['severity']] = severity_counts.get(r['severity'], 0) + 1
            
            if severity_counts:
                fig = px.pie(values=list(severity_counts.values()), 
                           names=list(severity_counts.keys()),
                           title="Alerts by Severity")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No alerts to display")

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Response Time Distribution")
            fig = px.histogram(
                df,
                x='avg_response_time',
                color='is_anomaly',
                title="Response Time: Normal vs Anomaly",
                barmode='overlay',
                labels={'is_anomaly': 'Is Anomaly'}
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("### Request Rate Distribution")
            fig = px.histogram(
                df,
                x='request_rate',
                color='is_anomaly',
                title="Request Rate: Normal vs Anomaly",
                barmode='overlay',
                labels={'is_anomaly': 'Is Anomaly'}
            )
            st.plotly_chart(fig, use_container_width=True)

        st.divider()

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### Top Users by Anomaly Count")
            user_anomalies = df.groupby('user')['is_anomaly'].sum().reset_index()
            user_anomalies = user_anomalies.sort_values('is_anomaly', ascending=False).head(10)
            fig = px.bar(user_anomalies, x='user', y='is_anomaly', 
                        title="Users with Most Anomalies",
                        labels={'is_anomaly': 'Anomaly Count', 'user': 'User'})
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.markdown("### Model Performance")
            y_true = df['is_anomaly'].values
            y_pred = np.array([1 if r['is_anomaly'] else 0 for r in results])
            
            tp = np.sum((y_true == 1) & (y_pred == 1))
            fp = np.sum((y_true == 0) & (y_pred == 1))
            tn = np.sum((y_true == 0) & (y_pred == 0))
            fn = np.sum((y_true == 1) & (y_pred == 0))
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            metrics_df = pd.DataFrame({
                'Metric': ['True Positives', 'False Positives', 'True Negatives', 'False Negatives', 
                          'Precision', 'Recall', 'F1 Score'],
                'Value': [int(tp), int(fp), int(tn), int(fn), f"{precision:.2%}", f"{recall:.2%}", f"{f1:.2%}"]
            })
            st.dataframe(metrics_df, use_container_width=True)

    st.divider()
    st.markdown("---")
    st.markdown("**SOC Sentinel** - AI-Powered Anomaly Detection System | [GitHub](https://github.com/ekkonomics-1/soc-sentinel)")


if __name__ == "__main__":
    create_dashboard()
