import os
import sys
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import pandas as pd
import numpy as np
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.ingestion.data_simulator import get_simulator
from src.ingestion.threat_client import get_threat_client
from src.features.feature_pipeline import get_feature_pipeline
from src.models.anomaly_detector import get_anomaly_detector, get_ensemble_detector
from src.alerts.alert_manager import get_alert_manager
from src.explainability.explainer import get_explainer

app = Flask(__name__, static_folder='static')
CORS(app)

simulator = None
threat_client = None
feature_pipeline = None
detector = None
ensemble_detector = None
alert_manager = None
explainer = None
events_df = None
results = None
X_scaled = None
available_features = []
shap_initialized = False


def initialize_components(virustotal_key: str = None):
    global simulator, threat_client, feature_pipeline, detector
    global ensemble_detector, alert_manager, explainer
    
    simulator = get_simulator()
    
    default_key = "e4d4d6f32775ee354c6bd7bbe134f75469cccb582a1659d8572cb5ae8b4d1572"
    api_key = virustotal_key or os.getenv("VIRUSTOTAL_API_KEY") or default_key
    threat_client = get_threat_client(api_key)
    feature_pipeline = get_feature_pipeline()
    detector = get_anomaly_detector(contamination=0.05)
    ensemble_detector = get_ensemble_detector(contamination=0.05)
    alert_manager = get_alert_manager()
    explainer = get_explainer()


def run_detection(n_events=2000):
    global events_df, results, X_scaled, available_features, shap_initialized, simulator, detector, explainer
    
    if simulator is None:
        initialize_components()
    
    events_df = simulator.generate_combined_events(n=n_events)
    
    feature_columns = [
        "login_failure_count", "login_success_count", "unique_ips",
        "request_rate", "avg_response_time", "error_rate", "bytes_sent",
        "hour_of_day", "is_business_hours", "day_of_week", "is_weekend",
        "geo_countries_accessed"
    ]
    
    available_features = [col for col in feature_columns if col in events_df.columns]
    
    if not available_features:
        return []
    
    X = events_df[available_features].values.astype(float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    detector.fit(X_scaled, available_features)
    results = detector.detect(X_scaled)
    
    if not shap_initialized:
        explainer.initialize(X_scaled, available_features, detector.isolation_forest)
        shap_initialized = True
    
    return results


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


@app.route('/api/detect', methods=['POST'])
def detect():
    data = request.get_json() or {}
    n_events = data.get('n_events', 2000)
    
    results = run_detection(n_events)
    
    detected_anomalies = []
    for i, r in enumerate(results):
        if r['is_anomaly']:
            row = events_df.iloc[i]
            anomaly = {
                'index': i,
                'is_anomaly': r['is_anomaly'],
                'anomaly_score': r['anomaly_score'],
                'severity': r['severity'],
                'confidence': r['confidence'],
                'user': row.get('user', 'N/A'),
                'ip_address': row.get('ip_address', 'N/A'),
                'country': row.get('country', 'N/A'),
                'timestamp': str(row.get('timestamp', 'N/A')),
                'attack_type': row.get('attack_type', 'N/A'),
                'login_failure_count': int(row.get('login_failure_count', 0)),
                'login_success_count': int(row.get('login_success_count', 0)),
                'unique_ips': int(row.get('unique_ips', 0)),
                'request_rate': float(row.get('request_rate', 0)),
                'error_rate': float(row.get('error_rate', 0)),
                'avg_response_time': float(row.get('avg_response_time', 0)),
                'bytes_sent': int(row.get('bytes_sent', 0)),
                'hour_of_day': int(row.get('hour_of_day', 0)),
                'is_business_hours': int(row.get('is_business_hours', 0)),
                'geo_countries_accessed': int(row.get('geo_countries_accessed', 0))
            }
            detected_anomalies.append(anomaly)
            
            alert = alert_manager.create_alert(
                severity=r['severity'],
                title=f"Anomaly detected for {row.get('user', 'Unknown')}",
                description=f"Anomaly score: {r['anomaly_score']:.3f}",
                source="anomaly_detector",
                metadata=anomaly
            )
            
            if shap_initialized and X_scaled is not None:
                try:
                    explanations = explainer.explain(X_scaled[i:i+1], available_features)
                    if explanations:
                        explanation = explanations[0]
                        alert_manager.add_explanation(
                            alert.alert_id,
                            explanation.get('explanation', ''),
                            explanation.get('shap_values', {})
                        )
                except:
                    pass
    
    return jsonify({
        'success': True,
        'total_events': len(events_df),
        'anomalies_detected': len(detected_anomalies),
        'anomalies': detected_anomalies,
        'summary': {
            'critical': sum(1 for a in detected_anomalies if a['severity'] == 'CRITICAL'),
            'high': sum(1 for a in detected_anomalies if a['severity'] == 'HIGH'),
            'medium': sum(1 for a in detected_anomalies if a['severity'] == 'MEDIUM'),
            'low': sum(1 for a in detected_anomalies if a['severity'] == 'LOW')
        }
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    global alert_manager
    if alert_manager is None:
        initialize_components()
    
    severity = request.args.get('severity')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 100))
    
    alerts = alert_manager.get_alerts(severity=severity, status=status, limit=limit)
    stats = alert_manager.get_statistics()
    
    return jsonify({
        'alerts': alerts,
        'statistics': stats
    })


@app.route('/api/alerts/<alert_id>', methods=['PUT'])
def update_alert(alert_id):
    data = request.get_json()
    new_status = data.get('status')
    
    success = alert_manager.update_status(alert_id, new_status)
    
    return jsonify({'success': success})


@app.route('/api/explain/<int:index>', methods=['GET'])
def explain_anomaly(index):
    global explainer, shap_initialized, X_scaled
    if explainer is None:
        initialize_components()
    if not shap_initialized or X_scaled is None:
        return jsonify({'error': 'SHAP not initialized'}), 400
    
    try:
        X_single = X_scaled[index:index+1]
        
        waterfall = explainer.get_waterfall_data(X_single, 0, available_features)
        global_imp = explainer.get_global_importance(X_single, available_features)
        force_plot = explainer.get_force_plot_data(X_single, 0, available_features)
        
        return jsonify({
            'waterfall': waterfall,
            'global_importance': global_imp,
            'force_plot': force_plot
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/config', methods=['POST'])
def config():
    global threat_client
    data = request.get_json() or {}
    virustotal_key = data.get('virustotal_api_key')
    
    if virustotal_key:
        threat_client = get_threat_client(virustotal_key)
        return jsonify({'success': True, 'message': 'API key configured'})
    
    return jsonify({'success': False, 'message': 'No API key provided'})


@app.route('/api/threat-intel/<ip>', methods=['GET'])
def threat_intel(ip):
    global threat_client
    if threat_client is None:
        initialize_components()
    try:
        threat_info = threat_client.check_ip(ip)
        return jsonify(threat_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics', methods=['GET'])
def statistics():
    if events_df is None:
        return jsonify({'error': 'No data'}), 400
    
    stats = {
        'total_events': len(events_df),
        'anomalies': int(events_df['is_anomaly'].sum()) if 'is_anomaly' in events_df.columns else 0,
        'attack_types': events_df['attack_type'].value_counts().to_dict() if 'attack_type' in events_df.columns else {},
        'top_users': events_df.groupby('user')['is_anomaly'].sum().sort_values(ascending=False).head(10).to_dict() if 'user' in events_df.columns else {},
        'countries': events_df['country'].value_counts().to_dict() if 'country' in events_df.columns else {},
        'hourly_distribution': events_df.groupby('hour_of_day')['is_anomaly'].sum().to_dict() if 'hour_of_day' in events_df.columns else {}
    }
    
    return jsonify(stats)


@app.route('/api/detection-rules', methods=['GET'])
def detection_rules():
    rules = [
        {"id": "SOC-001", "title": "Brute Force Attack Detection", "severity": "HIGH", "condition": "login_failure_count > 10", "mitre": "T1110", "mitre_name": "Brute Force"},
        {"id": "SOC-002", "title": "Suspicious IP Spread", "severity": "HIGH", "condition": "unique_ips > 5", "mitre": "T1078", "mitre_name": "Valid Accounts"},
        {"id": "SOC-003", "title": "High Request Rate", "severity": "MEDIUM", "condition": "request_rate > 100", "mitre": "T1498", "mitre_name": "Resource Hijacking"},
        {"id": "SOC-004", "title": "Data Exfiltration", "severity": "CRITICAL", "condition": "bytes_sent > 50000", "mitre": "T1041", "mitre_name": "Exfiltration Over C2"},
        {"id": "SOC-005", "title": "After Hours Activity", "severity": "MEDIUM", "condition": "is_business_hours == 0", "mitre": "T1078", "mitre_name": "Valid Accounts"},
        {"id": "SOC-006", "title": "Geographic Anomaly", "severity": "HIGH", "condition": "geo_countries_accessed > 3", "mitre": "T1078", "mitre_name": "Valid Accounts"},
        {"id": "SOC-007", "title": "High Error Rate", "severity": "MEDIUM", "condition": "error_rate > 0.3", "mitre": "T1494", "mitre_name": "Runtime Data Manipulation"},
        {"id": "SOC-008", "title": "Slow Response Attack", "severity": "LOW", "condition": "avg_response_time > 200", "mitre": "T1499", "mitre_name": "Endpoint DoS"}
    ]
    return jsonify(rules)


@app.route('/api/export-alerts', methods=['POST'])
def export_alerts():
    data = request.get_json()
    filepath = data.get('filepath', 'alerts_export.json')
    
    try:
        alert_manager.export_json(filepath)
        return jsonify({'success': True, 'filepath': filepath})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai-chat', methods=['POST'])
def ai_chat():
    global events_df, results
    
    data = request.get_json() or {}
    user_message = data.get('message', '').lower().strip()
    conversation_history = data.get('history', [])
    
    if not user_message:
        return jsonify({'error': 'No message provided'}), 400
    
    if events_df is None:
        run_detection(2000)
    
    anomalies = []
    if results:
        anomalies = [
            {
                'user': events_df.iloc[i].get('user', 'N/A'),
                'ip': events_df.iloc[i].get('ip_address', 'N/A'),
                'country': events_df.iloc[i].get('country', 'N/A'),
                'score': r['anomaly_score'],
                'severity': r['severity'],
                'attack_type': events_df.iloc[i].get('attack_type', 'N/A'),
                'timestamp': str(events_df.iloc[i].get('timestamp', 'N/A'))
            }
            for i, r in enumerate(results) if r.get('is_anomaly')
        ]
    
    response = generate_ai_response(user_message, anomalies, conversation_history)
    
    return jsonify({
        'response': response['message'],
        'suggestions': response.get('suggestions', []),
        'action': response.get('action'),
        'data': response.get('data')
    })


def generate_ai_response(user_message, anomalies, history):
    query_lower = user_message.lower()
    
    if any(word in query_lower for word in ['hello', 'hi', 'hey', 'help']):
        return {
            'message': """Hello! I'm your AI Security Analyst. I can help you with:

🔍 **Threat Analysis**
- "Show me all brute force attacks"
- "What are the top attack types?"

📊 **Statistics**
- "How many critical alerts do we have?"
- "Show me threats by country"

🎯 **Investigation**
- "Tell me about the highest scoring anomaly"
- "What IPs are from Russia/China?"

💡 **Recommendations**
- "What should I investigate first?"
- "Summarize today's threats"

Just ask me naturally!""",
            'suggestions': [
                'Show me all brute force attacks',
                'What are the top attack types?',
                'How many critical alerts?',
                'Summarize today\'s threats'
            ]
        }
    
    if 'brute force' in query_lower:
        filtered = [a for a in anomalies if 'brute' in a.get('attack_type', '').lower()]
        country_filter = None
        for country in ['russia', 'china', 'iran', 'korea', 'syria', 'us', 'uk', 'germany']:
            if country in query_lower:
                country_filter = country.upper() if len(country) == 2 else country.upper()[:2]
                break
        if country_filter:
            filtered = [a for a in filtered if country_filter in str(a.get('country', ''))]
        
        if filtered:
            msg = f"Found **{len(filtered)} brute force attack(s)**"
            if country_filter:
                msg += f" from **{country_filter}**"
            msg += ":\n\n"
            for a in filtered[:5]:
                msg += f"• **{a['user']}** from {a['ip']} ({a['country']}) - Score: {a['score']:.2f}\n"
            return {
                'message': msg,
                'suggestions': ['Show me credential stuffing attacks', 'What about data exfiltration?', 'Show me the full list'],
                'data': filtered
            }
        return {'message': 'No brute force attacks found in the current dataset.', 'suggestions': ['Show me all attacks', 'What attack types exist?']}
    
    if 'country' in query_lower or any(c in query_lower for c in ['russia', 'china', 'iran', 'korea', 'us', 'germany', 'france']):
        country_counts = {}
        for a in anomalies:
            c = a.get('country', 'Unknown')
            country_counts[c] = country_counts.get(c, 0) + 1
        
        sorted_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        
        msg = "**Threats by Country:**\n\n"
        for country, count in sorted_countries[:8]:
            bar = "█" * min(count, 20)
            msg += f"🌍 **{country}**: {count} {bar}\n"
        
        return {
            'message': msg,
            'suggestions': ['Show threats from Russia', 'Show threats from China', 'What\'s the most common attack?']
        }
    
    if 'critical' in query_lower or 'high severity' in query_lower:
        critical = [a for a in anomalies if a.get('severity') == 'CRITICAL']
        high = [a for a in anomalies if a.get('severity') == 'HIGH']
        
        msg = f"""**Severity Breakdown:**

🔴 Critical: **{len(critical)}**
🟠 High: **{len(high)}**
🟡 Medium: **{len([a for a in anomalies if a.get('severity') == 'MEDIUM'])}**
🟢 Low: **{len([a for a in anomalies if a.get('severity') == 'LOW'])}**

"""
        if critical:
            msg += "**Critical Threats:**\n"
            for a in critical[:3]:
                msg += f"• {a['user']} - {a['ip']} ({a['attack_type']}) - Score: {a['score']:.2f}\n"
        
        return {
            'message': msg,
            'suggestions': ['Show me the critical threats', 'What should I investigate first?', 'Summarize all threats']
        }
    
    if 'top' in query_lower and ('attack' in query_lower or 'type' in query_lower):
        attack_counts = {}
        for a in anomalies:
            at = a.get('attack_type', 'unknown')
            attack_counts[at] = attack_counts.get(at, 0) + 1
        
        sorted_attacks = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        
        msg = "**Attack Type Distribution:**\n\n"
        for attack, count in sorted_attacks:
            pct = count / len(anomalies) * 100
            bar = "█" * int(pct / 5)
            msg += f"⚡ **{attack}**: {count} ({pct:.1f}%) {bar}\n"
        
        return {
            'message': msg,
            'suggestions': ['Show brute force attacks', 'Show data exfiltration', 'What\'s the most dangerous?']
        }
    
    if 'summarize' in query_lower or 'summary' in query_lower:
        critical = len([a for a in anomalies if a.get('severity') == 'CRITICAL'])
        high = len([a for a in anomalies if a.get('severity') == 'HIGH'])
        medium = len([a for a in anomalies if a.get('severity') == 'MEDIUM'])
        
        countries = {}
        for a in anomalies:
            c = a.get('country', 'Unknown')
            countries[c] = countries.get(c, 0) + 1
        top_country = max(countries.items(), key=lambda x: x[1]) if countries else ('None', 0)
        
        users = {}
        for a in anomalies:
            u = a.get('user', 'Unknown')
            users[u] = users.get(u, 0) + 1
        top_user = max(users.items(), key=lambda x: x[1]) if users else ('None', 0)
        
        msg = f"""## 📊 Security Summary

**Total Threats Detected:** {len(anomalies)}

**Severity:**
🔴 Critical: {critical}
🟠 High: {high}
🟡 Medium: {medium}

**Top Threat Country:** {top_country[0]} ({top_country[1]} incidents)
**Most Targeted User:** {top_user[0]} ({top_user[1]} incidents)

**Recommendation:**
"""
        if critical > 0:
            msg += "⚠️ Immediate action required - Critical threats detected!"
        elif high > 5:
            msg += "🔶 High priority - Review high-severity alerts within 1 hour"
        else:
            msg += "✅ Monitor - Threat levels within normal parameters"
        
        return {
            'message': msg,
            'suggestions': ['Show critical threats', 'What countries are attacking?', 'Tell me about the top user']
        }
    
    if 'investigate' in query_lower or 'priority' in query_lower:
        sorted_anomalies = sorted(anomalies, key=lambda x: x['score'], reverse=True)
        
        if sorted_anomalies:
            top = sorted_anomalies[0]
            msg = f"""## 🎯 Recommended Priority Investigation

**Highest Threat Score:** {top['score']:.2f}

**Details:**
- 👤 User: {top['user']}
- 🌐 IP: {top['ip']}
- 🌍 Country: {top['country']}
- ⚔️ Attack Type: {top['attack_type']}
- ⏰ Time: {top['timestamp']}

**Recommended Actions:**
1. Review login history for {top['user']}
2. Check IP reputation ({top['ip']})
3. Check for lateral movement
4. Review access logs

Would you like me to investigate this further?"""
            return {
                'message': msg,
                'suggestions': ['Investigate this IP', 'Show threat intel for this IP', 'What are the next highest?'],
                'action': {'type': 'investigate', 'data': top}
            }
    
    if 'ip' in query_lower:
        ips = list(set([a['ip'] for a in anomalies]))
        msg = f"**Unique Threat IPs ({len(ips)} total):**\n\n"
        for ip in ips[:10]:
            msg += f"• {ip}\n"
        if len(ips) > 10:
            msg += f"\n...and {len(ips) - 10} more"
        
        return {
            'message': msg,
            'suggestions': ['Show threat intel for top IP', 'Which IPs are from Russia?', 'Show all unique countries']
        }
    
    if 'user' in query_lower:
        users = {}
        for a in anomalies:
            u = a.get('user', 'Unknown')
            users[u] = users.get(u, 0) + 1
        sorted_users = sorted(users.items(), key=lambda x: x[1], reverse=True)
        
        msg = "**Most Targeted Users:**\n\n"
        for user, count in sorted_users[:10]:
            bar = "█" * min(count, 15)
            msg += f"👤 **{user}**: {count} {bar}\n"
        
        return {
            'message': msg,
            'suggestions': ['Show threats for top user', 'What IPs attacked this user?', 'Show user activity timeline']
        }
    
    return {
        'message': f"I understand you're asking about: *\"{user_message}\"*. \n\nI can help you with:\n\n• **Threat queries** - \"Show brute force attacks\", \"What from Russia?\"\n• **Statistics** - \"Critical alerts\", \"Top attack types\"\n• **Investigation** - \"What should I investigate?\"\n• **Summaries** - \"Summarize today's threats\"\n\nTry asking me something specific!",
        'suggestions': [
            'Summarize today\'s threats',
            'Show critical alerts',
            'What attack types exist?',
            'Show threats by country'
        ]
    }


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'components': {
            'simulator': simulator is not None,
            'detector': detector is not None,
            'explainer': explainer is not None,
            'shap_initialized': shap_initialized,
            'threat_intel': threat_client is not None
        }
    })


# Threat Intelligence Endpoints
threat_intel_initialized = False

def init_threat_intel(abuseipdb_key=None):
    global threat_client, threat_intel_initialized
    from src.threat_intel.client import get_threat_client
    threat_client = get_threat_client(abuseipdb_key)
    threat_intel_initialized = True
    print("Threat Intelligence client initialized")


@app.route('/api/threat/check-ip', methods=['POST'])
def check_ip_threat():
    """Check IP address against threat intelligence databases"""
    data = request.get_json() or {}
    ip_address = data.get('ip_address')
    
    if not ip_address:
        return jsonify({'error': 'IP address required'}), 400
    
    if not threat_intel_initialized:
        init_threat_intel()
    
    result = threat_client.check_ip(ip_address)
    
    if result:
        return jsonify({
            'success': True,
            'ip_address': ip_address,
            'is_malicious': result.get('is_malicious', False),
            'threat_level': result.get('threat_level', 'UNKNOWN'),
            'abuse_confidence_score': result.get('abuse_confidence_score', 0),
            'country_code': result.get('country_code'),
            'country_name': result.get('country_name'),
            'isp': result.get('isp'),
            'categories': result.get('categories', []),
            'total_reports': result.get('total_reports', 0),
            'last_reported': result.get('last_reported_at'),
            'timestamp': result.get('timestamp')
        })
    else:
        return jsonify({
            'success': False,
            'ip_address': ip_address,
            'error': 'Unable to check IP'
        })


@app.route('/api/threat/intelligence', methods=['GET'])
def get_threat_intel():
    """Get threat intelligence statistics"""
    if not threat_intel_initialized:
        init_threat_intel()
    
    stats = threat_client.get_statistics()
    
    return jsonify({
        'success': True,
        'statistics': stats,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/threat/blacklist', methods=['GET'])
def get_blacklist():
    """Get current blacklist"""
    if not threat_intel_initialized:
        init_threat_intel()
    
    limit = int(request.args.get('limit', 100))
    confidence = int(request.args.get('confidence_min', 50))
    
    blacklist = threat_client.get_blacklist(confidence_min=confidence, limit=limit)
    
    if blacklist:
        return jsonify({
            'success': True,
            'count': len(blacklist),
            'blacklist': blacklist
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Unable to fetch blacklist'
        })


# Live Detection with Real Data
real_detection_enabled = False
detection_history = []

@app.route('/api/detection/start', methods=['POST'])
def start_real_detection():
    """Start real-time threat detection"""
    global real_detection_enabled, detection_history
    
    data = request.get_json() or {}
    abuseipdb_key = data.get('abuseipdb_api_key')
    
    if abuseipdb_key:
        init_threat_intel(abuseipdb_key)
    elif not threat_intel_initialized:
        init_threat_intel()
    
    real_detection_enabled = True
    detection_history = []
    
    return jsonify({
        'success': True,
        'message': 'Real-time detection started',
        'mode': 'hybrid' if abuseipdb_key else 'demo'
    })


@app.route('/api/detection/stop', methods=['POST'])
def stop_real_detection():
    """Stop real-time threat detection"""
    global real_detection_enabled
    real_detection_enabled = False
    
    return jsonify({
        'success': True,
        'message': 'Real-time detection stopped'
    })


@app.route('/api/detection/status', methods=['GET'])
def get_detection_status():
    """Get current detection status"""
    return jsonify({
        'enabled': real_detection_enabled,
        'total_detections': len(detection_history),
        'recent_detections': detection_history[-10:] if detection_history else []
    })


@app.route('/api/detection/simulate', methods=['POST'])
def simulate_detection():
    """Simulate detection event with threat intelligence"""
    global detection_history
    
    data = request.get_json() or {}
    use_real_ip = data.get('use_real_ip', False)
    
    import random
    
    sample_malicious_ips = [
        "185.220.101.1", "45.33.32.156", "23.129.64.130",
        "195.154.181.163", "91.121.87.10", "149.202.38.189"
    ]
    
    sample_ips = [
        "192.168.1." + str(random.randint(1, 254)),
        "10.0.0." + str(random.randint(1, 254)),
        "172.16.0." + str(random.randint(1, 254))
    ]
    
    if use_real_ip:
        ip_address = random.choice(sample_malicious_ips)
    else:
        ip_address = random.choice(sample_ips + sample_malicious_ips)
    
    if threat_intel_initialized and threat_client:
        threat_info = threat_client.check_ip(ip_address)
    else:
        threat_info = None
    
    attack_types = [
        "DDoS", "Brute Force", "Malware", "Port Scan", 
        "SQL Injection", "XSS", "Botnet", "Phishing"
    ]
    
    countries = {
        "CN": {"name": "China", "lat": 35.8617, "lng": 104.1954},
        "RU": {"name": "Russia", "lat": 61.5240, "lng": 105.3188},
        "US": {"name": "United States", "lat": 37.0902, "lng": -95.7129},
        "IR": {"name": "Iran", "lat": 32.4279, "lng": 53.6880},
        "DE": {"name": "Germany", "lat": 51.1657, "lng": 10.4515},
        "BR": {"name": "Brazil", "lat": -14.2350, "lng": -51.9253}
    }
    
    country_code = random.choice(list(countries.keys()))
    country = countries[country_code]
    
    severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_weights = [0.1, 0.25, 0.35, 0.3]
    severity = random.choices(severity_levels, weights=severity_weights)[0]
    
    detection = {
        "id": len(detection_history) + 1,
        "timestamp": datetime.now().isoformat(),
        "ip_address": ip_address,
        "country_code": country_code,
        "country_name": country["name"],
        "latitude": country["lat"],
        "longitude": country["lng"],
        "attack_type": random.choice(attack_types),
        "severity": severity,
        "anomaly_score": random.uniform(0.7, 1.0) if severity in ["CRITICAL", "HIGH"] else random.uniform(0.4, 0.7),
        "threat_intel": threat_info,
        "is_malicious_ip": threat_info.get('is_malicious', False) if threat_info else False,
        "abuse_score": threat_info.get('abuse_confidence_score', 0) if threat_info else 0
    }
    
    detection_history.append(detection)
    
    if len(detection_history) > 1000:
        detection_history = detection_history[-1000:]
    
    return jsonify({
        'success': True,
        'detection': detection
    })


@app.route('/api/detection/history', methods=['GET'])
def get_detection_history():
    """Get detection history"""
    limit = int(request.args.get('limit', 50))
    severity = request.args.get('severity')
    
    filtered = detection_history
    if severity:
        filtered = [d for d in detection_history if d.get('severity') == severity.upper()]
    
    return jsonify({
        'success': True,
        'count': len(filtered),
        'detections': filtered[-limit:]
    })


@app.route('/api/detection/stats', methods=['GET'])
def get_detection_stats():
    """Get detection statistics"""
    if not detection_history:
        return jsonify({
            'success': True,
            'total': 0,
            'by_severity': {},
            'by_country': {},
            'by_attack_type': {},
            'malicious_ips': 0
        })
    
    by_severity = {}
    by_country = {}
    by_attack_type = {}
    malicious_ips = 0
    
    for d in detection_history:
        sev = d.get('severity', 'UNKNOWN')
        by_severity[sev] = by_severity.get(sev, 0) + 1
        
        country = d.get('country_name', 'Unknown')
        by_country[country] = by_country.get(country, 0) + 1
        
        attack = d.get('attack_type', 'Unknown')
        by_attack_type[attack] = by_attack_type.get(attack, 0) + 1
        
        if d.get('is_malicious_ip'):
            malicious_ips += 1
    
    return jsonify({
        'success': True,
        'total': len(detection_history),
        'by_severity': by_severity,
        'by_country': by_country,
        'by_attack_type': by_attack_type,
        'malicious_ips': malicious_ips,
        'percentage_malicious': round(malicious_ips / len(detection_history) * 100, 2) if detection_history else 0
    })


if __name__ == '__main__':
    initialize_components()
    print("SOC Sentinel API starting on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
