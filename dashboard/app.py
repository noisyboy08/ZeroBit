import json
import os
import platform
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st

from src.advisor import SecurityAdvisor
from src.honeypot import start_honeypot
from src.discovery import scan_network, get_mac_vendor
from src.reporting import SecurityReport
from src.mitre import get_mitre_details
from src.threat_intel import ThreatIntel
from src.response import ResponseEngine
from src.visualization import render_attack_graph
from src.feedback import IncidentManager
from src.training import retrain_on_feedback
from src.simulator import AttackSimulator
from src.canary import CanaryMonitor


ALERT_DIR = Path("static/alerts")
FALSE_POS_DIR = Path("data/false_positives")
HONEYPOT_LOG = Path("data/honeypot_logs.json")
UEBA_LOG = Path("data/ueba_history.json")
ALERTS_DB = Path("data/alerts.db")


def fetch_latest_alerts(limit: int = 10) -> pd.DataFrame:
    """Fetch latest alerts from SQLite database."""
    if not ALERTS_DB.exists():
        return pd.DataFrame(columns=["id", "timestamp", "src_ip", "dst_ip", "attack_type", "confidence"])
    
    try:
        conn = sqlite3.connect(ALERTS_DB)
        df = pd.read_sql_query(
            f"""
            SELECT id, timestamp, src_ip, dst_ip, attack_type, confidence, is_read
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT {limit}
            """,
            conn,
        )
        conn.close()
        return df
    except Exception as exc:
        return pd.DataFrame(columns=["id", "timestamp", "src_ip", "dst_ip", "attack_type", "confidence"])


def list_alerts() -> List[Path]:
    if not ALERT_DIR.exists():
        return []
    return sorted(ALERT_DIR.glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)


def load_honeypot_logs() -> pd.DataFrame:
    if not HONEYPOT_LOG.exists():
        return pd.DataFrame(columns=["attacker_ip", "timestamp", "payload"])
    try:
        data = json.loads(HONEYPOT_LOG.read_text(encoding="utf-8"))
        return pd.DataFrame(data)
    except Exception:
        return pd.DataFrame(columns=["attacker_ip", "timestamp", "payload"])


def load_ueba_history() -> pd.DataFrame:
    if not UEBA_LOG.exists():
        return pd.DataFrame(columns=["timestamp", "ip", "bytes"])
    try:
        data = json.loads(UEBA_LOG.read_text(encoding="utf-8"))
        return pd.DataFrame(data)
    except Exception:
        return pd.DataFrame(columns=["timestamp", "ip", "bytes"])


def parse_timestamp(name: str) -> str:
    # Expected format: alert_<timestamp>.png
    stem = Path(name).stem
    if stem.startswith("alert_"):
        return stem.replace("alert_", "")
    return stem


def move_false_positive(file_path: Path) -> None:
    FALSE_POS_DIR.mkdir(parents=True, exist_ok=True)
    target = FALSE_POS_DIR / file_path.name
    shutil.move(str(file_path), target)


def render_sidebar(alerts: List[Path]) -> Path | None:
    st.sidebar.title("Alerts")
    st.sidebar.text_input("Groq API Key", type="password", key="groq_api_key")
    st.sidebar.text_input("AbuseIPDB API Key", type="password", key="abuseipdb_key")
    st.sidebar.text_input("VirusTotal API Key", type="password", key="virustotal_key")
    if st.sidebar.button("Download Report"):
        st.session_state["download_report"] = True
    # Auto-block toggle
    auto_block = st.sidebar.checkbox("Enable Auto-Block (Active Response)", value=False, key="auto_block")
    st.session_state["auto_block_enabled"] = auto_block
    # Honeypot toggle
    on = st.sidebar.toggle("Trap Switch (Honeypot on 2222)", value=False, key="honeypot_toggle")
    if on and not st.session_state.get("honeypot_started"):
        start_honeypot()
        st.session_state["honeypot_started"] = True
        st.sidebar.success("Honeypot started on port 2222.")
    if not on and st.session_state.get("honeypot_started"):
        st.sidebar.warning("Honeypot stop not supported; restart app to fully stop.")
    
    # Model Training Gym Section
    st.sidebar.divider()
    st.sidebar.subheader("⚔️ Model Training Gym")
    st.sidebar.caption("Test Adaptive Learning with simulated traffic")
    
    target_ip = st.sidebar.text_input("Target IP", value="192.168.1.1", key="sim_target_ip")
    
    if st.sidebar.button("🚨 Launch Test Attack (DoS)", use_container_width=True):
        simulator = AttackSimulator()
        with st.sidebar:
            with st.spinner("Simulating DoS attack..."):
                count = simulator.simulate_dos(target_ip, duration=3)
                st.success(f"Sent {count} attack packets!")
        # Don't auto-rerun - user can manually refresh if needed
    
    if st.sidebar.button("🔍 Launch Port Probe", use_container_width=True):
        simulator = AttackSimulator()
        with st.sidebar:
            with st.spinner("Simulating port scan..."):
                count = simulator.simulate_probe(target_ip, num_ports=15)
                st.success(f"Probed {count} ports!")
        # Don't auto-rerun - user can manually refresh if needed
    
    if st.sidebar.button("✅ Generate Safe Noise", use_container_width=True, type="primary"):
        simulator = AttackSimulator()
        with st.sidebar:
            with st.spinner("Generating safe traffic (HTTP/DNS)..."):
                count = simulator.simulate_noise(target_ip="8.8.8.8", num_packets=10)
                st.info(f"Generated {count} safe packets. Check if system alerts (should be False Positive).")
        # Don't auto-rerun - user can manually refresh if needed
    
    # Canary Deployment Section
    st.sidebar.divider()
    st.sidebar.subheader("🛡️ ZeroBit Canary")
    st.sidebar.caption("Ransomware Kill Switch")
    
    canary = st.session_state.get("canary_monitor")
    if canary:
        status = canary.get_status()
        if status["is_active"]:
            st.sidebar.success(f"Monitoring {len(status['monitored_directories'])} directory(ies)")
            st.sidebar.write(f"Canary files: {status['canary_files_count']}")
        else:
            st.sidebar.info("Canary not active")
        
        if st.sidebar.button("📁 Deploy Canaries", use_container_width=True):
            # Default to user's Documents folder
            if platform.system() == "Windows":
                default_dir = Path(os.path.expanduser("~/Documents/ZeroBit_Canaries"))
            else:
                default_dir = Path(os.path.expanduser("~/Documents/ZeroBit_Canaries"))
            
            default_dir.mkdir(parents=True, exist_ok=True)
            created = canary.setup_traps(default_dir)
            canary.start_monitoring(default_dir)
            st.sidebar.success(f"Deployed {len(created)} canary files in {default_dir}")
            # Removed auto-rerun to prevent refresh loop
        
        if status["alert_triggered"]:
            st.sidebar.error("🚨 RANSOMWARE ALERT ACTIVE")
            if st.sidebar.button("🔄 Reset Alert", use_container_width=True):
                canary.reset_alert()
                st.sidebar.success("Alert reset. Refresh page manually if needed.")
    
    if not alerts:
        st.sidebar.info("No alerts yet.")
        return None
    labels = [f"{p.name}" for p in alerts]
    choice = st.sidebar.selectbox("Select alert image", labels)
    idx = labels.index(choice)
    return alerts[idx]


def render_priority_badge(priority: str) -> None:
    """Render a colored priority badge."""
    colors = {
        "P0-Critical": "🔴",
        "P1-High": "🟠",
        "P2-Medium": "🟡",
        "P3-Low": "🟢",
    }
    emoji = colors.get(priority, "⚪")
    st.markdown(f"### {emoji} **Priority: {priority}**")


def render_alert_detail(
    selected: Path | None,
    alert_log_df: pd.DataFrame,
    groq_api_key: str | None,
    threat_intel: ThreatIntel | None = None,
    incident_manager: IncidentManager | None = None,
) -> None:
    st.header("Alert Detail")
    if not selected:
        st.info("Select an alert from the sidebar to view details.")
        return
    ts = parse_timestamp(selected.name)
    st.subheader(f"Timestamp: {ts}")
    st.image(str(selected), caption=selected.name, use_container_width=True)

    # Get alert row data
    row = None
    if not alert_log_df.empty and "timestamp" in alert_log_df.columns:
        match = alert_log_df[alert_log_df["timestamp"] == ts]
        if not match.empty:
            row = match.iloc[0]

    src_ip = row["src_ip"] if row is not None and "src_ip" in row else "Unknown"
    threat_score = float(row["threat_score"]) if row is not None and "threat_score" in row and pd.notna(row["threat_score"]) else 0.0

    # Priority Badge
    if incident_manager:
        priority = incident_manager.calculate_priority(threat_score)
        render_priority_badge(priority)

    # Feedback Loop Section
    st.divider()
    st.subheader("📝 Analyst Feedback")
    col1, col2 = st.columns(2)

    # Get current alert features for similarity search
    current_features = None
    incident_id = None
    if row is not None and incident_manager:
        # Try to reconstruct feature vector from alert data
        # In a real system, this would be stored when the alert was created
        try:
            # Create a simple feature dict from available data
            current_features = {
                "threat_score": threat_score,
                "confidence": float(row["confidence"]) if "confidence" in row and pd.notna(row["confidence"]) else 0.0,
            }
            # Log incident if not already logged
            incident_id = incident_manager.log_incident(
                features=current_features,
                prediction=1,  # Assuming malicious since it's an alert
                threat_score=threat_score,
                ip=src_ip,
                attack_type=row.get("reason", "Unknown") if row is not None else "Unknown",
            )
        except Exception:
            pass

    with col1:
        if st.button("👍 Confirmed Attack", type="primary", use_container_width=True):
            if incident_manager and incident_id:
                incident_manager.add_feedback(incident_id, is_true_positive=True, notes="Confirmed by analyst")
                st.success("✅ Feedback recorded: Confirmed Attack")
            else:
                st.warning("Incident manager not available")

    with col2:
        if st.button("👎 False Alarm", type="secondary", use_container_width=True):
            if incident_manager and incident_id:
                incident_manager.add_feedback(incident_id, is_true_positive=False, notes="False positive")
                st.success("✅ Feedback recorded: False Alarm")
                # Trigger retraining in background
                with st.spinner("Retraining model with feedback..."):
                    try:
                        result = retrain_on_feedback()
                        st.info(result)
                    except Exception as exc:
                        st.error(f"Retraining failed: {exc}")
            else:
                st.warning("Incident manager not available")
            move_false_positive(selected)
            # Removed auto-rerun to prevent refresh loop - user can manually refresh

    # Similar Past Incidents Section
    if incident_manager and current_features:
        st.divider()
        st.subheader("📚 Similar Past Incidents")
        similar = incident_manager.get_similar_incidents(current_features, top_k=3)
        if similar:
            for sim_incident in similar:
                with st.expander(
                    f"Incident #{sim_incident['id']} - {sim_incident['ip']} "
                    f"(Similarity: {sim_incident['similarity']:.2%})"
                ):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"**Timestamp:** {sim_incident['timestamp']}")
                        st.write(f"**IP:** {sim_incident['ip']}")
                        st.write(f"**Attack Type:** {sim_incident['attack_type']}")
                        st.write(f"**Priority:** {sim_incident['priority']}")
                    with col_b:
                        st.write(f"**Threat Score:** {sim_incident['threat_score']:.1f}")
                        label_text = "✅ True Positive" if sim_incident['human_label'] == 1 else "❌ False Positive"
                        st.write(f"**Status:** {label_text}")
                        if sim_incident['resolved']:
                            st.write(f"**Resolved by:** {sim_incident['resolved_by']}")
                            st.write(f"**Resolved at:** {sim_incident['resolved_at']}")
                        if sim_incident['analyst_notes']:
                            st.write(f"**Notes:** {sim_incident['analyst_notes']}")
        else:
            st.info("No similar past incidents found.")

    # Threat Intelligence Section
    if threat_intel and src_ip != "Unknown":
        with st.expander("🔍 Threat Intelligence", expanded=True):
            intel_data = threat_intel.get_combined_score(src_ip)
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Threat Score", f"{intel_data['threat_score']}/100", delta=None)
            with col2:
                risk_color = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🟢",
                }.get(intel_data["risk_level"], "⚪")
                st.metric("Risk Level", f"{risk_color} {intel_data['risk_level']}")
            with col3:
                abuse_conf = intel_data["abuseipdb"].get("confidence", 0)
                st.metric("AbuseIPDB Confidence", f"{abuse_conf}%")

            st.divider()
            col_a, col_b = st.columns(2)
            with col_a:
                st.subheader("AbuseIPDB")
                abuse = intel_data["abuseipdb"]
                st.write(f"**Confidence:** {abuse.get('confidence', 0)}%")
                st.write(f"**Abuse Reports:** {abuse.get('abuse_count', 0)}")
                st.write(f"**Usage Type:** {abuse.get('usage_type', 'Unknown')}")

            with col_b:
                st.subheader("VirusTotal")
                vt = intel_data["virustotal"]
                st.write(f"**Malicious:** {vt.get('malicious', 0)}")
                st.write(f"**Suspicious:** {vt.get('suspicious', 0)}")
                st.write(f"**Harmless:** {vt.get('harmless', 0)}")

    if st.button("🤖 Generate AI Report", type="primary", disabled=not groq_api_key):
        if not groq_api_key:
            st.warning("Enter Groq API Key in the sidebar to generate a report.")
        else:
            advisor = SecurityAdvisor(api_key=groq_api_key)
            attack_type = "Malicious network flow"
            affected_port = row["affected_port"] if row is not None and "affected_port" in row else "N/A"
            os_system = "Linux"
            try:
                resp = advisor.get_remediation(
                    attack_type=attack_type,
                    ip_address=src_ip,
                    affected_port=str(affected_port),
                    os_system=os_system,
                )
                st.info(resp)
                for line in resp.splitlines():
                    if any(k in line.lower() for k in ["iptables", "ufw", "netsh", "firewall-cmd", "block", "deny"]):
                        st.code(line.strip(), language="bash")
                        break
            except Exception as exc:
                st.error(f"AI Advisor failed: {exc}")

    # Kill Chain Card (MITRE)
    mitre_id = mitre_name = mitre_phase = mitre_desc = None
    # Attempt to map using alert log reason/label if available
    mitre_row = None
    if not alert_log_df.empty and "timestamp" in alert_log_df.columns:
        match = alert_log_df[alert_log_df["timestamp"] == ts]
        if not match.empty:
            mitre_row = match.iloc[0]
    label_guess = None
    for key in ["reason", "label", "type"]:
        if mitre_row is not None and key in mitre_row and pd.notna(mitre_row[key]):
            label_guess = str(mitre_row[key]).split()[0].lower()
            break
    details = get_mitre_details(label_guess or "generic")
    mitre_id = details["id"]
    mitre_name = details["name"]
    mitre_phase = details["phase"]
    mitre_desc = details["description"]

    with st.expander("Kill Chain Card"):
        st.markdown(f"**Technique ID:** :red[{mitre_id}] — {mitre_name}")
        st.markdown(f"**Tactic:** {mitre_phase}")
        st.markdown(f"**Description:** {mitre_desc}")
        link = f"https://attack.mitre.org/techniques/{mitre_id}"
        st.link_button("View on MITRE Website", link)


def render_honeypot_metrics(hp_df: pd.DataFrame) -> None:
    st.subheader("Deception Metrics")
    count = len(hp_df)
    st.metric("Confirmed Traps", value=count)
    if count:
        display = hp_df.rename(
            columns={
                "attacker_ip": "Attacker IP",
                "timestamp": "Time",
                "payload": "Captured Credentials",
            }
        )
        st.dataframe(display[["Attacker IP", "Time", "Captured Credentials"]], use_container_width=True)
    else:
        st.info("No honeypot captures yet.")


def render_ueba_chart(ueba_df: pd.DataFrame) -> None:
    st.subheader("Traffic Deviations")
    if ueba_df.empty:
        st.info("No UEBA data yet.")
        return
    df = ueba_df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp")
    baseline = df["bytes"].mean()
    plot_df = pd.DataFrame(
        {
            "timestamp": df["timestamp"],
            "Actual Traffic": df["bytes"],
            "Normal Baseline": [baseline] * len(df),
        }
    ).set_index("timestamp")
    st.line_chart(plot_df, height=260)


def render_live_feed(alerts: List[Path]) -> None:
    st.header("Live Feed")
    st.caption("Auto-refreshes every 2 seconds for new alerts.")
    # Lightweight auto-refresh via meta refresh
    st.markdown(
        "<meta http-equiv='refresh' content='2'>",
        unsafe_allow_html=True,
    )
    if alerts:
        latest = alerts[0]
        st.image(str(latest), caption=f"Latest: {latest.name}", use_container_width=True)
    else:
        st.info("Waiting for alerts...")


def render_threat_map(alert_log: Path) -> None:
    st.header("Live Threat Map")
    if not alert_log.exists():
        st.info("No alerts logged yet.")
        return
    df = pd.read_csv(alert_log)
    if df.empty or "lat" not in df.columns or "lon" not in df.columns:
        st.info("No geolocated alerts to display.")
        return
    df = df.dropna(subset=["lat", "lon"])
    if df.empty:
        st.info("No geolocated alerts to display.")
        return
    st.map(df[["lat", "lon"]])
    st.subheader("Recent Threats")
    display_cols = ["src_ip", "country", "isp", "confidence"]
    available = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available], use_container_width=True)


def render_threat_level_header(alert_log_df: pd.DataFrame, threat_intel: ThreatIntel) -> None:
    """Calculate and display overall threat level based on recent alerts."""
    if alert_log_df.empty or "src_ip" not in alert_log_df.columns:
        st.metric("Threat Level", "🟢 Low", delta=None)
        return

    # Get recent alerts (last 24 hours worth if timestamp available)
    recent = alert_log_df.tail(10)  # Last 10 alerts
    scores = []
    for _, row in recent.iterrows():
        ip = row.get("src_ip", "Unknown")
        if ip != "Unknown":
            intel = threat_intel.get_combined_score(ip)
            scores.append(intel["threat_score"])

    if not scores:
        st.metric("Threat Level", "🟢 Low", delta=None)
        return

    avg_score = sum(scores) / len(scores)
    if avg_score >= 70:
        level = "🔴 Critical"
    elif avg_score >= 50:
        level = "🟠 High"
    elif avg_score >= 30:
        level = "🟡 Medium"
    else:
        level = "🟢 Low"

    st.metric("Threat Level", level, delta=f"Avg Score: {avg_score:.1f}")


def render_live_intel_tab(alert_log_df: pd.DataFrame, threat_intel: ThreatIntel) -> None:
    """Tab showing live threat intelligence for selected alerts."""
    st.header("Live Threat Intelligence")
    if alert_log_df.empty:
        st.info("No alerts to analyze.")
        return

    # Show recent alerts with threat scores
    recent = alert_log_df.tail(20)
    st.subheader("Recent Alerts with Threat Scores")

    intel_rows = []
    for _, row in recent.iterrows():
        ip = row.get("src_ip", "Unknown")
        if ip != "Unknown":
            intel = threat_intel.get_combined_score(ip)
            intel_rows.append(
                {
                    "IP": ip,
                    "Threat Score": intel["threat_score"],
                    "Risk Level": intel["risk_level"],
                    "AbuseIPDB": intel["abuseipdb"].get("confidence", 0),
                    "VT Malicious": intel["virustotal"].get("malicious", 0),
                    "Timestamp": row.get("timestamp", "N/A"),
                }
            )

    if intel_rows:
        intel_df = pd.DataFrame(intel_rows)
        st.dataframe(intel_df, use_container_width=True)
    else:
        st.info("No IPs to analyze.")


def render_attack_graph_tab(alert_log_df: pd.DataFrame) -> None:
    """Tab showing attack chain graph visualization."""
    st.header("Attack Chain Graph")
    if alert_log_df.empty:
        st.info("No alerts to visualize.")
        return

    # Convert alert log to list of dicts for graph
    alerts_list = []
    for _, row in alert_log_df.tail(50).iterrows():  # Last 50 alerts
        alerts_list.append(
            {
                "src_ip": row.get("src_ip", "Unknown"),
                "dst_port": row.get("dst_port", "Unknown"),
                "attack_type": row.get("reason", "Unknown Attack"),
                "timestamp": row.get("timestamp", ""),
            }
        )

    if alerts_list:
        render_attack_graph(alerts_list)
    else:
        st.info("No attack data to visualize.")


def main() -> None:
    st.set_page_config(layout="wide", page_title="ZeroBit: Threat Monitor")
    ALERT_DIR.mkdir(parents=True, exist_ok=True)
    alert_log = Path("data/alerts.csv")
    alert_log_df = pd.read_csv(alert_log) if alert_log.exists() else pd.DataFrame()
    honeypot_df = load_honeypot_logs()
    ueba_df = load_ueba_history()
    alerts = list_alerts()

    # Initialize threat intelligence and response engine
    threat_intel = ThreatIntel()
    # Override API keys from sidebar if provided
    abuse_key = st.session_state.get("abuseipdb_key")
    vt_key = st.session_state.get("virustotal_key")
    if abuse_key:
        threat_intel.abuseipdb_key = abuse_key
    if vt_key:
        threat_intel.virustotal_key = vt_key

    response_engine = ResponseEngine()
    incident_manager = IncidentManager()
    
    # Initialize Canary Monitor
    if "canary_monitor" not in st.session_state:
        st.session_state["canary_monitor"] = CanaryMonitor()

    # Header with threat level
    col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
    with col1:
        st.title("ZeroBit: Threat Intelligence Dashboard")
    with col2:
        render_threat_level_header(alert_log_df, threat_intel)
    with col3:
        auto_block_enabled = st.session_state.get("auto_block_enabled", False)
        status = "🟢 Active" if auto_block_enabled else "⚪ Inactive"
        st.metric("Auto-Block", status)
    with col4:
        # Kill Switch Status
        canary = st.session_state["canary_monitor"]
        if canary.alert_triggered:
            st.markdown(
                '<div style="background-color: #ff0000; padding: 10px; border-radius: 5px; text-align: center; animation: blink 1s infinite;">'
                '<h2 style="color: white; margin: 0;">🚨 RANSOMWARE DETECTED</h2>'
                '<p style="color: white; margin: 5px 0;">NETWORK SEVERED</p>'
                '</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div style="background-color: #00ff00; padding: 10px; border-radius: 5px; text-align: center;">'
                '<h3 style="color: black; margin: 0;">🟢 System Healthy</h3>'
                '</div>',
                unsafe_allow_html=True
            )

    tabs = st.tabs(
        ["Alerts", "Live Intel", "Attack Graph", "Live Threat Map", "Network Topology", "Live Feed"]
    )

    with tabs[0]:
        groq_api_key = st.session_state.get("groq_api_key")
        selected = render_sidebar(alerts)
        
        # Real-Time Alerts from Pipeline
        st.subheader("🔴 Live Alerts (Real-Time)")
        alert_placeholder = st.empty()
        
        # Auto-refresh logic
        if st.session_state.get("pipeline_running", False):
            latest_alerts = fetch_latest_alerts(limit=20)
            if not latest_alerts.empty:
                with alert_placeholder.container():
                    # Show alert count
                    st.metric("Active Alerts", len(latest_alerts))
                    # Display alerts table
                    display_df = latest_alerts[["timestamp", "src_ip", "dst_ip", "attack_type", "confidence"]].copy()
                    display_df["confidence"] = display_df["confidence"].apply(
                        lambda x: f"{x:.2%}" if pd.notna(x) else "N/A"
                    )
                    display_df.columns = ["Time", "Source IP", "Dest IP", "Attack Type", "Confidence"]
                    st.dataframe(display_df, use_container_width=True, height=300)
            else:
                with alert_placeholder.container():
                    st.info("No alerts yet. Start the processing engine and wait for network traffic.")
        else:
            with alert_placeholder.container():
                st.warning("⚠️ Processing engine is not running. Click 'Start Engine' in the sidebar to begin real-time detection.")
        
        # Use Streamlit's auto-refresh instead of manual rerun
        # Auto-refresh is handled by Streamlit's built-in refresh mechanism
        # Remove the manual st.rerun() to prevent infinite refresh loop
        
        # Demo Flow Instructions
        with st.expander("📖 Adaptive Learning Demo Flow", expanded=False):
            st.markdown("""
            **Test the Adaptive Learning System:**
            1. Click **"✅ Generate Safe Noise"** in sidebar → System may alert (False Positive)
            2. Select the alert → Click **"👎 False Alarm"** button
            3. System retrains model with your feedback
            4. Click **"✅ Generate Safe Noise"** again → System should stay silent! ✅
            
            **Why it works:** The model learns from your feedback and reduces false positives over time.
            """)
        
        render_honeypot_metrics(honeypot_df)
        render_ueba_chart(ueba_df)
        render_alert_detail(selected, alert_log_df, groq_api_key, threat_intel, incident_manager)
        # Handle report download
        if st.session_state.get("download_report"):
            if alert_log_df.empty:
                st.warning("No alerts to include in the report.")
            else:
                report = SecurityReport()
                out_path = Path("report.pdf")
                report.generate_daily_report(alert_log_df, out_path)
                with out_path.open("rb") as f:
                    st.download_button(
                        label="Download report.pdf",
                        data=f,
                        file_name="report.pdf",
                        mime="application/pdf",
                    )
            st.session_state["download_report"] = False

    with tabs[1]:
        render_live_intel_tab(alert_log_df, threat_intel)

    with tabs[2]:
        render_attack_graph_tab(alert_log_df)

    with tabs[3]:
        render_threat_map(alert_log)

    with tabs[4]:
        st.header("Network Topology")
        with st.form("network_scan"):
            ip_range = st.text_input("IP Range (CIDR)", value="192.168.1.1/24")
            submitted = st.form_submit_button("Scan Network Now")
        if submitted:
            with st.spinner("Scanning network..."):
                hosts = scan_network(ip_range)
                # Enrich with vendor
                for h in hosts:
                    h["Vendor"] = get_mac_vendor(h["MAC"])
                if hosts:
                    df_hosts = pd.DataFrame(hosts)
                    st.metric("Total Devices Online", len(df_hosts))
                    st.dataframe(df_hosts[["IP", "MAC", "Vendor"]], use_container_width=True)
                else:
                    st.info("No hosts discovered.")

    with tabs[5]:
        render_live_feed(alerts)

    # Auto-block processing (if enabled)
    if st.session_state.get("auto_block_enabled") and not alert_log_df.empty:
        # Check latest alerts and auto-block if needed
        latest = alert_log_df.tail(5)
        for _, row in latest.iterrows():
            ip = row.get("src_ip", "Unknown")
            if ip != "Unknown":
                intel = threat_intel.get_combined_score(ip)
                if intel["threat_score"] > 80:
                    result = response_engine.execute_playbook(
                        {"src_ip": ip}, intel["threat_score"]
                    )
                    if result["action"] == "blocked":
                        st.sidebar.success(f"Auto-blocked: {ip}")


if __name__ == "__main__":
    main()

