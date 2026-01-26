"""
ZeroBit SOC Dashboard - Simplified Working Version
"""
import json
import os
import sqlite3
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st

# Safe imports with fallbacks
try:
    from src.threat_intel import ThreatIntel
    HAS_THREAT_INTEL = True
except:
    HAS_THREAT_INTEL = False

try:
    from src.mitre import get_mitre_details
    HAS_MITRE = True
except:
    HAS_MITRE = False

try:
    from src.feedback import IncidentManager
    HAS_FEEDBACK = True
except:
    HAS_FEEDBACK = False


ALERT_DIR = Path("static/alerts")
ALERTS_DB = Path("data/alerts.db")
HONEYPOT_LOG = Path("data/honeypot_logs.json")
UEBA_LOG = Path("data/ueba_history.json")
ALERT_CSV = Path("data/alerts.csv")


def fetch_latest_alerts(limit: int = 10) -> pd.DataFrame:
    """Fetch latest alerts from SQLite database."""
    if not ALERTS_DB.exists():
        return pd.DataFrame()
    
    try:
        conn = sqlite3.connect(ALERTS_DB)
        df = pd.read_sql_query(
            f"""
            SELECT id, timestamp, src_ip, dst_ip, attack_type, confidence
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT {limit}
            """,
            conn,
        )
        conn.close()
        return df
    except:
        return pd.DataFrame()


def load_alert_csv() -> pd.DataFrame:
    """Load alerts from CSV file."""
    if ALERT_CSV.exists():
        try:
            return pd.read_csv(ALERT_CSV)
        except:
            pass
    return pd.DataFrame()


def load_honeypot_logs() -> pd.DataFrame:
    """Load honeypot interaction logs."""
    if not HONEYPOT_LOG.exists():
        return pd.DataFrame()
    try:
        data = json.loads(HONEYPOT_LOG.read_text(encoding="utf-8"))
        return pd.DataFrame(data)
    except:
        return pd.DataFrame()


def load_ueba_history() -> pd.DataFrame:
    """Load UEBA history."""
    if not UEBA_LOG.exists():
        return pd.DataFrame()
    try:
        data = json.loads(UEBA_LOG.read_text(encoding="utf-8"))
        return pd.DataFrame(data)
    except:
        return pd.DataFrame()


def main():
    st.set_page_config(layout="wide", page_title="ZeroBit SOC Dashboard", page_icon="🛡️")
    
    # Create necessary directories
    ALERT_DIR.mkdir(parents=True, exist_ok=True)
    Path("data").mkdir(exist_ok=True)
    
    # Initialize session state
    if "pipeline_running" not in st.session_state:
        st.session_state["pipeline_running"] = False
    
    # Title and description
    st.title("🛡️ ZeroBit: AI-Powered Network Threat Detection")
    st.markdown("""
    **Advanced Intrusion Detection & Response Platform**
    - Real-time packet analysis with ML detection
    - Encrypted traffic analysis without decryption
    - User behavior analytics (UEBA)
    - Active defense & honeypots
    - MITRE ATT&CK mapping
    """)
    
    # Sidebar controls
    st.sidebar.header("⚙️ Controls")
    
    # Pipeline status
    col1, col2 = st.sidebar.columns(2)
    with col1:
        if st.button("▶️ Start Pipeline", use_container_width=True):
            st.session_state["pipeline_running"] = True
            st.success("Pipeline started!")
    
    with col2:
        if st.button("⏹️ Stop Pipeline", use_container_width=True):
            st.session_state["pipeline_running"] = False
            st.info("Pipeline stopped")
    
    st.sidebar.divider()
    
    # API Keys section
    st.sidebar.subheader("🔑 API Keys")
    groq_key = st.sidebar.text_input("Groq API Key", type="password", help="For AI advisor")
    abuse_key = st.sidebar.text_input("AbuseIPDB Key", type="password", help="For IP reputation")
    vt_key = st.sidebar.text_input("VirusTotal Key", type="password", help="For file/URL analysis")
    
    st.sidebar.divider()
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📊 Dashboard", 
        "🚨 Alerts", 
        "🕸️ Attack Chain", 
        "🐝 Honeypot",
        "📈 UEBA"
    ])
    
    # Load data
    alerts_db = fetch_latest_alerts(limit=50)
    alerts_csv = load_alert_csv()
    honeypot_df = load_honeypot_logs()
    ueba_df = load_ueba_history()
    
    # ===== TAB 1: DASHBOARD =====
    with tab1:
        st.header("System Overview")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            alert_count = len(alerts_db) if not alerts_db.empty else 0
            st.metric("Total Alerts", alert_count, delta="Real-time")
        
        with col2:
            honeypot_count = len(honeypot_df) if not honeypot_df.empty else 0
            st.metric("Honeypot Captures", honeypot_count)
        
        with col3:
            if not alerts_db.empty and "confidence" in alerts_db.columns:
                avg_confidence = alerts_db["confidence"].mean()
                st.metric("Avg Confidence", f"{avg_confidence:.1%}")
            else:
                st.metric("Avg Confidence", "N/A")
        
        with col4:
            status = "🟢 Running" if st.session_state.get("pipeline_running") else "⚫ Idle"
            st.metric("Pipeline Status", status)
        
        st.divider()
        
        # Alert distribution
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Alert Timeline")
            if not alerts_db.empty:
                alerts_db_copy = alerts_db.copy()
                if "timestamp" in alerts_db_copy.columns:
                    alerts_db_copy["timestamp"] = pd.to_datetime(alerts_db_copy["timestamp"], errors='coerce')
                    alerts_db_copy = alerts_db_copy.dropna(subset=["timestamp"])
                    if not alerts_db_copy.empty:
                        timeline = alerts_db_copy.set_index("timestamp").resample("1H").size()
                        st.line_chart(timeline)
                    else:
                        st.info("No valid timestamps in data")
                else:
                    st.info("No timestamp data")
            else:
                st.info("No alerts yet")
        
        with col2:
            st.subheader("Attack Type Distribution")
            if not alerts_db.empty and "attack_type" in alerts_db.columns:
                attack_dist = alerts_db["attack_type"].value_counts()
                st.bar_chart(attack_dist)
            else:
                st.info("No attack type data")
    
    # ===== TAB 2: ALERTS =====
    with tab2:
        st.header("Real-Time Alerts")
        
        if not alerts_db.empty:
            # Display alerts table
            display_df = alerts_db.copy()
            if "confidence" in display_df.columns:
                display_df["confidence"] = display_df["confidence"].apply(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
            
            st.dataframe(display_df, use_container_width=True)
            
            # Alert details
            st.subheader("Alert Details")
            selected_idx = st.selectbox("Select alert", range(len(alerts_db)))
            if selected_idx is not None:
                alert = alerts_db.iloc[selected_idx]
                
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Source IP:** {alert.get('src_ip', 'N/A')}")
                    st.write(f"**Timestamp:** {alert.get('timestamp', 'N/A')}")
                
                with col2:
                    st.write(f"**Destination IP:** {alert.get('dst_ip', 'N/A')}")
                    st.write(f"**Attack Type:** {alert.get('attack_type', 'N/A')}")
        else:
            st.info("⏳ No alerts yet. Start the pipeline to begin detection.")
    
    # ===== TAB 3: ATTACK CHAIN =====
    with tab3:
        st.header("Attack Chain Analysis")
        
        if not alerts_csv.empty:
            if "src_ip" in alerts_csv.columns and "dst_port" in alerts_csv.columns:
                st.subheader("Source IPs and Target Ports")
                
                attack_chain = alerts_csv.groupby(["src_ip", "dst_port"]).size().reset_index(name="attempts")
                attack_chain = attack_chain.sort_values("attempts", ascending=False).head(20)
                
                st.dataframe(attack_chain, use_container_width=True)
            else:
                st.info("No attack chain data available")
        else:
            st.info("No data available")
    
    # ===== TAB 4: HONEYPOT =====
    with tab4:
        st.header("Deception Metrics (Honeypot)")
        
        if not honeypot_df.empty:
            col1, col2 = st.columns(2)
            
            with col1:
                st.metric("Total Captures", len(honeypot_df))
            
            with col2:
                unique_ips = honeypot_df["attacker_ip"].nunique() if "attacker_ip" in honeypot_df.columns else 0
                st.metric("Unique Attackers", unique_ips)
            
            st.subheader("Honeypot Activity Log")
            st.dataframe(honeypot_df, use_container_width=True)
        else:
            st.info("🐝 Honeypot is active but no captures yet.")
    
    # ===== TAB 5: UEBA =====
    with tab5:
        st.header("User & Entity Behavior Analytics")
        
        if not ueba_df.empty:
            st.subheader("Traffic Pattern Analysis")
            
            ueba_copy = ueba_df.copy()
            if "timestamp" in ueba_copy.columns and "bytes" in ueba_copy.columns:
                ueba_copy["timestamp"] = pd.to_datetime(ueba_copy["timestamp"], errors='coerce')
                ueba_copy = ueba_copy.dropna(subset=["timestamp"])
                
                if not ueba_copy.empty:
                    ueba_plot = ueba_copy.set_index("timestamp")["bytes"]
                    st.line_chart(ueba_plot)
                    
                    st.subheader("Statistics")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Avg Bytes/sec", f"{ueba_copy['bytes'].mean():.0f}")
                    with col2:
                        st.metric("Max Bytes/sec", f"{ueba_copy['bytes'].max():.0f}")
                    with col3:
                        st.metric("Min Bytes/sec", f"{ueba_copy['bytes'].min():.0f}")
                else:
                    st.info("No valid UEBA data")
            else:
                st.info("No timestamp or bytes data in UEBA logs")
        else:
            st.info("📊 No UEBA data available yet.")
    
    # Footer
    st.divider()
    st.caption("🛡️ ZeroBit v1.0 | AI-Powered Network Intrusion Detection")


if __name__ == "__main__":
    main()
