"""
<<<<<<< HEAD
ZeroBit SOC Dashboard - Enhanced Version with Dark Theme
=======
ZeroBit SOC Dashboard - Simplified Working Version
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
"""
import json
import os
import sqlite3
<<<<<<< HEAD
import time
from pathlib import Path
from typing import List, Optional
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
=======
from pathlib import Path
from typing import List

import pandas as pd
import streamlit as st
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47

# Safe imports with fallbacks
try:
    from src.threat_intel import ThreatIntel
    HAS_THREAT_INTEL = True
<<<<<<< HEAD
except (ImportError, ModuleNotFoundError, Exception):
    HAS_THREAT_INTEL = False
    ThreatIntel = None
=======
except:
    HAS_THREAT_INTEL = False
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47

try:
    from src.mitre import get_mitre_details
    HAS_MITRE = True
<<<<<<< HEAD
except (ImportError, ModuleNotFoundError, Exception):
    HAS_MITRE = False
    get_mitre_details = None
=======
except:
    HAS_MITRE = False
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47

try:
    from src.feedback import IncidentManager
    HAS_FEEDBACK = True
<<<<<<< HEAD
except (ImportError, ModuleNotFoundError, Exception):
    HAS_FEEDBACK = False
    IncidentManager = None

try:
    from src.advisor import SecurityAdvisor
    HAS_ADVISOR = True
except (ImportError, ModuleNotFoundError, Exception):
    HAS_ADVISOR = False
    SecurityAdvisor = None

try:
    from src.visualization import render_attack_graph
    HAS_VISUALIZATION = True
except (ImportError, ModuleNotFoundError, Exception):
    HAS_VISUALIZATION = False
    render_attack_graph = None

try:
    from src.enrichment import get_ip_details
    HAS_ENRICHMENT = True
except (ImportError, ModuleNotFoundError, Exception):
    HAS_ENRICHMENT = False
    get_ip_details = None
=======
except:
    HAS_FEEDBACK = False
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47


ALERT_DIR = Path("static/alerts")
ALERTS_DB = Path("data/alerts.db")
HONEYPOT_LOG = Path("data/honeypot_logs.json")
UEBA_LOG = Path("data/ueba_history.json")
ALERT_CSV = Path("data/alerts.csv")


<<<<<<< HEAD
def fetch_latest_alerts(limit: int = 100) -> pd.DataFrame:
=======
def fetch_latest_alerts(limit: int = 10) -> pd.DataFrame:
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
    """Fetch latest alerts from SQLite database."""
    if not ALERTS_DB.exists():
        return pd.DataFrame()
    
    try:
        conn = sqlite3.connect(ALERTS_DB)
        df = pd.read_sql_query(
            f"""
<<<<<<< HEAD
            SELECT id, timestamp, src_ip, dst_ip, dst_port, attack_type, confidence
=======
            SELECT id, timestamp, src_ip, dst_ip, attack_type, confidence
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
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


<<<<<<< HEAD
def get_priority_badge(confidence: float) -> str:
    """Get priority badge based on confidence score."""
    if confidence >= 0.9:
        return "🔴 P0-Critical"
    elif confidence >= 0.7:
        return "🟠 P1-High"
    elif confidence >= 0.5:
        return "🟡 P2-Medium"
    else:
        return "🟢 P3-Low"


def apply_dark_theme(fig):
    """Apply dark theme to Plotly figure. Handles both regular and geographic plots."""
    try:
        # Check if this is a geographic plot
        is_geo_plot = hasattr(fig.layout, 'geo') and fig.layout.geo is not None
        
        # Update general layout properties
        layout_updates = {
            "paper_bgcolor": "rgba(0,0,0,0)",
            "plot_bgcolor": "rgba(0,0,0,0)",
            "font": dict(color='white')
        }
        
        # Only add xaxis/yaxis updates for non-geo plots
        if not is_geo_plot:
            layout_updates["xaxis"] = dict(
                gridcolor='rgba(255,255,255,0.1)',
                linecolor='rgba(255,255,255,0.3)',
                titlefont=dict(color='white'),
                tickfont=dict(color='white')
            )
            layout_updates["yaxis"] = dict(
                gridcolor='rgba(255,255,255,0.1)',
                linecolor='rgba(255,255,255,0.3)',
                titlefont=dict(color='white'),
                tickfont=dict(color='white')
            )
        
        fig.update_layout(**layout_updates)
        
    except Exception:
        # If update fails, try minimal update
        try:
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color='white')
            )
        except Exception:
            pass  # Return figure as-is if all updates fail
    
    return fig


def create_threat_map(alerts_df: pd.DataFrame) -> Optional[go.Figure]:
    """Create geographic threat map using Plotly with dark theme."""
    if alerts_df.empty or "src_ip" not in alerts_df.columns:
        return None
    
    # Get unique IPs and their counts
    ip_counts = alerts_df["src_ip"].value_counts().head(20)
    
    # Get geo data for IPs
    geo_data = []
    for ip, count in ip_counts.items():
        if HAS_ENRICHMENT and get_ip_details:
            try:
                details = get_ip_details(ip)
                if details.get("lat") and details.get("lon"):
                    geo_data.append({
                        "ip": ip,
                        "lat": details["lat"],
                        "lon": details["lon"],
                        "country": details.get("country", "Unknown"),
                        "count": count,
                        "city": details.get("city", "Unknown")
                    })
            except:
                continue
    
    if not geo_data:
        return None
    
    geo_df = pd.DataFrame(geo_data)
    
    # Ensure data types are correct and convert to lists
    try:
        geo_df["lon"] = pd.to_numeric(geo_df["lon"], errors='coerce')
        geo_df["lat"] = pd.to_numeric(geo_df["lat"], errors='coerce')
        geo_df["count"] = pd.to_numeric(geo_df["count"], errors='coerce').fillna(0).astype(int)
        
        # Remove any rows with invalid coordinates
        geo_df = geo_df.dropna(subset=["lon", "lat"])
        
        if geo_df.empty:
            return None
        
        # Convert to lists for Plotly
        lon_list = geo_df["lon"].tolist()
        lat_list = geo_df["lat"].tolist()
        count_list = geo_df["count"].tolist()
        text_list = (geo_df["ip"] + "<br>" + geo_df["country"] + "<br>Attacks: " + geo_df["count"].astype(str)).tolist()
        size_list = (geo_df["count"] * 3).tolist()
    except Exception:
        return None
    
    fig = go.Figure()
    
    fig.add_trace(go.Scattergeo(
        lon=lon_list,
        lat=lat_list,
        text=text_list,
        mode='markers',
        marker=dict(
            size=size_list,
            color=count_list,
            colorscale='Reds',
            showscale=True,
            colorbar=dict(
                title="Attack Count",
                thickness=15,
                len=0.5
            ),
            line=dict(width=2, color='#FF6B6B'),
            opacity=0.8
        ),
        hovertemplate='<b>%{text}</b><extra></extra>'
    ))
    
    fig.update_layout(
        title=dict(
            text="🌍 Global Threat Map",
            font=dict(color='white', size=18)
        ),
        geo=dict(
            projection_type="natural earth",
            showland=True,
            landcolor="rgb(40, 40, 40)",  # Dark gray land
            coastlinecolor="rgb(100, 100, 100)",  # Gray coastlines
            oceancolor="rgb(20, 20, 30)",  # Dark blue ocean
            bgcolor="rgb(20, 20, 30)",  # Dark background
            lakecolor="rgb(20, 20, 30)",
            showocean=True,
            showlakes=True,
            showcountries=True,
            countrycolor="rgb(80, 80, 80)",  # Gray country borders
            showframe=True,
            framecolor="rgb(60, 60, 60)",
            framewidth=1
        ),
        height=500,
        margin=dict(l=0, r=0, t=50, b=0),
        paper_bgcolor="rgba(0,0,0,0)",  # Transparent paper background
        plot_bgcolor="rgba(0,0,0,0)",  # Transparent plot background
        font=dict(color='white')
    )
    
    return fig


def main():
    st.set_page_config(
        layout="wide", 
        page_title="ZeroBit SOC Dashboard", 
        page_icon="🛡️",
        initial_sidebar_state="expanded"
    )
    
    # Custom CSS for dark theme styling
    st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
    }
    .metric-card {
        background-color: #1e1e1e;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .priority-critical { color: #dc3545; font-weight: bold; }
    .priority-high { color: #fd7e14; font-weight: bold; }
    .priority-medium { color: #ffc107; font-weight: bold; }
    .priority-low { color: #28a745; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)
=======
def main():
    st.set_page_config(layout="wide", page_title="ZeroBit SOC Dashboard", page_icon="🛡️")
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
    
    # Create necessary directories
    ALERT_DIR.mkdir(parents=True, exist_ok=True)
    Path("data").mkdir(exist_ok=True)
    
    # Initialize session state
    if "pipeline_running" not in st.session_state:
        st.session_state["pipeline_running"] = False
<<<<<<< HEAD
    if "auto_refresh" not in st.session_state:
        st.session_state["auto_refresh"] = False
    
    # Initialize managers
    threat_intel = ThreatIntel() if HAS_THREAT_INTEL and ThreatIntel else None
    incident_manager = IncidentManager() if HAS_FEEDBACK and IncidentManager else None
    security_advisor = None
    
    # Title and description
    col_title, col_status = st.columns([3, 1])
    with col_title:
        st.title("🛡️ ZeroBit: AI-Powered Network Threat Detection")
        st.markdown("""
        **Advanced Intrusion Detection & Response Platform** | 
        Real-time ML Detection • Encrypted Traffic Analysis • UEBA • Active Defense
        """)
    with col_status:
        status_color = "🟢" if st.session_state.get("pipeline_running") else "⚫"
        st.markdown(f"### {status_color} Pipeline: {'Running' if st.session_state.get('pipeline_running') else 'Idle'}")
    
    # Sidebar controls
    with st.sidebar:
        st.header("⚙️ Control Panel")
        
        # Pipeline controls
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start", use_container_width=True):
                st.session_state["pipeline_running"] = True
                st.success("Pipeline started!")
                st.rerun()
        with col2:
            if st.button("⏹️ Stop", use_container_width=True):
                st.session_state["pipeline_running"] = False
                st.info("Pipeline stopped")
                st.rerun()
        
        st.divider()
        
        # Auto-refresh toggle
        auto_refresh = st.checkbox("🔄 Auto-refresh (30s)", value=st.session_state.get("auto_refresh", False))
        st.session_state["auto_refresh"] = auto_refresh
        
        st.divider()
    
    # API Keys section
        st.subheader("🔑 API Configuration")
        groq_key = st.text_input("Groq API Key", type="password", help="For AI security advisor")
        if groq_key and HAS_ADVISOR:
            security_advisor = SecurityAdvisor(api_key=groq_key)
        
        abuse_key = st.text_input("AbuseIPDB Key", type="password", help="For IP reputation")
        vt_key = st.text_input("VirusTotal Key", type="password", help="For file/URL analysis")
        
        if abuse_key and threat_intel:
            threat_intel.abuseipdb_key = abuse_key
        if vt_key and threat_intel:
            threat_intel.virustotal_key = vt_key
        
        st.divider()
        
        # Filter options
        st.subheader("🔍 Filters")
        filter_confidence = st.slider("Min Confidence", 0.0, 1.0, 0.0, 0.05)
        filter_time = st.selectbox("Time Range", ["All Time", "Last 24h", "Last 7d", "Last 30d"])
        
        st.divider()
        st.caption("🛡️ ZeroBit v2.0 | Enhanced Dashboard")
    
    # Create tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
=======
    
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
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
        "📊 Dashboard", 
        "🚨 Alerts", 
        "🕸️ Attack Chain", 
        "🐝 Honeypot",
<<<<<<< HEAD
        "📈 UEBA",
        "🌍 Threat Intel"
    ])
    
    # Load data
    alerts_db = fetch_latest_alerts(limit=100)
=======
        "📈 UEBA"
    ])
    
    # Load data
    alerts_db = fetch_latest_alerts(limit=50)
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
    alerts_csv = load_alert_csv()
    honeypot_df = load_honeypot_logs()
    ueba_df = load_ueba_history()
    
<<<<<<< HEAD
    # Apply filters
    if not alerts_db.empty:
        if "confidence" in alerts_db.columns:
            alerts_db = alerts_db[alerts_db["confidence"] >= filter_confidence]
        
        if filter_time != "All Time":
            alerts_db["timestamp"] = pd.to_datetime(alerts_db["timestamp"], errors='coerce')
            now = datetime.now()
            if filter_time == "Last 24h":
                cutoff = now - timedelta(hours=24)
            elif filter_time == "Last 7d":
                cutoff = now - timedelta(days=7)
            else:
                cutoff = now - timedelta(days=30)
            alerts_db = alerts_db[alerts_db["timestamp"] >= cutoff]
    
    # ===== TAB 1: ENHANCED DASHBOARD =====
    with tab1:
        st.header("📊 System Overview")
        
        # Enhanced metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            alert_count = len(alerts_db) if not alerts_db.empty else 0
            st.metric("Total Alerts", alert_count, delta=f"{alert_count} active" if alert_count > 0 else None)
        
        with col2:
            high_risk = len(alerts_db[(alerts_db["confidence"] >= 0.7)]) if not alerts_db.empty and "confidence" in alerts_db.columns else 0
            st.metric("High Risk", high_risk, delta="⚠️" if high_risk > 0 else None, delta_color="inverse")
        
        with col3:
            honeypot_count = len(honeypot_df) if not honeypot_df.empty else 0
            st.metric("Honeypot Captures", honeypot_count)
        
        with col4:
=======
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
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
            if not alerts_db.empty and "confidence" in alerts_db.columns:
                avg_confidence = alerts_db["confidence"].mean()
                st.metric("Avg Confidence", f"{avg_confidence:.1%}")
            else:
                st.metric("Avg Confidence", "N/A")
        
<<<<<<< HEAD
        with col5:
            unique_attackers = alerts_db["src_ip"].nunique() if not alerts_db.empty and "src_ip" in alerts_db.columns else 0
            st.metric("Unique Attackers", unique_attackers)
        
        st.divider()
        
        # Enhanced charts with Plotly
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Alert Timeline")
            if not alerts_db.empty and "timestamp" in alerts_db.columns:
                alerts_db_copy = alerts_db.copy()
                alerts_db_copy["timestamp"] = pd.to_datetime(alerts_db_copy["timestamp"], errors='coerce')
                alerts_db_copy = alerts_db_copy.dropna(subset=["timestamp"])
                if not alerts_db_copy.empty:
                    timeline = alerts_db_copy.set_index("timestamp").resample("1h").size().reset_index()
                    timeline.columns = ["timestamp", "count"]
                    
                    fig = px.line(timeline, x="timestamp", y="count", 
                                 title="Alerts Over Time",
                                 labels={"count": "Alert Count", "timestamp": "Time"})
                    fig.update_traces(line_color='#FF6B6B', line_width=2)
                    fig.update_layout(height=300, showlegend=False)
                    fig = apply_dark_theme(fig)
                    st.plotly_chart(fig, use_container_width=True, theme="streamlit")
                else:
                    st.info("No valid timestamps in data")
=======
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
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
            else:
                st.info("No alerts yet")
        
        with col2:
<<<<<<< HEAD
            st.subheader("📊 Attack Type Distribution")
            if not alerts_db.empty and "attack_type" in alerts_db.columns:
                attack_dist = alerts_db["attack_type"].value_counts().head(10)
                
                fig = px.bar(x=attack_dist.index, y=attack_dist.values,
                           title="Top Attack Types",
                           labels={"x": "Attack Type", "y": "Count"})
                fig.update_traces(marker_color='#4ECDC4')
                fig.update_layout(height=300, showlegend=False, xaxis_tickangle=-45)
                fig = apply_dark_theme(fig)
                st.plotly_chart(fig, use_container_width=True, theme="streamlit")
            else:
                st.info("No attack type data")
    
        # Threat Map
        if not alerts_db.empty:
            st.subheader("🌍 Geographic Threat Map")
            threat_map = create_threat_map(alerts_db)
            if threat_map:
                st.plotly_chart(threat_map, use_container_width=True, theme="streamlit")
            else:
                st.info("Geographic data not available. Enable IP enrichment for threat map.")
        
        # Top Attackers Table
        if not alerts_db.empty and "src_ip" in alerts_db.columns:
            st.subheader("🎯 Top Attackers")
            attacker_stats = alerts_db.groupby("src_ip").agg({
                "confidence": "mean",
                "attack_type": "count"
            }).reset_index()
            attacker_stats.columns = ["IP Address", "Avg Confidence", "Attack Count"]
            attacker_stats = attacker_stats.sort_values("Attack Count", ascending=False).head(10)
            st.dataframe(attacker_stats, width='stretch', hide_index=True)
    
    # ===== TAB 2: ENHANCED ALERTS =====
    with tab2:
        st.header("🚨 Real-Time Alerts")
        
        if not alerts_db.empty:
            # Search and filter
            col_search, col_sort = st.columns([2, 1])
            with col_search:
                search_term = st.text_input("🔍 Search alerts (IP, type, etc.)", "")
            with col_sort:
                sort_by = st.selectbox("Sort by", ["Timestamp", "Confidence", "Attack Type"])
            
            # Apply search
            display_df = alerts_db.copy()
            if search_term:
                mask = (
                    display_df["src_ip"].astype(str).str.contains(search_term, case=False, na=False) |
                    display_df["attack_type"].astype(str).str.contains(search_term, case=False, na=False) |
                    display_df["dst_ip"].astype(str).str.contains(search_term, case=False, na=False)
                )
                display_df = display_df[mask]
            
            # Apply sorting
            if sort_by == "Confidence" and "confidence" in display_df.columns:
                display_df = display_df.sort_values("confidence", ascending=False)
            elif sort_by == "Attack Type" and "attack_type" in display_df.columns:
                display_df = display_df.sort_values("attack_type")
            else:
                display_df = display_df.sort_values("timestamp", ascending=False)
            
            # Add priority column
            if "confidence" in display_df.columns:
                display_df["Priority"] = display_df["confidence"].apply(get_priority_badge)
            
            # Format confidence
            if "confidence" in display_df.columns:
                display_df["Confidence"] = display_df["confidence"].apply(lambda x: f"{x:.1%}" if pd.notna(x) else "N/A")
                display_df = display_df.drop(columns=["confidence"])
            
            st.dataframe(display_df, width='stretch', hide_index=True)
            
            # Alert details
            st.subheader("📋 Alert Details")
            if len(display_df) > 0:
                selected_idx = st.selectbox("Select alert", range(len(display_df)), format_func=lambda x: f"Alert #{display_df.iloc[x].get('id', x)}")
                if selected_idx is not None and selected_idx < len(display_df):
                    alert = display_df.iloc[selected_idx]
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.markdown("### Source Information")
                        st.write(f"**IP:** {alert.get('src_ip', 'N/A')}")
                        st.write(f"**Timestamp:** {alert.get('timestamp', 'N/A')}")
                        if HAS_ENRICHMENT and get_ip_details:
                            try:
                                ip_details = get_ip_details(alert.get('src_ip', ''))
                                if ip_details:
                                    st.write(f"**Location:** {ip_details.get('city', 'N/A')}, {ip_details.get('country', 'N/A')}")
                            except:
                                pass
                    
                    with col2:
                        st.markdown("### Attack Details")
                        st.write(f"**Type:** {alert.get('attack_type', 'N/A')}")
                        st.write(f"**Destination:** {alert.get('dst_ip', 'N/A')}")
                        if 'dst_port' in alert:
                            st.write(f"**Port:** {alert.get('dst_port', 'N/A')}")
                        if "Confidence" in alert:
                            st.write(f"**Confidence:** {alert.get('Confidence', 'N/A')}")
                    
                    with col3:
                        st.markdown("### Threat Intelligence")
                        if threat_intel and alert.get('src_ip'):
                            try:
                                with st.spinner("Fetching threat intel..."):
                                    threat_score = threat_intel.get_combined_score(alert.get('src_ip', ''))
                                    st.metric("Threat Score", f"{threat_score.get('threat_score', 0):.1f}/100")
                                    st.write(f"**Risk Level:** {threat_score.get('risk_level', 'Unknown')}")
                                    st.write(f"**Abuse Count:** {threat_score.get('abuseipdb', {}).get('abuse_count', 0)}")
                            except:
                                st.info("Threat intel unavailable")
                        
                        # MITRE ATT&CK mapping
                        if HAS_MITRE and get_mitre_details and alert.get('attack_type'):
                            try:
                                mitre_info = get_mitre_details(alert.get('attack_type', ''))
                                st.markdown("### MITRE ATT&CK")
                                st.write(f"**Technique:** {mitre_info.get('id', 'N/A')}")
                                st.write(f"**Name:** {mitre_info.get('name', 'N/A')}")
                                st.write(f"**Phase:** {mitre_info.get('phase', 'N/A')}")
                            except:
                                pass
        else:
            st.info("⏳ No alerts yet. Start the pipeline to begin detection.")
    
    # ===== TAB 3: ENHANCED ATTACK CHAIN =====
    with tab3:
        st.header("🕸️ Attack Chain Analysis")
        
        if not alerts_csv.empty:
            if "src_ip" in alerts_csv.columns and "dst_port" in alerts_csv.columns:
                # Interactive attack graph
                if HAS_VISUALIZATION and render_attack_graph:
                    st.subheader("Interactive Attack Graph")
                    alerts_list = alerts_csv.to_dict('records')
                    render_attack_graph(alerts_list[:50])  # Limit for performance
                
                st.subheader("Source IPs and Target Ports")
                attack_chain = alerts_csv.groupby(["src_ip", "dst_port"]).size().reset_index(name="attempts")
                attack_chain = attack_chain.sort_values("attempts", ascending=False).head(20)
                
                # Enhanced visualization
                fig = px.scatter(attack_chain, x="src_ip", y="dst_port", size="attempts",
                               title="Attack Pattern: Source IP vs Target Port",
                               labels={"src_ip": "Source IP", "dst_port": "Target Port", "attempts": "Attempts"})
                fig.update_layout(height=400)
                fig = apply_dark_theme(fig)
                st.plotly_chart(fig, use_container_width=True, theme="streamlit")
                
                st.dataframe(attack_chain, width='stretch', hide_index=True)
=======
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
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
            else:
                st.info("No attack chain data available")
        else:
            st.info("No data available")
    
<<<<<<< HEAD
    # ===== TAB 4: ENHANCED HONEYPOT =====
    with tab4:
        st.header("🐝 Deception Metrics (Honeypot)")
        
        if not honeypot_df.empty:
            col1, col2, col3 = st.columns(3)
=======
    # ===== TAB 4: HONEYPOT =====
    with tab4:
        st.header("Deception Metrics (Honeypot)")
        
        if not honeypot_df.empty:
            col1, col2 = st.columns(2)
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
            
            with col1:
                st.metric("Total Captures", len(honeypot_df))
            
            with col2:
                unique_ips = honeypot_df["attacker_ip"].nunique() if "attacker_ip" in honeypot_df.columns else 0
                st.metric("Unique Attackers", unique_ips)
            
<<<<<<< HEAD
            with col3:
                if "timestamp" in honeypot_df.columns:
                    honeypot_df["timestamp"] = pd.to_datetime(honeypot_df["timestamp"], errors='coerce')
                    recent = len(honeypot_df[honeypot_df["timestamp"] >= datetime.now() - timedelta(days=1)])
                    st.metric("Last 24h", recent)
            
            # Timeline chart
            if "timestamp" in honeypot_df.columns:
                st.subheader("Honeypot Activity Timeline")
                honeypot_timeline = honeypot_df.copy()
                honeypot_timeline["timestamp"] = pd.to_datetime(honeypot_timeline["timestamp"], errors='coerce')
                honeypot_timeline = honeypot_timeline.dropna(subset=["timestamp"])
                if not honeypot_timeline.empty:
                    timeline_counts = honeypot_timeline.set_index("timestamp").resample("1h").size().reset_index()
                    timeline_counts.columns = ["timestamp", "count"]
                    fig = px.bar(timeline_counts, x="timestamp", y="count",
                               title="Honeypot Captures Over Time")
                    fig.update_traces(marker_color='#FF6B6B')
                    fig = apply_dark_theme(fig)
                    st.plotly_chart(fig, use_container_width=True, theme="streamlit")
            
            st.subheader("Honeypot Activity Log")
            st.dataframe(honeypot_df, width='stretch', hide_index=True)
        else:
            st.info("🐝 Honeypot is active but no captures yet.")
    
    # ===== TAB 5: ENHANCED UEBA =====
    with tab5:
        st.header("📈 User & Entity Behavior Analytics")
=======
            st.subheader("Honeypot Activity Log")
            st.dataframe(honeypot_df, use_container_width=True)
        else:
            st.info("🐝 Honeypot is active but no captures yet.")
    
    # ===== TAB 5: UEBA =====
    with tab5:
        st.header("User & Entity Behavior Analytics")
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
        
        if not ueba_df.empty:
            st.subheader("Traffic Pattern Analysis")
            
            ueba_copy = ueba_df.copy()
            if "timestamp" in ueba_copy.columns and "bytes" in ueba_copy.columns:
                ueba_copy["timestamp"] = pd.to_datetime(ueba_copy["timestamp"], errors='coerce')
                ueba_copy = ueba_copy.dropna(subset=["timestamp"])
                
                if not ueba_copy.empty:
<<<<<<< HEAD
                    # Enhanced line chart with Plotly
                    fig = px.line(ueba_copy, x="timestamp", y="bytes",
                                title="Network Traffic Over Time",
                                labels={"bytes": "Bytes", "timestamp": "Time"})
                    fig.update_traces(line_color='#4ECDC4', line_width=2)
                    fig.update_layout(height=400)
                    fig = apply_dark_theme(fig)
                    st.plotly_chart(fig, use_container_width=True, theme="streamlit")
                    
                    # Statistics
                    st.subheader("📊 Statistics")
                    col1, col2, col3, col4 = st.columns(4)
=======
                    ueba_plot = ueba_copy.set_index("timestamp")["bytes"]
                    st.line_chart(ueba_plot)
                    
                    st.subheader("Statistics")
                    col1, col2, col3 = st.columns(3)
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
                    with col1:
                        st.metric("Avg Bytes/sec", f"{ueba_copy['bytes'].mean():.0f}")
                    with col2:
                        st.metric("Max Bytes/sec", f"{ueba_copy['bytes'].max():.0f}")
                    with col3:
                        st.metric("Min Bytes/sec", f"{ueba_copy['bytes'].min():.0f}")
<<<<<<< HEAD
                    with col4:
                        st.metric("Std Deviation", f"{ueba_copy['bytes'].std():.0f}")
                    
                    # IP-based analysis
                    if "ip" in ueba_copy.columns:
                        st.subheader("Top Traffic Sources")
                        ip_stats = ueba_copy.groupby("ip")["bytes"].agg(['sum', 'mean', 'count']).reset_index()
                        ip_stats.columns = ["IP Address", "Total Bytes", "Avg Bytes", "Event Count"]
                        ip_stats = ip_stats.sort_values("Total Bytes", ascending=False).head(10)
                        st.dataframe(ip_stats, width='stretch', hide_index=True)
=======
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47
                else:
                    st.info("No valid UEBA data")
            else:
                st.info("No timestamp or bytes data in UEBA logs")
        else:
            st.info("📊 No UEBA data available yet.")
    
<<<<<<< HEAD
    # ===== TAB 6: THREAT INTELLIGENCE =====
    with tab6:
        st.header("🌍 Threat Intelligence & Enrichment")
        
        if threat_intel:
            st.subheader("IP Reputation Lookup")
            lookup_ip = st.text_input("Enter IP address to analyze", "")
            
            if lookup_ip:
                try:
                    with st.spinner("Fetching threat intelligence..."):
                        threat_score = threat_intel.get_combined_score(lookup_ip)
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("Threat Score", f"{threat_score.get('threat_score', 0):.1f}/100")
                            risk_level = threat_score.get('risk_level', 'Unknown')
                            risk_colors = {
                                'Critical': '🔴',
                                'High': '🟠',
                                'Medium': '🟡',
                                'Low': '🟢'
                            }
                            st.write(f"**Risk Level:** {risk_colors.get(risk_level, '⚪')} {risk_level}")
                        
                        with col2:
                            abuse_data = threat_score.get('abuseipdb', {})
                            st.write(f"**Abuse Confidence:** {abuse_data.get('confidence', 0)}%")
                            st.write(f"**Abuse Reports:** {abuse_data.get('abuse_count', 0)}")
                            st.write(f"**Usage Type:** {abuse_data.get('usage_type', 'Unknown')}")
                        
                        # VirusTotal data
                        if "virustotal" in threat_score:
                            st.subheader("VirusTotal Analysis")
                            vt_data = threat_score.get('virustotal', {})
                            col_vt1, col_vt2, col_vt3, col_vt4 = st.columns(4)
                            with col_vt1:
                                st.metric("Malicious", vt_data.get('malicious', 0))
                            with col_vt2:
                                st.metric("Suspicious", vt_data.get('suspicious', 0))
                            with col_vt3:
                                st.metric("Harmless", vt_data.get('harmless', 0))
                            with col_vt4:
                                st.metric("Undetected", vt_data.get('undetected', 0))
                except Exception as e:
                    st.error(f"Error fetching threat intelligence: {e}")
        else:
            st.info("Threat intelligence module not available. Configure API keys in sidebar.")
        
        # Top threats summary
        if not alerts_db.empty and "src_ip" in alerts_db.columns:
            st.subheader("Top Threat IPs")
            top_ips = alerts_db["src_ip"].value_counts().head(10)
            threat_summary = pd.DataFrame({
                "IP Address": top_ips.index,
                "Alert Count": top_ips.values
            })
            st.dataframe(threat_summary, width='stretch', hide_index=True)
    
    # Auto-refresh handled via Streamlit's built-in mechanism
    # Note: Auto-refresh in Streamlit is better handled with st.rerun() on button click
    # or using Streamlit's native auto-refresh features
    
    # Footer
    st.divider()
    st.caption("🛡️ ZeroBit v2.0 Enhanced | AI-Powered Network Intrusion Detection")
=======
    # Footer
    st.divider()
    st.caption("🛡️ ZeroBit v1.0 | AI-Powered Network Intrusion Detection")
>>>>>>> 766c7e1fe5dbb41d48b625425c5c1a1c985b7d47


if __name__ == "__main__":
    main()
