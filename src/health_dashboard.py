"""
System Health Dashboard for ZeroBit.
Displays performance metrics, resource usage, and detection statistics.
"""

from __future__ import annotations

import streamlit as st
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict, Any
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from src.metrics import MetricsTracker
except ImportError:
    MetricsTracker = None


def render_health_dashboard() -> None:
    """Render system health and performance metrics dashboard."""
    st.header("🏥 System Health Dashboard")
    
    if MetricsTracker is None:
        st.warning("Metrics module not available. Install required dependencies.")
        return
    
    # Initialize metrics tracker
    tracker = MetricsTracker()
    health = tracker.get_health_summary()
    
    # Top KPIs
    st.subheader("📊 Key Performance Indicators")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "System Status",
            health["status"],
            delta="All systems operational" if health["status"] == "Healthy" else "Attention needed",
            delta_color="normal" if health["status"] == "Healthy" else "off"
        )
    
    with col2:
        st.metric(
            "Uptime",
            health["uptime"],
            delta="Running continuously"
        )
    
    with col3:
        st.metric(
            "Detections/Hour",
            f"{health['detection_rate_per_hour']:.1f}",
            delta="Real-time alerts"
        )
    
    with col4:
        st.metric(
            "False Positive Rate",
            f"{health['false_positive_rate_percent']:.1f}%",
            delta="Lower is better",
            delta_color="off" if health['false_positive_rate_percent'] > 10 else "normal"
        )
    
    # System Resources
    st.subheader("💻 System Resources")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "CPU Usage",
            f"{health['cpu_percent']:.1f}%",
            delta="Real-time",
            delta_color="inverse" if health['cpu_percent'] > 80 else "normal"
        )
    
    with col2:
        st.metric(
            "Memory Usage",
            f"{health['memory_percent']:.1f}%",
            delta=f"{health['memory_available_gb']:.1f}GB free",
            delta_color="inverse" if health['memory_percent'] > 85 else "normal"
        )
    
    with col3:
        st.metric(
            "Disk Usage",
            f"{health['disk_percent']:.1f}%",
            delta="Storage status",
            delta_color="inverse" if health['disk_percent'] > 90 else "normal"
        )
    
    # Detection Statistics
    st.subheader("📈 Detection Statistics")
    col1, col2 = st.columns(2)
    
    with col1:
        # Average Confidence Chart
        st.metric(
            "Average Confidence",
            f"{health['avg_confidence_percent']:.1f}%",
            delta="Model performance"
        )
        
        # Confidence distribution
        dist = tracker.get_confidence_distribution(hours=24)
        if dist:
            fig = go.Figure(
                data=[go.Bar(
                    x=list(dist.keys()),
                    y=list(dist.values()),
                    marker_color=['#d32f2f', '#f57c00', '#fbc02d', '#7cb342', '#388e3c'],
                    text=list(dist.values()),
                    textposition='auto',
                )]
            )
            fig.update_layout(
                title="Confidence Score Distribution (24h)",
                xaxis_title="Confidence Range",
                yaxis_title="Number of Alerts",
                height=300,
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Detection Timeline
        st.metric(
            "Alerts This Hour",
            f"{health['detection_rate_per_hour']:.0f}",
            delta="Real-time monitoring"
        )
        
        # Hourly trend (simulated)
        hours = list(range(24, 0, -1))
        # This is simplified - in production, fetch actual hourly data
        alerts = [tracker.get_detection_rate(hours=h) for h in [24, 12, 6, 1]]
        
        fig = go.Figure(
            data=[go.Scatter(
                x=["Last 24h", "Last 12h", "Last 6h", "Last 1h"],
                y=alerts,
                mode='lines+markers',
                fill='tozeroy',
                line_color='#1976d2',
                marker=dict(size=8),
            )]
        )
        fig.update_layout(
            title="Detection Rate Trend",
            xaxis_title="Time Period",
            yaxis_title="Alerts per Hour",
            height=300,
            showlegend=False,
            hovermode='x unified',
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Alerts & Accuracy
    st.subheader("🎯 Accuracy Metrics")
    col1, col2 = st.columns(2)
    
    with col1:
        st.info(
            f"""
            **Detection Performance**
            - False Positive Rate: {health['false_positive_rate_percent']:.1f}%
            - Average Confidence: {health['avg_confidence_percent']:.1f}%
            - Detection Rate: {health['detection_rate_per_hour']:.1f} alerts/hour
            """
        )
    
    with col2:
        st.info(
            f"""
            **System Health Status**
            - Status: {health['status']}
            - Uptime: {health['uptime']}
            - CPU: {health['cpu_percent']:.1f}% | Memory: {health['memory_percent']:.1f}%
            - Disk: {health['disk_percent']:.1f}% | Free RAM: {health['memory_available_gb']:.1f}GB
            """
        )
    
    # Alert History
    st.subheader("📋 Recent Performance")
    
    # Create a summary table
    summary_data = {
        "Metric": [
            "Total Detections (24h)",
            "Average Confidence",
            "False Positive Rate",
            "Detection Rate",
            "CPU Usage",
            "Memory Usage",
        ],
        "Value": [
            f"{tracker.get_detection_rate(hours=24) * 24:.0f}",
            f"{health['avg_confidence_percent']:.1f}%",
            f"{health['false_positive_rate_percent']:.1f}%",
            f"{health['detection_rate_per_hour']:.1f}/hour",
            f"{health['cpu_percent']:.1f}%",
            f"{health['memory_percent']:.1f}%",
        ],
        "Status": [
            "✓ Active" if health['detection_rate_per_hour'] > 0 else "○ Idle",
            "✓ Good" if health['avg_confidence_percent'] > 70 else "⚠ Low",
            "✓ Good" if health['false_positive_rate_percent'] < 10 else "⚠ High",
            "✓ Active",
            "✓ Normal" if health['cpu_percent'] < 80 else "⚠ High",
            "✓ Normal" if health['memory_percent'] < 85 else "⚠ High",
        ]
    }
    
    import pandas as pd
    summary_df = pd.DataFrame(summary_data)
    st.dataframe(summary_df, use_container_width=True, hide_index=True)
    
    # Health Recommendations
    st.subheader("💡 Recommendations")
    recommendations = []
    
    if health['cpu_percent'] > 80:
        recommendations.append("⚠️ CPU usage is high. Consider reducing alert volume or upgrading hardware.")
    if health['memory_percent'] > 85:
        recommendations.append("⚠️ Memory usage is high. Check for memory leaks or restart the service.")
    if health['disk_percent'] > 90:
        recommendations.append("⚠️ Disk usage is high. Archive old logs or increase storage.")
    if health['false_positive_rate_percent'] > 20:
        recommendations.append("⚠️ False positive rate is high. Consider tuning the confidence threshold.")
    if health['avg_confidence_percent'] < 60:
        recommendations.append("⚠️ Average confidence is low. Review model performance and training data.")
    
    if recommendations:
        for rec in recommendations:
            st.warning(rec)
    else:
        st.success("✓ All systems operating normally!")
    
    # Refresh button
    col1, col2, col3 = st.columns([1, 1, 1])
    with col1:
        if st.button("🔄 Refresh Metrics", use_container_width=True):
            st.rerun()
    with col2:
        if st.button("📊 Export Report", use_container_width=True):
            # Export summary as JSON
            import json
            report = {
                "timestamp": datetime.now().isoformat(),
                "health_summary": health,
                "confidence_distribution": tracker.get_confidence_distribution(),
            }
            st.download_button(
                label="Download JSON Report",
                data=json.dumps(report, indent=2),
                file_name=f"zerobit_health_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
            )


if __name__ == "__main__":
    st.set_page_config(layout="wide", page_title="ZeroBit: System Health")
    render_health_dashboard()
