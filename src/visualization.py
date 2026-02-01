"""
Attack Chain Visualization Module for ZeroBit.
Creates graph-based visualizations of attack progression and relationships.
"""

from __future__ import annotations

from typing import List, Dict, Any

import networkx as nx  # type: ignore
from streamlit_agraph import agraph, Node, Edge, Config  # type: ignore


def render_attack_graph(alerts_list: List[Dict[str, Any]]) -> None:
    """
    Render an interactive attack chain graph using streamlit-agraph.
    Creates nodes for IPs and ports, edges for attack types.
    """
    if not alerts_list:
        return

    # Build NetworkX graph
    G = nx.DiGraph()

    # Extract unique IPs and ports
    ip_nodes = set()
    port_nodes = set()
    edges_data = []

    for alert in alerts_list:
        src_ip = alert.get("src_ip") or alert.get("ip", "Unknown")
        dst_port = alert.get("dst_port") or alert.get("port", "Unknown")
        attack_type = alert.get("attack_type") or alert.get("reason", "Unknown Attack")
        timestamp = alert.get("timestamp", "")

        if src_ip != "Unknown":
            ip_nodes.add(src_ip)
        if dst_port != "Unknown":
            port_nodes.add(f"Port {dst_port}")

        # Create edge: IP -> Port (with attack type as label)
        if src_ip != "Unknown" and dst_port != "Unknown":
            edge_key = (src_ip, f"Port {dst_port}")
            if edge_key not in edges_data:
                edges_data.append(
                    {
                        "source": src_ip,
                        "target": f"Port {dst_port}",
                        "label": attack_type[:30],  # Truncate long labels
                        "timestamp": timestamp,
                    }
                )

    # Convert to agraph format
    nodes = []
    edges = []

    # IP nodes (red - attackers)
    for ip in ip_nodes:
        nodes.append(
            Node(
                id=ip,
                label=ip,
                size=25,
                color="#FF6B6B",  # Red for attackers
                shape="dot",
            )
        )

    # Port nodes (blue - targets)
    for port in port_nodes:
        nodes.append(
            Node(
                id=port,
                label=port,
                size=20,
                color="#4ECDC4",  # Teal for ports
                shape="square",
            )
        )

    # Edges (attack connections)
    for edge_data in edges_data:
        edges.append(
            Edge(
                source=edge_data["source"],
                target=edge_data["target"],
                label=edge_data["label"],
                color="#95A5A6",  # Gray edges
            )
        )

    # Graph configuration
    config = Config(
        width=800,
        height=600,
        directed=True,
        physics=True,
        hierarchical=False,
        nodeHighlightBehavior=True,
        highlightColor="#F7A072",
        collapsible=False,
    )

    # Render graph
    if nodes:
        agraph(nodes=nodes, edges=edges, config=config)
    else:
        return


def build_attack_timeline(alerts_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a timeline structure for attack progression visualization.
    Returns a dict with stages and timestamps.
    """
    if not alerts_list:
        return {"stages": [], "timeline": []}

    # Group by IP and sort by timestamp
    timeline = []
    for alert in sorted(alerts_list, key=lambda x: x.get("timestamp", "")):
        timeline.append(
            {
                "timestamp": alert.get("timestamp", ""),
                "ip": alert.get("src_ip") or alert.get("ip", "Unknown"),
                "attack": alert.get("attack_type") or alert.get("reason", "Unknown"),
                "port": alert.get("dst_port") or alert.get("port", "N/A"),
            }
        )

    return {"stages": ["Reconnaissance", "Exploitation", "Lateral Movement"], "timeline": timeline}

