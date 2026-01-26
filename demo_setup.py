"""
ZeroBit Demo Data Generator
Creates sample alerts, honeypot logs, and UEBA data for dashboard demonstration
"""
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import random
import csv


def create_demo_alerts_db():
    """Create SQLite database with sample alerts"""
    db_path = Path("data/alerts.db")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Drop existing table if it exists
    cursor.execute("DROP TABLE IF EXISTS alerts")
    
    # Create alerts table
    cursor.execute("""
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            attack_type TEXT,
            confidence REAL,
            is_read INTEGER DEFAULT 0,
            feature_vector TEXT
        )
    """)
    
    # Sample data
    attack_types = [
        "DoS/DDoS Attack",
        "Port Scan",
        "Brute Force",
        "SQL Injection",
        "XSS Attack",
        "Malware Detection",
        "Botnet Communication",
        "Credential Theft",
        "Data Exfiltration",
        "Unauthorized Access"
    ]
    
    source_ips = [
        "203.0.113.45",
        "198.51.100.32",
        "192.0.2.88",
        "203.0.113.100",
        "198.51.100.12",
        "192.0.2.200",
        "203.0.113.250",
        "198.51.100.99"
    ]
    
    dest_ips = [
        "10.0.0.1",
        "10.0.0.50",
        "10.0.0.100",
        "192.168.1.1",
        "192.168.1.50"
    ]
    
    dest_ports = [22, 80, 443, 3306, 5432, 8080, 21, 25, 53, 3389]
    
    # Generate 50 sample alerts over the last 24 hours
    alerts = []
    now = datetime.now()
    
    for i in range(50):
        timestamp = now - timedelta(hours=random.randint(0, 24), minutes=random.randint(0, 59))
        alert = {
            "timestamp": timestamp.isoformat(),
            "src_ip": random.choice(source_ips),
            "dst_ip": random.choice(dest_ips),
            "dst_port": random.choice(dest_ports),
            "attack_type": random.choice(attack_types),
            "confidence": round(random.uniform(0.6, 0.99), 2),
            "is_read": 0
        }
        alerts.append(alert)
    
    # Sort by timestamp descending
    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    
    # Insert into database
    for alert in alerts:
        cursor.execute("""
            INSERT INTO alerts (timestamp, src_ip, dst_ip, dst_port, attack_type, confidence, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["timestamp"],
            alert["src_ip"],
            alert["dst_ip"],
            alert["dst_port"],
            alert["attack_type"],
            alert["confidence"],
            alert["is_read"]
        ))
    
    conn.commit()
    conn.close()
    print(f"✅ Created alerts database with {len(alerts)} sample alerts")


def create_demo_alerts_csv():
    """Create CSV file with sample alerts"""
    csv_path = Path("data/alerts.csv")
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    
    attack_types = [
        "DoS/DDoS Attack",
        "Port Scan",
        "Brute Force",
        "SQL Injection",
        "XSS Attack",
        "Malware Detection",
        "Botnet Communication",
        "Credential Theft",
        "Data Exfiltration",
        "Unauthorized Access"
    ]
    
    source_ips = [
        "203.0.113.45",
        "198.51.100.32",
        "192.0.2.88",
        "203.0.113.100",
        "198.51.100.12",
        "192.0.2.200",
        "203.0.113.250",
        "198.51.100.99"
    ]
    
    dest_ips = [
        "10.0.0.1",
        "10.0.0.50",
        "10.0.0.100",
        "192.168.1.1",
        "192.168.1.50"
    ]
    
    dest_ports = [22, 80, 443, 3306, 5432, 8080, 21, 25, 53, 3389]
    
    now = datetime.now()
    alerts = []
    
    for i in range(40):
        timestamp = now - timedelta(hours=random.randint(0, 24), minutes=random.randint(0, 59))
        alerts.append({
            "timestamp": timestamp.isoformat(),
            "src_ip": random.choice(source_ips),
            "dst_ip": random.choice(dest_ips),
            "dst_port": random.choice(dest_ports),
            "reason": random.choice(attack_types),
            "confidence": round(random.uniform(0.6, 0.99), 2),
            "country": random.choice(["CN", "RU", "US", "UK", "IN"]),
            "isp": random.choice(["Alibaba", "AS206", "Cogent", "Verizon", "MTNL"])
        })
    
    alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
        writer.writeheader()
        writer.writerows(alerts)
    
    print(f"✅ Created alerts CSV with {len(alerts)} entries")


def create_demo_honeypot_logs():
    """Create honeypot interaction logs"""
    log_path = Path("data/honeypot_logs.json")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    honeypot_data = [
        {
            "attacker_ip": "203.0.113.45",
            "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
            "payload": "admin:password123"
        },
        {
            "attacker_ip": "198.51.100.32",
            "timestamp": (datetime.now() - timedelta(hours=6)).isoformat(),
            "payload": "root:12345678"
        },
        {
            "attacker_ip": "192.0.2.88",
            "timestamp": (datetime.now() - timedelta(hours=12)).isoformat(),
            "payload": "user:letmein"
        },
        {
            "attacker_ip": "203.0.113.100",
            "timestamp": (datetime.now() - timedelta(hours=18)).isoformat(),
            "payload": "admin:admin123"
        },
        {
            "attacker_ip": "198.51.100.12",
            "timestamp": (datetime.now() - timedelta(hours=20)).isoformat(),
            "payload": "test:test123"
        }
    ]
    
    with open(log_path, "w") as f:
        json.dump(honeypot_data, f, indent=2)
    
    print(f"✅ Created honeypot logs with {len(honeypot_data)} captures")


def create_demo_ueba_history():
    """Create UEBA behavior history"""
    log_path = Path("data/ueba_history.json")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    ueba_data = []
    now = datetime.now()
    
    # Generate hourly traffic data for the last 24 hours
    for hours_ago in range(24, 0, -1):
        timestamp = now - timedelta(hours=hours_ago)
        
        # Create multiple entries per hour from different IPs
        for _ in range(3):
            ip = f"10.0.0.{random.randint(1, 254)}"
            bytes_transferred = random.randint(1000, 50000)
            
            ueba_data.append({
                "timestamp": timestamp.isoformat(),
                "ip": ip,
                "bytes": bytes_transferred
            })
    
    with open(log_path, "w") as f:
        json.dump(ueba_data, f, indent=2)
    
    print(f"✅ Created UEBA history with {len(ueba_data)} entries")


def create_demo_directories():
    """Create necessary directories for demo"""
    directories = [
        Path("data"),
        Path("models"),
        Path("static/alerts")
    ]
    
    for d in directories:
        d.mkdir(parents=True, exist_ok=True)
    
    print("✅ Created demo directories")


def main():
    print("\n" + "="*60)
    print("🛡️  ZeroBit Demo Data Generator")
    print("="*60 + "\n")
    
    create_demo_directories()
    create_demo_alerts_db()
    create_demo_alerts_csv()
    create_demo_honeypot_logs()
    create_demo_ueba_history()
    
    print("\n" + "="*60)
    print("✅ Demo setup complete!")
    print("="*60)
    print("\n📊 Dashboard is ready to view at http://localhost:8501")
    print("\nDemo data includes:")
    print("  • 50 sample security alerts (various attack types)")
    print("  • 5 honeypot captures with attacker credentials")
    print("  • 72 UEBA entries (24-hour traffic history)")
    print("  • 40 attack chain entries for visualization")
    print("\n" + "="*60 + "\n")


if __name__ == "__main__":
    main()
