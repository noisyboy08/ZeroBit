# 🛡️ ZeroBit Demo Setup Guide

## ✅ What's Running

Your **ZeroBit SOC Dashboard** is now live with demo data!

### 🌐 Access Points
- **Local:** http://localhost:8501
- **Network:** http://10.173.13.58:8501
- **External:** http://152.58.30.143:8501

---

## 📊 Demo Data Overview

The dashboard is populated with realistic security data:

### 🚨 Alerts (50 samples)
- **Source:** Security alerts database
- **Types:** DoS/DDoS, Port Scan, Brute Force, SQL Injection, XSS, Malware, Botnet, etc.
- **Confidence:** 60-99% threat scores
- **Time Range:** Last 24 hours
- **Location:** `data/alerts.db` (SQLite) + `data/alerts.csv`

### 🐝 Honeypot Captures (5 samples)
- **Attacker IPs:** Multiple compromised sources
- **Data:** Captured credentials and payloads
- **Examples:**
  - admin:password123
  - root:12345678
  - user:letmein
- **Location:** `data/honeypot_logs.json`

### 📈 UEBA History (72 entries)
- **Duration:** 24-hour traffic history (hourly)
- **IPs:** 10.0.0.1-254 (internal network)
- **Traffic:** 1-50 KB per hour samples
- **Location:** `data/ueba_history.json`

### 🕸️ Attack Chain (40 entries)
- **Source IPs:** 8 attacker IPs
- **Target Ports:** 22, 80, 443, 3306, 5432, 8080, 21, 25, 53, 3389
- **Destinations:** Internal servers (10.0.0.x, 192.168.1.x)

---

## 📱 Dashboard Tabs Explained

### **1️⃣ Dashboard Tab** 
**Main system overview**
- Total alerts counter
- Honeypot captures count
- Average threat confidence
- Pipeline status indicator
- Alert timeline (hourly distribution)
- Attack type bar chart

**What you'll see:**
- 50 total alerts
- 5 honeypot captures
- Average confidence ~80%
- Real-time visualization of attack patterns

### **2️⃣ Alerts Tab**
**Real-time alert monitoring**
- Full alerts table with columns:
  - Timestamp
  - Source IP
  - Destination IP
  - Attack Type
  - Confidence score

- Alert details selector:
  - Click any alert row to expand details
  - View full attack information
  - See source/destination mapping

**Demo features:**
- 50 diverse attack types
- Various source IPs
- Different confidence levels
- Complete audit trail

### **3️⃣ Attack Chain Tab**
**Attack progression visualization**
- Attack chain graph showing:
  - Source IP → Target Port connections
  - Number of attempts per path
  - Top 20 attack chains (sorted by frequency)

**What to look for:**
- Suspicious IP patterns
- Commonly targeted ports (22, 443, 3306)
- Repeated attack patterns
- High-frequency source IPs

### **4️⃣ Honeypot Tab**
**Deception capture logs**
- Total captures count
- Unique attacker IP count
- Honeypot activity log table

**Demo data shows:**
- 5 captured attempts
- Attacker credentials
- Timestamps of compromise
- Payload information

**Security Insight:**
- This shows how attackers interact with bait systems
- Helps identify attack techniques
- Provides real credential samples for analysis

### **5️⃣ UEBA Tab**
**User & Entity Behavior Analytics**
- 24-hour traffic trend line
- Statistics:
  - Average bytes/second
  - Peak traffic
  - Minimum traffic
- Anomaly detection visualization

**What to observe:**
- Traffic baseline pattern
- Potential spikes (anomalies)
- Normal business hours patterns
- Unusual after-hours activity

---

## 🎮 Interactive Features

### Controls in Sidebar
```
⚙️ Controls
├── ▶️ Start Pipeline      (marks pipeline as running)
├── ⏹️ Stop Pipeline       (stops pipeline)
├── 🔑 API Keys section   (Groq, AbuseIPDB, VirusTotal)
└── [Tabs above]
```

### Try These Actions

1. **View Different Tabs**
   - Click each tab to explore different views
   - Each has unique demo data

2. **Interact with Alerts**
   - Select an alert from the dropdown in "Alerts" tab
   - View full details of the attack

3. **Monitor Timeline**
   - Watch the alert distribution chart
   - See hourly attack patterns

4. **Analyze Honeypot**
   - Check captured credentials
   - Review attacker behavior

5. **Review UEBA**
   - Look for traffic anomalies
   - Identify behavioral patterns

---

## 📂 Generated Demo Files

```
ZeroBit/
├── data/
│   ├── alerts.db          ← 50 sample alerts (SQLite)
│   ├── alerts.csv         ← 40 alerts (CSV format)
│   ├── honeypot_logs.json ← 5 honeypot captures
│   └── ueba_history.json  ← 72 UEBA entries (24 hours)
├── models/                ← Ready for trained ML models
├── static/alerts/         ← Ready for alert images
└── demo_setup.py          ← Generator script
```

---

## 🚀 Next Steps (Production)

### To Use with Real Data:

1. **Train Detection Models**
   ```powershell
   # Use NSL-KDD dataset
   .\venv\Scripts\python.exe -m src.training --dataset data/KDDTrain+.txt --model-path models/zerobit_model.pkl
   ```

2. **Start Real-Time Detection Pipeline**
   ```powershell
   .\venv\Scripts\python.exe -m src.pipeline
   ```
   This will:
   - Capture live packets from your network
   - Run ML detection
   - Store real alerts in the database
   - Update dashboard in real-time

3. **Configure Integrations**
   - Add Groq API key for AI advisor
   - Add AbuseIPDB key for IP reputation
   - Add VirusTotal key for file analysis

4. **Deploy Active Defense**
   - Enable honeypot (Trap Switch)
   - Deploy canary files (Ransomware Kill-Switch)
   - Configure firewall auto-response

---

## 🎯 Demo Scenarios

### Scenario 1: Distributed Attack Analysis
**What to observe:**
1. Go to **Dashboard** tab
2. Look at alert timeline showing attack bursts
3. Switch to **Attack Chain** tab
4. Identify the most active source IPs
5. Check **Alerts** tab for details on high-confidence threats

### Scenario 2: Honeypot Effectiveness
**What to observe:**
1. Navigate to **Honeypot** tab
2. See captured attacker credentials
3. Note timestamp patterns
4. Analyze if attacks cluster during specific times

### Scenario 3: Anomaly Detection
**What to observe:**
1. Go to **UEBA** tab
2. Look at traffic timeline
3. Identify traffic spikes
4. Correlate with alerts in other tabs
5. Hypothesize what caused the anomaly

---

## 🛠️ Troubleshooting

### Dashboard Not Loading?
```powershell
# Restart Streamlit
cd "c:\Users\udayd\OneDrive\Desktop\Zero\ZeroBit"
.\venv\Scripts\streamlit.exe run dashboard/app.py
```

### No Data Showing?
```powershell
# Regenerate demo data
.\venv\Scripts\python.exe demo_setup.py
```

### Want Fresh Data?
```powershell
# Delete old data and regenerate
Remove-Item data\alerts.db, data\alerts.csv, data\honeypot_logs.json, data\ueba_history.json
.\venv\Scripts\python.exe demo_setup.py
```

---

## 📚 Key Metrics to Understand

| Metric | Meaning | Demo Range |
|--------|---------|-----------|
| **Confidence** | ML certainty of threat | 60-99% |
| **Alert Count** | Total detected incidents | 50 |
| **Honeypot Captures** | Successful deception traps | 5 |
| **Unique Attackers** | Distinct source IPs | 8 |
| **Attack Types** | Threat categories detected | 10 different types |
| **UEBA Entries** | Behavior data points | 72 (24 hours) |

---

## 🎓 Learning from the Demo

### Questions to Answer:

1. **What are the top 3 most common attack types?**
   - Check the attack distribution chart

2. **Which source IP is most active?**
   - Look at the attack chain analysis

3. **When do most attacks occur?**
   - Analyze the alert timeline

4. **How effective is the honeypot?**
   - Check the honeypot tab

5. **Are there any traffic anomalies?**
   - Review the UEBA chart

---

## 💾 Customizing Demo Data

To generate different data:

1. **Open `demo_setup.py`** and edit:
   - `attack_types` list for different threat types
   - `source_ips` for different attacker IPs
   - Alert count (50 → any number)
   - Time range (24 hours → any duration)

2. **Run again:**
   ```powershell
   .\venv\Scripts\python.exe demo_setup.py
   ```

3. **Refresh dashboard** - Streamlit auto-reloads data

---

## ✨ Features Ready to Explore

- ✅ Real-time alert streaming
- ✅ Attack timeline visualization
- ✅ Threat severity metrics
- ✅ Honeypot deception logs
- ✅ UEBA anomaly detection
- ✅ Attack chain mapping
- ✅ IP reputation scoring (with API keys)
- ✅ AI-powered remediation advice (with Groq API)

---

## 🎉 You're All Set!

Your ZeroBit demo is ready to explore. Open the dashboard and start investigating the sample security events!

**Happy hunting! 🛡️**

---

**Dashboard URL:** http://localhost:8501
**Generated:** 2026-01-26
**Demo Data:** 50 alerts, 5 honeypot captures, 72 UEBA entries
