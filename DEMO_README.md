# 🎉 ZeroBit Demo Setup - Complete Guide

## ✅ Your Demo is Ready!

Everything is configured and running. Your **ZeroBit SOC Dashboard** is live with complete demo data!

---

## 🚀 Quick Start (30 seconds)

### Option 1: Web Browser (Easiest)
**Just open your browser:**
```
http://localhost:8501
```

### Option 2: Windows Batch File
```powershell
.\start_demo.bat
```

### Option 3: PowerShell
```powershell
.\start_demo.ps1
```

### Option 4: Manual Command
```powershell
.\venv\Scripts\streamlit.exe run dashboard/app.py
```

---

## 📊 What's Included in the Demo

### ✅ Sample Data (Already Generated)
- **50 Security Alerts** - Various attack types with realistic patterns
- **5 Honeypot Captures** - Attacker credentials and interaction logs
- **72 UEBA Records** - 24-hour user behavior analytics
- **40 Attack Chains** - IP→Port attack relationship mapping

### ✅ Database Files
```
data/
├── alerts.db              ← SQLite database with 50 alerts
├── alerts.csv             ← CSV export for easy viewing
├── honeypot_logs.json     ← 5 honeypot interaction captures
└── ueba_history.json      ← 24-hour behavior history
```

### ✅ Dashboard Features
- 📊 Real-time alert visualization
- 📈 Attack timeline with hourly distribution
- 🎯 Attack type distribution chart
- 🚨 Detailed alert inspector
- 🕸️ Attack chain network analysis
- 🐝 Honeypot deception log viewer
- 📊 UEBA anomaly detection charts

---

## 🎬 Demo Walkthrough (5 minutes)

### Step 1: Open Dashboard
```
http://localhost:8501
```
You see the main dashboard overview.

### Step 2: Check Metrics
Look at the top cards:
- **Total Alerts:** 50
- **Honeypot Captures:** 5
- **Avg Confidence:** ~80%
- **Pipeline Status:** Running ✅

### Step 3: View Alert Timeline
Scroll down to see hourly attack distribution chart.
- Notice attack patterns over 24 hours
- See when most attacks occurred

### Step 4: Analyze Attack Types
Look at the bar chart showing attack type distribution.
- DoS/DDoS is most common
- Followed by Port Scans
- Then Brute Force attempts

### Step 5: Browse Detailed Alerts
Click **"Alerts"** tab to see all 50 alerts in table format.
- Sort by timestamp, IP, or attack type
- Click on any row to view full details
- See confidence scores for each

### Step 6: Map Attack Patterns
Click **"Attack Chain"** tab to see which IPs attacked which ports.
- Top attackers are clearly visible
- See targeting patterns
- Identify most-targeted ports (443, 22, 3306)

### Step 7: Review Honeypot
Click **"Honeypot"** tab to see deception success.
- 5 captured login attempts
- View the fake credentials attackers used
- See timestamps of each capture

### Step 8: Analyze Behavior
Click **"UEBA"** tab to see traffic patterns.
- 24-hour traffic baseline
- Notice spikes when attacks occurred
- Identify baseline normal traffic

---

## 📚 Documentation Files

Three comprehensive guides are included:

### 📖 DEMO_GUIDE.md
**Detailed guide covering:**
- Data overview and statistics
- Tab-by-tab feature explanation
- Interactive feature guide
- Troubleshooting section
- 10+ minute deep dive

👉 **Read this for comprehensive understanding**

### 🚶 DEMO_WALKTHROUGH.md
**Visual step-by-step walkthrough:**
- ASCII art visualizations of each tab
- Sample screenshots (text-based)
- Interactive demo scenarios
- Learning exercises
- 5-minute guided tour

👉 **Read this to see visual examples**

### 📊 DEMO_DATA_SAMPLES.md
**Actual data samples showing:**
- Real alert records
- Honeypot captures with payloads
- UEBA traffic data
- Data analysis examples
- Quality metrics

👉 **Read this to understand the data**

---

## 🎮 Five Interactive Demo Scenarios

### Scenario 1: Incident Analysis
**Goal:** Investigate a high-confidence threat
1. Go to Dashboard → Notice alert timeline
2. Go to Alerts → Find highest confidence (95%+)
3. Click alert details → Note source IP
4. Go to Attack Chain → Find that IP
5. Count how many times it attacked

**Learning:** How to investigate threats

### Scenario 2: Honeypot Effectiveness
**Goal:** Understand deception efficiency
1. Go to Honeypot tab
2. Note 5 captured attempts
3. Check timestamps → See when attacks occurred
4. Compare with Dashboard timeline
5. Note: All attacks were caught!

**Learning:** How honeypots enhance security

### Scenario 3: Pattern Recognition
**Goal:** Identify attacker patterns
1. Go to Attack Chain → Sort by attempts
2. Pick top attacker IP
3. Go to Alerts → Filter by that IP
4. Count total attacks
5. Note preferred ports and times

**Learning:** How to profile attackers

### Scenario 4: Anomaly Detection
**Goal:** Spot unusual behavior
1. Go to UEBA → Study the traffic chart
2. Identify baseline traffic level
3. Find the biggest spike
4. Check Dashboard timeline → correlate with alerts
5. Conclude: Spike = attack activity

**Learning:** UEBA helps detect unusual activity

### Scenario 5: Dashboard Mastery
**Goal:** Use all features together
1. Start at Dashboard → get overview
2. Alerts tab → see detailed list
3. Attack Chain → understand patterns
4. Honeypot → see captures
5. UEBA → see behavior impact
6. Form complete security picture

**Learning:** How to use SOC dashboard professionally

---

## 🎓 Learning Outcomes

After exploring the demo, you'll understand:

✅ How security alerts are generated and visualized
✅ How threat scoring works (confidence levels)
✅ What honeypots capture and why they're useful
✅ How UEBA detects abnormal behavior
✅ How to identify attack patterns
✅ How SOC dashboards help security teams
✅ What real security data looks like
✅ How to correlate events across tabs

---

## 🔧 Advanced: Customizing Demo Data

### Change Alert Count
Edit `demo_setup.py`, line with `for i in range(50):` → change 50 to any number

### Add Different Attack Types
Edit the `attack_types` list in `demo_setup.py`

### Change Time Range
Edit the `timedelta` values to generate data over different periods

### Add More Honeypot Captures
Add more entries to the `honeypot_data` list

### Regenerate Data
```powershell
.\venv\Scripts\python.exe demo_setup.py
```
Then refresh browser (Ctrl+R)

---

## 🐛 Troubleshooting

### Dashboard Not Loading?
```powershell
# Stop current process (Ctrl+C in terminal)
# Then restart:
.\venv\Scripts\streamlit.exe run dashboard/app.py
```

### No Data Showing?
```powershell
# Regenerate demo data
.\venv\Scripts\python.exe demo_setup.py

# Then refresh browser (Ctrl+R)
```

### Port 8501 Already in Use?
```powershell
# Use different port
.\venv\Scripts\streamlit.exe run dashboard/app.py --server.port 8502
```
Then open: http://localhost:8502

### Still Have Issues?
1. Check all data files exist: `ls data/`
2. Verify virtual environment: `.\venv\Scripts\python.exe --version`
3. Check Python packages: `pip list | grep streamlit`
4. Read the full guide: `DEMO_GUIDE.md`

---

## 📊 Data Structure Reference

### alerts.db (SQLite)
```
Table: alerts
Columns:
- id (INTEGER PRIMARY KEY)
- timestamp (TEXT) - ISO 8601 format
- src_ip (TEXT) - Attacker IP
- dst_ip (TEXT) - Target IP
- dst_port (INTEGER) - Target port number
- attack_type (TEXT) - Type of attack
- confidence (REAL) - 0.0 to 1.0 confidence score
- is_read (INTEGER) - 0 or 1 for read status
```

### alerts.csv
Same structure, viewable in Excel/spreadsheet apps

### honeypot_logs.json
```json
[
  {
    "attacker_ip": "x.x.x.x",
    "timestamp": "ISO 8601 timestamp",
    "payload": "captured_credentials"
  }
]
```

### ueba_history.json
```json
[
  {
    "timestamp": "ISO 8601 timestamp",
    "ip": "10.x.x.x",
    "bytes": number_of_bytes
  }
]
```

---

## 🌐 Network Access

Your dashboard is accessible from:

| Access | URL | Notes |
|--------|-----|-------|
| **Local Machine** | http://localhost:8501 | Fastest |
| **Same Network** | http://10.173.13.58:8501 | Other devices on network |
| **Internet** | http://152.58.30.143:8501 | External access (if firewall allows) |

---

## 💾 File Structure

```
ZeroBit/
├── dashboard/
│   ├── app.py                 ← Main Streamlit app
│   └── app_original.py        ← Original (backup)
├── src/
│   ├── __init__.py
│   ├── advisor.py
│   ├── threat_intel.py
│   ├── mitre.py
│   ├── feedback.py
│   └── [other modules]
├── data/
│   ├── alerts.db              ← ✅ Generated
│   ├── alerts.csv             ← ✅ Generated
│   ├── honeypot_logs.json     ← ✅ Generated
│   └── ueba_history.json      ← ✅ Generated
├── models/                     ← For trained ML models
├── static/alerts/              ← For alert visualizations
├── demo_setup.py              ← Demo data generator
├── start_demo.bat             ← Windows batch launcher
├── start_demo.ps1             ← PowerShell launcher
├── DEMO_GUIDE.md              ← Comprehensive guide
├── DEMO_WALKTHROUGH.md        ← Visual walkthrough
├── DEMO_DATA_SAMPLES.md       ← Data examples
└── README.md                  ← Project overview
```

---

## 📈 What Happens When You:

### Click "Dashboard" Tab
→ See overview metrics and charts

### Click "Alerts" Tab
→ Table of 50 security alerts, click to expand details

### Click "Attack Chain" Tab
→ Source IP → Destination Port relationships

### Click "Honeypot" Tab
→ 5 captured login attempts with credentials

### Click "UEBA" Tab
→ 24-hour traffic pattern and statistics

### Interact with Sidebar Controls
→ Manage API keys, start/stop pipeline simulation

---

## 🎯 Success Criteria

You'll know the demo is working when you can:

✅ See 50 alerts in the alerts table
✅ View 5 honeypot captures
✅ See charts and visualizations
✅ Click alerts to see details
✅ View 24-hour UEBA timeline
✅ Identify attack patterns
✅ Understand the threat level

---

## 🚀 Next Steps After Demo

### 1. Explore Production Features
- Read `README.md` for full feature list
- Check `QUICK_START.md` for training models
- Review `NEXT_STEPS.md` for advanced topics

### 2. Train Real Models
```powershell
# Download NSL-KDD dataset
# Then train:
.\venv\Scripts\python.exe -m src.training --dataset data/KDDTrain+.txt --model-path models/zerobit_model.pkl
```

### 3. Run Detection Pipeline
```powershell
# Start real-time detection
.\venv\Scripts\python.exe -m src.pipeline
```

### 4. Deploy Active Defense
- Enable honeypot service
- Deploy canary files
- Configure firewall response

---

## 📞 Support Resources

| Need | File | Action |
|------|------|--------|
| Overview | `README.md` | Read project intro |
| Quick Start | `QUICK_START.md` | Set up pipeline |
| Demo Guide | `DEMO_GUIDE.md` | Detailed explanation |
| Walkthrough | `DEMO_WALKTHROUGH.md` | Step-by-step tour |
| Data Samples | `DEMO_DATA_SAMPLES.md` | See actual data |
| Next Steps | `NEXT_STEPS.md` | Advanced features |
| Problems | `PROBLEM_SOLUTION_FEATURES.md` | Troubleshooting |

---

## ⏱️ Time Estimates

| Activity | Time |
|----------|------|
| Open dashboard | 30 seconds |
| Basic 5-tab tour | 5 minutes |
| Deep exploration | 15 minutes |
| All scenarios | 30 minutes |
| Full understanding | 1 hour |

---

## 🎉 You're All Set!

Everything is configured and working. Your demo includes:

✅ Working dashboard (running now)
✅ 50 realistic security alerts
✅ 5 honeypot captures
✅ 72 UEBA data points
✅ 4 comprehensive guides
✅ Interactive learning scenarios
✅ Customizable demo data
✅ Quick-start launchers

---

## 🔗 Access Your Dashboard Now

### **→ http://localhost:8501 ←**

---

## 📝 Quick Reference Commands

```powershell
# Start dashboard
.\venv\Scripts\streamlit.exe run dashboard/app.py

# Regenerate demo data
.\venv\Scripts\python.exe demo_setup.py

# Stop dashboard
# Press Ctrl+C in terminal

# View alerts data
cat data/alerts.csv

# View honeypot logs
cat data/honeypot_logs.json
```

---

## 🛡️ Happy Threat Hunting!

Your ZeroBit SOC is fully operational and ready to explore.

**Dashboard Status:** ✅ RUNNING
**Demo Data:** ✅ COMPLETE
**Documentation:** ✅ COMPREHENSIVE

Open your browser and start investigating! 🎯

---

**Created:** 2026-01-26
**Demo Version:** 1.0
**Status:** ✅ PRODUCTION READY

🛡️ **ZeroBit: Detect. Explain. Deceive. Respond.** 🛡️
