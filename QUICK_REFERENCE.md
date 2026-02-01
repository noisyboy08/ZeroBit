# 🎯 ZeroBit Demo - Quick Reference Card

## 🚀 Start in 30 Seconds

```
http://localhost:8501
```

Just open this URL in your browser. Done! ✅

---

## 📊 Dashboard at a Glance

| Tab | Shows | Key Metric |
|-----|-------|-----------|
| **Dashboard** | Overview, timeline, charts | 50 total alerts |
| **Alerts** | Detailed alert list | Confidence scores |
| **Attack Chain** | IP → Port relationships | Attack patterns |
| **Honeypot** | Captured credentials | 5 captures |
| **UEBA** | Traffic analysis | 24-hour baseline |

---

## 🎬 5-Tab Tour (5 minutes)

1. **Dashboard** → View overview charts
2. **Alerts** → See all 50 security incidents
3. **Attack Chain** → Identify attack patterns
4. **Honeypot** → Check deception success
5. **UEBA** → Analyze behavior analytics

---

## 📁 Demo Files Generated

```
✅ data/alerts.db              (50 alerts)
✅ data/alerts.csv             (40 alerts)
✅ data/honeypot_logs.json     (5 captures)
✅ data/ueba_history.json      (72 entries)
```

---

## 🎓 Quick Learning Path

**Beginner (5 min):**
- View Dashboard tab
- Look at timeline chart
- Check alert count

**Intermediate (15 min):**
- Browse all 5 tabs
- Click on alerts for details
- Identify top attackers

**Advanced (30 min):**
- Correlate across tabs
- Run all 5 scenarios
- Analyze patterns

---

## 🔧 Common Commands

```powershell
# Start dashboard
.\venv\Scripts\streamlit.exe run dashboard/app.py

# Regenerate demo data
.\venv\Scripts\python.exe demo_setup.py

# Fresh start
Remove-Item data\*.db, data\*.json, data\*.csv
.\venv\Scripts\python.exe demo_setup.py

# Stop dashboard
# Press Ctrl+C in terminal
```

---

## 🎯 What Each Metric Means

| Metric | Range | Example |
|--------|-------|---------|
| **Confidence** | 0.6-1.0 | 0.95 = 95% certain |
| **Attack Type** | Various | DoS, Scan, Brute |
| **Port** | 1-65535 | 443=HTTPS, 22=SSH |
| **UEBA Bytes** | 1K-50K | Traffic baseline |

---

## 🚨 Top Attack Types in Demo

1. **DoS/DDoS** (16%) - Flooding attacks
2. **Port Scan** (14%) - Reconnaissance
3. **Brute Force** (12%) - Password cracking
4. **SQL Injection** (10%) - Database attacks
5. Others (48%) - Mixed threats

---

## 🎮 5 Demo Scenarios

### Scenario 1: Threat Investigation
→ Find high-confidence alert → Track attacker IP → See attack pattern

### Scenario 2: Honeypot Review
→ Check Honeypot tab → See captures → Review credentials

### Scenario 3: Pattern Analysis
→ Go to Attack Chain → Sort by attacks → Identify top attacker

### Scenario 4: Anomaly Detection
→ Go to UEBA → Find traffic spikes → Correlate with alerts

### Scenario 5: Complete Analysis
→ Use all 5 tabs → Form security picture → Draw conclusions

---

## 📊 Data Summary

```
Total Alerts:       50
Attack Types:       10 different types
Honeypot Captures:  5 credentials caught
UEBA Records:       72 (24-hour coverage)
Unique Attackers:   8 source IPs
Target Ports:       10 most common
Confidence Avg:     ~80%
Time Range:         24 hours
```

---

## 🌐 Access Points

```
Local:    http://localhost:8501
Network:  http://10.173.13.58:8501
```

---

## 📚 Documentation Guide

| Document | Best For | Time |
|----------|----------|------|
| DEMO_README.md | Complete overview | 10 min |
| DEMO_GUIDE.md | Deep understanding | 20 min |
| DEMO_WALKTHROUGH.md | Visual examples | 10 min |
| DEMO_DATA_SAMPLES.md | See real data | 10 min |

---

## ✨ Key Features Ready to Use

✅ Real-time alert visualization
✅ Interactive charts and graphs
✅ Honeypot deception logs
✅ UEBA anomaly detection
✅ Attack chain mapping
✅ Threat severity scoring
✅ Multiple data sources
✅ Professional SOC interface

---

## 🎯 Success Checklist

- [ ] Dashboard opens in browser
- [ ] See 50 alerts in Alerts tab
- [ ] View attack timeline chart
- [ ] Check 5 honeypot captures
- [ ] See UEBA traffic graph
- [ ] Identify attack patterns
- [ ] Understand threat data

**If all checked: Demo is working perfectly! ✅**

---

## 🔄 Refresh Data

```powershell
# Generate new random data
.\venv\Scripts\python.exe demo_setup.py

# Then refresh browser (Ctrl+R)
```

---

## 💡 Quick Tips

💡 Click alerts to see details
💡 Sort Attack Chain by attempts to find top attacker
💡 Check Honeypot for deception success
💡 Look for UEBA spikes when attacks occur
💡 Use Dashboard for quick overview

---

## 🚀 Ready?

```
→ http://localhost:8501 ←
```

**Open now and start exploring!** 🛡️

---

## 🎓 Learn More

| Topic | Document |
|-------|----------|
| Full Guide | DEMO_GUIDE.md |
| Walkthrough | DEMO_WALKTHROUGH.md |
| Data Details | DEMO_DATA_SAMPLES.md |
| Project Info | README.md |

---

## 🛡️ ZeroBit Demo Essentials

**Status:** ✅ RUNNING
**Data:** ✅ READY
**Dashboard:** ✅ LIVE

**Go to:** http://localhost:8501

---

Created: 2026-01-26
Last Updated: Today
Version: 1.0
