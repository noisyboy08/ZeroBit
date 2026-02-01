# 📊 ZeroBit Demo Data - Sample Records

## Database Content Preview

### 🚨 Sample Alerts (from alerts.db)

```
ID │ Timestamp          │ Source IP      │ Dest IP     │ Port │ Attack Type       │ Confidence
───┼────────────────────┼────────────────┼─────────────┼──────┼───────────────────┼────────────
1  │ 2026-01-26 12:45 │ 203.0.113.45   │ 10.0.0.1   │ 443  │ DoS/DDoS Attack   │ 0.95
2  │ 2026-01-26 12:40 │ 198.51.100.32  │ 10.0.0.50  │ 22   │ Port Scan         │ 0.87
3  │ 2026-01-26 12:35 │ 192.0.2.88     │ 10.0.0.1   │ 3306 │ Brute Force       │ 0.92
4  │ 2026-01-26 12:30 │ 203.0.113.100  │ 10.0.0.100 │ 80   │ SQL Injection     │ 0.78
5  │ 2026-01-26 12:25 │ 198.51.100.12  │ 192.168.1.1│ 443  │ XSS Attack        │ 0.65
6  │ 2026-01-26 12:20 │ 192.0.2.200    │ 10.0.0.50  │ 5432 │ Malware Detection │ 0.88
...
50 │ 2026-01-25 13:15 │ 203.0.113.250  │ 192.168.1.50│ 21   │ Botnet Comm       │ 0.91
```

**Key Insights:**
- 50 total alerts spanning 24 hours
- Confidence scores range from 0.65 to 0.99
- Mix of different attack types
- Various source and destination IPs

---

### 🐝 Honeypot Captured Credentials

```json
[
  {
    "attacker_ip": "203.0.113.45",
    "timestamp": "2026-01-26T09:15:30.123456",
    "payload": "admin:password123"
  },
  {
    "attacker_ip": "198.51.100.32",
    "timestamp": "2026-01-26T06:45:22.654321",
    "payload": "root:12345678"
  },
  {
    "attacker_ip": "192.0.2.88",
    "timestamp": "2026-01-25T18:30:15.987654",
    "payload": "user:letmein"
  },
  {
    "attacker_ip": "203.0.113.100",
    "timestamp": "2026-01-25T12:20:45.456789",
    "payload": "admin:admin123"
  },
  {
    "attacker_ip": "198.51.100.12",
    "timestamp": "2026-01-25T04:10:30.789123",
    "payload": "test:test123"
  }
]
```

**What This Shows:**
- 5 different attackers tried to gain access
- All used weak credentials (honeypot trick worked!)
- Timestamps show when attacks occurred
- Confirms honeypot is effectively catching attempts

---

### 📈 UEBA Traffic History (Sample)

```json
[
  {
    "timestamp": "2026-01-26T00:00:00",
    "ip": "10.0.0.45",
    "bytes": 5420
  },
  {
    "timestamp": "2026-01-26T00:05:00",
    "ip": "10.0.0.102",
    "bytes": 8950
  },
  {
    "timestamp": "2026-01-26T01:00:00",
    "ip": "10.0.0.67",
    "bytes": 3200
  },
  ... (72 entries total for 24-hour period) ...
  {
    "timestamp": "2026-01-26T23:00:00",
    "ip": "10.0.0.200",
    "bytes": 12450
  }
]
```

**Hourly Breakdown:**
- 3 entries per hour (different IPs reporting)
- Byte ranges: 1,000 - 50,000 bytes/hour
- Shows normal traffic baseline
- Helps identify anomalies when spikes occur

---

## 📊 Data Analysis Examples

### Top 5 Most Active Attacker IPs

| IP Address | Attack Count | Favorite Target Port |
|------------|-------------|---------------------|
| 203.0.113.45 | 8 | 443 (HTTPS) |
| 198.51.100.32 | 6 | 22 (SSH) |
| 192.0.2.88 | 5 | 3306 (MySQL) |
| 203.0.113.100 | 7 | 80 (HTTP) |
| 198.51.100.12 | 4 | 443 (HTTPS) |

### Attack Type Frequency

| Attack Type | Count | Percentage |
|-------------|-------|-----------|
| DoS/DDoS | 8 | 16% |
| Port Scan | 7 | 14% |
| Brute Force | 6 | 12% |
| SQL Injection | 5 | 10% |
| XSS Attack | 4 | 8% |
| Malware | 5 | 10% |
| Botnet Comm | 4 | 8% |
| Credential Theft | 4 | 8% |
| Data Exfil | 3 | 6% |
| Unauthorized | 3 | 6% |

### Most Targeted Ports

| Port | Service | Hit Count |
|------|---------|-----------|
| 443 | HTTPS | 12 |
| 22 | SSH | 10 |
| 3306 | MySQL | 8 |
| 80 | HTTP | 7 |
| 5432 | PostgreSQL | 6 |
| 8080 | HTTP Alt | 4 |
| 21 | FTP | 2 |
| 25 | SMTP | 1 |
| 53 | DNS | 1 |
| 3389 | RDP | 1 |

---

## 🎯 Real Data Samples from Dashboard

### Alert Detail View Example

```
════════════════════════════════════════════════════════
          DETAILED ALERT INFORMATION
════════════════════════════════════════════════════════

Source IP:          203.0.113.45
Timestamp:          2026-01-26 12:45:00 UTC
Destination IP:     10.0.0.1
Destination Port:   443
Attack Type:        DoS/DDoS Attack
Confidence:         95%

════════════════════════════════════════════════════════
```

### Timeline Data Example

```
Hour    Alerts    Chart
00:00   │ 2      ▂
01:00   │ 1      ▁
02:00   │ 3      ▃
03:00   │ 2      ▂
04:00   │ 4      ▄
05:00   │ 2      ▂
06:00   │ 5      ▅
07:00   │ 3      ▃
08:00   │ 6      ▆
09:00   │ 8      ██  ← PEAK
10:00   │ 4      ▄
11:00   │ 2      ▂
12:00   │ 5      ▅
...
```

---

## 🔍 Data Quality Metrics

```
DATA QUALITY REPORT
═══════════════════════════════════════════════════════

Alert Database:
├─ Total Records: 50 ✅
├─ Timestamp Validity: 100% ✅
├─ IP Format Valid: 100% ✅
├─ Confidence Range: 0.65 - 0.99 ✅
└─ No Duplicates: ✅

Honeypot Logs:
├─ Total Captures: 5 ✅
├─ Unique Attackers: 5 ✅
├─ Payload Logged: 100% ✅
└─ Timestamp Range: 24-hour ✅

UEBA History:
├─ Total Records: 72 ✅
├─ Hourly Coverage: 24/24 hours ✅
├─ IPs Tracked: 25+ unique IPs ✅
├─ Byte Range: 1K - 50K ✅
└─ No Gaps: ✅

Attack Chains:
├─ Unique Source IPs: 8 ✅
├─ Target Ports: 10 ✅
├─ Attack Sequences: 40 ✅
└─ Complete Data: ✅

═══════════════════════════════════════════════════════
```

---

## 📚 Understanding the Data

### What Each Field Means

**alerts.db Fields:**
- `timestamp` - When the attack was detected
- `src_ip` - Attacker's IP address
- `dst_ip` - Target system's IP
- `dst_port` - Target service port (22=SSH, 443=HTTPS, etc.)
- `attack_type` - What kind of attack was detected
- `confidence` - How certain the AI is (0.0-1.0, higher = more certain)

**honeypot_logs.json:**
- `attacker_ip` - IP that attempted login on honeypot
- `timestamp` - When they tried
- `payload` - What credentials they used

**ueba_history.json:**
- `timestamp` - When measured
- `ip` - Which internal IP this is from
- `bytes` - How much data transferred (baseline)

---

## 🎨 Visualization Examples

### Alert Timeline Visualization
```
ATTACK FREQUENCY BY HOUR

50+ │
    │          ╭─────╮
40+ │          │     │
    │    ╭─────╯     │
30+ │    │           ╰─────╮
    │    │                 │
20+ │    │                 ╰──
    │  ╱─╲                    ╭
10+ │╱   │                    │
    │    │                    ╰───╮
 0+ └────────────────────────────
    0    6   12   18   24 hours
    │    │   │    │    │
    MID  MORNING AFTERNOON NIGHT
```

### Attack Type Pie Chart (Text Representation)
```
DoS/DDoS        ████████░░ 16%
Port Scan       ███████░░░ 14%
Brute Force     ██████░░░░ 12%
SQL Injection   █████░░░░░ 10%
XSS Attack      ████░░░░░░  8%
Malware         █████░░░░░ 10%
Botnet Comm     ████░░░░░░  8%
Credential      ████░░░░░░  8%
Data Exfil      ███░░░░░░░  6%
Unauthorized    ███░░░░░░░  6%
```

---

## 📞 Common Questions About Demo Data

**Q: Is this real attack data?**
A: No, it's realistic sample data. Real attacks would vary by network.

**Q: Can I modify the demo data?**
A: Yes! Edit `demo_setup.py` to change IPs, attacks, timeframes, etc.

**Q: How do I get real data?**
A: Run the detection pipeline (`src/pipeline.py`) on your live network.

**Q: Will real data look like this?**
A: Yes, same fields and structure, but with your actual network IPs and attacks.

---

## 🚀 Using Demo Data for Learning

### Beginner Exercise
1. Open dashboard to "Alerts" tab
2. Pick 3 random alerts
3. Write down: Source IP, Attack Type, Confidence
4. Guess: Which is most dangerous?

### Intermediate Exercise
1. Go to "Attack Chain" tab
2. Find the most-attacked IP address
3. Check "Alerts" tab for attacks from that source
4. Identify: What's the attacker's pattern?

### Advanced Exercise
1. Analyze all 5 tabs together
2. Correlate: When honeypot got hits vs when alerts spiked
3. Study: UEBA traffic when attacks happened
4. Conclude: What's the attack timeline?

---

**All demo data files are located in: `/data/` folder**

📁 Files:
- `alerts.db` - SQLite database (50 alerts)
- `alerts.csv` - CSV export (40 alerts)
- `honeypot_logs.json` - Honeypot data (5 captures)
- `ueba_history.json` - Behavior analytics (72 entries)

✨ **Ready to explore!** ✨
