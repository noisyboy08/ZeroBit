<div align="center">



## 🚀 ZEROBIT – ADVANCED AI-POWERED NETWORK INTRUSION DEFENSE

### *Encrypted Traffic Analysis, Smart SOC, and Ransomware Kill‑Switch in One Platform*



![ZeroBit](https://img.shields.io/badge/🚀%20ZeroBit-AI%20Network%20Defense-blue?style=for-the-badge&logoColor=white)
![Python](https://img.shields.io/badge/🐍%20Python-3.10%2B-yellow?style=for-the-badge&logoColor=white)
![ML](https://img.shields.io/badge/🤖%20ML-scikit--learn%20%7C%20XGBoost-orange?style=for-the-badge&logoColor=white)
![Scapy](https://img.shields.io/badge/📡%20Scapy-Live%20Packet%20Sniffing-red?style=for-the-badge&logoColor=white)
![Streamlit](https://img.shields.io/badge/📊%20Streamlit-SOC%20Dashboard-brightgreen?style=for-the-badge&logoColor=white)
![Status](https://img.shields.io/badge/🛡️%20Status-Research%20/Production%20Ready-brightgreen?style=for-the-badge&logoColor=white)


```text
███████╗███████╗██████╗  ██████╗ ██████╗ ██╗████████╗
██╔════╝██╔════╝██╔══██╗██╔════╝██╔═══██╗██║╚══██╔══╝
███████╗█████╗  ██████╔╝██║     ██║   ██║██║   ██║
╚════██║██╔══╝  ██╔══██╗██║     ██║   ██║██║   ██║
███████║███████╗██║  ██║╚██████╗╚██████╔╝██║   ██║
╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝

 ZERO‑TRUST  •  ZERO‑DAY  •  ZEROBIT
```

🎯 **ZeroBit is an intelligent Network Intrusion Detection & Response Platform** that combines
encrypted traffic analysis, explainable AI, UEBA, active deception, and a ransomware kill‑switch
into a single, operator‑friendly SOC dashboard.


🔧 *Docs & Demo coming soon* • ⭐ *Star this repo if you like deep‑security projects*

</div>

---

## 🌟 Killer Features

### 🤖 AI & ENCRYPTED TRAFFIC ANALYSIS (ETA)

- NSL‑KDD / tabular ML pipeline with `RandomForestClassifier`
- ETA model using `XGBoost` on flow metadata (sizes, IAT, JA3/JA3S)
- Scapy‑based sniffer + Joy JSON exports for encrypted traffic
- SHAP explainability – shows *why* a flow is malicious (top features + plots)

### 🔬 SMART SOC & ADAPTIVE LEARNING

- Incident history in `soc_history.db` with analyst feedback
- Priority engine (P0–P3) driven by threat score, MITRE mapping, UEBA anomalies
- Adaptive retraining – feed confirmed/false alerts back into the ETA model
- Similarity search to find past incidents that look like the current one

### 🛰️ THREAT ENRICHMENT & INTEL

- IP enrichment via `ip-api.com` (Geo, ISP, ASN)
- Threat intel integration hooks for AbuseIPDB / VirusTotal
- Per‑alert threat scores and context cards in the dashboard

### 📡 ACTIVE DEFENSE & DECEPTION

- Honeypot module to trap attackers and log payloads
- Firewall response engine (`netsh` / `iptables` command templates)
- ZeroBit Canary – ransomware kill‑switch using bait files + filesystem watch
- Optional auto‑blocking of high‑confidence threats

### 📊 SOC DASHBOARD & REPORTING

- Modern Streamlit dashboard for analysts
- Real‑time alert stream from `alerts.db`
- Live threat map, attack graph, UEBA charts, honeypot metrics, and more
- PDF daily security reports summarizing incidents and alerts

---

## 🚀 Quick Start

### ⚡ Prerequisites

```bash
✅ Python 3.10+
✅ pip / virtualenv
✅ (Windows) Admin / (Linux) sudo for packet capture & firewall
✅ Internet access for threat intel & Telegram (optional)
```

### 🛠️ Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/zerobit-nids.git
cd ZeroBit

# Create & activate virtual environment (recommended)
python -m venv venv
.\venv\Scripts\activate   # Windows
# source venv/bin/activate  # Linux / macOS

# Install dependencies
pip install -r requirements.txt
```

### 🧠 Train Detection Models

#### NSL‑KDD / Tabular Model

```bash
python -m src.training --dataset data/nsl_kdd.csv --model-path models/zerobit_rf.pkl
```

#### Encrypted Traffic Analysis (ETA)

1. Export flows from a pcap with Joy:

```bash
joy -x -y -w data/flows.json -p data/capture.pcap
```

2. Train ETA model:

```bash
python -m src.training --eta-json data/flows.json --model-path models/eta_model.pkl
```

3. (Optional) Retrain from analyst feedback:

```bash
python -m src.training --retrain-from-feedback
```

### 📡 Run Real‑Time Detection Pipeline

```bash
python -m src.pipeline
```

This will:

- Start Scapy packet sniffing
- Push packets into a processing queue
- Run ML detection + UEBA + MITRE mapping
- Store alerts in `data/alerts.db` for the dashboard

### 📊 Launch ZeroBit SOC Dashboard

```bash
streamlit run dashboard/app.py
```

Open your browser at `http://localhost:8501` and you’ll get:

- Alerts tab – live alerts, priority badges, AI explanations, analyst feedback
- Live Intel tab – threat enrichment & scores
- Attack Graph tab – visual kill‑chain graph
- Live Threat Map tab – geolocated attacks
- Network Topology tab – ARP discovery + MAC vendor lookup
- Live Feed tab – latest SHAP / alert images

---

## 🏗️ Project Architecture

```text
ZeroBit/
┣━━ data/                 # Datasets, flow JSON, UEBA & honeypot logs, SQLite DBs
┣━━ models/               # Trained ML models (RF, XGBoost, SHAP explainer)
┣━━ src/
┃   ┣━━ training.py       # NSL-KDD & ETA training, adaptive retraining
┃   ┣━━ sniffer.py        # Scapy packet capture
┃   ┣━━ pipeline.py       # Queue-based real-time processing engine
┃   ┣━━ detection.py      # Core detection logic & feature extraction
┃   ┣━━ eta_features.py   # Joy flow → ETA feature vectors
┃   ┣━━ explainability.py # SHAP-based XAI for ETA decisions
┃   ┣━━ enrichment.py     # IP geo/ISP enrichment
┃   ┣━━ alerts.py         # Telegram alerting
┃   ┣━━ advisor.py        # Groq AI security assistant
┃   ┣━━ honeypot.py       # Active deception server
┃   ┣━━ discovery.py      # Network discovery & MAC vendor lookup
┃   ┣━━ reporting.py      # PDF daily security reports
┃   ┣━━ ueba.py           # User & Entity Behavior Analytics
┃   ┣━━ mitre.py          # MITRE ATT&CK mapping
┃   ┣━━ feedback.py       # Incident history & analyst feedback
┃   ┣━━ simulator.py      # Attack traffic simulator
┃   ┣━━ canary.py         # Ransomware kill-switch (bait files)
┃   ┗━━ response.py       # Response engine (auto-block / isolate)
┣━━ dashboard/
┃   ┗━━ app.py            # Streamlit SOC dashboard
┣━━ requirements.txt
┗━━ README.md
```

---

## 🧠 Core Modules Overview

- `src/training.py` – dataset loading, feature preprocessing, model training, and adaptive retraining.
- `src/detection.py` – glues models, UEBA, MITRE, enrichment, and response into a single decision engine.
- `src/pipeline.py` – production‑style queue pipeline for real‑time packet processing.
- `src/ueba.py` – rolling traffic statistics and anomaly detection per user/entity.
- `src/honeypot.py` – simple TCP honeypot with interaction logging.
- `src/canary.py` – bait file creation and ransomware kill‑switch automation.
- `dashboard/app.py` – one‑pane‑of‑glass SOC interface built with Streamlit.

---

## 🛡️ Security Notes

- Running packet capture and firewall rules typically requires administrator/root privileges.
- Test ZeroBit in a lab environment first before deploying to production networks.
- Some integrations (Telegram, Groq, threat‑intel APIs) require API keys / tokens – keep them secret.
- Auto‑blocking can disrupt traffic; start in monitor‑only mode and tune thresholds.

---

## 🤝 Contributing

- Open issues for bugs, feature ideas, or research questions.
- Propose new detectors (e.g., TLS fingerprinting, DNS tunneling, LLM‑based log analysis).
- PRs that improve stability, test coverage, or add high‑quality security content are welcome.

---

## 📜 License & Credits

- Licensed under the MIT License.
- Built with Python, scikit‑learn, XGBoost, Scapy, Streamlit, SHAP, and other open‑source tools.
- Inspired by modern SOC workflows, UEBA platforms, and academic work on encrypted traffic analysis.


<div align="center">

**🛡️ Built for Defenders, Red‑Teamers, and Curious Hackers 🛡️**  

⭐ *Star this repo if ZeroBit inspires your next security project!* ⭐  

🚀 *Detect. Explain. Deceive. Respond. With ZeroBit.* 🚀

</div>

