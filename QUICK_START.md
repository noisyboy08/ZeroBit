# ZeroBit Quick Start Guide

## 🚀 Running the Dashboard

The Streamlit dashboard should now be starting! Look for output like:

```
You can now view your Streamlit app in your browser.

Local URL: http://localhost:8501
Network URL: http://192.168.x.x:8501
```

**Open your browser and go to:** `http://localhost:8501`

---

## 📋 First-Time Setup

### 1. Install All Dependencies

If you haven't already, install all required packages:

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Train a Model (Required for Detection)

Before the pipeline can detect attacks, you need a trained model:

**Option A: Train on NSL-KDD Dataset**
```powershell
# Download NSL-KDD dataset to data/ folder first
.\venv\Scripts\python.exe -m src.training --dataset data/KDDTrain+.txt --model-path models/zerobit_model.pkl
```

**Option B: Train ETA Model (Encrypted Traffic)**
```powershell
# First export flows with Joy (if you have pcap files)
# joy -x -y -w data/flows.json -p data/capture.pcap

.\venv\Scripts\python.exe -m src.training --eta-json data/flows.json --model-path models/eta_model.pkl
```

**Note:** If you don't have a dataset yet, the dashboard will still run but detection won't work until you train a model.

---

## 🎮 Using the Dashboard

### Starting the Processing Engine

1. **Open the Dashboard:** Go to `http://localhost:8501`
2. **Start Engine:** In the sidebar, find "⚙️ Processing Engine" section
3. **Click "▶️ Start Engine"** - This will begin real-time packet capture and detection
4. **Watch for Alerts:** The "🔴 Live Alerts (Real-Time)" section will show detected attacks

### Testing the System

1. **Generate Test Traffic:**
   - Use the "⚔️ Model Training Gym" section in sidebar
   - Click "✅ Generate Safe Noise" to test false positive detection
   - Click "🚨 Launch Test Attack (DoS)" to simulate an attack

2. **Provide Feedback:**
   - When an alert appears, click "👎 False Alarm" if it's a false positive
   - The system will retrain the model with your feedback
   - This improves accuracy over time!

### Key Features to Try

- **Threat Intelligence:** Enter AbuseIPDB/VirusTotal API keys in sidebar for enriched alerts
- **Attack Graph:** View "Attack Graph" tab to see attack chains
- **Network Topology:** Scan your network in "Network Topology" tab
- **Canary Deployment:** Deploy ransomware bait files in "🛡️ ZeroBit Canary" section

---

## ⚠️ Important Notes

### Permissions Required

- **Packet Capture:** Requires administrator/elevated privileges on Windows
- **Firewall Rules:** Auto-blocking requires admin rights
- **Network Interface:** May need to specify interface name (e.g., `eth0`, `Wi-Fi`)

### Troubleshooting

**Dashboard won't start:**
```powershell
# Check if port 8501 is in use
netstat -ano | findstr :8501

# Try a different port
.\venv\Scripts\python.exe -m streamlit run dashboard/app.py --server.port 8502
```

**No alerts appearing:**
- Make sure the processing engine is started (green "🟢 Engine Running" status)
- Check that a trained model exists in `models/` folder
- Verify network interface is correct (may need to specify `--iface` in pipeline)

**Model not found error:**
- Train a model first using the training script
- Default model path: `models/eta_model.pkl` or `models/zerobit_model.pkl`

---

## 🔧 Manual Pipeline Start

If you prefer to run the pipeline separately:

```powershell
.\venv\Scripts\python.exe -m src.pipeline --model-path models/eta_model.pkl --iface "Wi-Fi"
```

---

## 📊 What to Expect

When everything is working:

1. **Dashboard loads** at `http://localhost:8501`
2. **Start Engine** button appears in sidebar
3. **Live Alerts** section shows real-time detections
4. **Alerts appear** as malicious traffic is detected
5. **Feedback loop** improves model accuracy over time

---

## 🎯 Next Steps

- Train a model with your own dataset
- Configure API keys for threat intelligence
- Deploy canaries for ransomware protection
- Test with simulated attacks
- Review alerts and provide feedback

**Enjoy using ZeroBit!** 🚀

