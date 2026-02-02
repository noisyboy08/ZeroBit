# ZeroBit Enterprise Features - Usage Guide

## 🎉 What's New?

ZeroBit has been upgraded with enterprise-grade features for production deployment:

### 1. Performance Metrics Dashboard
**File:** `src/metrics.py`

Track real-time performance metrics:
```python
from src.metrics import MetricsTracker

tracker = MetricsTracker()

# Record an alert
tracker.record_alert(confidence=0.92, alert_type="Brute Force")

# Get metrics
detection_rate = tracker.get_detection_rate(hours=1)  # alerts/hour
fp_rate = tracker.get_false_positive_rate(hours=24)  # false positive %
avg_confidence = tracker.get_avg_confidence(hours=24)  # average %

# Get comprehensive health
health = tracker.get_health_summary()
print(health)
```

**Output Example:**
```json
{
  "uptime": "2h 30m 45s",
  "detection_rate_per_hour": 4.5,
  "false_positive_rate_percent": 8.2,
  "avg_confidence_percent": 82.3,
  "cpu_percent": 45.2,
  "memory_percent": 62.1,
  "disk_percent": 35.0,
  "status": "Healthy"
}
```

### 2. Email Alerting
**File:** `src/email_alerter.py`

Send professional email alerts:
```python
from src.email_alerter import EmailAlerter

alerter = EmailAlerter(
    smtp_server="smtp.gmail.com",
    sender_email="security@yourcompany.com",
    sender_password="your_app_password"  # Use app-specific password
)

# Send alert
alerter.send_alert(
    recipient_email="soc@yourcompany.com",
    alert_type="SQL Injection",
    source_ip="203.0.113.45",
    dest_ip="10.0.0.1",
    dest_port=3306,
    confidence=0.91,
    threat_details="Detected SQL injection pattern in HTTP request"
)

# Send batch alerts
alerter.send_batch_alerts(
    recipient_emails=["soc@company.com", "ciso@company.com"],
    alerts=[
        {"alert_type": "DDoS", "source_ip": "198.51.100.1", ...},
        {"alert_type": "Brute Force", "source_ip": "192.0.2.5", ...}
    ]
)
```

**Email Features:**
- HTML formatted with color-coded severity
- Includes source IP, target, and port information
- Automatic remediation recommendations
- Timestamp and confidence scores

### 3. Structured Logging
**File:** `src/logger.py`

Production-grade JSON logging:
```python
from src.logger import get_logger, log_alert, log_error

# Get logger
logger = get_logger()

# Log alerts
log_alert(
    alert_type="Port Scan",
    source_ip="203.0.113.100",
    dest_ip="10.0.0.5",
    confidence=0.78,
    target_ports="22,23,80,443,3389"
)

# Log errors with context
try:
    # some operation
    pass
except Exception as e:
    log_error(e, context="Alert processing", user_id="analyst_001")

# Log info and debug
logger.log_info("Pipeline started")
logger.log_debug("Processing alert", alert_id=12345)
```

**Log Output (JSON format):**
```json
{
  "timestamp": "2026-02-02T10:30:45.123456",
  "level": "INFO",
  "logger": "zerobit.security",
  "message": "ALERT: Port Scan from 203.0.113.100 to 10.0.0.5",
  "module": "detection",
  "function": "process_alert",
  "line": 156,
  "context": {
    "target_ports": "22,23,80,443,3389"
  }
}
```

**Log Files:**
- `logs/zerobit.log` - Main application log (10MB rotating, 10 backups)
- `logs/security_events.log` - Security events only (50MB rotating, 20 backups)

### 4. Configuration Management
**File:** `src/config.py`

Flexible configuration system:

**Create `config.json`:**
```json
{
  "detection_enabled": true,
  "confidence_threshold": 0.65,
  "max_alerts_per_hour": 500,
  "auto_block_enabled": false,
  "email_enabled": true,
  "email_recipients": ["soc@company.com", "ciso@company.com"],
  "honeypot_enabled": true,
  "honeypot_ports": [22, 23, 3389],
  "api_enabled": true,
  "api_port": 8000,
  "log_level": "INFO"
}
```

**Use in Code:**
```python
from src.config import get_config, load_config
from pathlib import Path

# Load config
config = get_config()

# Access settings
if config.get("email_enabled"):
    recipients = config.get("email_recipients")

# Or load from specific file
config = load_config(Path("config/production.json"))

# Validate
if config.validate():
    print("Configuration is valid!")

# Save
config.save(Path("config.json"))
```

**Environment Variables (Alternative):**
```bash
export ZEROBIT_DETECTION_ENABLED=true
export ZEROBIT_CONFIDENCE_THRESHOLD=0.65
export ZEROBIT_EMAIL_ENABLED=true
export ZEROBIT_EMAIL_RECIPIENTS="soc@company.com,ciso@company.com"
export ZEROBIT_SMTP_SERVER="smtp.gmail.com"
export ZEROBIT_SMTP_PORT=587
export ZEROBIT_LOG_LEVEL=DEBUG
```

### 5. System Health Dashboard
**File:** `src/health_dashboard.py`

Embedded in main dashboard UI with:

**KPI Cards:**
- System Status (Healthy/Warning)
- Uptime
- Detection Rate (alerts/hour)
- False Positive Rate (%)

**Performance Charts:**
- Confidence Score Distribution
- Detection Rate Trends
- CPU/Memory/Disk Usage

**Metrics Table:**
| Metric | Value | Status |
|--------|-------|--------|
| Total Detections (24h) | 42 | ✓ Active |
| Average Confidence | 84.2% | ✓ Good |
| False Positive Rate | 6.3% | ✓ Good |
| Detection Rate | 1.8/hour | ✓ Active |
| CPU Usage | 35.2% | ✓ Normal |
| Memory Usage | 62.1% | ✓ Normal |

**Features:**
- Auto-generates recommendations for issues
- Export metrics as JSON
- Real-time refresh capability

---

## 📋 Configuration Examples

### Gmail SMTP Setup
```python
# 1. Enable 2FA on Gmail
# 2. Create app-specific password: https://myaccount.google.com/apppasswords
# 3. Use app password in config:

from src.email_alerter import EmailAlerter

alerter = EmailAlerter(
    smtp_server="smtp.gmail.com",
    smtp_port=587,
    sender_email="security@yourcompany.com",
    sender_password="xxxx xxxx xxxx xxxx"  # 16-char app password
)
```

### Production Configuration
```json
{
  "detection_enabled": true,
  "confidence_threshold": 0.70,
  "max_alerts_per_hour": 1000,
  "auto_block_enabled": true,
  "email_enabled": true,
  "email_recipients": [
    "soc@company.com",
    "ciso@company.com",
    "noc@company.com"
  ],
  "honeypot_enabled": true,
  "honeypot_ports": [22, 23, 3389, 5432, 3306],
  "api_enabled": true,
  "api_port": 8000,
  "log_level": "INFO",
  "log_dir": "/var/log/zerobit",
  "data_dir": "/var/lib/zerobit"
}
```

### Development Configuration
```json
{
  "detection_enabled": true,
  "confidence_threshold": 0.50,
  "auto_block_enabled": false,
  "email_enabled": false,
  "honeypot_enabled": false,
  "api_enabled": false,
  "log_level": "DEBUG"
}
```

---

## 🚀 Integration Examples

### With Detection Pipeline
```python
from src.metrics import MetricsTracker
from src.logger import log_alert
from src.email_alerter import EmailAlerter

metrics = MetricsTracker()
alerter = EmailAlerter(...)

def process_detection(alert):
    # Record metrics
    metrics.record_alert(
        confidence=alert['confidence'],
        alert_type=alert['type']
    )
    
    # Log security event
    log_alert(
        alert_type=alert['type'],
        source_ip=alert['src_ip'],
        dest_ip=alert['dst_ip'],
        confidence=alert['confidence']
    )
    
    # Send critical alerts
    if alert['confidence'] > 0.85:
        alerter.send_alert(
            recipient_email="soc@company.com",
            alert_type=alert['type'],
            source_ip=alert['src_ip'],
            dest_ip=alert['dst_ip'],
            dest_port=alert['dst_port'],
            confidence=alert['confidence']
        )
```

### Dashboard Health Check
```python
from src.metrics import MetricsTracker
import streamlit as st

tracker = MetricsTracker()
health = tracker.get_health_summary()

st.metric("System Status", health['status'])
st.metric("Detection Rate", f"{health['detection_rate_per_hour']:.1f}/hour")
st.metric("Confidence", f"{health['avg_confidence_percent']:.1f}%")
```

---

## ⚙️ Performance Tuning

### High Alert Volume Scenario
```json
{
  "confidence_threshold": 0.75,
  "max_alerts_per_hour": 2000,
  "log_level": "WARNING"
}
```

### High Accuracy Scenario
```json
{
  "confidence_threshold": 0.60,
  "max_alerts_per_hour": 500,
  "log_level": "DEBUG"
}
```

### Security Monitoring Scenario
```json
{
  "email_enabled": true,
  "email_recipients": ["soc@company.com"],
  "honeypot_enabled": true,
  "auto_block_enabled": true,
  "log_level": "INFO"
}
```

---

## 📊 Monitoring Best Practices

1. **Check Health Dashboard Daily** - Review system status and metrics
2. **Monitor False Positive Rate** - Aim for < 10%
3. **Track Average Confidence** - Should be > 75%
4. **Review Logs Weekly** - Look for patterns or errors
5. **Adjust Thresholds** - Based on your environment
6. **Test Email Alerts** - Verify SMTP configuration
7. **Validate Configuration** - Run config.validate() before production

---

## 🆘 Troubleshooting

**Metrics not showing?**
- Ensure metrics.db is writable: `chmod 666 data/metrics.db`
- Check logs: `tail -f logs/zerobit.log`

**Email alerts not sending?**
- Verify SMTP credentials
- Check firewall allows port 587
- Review logs for SMTP errors
- Test with: `python -m src.email_alerter`

**High CPU usage?**
- Check log rotation settings
- Review detection threshold
- Monitor running processes

**Memory leaks?**
- Review logs for errors
- Check metrics tracking interval
- Consider restarting service periodically

---

## 📈 What's Next?

See NEXT_STEPS.md for additional features:
- Real-Time Packet Processing Pipeline
- Custom Rule Engine
- Threat Hunting Queries
- IOC Management
- Alert Correlation
- Docker Containerization
- API Endpoints for Integration

---

**Version:** 2.0 (with Enterprise Features)  
**Last Updated:** February 2, 2026
