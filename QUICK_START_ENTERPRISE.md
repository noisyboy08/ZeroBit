# 🚀 ZeroBit Enterprise Features - Quick Start

## ⚡ 5-Minute Setup

### 1. Create Configuration File

Create `config.json` in the project root:

```json
{
  "detection_enabled": true,
  "confidence_threshold": 0.70,
  "max_alerts_per_hour": 1000,
  "auto_block_enabled": false,
  "email_enabled": false,
  "honeypot_enabled": false,
  "api_enabled": false,
  "log_level": "INFO",
  "log_dir": "logs",
  "data_dir": "data"
}
```

### 2. Update Requirements

```bash
pip install -r requirements.txt
```

### 3. Use in Your Code

#### Track Metrics
```python
from src.metrics import MetricsTracker

tracker = MetricsTracker()
tracker.record_alert(confidence=0.92, alert_type="Brute Force")

health = tracker.get_health_summary()
print(f"Status: {health['status']}")
print(f"Detections: {health['detection_rate_per_hour']:.1f}/hour")
print(f"FP Rate: {health['false_positive_rate_percent']:.1f}%")
```

#### Enable Logging
```python
from src.logger import log_alert, log_error

# Log security events
log_alert(
    alert_type="Port Scan",
    source_ip="203.0.113.100",
    dest_ip="10.0.0.1",
    confidence=0.85
)

# Log errors with context
try:
    # your code
except Exception as e:
    log_error(e, context="Detection pipeline")
```

#### Load Configuration
```python
from src.config import get_config

config = get_config()
if config.get("email_enabled"):
    print("Email alerts enabled!")
```

## 🔧 Setup Email Alerts (Optional)

### Gmail Setup

1. **Enable 2-Factor Authentication**
   - Go to https://myaccount.google.com/
   - Search for "App passwords"

2. **Generate App Password**
   - Select "Mail" and "Windows Computer"
   - Copy the 16-character password

3. **Update config.json**
   ```json
   {
     "email_enabled": true,
     "email_recipients": ["soc@company.com"],
     "smtp_server": "smtp.gmail.com",
     "smtp_port": 587
   }
   ```

4. **Create .env file** (don't commit!)
   ```
   ZEROBIT_SMTP_PASSWORD=xxxx xxxx xxxx xxxx
   ```

5. **Use in Code**
   ```python
   from src.email_alerter import EmailAlerter
   import os
   
   alerter = EmailAlerter(
       sender_email="security@company.com",
       sender_password=os.getenv("ZEROBIT_SMTP_PASSWORD")
   )
   
   alerter.send_alert(
       recipient_email="soc@company.com",
       alert_type="SQL Injection",
       source_ip="203.0.113.45",
       dest_ip="10.0.0.1",
       dest_port=3306,
       confidence=0.91
   )
   ```

## 📊 Monitor System Health

### Check Metrics Programmatically
```python
from src.metrics import MetricsTracker

tracker = MetricsTracker()

# Get current health
health = tracker.get_health_summary()

# Check specific metrics
if health['cpu_percent'] > 80:
    print("⚠️ High CPU usage!")

if health['false_positive_rate_percent'] > 10:
    print("⚠️ High false positive rate!")

# Get confidence distribution
dist = tracker.get_confidence_distribution(hours=24)
print(f"Alerts by confidence: {dist}")
```

### View Logs
```bash
# Tail main log
tail -f logs/zerobit.log

# View security events (JSON format)
tail -f logs/security_events.log | jq .

# Search logs
grep "CRITICAL" logs/zerobit.log
```

## 🎯 Common Patterns

### Integration with Detection Pipeline

```python
from src.metrics import MetricsTracker
from src.logger import log_alert
from src.config import get_config

def process_alert(alert):
    metrics = MetricsTracker()
    config = get_config()
    
    # Record metrics
    metrics.record_alert(
        confidence=alert['confidence'],
        alert_type=alert['type']
    )
    
    # Log event
    log_alert(
        alert_type=alert['type'],
        source_ip=alert['src_ip'],
        dest_ip=alert['dst_ip'],
        confidence=alert['confidence']
    )
    
    # Send email if critical
    if alert['confidence'] > 0.85:
        if config.get("email_enabled"):
            from src.email_alerter import EmailAlerter
            alerter = EmailAlerter(...)
            alerter.send_alert(...)
```

### Configuration from Environment

```bash
export ZEROBIT_DETECTION_ENABLED=true
export ZEROBIT_CONFIDENCE_THRESHOLD=0.65
export ZEROBIT_EMAIL_ENABLED=true
export ZEROBIT_EMAIL_RECIPIENTS="soc@company.com,ciso@company.com"
export ZEROBIT_LOG_LEVEL=DEBUG
```

## ✅ Verification Checklist

- [ ] `config.json` created
- [ ] `requirements.txt` installed
- [ ] `logs/` directory accessible
- [ ] `data/metrics.db` can be created
- [ ] Email credentials configured (if using alerts)
- [ ] Python compiles without errors: `python -c "from src.metrics import MetricsTracker"`

## 🆘 Troubleshooting

**Metrics not found?**
```bash
pip install psutil
```

**Email not sending?**
- Check SMTP credentials
- Test: `python -c "from src.email_alerter import EmailAlerter; print('OK')"`
- Review logs: `tail -f logs/zerobit.log | grep -i email`

**Config validation fails?**
```python
from src.config import get_config
config = get_config()
if not config.validate():
    print("Fix config.json and try again")
```

## 📚 Full Documentation

See **ENTERPRISE_FEATURES.md** for:
- Complete API documentation
- Integration examples
- Performance tuning
- Best practices
- Advanced configuration

## 🚀 Next Steps

1. Read ENTERPRISE_FEATURES.md
2. Set up email alerts (optional)
3. Monitor health dashboard
4. Review logs daily
5. Adjust thresholds for your environment

---

**Version:** 2.0  
**Status:** Production Ready ✓
