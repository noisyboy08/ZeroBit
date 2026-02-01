# 🚀 ZeroBit Dashboard Deployment Guide

## ⚠️ Important: Netlify Limitation

**Netlify is NOT suitable for Streamlit applications** because:
- Netlify is designed for static sites (HTML/CSS/JS)
- Streamlit requires a Python runtime and web server
- Netlify Functions have execution time limits (10s free tier)
- Streamlit apps need persistent connections

## ✅ Recommended Deployment Options

### Option 1: Streamlit Cloud (BEST - FREE & EASY)

**Recommended for Streamlit apps!**

1. **Sign up**: https://streamlit.io/cloud
2. **Connect GitHub**: Link your repository
3. **Deploy**: Click "Deploy" - it's automatic!
4. **Free tier**: Unlimited apps, public repos

**Steps:**
```bash
# 1. Push code to GitHub
git init
git add .
git commit -m "Initial commit"
git remote add origin YOUR_GITHUB_REPO_URL
git push -u origin main

# 2. Go to streamlit.io/cloud
# 3. Sign in with GitHub
# 4. Click "New app"
# 5. Select your repo
# 6. Main file path: dashboard/app.py
# 7. Click "Deploy"
```

### Option 2: Render (FREE TIER AVAILABLE)

1. **Sign up**: https://render.com
2. **New Web Service**
3. **Connect GitHub repo**
4. **Settings:**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `streamlit run dashboard/app.py --server.port=$PORT --server.address=0.0.0.0`
   - Environment: Python 3

### Option 3: Railway (EASY & FREE TRIAL)

1. **Sign up**: https://railway.app
2. **New Project** → **Deploy from GitHub**
3. **Add service** → **Web Service**
4. **Settings:**
   - Start Command: `streamlit run dashboard/app.py --server.port=$PORT --server.address=0.0.0.0`

### Option 4: Heroku (PAID NOW, BUT STABLE)

1. **Create `Procfile`:**
```
web: streamlit run dashboard/app.py --server.port=$PORT --server.address=0.0.0.0
```

2. **Deploy:**
```bash
heroku create your-app-name
git push heroku main
```

### Option 5: Docker + Any Cloud Provider

**Create `Dockerfile`:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

ENTRYPOINT ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

**Deploy to:**
- AWS ECS/Fargate
- Google Cloud Run
- Azure Container Instances
- DigitalOcean App Platform

## 📋 Pre-Deployment Checklist

### ✅ Code Fixes Applied

- [x] Fixed all import errors
- [x] Fixed Plotly colorbar configuration
- [x] Fixed geographic map errors
- [x] Added error handling throughout
- [x] Removed blocking time.sleep()
- [x] All dependencies in requirements.txt

### ✅ Files Ready for Deployment

- `dashboard/app.py` - Main dashboard (error-free)
- `requirements.txt` - All dependencies
- `demo_setup.py` - Data generator
- `src/` - All source modules

### ⚠️ Before Deploying

1. **Test locally:**
```bash
python -m streamlit run dashboard/app.py
```

2. **Check for errors:**
- All imports work
- Charts render correctly
- No console errors

3. **Environment variables** (if needed):
- GROQ_API_KEY
- ABUSEIPDB_API_KEY
- VIRUSTOTAL_API_KEY

## 🎯 Quick Deploy to Streamlit Cloud

**Fastest way (5 minutes):**

1. **Create GitHub repo:**
```bash
cd ZeroBit-main
git init
git add .
git commit -m "ZeroBit Dashboard"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/zerobit-dashboard.git
git push -u origin main
```

2. **Deploy on Streamlit Cloud:**
   - Go to https://share.streamlit.io
   - Sign in with GitHub
   - Click "New app"
   - Select repo: `zerobit-dashboard`
   - Main file: `dashboard/app.py
   - Click "Deploy"

3. **Done!** Your app will be live at:
   `https://YOUR-APP-NAME.streamlit.app`

## 🔧 If You Must Use Netlify

**You would need to:**
1. Convert Streamlit to a static React/Vue app (major rewrite)
2. Use Netlify Functions for backend (limited)
3. Rebuild all visualizations in JavaScript

**This is NOT recommended** - use Streamlit Cloud instead!

## 📞 Support

For deployment issues:
- Streamlit Cloud: https://docs.streamlit.io/streamlit-community-cloud
- Render: https://render.com/docs
- Railway: https://docs.railway.app

---

**Recommendation: Use Streamlit Cloud - it's free, easy, and designed for Streamlit apps!**
