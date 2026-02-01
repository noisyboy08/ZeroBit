@echo off
REM ZeroBit Quick Start Script for Windows

echo.
echo ============================================================
echo  🛡️  ZeroBit SOC Dashboard - Quick Start
echo ============================================================
echo.

REM Check if virtual environment exists
if not exist ".venv" (
    echo ❌ Virtual environment not found!
    echo.
    echo Creating virtual environment...
    python -m venv .venv
)

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Check if dependencies are installed
echo.
echo Checking dependencies...
pip list | findstr streamlit >nul
if errorlevel 1 (
    echo.
    echo 📦 Installing dependencies...
    pip install -r requirements.txt -q
)

REM Generate demo data if not exists
if not exist "data\alerts.db" (
    echo.
    echo 🎬 Generating demo data...
    python demo_setup.py
)

REM Start Streamlit dashboard
echo.
echo ============================================================
echo  ✅ Starting ZeroBit Dashboard...
echo ============================================================
echo.
echo 📊 Dashboard URL: http://localhost:8501
echo.
echo Press Ctrl+C to stop the dashboard
echo.

streamlit run dashboard/app.py

pause
