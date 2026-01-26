#!/usr/bin/env powershell
# ZeroBit Quick Start Script for PowerShell

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  🛡️  ZeroBit SOC Dashboard - Quick Start" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if virtual environment exists
if (-not (Test-Path ".venv")) {
    Write-Host "❌ Virtual environment not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

# Activate virtual environment
Write-Host "✅ Activating virtual environment..." -ForegroundColor Green
& ".\.venv\Scripts\Activate.ps1"

# Check if dependencies are installed
Write-Host ""
Write-Host "📦 Checking dependencies..." -ForegroundColor Yellow

$installed = pip list | Select-String "streamlit"
if (-not $installed) {
    Write-Host ""
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt -q
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
}

# Generate demo data if not exists
if (-not (Test-Path "data\alerts.db")) {
    Write-Host ""
    Write-Host "🎬 Generating demo data..." -ForegroundColor Yellow
    python demo_setup.py
}

# Start Streamlit dashboard
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ✅ Starting ZeroBit Dashboard..." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 Dashboard URL: http://localhost:8501" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop the dashboard" -ForegroundColor Yellow
Write-Host ""

streamlit run dashboard/app.py

Write-Host ""
Write-Host "Dashboard stopped." -ForegroundColor Yellow
Read-Host "Press Enter to exit"
