@echo off
REM ============================================================
REM  Recon Toolkit — Windows Setup Script
REM  Run this after cloning the repo on a new machine
REM ============================================================

echo.
echo  ============================================
echo   Recon Toolkit - First Time Setup
echo  ============================================
echo.

REM Step 1: Create virtual environment
echo [1/4] Creating Python virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from python.org
    pause
    exit /b 1
)

REM Step 2: Install dependencies
echo [2/4] Installing dependencies...
.\venv\Scripts\pip.exe install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

REM Step 3: Copy config templates
echo [3/4] Setting up configuration files...

if not exist "src\.env" (
    copy "src\.env.example" "src\.env"
    echo    Created src\.env — FILL IN YOUR API KEYS
) else (
    echo    src\.env already exists, skipping
)

if not exist "vps_config.ini" (
    copy "vps_config.example.ini" "vps_config.ini"
    echo    Created vps_config.ini — FILL IN YOUR VPS CREDENTIALS
) else (
    echo    vps_config.ini already exists, skipping
)

REM Step 4: Create output directory
echo [4/4] Creating output directory...
if not exist "output" mkdir output

echo.
echo  ============================================
echo   Setup Complete!
echo  ============================================
echo.
echo  NEXT STEPS:
echo   1. Edit src\.env and add your API keys
echo   2. Edit vps_config.ini and add your VPS credentials
echo   3. Run: .\venv\Scripts\python.exe scripts\vps\deploy_vps.py
echo.
pause
