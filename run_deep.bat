@echo off
REM ============================================================
REM  Recon Toolkit — Deep Elite Recon Runner
REM ============================================================

echo.
echo  ============================================
echo   Deep Recon Pipeline (Elite Features)
echo  ============================================
echo.
echo This script runs ONLY the new Deep Recon modules:
echo  1. SaaS Misconfiguration Hunter
echo  2. Semantic API Wordlist Generator
echo.

set /p domain="Enter target domain (e.g., wix.com): "

if "%domain%"=="" (
    echo Error: Domain cannot be empty.
    pause
    exit /b 1
)

echo.
echo [!] Starting Deep Recon for %domain%...
.\venv\Scripts\python.exe src\recon_master.py -d %domain% --modules deep --deep

echo.
echo [!] Deep Recon Complete.
pause
