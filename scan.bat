@echo off
title Recon Pipeline — Scan Launcher
color 0B

if not exist "venv\Scripts\python.exe" (
    color 0C
    echo [ERROR] venv\Scripts\python.exe not found.
    echo Run: python -m venv venv ^&^& venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

echo ============================================================
echo   Recon Pipeline — Scan Launcher
echo ============================================================
echo.
echo Usage:
echo   scan.bat bykea.com api.bykea.net
echo   scan.bat --active
echo   scan.bat --file targets\targets.txt
echo   scan.bat --sync-only
echo.

venv\Scripts\python.exe scripts\local\scan.py %*
echo.
echo ============================================================
echo   Done
echo ============================================================
echo.
pause
