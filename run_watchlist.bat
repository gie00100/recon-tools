@echo off
title Recon Pipeline — Run Watchlist Scan
color 0A
echo ========================================================
echo   Recon Pipeline — Watchlist Sequential Scan
echo ========================================================
echo.

if not exist "venv\Scripts\python.exe" (
    color 0C
    echo [ERROR] Virtual environment python was not found!
    echo Please run setup_vps.sh or create a venv in the project root.
    echo.
    pause
    exit /b 1
)

echo [*] Launching sequential scan on VPS for watchlist domains...
echo.
venv\Scripts\python.exe scripts\vps\run_watchlist.py %*
echo.
echo ========================================================
echo   Process Finished
echo ========================================================
echo.
pause
