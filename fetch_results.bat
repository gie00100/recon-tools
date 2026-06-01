@echo off
title Recon Pipeline — Fetch Latest Results
color 0B
echo ========================================================
echo   Recon Pipeline — Fetching Latest Results from VPS
echo ========================================================
echo.

:: Check if virtual environment python exists
if not exist "venv\Scripts\python.exe" (
    color 0C
    echo [ERROR] Virtual environment python was not found!
    echo Please run setup_vps.sh or create a venv in the project root.
    echo.
    pause
    exit /b 1
)

echo [*] Connecting to VPS and checking for new results...
echo.
venv\Scripts\python.exe scripts\local\fetch_results.py
echo.
echo ========================================================
echo   Process Finished
echo ========================================================
echo.
pause
