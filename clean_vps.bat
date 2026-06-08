@echo off
title Recon Pipeline — Clean VPS Data
color 0E
echo ========================================================
echo   Recon Pipeline — VPS Data Cleanup
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

:: Pass all arguments through to the script
echo [*] Connecting to VPS and analyzing stored data...
echo.
venv\Scripts\python.exe scripts\vps\clean_vps_data.py %*
echo.
echo ========================================================
echo   Process Finished
echo ========================================================
echo.
pause
