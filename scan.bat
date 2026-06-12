@echo off
title Recon Pipeline — Scan Launcher
color 0B
echo ============================================================
echo   Recon Pipeline — Scan Launcher
echo ============================================================
echo.
echo   Usage examples:
echo     scan.bat --program bykea
echo     scan.bat --program wellsfargo
echo     scan.bat --program khealth
echo     scan.bat --domains bykea.com api.bykea.net
echo     scan.bat --all
echo     scan.bat --program bykea --dry-run
echo     scan.bat --no-sync --program khealth   (skip code sync)
echo.
echo ============================================================
echo.

if not exist "venv\Scripts\python.exe" (
    color 0C
    echo [ERROR] Virtual environment not found!
    echo Run setup.bat first.
    echo.
    pause
    exit /b 1
)

if "%~1"=="" (
    echo [!] No arguments given. Showing help:
    echo.
    venv\Scripts\python.exe scripts\local\scan.py --help
    echo.
    pause
    exit /b 0
)

venv\Scripts\python.exe scripts\local\scan.py %*
echo.
echo ============================================================
echo   Done
echo ============================================================
echo.
pause
