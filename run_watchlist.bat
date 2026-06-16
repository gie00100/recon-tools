@echo off
title Recon Pipeline — Run Watchlist Scan
color 0A
echo ================================================================
echo   Recon Pipeline — VPS Clean + Update + Sequential Scan
echo ================================================================
echo.
echo   What this does:
echo     1. Kills any running scans on VPS
echo     2. Cleans VPS output directory  (rm -rf output/*)
echo     3. Git pulls latest code + targets on VPS
echo     4. Uploads active domain list from targets/targets.txt
echo     5. Launches sequential scan (one domain at a time)
echo.
echo   Active domains: all uncommented lines in targets/targets.txt
echo ================================================================
echo.

if not exist "venv\Scripts\python.exe" (
    color 0C
    echo [ERROR] Virtual environment python was not found!
    echo Please run setup or create a venv in the project root.
    echo.
    pause
    exit /b 1
)

REM Check for flags
set FLAGS=
if "%1"=="--dry-run"  set FLAGS=--dry-run
if "%1"=="--no-clean" set FLAGS=--no-clean
if "%1"=="--help"     goto :HELP

echo [*] Reading active domains from targets/targets.txt...
echo.

venv\Scripts\python.exe scripts\vps\run_watchlist.py --file targets.txt %FLAGS% %2 %3

echo.
echo ================================================================
echo   Process Finished
echo ================================================================
echo.
echo   Useful commands:
echo     Fetch results:    run_fetch_results.bat
echo     Check progress:   python scripts/vps/check_recon_progress.py
echo.
pause
goto :EOF

:HELP
echo Usage:
echo   run_watchlist.bat              - Full run (clean + update + scan)
echo   run_watchlist.bat --dry-run    - Preview domains without launching
echo   run_watchlist.bat --no-clean   - Skip VPS output cleanup
echo.
pause
