@echo off
title Recon Pipeline — Run Watchlist Scan
color 0A
echo ================================================================
echo   Recon Pipeline — VPS Clean + Update + Sequential Scan
echo ================================================================
echo.
echo   What this does:
echo     1. Kills any running SCAN sessions on VPS (not the bot)
echo     2. Cleans VPS output directory  (rm -rf output/*)
echo     3. Git pulls latest code + targets on VPS
echo     4. Restarts Discord bot safely via systemctl
echo        (prevents double-message bug from duplicate processes)
echo     5. Uploads active domain list from targets/targets.txt
echo     6. Launches sequential scan (one domain at a time)
echo.
echo   Active domains: all uncommented lines in targets/targets.txt
echo.
echo   FLAGS:
echo     --dry-run        Preview domains without launching
echo     --no-clean       Skip VPS output cleanup
echo     --no-bot-restart Skip Discord bot restart
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

REM Parse flags - support up to 2 flags
set FLAGS=
if "%1"=="--dry-run"        set FLAGS=--dry-run
if "%1"=="--no-clean"       set FLAGS=--no-clean
if "%1"=="--no-bot-restart" set FLAGS=--no-bot-restart
if "%1"=="--help"           goto :HELP
if "%2"=="--no-bot-restart" set FLAGS=%FLAGS% --no-bot-restart
if "%2"=="--no-clean"       set FLAGS=%FLAGS% --no-clean

echo [*] Reading active domains from targets/targets.txt...
echo.

venv\Scripts\python.exe scripts\vps\run_watchlist.py --file targets.txt %FLAGS%

echo.
echo ================================================================
echo   Process Finished
echo ================================================================
echo.
echo   Useful commands:
echo     Fetch results:    run_fetch_results.bat
echo     Check progress:   python scripts/vps/check_recon_progress.py
echo     Bot log:          ssh root@VPS "journalctl -u recon-bot -n 20"
echo.
pause
goto :EOF

:HELP
echo Usage:
echo   run_watchlist.bat                          - Full run
echo   run_watchlist.bat --dry-run                - Preview domains only
echo   run_watchlist.bat --no-clean               - Skip output cleanup
echo   run_watchlist.bat --no-bot-restart         - Skip bot restart
echo   run_watchlist.bat --no-clean --no-bot-restart
echo.
echo NOTE: Discord bot is managed by systemd (recon-bot.service).
echo       This script uses 'systemctl restart' to avoid duplicate
echo       bot processes which cause double Discord responses.
echo       NEVER use pkill or nohup to restart the bot manually.
echo.
pause
