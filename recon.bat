@echo off
chcp 65001 >nul 2>&1
title Recon Pipeline — Control Panel
color 0A

:MENU
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║          RECON PIPELINE — Control Panel                     ║
echo  ║          VPS: 134.209.72.156                                ║
echo  ╠══════════════════════════════════════════════════════════════╣
echo  ║                                                              ║
echo  ║  [1]  Run Watchlist Scan    (clean + update + scan all)      ║
echo  ║  [2]  Fetch Results         (pull output from VPS)           ║
echo  ║  [3]  VPS Status            (screen sessions + progress)     ║
echo  ║  [4]  Stop All Sessions     (kill all running scans)         ║
echo  ║  [5]  Clean VPS Data        (remove old output files)        ║
echo  ║  [6]  Scan Single Domain    (recon on one domain)            ║
echo  ║  [7]  Dry Run               (preview targets, no scan)       ║
echo  ║  [8]  Setup / Install       (install deps and configure)     ║
echo  ║  [Q]  Quit                                                   ║
echo  ║                                                              ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.

if not exist "venv\Scripts\python.exe" (
    color 0C
    echo  [ERROR] Virtual environment not found!
    echo  Run option [8] Setup first, or run: python -m venv venv ^&^& venv\Scripts\pip install -r requirements.txt
    echo.
)

set /p CHOICE="  Select option: "

if /i "%CHOICE%"=="1" goto :WATCHLIST
if /i "%CHOICE%"=="2" goto :FETCH
if /i "%CHOICE%"=="3" goto :STATUS
if /i "%CHOICE%"=="4" goto :STOP
if /i "%CHOICE%"=="5" goto :CLEAN
if /i "%CHOICE%"=="6" goto :SINGLE
if /i "%CHOICE%"=="7" goto :DRYRUN
if /i "%CHOICE%"=="8" goto :SETUP
if /i "%CHOICE%"=="Q" goto :EOF
if /i "%CHOICE%"=="q" goto :EOF

echo  [!] Invalid option. Try again.
timeout /t 1 >nul
goto :MENU


REM ══════════════════════════════════════════════════════════════════
:WATCHLIST
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [1] Run Watchlist Scan                                     ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  Steps:
echo    1. Kill existing scan sessions on VPS
echo    2. Clean VPS output directory
echo    3. Git pull latest code + targets on VPS
echo    4. Restart Discord bot (systemctl — avoids duplicate processes)
echo    5. Upload active domains from targets\targets.txt to VPS
echo    5b. Sync targets.txt on VPS so !status shows correct list
echo    6. Launch sequential scan in detached screen session
echo.
echo  Active domains: all uncommented lines in targets\targets.txt
echo.
echo  Options:
echo    [1] Full run (default)
echo    [2] Skip VPS output cleanup  (--no-clean)
echo    [3] Skip Discord bot restart (--no-bot-restart)
echo    [4] Skip both                (--no-clean --no-bot-restart)
echo    [B] Back to menu
echo.
set /p WL_CHOICE="  Select: "

if /i "%WL_CHOICE%"=="B" goto :MENU
if /i "%WL_CHOICE%"=="1" (
    set WL_FLAGS=
    goto :RUN_WATCHLIST
)
if /i "%WL_CHOICE%"=="2" (
    set WL_FLAGS=--no-clean
    goto :RUN_WATCHLIST
)
if /i "%WL_CHOICE%"=="3" (
    set WL_FLAGS=--no-bot-restart
    goto :RUN_WATCHLIST
)
if /i "%WL_CHOICE%"=="4" (
    set WL_FLAGS=--no-clean --no-bot-restart
    goto :RUN_WATCHLIST
)
echo  [!] Invalid — defaulting to full run.
set WL_FLAGS=

:RUN_WATCHLIST
echo.
venv\Scripts\python.exe scripts\vps\run_watchlist.py --file targets.txt %WL_FLAGS%
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:FETCH
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [2] Fetch Results from VPS                                 ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
venv\Scripts\python.exe scripts\local\fetch_results.py
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:STATUS
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [3] VPS Status                                             ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
venv\Scripts\python.exe scripts\vps\check_recon_progress.py
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:STOP
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [4] Stop All Sessions                                      ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
echo  WARNING: This will kill all running scan processes on VPS.
echo  The Discord bot will NOT be affected.
echo.
set /p CONFIRM="  Type YES to confirm: "
if /i not "%CONFIRM%"=="YES" (
    echo  Cancelled.
    goto :DONE
)
echo.
venv\Scripts\python.exe -c "
import sys
sys.path.insert(0, 'scripts/vps')
from vps_helper import connect_vps, run_remote
import time

ssh, cfg = connect_vps()
print()

print('[*] Current screen sessions:')
out = run_remote(ssh, 'screen -ls', silent=True)
print(out or '  (none)')

print()
print('[*] Killing all screen sessions...')
run_remote(ssh, 'screen -ls | grep -oP \"\\d+\\.\\S+\" | xargs -I{} screen -X -S {} quit 2>&1 || true', silent=True)
time.sleep(1)

print('[*] Killing scan processes...')
run_remote(ssh, 'pkill -f bulk_runner.py 2>/dev/null; pkill -f \"python.*recon\" 2>/dev/null; pkill -f run_scan.sh 2>/dev/null; pkill -f run_bulk.sh 2>/dev/null; true', silent=True)
time.sleep(1)

print()
print('[*] Remaining sessions:')
out = run_remote(ssh, 'screen -ls 2>/dev/null || echo \"(none)\"', silent=True)
print(out)

ssh.close()
print()
print('[+] All scan sessions stopped.')
"
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:CLEAN
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [5] Clean VPS Data                                         ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
venv\Scripts\python.exe scripts\vps\clean_vps_data.py %*
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:SINGLE
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [6] Scan Single Domain                                     ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
set /p DOMAIN="  Enter domain to scan (e.g. example.com): "
if "%DOMAIN%"=="" (
    echo  [!] No domain entered.
    goto :DONE
)
echo.
venv\Scripts\python.exe scripts\local\scan.py --domains %DOMAIN%
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:DRYRUN
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [7] Dry Run — Preview Targets                              ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
venv\Scripts\python.exe scripts\vps\run_watchlist.py --file targets.txt --dry-run
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:SETUP
cls
echo.
echo  ╔══════════════════════════════════════════════════════════════╗
echo  ║  [8] Setup / Install                                        ║
echo  ╚══════════════════════════════════════════════════════════════╝
echo.
call setup.bat
goto :DONE


REM ══════════════════════════════════════════════════════════════════
:DONE
echo.
echo ════════════════════════════════════════════════════════════════
echo.
set /p BACK="  Press Enter to return to menu, or Q to quit: "
if /i "%BACK%"=="Q" goto :EOF
goto :MENU
