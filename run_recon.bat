@echo off
setlocal

if "%~1"=="" (
    echo Usage: run_recon.bat ^<domain^>
    echo Example: run_recon.bat example.com
    exit /b 1
)

set DOMAIN=%~1
set SCRIPT_DIR=%~dp0

echo ========================================================
echo Starting Advanced Bug Bounty Recon on: %DOMAIN%
echo ========================================================

REM Check if venv exists
if not exist "%SCRIPT_DIR%venv\Scripts\python.exe" (
    echo Virtual environment not found at %SCRIPT_DIR%venv\Scripts\python.exe.
    echo Please create it and install requirements first.
    exit /b 1
)

REM Run the recon pipeline with all features enabled
"%SCRIPT_DIR%venv\Scripts\python.exe" "%SCRIPT_DIR%src\recon_master.py" -d "%DOMAIN%" -o "%CD%\output" --full --brute --permutations --active

echo.
echo Reconnaissance finished. Check the output directory for results.
endlocal
