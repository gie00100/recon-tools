@echo off
chcp 65001 >nul 2>&1
echo.
echo ============================================
echo   VPS Recon Status Check
echo   VPS: 134.209.72.156
echo ============================================
echo.

ssh -o ConnectTimeout=10 -o ServerAliveInterval=5 -p 22 root@134.209.72.156 "bash -s" < "%~dp0scripts\vps_check.sh"

echo.
echo ============================================
pause
