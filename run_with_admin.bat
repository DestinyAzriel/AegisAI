@echo off
:: AegisAI Launcher with Automatic Admin Elevation
:: This script will automatically request administrator privileges if not already running as admin

:: Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    :: Already running as admin
    echo Running with administrator privileges
    cd /d D:\AegisAI
    python realtime_aegisai.py
) else (
    :: Not running as admin, request elevation
    echo Requesting administrator privileges...
    echo This is required for full AegisAI functionality:
    echo   - System hardening (ASLR, DEP, Firewall)
    echo   - Automatic threat quarantine
    echo   - Registry modifications
    echo   - Network protection
    echo.
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d D:\AegisAI && python realtime_aegisai.py' -Verb RunAs"
)

pause