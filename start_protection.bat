@echo off
cls
color 0A
echo =====================================================
echo            AegisAI Real-Time Protection
echo =====================================================
echo.
echo Features:
echo  - Real-time file system monitoring
echo  - Automatic threat detection and quarantine
echo  - Ad blocking (works automatically - no configuration needed)
echo  - Malware and virus protection
echo  - System performance optimization
echo.
echo The ad blocker works automatically by modifying your hosts file
echo to redirect ad domains to your local machine.
echo.
echo To stop protection, press Ctrl+C and confirm with 'Y'
echo.
echo Starting protection in 3 seconds...
timeout /t 3 /nobreak >nul
echo.
python "%~dp0realtime_aegisai.py"