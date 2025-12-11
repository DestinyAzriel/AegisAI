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
echo  - Ad blocking (works automatically)
echo  - Malware and virus protection
echo  - System performance optimization
echo.
echo Press Ctrl+C to stop protection at any time
echo.
echo Starting protection in 3 seconds...
timeout /t 3 /nobreak >nul
echo.
python "%~dp0realtime_aegisai.py"