@echo off
REM This is a suspicious batch file
echo "Suspicious Activity"
REM CreateProcess
REM WriteFile
REM RegSetValue
REM Network connection simulation
ping -n 1 127.0.0.1 > nul
echo Malicious activity detected >> log.txt
