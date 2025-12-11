@echo off
echo AegisAI Kernel Driver Installation
echo =================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo Error: This script must be run as Administrator
    echo Please right-click and select "Run as Administrator"
    pause
    exit /b 1
)

REM Check if driver files exist
if not exist "aegisai_filter.sys" (
    echo Warning: aegisai_filter.sys not found
    echo You need to build the kernel driver first
)

if not exist "aegisai_filter.inf" (
    echo Error: aegisai_filter.inf not found
    pause
    exit /b 1
)

REM Stop existing service if running
echo Stopping existing AegisAI filter service...
sc stop AegisAIFilter >nul 2>&1

REM Uninstall existing driver
echo Uninstalling existing driver...
pnputil /delete-driver aegisai_filter.inf /force >nul 2>&1

REM Install the driver
echo Installing AegisAI filter driver...
pnputil /add-driver aegisai_filter.inf /install
if %errorlevel% neq 0 (
    echo Error: Driver installation failed
    pause
    exit /b 1
)

REM Start the service
echo Starting AegisAI filter service...
sc start AegisAIFilter
if %errorlevel% neq 0 (
    echo Warning: Could not start service automatically
    echo You may need to start it manually from Services
)

echo.
echo Installation completed!
echo The AegisAI kernel-level monitoring driver is now installed.
echo It will monitor file system operations for enhanced threat detection.

pause