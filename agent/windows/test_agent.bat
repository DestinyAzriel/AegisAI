@echo off
echo AegisAI Windows Agent Test
echo =========================

REM Check if agent executable exists
if not exist "build\Release\aegisai-agent.exe" (
    echo Error: aegisai-agent.exe not found
    echo Please build the agent first using CMake
    pause
    exit /b 1
)

echo Starting AegisAI agent test...
echo.

REM Run basic agent functionality test
echo Testing help info:
build\Release\aegisai-agent.exe /?

echo.
echo Testing scan with timeout:
powershell -Command "Start-Process -FilePath 'build\Release\aegisai-agent.exe' -ArgumentList 'scan', '..' -Wait -NoNewWindow -PassThru | Select-Object -First 1 | Wait-Process -Timeout 10"

echo.
echo Test completed!

pause