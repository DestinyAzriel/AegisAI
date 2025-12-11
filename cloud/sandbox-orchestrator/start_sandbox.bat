@echo off
REM AegisAI Sandbox Orchestrator Startup Script

echo ========================================
echo    AegisAI Sandbox Orchestrator
echo ========================================

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Docker is not running or not accessible
    echo Please start Docker Desktop and try again
    pause
    exit /b 1
)

echo Starting AegisAI Sandbox Orchestrator...

REM Build Docker image if it doesn't exist
echo Building sandbox Docker image...
docker build -t aegisai/sandbox-orchestrator:latest .

if %errorlevel% neq 0 (
    echo ERROR: Failed to build Docker image
    pause
    exit /b 1
)

REM Run the sandbox orchestrator
echo Starting sandbox orchestrator service...
docker run -d --name aegisai-sandbox-orchestrator ^
  -p 8002:8002 ^
  -v /var/run/docker.sock:/var/run/docker.sock ^
  aegisai/sandbox-orchestrator:latest

if %errorlevel% neq 0 (
    echo ERROR: Failed to start sandbox orchestrator
    pause
    exit /b 1
)

echo Sandbox orchestrator started successfully!
echo API available at: http://localhost:8002
echo Documentation: http://localhost:8002/docs
echo Health check: http://localhost:8002/health

echo.
echo Press any key to continue...
pause >nul