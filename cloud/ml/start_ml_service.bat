@echo off
echo Starting AegisAI ML Service...

REM Check if Python is installed
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: Python not found. Please install Python 3.8 or later.
    pause
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies.
    pause
    exit /b 1
)

REM Create models directory
if not exist "models" mkdir models

REM Start the service
echo Starting ML service...
uvicorn main:app --host 0.0.0.0 --port 8002

pause