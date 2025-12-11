@echo off
echo Starting AegisAI Cloud Backend...

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

REM Initialize database
echo Initializing database...
python init_db.py
if %errorlevel% neq 0 (
    echo Warning: Database initialization failed. Continuing anyway...
)

REM Start the server
echo Starting server...
python main.py

pause