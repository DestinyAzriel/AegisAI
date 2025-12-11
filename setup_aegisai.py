#!/usr/bin/env python3
"""
Setup script for AegisAI antivirus deployment
Prepares the system for test environment deployment
"""

import sys
import os
import subprocess
import json
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher is required")
        return False
    print(f"✅ Python version: {sys.version}")
    return True

def install_requirements():
    """Install required packages"""
    print("📦 Installing required packages...")
    
    requirements = [
        "psutil>=5.8.0",
        "watchdog>=2.1.0",
        "cryptography>=3.4.7",
        "requests>=2.25.1",
        "pyyaml>=5.4.1"
    ]
    
    try:
        for package in requirements:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"  ✅ Installed {package}")
        
        print("✅ All required packages installed")
        return True
    except Exception as e:
        print(f"❌ Failed to install packages: {e}")
        return False

def create_startup_script():
    """Create a startup script for easy execution"""
    startup_script = '''@echo off
TITLE AegisAI Antivirus
ECHO ========================================
ECHO AegisAI Advanced Endpoint Protection
ECHO ========================================
ECHO Starting protection...

python "%~dp0run_aegisai.py"

PAUSE
'''
    
    with open('start_aegisai.bat', 'w') as f:
        f.write(startup_script)
    
    print("✅ Startup script created: start_aegisai.bat")

def create_desktop_shortcut_script():
    """Create a script to create desktop shortcut"""
    shortcut_script = '''@echo off
set SCRIPT="%TEMP%\%RANDOM%-%RANDOM%-%RANDOM%-%RANDOM%.vbs"
echo Set oWS = WScript.CreateObject("WScript.Shell") > %SCRIPT%
echo sLinkFile = "%USERPROFILE%\Desktop\AegisAI.lnk" >> %SCRIPT%
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> %SCRIPT%
echo oLink.TargetPath = "%CD%\start_aegisai.bat" >> %SCRIPT%
echo oLink.WorkingDirectory = "%CD%" >> %SCRIPT%
echo oLink.IconLocation = "shell32.dll,13" >> %SCRIPT%
echo oLink.Save >> %SCRIPT%
cscript /nologo %SCRIPT%
del %SCRIPT%
echo Desktop shortcut created successfully!
pause
'''
    
    with open('create_shortcut.bat', 'w') as f:
        f.write(shortcut_script)
    
    print("✅ Desktop shortcut script created: create_shortcut.bat")

def create_config_file():
    """Create default configuration file"""
    config = {
        "scan_settings": {
            "real_time_protection": True,
            "behavioral_analysis": True,
            "ai_detection": True
        },
        "update_settings": {
            "auto_update": True,
            "update_frequency_hours": 24
        },
        "logging": {
            "level": "INFO",
            "file_logging": True,
            "max_log_size_mb": 10
        },
        "paths": {
            "quarantine_directory": "quarantine",
            "signature_database": "signatures.db",
            "log_directory": "logs"
        }
    }
    
    with open('aegisai_config.json', 'w') as f:
        json.dump(config, f, indent=2)
    
    print("✅ Configuration file created: aegisai_config.json")

def create_deployment_readme():
    """Create deployment instructions"""
    readme_content = '''# AegisAI Antivirus - Test Environment Setup

## System Requirements
- Windows 10/11 or Windows Server 2016+
- Python 3.7 or higher
- Minimum 2GB RAM
- Minimum 100MB free disk space

## Installation Steps

1. Ensure Python 3.7+ is installed on the system
2. Run the setup script: python setup_aegisai.py
3. Execute the startup script: start_aegisai.bat
4. (Optional) Run create_shortcut.bat to create desktop shortcut

## Usage

### Command Line Interface
```
python run_aegisai.py --help              # Show help
python run_aegisai.py                     # Start protection
python run_aegisai.py --status            # Check status
python run_aegisai.py --scan-file <file>  # Scan a file
python run_aegisai.py --scan-dir <dir>    # Scan a directory
```

### GUI Method
- Double-click start_aegisai.bat
- Or use the desktop shortcut after running create_shortcut.bat

## Features Enabled
- Real-time file monitoring
- Behavioral analysis
- AI-powered threat detection
- Predictive threat intelligence
- Multi-layered protection

## Support
For issues, contact the development team.
'''
    
    with open('DEPLOYMENT_README.txt', 'w') as f:
        f.write(readme_content)
    
    print("✅ Deployment instructions created: DEPLOYMENT_README.txt")

def setup_test_environment():
    """Setup complete test environment"""
    print("🔧 Setting up AegisAI Test Environment")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install requirements
    if not install_requirements():
        return False
    
    # Create helper scripts
    create_startup_script()
    create_desktop_shortcut_script()
    create_config_file()
    create_deployment_readme()
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    print("✅ Logs directory created")
    
    # Create quarantine directory
    Path("quarantine").mkdir(exist_ok=True)
    print("✅ Quarantine directory created")
    
    print("\n🎉 AegisAI Test Environment Setup Complete!")
    print("\nNext steps:")
    print("1. Run start_aegisai.bat to start protection")
    print("2. Run create_shortcut.bat to create desktop shortcut")
    print("3. Check DEPLOYMENT_README.txt for detailed instructions")
    
    return True

if __name__ == "__main__":
    success = setup_test_environment()
    sys.exit(0 if success else 1)