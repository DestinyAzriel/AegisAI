# AegisAI Antivirus - Test Environment Setup

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
