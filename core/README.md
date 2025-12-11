# AegisAI Core Engine

The AegisAI Core Engine is a comprehensive antivirus and antimalware solution that provides essential protection capabilities for endpoint security.

## Features

- **File Scanning Engine**: Multi-layered scanning with signature-based detection, heuristic analysis, and cloud-assisted scanning
- **Real-Time Protection**: Continuous monitoring of file system events to detect and block threats in real-time
- **Quarantine Management**: Secure isolation of infected files with restoration and deletion capabilities
- **Cross-Platform Support**: Works on Windows, macOS, and Linux
- **Lightweight Design**: Minimal system resource usage for optimal performance
- **Advanced Heuristics**: Entropy analysis, pattern matching, and behavioral analysis
- **Rate Limiting**: Prevents system overload during high file activity
- **Configurable Monitoring**: Customizable directories and file types to monitor

## Components

### File Scanner
The core scanning engine performs multi-layered analysis of files:
- Signature-based detection using hash matching
- Heuristic analysis for suspicious file characteristics
- Cloud-assisted scanning for unknown threats (optional)
- Entropy analysis to detect packed/encrypted files
- Pattern matching for suspicious code patterns

### Real-Time Protection
Monitors file system events to provide immediate threat detection:
- File creation, modification, and move events
- Real-time scanning of accessed files
- Configurable directory monitoring
- Rate limiting to prevent system overload
- Automatic skipping of temporary and system files

### Quarantine Manager
Safely isolates infected files:
- Secure file movement to quarantine directory
- Database tracking of quarantined files
- File restoration and permanent deletion capabilities
- Safe filename encoding to handle special characters

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### As a Module

```python
from core.agent import AegisAICoreAgent

# Create agent instance
agent = AegisAICoreAgent()

# Start real-time protection
agent.start()

# Scan a single file
result = agent.scan_file("/path/to/file")

# Scan a directory
results = agent.scan_directory("/path/to/directory")

# Check agent status
status = agent.get_agent_status()

# Restore a quarantined file
agent.restore_quarantined_file("file_hash")

# Delete a quarantined file
agent.delete_quarantined_file("file_hash")
```

### Command Line

```bash
# Start agent with real-time protection
python -m core.agent

# Scan a single file
python -m core.agent --scan-file /path/to/file

# Scan a directory
python -m core.agent --scan-dir /path/to/directory

# Show agent status
python -m core.agent --status

# List quarantined files
python -m core.agent --list-quarantined

# Restore a quarantined file
python -m core.agent --restore file_hash

# Delete a quarantined file
python -m core.agent --delete file_hash
```

## Configuration

The agent can be configured using a JSON configuration file:

```json
{
    "signature_db_path": "/path/to/signatures.db",
    "quarantine_path": "/path/to/quarantine",
    "watch_directories": [
        "/home/user",
        "/home/user/Downloads",
        "/home/user/Documents",
        "/home/user/Desktop"
    ],
    "cloud_api_url": "https://api.aegisai.com/scan",
    "enable_realtime": true,
    "enable_quarantine": true,
    "log_level": "INFO",
    "scan_timeout": 30
}
```

## Requirements

- Python 3.7 or higher
- watchdog library for file system monitoring

## Testing

Run the test suite to verify functionality:

```bash
python -m core.test_core
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.