# AegisAI Sandbox Orchestrator

## Overview

The AegisAI Sandbox Orchestrator provides secure, isolated environments for malware analysis. It enables safe execution and behavioral analysis of suspicious files while protecting the host system.

## Features

- **Secure Isolation**: Uses Docker containers to isolate malware execution
- **Behavioral Analysis**: Monitors process creation, file system changes, network activity, and registry modifications
- **Multi-Platform Support**: Supports Windows and Linux sandbox environments
- **Resource Management**: Enforces CPU, memory, and time limits
- **REST API**: Provides programmatic access for integration with other AegisAI components
- **Automated Cleanup**: Automatically cleans up analysis environments after completion

## Architecture

```
┌─────────────────────────────────────┐
│        AegisAI Cloud Backend        │
├─────────────────────────────────────┤
│                                     │
│  ┌─────────────────────────────┐    │
│  │   Sandbox Orchestrator      │    │
│  │   (This Service)            │    │
│  └─────────────────────────────┘    │
│               │                     │
│               ▼                     │
│  ┌─────────────────────────────┐    │
│  │    Docker Containers        │    │
│  │  ┌─────────────────────┐    │    │
│  │  │   Windows Sandbox   │    │    │
│  │  ├─────────────────────┤    │    │
│  │  │   Linux Sandbox     │    │    │
│  │  └─────────────────────┘    │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

## API Endpoints

### Health Check
- `GET /health` - Check service health

### Analysis
- `POST /analyze` - Submit a file for sandbox analysis
- `GET /results/{analysis_id}` - Retrieve analysis results

## Configuration

The orchestrator can be configured through `config.json`:

```json
{
  "sandbox": {
    "default_timeout": 60,
    "memory_limit": "1g",
    "cpu_limit": "0.5"
  }
}
```

## Requirements

- Docker Engine
- Python 3.8+
- Required Python packages (see requirements.txt)

## Deployment

1. Install Docker Desktop
2. Build the orchestrator image:
   ```bash
   docker build -t aegisai/sandbox-orchestrator:latest .
   ```
3. Run the orchestrator:
   ```bash
   docker run -d -p 8002:8002 \
     -v /var/run/docker.sock:/var/run/docker.sock \
     aegisai/sandbox-orchestrator:latest
   ```

## Usage

### Submitting a File for Analysis

```bash
curl -X POST "http://localhost:8002/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "file_data": "base64_encoded_file_data",
    "file_name": "sample.exe",
    "analysis_timeout": 60
  }'
```

### Retrieving Analysis Results

```bash
curl -X GET "http://localhost:8002/results/{analysis_id}"
```

## Security Considerations

- All analysis environments are isolated using Docker containers
- Resource limits prevent resource exhaustion
- Time limits prevent infinite execution
- Network access can be restricted or monitored
- Containers are automatically cleaned up after analysis

## Integration with AegisAI

The sandbox orchestrator integrates with the AegisAI cloud backend through API calls:

1. When a suspicious file is detected, the backend can submit it for sandbox analysis
2. The orchestrator performs the analysis and returns detailed behavioral data
3. The backend uses this data to improve threat detection models