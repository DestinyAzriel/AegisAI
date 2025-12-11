# AegisAI Android Agent

The AegisAI Android agent provides comprehensive mobile protection for Android devices, including:

- Real-time file monitoring
- Threat scanning and detection
- Network security monitoring
- Device administration capabilities
- Cloud-based threat intelligence integration

## Features

- **Real-time Protection**: Monitors file system changes and network activity
- **Threat Scanning**: Scans files for malware using cloud-based analysis
- **Device Admin**: Provides enhanced security through device administration permissions
- **Automatic Updates**: Regular updates of threat intelligence database
- **Privacy Focused**: Minimal data collection with strong encryption

## Permissions

The AegisAI Android agent requires the following permissions:

- Device Administrator: For enhanced protection features
- Internet: To communicate with cloud services
- Storage: To scan files on the device
- Network State: To monitor network connections

## Installation

1. Build the APK using Android Studio or Gradle
2. Install the APK on the target device
3. Grant device administrator permissions when prompted
4. Start protection using the app interface

## Architecture

The Android agent consists of several key components:

- `MainActivity`: User interface for controlling the service
- `AegisAIService`: Background service for continuous monitoring
- `FileMonitor`: Monitors file system changes
- `ThreatScanner`: Scans files for threats using cloud analysis
- `NetworkMonitor`: Monitors network connections and blocks malicious domains
- `AegisDeviceAdminReceiver`: Handles device administration features

## API Integration

The agent communicates with the AegisAI cloud backend for:

- Threat intelligence updates
- File analysis
- Security policy enforcement
- Incident reporting