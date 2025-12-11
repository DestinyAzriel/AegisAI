# AegisAI Web Protection System

## Overview

AegisAI provides comprehensive web protection that goes beyond traditional antivirus capabilities. The system automatically deals with viruses, malware, trojans, and other threats while providing ad blocking for clean browsing.

## Key Features

### 1. Automatic Threat Handling
- **Real-time Detection**: Multi-layered scanning using YARA rules, behavioral analysis, and predictive intelligence
- **Automatic Quarantine**: High-confidence threats (confidence ≥70%) are automatically moved to secure quarantine
- **Threat Reporting**: Detailed analysis with confidence levels and detection methods
- **System-wide Protection**: Monitors all file system changes in real-time

### 2. Web Protection & Ad Blocking
- **DNS-level Blocking**: Intercepts DNS queries and blocks ads, tracking, and malware domains
- **HTTP Proxy Filtering**: Filters web traffic to block ads and malicious content
- **Browser Integration**: Works with all browsers by configuring system DNS or proxy settings
- **Comprehensive Domain Lists**: Blocks thousands of known ad, tracking, and malware domains

### 3. Multi-layered Security Approach
- **File System Monitoring**: Real-time monitoring of C:\ and D:\ drives
- **Signature-based Detection**: YARA pattern matching for known threats
- **Behavioral Analysis**: Detects suspicious file activities and patterns
- **Predictive Intelligence**: AI-powered threat prediction and analysis
- **Network-level Protection**: DNS and HTTP filtering for web threats

## How It Works

### Threat Detection & Handling
1. **File Monitoring**: The system monitors all file system changes in real-time
2. **Multi-layered Scanning**: Each file is scanned using:
   - Agent-based analysis
   - YARA signature matching
   - Behavioral pattern detection
   - Predictive threat intelligence
3. **Confidence Calculation**: System calculates threat confidence level (0-100%)
4. **Automatic Response**:
   - Confidence ≥90%: MALICIOUS - Automatically quarantined
   - Confidence ≥70%: SUSPICIOUS - Automatically quarantined
   - Confidence ≥50%: POTENTIALLY_UNWANTED - Flagged for review
5. **Quarantine Process**: 
   - Files moved to secure quarantine directory
   - Original file paths preserved
   - Files encrypted to prevent execution
   - Detailed logs maintained

### Web Protection & Ad Blocking
1. **DNS Blocking**: 
   - Runs DNS server on localhost:53
   - Intercepts all DNS queries
   - Blocks known ad/tracking/malware domains with NXDOMAIN responses
2. **HTTP Proxy**:
   - Runs HTTP proxy on localhost:8080
   - Filters HTTP traffic for ads and malicious content
   - Blocks requests to known malicious URLs
3. **Browser Integration**:
   - Set system DNS to 127.0.0.1 for DNS-level blocking
   - Configure browser proxy to 127.0.0.1:8080 for HTTP filtering
   - Works with Chrome, Firefox, Edge, Safari, etc.

## Usage Instructions

### Running the Full Protection System

```bash
# Navigate to AegisAI directory
cd d:\AegisAI

# Run the real-time protection system
python realtime_aegisai.py
```

This command starts:
- File system monitoring on C:\ and D:\ drives
- DNS blocking server on 127.0.0.1:53
- HTTP proxy server on 127.0.0.1:8080
- Windows agent with WFP filtering (if available)

### Enabling Browser Ad Blocking

1. **DNS-level Blocking** (Recommended):
   - Open Network Settings
   - Change DNS servers to: 127.0.0.1
   - This blocks ads system-wide for all applications

2. **HTTP Proxy Blocking**:
   - Open Browser Settings
   - Navigate to Proxy Settings
   - Set HTTP proxy to: 127.0.0.1:8080
   - This provides additional filtering for HTTP content

### Testing the System

```bash
# Test web protection functionality
python test_web_protection.py

# Test automatic quarantine
python test_automatic_quarantine.py

# Demo all protection features
python demo_web_protection.py
```

## Technical Implementation

### Core Components

1. **WebProtectionEngine** (`core/web_protection.py`):
   - Manages domain, IP, URL, and content filtering
   - Contains extensive lists of known ad, tracking, and malware domains
   - Provides real-time checking of domains and URLs

2. **DNSBlockingServer** (`core/dns_blocking.py`):
   - DNS server that intercepts queries
   - Returns NXDOMAIN for blocked domains
   - More effective than redirecting to localhost

3. **HTTPProxyServer** (`core/http_proxy.py`):
   - HTTP proxy that filters web traffic
   - Blocks requests to known malicious URLs
   - Filters content for ads and tracking elements

4. **QuarantineManager** (`core/quarantine.py`):
   - Securely moves threats to quarantine
   - Maintains encrypted quarantine database
   - Preserves original file metadata

5. **RealTimeAegisAIHandler** (`realtime_aegisai.py`):
   - Main real-time protection coordinator
   - Integrates all protection components
   - Handles threat reporting and automatic quarantine

### Domain Blocking Categories

The system blocks domains in these categories:
- **Ads**: Banner ads, popups, video ads, etc.
- **Tracking**: Analytics, user behavior tracking, pixels
- **Malware**: Known malicious domains and download sites
- **Social Media**: Optional blocking (disabled by default)
- **Cryptominers**: Coinhive and similar mining services

## System Requirements

- **Operating System**: Windows 10/11 (64-bit)
- **Python**: 3.8 or higher
- **Dependencies**: 
  - `watchdog` for file system monitoring
  - `dnspython` for DNS blocking
  - `requests` for HTTP proxy
- **Permissions**: Administrator rights for full protection

## Troubleshooting

### Ads Still Appearing

1. **Verify DNS Settings**:
   - Ensure system DNS is set to 127.0.0.1
   - Flush DNS cache: `ipconfig /flushdns`

2. **Check HTTP Proxy**:
   - Verify browser proxy settings
   - Ensure proxy server is running

3. **Restart Protection**:
   - Stop and restart `realtime_aegisai.py`

### Threats Not Being Quarantined

1. **Check Confidence Levels**:
   - Only threats with confidence ≥70% are auto-quarantined
   - Lower confidence threats are flagged for review

2. **Verify Quarantine Directory**:
   - Check `C:\ProgramData\AegisAI\Quarantine` for quarantined files
   - Ensure directory has proper permissions

## Customization

### Adding Custom Domains to Block

Edit the domain lists in `core/web_protection.py`:
- Add domains to `ad_domains`, `tracking_domains`, or `malware_domains` lists
- Or create custom filter rules using the `WebFilterRule` class

### Adjusting Quarantine Thresholds

Modify the confidence thresholds in `realtime_aegisai.py`:
- Change the values in the `report_threat` method
- Adjust automatic quarantine behavior

## Security Notes

- Quarantined files are encrypted and cannot execute
- All actions are logged for forensic analysis
- System provides detailed threat reports for security teams
- Protection can be temporarily disabled for trusted operations