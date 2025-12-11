#!/usr/bin/env python3
"""
AegisAI Behavioral Analyzer
==========================

This module provides behavioral analysis capabilities for detecting suspicious
file activities and anomalous system behavior.
"""

import os
import json
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib
import math

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BehavioralAnalyzer:
    """Analyzes file behavior to detect suspicious activities"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the behavioral analyzer"""
        self.config = self._load_config(config_path)
        self.rule_violations = []
        self.suspicious_patterns = []
        
        # Load behavioral rules
        self.rules = self._load_behavioral_rules()
        
        logger.info("Behavioral analyzer initialized")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            "behavioral_analysis": {
                "enabled": True,
                "sensitivity": "medium",
                "check_intervals": 60,
                "log_level": "INFO"
            }
        }
        
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'behavioral_config.json')
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            except Exception as e:
                logger.error(f"Error loading behavioral config: {e}")
        
        return default_config
    
    def _load_behavioral_rules(self) -> List[Dict]:
        """Load behavioral analysis rules"""
        # These are example rules - in a real implementation, these would be more comprehensive
        rules = [
            {
                "id": "rapid_file_modification",
                "name": "Rapid File Modification",
                "description": "Detects rapid modification of multiple files",
                "pattern": "file_modification_rate",
                "threshold": 10,  # files per second
                "severity": "high"
            },
            {
                "id": "suspicious_process_creation",
                "name": "Suspicious Process Creation",
                "description": "Detects creation of suspicious processes",
                "pattern": "process_creation",
                "suspicious_processes": [
                    "cmd.exe", "powershell.exe", "wmic.exe", "mshta.exe", 
                    "regsvr32.exe", "rundll32.exe", "msbuild.exe"
                ],
                "severity": "high"
            },
            {
                "id": "registry_modification",
                "name": "Registry Modification",
                "description": "Detects suspicious registry modifications",
                "pattern": "registry_write",
                "suspicious_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
                ],
                "severity": "medium"
            },
            {
                "id": "network_activity",
                "name": "Suspicious Network Activity",
                "description": "Detects suspicious network connections",
                "pattern": "network_connection",
                "suspicious_ports": [4444, 5555, 6666, 7777, 8888, 9999],
                "severity": "high"
            },
            {
                "id": "file_encryption",
                "name": "File Encryption Activity",
                "description": "Detects rapid file encryption (possible ransomware)",
                "pattern": "file_encryption",
                "threshold": 5,  # files per second
                "severity": "critical"
            }
        ]
        
        return rules
    
    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """
        Analyze a file for suspicious behavior patterns
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Dictionary with analysis results
        """
        try:
            # Check if file exists
            if not os.path.exists(filepath):
                return {
                    'is_anomaly': False,
                    'confidence': 0.0,
                    'rule_violations': [],
                    'suspicious_patterns': [],
                    'file_info': {
                        'path': filepath,
                        'exists': False
                    }
                }
            
            # Get file information
            stat = os.stat(filepath)
            file_info = {
                'path': filepath,
                'size': stat.st_size,
                'modified_time': stat.st_mtime,
                'created_time': stat.st_ctime,
                'accessed_time': stat.st_atime
            }
            
            # Calculate file entropy (simplified)
            entropy = self._calculate_entropy(filepath)
            
            # Check for suspicious patterns
            violations = []
            suspicious_patterns = []
            
            # Check file extension for suspicious types
            _, ext = os.path.splitext(filepath)
            suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.com']
            if ext.lower() in suspicious_extensions:
                violations.append({
                    'rule_id': 'suspicious_extension',
                    'rule_name': 'Suspicious File Extension',
                    'description': f'File has suspicious extension: {ext}',
                    'severity': 'medium',
                    'confidence': 0.6
                })
                suspicious_patterns.append(f'suspicious_extension_{ext}')
            
            # Check file size for anomalies
            if stat.st_size > 100 * 1024 * 1024:  # 100MB
                violations.append({
                    'rule_id': 'large_file',
                    'rule_name': 'Large File Size',
                    'description': f'File is unusually large: {stat.st_size} bytes',
                    'severity': 'low',
                    'confidence': 0.3
                })
                suspicious_patterns.append('large_file')
            
            # Check entropy for packed/encrypted files
            if entropy > 7.5:
                violations.append({
                    'rule_id': 'high_entropy',
                    'rule_name': 'High Entropy',
                    'description': f'File has high entropy ({entropy:.2f}), may be packed or encrypted',
                    'severity': 'medium',
                    'confidence': 0.7
                })
                suspicious_patterns.append('high_entropy')
            
            # Determine if this is an anomaly
            is_anomaly = len(violations) > 0
            confidence = sum(violation['confidence'] for violation in violations)
            confidence = min(confidence, 1.0)  # Cap at 1.0
            
            return {
                'is_anomaly': is_anomaly,
                'confidence': confidence,
                'rule_violations': violations,
                'suspicious_patterns': suspicious_patterns,
                'file_info': file_info,
                'entropy': entropy
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {filepath}: {e}")
            return {
                'is_anomaly': False,
                'confidence': 0.0,
                'rule_violations': [],
                'suspicious_patterns': [],
                'error': str(e)
            }
    
    def _calculate_entropy(self, filepath: str) -> float:
        """
        Calculate file entropy (simplified implementation)
        
        Args:
            filepath: Path to the file
            
        Returns:
            Entropy value between 0 and 8
        """
        try:
            # For performance, only analyze first 1KB of large files
            with open(filepath, 'rb') as f:
                data = f.read(1024)
                if not data:
                    return 0.0
            
            # Calculate frequency of each byte
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy using Shannon entropy formula
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return entropy
        except:
            return 0.0
    
    def get_analysis_report(self) -> Dict[str, Any]:
        """
        Get a report of all behavioral analysis findings
        
        Returns:
            Dictionary with analysis report
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'total_violations': len(self.rule_violations),
            'violations': self.rule_violations,
            'suspicious_patterns': self.suspicious_patterns,
            'config': self.config
        }

# Example usage
if __name__ == "__main__":
    # Test the behavioral analyzer
    analyzer = BehavioralAnalyzer()
    
    # Analyze a test file
    test_file = __file__  # Analyze this script
    result = analyzer.analyze_file(test_file)
    
    print("Behavioral Analysis Result:")
    print(json.dumps(result, indent=2))