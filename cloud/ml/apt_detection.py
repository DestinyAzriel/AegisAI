#!/usr/bin/env python3
"""
AegisAI Advanced Persistent Threat (APT) Detection Module

This module implements specialized detection capabilities for identifying
Advanced Persistent Threats using behavioral analysis, network traffic analysis,
and advanced machine learning techniques.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
import warnings
import hashlib
import base64
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APTBehavioralAnalyzer:
    """APT behavioral analysis engine for detecting sophisticated threats"""
    
    def __init__(self):
        """Initialize the APT behavioral analyzer"""
        # Models for different APT detection techniques
        self.isolation_forest = IsolationForest(
            contamination=0.1,  # Expected proportion of APT outliers
            random_state=42
        )
        self.dbscan = DBSCAN(eps=0.3, min_samples=3)
        self.apt_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight='balanced'
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.baseline_profiles = {}
        self.apt_patterns = {}
        
        # APT-specific behavioral indicators
        self.apt_indicators = {
            'lateral_movement': ['smb_exec', 'wmi_exec', 'psexec', 'remote_desktop'],
            'persistence': ['registry_run_keys', 'scheduled_tasks', 'services', 'dll_hijacking'],
            'credential_access': ['keyloggers', 'password_dumpers', 'kerberoasting'],
            'defense_evasion': ['process_injection', 'fileless_malware', 'obfuscation'],
            'command_control': ['dns_tunneling', 'http_c2', 'custom_protocols'],
            'exfiltration': ['large_data_transfers', 'unusual_network_patterns', 'steganography']
        }
        
        logger.info("APT behavioral analyzer initialized")
    
    def extract_apt_features(self, process_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract APT-specific behavioral features from process data
        
        Args:
            process_data: Dictionary containing process information
            
        Returns:
            np.ndarray: APT feature vector
        """
        features = []
        
        # Process creation patterns
        features.append(process_data.get('creation_rate', 0))
        features.append(process_data.get('unusual_parent_child', 0))
        features.append(process_data.get('suspicious_spawn_locations', 0))
        
        # CPU and memory usage patterns
        features.append(process_data.get('avg_cpu_usage', 0))
        features.append(process_data.get('max_cpu_usage', 0))
        features.append(process_data.get('avg_memory_usage', 0))
        features.append(process_data.get('max_memory_usage', 0))
        features.append(process_data.get('memory_fluctuation', 0))
        
        # Network activity patterns
        features.append(process_data.get('network_connections', 0))
        features.append(process_data.get('data_transferred', 0))
        features.append(process_data.get('unusual_ports', 0))
        features.append(process_data.get('dns_queries', 0))
        features.append(process_data.get('http_requests', 0))
        features.append(process_data.get('encrypted_traffic', 0))
        
        # File system activity
        features.append(process_data.get('files_accessed', 0))
        features.append(process_data.get('files_created', 0))
        features.append(process_data.get('registry_modifications', 0))
        features.append(process_data.get('suspicious_file_operations', 0))
        
        # Process behavior
        features.append(process_data.get('process_tree_depth', 0))
        features.append(process_data.get('child_processes', 0))
        features.append(process_data.get('process_injection_attempts', 0))
        features.append(process_data.get('privilege_escalation', 0))
        
        # Timing patterns
        features.append(process_data.get('execution_time_anomalies', 0))
        features.append(process_data.get('periodic_activity', 0))
        
        # Persistence mechanisms
        features.append(process_data.get('persistence_attempts', 0))
        
        return np.array(features).reshape(1, -1)
    
    def detect_lateral_movement(self, network_data: Dict[str, Any]) -> bool:
        """
        Detect signs of lateral movement
        
        Args:
            network_data: Network activity data
            
        Returns:
            bool: True if lateral movement detected
        """
        suspicious_protocols = ['smb', 'wmi', 'dcom', 'winrm']
        suspicious_ports = [135, 139, 445, 5985, 5986]
        
        protocol = network_data.get('protocol', '').lower()
        port = network_data.get('port', 0)
        
        return (protocol in suspicious_protocols) or (port in suspicious_ports)
    
    def detect_persistence(self, registry_data: Dict[str, Any]) -> bool:
        """
        Detect persistence mechanisms
        
        Args:
            registry_data: Registry modification data
            
        Returns:
            bool: True if persistence mechanism detected
        """
        persistence_keys = [
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'SYSTEM\\CurrentControlSet\\Services',
            'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
        ]
        
        key = registry_data.get('key', '')
        return any(p_key in key for p_key in persistence_keys)
    
    def detect_credential_access(self, process_data: Dict[str, Any]) -> bool:
        """
        Detect credential access attempts
        
        Args:
            process_data: Process data
            
        Returns:
            bool: True if credential access detected
        """
        suspicious_processes = ['mimikatz', 'lsass.exe', 'samdump2', 'john']
        process_name = process_data.get('process_name', '').lower()
        
        return any(suspicious in process_name for suspicious in suspicious_processes)
    
    def create_apt_baseline(self, agent_id: str, features: np.ndarray, labels: Optional[np.ndarray] = None):
        """
        Create a baseline APT behavioral profile for an agent
        
        Args:
            agent_id: Unique identifier for the agent
            features: Feature vectors for baseline
            labels: Labels for supervised learning (optional)
        """
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        # Train unsupervised models
        self.isolation_forest.fit(scaled_features)
        self.dbscan.fit(scaled_features)
        
        # Train supervised classifier if labels provided
        if labels is not None:
            self.apt_classifier.fit(scaled_features, labels)
            self.is_trained = True
        
        # Store baseline profile
        self.baseline_profiles[agent_id] = {
            'scaler': self.scaler,
            'features': scaled_features,
            'timestamp': datetime.now()
        }
        
        logger.info(f"APT baseline profile created for agent {agent_id}")
    
    def detect_apt_behavior(self, agent_id: str, features: np.ndarray) -> Dict[str, Any]:
        """
        Detect APT behavioral patterns
        
        Args:
            agent_id: Unique identifier for the agent
            features: Feature vectors to analyze
            
        Returns:
            Dict containing APT detection results
        """
        if not self.is_trained and agent_id not in self.baseline_profiles:
            logger.warning("APT analyzer not trained yet")
            return {
                'apt_score': 0.0, 
                'is_apt': False, 
                'confidence': 0.0,
                'techniques': []
            }
        
        # Scale features using baseline scaler
        if agent_id in self.baseline_profiles:
            scaler = self.baseline_profiles[agent_id]['scaler']
            scaled_features = scaler.transform(features)
        else:
            scaled_features = self.scaler.transform(features)
        
        # Isolation Forest detection
        anomaly_scores_if = self.isolation_forest.decision_function(scaled_features)
        predictions_if = self.isolation_forest.predict(scaled_features)
        
        # DBSCAN detection
        clusters = self.dbscan.fit_predict(scaled_features)
        is_noise = (clusters == -1)
        
        # Supervised classification if trained
        supervised_score = 0.0
        if self.is_trained:
            supervised_prob = self.apt_classifier.predict_proba(scaled_features)[0]
            supervised_score = supervised_prob[1] if len(supervised_prob) > 1 else 0.0
        
        # Combine results
        anomaly_score = -anomaly_scores_if[0]  # Convert to positive score
        is_anomaly_if = (predictions_if[0] == -1)
        is_anomaly_dbscan = is_noise[0]
        
        # Calculate final APT score
        apt_score = (
            abs(anomaly_score) * 0.4 +  # Anomaly detection weight
            (1.0 if is_anomaly_if else 0.0) * 0.3 +  # Isolation Forest weight
            (1.0 if is_anomaly_dbscan else 0.0) * 0.2 +  # DBSCAN weight
            supervised_score * 0.1  # Supervised classification weight
        )
        
        # Determine if APT behavior detected
        is_apt = apt_score > 0.6
        confidence = min(apt_score * 1.5, 1.0)  # Normalize confidence
        
        # Identify specific APT techniques
        techniques = self.identify_apt_techniques(features)
        
        return {
            'apt_score': float(apt_score),
            'is_apt': bool(is_apt),
            'confidence': float(confidence),
            'techniques': techniques,
            'methods': {
                'isolation_forest': {
                    'score': float(anomaly_scores_if[0]),
                    'is_anomaly': bool(is_anomaly_if)
                },
                'dbscan': {
                    'is_anomaly': bool(is_anomaly_dbscan)
                },
                'supervised': {
                    'score': float(supervised_score)
                }
            }
        }
    
    def identify_apt_techniques(self, features: np.ndarray) -> List[str]:
        """
        Identify specific APT techniques based on features
        
        Args:
            features: Feature vector
            
        Returns:
            List of detected APT techniques
        """
        techniques = []
        feature_values = features.flatten()
        
        # Map features to techniques (simplified for demonstration)
        if len(feature_values) > 10:
            # High network activity might indicate C2 or exfiltration
            if feature_values[8] > 50:  # network_connections
                techniques.append('command_and_control')
                techniques.append('exfiltration')
            
            # Unusual parent-child relationships might indicate process injection
            if feature_values[1] > 0.5:  # unusual_parent_child
                techniques.append('process_injection')
                techniques.append('defense_evasion')
            
            # Registry modifications might indicate persistence
            if feature_values[12] > 5:  # registry_modifications
                techniques.append('persistence')
            
            # Process injection attempts
            if feature_values[15] > 0.5:  # process_injection_attempts
                techniques.append('process_injection')
                techniques.append('defense_evasion')
            
            # Privilege escalation
            if feature_values[16] > 0.5:  # privilege_escalation
                techniques.append('privilege_escalation')
        
        return list(set(techniques))  # Remove duplicates

class NetworkTrafficAnalyzer:
    """Analyze network traffic for APT indicators"""
    
    def __init__(self):
        """Initialize the network traffic analyzer"""
        self.suspicious_patterns = {
            'dns_tunneling': r'[a-zA-Z0-9]{32,}\.domain\.com',  # Long subdomains
            'http_c2': r'(POST|GET) /.*\.(php|asp|jsp)\?id=[a-zA-Z0-9]{16,}',  # C2 patterns
            'data_exfiltration': r'(PUT|POST) /upload.*Content-Length: [0-9]{7,}'  # Large uploads
        }
        self.baseline_traffic = {}
        
        logger.info("Network traffic analyzer initialized")
    
    def analyze_dns_traffic(self, dns_queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze DNS traffic for tunneling and other APT techniques
        
        Args:
            dns_queries: List of DNS query data
            
        Returns:
            Dict containing DNS analysis results
        """
        suspicious_queries = []
        total_queries = len(dns_queries)
        
        for query in dns_queries:
            domain = query.get('domain', '')
            # Check for long subdomains (potential DNS tunneling)
            subdomain = domain.split('.')[0] if '.' in domain else domain
            if len(subdomain) > 32:
                suspicious_queries.append(query)
        
        tunneling_score = len(suspicious_queries) / max(total_queries, 1)
        
        return {
            'tunneling_detected': tunneling_score > 0.1,
            'tunneling_score': tunneling_score,
            'suspicious_queries': suspicious_queries,
            'total_queries': total_queries
        }
    
    def analyze_http_traffic(self, http_requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze HTTP traffic for C2 communication
        
        Args:
            http_requests: List of HTTP request data
            
        Returns:
            Dict containing HTTP analysis results
        """
        suspicious_requests = []
        total_requests = len(http_requests)
        
        for request in http_requests:
            url = request.get('url', '')
            method = request.get('method', '')
            user_agent = request.get('user_agent', '')
            
            # Check for suspicious patterns
            if 'php?id=' in url or 'asp?id=' in url or 'jsp?id=' in url:
                if len(url.split('id=')[1]) > 16:  # Long ID parameter
                    suspicious_requests.append(request)
        
        c2_score = len(suspicious_requests) / max(total_requests, 1)
        
        return {
            'c2_detected': c2_score > 0.05,
            'c2_score': c2_score,
            'suspicious_requests': suspicious_requests,
            'total_requests': total_requests
        }
    
    def detect_data_exfiltration(self, network_flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detect potential data exfiltration
        
        Args:
            network_flows: List of network flow data
            
        Returns:
            Dict containing exfiltration detection results
        """
        large_transfers = []
        total_flows = len(network_flows)
        total_data = 0
        
        for flow in network_flows:
            data_size = flow.get('data_size', 0)
            total_data += data_size
            
            # Flag large transfers
            if data_size > 10000000:  # 10MB
                large_transfers.append(flow)
        
        avg_data_size = total_data / max(total_flows, 1)
        exfil_score = len(large_transfers) / max(total_flows, 1)
        
        return {
            'exfiltration_detected': exfil_score > 0.02,
            'exfiltration_score': exfil_score,
            'large_transfers': large_transfers,
            'average_data_size': avg_data_size,
            'total_data': total_data
        }

class APTDetectionEngine:
    """Main APT detection engine that combines all detection methods"""
    
    def __init__(self):
        """Initialize the APT detection engine"""
        self.behavioral_analyzer = APTBehavioralAnalyzer()
        self.network_analyzer = NetworkTrafficAnalyzer()
        self.threat_intel = {}
        self.detection_history = {}
        
        logger.info("APT detection engine initialized")
    
    def analyze_endpoint(self, agent_id: str, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive APT analysis on endpoint data
        
        Args:
            agent_id: Unique identifier for the agent
            endpoint_data: Comprehensive endpoint data
            
        Returns:
            Dict containing APT analysis results
        """
        results = {
            'agent_id': agent_id,
            'timestamp': datetime.now().isoformat(),
            'apt_detected': False,
            'overall_score': 0.0,
            'confidence': 0.0,
            'techniques': [],
            'evidence': []
        }
        
        # Behavioral analysis
        process_data = endpoint_data.get('processes', [])
        if process_data:
            # Extract features from process data
            features = self.behavioral_analyzer.extract_apt_features(process_data[0] if process_data else {})
            behavioral_result = self.behavioral_analyzer.detect_apt_behavior(agent_id, features)
            
            results['behavioral_analysis'] = behavioral_result
            if behavioral_result['is_apt']:
                results['apt_detected'] = True
                results['overall_score'] += behavioral_result['apt_score'] * 0.5
                results['confidence'] = max(results['confidence'], behavioral_result['confidence'])
                results['techniques'].extend(behavioral_result['techniques'])
                results['evidence'].append({
                    'type': 'behavioral',
                    'score': behavioral_result['apt_score'],
                    'details': behavioral_result
                })
        
        # Network analysis
        network_data = endpoint_data.get('network', {})
        if network_data:
            # DNS analysis
            dns_queries = network_data.get('dns_queries', [])
            dns_result = self.network_analyzer.analyze_dns_traffic(dns_queries)
            
            # HTTP analysis
            http_requests = network_data.get('http_requests', [])
            http_result = self.network_analyzer.analyze_http_traffic(http_requests)
            
            # Exfiltration detection
            network_flows = network_data.get('flows', [])
            exfil_result = self.network_analyzer.detect_data_exfiltration(network_flows)
            
            network_results = {
                'dns_analysis': dns_result,
                'http_analysis': http_result,
                'exfiltration_detection': exfil_result
            }
            
            results['network_analysis'] = network_results
            
            # Check for network-based APT indicators
            network_score = (
                dns_result['tunneling_score'] * 0.4 +
                http_result['c2_score'] * 0.4 +
                exfil_result['exfiltration_score'] * 0.2
            )
            
            if network_score > 0.3:
                results['apt_detected'] = True
                results['overall_score'] += network_score * 0.3
                results['confidence'] = max(results['confidence'], network_score)
                results['evidence'].append({
                    'type': 'network',
                    'score': network_score,
                    'details': network_results
                })
        
        # Threat intelligence correlation
        threat_intel_result = self.correlate_threat_intel(endpoint_data)
        if threat_intel_result['matched_indicators']:
            results['apt_detected'] = True
            results['overall_score'] += threat_intel_result['confidence'] * 0.2
            results['confidence'] = max(results['confidence'], threat_intel_result['confidence'])
            results['evidence'].append({
                'type': 'threat_intel',
                'score': threat_intel_result['confidence'],
                'details': threat_intel_result
            })
        
        # Normalize overall score
        results['overall_score'] = min(results['overall_score'], 1.0)
        
        # Store detection history
        if agent_id not in self.detection_history:
            self.detection_history[agent_id] = []
        self.detection_history[agent_id].append(results)
        
        # Keep only recent history
        if len(self.detection_history[agent_id]) > 100:
            self.detection_history[agent_id] = self.detection_history[agent_id][-50:]
        
        return results
    
    def correlate_threat_intel(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlate endpoint data with threat intelligence
        
        Args:
            endpoint_data: Endpoint data to correlate
            
        Returns:
            Dict containing threat intelligence correlation results
        """
        matched_indicators = []
        total_indicators = len(self.threat_intel)
        
        # Check for known malicious hashes
        file_hashes = endpoint_data.get('file_hashes', [])
        for file_hash in file_hashes:
            if file_hash in self.threat_intel.get('malicious_hashes', []):
                matched_indicators.append({
                    'type': 'malicious_hash',
                    'value': file_hash,
                    'threat_actor': self.threat_intel['malicious_hashes'][file_hash]
                })
        
        # Check for known C2 domains
        network_data = endpoint_data.get('network', {})
        dns_queries = network_data.get('dns_queries', [])
        for query in dns_queries:
            domain = query.get('domain', '')
            if domain in self.threat_intel.get('c2_domains', []):
                matched_indicators.append({
                    'type': 'c2_domain',
                    'value': domain,
                    'threat_actor': self.threat_intel['c2_domains'][domain]
                })
        
        # Check for known malicious IPs
        ip_addresses = network_data.get('ip_addresses', [])
        for ip in ip_addresses:
            if ip in self.threat_intel.get('malicious_ips', []):
                matched_indicators.append({
                    'type': 'malicious_ip',
                    'value': ip,
                    'threat_actor': self.threat_intel['malicious_ips'][ip]
                })
        
        confidence = len(matched_indicators) / max(total_indicators, 1) if total_indicators > 0 else 0.0
        
        return {
            'matched_indicators': matched_indicators,
            'confidence': confidence,
            'total_matches': len(matched_indicators)
        }
    
    def update_threat_intel(self, threat_intel: Dict[str, Any]):
        """
        Update threat intelligence feeds
        
        Args:
            threat_intel: New threat intelligence data
        """
        self.threat_intel.update(threat_intel)
        logger.info("Threat intelligence updated")
    
    def generate_apt_report(self, agent_id: str, time_range_hours: int = 24) -> Dict[str, Any]:
        """
        Generate APT analysis report for an agent
        
        Args:
            agent_id: Unique identifier for the agent
            time_range_hours: Time range for analysis in hours
            
        Returns:
            Dict containing APT analysis report
        """
        if agent_id not in self.detection_history:
            return {'agent_id': agent_id, 'detections': [], 'summary': 'No APT detections'}
        
        # Filter detections by time range
        cutoff_time = datetime.now() - timedelta(hours=time_range_hours)
        recent_detections = [
            detection for detection in self.detection_history[agent_id]
            if datetime.fromisoformat(detection['timestamp'].replace('Z', '+00:00')) > cutoff_time
        ]
        
        # Summarize findings
        apt_detections = [d for d in recent_detections if d['apt_detected']]
        total_detections = len(apt_detections)
        
        # Aggregate techniques
        all_techniques = []
        for detection in apt_detections:
            all_techniques.extend(detection.get('techniques', []))
        
        technique_counts = {}
        for technique in all_techniques:
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        return {
            'agent_id': agent_id,
            'time_range_hours': time_range_hours,
            'total_detections': total_detections,
            'detections': apt_detections,
            'technique_analysis': technique_counts,
            'risk_level': 'high' if total_detections > 3 else 'medium' if total_detections > 0 else 'low',
            'recommendations': self.generate_recommendations(apt_detections)
        }
    
    def generate_recommendations(self, apt_detections: List[Dict[str, Any]]) -> List[str]:
        """
        Generate security recommendations based on APT detections
        
        Args:
            apt_detections: List of APT detections
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        if not apt_detections:
            return ["No APT activity detected. Continue monitoring."]
        
        # Analyze common techniques
        techniques = []
        for detection in apt_detections:
            techniques.extend(detection.get('techniques', []))
        
        unique_techniques = list(set(techniques))
        
        if 'command_and_control' in unique_techniques:
            recommendations.append("Investigate network connections for C2 communication")
            recommendations.append("Implement network segmentation to limit lateral movement")
        
        if 'persistence' in unique_techniques:
            recommendations.append("Review startup programs and scheduled tasks")
            recommendations.append("Audit registry modifications for unauthorized persistence")
        
        if 'credential_access' in unique_techniques:
            recommendations.append("Implement multi-factor authentication")
            recommendations.append("Monitor for credential dumping tools")
        
        if 'exfiltration' in unique_techniques:
            recommendations.append("Implement data loss prevention (DLP) controls")
            recommendations.append("Monitor for large data transfers")
        
        # General recommendations
        recommendations.append("Conduct thorough forensic analysis of affected systems")
        recommendations.append("Review and update security policies")
        recommendations.append("Enhance user security awareness training")
        
        return recommendations

# Example usage and testing
if __name__ == "__main__":
    # Create APT detection engine
    apt_engine = APTDetectionEngine()
    
    # Simulate endpoint data
    endpoint_data = {
        'agent_id': 'test-agent-001',
        'processes': [
            {
                'process_id': '12345',
                'creation_rate': 2.5,
                'unusual_parent_child': 1,
                'suspicious_spawn_locations': 0,
                'avg_cpu_usage': 15.5,
                'max_cpu_usage': 85.2,
                'avg_memory_usage': 145.3,
                'max_memory_usage': 289.1,
                'memory_fluctuation': 0.3,
                'network_connections': 52,
                'data_transferred': 102400,
                'unusual_ports': 2,
                'dns_queries': 15,
                'http_requests': 8,
                'encrypted_traffic': 1,
                'files_accessed': 15,
                'files_created': 3,
                'registry_modifications': 8,
                'suspicious_file_operations': 2,
                'process_tree_depth': 5,
                'child_processes': 3,
                'process_injection_attempts': 1,
                'privilege_escalation': 0,
                'execution_time_anomalies': 1,
                'periodic_activity': 1,
                'persistence_attempts': 1
            }
        ],
        'network': {
            'dns_queries': [
                {'domain': 'normal-domain.com', 'timestamp': '2023-01-01T12:00:00Z'},
                {'domain': 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.domain.com', 'timestamp': '2023-01-01T12:05:00Z'}
            ],
            'http_requests': [
                {'url': '/normal-page.html', 'method': 'GET', 'user_agent': 'Mozilla/5.0'},
                {'url': '/malware.php?id=a1b2c3d4e5f6g7h8i9j0', 'method': 'POST', 'user_agent': 'Custom-Agent'}
            ],
            'flows': [
                {'data_size': 512, 'destination': '192.168.1.100'},
                {'data_size': 50000000, 'destination': '104.16.123.45'}  # 50MB transfer
            ],
            'ip_addresses': ['192.168.1.100', '104.16.123.45']
        },
        'file_hashes': ['eicar_test_file_hash']
    }
    
    # Update threat intelligence
    apt_engine.update_threat_intel({
        'malicious_hashes': {
            'eicar_test_file_hash': 'TestMalware'
        },
        'c2_domains': {
            'malicious-c2.com': 'APTGroup1'
        },
        'malicious_ips': {
            '104.16.123.45': 'KnownBadIP'
        }
    })
    
    # Analyze endpoint for APT activity
    print("Analyzing endpoint for APT activity...")
    result = apt_engine.analyze_endpoint('test-agent-001', endpoint_data)
    print(f"APT Analysis Result: {json.dumps(result, indent=2)}")
    
    # Generate APT report
    print("\nGenerating APT report...")
    report = apt_engine.generate_apt_report('test-agent-001')
    print(f"APT Report: {json.dumps(report, indent=2)}")