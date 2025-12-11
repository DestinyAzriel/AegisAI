#!/usr/bin/env python3
"""
AegisAI Enhanced Behavioral Analyzer
Enhanced behavioral analysis for real-time threat detection
"""

import os
import json
import logging
import time
from typing import Dict, List, Any
from datetime import datetime, timedelta
import numpy as np

# Try to import required libraries
SKLEARN_AVAILABLE = False
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    SKLEARN_AVAILABLE = True
except ImportError:
    logging.warning("Behavioral analysis dependencies not available. Install with: pip install scikit-learn")

logger = logging.getLogger(__name__)

class EnhancedBehavioralAnalyzer:
    """Enhanced behavioral analysis engine for threat detection"""
    
    def __init__(self):
        """Initialize the enhanced behavioral analyzer"""
        if SKLEARN_AVAILABLE:
            self.isolation_forest = IsolationForest(
                contamination=0.1,  # Expected proportion of outliers
                random_state=42
            )
            self.dbscan = DBSCAN(eps=0.5, min_samples=5)
            self.scaler = StandardScaler()
            self.is_trained = False
        else:
            self.isolation_forest = None
            self.dbscan = None
            self.scaler = None
            self.is_trained = False
            
        self.baseline_data = []
        
        # Behavioral patterns to monitor
        self.suspicious_patterns = {
            'file_operations': {
                'high_frequency': 50,  # More than 50 file operations per minute
                'sensitive_paths': [
                    'C:\\Windows\\System32\\', 
                    'C:\\Program Files\\', 
                    'AppData\\Local\\Temp\\'
                ]
            },
            'network_activity': {
                'connections_per_minute': 20,
                'suspicious_ports': [4444, 6667, 1337, 31337]
            },
            'process_behavior': {
                'child_processes': 10,  # More than 10 child processes
                'suspicious_names': ['powershell', 'cmd', 'wmic', 'netsh']
            },
            'registry_activity': {
                'modifications_per_minute': 30,
                'sensitive_keys': [
                    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                ]
            }
        }
    
    def collect_baseline_data(self, duration_minutes: int = 10) -> List[Dict]:
        """
        Collect baseline behavioral data (simulated for this demo)
        
        Args:
            duration_minutes: Duration to collect baseline data
            
        Returns:
            List of baseline data samples
        """
        logger.info(f"Collecting baseline behavioral data for {duration_minutes} minutes...")
        
        # Simulate collecting baseline data
        baseline_data = []
        for i in range(duration_minutes * 10):  # 10 samples per minute
            sample = {
                'timestamp': datetime.now().isoformat(),
                'file_operations': np.random.randint(5, 20),
                'network_connections': np.random.randint(2, 8),
                'cpu_usage': np.random.uniform(5.0, 30.0),
                'memory_usage': np.random.uniform(50.0, 200.0),
                'child_processes': np.random.randint(0, 3),
                'registry_modifications': np.random.randint(0, 5),
                'suspicious_activity': 0  # Baseline should be normal
            }
            baseline_data.append(sample)
            time.sleep(0.1)  # Simulate time passing
        
        logger.info(f"Collected {len(baseline_data)} baseline samples")
        return baseline_data
    
    def train_model(self, baseline_data: List[Dict]) -> bool:
        """
        Train the behavioral analysis model
        
        Args:
            baseline_data: List of baseline behavioral data
            
        Returns:
            True if training successful, False otherwise
        """
        if not SKLEARN_AVAILABLE:
            logger.warning("Behavioral analysis not available - skipping training")
            return False
        
        if not baseline_data:
            logger.error("No baseline data provided for training")
            return False
        
        try:
            # Extract features for training
            features = []
            for sample in baseline_data:
                feature_vector = [
                    sample['file_operations'],
                    sample['network_connections'],
                    sample['cpu_usage'],
                    sample['memory_usage'],
                    sample['child_processes'],
                    sample.get('registry_modifications', 0)
                ]
                features.append(feature_vector)
            
            # Convert to numpy array
            X = np.array(features)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train isolation forest
            self.isolation_forest.fit(X_scaled)
            
            # Train DBSCAN
            self.dbscan.fit(X_scaled)
            
            self.is_trained = True
            self.baseline_data = baseline_data
            logger.info("Enhanced behavioral analysis model trained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to train behavioral analysis model: {e}")
            return False
    
    def extract_features(self, behavioral_data: Dict) -> np.ndarray:
        """
        Extract features from behavioral data
        
        Args:
            behavioral_data: Dictionary containing behavioral metrics
            
        Returns:
            Feature vector as numpy array
        """
        feature_vector = [
            behavioral_data.get('file_operations', 0),
            behavioral_data.get('network_connections', 0),
            behavioral_data.get('cpu_usage', 0.0),
            behavioral_data.get('memory_usage', 0.0),
            behavioral_data.get('child_processes', 0),
            behavioral_data.get('registry_modifications', 0)
        ]
        return np.array(feature_vector).reshape(1, -1)
    
    def analyze_behavior(self, behavioral_data: Dict) -> Dict[str, Any]:
        """
        Analyze behavioral data for anomalies using multiple methods
        
        Args:
            behavioral_data: Dictionary containing current behavioral metrics
            
        Returns:
            Dictionary with analysis results
        """
        if not self.is_trained or not SKLEARN_AVAILABLE:
            # Fallback to rule-based detection
            return self._rule_based_detection(behavioral_data)
        
        try:
            # Extract features
            features = self.extract_features(behavioral_data)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Isolation Forest analysis
            anomaly_prediction = self.isolation_forest.predict(features_scaled)
            anomaly_score = self.isolation_forest.decision_function(features_scaled)
            
            # DBSCAN analysis
            clusters = self.dbscan.fit_predict(features_scaled)
            is_noise = (clusters == -1)
            
            # Rule-based additional checks
            rule_violations = self._check_rules(behavioral_data)
            
            # Combine results
            is_anomaly_if = (anomaly_prediction[0] == -1)
            is_anomaly_dbscan = is_noise[0]
            has_rule_violations = len(rule_violations) > 0
            
            # Final decision
            is_anomaly = is_anomaly_if or is_anomaly_dbscan or has_rule_violations
            
            # Confidence calculation
            confidence_scores = []
            if is_anomaly_if:
                confidence_scores.append(abs(anomaly_score[0]))
            if is_anomaly_dbscan:
                confidence_scores.append(0.8)  # High confidence for DBSCAN noise
            if has_rule_violations:
                # Scale confidence by number of violations
                confidence_scores.append(min(len(rule_violations) * 0.3, 1.0))
            
            confidence = max(confidence_scores) if confidence_scores else 0.0
            
            return {
                'is_anomaly': bool(is_anomaly),
                'confidence': float(confidence),
                'methods': {
                    'isolation_forest': {
                        'is_anomaly': bool(is_anomaly_if),
                        'score': float(anomaly_score[0])
                    },
                    'dbscan': {
                        'is_anomaly': bool(is_anomaly_dbscan),
                        'cluster': int(clusters[0])
                    }
                },
                'rule_violations': rule_violations,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            # Fallback to rule-based detection
            return self._rule_based_detection(behavioral_data)
    
    def _rule_based_detection(self, behavioral_data: Dict) -> Dict[str, Any]:
        """
        Rule-based behavioral detection as fallback
        
        Args:
            behavioral_data: Dictionary containing current behavioral metrics
            
        Returns:
            Dictionary with analysis results
        """
        violations = self._check_rules(behavioral_data)
        
        is_anomaly = len(violations) > 0
        confidence = min(len(violations) * 0.3, 1.0)  # Scale confidence by violations
        
        return {
            'is_anomaly': is_anomaly,
            'confidence': confidence,
            'anomaly_score': confidence,
            'rule_violations': violations,
            'timestamp': datetime.now().isoformat(),
            'method': 'rule_based'
        }
    
    def _check_rules(self, behavioral_data: Dict) -> List[str]:
        """
        Check behavioral data against suspicious patterns
        
        Args:
            behavioral_data: Dictionary containing current behavioral metrics
            
        Returns:
            List of rule violations
        """
        violations = []
        
        # Check file operations
        if behavioral_data.get('file_operations', 0) > self.suspicious_patterns['file_operations']['high_frequency']:
            violations.append("High frequency file operations")
        
        # Check network connections
        if behavioral_data.get('network_connections', 0) > self.suspicious_patterns['network_activity']['connections_per_minute']:
            violations.append("High frequency network connections")
        
        # Check child processes
        if behavioral_data.get('child_processes', 0) > self.suspicious_patterns['process_behavior']['child_processes']:
            violations.append("Excessive child process creation")
        
        # Check registry modifications
        if behavioral_data.get('registry_modifications', 0) > self.suspicious_patterns['registry_activity']['modifications_per_minute']:
            violations.append("High frequency registry modifications")
        
        return violations
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate a behavioral analysis report
        
        Returns:
            Dictionary with analysis report
        """
        return {
            'analyzer_status': 'active' if self.is_trained else 'baseline_required',
            'models_trained': {
                'isolation_forest': self.isolation_forest is not None,
                'dbscan': self.dbscan is not None
            },
            'baseline_samples': len(self.baseline_data),
            'suspicious_patterns_monitored': len(self.suspicious_patterns),
            'last_updated': datetime.now().isoformat()
        }

def main():
    """Demo function to show enhanced behavioral analysis in action"""
    print("=" * 70)
    print("           AEGISAI ENHANCED BEHAVIORAL ANALYSIS DEMO")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = EnhancedBehavioralAnalyzer()
    
    # Collect and train on baseline data
    print("Collecting baseline behavioral data...")
    baseline_data = analyzer.collect_baseline_data(2)  # 2 minutes for demo
    
    if SKLEARN_AVAILABLE:
        print("Training enhanced behavioral analysis model...")
        success = analyzer.train_model(baseline_data)
        if success:
            print("✅ Enhanced behavioral analysis model trained successfully")
        else:
            print("⚠️  Failed to train model")
    else:
        print("⚠️  Behavioral analysis dependencies not available")
    
    # Test with normal behavior
    print("\nTesting with normal behavior...")
    normal_behavior = {
        'file_operations': 15,
        'network_connections': 5,
        'cpu_usage': 25.0,
        'memory_usage': 150.0,
        'child_processes': 2,
        'registry_modifications': 3
    }
    
    result = analyzer.analyze_behavior(normal_behavior)
    print(f"Normal behavior analysis: {result}")
    
    # Test with suspicious behavior
    print("\nTesting with suspicious behavior...")
    suspicious_behavior = {
        'file_operations': 150,  # High frequency
        'network_connections': 50,  # Many connections
        'cpu_usage': 85.0,
        'memory_usage': 300.0,
        'child_processes': 15,  # Many child processes
        'registry_modifications': 45  # Many registry changes
    }
    
    result = analyzer.analyze_behavior(suspicious_behavior)
    print(f"Suspicious behavior analysis: {result}")
    
    # Show report
    print("\n" + "=" * 70)
    print("ENHANCED BEHAVIORAL ANALYSIS REPORT")
    print("=" * 70)
    report = analyzer.generate_report()
    for key, value in report.items():
        print(f"  {key}: {value}")
    print("=" * 70)

if __name__ == "__main__":
    main()