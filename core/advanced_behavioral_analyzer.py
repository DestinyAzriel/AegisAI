#!/usr/bin/env python3
"""
AegisAI Advanced Behavioral Analyzer
Enhanced behavioral analysis with deep learning for real-time threat detection
"""

import os
import json
import logging
import time
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import numpy as np

# Try to import required libraries
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    BEHAVIORAL_ANALYSIS_AVAILABLE = True
except ImportError:
    BEHAVIORAL_ANALYSIS_AVAILABLE = False
    IsolationForest = None
    StandardScaler = None
    DBSCAN = None
    logging.warning("Basic behavioral analysis dependencies not available. Install with: pip install scikit-learn")

# Try to import deep learning libraries
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    from tensorflow.keras.optimizers import Adam
    DEEP_LEARNING_AVAILABLE = True
except ImportError:
    DEEP_LEARNING_AVAILABLE = False
    tf = None
    Sequential = None
    LSTM = None
    Dense = None
    Dropout = None
    Adam = None
    logging.warning("Deep learning dependencies not available. Install with: pip install tensorflow")

logger = logging.getLogger(__name__)

class AdvancedBehavioralAnalyzer:
    """Advanced behavioral analysis engine with deep learning for threat detection"""
    
    def __init__(self):
        """Initialize the advanced behavioral analyzer"""
        # Basic ML components
        if BEHAVIORAL_ANALYSIS_AVAILABLE:
            self.isolation_forest = IsolationForest(
                contamination=0.1,  # Expected proportion of outliers
                random_state=42
            )
            self.dbscan = DBSCAN(eps=0.5, min_samples=5)
            self.scaler = StandardScaler()
        else:
            self.isolation_forest = None
            self.dbscan = None
            self.scaler = None
            
        # Deep learning components
        if DEEP_LEARNING_AVAILABLE:
            self.lstm_model = None
            self.sequence_length = 10  # Number of time steps to consider
        else:
            self.lstm_model = None
            self.sequence_length = 10
            
        self.is_trained = False
        self.baseline_data = []
        self.behavioral_sequence = []  # For LSTM sequence prediction
        
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
    
    def build_lstm_model(self, input_shape: Tuple[int, int]) -> Any:
        """
        Build LSTM model for sequence prediction
        
        Args:
            input_shape: Shape of input data (timesteps, features)
            
        Returns:
            Compiled LSTM model
        """
        if not DEEP_LEARNING_AVAILABLE:
            return None
            
        model = Sequential([
            LSTM(64, return_sequences=True, input_shape=input_shape),
            Dropout(0.2),
            LSTM(32, return_sequences=False),
            Dropout(0.2),
            Dense(16, activation='relu'),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
        return model
    
    def prepare_sequences(self, data: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare sequences for LSTM training
        
        Args:
            data: List of behavioral data samples
            
        Returns:
            Tuple of (X, y) for training
        """
        if len(data) < self.sequence_length:
            raise ValueError(f"Not enough data for sequence length {self.sequence_length}")
        
        # Extract features
        features = []
        for sample in data:
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
        features = np.array(features)
        
        # Create sequences
        X, y = [], []
        for i in range(len(features) - self.sequence_length):
            X.append(features[i:(i + self.sequence_length)])
            # For anomaly detection, we'll use the next value as target
            # In a real implementation, this would be based on labels
            y.append(1 if data[i + self.sequence_length].get('suspicious_activity', 0) > 0 else 0)
        
        return np.array(X), np.array(y)
    
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
    
    def train_models(self, baseline_data: List[Dict]) -> bool:
        """
        Train all behavioral analysis models
        
        Args:
            baseline_data: List of baseline behavioral data
            
        Returns:
            True if training successful, False otherwise
        """
        if not baseline_data:
            logger.error("No baseline data provided for training")
            return False
        
        try:
            # Extract features for traditional ML
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
            if self.isolation_forest:
                self.isolation_forest.fit(X_scaled)
            
            # Train DBSCAN
            if self.dbscan:
                self.dbscan.fit(X_scaled)
            
            # Train LSTM if available
            if DEEP_LEARNING_AVAILABLE and len(baseline_data) > self.sequence_length:
                try:
                    X_seq, y_seq = self.prepare_sequences(baseline_data)
                    if len(X_seq) > 0:
                        self.lstm_model = self.build_lstm_model((X_seq.shape[1], X_seq.shape[2]))
                        if self.lstm_model:
                            self.lstm_model.fit(
                                X_seq, y_seq,
                                epochs=50,
                                batch_size=32,
                                validation_split=0.2,
                                verbose=0
                            )
                            logger.info("LSTM model trained successfully")
                except Exception as e:
                    logger.warning(f"LSTM training failed: {e}")
            
            self.is_trained = True
            self.baseline_data = baseline_data
            logger.info("Advanced behavioral analysis models trained successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to train behavioral analysis models: {e}")
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
        Analyze behavioral data for anomalies using all available methods
        
        Args:
            behavioral_data: Dictionary containing current behavioral metrics
            
        Returns:
            Dictionary with analysis results
        """
        if not self.is_trained:
            # Fallback to rule-based detection
            return self._rule_based_detection(behavioral_data)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'methods': {},
            'is_anomaly': False,
            'confidence': 0.0,
            'rule_violations': []
        }
        
        # Add to sequence for LSTM analysis
        self.behavioral_sequence.append(behavioral_data)
        if len(self.behavioral_sequence) > self.sequence_length:
            self.behavioral_sequence.pop(0)  # Remove oldest
        
        try:
            # Extract features
            features = self.extract_features(behavioral_data)
            
            # Scale features
            features_scaled = self.scaler.transform(features)
            
            # Isolation Forest analysis
            if self.isolation_forest:
                anomaly_prediction = self.isolation_forest.predict(features_scaled)
                anomaly_score = self.isolation_forest.decision_function(features_scaled)
                
                results['methods']['isolation_forest'] = {
                    'is_anomaly': bool(anomaly_prediction[0] == -1),
                    'score': float(anomaly_score[0])
                }
            
            # DBSCAN analysis
            if self.dbscan:
                clusters = self.dbscan.fit_predict(features_scaled)
                is_noise = (clusters == -1)
                
                results['methods']['dbscan'] = {
                    'is_anomaly': bool(is_noise[0]),
                    'cluster': int(clusters[0])
                }
            
            # LSTM sequence analysis
            if self.lstm_model and len(self.behavioral_sequence) == self.sequence_length:
                try:
                    # Prepare sequence for prediction
                    sequence_features = []
                    for sample in self.behavioral_sequence:
                        feature_vector = [
                            sample['file_operations'],
                            sample['network_connections'],
                            sample['cpu_usage'],
                            sample['memory_usage'],
                            sample['child_processes'],
                            sample.get('registry_modifications', 0)
                        ]
                        sequence_features.append(feature_vector)
                    
                    sequence_array = np.array([sequence_features])
                    lstm_prediction = self.lstm_model.predict(sequence_array, verbose=0)
                    
                    results['methods']['lstm'] = {
                        'anomaly_probability': float(lstm_prediction[0][0]),
                        'is_anomaly': bool(lstm_prediction[0][0] > 0.7)
                    }
                except Exception as e:
                    logger.warning(f"LSTM prediction failed: {e}")
            
            # Rule-based additional checks
            rule_violations = self._check_rules(behavioral_data)
            results['rule_violations'] = rule_violations
            
            # Combine all results
            anomaly_scores = []
            
            # Isolation Forest score
            if 'isolation_forest' in results['methods']:
                score = abs(results['methods']['isolation_forest']['score'])
                anomaly_scores.append(score)
            
            # LSTM probability
            if 'lstm' in results['methods']:
                score = results['methods']['lstm']['anomaly_probability']
                anomaly_scores.append(score)
            
            # Rule violations (high confidence if any violations)
            if len(rule_violations) > 0:
                anomaly_scores.append(0.9)
            
            # Determine final result
            results['is_anomaly'] = any([
                results['methods'].get('isolation_forest', {}).get('is_anomaly', False),
                results['methods'].get('dbscan', {}).get('is_anomaly', False),
                results['methods'].get('lstm', {}).get('is_anomaly', False),
                len(rule_violations) > 0
            ])
            
            # Calculate confidence as max of all scores
            results['confidence'] = max(anomaly_scores) if anomaly_scores else 0.0
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            # Fallback to rule-based detection
            return self._rule_based_detection(behavioral_data)
        
        return results
    
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
                'dbscan': self.dbscan is not None,
                'lstm': self.lstm_model is not None
            },
            'baseline_samples': len(self.baseline_data),
            'suspicious_patterns_monitored': len(self.suspicious_patterns),
            'sequence_length': self.sequence_length,
            'last_updated': datetime.now().isoformat()
        }

def main():
    """Demo function to show advanced behavioral analysis in action"""
    print("=" * 70)
    print("           AEGISAI ADVANCED BEHAVIORAL ANALYSIS DEMO")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = AdvancedBehavioralAnalyzer()
    
    # Collect and train on baseline data
    print("Collecting baseline behavioral data...")
    baseline_data = analyzer.collect_baseline_data(2)  # 2 minutes for demo
    
    print("Training advanced behavioral analysis models...")
    success = analyzer.train_models(baseline_data)
    if success:
        print("✅ Advanced behavioral analysis models trained successfully")
    else:
        print("⚠️  Failed to train models")
        return
    
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
    print("ADVANCED BEHAVIORAL ANALYSIS REPORT")
    print("=" * 70)
    report = analyzer.generate_report()
    for key, value in report.items():
        print(f"  {key}: {value}")
    print("=" * 70)

if __name__ == "__main__":
    main()