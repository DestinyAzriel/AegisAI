#!/usr/bin/env python3
"""
AegisAI Robust Behavioral Analyzer
Behavioral analysis that works with or without ML dependencies
"""

import os
import json
import logging
import time
from typing import Dict, List, Any, Optional
from datetime import datetime
import numpy as np

# Try to import required libraries
SKLEARN_AVAILABLE = False
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    SKLEARN_AVAILABLE = True
except ImportError:
    logging.warning("Scikit-learn not available. Behavioral analysis will use rule-based detection only.")

# Try to import deep learning libraries
TF_AVAILABLE = False
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    TF_AVAILABLE = True
except ImportError:
    logging.warning("TensorFlow not available. LSTM-based behavioral analysis disabled.")

logger = logging.getLogger(__name__)

class RobustBehavioralAnalyzer:
    """Robust behavioral analysis engine that works with or without ML dependencies"""
    
    def __init__(self):
        """Initialize the robust behavioral analyzer"""
        # Initialize ML components only if available
        self.isolation_forest: Optional[IsolationForest] = None
        self.dbscan: Optional[DBSCAN] = None
        self.scaler: Optional[StandardScaler] = None
        self.lstm_model: Optional[Any] = None
        
        if SKLEARN_AVAILABLE:
            try:
                self.isolation_forest = IsolationForest(
                    contamination="auto",  # type: ignore
                    random_state=42
                )
                self.dbscan = DBSCAN(eps=0.5, min_samples=5)
                self.scaler = StandardScaler()
            except Exception as e:
                logger.warning(f"Failed to initialize scikit-learn components: {e}")
        
        if TF_AVAILABLE:
            try:
                # LSTM model will be built during training
                self.sequence_length = 10
            except Exception as e:
                logger.warning(f"Failed to initialize TensorFlow components: {e}")
                self.lstm_model = None
        
        self.is_trained = False
        self.baseline_data = []
        self.behavioral_sequence = []
        
        # Behavioral patterns to monitor
        self.suspicious_patterns = {
            'file_operations': {
                'high_frequency': 50,
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
                'child_processes': 10,
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
    
    def build_lstm_model(self, input_shape: tuple) -> Optional[Any]:
        """
        Build LSTM model for sequence prediction
        
        Args:
            input_shape: Shape of input data (timesteps, features)
            
        Returns:
            Compiled LSTM model or None if TensorFlow not available
        """
        if not TF_AVAILABLE:
            return None
        
        try:
            model = Sequential([
                LSTM(64, return_sequences=True, input_shape=input_shape),
                Dropout(0.2),
                LSTM(32, return_sequences=False),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            return model
        except Exception as e:
            logger.error(f"Failed to build LSTM model: {e}")
            return None
    
    def collect_baseline_data(self, duration_minutes: int = 5) -> List[Dict]:
        """
        Collect baseline behavioral data (simulated)
        
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
            
            # Scale features if scaler is available
            if self.scaler and SKLEARN_AVAILABLE:
                X_scaled = self.scaler.fit_transform(X)
            else:
                X_scaled = X
            
            # Train isolation forest if available
            if self.isolation_forest and SKLEARN_AVAILABLE:
                self.isolation_forest.fit(X_scaled)
            
            # Train DBSCAN if available
            if self.dbscan and SKLEARN_AVAILABLE:
                self.dbscan.fit(X_scaled)
            
            # Train LSTM if available
            if TF_AVAILABLE and len(baseline_data) > self.sequence_length:
                try:
                    # Prepare sequences
                    if len(baseline_data) >= self.sequence_length:
                        sequence_features = []
                        targets = []
                        for i in range(len(baseline_data) - self.sequence_length):
                            seq = []
                            for j in range(self.sequence_length):
                                sample = baseline_data[i + j]
                                feature_vector = [
                                    sample['file_operations'],
                                    sample['network_connections'],
                                    sample['cpu_usage'],
                                    sample['memory_usage'],
                                    sample['child_processes'],
                                    sample.get('registry_modifications', 0)
                                ]
                                seq.append(feature_vector)
                            sequence_features.append(seq)
                            # Target is suspicious activity of next sample
                            targets.append(baseline_data[i + self.sequence_length].get('suspicious_activity', 0))
                        
                        if sequence_features:
                            X_seq = np.array(sequence_features)
                            y_seq = np.array(targets)
                            
                            self.lstm_model = self.build_lstm_model((X_seq.shape[1], X_seq.shape[2]))
                            if self.lstm_model:
                                self.lstm_model.fit(
                                    X_seq, y_seq,
                                    epochs=20,
                                    batch_size=16,
                                    validation_split=0.2,
                                    verbose=0
                                )
                                logger.info("LSTM model trained successfully")
                except Exception as e:
                    logger.warning(f"LSTM training failed: {e}")
            
            self.is_trained = True
            self.baseline_data = baseline_data
            logger.info("Behavioral analysis model trained successfully")
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
        Analyze behavioral data for anomalies using available methods
        
        Args:
            behavioral_data: Dictionary containing current behavioral metrics
            
        Returns:
            Dictionary with analysis results
        """
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
            self.behavioral_sequence.pop(0)
        
        # Rule-based detection (always available)
        rule_violations = self._check_rules(behavioral_data)
        results['rule_violations'] = rule_violations
        
        # ML-based detection (if available)
        if self.is_trained and (SKLEARN_AVAILABLE or TF_AVAILABLE):
            try:
                # Extract features
                features = self.extract_features(behavioral_data)
                
                # Scale features if scaler is available
                if self.scaler and SKLEARN_AVAILABLE:
                    features_scaled = self.scaler.transform(features)
                else:
                    features_scaled = features
                
                # Isolation Forest analysis
                if self.isolation_forest and SKLEARN_AVAILABLE:
                    try:
                        anomaly_prediction = self.isolation_forest.predict(features_scaled)
                        anomaly_score = self.isolation_forest.decision_function(features_scaled)
                        
                        results['methods']['isolation_forest'] = {
                            'is_anomaly': bool(anomaly_prediction[0] == -1),
                            'score': float(anomaly_score[0])
                        }
                    except Exception as e:
                        logger.warning(f"Isolation Forest analysis failed: {e}")
                
                # DBSCAN analysis
                if self.dbscan and SKLEARN_AVAILABLE:
                    try:
                        clusters = self.dbscan.fit_predict(features_scaled)
                        is_noise = (clusters == -1)
                        
                        results['methods']['dbscan'] = {
                            'is_anomaly': bool(is_noise[0]),
                            'cluster': int(clusters[0])
                        }
                    except Exception as e:
                        logger.warning(f"DBSCAN analysis failed: {e}")
                
                # LSTM sequence analysis
                if self.lstm_model and TF_AVAILABLE and len(self.behavioral_sequence) == self.sequence_length:
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
                
            except Exception as e:
                logger.error(f"ML-based behavioral analysis failed: {e}")
        
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
        
        # If no ML methods are available, rely on rule-based detection
        if not results['methods'] and len(rule_violations) > 0:
            results['is_anomaly'] = True
            results['confidence'] = min(len(rule_violations) * 0.3, 1.0)
            results['method'] = 'rule_based'
        
        return results
    
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
            'models_available': {
                'isolation_forest': self.isolation_forest is not None,
                'dbscan': self.dbscan is not None,
                'lstm': self.lstm_model is not None
            },
            'baseline_samples': len(self.baseline_data),
            'suspicious_patterns_monitored': len(self.suspicious_patterns),
            'sequence_length': self.sequence_length if self.lstm_model else 0,
            'last_updated': datetime.now().isoformat()
        }

def main():
    """Demo function to show robust behavioral analysis in action"""
    print("=" * 70)
    print("           AEGISAI ROBUST BEHAVIORAL ANALYSIS DEMO")
    print("=" * 70)
    
    # Initialize analyzer
    analyzer = RobustBehavioralAnalyzer()
    
    # Collect and train on baseline data
    print("Collecting baseline behavioral data...")
    baseline_data = analyzer.collect_baseline_data(1)  # 1 minute for demo
    
    print("Training behavioral analysis model...")
    success = analyzer.train_model(baseline_data)
    if success:
        print("✅ Behavioral analysis model trained successfully")
    else:
        print("⚠️  Failed to train model")
    
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
    print("ROBUST BEHAVIORAL ANALYSIS REPORT")
    print("=" * 70)
    report = analyzer.generate_report()
    for key, value in report.items():
        print(f"  {key}: {value}")
    print("=" * 70)

if __name__ == "__main__":
    main()