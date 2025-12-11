#!/usr/bin/env python3
"""
AegisAI Behavioral Analysis Module

This module implements machine learning models for behavioral analysis
to detect anomalous patterns that may indicate security threats.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any
import warnings
warnings.filterwarnings('ignore')

# Try to import deep learning libraries
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, Attention
    from tensorflow.keras.optimizers import Adam
    DEEP_LEARNING_AVAILABLE = True
    logging.info("Deep learning libraries available")
except ImportError:
    DEEP_LEARNING_AVAILABLE = False
    logging.warning("Deep learning libraries not available, using traditional ML only")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BehavioralAnalyzer:
    """Behavioral analysis engine for threat detection"""
    
    def __init__(self):
        """Initialize the behavioral analyzer"""
        self.isolation_forest = IsolationForest(
            contamination='auto',  # Expected proportion of outliers
            random_state=42
        )
        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.baseline_profiles = {}
        self.anomaly_threshold = 0.7
        
        logger.info("Behavioral analyzer initialized")
    
    def extract_features(self, process_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract behavioral features from process data
        
        Args:
            process_data: Dictionary containing process information
            
        Returns:
            np.ndarray: Feature vector
        """
        features = []
        
        # Process creation rate
        features.append(process_data.get('creation_rate', 0))
        
        # CPU usage patterns
        features.append(process_data.get('avg_cpu_usage', 0))
        features.append(process_data.get('max_cpu_usage', 0))
        
        # Memory usage patterns
        features.append(process_data.get('avg_memory_usage', 0))
        features.append(process_data.get('max_memory_usage', 0))
        
        # Network activity
        features.append(process_data.get('network_connections', 0))
        features.append(process_data.get('data_transferred', 0))
        
        # File system activity
        features.append(process_data.get('files_accessed', 0))
        features.append(process_data.get('files_created', 0))
        
        # Process tree depth
        features.append(process_data.get('process_tree_depth', 0))
        
        # Parent-child relationships
        features.append(process_data.get('child_processes', 0))
        
        return np.array(features).reshape(1, -1)
    
    def create_baseline_profile(self, agent_id: str, features: np.ndarray):
        """
        Create a baseline behavioral profile for an agent
        
        Args:
            agent_id: Unique identifier for the agent
            features: Feature vectors for baseline
        """
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        # Train models
        self.isolation_forest.fit(scaled_features)
        self.dbscan.fit(scaled_features)
        
        # Store baseline profile
        self.baseline_profiles[agent_id] = {
            'scaler': self.scaler,
            'features': scaled_features,
            'timestamp': datetime.now()
        }
        
        self.is_trained = True
        logger.info(f"Baseline profile created for agent {agent_id}")
    
    def detect_anomalies(self, agent_id: str, features: np.ndarray) -> Dict[str, Any]:
        """
        Detect behavioral anomalies
        
        Args:
            agent_id: Unique identifier for the agent
            features: Feature vectors to analyze
            
        Returns:
            Dict containing anomaly detection results
        """
        if not self.is_trained:
            logger.warning("Analyzer not trained yet")
            return {'anomaly_score': 0.0, 'is_anomaly': False, 'confidence': 0.0}
        
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
        
        # Combine results
        anomaly_score = -anomaly_scores_if[0]  # Convert to positive score
        is_anomaly_if = (predictions_if[0] == -1)
        is_anomaly_dbscan = is_noise[0]
        
        # Final decision
        is_anomaly = is_anomaly_if or is_anomaly_dbscan
        confidence = max(
            abs(anomaly_score) / 2.0,  # Normalize score
            0.9 if is_anomaly_if else 0.1,
            0.8 if is_anomaly_dbscan else 0.2
        )
        
        return {
            'anomaly_score': float(anomaly_score),
            'is_anomaly': bool(is_anomaly),
            'confidence': float(confidence),
            'methods': {
                'isolation_forest': {
                    'score': float(anomaly_scores_if[0]),
                    'is_anomaly': bool(is_anomaly_if)
                },
                'dbscan': {
                    'is_anomaly': bool(is_anomaly_dbscan)
                }
            }
        }
    
    def update_model(self, agent_id: str, new_features: np.ndarray):
        """
        Update the behavioral model with new data
        
        Args:
            agent_id: Unique identifier for the agent
            new_features: New feature vectors
        """
        if agent_id not in self.baseline_profiles:
            logger.warning(f"No baseline profile for agent {agent_id}")
            return
        
        # Combine with existing features
        existing_features = self.baseline_profiles[agent_id]['features']
        combined_features = np.vstack([existing_features, new_features])
        
        # Retrain models
        self.create_baseline_profile(agent_id, combined_features)
        logger.info(f"Model updated for agent {agent_id}")

class DeepBehavioralAnalyzer:
    """Deep learning behavioral analysis engine for enhanced threat detection"""
    
    def __init__(self, sequence_length: int = 10):
        """Initialize the deep behavioral analyzer"""
        self.sequence_length = sequence_length
        self.lstm_model = None
        self.autoencoder = None
        self.attention_model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        
        # Initialize deep learning models if available
        if DEEP_LEARNING_AVAILABLE:
            self._build_models()
        
        logger.info("Deep behavioral analyzer initialized")
    
    def _build_models(self):
        """Build deep learning models"""
        try:
            # LSTM model for sequential behavior analysis
            self.lstm_model = Sequential([
                LSTM(64, return_sequences=True, input_shape=(self.sequence_length, 17)),
                Dropout(0.2),
                LSTM(32, return_sequences=False),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            # Autoencoder for anomaly detection
            input_layer = Input(shape=(17,))
            encoded = Dense(12, activation='relu')(input_layer)
            encoded = Dense(8, activation='relu')(encoded)
            encoded = Dense(4, activation='relu')(encoded)
            
            decoded = Dense(8, activation='relu')(encoded)
            decoded = Dense(12, activation='relu')(decoded)
            decoded = Dense(17, activation='sigmoid')(decoded)
            
            self.autoencoder = Model(input_layer, decoded)
            self.autoencoder.compile(optimizer='adam', loss='mse')
            
            # Attention-based model
            query_input = Input(shape=(self.sequence_length, 17))
            value_input = Input(shape=(self.sequence_length, 17))
            
            attention_output = tf.keras.layers.Attention()([query_input, value_input])
            lstm_output = LSTM(32)(attention_output)
            output = Dense(1, activation='sigmoid')(lstm_output)
            
            self.attention_model = Model([query_input, value_input], output)
            
            logger.info("Deep learning models built successfully")
        except Exception as e:
            logger.error(f"Failed to build deep learning models: {e}")
    
    def extract_features(self, process_data: Dict[str, Any]) -> np.ndarray:
        """
        Extract enhanced behavioral features from process data
        
        Args:
            process_data: Dictionary containing process information
            
        Returns:
            np.ndarray: Enhanced feature vector
        """
        features = []
        
        # Traditional features
        features.append(process_data.get('creation_rate', 0))
        features.append(process_data.get('avg_cpu_usage', 0))
        features.append(process_data.get('max_cpu_usage', 0))
        features.append(process_data.get('avg_memory_usage', 0))
        features.append(process_data.get('max_memory_usage', 0))
        features.append(process_data.get('network_connections', 0))
        features.append(process_data.get('data_transferred', 0))
        features.append(process_data.get('files_accessed', 0))
        features.append(process_data.get('files_created', 0))
        features.append(process_data.get('process_tree_depth', 0))
        features.append(process_data.get('child_processes', 0))
        
        # Enhanced features for deep learning
        features.append(process_data.get('memory_fluctuation', 0))
        features.append(process_data.get('cpu_variance', 0))
        features.append(process_data.get('network_byte_distribution', 0))
        features.append(process_data.get('file_access_pattern', 0))
        features.append(process_data.get('process_spawn_rate', 0))
        features.append(process_data.get('registry_changes', 0))
        
        return np.array(features).reshape(1, -1)
    
    def prepare_sequences(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare sequential data for LSTM training
        
        Args:
            data: List of process data dictionaries
            
        Returns:
            Tuple of (X, y) sequences
        """
        # Extract features from all data points
        features = []
        for process_data in data:
            feature_vector = self.extract_features(process_data)
            features.append(feature_vector.flatten())
        
        # Convert to numpy array
        features = np.array(features)
        
        # Create sequences
        X, y = [], []
        for i in range(len(features) - self.sequence_length):
            X.append(features[i:(i + self.sequence_length)])
            y.append(1 if np.mean(features[i + self.sequence_length]) > 0.5 else 0)  # Simplified label
        
        return np.array(X), np.array(y)
    
    def train_lstm_model(self, training_sequences: List[Dict[str, Any]], labels: List[int]):
        """
        Train the LSTM model on behavioral sequences
        
        Args:
            training_sequences: List of behavioral sequences
            labels: List of labels (0 for normal, 1 for anomalous)
        """
        if not DEEP_LEARNING_AVAILABLE or not self.lstm_model:
            logger.warning("Deep learning not available or LSTM model not built")
            return
        
        try:
            # Prepare sequences
            X, y = self.prepare_sequences(training_sequences)
            
            if len(X) == 0:
                logger.warning("No sequences to train on")
                return
            
            # Train the model
            self.lstm_model.compile(
                optimizer=Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            self.lstm_model.fit(
                X, y,
                epochs=50,
                batch_size=32,
                validation_split=0.2,
                verbose=0
            )
            
            self.is_trained = True
            logger.info("LSTM model trained successfully")
        except Exception as e:
            logger.error(f"Failed to train LSTM model: {e}")
    
    def detect_sequential_anomalies(self, agent_id: str, process_sequence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detect anomalies in sequential process behavior using deep learning
        
        Args:
            agent_id: Unique identifier for the agent
            process_sequence: Sequence of process data
            
        Returns:
            Dict containing sequential anomaly detection results
        """
        if not DEEP_LEARNING_AVAILABLE:
            # Fallback to traditional methods
            return self._fallback_detection(process_sequence)
        
        # Prepare sequences
        X, _ = self.prepare_sequences(process_sequence)
        
        if len(X) == 0:
            return {'anomaly_score': 0.0, 'is_anomaly': False, 'confidence': 0.0}
        
        try:
            # LSTM prediction
            lstm_score = 0.0
            if self.lstm_model and self.is_trained:
                lstm_pred = self.lstm_model.predict(X[-1:], verbose=0)
                lstm_score = lstm_pred[0][0]
            
            # Autoencoder reconstruction error
            autoencoder_error = 0.0
            if self.autoencoder:
                # Prepare data for autoencoder
                latest_features = X[-1][-1]  # Last feature vector
                latest_features = latest_features.reshape(1, -1)
                reconstructed = self.autoencoder.predict(latest_features, verbose=0)
                autoencoder_error = np.mean(np.square(latest_features - reconstructed))
            
            # Combine scores
            combined_score = (lstm_score + min(autoencoder_error * 10, 1.0)) / 2
            
            return {
                'anomaly_score': float(combined_score),
                'is_anomaly': bool(combined_score > 0.7),
                'confidence': float(combined_score),
                'methods': {
                    'lstm': float(lstm_score),
                    'autoencoder': float(autoencoder_error)
                },
                'sequence_length': len(X)
            }
        except Exception as e:
            logger.error(f"Deep learning detection failed: {e}")
            return self._fallback_detection(process_sequence)
    
    def _fallback_detection(self, process_sequence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Fallback detection method when deep learning is not available
        
        Args:
            process_sequence: Sequence of process data
            
        Returns:
            Dict containing detection results
        """
        # Use traditional statistical methods
        if not process_sequence:
            return {'anomaly_score': 0.0, 'is_anomaly': False, 'confidence': 0.0}
        
        # Simple statistical anomaly detection
        features = []
        for process_data in process_sequence[-10:]:  # Last 10 processes
            feature_vector = self.extract_features(process_data)
            features.append(feature_vector.flatten())
        
        features = np.array(features)
        mean_features = np.mean(features, axis=0)
        std_features = np.std(features, axis=0)
        
        # Calculate anomaly score based on deviation from mean
        anomaly_score = np.mean(np.abs(mean_features) / (std_features + 1e-8))
        normalized_score = min(anomaly_score / 5.0, 1.0)  # Normalize
        
        return {
            'anomaly_score': float(normalized_score),
            'is_anomaly': bool(normalized_score > 0.7),
            'confidence': float(normalized_score),
            'methods': {
                'statistical': float(normalized_score)
            }
        }

class ProcessBehaviorMonitor:
    """Monitor process behavior for anomalies"""
    
    def __init__(self):
        """Initialize the process behavior monitor"""
        self.analyzer = BehavioralAnalyzer()
        self.deep_analyzer = DeepBehavioralAnalyzer() if DEEP_LEARNING_AVAILABLE else None
        self.process_history = {}
        self.threat_threshold = 0.8
        
        logger.info("Process behavior monitor initialized")
    
    def monitor_process(self, agent_id: str, process_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Monitor a process for anomalous behavior
        
        Args:
            agent_id: Unique identifier for the agent
            process_data: Process information
            
        Returns:
            Dict containing monitoring results
        """
        # Extract features
        features = self.analyzer.extract_features(process_data)
        
        # Detect anomalies with traditional methods
        result = self.analyzer.detect_anomalies(agent_id, features)
        
        # Enhance with deep learning if available
        if self.deep_analyzer and agent_id in self.process_history:
            # Get process sequence for this agent
            process_sequence = list(self.process_history[agent_id].values())
            if len(process_sequence) >= 10:  # Need at least 10 processes for sequence analysis
                deep_result = self.deep_analyzer.detect_sequential_anomalies(agent_id, process_sequence)
                
                # Combine results
                combined_score = (result['anomaly_score'] + deep_result['anomaly_score']) / 2
                combined_confidence = (result['confidence'] + deep_result['confidence']) / 2
                is_anomaly = result['is_anomaly'] or deep_result['is_anomaly']
                
                result = {
                    'anomaly_score': combined_score,
                    'is_anomaly': is_anomaly,
                    'confidence': combined_confidence,
                    'methods': {
                        'traditional': result['methods'],
                        'deep_learning': deep_result['methods']
                    }
                }
        
        # Store process history
        process_id = process_data.get('process_id', 'unknown')
        if agent_id not in self.process_history:
            self.process_history[agent_id] = {}
        
        self.process_history[agent_id][process_id] = {
            'data': process_data,
            'analysis': result,
            'timestamp': datetime.now()
        }
        
        # Check for threats
        if result['is_anomaly'] and result['confidence'] > self.threat_threshold:
            logger.warning(f"Potential threat detected in process {process_id} on agent {agent_id}")
            return {
                'threat_detected': True,
                'threat_level': 'high' if result['confidence'] > 0.9 else 'medium',
                'analysis': result,
                'process_data': process_data
            }
        
        return {
            'threat_detected': False,
            'analysis': result,
            'process_data': process_data
        }
    
    def generate_behavioral_report(self, agent_id: str) -> Dict[str, Any]:
        """
        Generate a behavioral analysis report for an agent
        
        Args:
            agent_id: Unique identifier for the agent
            
        Returns:
            Dict containing behavioral analysis report
        """
        if agent_id not in self.process_history:
            return {'agent_id': agent_id, 'total_processes': 0, 'anomalies_detected': 0}
        
        processes = self.process_history[agent_id]
        total_processes = len(processes)
        anomalies = [p for p in processes.values() if p['analysis']['is_anomaly']]
        threats = [p for p in processes.values() if p['analysis'].get('threat_detected', False)]
        
        return {
            'agent_id': agent_id,
            'total_processes': total_processes,
            'anomalies_detected': len(anomalies),
            'threats_detected': len(threats),
            'anomaly_rate': len(anomalies) / total_processes if total_processes > 0 else 0,
            'threat_rate': len(threats) / total_processes if total_processes > 0 else 0,
            'timestamp': datetime.now().isoformat()
        }

# Advanced Behavioral Models
class AdvancedBehavioralAnalyzer:
    """Advanced behavioral analysis with deep learning capabilities"""
    
    def __init__(self):
        """Initialize the advanced behavioral analyzer"""
        self.lstm_model = None
        self.autoencoder = None
        self.sequence_length = 10
        self.feature_extractor = BehavioralAnalyzer()
        
        logger.info("Advanced behavioral analyzer initialized")
    
    def prepare_sequences(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """
        Prepare sequential data for LSTM training
        
        Args:
            data: List of process data dictionaries
            
        Returns:
            Tuple of (X, y) sequences
        """
        # Extract features from all data points
        features = []
        for process_data in data:
            feature_vector = self.feature_extractor.extract_features(process_data)
            features.append(feature_vector.flatten())
        
        # Convert to numpy array
        features = np.array(features)
        
        # Create sequences
        X, y = [], []
        for i in range(len(features) - self.sequence_length):
            X.append(features[i:(i + self.sequence_length)])
            y.append(features[i + self.sequence_length])
        
        return np.array(X), np.array(y)
    
    def detect_sequential_anomalies(self, agent_id: str, process_sequence: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Detect anomalies in sequential process behavior
        
        Args:
            agent_id: Unique identifier for the agent
            process_sequence: Sequence of process data
            
        Returns:
            Dict containing sequential anomaly detection results
        """
        # Prepare sequences
        X, _ = self.prepare_sequences(process_sequence)
        
        if len(X) == 0:
            return {'anomaly_score': 0.0, 'is_anomaly': False, 'confidence': 0.0}
        
        # In a real implementation, this would use an LSTM model
        # For now, we'll simulate the results
        anomaly_scores = np.random.random(len(X))
        predictions = anomaly_scores > 0.8
        
        # Return results for the last sequence
        return {
            'anomaly_score': float(anomaly_scores[-1]),
            'is_anomaly': bool(predictions[-1]),
            'confidence': float(anomaly_scores[-1]),
            'sequence_length': len(X)
        }

# Example usage and testing
if __name__ == "__main__":
    # Create behavioral analyzer
    monitor = ProcessBehaviorMonitor()
    
    # Simulate normal process behavior
    normal_process = {
        'process_id': '12345',
        'creation_rate': 1.2,
        'avg_cpu_usage': 5.5,
        'max_cpu_usage': 15.2,
        'avg_memory_usage': 45.3,
        'max_memory_usage': 89.1,
        'network_connections': 2,
        'data_transferred': 1024,
        'files_accessed': 5,
        'files_created': 0,
        'process_tree_depth': 3,
        'child_processes': 1,
        'memory_fluctuation': 0.1,
        'cpu_variance': 2.3,
        'network_byte_distribution': 0.5,
        'file_access_pattern': 0.2,
        'process_spawn_rate': 0.8,
        'registry_changes': 0
    }
    
    # Create baseline profile
    features = monitor.analyzer.extract_features(normal_process)
    monitor.analyzer.create_baseline_profile('test-agent-001', features)
    
    # Test normal behavior
    print("Testing normal process behavior:")
    result = monitor.monitor_process('test-agent-001', normal_process)
    print(f"Result: {result}")
    
    # Test anomalous behavior
    anomalous_process = normal_process.copy()
    anomalous_process['creation_rate'] = 50.0  # Unusually high
    anomalous_process['network_connections'] = 100  # Unusually high
    anomalous_process['data_transferred'] = 1024000  # Unusually high
    
    print("\nTesting anomalous process behavior:")
    result = monitor.monitor_process('test-agent-001', anomalous_process)
    print(f"Result: {result}")
    
    # Generate report
    print("\nBehavioral analysis report:")
    report = monitor.generate_behavioral_report('test-agent-001')
    print(f"Report: {report}")
    
    # Test advanced analyzer
    print("\nTesting advanced behavioral analyzer:")
    advanced_analyzer = AdvancedBehavioralAnalyzer()
    
    # Create sequence of process data
    process_sequence = [normal_process] * 15
    process_sequence[12] = anomalous_process  # Insert anomaly
    
    result = advanced_analyzer.detect_sequential_anomalies('test-agent-001', process_sequence)
    print(f"Sequential analysis result: {result}")