#!/usr/bin/env python3
"""
AegisAI Behavioral ML Analyzer
=============================

This module provides machine learning-based behavioral analysis for detecting
suspicious system activities and anomalous behavior patterns.
"""

import os
import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict, deque

# Try to import ML libraries
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    IsolationForest = None
    RandomForestClassifier = None
    StandardScaler = None
    DBSCAN = None
    logging.warning("Scikit-learn not available. Install with: pip install scikit-learn")

logger = logging.getLogger(__name__)

class BehavioralMLAnalyzer:
    """Machine learning-based behavioral analyzer for threat detection"""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the behavioral ML analyzer"""
        self.model_path = model_path
        self.anomaly_detector = None
        self.behavior_classifier = None
        self.scaler = StandardScaler() if StandardScaler else None
        self.behavior_history = defaultdict(deque)  # Store recent behavior patterns
        self.max_history = 1000  # Maximum history per entity
        self.is_trained = False
        
        # Behavioral baselines
        self.baselines = {
            'file_operations_rate': 5.0,  # operations per minute
            'network_connections_rate': 2.0,  # connections per minute
            'process_creations_rate': 1.0,  # processes per minute
            'registry_modifications_rate': 0.5  # modifications per minute
        }
        
        # Load pre-trained models if available
        if model_path and os.path.exists(model_path):
            self.load_models()
        
        logger.info("Behavioral ML analyzer initialized")
    
    def record_behavior(self, entity_id: str, behavior_type: str, timestamp: datetime = None):
        """
        Record a behavioral event for analysis
        
        Args:
            entity_id: Identifier for the entity (e.g., process ID, user ID)
            behavior_type: Type of behavior (e.g., 'file_access', 'network_connection')
            timestamp: When the behavior occurred (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # Store behavior event
        behavior_event = {
            'type': behavior_type,
            'timestamp': timestamp.isoformat(),
            'entity_id': entity_id
        }
        
        # Add to history
        self.behavior_history[entity_id].append(behavior_event)
        
        # Maintain history size limit
        if len(self.behavior_history[entity_id]) > self.max_history:
            self.behavior_history[entity_id].popleft()
        
        logger.debug(f"Recorded behavior: {entity_id} - {behavior_type}")
    
    def extract_behavioral_features(self, entity_id: str, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Extract behavioral features for ML analysis
        
        Args:
            entity_id: Identifier for the entity to analyze
            time_window_minutes: Time window to analyze (default: 60 minutes)
            
        Returns:
            Dictionary with behavioral features
        """
        if entity_id not in self.behavior_history:
            return {'error': 'No behavior history for entity'}
        
        # Get events within time window
        cutoff_time = datetime.now() - timedelta(minutes=time_window_minutes)
        recent_events = [
            event for event in self.behavior_history[entity_id]
            if datetime.fromisoformat(event['timestamp']) > cutoff_time
        ]
        
        if not recent_events:
            return {'error': 'No recent events for entity'}
        
        # Extract features
        features = {
            'entity_id': entity_id,
            'time_window_minutes': time_window_minutes,
            'total_events': len(recent_events),
            'event_types': {},
            'rate_features': {},
            'temporal_features': {}
        }
        
        # Count event types
        event_type_counts = defaultdict(int)
        timestamps = []
        
        for event in recent_events:
            event_type = event['type']
            event_type_counts[event_type] += 1
            timestamps.append(datetime.fromisoformat(event['timestamp']))
        
        features['event_types'] = dict(event_type_counts)
        
        # Rate features (events per minute)
        if timestamps:
            time_span = (max(timestamps) - min(timestamps)).total_seconds() / 60  # minutes
            if time_span > 0:
                features['rate_features'] = {
                    'events_per_minute': len(recent_events) / time_span,
                    'file_operations_per_minute': event_type_counts.get('file_operation', 0) / time_span,
                    'network_connections_per_minute': event_type_counts.get('network_connection', 0) / time_span,
                    'process_creations_per_minute': event_type_counts.get('process_creation', 0) / time_span,
                    'registry_modifications_per_minute': event_type_counts.get('registry_modification', 0) / time_span
                }
            
            # Temporal features
            timestamps_sorted = sorted(timestamps)
            if len(timestamps_sorted) > 1:
                # Time gaps between consecutive events
                time_gaps = [
                    (timestamps_sorted[i+1] - timestamps_sorted[i]).total_seconds()
                    for i in range(len(timestamps_sorted) - 1)
                ]
                
                features['temporal_features'] = {
                    'avg_time_gap': np.mean(time_gaps) if time_gaps else 0,
                    'std_time_gap': np.std(time_gaps) if len(time_gaps) > 1 else 0,
                    'min_time_gap': min(time_gaps) if time_gaps else 0,
                    'max_time_gap': max(time_gaps) if time_gaps else 0
                }
        
        # Deviation from baseline features
        rate_features = features['rate_features']
        baseline_deviations = {}
        
        for behavior_type, baseline_rate in self.baselines.items():
            actual_rate = rate_features.get(f'{behavior_type}_per_minute', 0)
            deviation = abs(actual_rate - baseline_rate) / (baseline_rate + 1e-8)  # Avoid division by zero
            baseline_deviations[f'{behavior_type}_deviation'] = deviation
        
        features['baseline_deviations'] = baseline_deviations
        
        return features
    
    def prepare_behavioral_features_for_ml(self, features_list: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """
        Prepare behavioral features for ML training/prediction
        
        Args:
            features_list: List of feature dictionaries
            
        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        if not features_list:
            return np.array([]), []
        
        # Define feature names in order
        feature_names = [
            'total_events',
            'events_per_minute',
            'file_operations_per_minute',
            'network_connections_per_minute',
            'process_creations_per_minute',
            'registry_modifications_per_minute',
            'avg_time_gap',
            'std_time_gap',
            'file_operations_deviation',
            'network_connections_deviation',
            'process_creations_deviation',
            'registry_modifications_deviation'
        ]
        
        # Create feature matrix
        feature_matrix = []
        for features in features_list:
            row = []
            for name in feature_names:
                # Handle nested features
                if name in ['file_operations_deviation', 'network_connections_deviation', 
                           'process_creations_deviation', 'registry_modifications_deviation']:
                    value = features.get('baseline_deviations', {}).get(name, 0)
                elif name in ['events_per_minute', 'file_operations_per_minute', 
                             'network_connections_per_minute', 'process_creations_per_minute', 
                             'registry_modifications_per_minute', 'avg_time_gap', 'std_time_gap']:
                    value = features.get('rate_features', {}).get(name, 0)
                else:
                    value = features.get(name, 0)
                
                row.append(float(value) if value is not None else 0.0)
            feature_matrix.append(row)
        
        return np.array(feature_matrix), feature_names
    
    def train_anomaly_detector(self, normal_behavior_data: List[Tuple[str, int]]) -> Dict[str, Any]:
        """
        Train the anomaly detector using normal behavior data
        
        Args:
            normal_behavior_data: List of tuples (entity_id, time_window_minutes) for normal behavior
            
        Returns:
            Dictionary with training results
        """
        if not ML_AVAILABLE:
            return {'error': 'Machine learning libraries not available'}
        
        try:
            # Extract features from normal behavior data
            features_list = []
            
            for entity_id, time_window in normal_behavior_data:
                features = self.extract_behavioral_features(entity_id, time_window)
                if 'error' not in features:
                    features_list.append(features)
            
            if len(features_list) == 0:
                return {'error': 'No valid training data'}
            
            # Prepare features for training
            X, feature_names = self.prepare_behavioral_features_for_ml(features_list)
            
            # Scale features
            if self.scaler:
                X_scaled = self.scaler.fit_transform(X)
            else:
                X_scaled = X
            
            # Train Isolation Forest for anomaly detection
            self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
            self.anomaly_detector.fit(X_scaled)
            
            self.is_trained = True
            
            # Save models if path provided
            if self.model_path:
                self.save_models()
            
            return {
                'status': 'success',
                'training_samples': len(X),
                'feature_names': feature_names
            }
            
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}")
            return {'error': str(e)}
    
    def detect_anomalous_behavior(self, entity_id: str, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Detect anomalous behavior for an entity
        
        Args:
            entity_id: Identifier for the entity to analyze
            time_window_minutes: Time window to analyze
            
        Returns:
            Dictionary with anomaly detection results
        """
        if not self.is_trained or not self.anomaly_detector:
            # Fallback to rule-based detection
            return self._rule_based_anomaly_detection(entity_id, time_window_minutes)
        
        try:
            # Extract features
            features = self.extract_behavioral_features(entity_id, time_window_minutes)
            
            if 'error' in features:
                return {
                    'is_anomalous': False,
                    'anomaly_score': 0.0,
                    'method': 'feature_extraction_failed',
                    'details': features
                }
            
            # Prepare features for prediction
            X, _ = self.prepare_behavioral_features_for_ml([features])
            
            # Scale features
            if self.scaler:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X
            
            # Make prediction
            anomaly_prediction = self.anomaly_detector.predict(X_scaled)[0]
            anomaly_scores = self.anomaly_detector.decision_function(X_scaled)
            
            # Convert to probability-like score (higher means more anomalous)
            # Isolation Forest returns -1 for anomalies, 1 for normal
            is_anomalous = anomaly_prediction == -1
            anomaly_score = -anomaly_scores[0]  # Invert so higher means more anomalous
            
            # Normalize score to 0-1 range (approximate)
            anomaly_score = 1 / (1 + np.exp(-anomaly_score))  # Sigmoid
            
            return {
                'is_anomalous': is_anomalous,
                'anomaly_score': float(anomaly_score),
                'method': 'ml_anomaly_detection',
                'features': features,
                'prediction': int(anomaly_prediction)
            }
            
        except Exception as e:
            logger.error(f"Error detecting anomalous behavior: {e}")
            # Fallback to rule-based detection
            return self._rule_based_anomaly_detection(entity_id, time_window_minutes)
    
    def _rule_based_anomaly_detection(self, entity_id: str, time_window_minutes: int = 60) -> Dict[str, Any]:
        """Fallback rule-based anomaly detection"""
        try:
            features = self.extract_behavioral_features(entity_id, time_window_minutes)
            
            if 'error' in features:
                return {
                    'is_anomalous': False,
                    'anomaly_score': 0.0,
                    'method': 'rule_based',
                    'details': features
                }
            
            # Rule-based anomaly detection
            anomaly_score = 0.0
            reasons = []
            
            # Check rate deviations
            baseline_deviations = features.get('baseline_deviations', {})
            for behavior_type, deviation in baseline_deviations.items():
                if deviation > 2.0:  # More than 2x deviation from baseline
                    anomaly_score += 0.3
                    reasons.append(f"High deviation in {behavior_type}: {deviation:.2f}x")
                elif deviation > 1.5:  # More than 1.5x deviation
                    anomaly_score += 0.15
                    reasons.append(f"Moderate deviation in {behavior_type}: {deviation:.2f}x")
            
            # Check for bursty behavior (low time gaps)
            temporal_features = features.get('temporal_features', {})
            avg_gap = temporal_features.get('avg_time_gap', 0)
            if avg_gap > 0 and avg_gap < 1.0:  # Less than 1 second between events on average
                anomaly_score += 0.2
                reasons.append(f"Bursty behavior: avg gap {avg_gap:.2f}s")
            
            # Check for high volume of events
            total_events = features.get('total_events', 0)
            if total_events > 100:  # More than 100 events in time window
                anomaly_score += 0.2
                reasons.append(f"High event volume: {total_events} events")
            
            is_anomalous = anomaly_score > 0.5
            anomaly_score = min(anomaly_score, 1.0)
            
            return {
                'is_anomalous': is_anomalous,
                'anomaly_score': anomaly_score,
                'method': 'rule_based',
                'reasons': reasons,
                'features': features
            }
            
        except Exception as e:
            logger.error(f"Error in rule-based anomaly detection: {e}")
            return {
                'is_anomalous': False,
                'anomaly_score': 0.0,
                'method': 'error',
                'error': str(e)
            }
    
    def update_baselines(self, new_baselines: Dict[str, float]):
        """
        Update behavioral baselines
        
        Args:
            new_baselines: Dictionary with new baseline values
        """
        self.baselines.update(new_baselines)
        logger.info(f"Updated behavioral baselines: {new_baselines}")
    
    def get_behavior_summary(self, entity_id: str, time_window_minutes: int = 60) -> Dict[str, Any]:
        """
        Get a summary of an entity's behavior
        
        Args:
            entity_id: Identifier for the entity to summarize
            time_window_minutes: Time window to analyze
            
        Returns:
            Dictionary with behavior summary
        """
        features = self.extract_behavioral_features(entity_id, time_window_minutes)
        
        if 'error' in features:
            return features
        
        # Create summary
        summary = {
            'entity_id': entity_id,
            'time_window_minutes': time_window_minutes,
            'total_events': features.get('total_events', 0),
            'event_distribution': features.get('event_types', {}),
            'activity_rates': features.get('rate_features', {}),
            'anomaly_indicators': []
        }
        
        # Add anomaly indicators based on baseline deviations
        baseline_deviations = features.get('baseline_deviations', {})
        for behavior_type, deviation in baseline_deviations.items():
            if deviation > 1.5:
                summary['anomaly_indicators'].append({
                    'type': behavior_type.replace('_deviation', ''),
                    'deviation': deviation,
                    'severity': 'high' if deviation > 2.0 else 'medium'
                })
        
        return summary
    
    def save_models(self):
        """Save trained models to disk"""
        if not self.is_trained or not self.model_path:
            return
        
        try:
            model_data = {
                'timestamp': datetime.now().isoformat(),
                'scaler': self.scaler,
                'anomaly_detector': self.anomaly_detector,
                'baselines': self.baselines
            }
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            # Save model (simplified - in practice, you'd use joblib or similar)
            with open(self.model_path, 'w') as f:
                json.dump({
                    'timestamp': model_data['timestamp'],
                    'is_trained': self.is_trained,
                    'baselines': self.baselines
                }, f)
            
            logger.info(f"Behavioral models saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving behavioral models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            with open(self.model_path, 'r') as f:
                model_data = json.load(f)
            
            self.is_trained = model_data.get('is_trained', False)
            self.baselines = model_data.get('baselines', self.baselines)
            logger.info(f"Behavioral models loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error loading behavioral models: {e}")

# Example usage
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = BehavioralMLAnalyzer()
    
    # Simulate some behavior recording
    entity_id = "test_process_123"
    
    # Record normal behavior
    for i in range(10):
        analyzer.record_behavior(entity_id, "file_operation")
        analyzer.record_behavior(entity_id, "network_connection")
    
    # Get behavior summary
    summary = analyzer.get_behavior_summary(entity_id)
    print("Behavior Summary:")
    print(json.dumps(summary, indent=2))
    
    # Detect anomalies
    anomaly_result = analyzer.detect_anomalous_behavior(entity_id)
    print("\nAnomaly Detection Result:")
    print(json.dumps(anomaly_result, indent=2))