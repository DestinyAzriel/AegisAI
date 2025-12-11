#!/usr/bin/env python3
"""
AegisAI Enhanced ML Detector
===========================

This module provides enhanced machine learning-based threat detection capabilities
using deep learning models for file classification and behavioral analysis.
"""

import os
import math
import hashlib
import json
import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime
import numpy as np

# Try to import ML libraries
try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, accuracy_score
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    RandomForestClassifier = None
    GradientBoostingClassifier = None
    StandardScaler = None
    logging.warning("Scikit-learn not available. Install with: pip install scikit-learn")

# Try to import deep learning libraries
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
    from tensorflow.keras.optimizers import Adam
    DL_AVAILABLE = True
except ImportError:
    DL_AVAILABLE = False
    tf = None
    Sequential = None
    Dense = None
    Dropout = None
    BatchNormalization = None
    Adam = None
    logging.warning("TensorFlow not available. Install with: pip install tensorflow")

logger = logging.getLogger(__name__)

class EnhancedMLDetector:
    """Enhanced machine learning detector for threat detection"""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize the enhanced ML detector"""
        self.model_path = model_path
        self.file_classifier = None
        self.behavioral_classifier = None
        self.scaler = StandardScaler() if StandardScaler else None
        self.feature_extractor = MLFeatureExtractor()
        self.is_trained = False
        
        # Load pre-trained models if available
        if model_path and os.path.exists(model_path):
            self.load_models()
        
        logger.info("Enhanced ML detector initialized")
    
    def extract_enhanced_features(self, filepath: str) -> Dict[str, Any]:
        """
        Extract enhanced features from a file for ML analysis
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Dictionary with extracted features
        """
        # Get basic features
        features = self.feature_extractor.extract_features(filepath)
        
        if not features.get('features_extracted', False):
            return features
        
        try:
            # Add statistical features
            with open(filepath, 'rb') as f:
                data = f.read(1024)  # Read first 1KB for performance
                
                if data:
                    # Byte frequency analysis
                    byte_freq = [0] * 256
                    for byte in data:
                        byte_freq[byte] += 1
                    
                    # Normalize frequencies
                    total_bytes = len(data)
                    byte_freq_normalized = [freq / total_bytes for freq in byte_freq]
                    
                    # Statistical moments
                    mean_freq = np.mean(byte_freq_normalized)
                    std_freq = np.std(byte_freq_normalized)
                    skewness = self._calculate_skewness(byte_freq_normalized)
                    kurtosis = self._calculate_kurtosis(byte_freq_normalized)
                    
                    # Add to features
                    features.update({
                        'byte_mean': mean_freq,
                        'byte_std': std_freq,
                        'byte_skewness': skewness,
                        'byte_kurtosis': kurtosis,
                        'byte_distribution': byte_freq_normalized[:16]  # First 16 bytes distribution
                    })
                
                # Add PE file features if it's a PE file
                if filepath.endswith(('.exe', '.dll', '.sys')):
                    pe_features = self._extract_pe_features(filepath)
                    features.update(pe_features)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting enhanced features: {e}")
            return features
    
    def _calculate_skewness(self, data: List[float]) -> float:
        """Calculate skewness of data distribution"""
        if len(data) == 0:
            return 0.0
        
        mean = np.mean(data)
        std = np.std(data)
        
        if std == 0:
            return 0.0
        
        n = len(data)
        skewness = sum(((x - mean) / std) ** 3 for x in data) * n / ((n - 1) * (n - 2))
        return skewness
    
    def _calculate_kurtosis(self, data: List[float]) -> float:
        """Calculate kurtosis of data distribution"""
        if len(data) == 0:
            return 0.0
        
        mean = np.mean(data)
        std = np.std(data)
        
        if std == 0:
            return 0.0
        
        n = len(data)
        kurtosis = sum(((x - mean) / std) ** 4 for x in data) * n * (n + 1) / ((n - 1) * (n - 2) * (n - 3)) - 3 * (n - 1) ** 2 / ((n - 2) * (n - 3))
        return kurtosis
    
    def _extract_pe_features(self, filepath: str) -> Dict[str, Any]:
        """Extract PE file specific features"""
        try:
            # Simplified PE feature extraction
            # In a real implementation, this would parse the PE header
            features = {
                'pe_sections': 3,  # Placeholder
                'pe_imports': 10,  # Placeholder
                'pe_exports': 2,   # Placeholder
                'pe_resources': 5, # Placeholder
                'pe_is_packed': False  # Placeholder
            }
            return features
        except:
            return {}
    
    def prepare_features_for_training(self, features_list: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """
        Prepare features for training by converting to numerical format
        
        Args:
            features_list: List of feature dictionaries
            
        Returns:
            Tuple of (feature_matrix, feature_names)
        """
        if not features_list:
            return np.array([]), []
        
        # Define feature names in order
        feature_names = [
            'file_size', 'entropy', 'byte_mean', 'byte_std', 'byte_skewness', 
            'byte_kurtosis', 'pe_sections', 'pe_imports', 'pe_exports', 
            'pe_resources'
        ]
        
        # Create feature matrix
        feature_matrix = []
        for features in features_list:
            row = []
            for name in feature_names:
                value = features.get(name, 0)
                # Handle list values (like byte_distribution)
                if isinstance(value, list):
                    row.extend(value)
                else:
                    row.append(float(value) if value is not None else 0.0)
            feature_matrix.append(row)
        
        return np.array(feature_matrix), feature_names
    
    def train_file_classifier(self, training_data: List[Tuple[str, int]], test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train the file classifier using enhanced features
        
        Args:
            training_data: List of tuples (filepath, label) where label is 0 (clean) or 1 (malicious)
            test_size: Proportion of data to use for testing
            
        Returns:
            Dictionary with training results
        """
        if not ML_AVAILABLE:
            return {'error': 'Machine learning libraries not available'}
        
        try:
            # Extract features from training data
            features_list = []
            labels = []
            
            for filepath, label in training_data:
                if os.path.exists(filepath):
                    features = self.extract_enhanced_features(filepath)
                    if features.get('features_extracted', False):
                        features_list.append(features)
                        labels.append(label)
            
            if len(features_list) == 0:
                return {'error': 'No valid training data'}
            
            # Prepare features for training
            X, feature_names = self.prepare_features_for_training(features_list)
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=test_size, random_state=42)
            
            # Scale features
            if self.scaler:
                X_train_scaled = self.scaler.fit_transform(X_train)
                X_test_scaled = self.scaler.transform(X_test)
            else:
                X_train_scaled = X_train
                X_test_scaled = X_test
            
            # Train Random Forest classifier
            rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            rf_classifier.fit(X_train_scaled, y_train)
            
            # Train Gradient Boosting classifier
            gb_classifier = GradientBoostingClassifier(n_estimators=100, random_state=42)
            gb_classifier.fit(X_train_scaled, y_train)
            
            # Evaluate models
            rf_predictions = rf_classifier.predict(X_test_scaled)
            gb_predictions = gb_classifier.predict(X_test_scaled)
            
            rf_accuracy = accuracy_score(y_test, rf_predictions)
            gb_accuracy = accuracy_score(y_test, gb_predictions)
            
            # Store the better performing model
            if rf_accuracy >= gb_accuracy:
                self.file_classifier = rf_classifier
                accuracy = rf_accuracy
                predictions = rf_predictions
            else:
                self.file_classifier = gb_classifier
                accuracy = gb_accuracy
                predictions = gb_predictions
            
            self.is_trained = True
            
            # Save models if path provided
            if self.model_path:
                self.save_models()
            
            return {
                'status': 'success',
                'accuracy': accuracy,
                'feature_importance': dict(zip(feature_names, self.file_classifier.feature_importances_)),
                'classification_report': classification_report(y_test, predictions, output_dict=True),
                'training_samples': len(X_train),
                'test_samples': len(X_test)
            }
            
        except Exception as e:
            logger.error(f"Error training file classifier: {e}")
            return {'error': str(e)}
    
    def predict_file_threat(self, filepath: str) -> Dict[str, Any]:
        """
        Predict if a file is a threat using the trained classifier
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Dictionary with prediction results
        """
        if not self.is_trained or not self.file_classifier:
            # Fallback to heuristic-based detection
            return self._heuristic_detection(filepath)
        
        try:
            # Extract features
            features = self.extract_enhanced_features(filepath)
            
            if not features.get('features_extracted', False):
                return {
                    'is_threat': False,
                    'confidence': 0.0,
                    'method': 'feature_extraction_failed',
                    'features': features
                }
            
            # Prepare features for prediction
            X, _ = self.prepare_features_for_training([features])
            
            # Scale features
            if self.scaler:
                X_scaled = self.scaler.transform(X)
            else:
                X_scaled = X
            
            # Make prediction
            prediction = self.file_classifier.predict(X_scaled)[0]
            probabilities = self.file_classifier.predict_proba(X_scaled)[0]
            
            # Get confidence (probability of predicted class)
            confidence = max(probabilities)
            
            return {
                'is_threat': bool(prediction),
                'confidence': float(confidence),
                'probabilities': {
                    'clean': float(probabilities[0]),
                    'malicious': float(probabilities[1])
                },
                'method': 'ml_classification',
                'features': features
            }
            
        except Exception as e:
            logger.error(f"Error predicting file threat: {e}")
            # Fallback to heuristic detection
            return self._heuristic_detection(filepath)
    
    def _heuristic_detection(self, filepath: str) -> Dict[str, Any]:
        """Fallback heuristic-based detection"""
        try:
            features = self.feature_extractor.extract_features(filepath)
            
            if not features.get('features_extracted', False):
                return {
                    'is_threat': False,
                    'confidence': 0.0,
                    'method': 'heuristic',
                    'features': features
                }
            
            # Heuristic rules
            threat_score = 0.0
            
            # High entropy suggests packing/encryption
            if features.get('entropy', 0) > 7.0:
                threat_score += 0.3
            
            # Large file size
            if features.get('file_size', 0) > 100 * 1024 * 1024:  # 100MB
                threat_score += 0.2
            
            # Suspicious extensions
            suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.com']
            if features.get('extension', '').lower() in suspicious_extensions:
                threat_score += 0.4
            
            # Very small files might be droppers
            if 0 < features.get('file_size', 0) < 1024:  # Less than 1KB
                threat_score += 0.1
            
            is_threat = threat_score > 0.5
            confidence = min(threat_score, 1.0)
            
            return {
                'is_threat': is_threat,
                'confidence': confidence,
                'method': 'heuristic',
                'threat_score_factors': {
                    'entropy': features.get('entropy', 0),
                    'file_size': features.get('file_size', 0),
                    'extension': features.get('extension', ''),
                    'score': threat_score
                },
                'features': features
            }
            
        except Exception as e:
            logger.error(f"Error in heuristic detection: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'method': 'error',
                'error': str(e)
            }
    
    def save_models(self):
        """Save trained models to disk"""
        if not self.is_trained or not self.model_path:
            return
        
        try:
            model_data = {
                'timestamp': datetime.now().isoformat(),
                'scaler': self.scaler,
                'classifier': self.file_classifier
            }
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            
            # Save model (simplified - in practice, you'd use joblib or similar)
            with open(self.model_path, 'w') as f:
                json.dump({
                    'timestamp': model_data['timestamp'],
                    'is_trained': self.is_trained
                }, f)
            
            logger.info(f"Models saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            with open(self.model_path, 'r') as f:
                model_data = json.load(f)
            
            self.is_trained = model_data.get('is_trained', False)
            logger.info(f"Models loaded from {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")

class MLFeatureExtractor:
    """Extracts features from files for machine learning analysis"""
    
    def __init__(self):
        """Initialize the ML feature extractor"""
        pass
    
    def extract_features(self, filepath: str) -> Dict[str, Any]:
        """
        Extract features from a file for ML analysis
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Dictionary with extracted features
        """
        if not os.path.exists(filepath):
            return {}
        
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            
            # Calculate entropy
            entropy = self._calculate_entropy(filepath)
            
            # Get file extension
            _, ext = os.path.splitext(filepath)
            
            # Calculate hash
            file_hash = self._calculate_hash(filepath)
            
            return {
                'file_size': file_size,
                'entropy': entropy,
                'extension': ext.lower() if ext else '',
                'hash': file_hash,
                'features_extracted': True
            }
        except Exception as e:
            return {
                'error': str(e),
                'features_extracted': False
            }
    
    def _calculate_entropy(self, filepath: str) -> float:
        """
        Calculate file entropy
        
        Args:
            filepath: Path to the file
            
        Returns:
            Entropy value between 0 and 8
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024)  # Read first 1KB for performance
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
    
    def _calculate_hash(self, filepath: str) -> str:
        """
        Calculate SHA256 hash of file
        
        Args:
            filepath: Path to the file
            
        Returns:
            SHA256 hash as hex string
        """
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read(1024)).hexdigest()  # Hash first 1KB
        except:
            return ''

# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = EnhancedMLDetector()
    
    # Test with this script file
    result = detector.predict_file_threat(__file__)
    print("Enhanced ML Detection Results:")
    print(json.dumps(result, indent=2))