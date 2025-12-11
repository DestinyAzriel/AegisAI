"""
AegisAI Enhanced ML Service
==========================

Enhanced machine learning service for AegisAI endpoint protection.
This service handles multiple model types, advanced feature extraction, 
and ensemble-based threat detection.
"""

import lightgbm as lgb
import xgboost as xgb
import numpy as np
import pandas as pd
import json
import hashlib
from typing import Dict, List, Tuple, Optional
import logging
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedMLService:
    """Enhanced machine learning service for malware detection with ensemble methods"""
    
    def __init__(self, model_dir: str = "models"):
        """
        Initialize the enhanced ML service
        
        Args:
            model_dir: Directory to store/load models
        """
        self.model_dir = model_dir
        self.models = {}
        self.scalers = {}
        self.feature_names = []
        self.label_encoders = {}
        
        # Create model directory if it doesn't exist
        os.makedirs(model_dir, exist_ok=True)
        
        # Load existing models if available
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models from disk"""
        try:
            model_files = os.listdir(self.model_dir)
            for model_file in model_files:
                if model_file.endswith('.joblib'):
                    model_name = model_file.replace('.joblib', '')
                    model_path = os.path.join(self.model_dir, model_file)
                    self.models[model_name] = joblib.load(model_path)
                    logger.info(f"Loaded model: {model_name}")
        except Exception as e:
            logger.warning(f"Failed to load models: {e}")
    
    def save_model(self, model_path: str):
        """Save the trained model
        
        Args:
            model_path: Path to save the model
        """
        if 'ensemble' in self.models:
            joblib.dump(self.models['ensemble'], model_path)
            logger.info(f"Model saved to {model_path}")
    
    def save_models(self):
        """Save trained models to disk"""
        try:
            for model_name, model in self.models.items():
                model_path = os.path.join(self.model_dir, f"{model_name}.joblib")
                joblib.dump(model, model_path)
                logger.info(f"Saved model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    def extract_advanced_features(self, file_data: bytes, file_path: str = "") -> Dict:
        """
        Extract advanced features from file data for ML analysis
        
        Args:
            file_data: File content as bytes
            file_path: File path (optional)
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Basic file information
        features['file_size'] = len(file_data)
        
        # Byte analysis
        if len(file_data) > 0:
            # Byte histogram
            byte_hist = [0] * 256
            for byte in file_data[:10000]:  # Sample first 10KB
                byte_hist[byte] += 1
            
            # Byte entropy
            total = sum(byte_hist)
            if total > 0:
                entropy = 0.0
                for count in byte_hist:
                    if count > 0:
                        probability = count / total
                        entropy -= probability * np.log2(probability)
                features['byte_entropy'] = entropy
            else:
                features['byte_entropy'] = 0.0
            
            # Byte frequency features
            features['byte_mean'] = np.mean(byte_hist)
            features['byte_std'] = np.std(byte_hist)
            features['byte_max'] = np.max(byte_hist)
            features['byte_min'] = np.min(byte_hist)
            
            # N-gram analysis (2-grams)
            if len(file_data) >= 2:
                bigram_hist = {}
                for i in range(len(file_data) - 1):
                    bigram = (file_data[i], file_data[i+1])
                    bigram_hist[bigram] = bigram_hist.get(bigram, 0) + 1
                
                features['bigram_count'] = len(bigram_hist)
                if bigram_hist:
                    bigram_values = list(bigram_hist.values())
                    features['bigram_mean'] = np.mean(bigram_values)
                    features['bigram_std'] = np.std(bigram_values)
        
        # String analysis
        try:
            text_content = file_data.decode('utf-8', errors='ignore')
            features['printable_chars_ratio'] = sum(1 for c in text_content if c.isprintable()) / max(len(text_content), 1)
            features['whitespace_ratio'] = sum(1 for c in text_content if c.isspace()) / max(len(text_content), 1)
            features['special_chars_ratio'] = sum(1 for c in text_content if not c.isalnum() and not c.isspace()) / max(len(text_content), 1)
        except:
            features['printable_chars_ratio'] = 0.0
            features['whitespace_ratio'] = 0.0
            features['special_chars_ratio'] = 0.0
        
        # Suspicious patterns
        suspicious_patterns = [
            b'MZ',  # PE header
            b'eval',  # JavaScript eval
            b'exec',  # Python exec
            b'shell',  # Shell commands
            b'powershell',  # PowerShell
            b'cmd.exe',  # Command prompt
        ]
        
        features['suspicious_pattern_count'] = 0
        for pattern in suspicious_patterns:
            if pattern in file_data:
                features['suspicious_pattern_count'] += 1
        
        # File path features (if available)
        if file_path:
            features['file_extension'] = os.path.splitext(file_path)[1].lower()
            features['path_depth'] = file_path.count(os.sep)
            suspicious_paths = ['temp', 'tmp', '$recycle.bin', 'appdata', 'programdata']
            features['suspicious_path'] = any(path in file_path.lower() for path in suspicious_paths)
        
        return features
    
    def prepare_features(self, features: Dict) -> np.ndarray:
        """
        Prepare features for model input
        
        Args:
            features: Dictionary of features
            
        Returns:
            Numpy array of prepared features
        """
        # Convert categorical features to numerical
        feature_vector = []
        feature_names = []
        
        # Numerical features
        numerical_features = [
            'file_size', 'byte_entropy', 'byte_mean', 'byte_std', 
            'byte_max', 'byte_min', 'bigram_count', 'bigram_mean', 
            'bigram_std', 'printable_chars_ratio', 'whitespace_ratio', 
            'special_chars_ratio', 'suspicious_pattern_count', 'path_depth'
        ]
        
        for feature_name in numerical_features:
            value = features.get(feature_name, 0)
            feature_vector.append(float(value) if value is not None else 0.0)
            feature_names.append(feature_name)
        
        # Categorical features
        categorical_features = ['file_extension']
        for feature_name in categorical_features:
            value = str(features.get(feature_name, ''))
            if feature_name not in self.label_encoders:
                self.label_encoders[feature_name] = LabelEncoder()
                # Fit with a default set of values to avoid issues
                self.label_encoders[feature_name].fit(['', '.exe', '.dll', '.pdf', '.doc', '.jpg'])
            
            try:
                encoded_value = self.label_encoders[feature_name].transform([value])[0]
            except ValueError:
                # Handle unknown categories
                encoded_value = -1
            
            feature_vector.append(float(encoded_value))
            feature_names.append(feature_name)
        
        # Boolean features
        boolean_features = ['suspicious_path']
        for feature_name in boolean_features:
            value = features.get(feature_name, False)
            feature_vector.append(1.0 if value else 0.0)
            feature_names.append(feature_name)
        
        self.feature_names = feature_names
        return np.array(feature_vector).reshape(1, -1)
    
    def train_ensemble_model(self, training_data: List[Dict], labels: List[int]):
        """
        Train an ensemble model with multiple algorithms
        
        Args:
            training_data: List of feature dictionaries
            labels: List of labels (0 for benign, 1 for malicious)
        """
        logger.info("Starting ensemble model training")
        
        # Prepare training data
        feature_vectors = []
        for data in training_data:
            features = self.prepare_features(data)
            feature_vectors.append(features.flatten())
        
        X = np.array(feature_vectors)
        y = np.array(labels)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        self.scalers['ensemble'] = scaler
        
        # Create individual models
        lgb_model = lgb.LGBMClassifier(
            n_estimators=100,
            learning_rate=0.05,
            num_leaves=31,
            random_state=42
        )
        
        xgb_model = xgb.XGBClassifier(
            n_estimators=100,
            learning_rate=0.05,
            max_depth=6,
            random_state=42
        )
        
        rf_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        
        # Create ensemble model
        ensemble_model = VotingClassifier(
            estimators=[
                ('lgb', lgb_model),
                ('xgb', xgb_model),
                ('rf', rf_model)
            ],
            voting='soft'
        )
        
        # Train ensemble model
        ensemble_model.fit(X_scaled, y)
        self.models['ensemble'] = ensemble_model
        
        logger.info("Ensemble model training completed")
        self.save_models()
    
    def predict(self, features: Dict) -> Tuple[float, str]:
        """
        Make a prediction using the ensemble model
        
        Args:
            features: Dictionary of features
            
        Returns:
            Tuple of (probability, verdict)
        """
        if 'ensemble' not in self.models:
            # Return a default response if no model is loaded
            logger.warning("No ensemble model loaded, returning default prediction")
            return 0.5, "unknown"
        
        try:
            # Prepare features
            feature_vector = self.prepare_features(features)
            
            # Scale features
            if 'ensemble' in self.scalers:
                feature_vector = self.scalers['ensemble'].transform(feature_vector)
            
            # Make prediction
            probability = self.models['ensemble'].predict_proba(feature_vector)[0]
            malicious_prob = probability[1] if len(probability) > 1 else 0.5
            
            # Convert to verdict
            if malicious_prob < 0.3:
                verdict = "clean"
            elif malicious_prob < 0.7:
                verdict = "suspicious"
            else:
                verdict = "malicious"
            
            return float(malicious_prob), verdict
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 0.5, "unknown"
    
    def train_model(self, training_data: List[Dict], labels: List[int]):
        """
        Train a new model (compatibility method)
        
        Args:
            training_data: List of feature dictionaries
            labels: List of labels (0 for benign, 1 for malicious)
        """
        self.train_ensemble_model(training_data, labels)
    
    def extract_features(self, ember_features: Dict) -> np.ndarray:
        """
        Extract features from EMBER-style features (compatibility method)
        
        Args:
            ember_features: Dictionary of EMBER features
            
        Returns:
            Numpy array of feature values
        """
        # Convert EMBER features to our format
        features = {}
        features['file_size'] = ember_features.get('size', 0)
        features['byte_entropy'] = ember_features.get('byte_entropy', 0)
        features['sections_count'] = ember_features.get('sections_count', 0)
        
        # Average section entropy
        sections = ember_features.get('sections', [])
        if sections:
            avg_entropy = np.mean([s.get('entropy', 0) for s in sections])
            features['byte_entropy'] = avg_entropy
        
        # Imports count
        imports = ember_features.get('imports', [])
        features['suspicious_pattern_count'] = len(imports)
        
        # Prepare features
        return self.prepare_features(features)
    
    def evaluate_model(self, test_data: List[Dict], labels: List[int]) -> Dict:
        """
        Evaluate the ensemble model on test data
        
        Args:
            test_data: List of feature dictionaries
            labels: List of true labels
            
        Returns:
            Dictionary of evaluation metrics
        """
        if 'ensemble' not in self.models:
            return {"error": "No ensemble model loaded"}
        
        # Prepare test data
        feature_vectors = []
        for data in test_data:
            features = self.prepare_features(data)
            feature_vectors.append(features.flatten())
        
        X = np.array(feature_vectors)
        y_true = np.array(labels)
        
        # Scale features
        if 'ensemble' in self.scalers:
            X = self.scalers['ensemble'].transform(X)
        
        # Make predictions
        y_pred_proba = self.models['ensemble'].predict_proba(X)
        y_pred = self.models['ensemble'].predict(X)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "sample_count": len(test_data)
        }

# Example usage
if __name__ == "__main__":
    # Initialize service
    ml_service = EnhancedMLService()
    
    # Example feature data
    example_data = b"This is a test file with some content that might be analyzed for malware detection."
    example_features = ml_service.extract_advanced_features(example_data, "C:\\test\\example.exe")
    
    print("Extracted features:")
    for key, value in example_features.items():
        print(f"  {key}: {value}")
    
    # Make prediction (will return default since no model is trained)
    probability, verdict = ml_service.predict(example_features)
    print(f"\nPrediction: {verdict} (probability: {probability})")