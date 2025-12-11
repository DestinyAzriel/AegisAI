"""
AegisAI ML Service
==================

Machine learning service for AegisAI endpoint protection.
This service handles model training, evaluation, and inference.
"""

import lightgbm as lgb
import numpy as np
import pandas as pd
import json
import hashlib
from typing import Dict, List, Tuple
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MLService:
    """Machine learning service for malware detection"""
    
    def __init__(self, model_path: str = None):
        """
        Initialize the ML service
        
        Args:
            model_path: Path to pre-trained model (optional)
        """
        self.model = None
        self.feature_names = []
        
        if model_path:
            try:
                self.load_model(model_path)
                logger.info(f"Model loaded from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
    
    def load_model(self, model_path: str):
        """
        Load a pre-trained model
        
        Args:
            model_path: Path to the model file
        """
        self.model = lgb.Booster(model_file=model_path)
        # In a real implementation, we would also load feature names
        # This is a simplified version for demonstration
    
    def save_model(self, model_path: str):
        """
        Save the trained model
        
        Args:
            model_path: Path to save the model
        """
        if self.model:
            self.model.save_model(model_path)
            logger.info(f"Model saved to {model_path}")
    
    def extract_features(self, ember_features: Dict) -> np.ndarray:
        """
        Extract features from EMBER-style features
        
        Args:
            ember_features: Dictionary of EMBER features
            
        Returns:
            Numpy array of feature values
        """
        # This is a simplified feature extraction
        # A real implementation would extract many more features
        features = []
        
        # File size
        features.append(ember_features.get('size', 0))
        
        # Byte entropy
        features.append(ember_features.get('byte_entropy', 0))
        
        # Sections count
        features.append(ember_features.get('sections_count', 0))
        
        # Average section entropy
        sections = ember_features.get('sections', [])
        if sections:
            avg_entropy = np.mean([s.get('entropy', 0) for s in sections])
            features.append(avg_entropy)
        else:
            features.append(0)
        
        # Imports count
        imports = ember_features.get('imports', [])
        features.append(len(imports))
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, features: np.ndarray) -> Tuple[float, str]:
        """
        Make a prediction using the model
        
        Args:
            features: Feature array for prediction
            
        Returns:
            Tuple of (probability, verdict)
        """
        if not self.model:
            # Return a default response if no model is loaded
            logger.warning("No model loaded, returning default prediction")
            return 0.5, "unknown"
        
        try:
            # Make prediction
            probability = self.model.predict(features)[0]
            
            # Convert to verdict
            if probability < 0.3:
                verdict = "clean"
            elif probability < 0.7:
                verdict = "suspicious"
            else:
                verdict = "malicious"
            
            return float(probability), verdict
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return 0.5, "unknown"
    
    def train_model(self, training_data: List[Dict], labels: List[int]):
        """
        Train a new model
        
        Args:
            training_data: List of feature dictionaries
            labels: List of labels (0 for benign, 1 for malicious)
        """
        logger.info("Starting model training")
        
        # Extract features from training data
        feature_vectors = []
        for data in training_data:
            features = self.extract_features(data)
            feature_vectors.append(features.flatten())
        
        X = np.array(feature_vectors)
        y = np.array(labels)
        
        # Create LightGBM dataset
        train_data = lgb.Dataset(X, label=y)
        
        # Define parameters
        params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.9
        }
        
        # Train model
        self.model = lgb.train(params, train_data, num_boost_round=100)
        logger.info("Model training completed")
    
    def evaluate_model(self, test_data: List[Dict], labels: List[int]) -> Dict:
        """
        Evaluate the model on test data
        
        Args:
            test_data: List of feature dictionaries
            labels: List of true labels
            
        Returns:
            Dictionary of evaluation metrics
        """
        if not self.model:
            return {"error": "No model loaded"}
        
        # Extract features
        feature_vectors = []
        for data in test_data:
            features = self.extract_features(data)
            feature_vectors.append(features.flatten())
        
        X = np.array(feature_vectors)
        y_true = np.array(labels)
        
        # Make predictions
        y_pred_proba = self.model.predict(X)
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        # Calculate metrics
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
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
    ml_service = MLService()
    
    # Example feature data (simplified)
    example_features = {
        'size': 1024,
        'byte_entropy': 7.2,
        'sections_count': 3,
        'sections': [
            {'entropy': 6.5},
            {'entropy': 7.8},
            {'entropy': 2.1}
        ],
        'imports': ['kernel32.dll', 'user32.dll']
    }
    
    # Extract features
    features = ml_service.extract_features(example_features)
    print(f"Extracted features shape: {features.shape}")
    
    # Make prediction (will return default since no model is loaded)
    probability, verdict = ml_service.predict(features)
    print(f"Prediction: {verdict} (probability: {probability})")