#!/usr/bin/env python3
"""
AegisAI Refined ML Service
=========================

Enhanced machine learning service with improved model management,
feature extraction, and prediction capabilities.
"""

import os
import json
import logging
import hashlib
import pickle
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
import asyncio
from contextlib import asynccontextmanager

# Data processing
import numpy as np
import pandas as pd

# Machine learning
try:
    import lightgbm as lgb
    LGBM_AVAILABLE = True
except ImportError:
    lgb = None
    LGBM_AVAILABLE = False
    logging.warning("LightGBM not available - ML features disabled")

try:
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    accuracy_score = None
    precision_score = None
    recall_score = None
    f1_score = None
    roc_auc_score = None
    train_test_split = None
    StandardScaler = None
    SKLEARN_AVAILABLE = False
    logging.warning("scikit-learn not available - some ML features disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Enhanced feature extractor for malware analysis"""
    
    def __init__(self):
        self.feature_names = [
            'file_size',
            'byte_entropy',
            'sections_count',
            'avg_section_entropy',
            'max_section_entropy',
            'min_section_entropy',
            'imports_count',
            'exports_count',
            'resources_count',
            'version_info_present',
            'debug_info_present',
            'relocations_present',
            'tls_callbacks_present',
            'rich_header_present',
            'overlay_present',
            'overlay_size_ratio'
        ]
    
    def extract_features(self, file_data: bytes, metadata: Dict = None) -> np.ndarray:
        """
        Extract comprehensive features from file data.
        
        Args:
            file_data: Raw file data
            metadata: Additional metadata (optional)
            
        Returns:
            Numpy array of feature values
        """
        features = []
        
        # Basic file features
        file_size = len(file_data)
        features.append(file_size)
        
        # Byte entropy
        if file_size > 0:
            byte_counts = np.bincount(np.frombuffer(file_data[:1024], dtype=np.uint8), minlength=256)
            probabilities = byte_counts / np.sum(byte_counts)
            entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            features.append(entropy)
        else:
            features.append(0.0)
        
        # If metadata is provided, extract more detailed features
        if metadata and isinstance(metadata, dict):
            # Sections information
            sections = metadata.get('sections', [])
            features.append(len(sections))
            
            if sections:
                section_entropies = [s.get('entropy', 0) for s in sections]
                features.append(np.mean(section_entropies))
                features.append(np.max(section_entropies))
                features.append(np.min(section_entropies))
            else:
                features.extend([0.0, 0.0, 0.0])
            
            # Imports and exports
            imports = metadata.get('imports', [])
            exports = metadata.get('exports', [])
            features.append(len(imports))
            features.append(len(exports))
            
            # Resources
            resources = metadata.get('resources', [])
            features.append(len(resources))
            
            # PE header features
            features.append(1 if metadata.get('version_info') else 0)
            features.append(1 if metadata.get('debug_info') else 0)
            features.append(1 if metadata.get('relocations') else 0)
            features.append(1 if metadata.get('tls_callbacks') else 0)
            features.append(1 if metadata.get('rich_header') else 0)
            
            # Overlay information
            overlay = metadata.get('overlay', {})
            if overlay:
                features.append(1)
                overlay_size = overlay.get('size', 0)
                features.append(overlay_size / max(file_size, 1))
            else:
                features.extend([0, 0])
        else:
            # Default values when no metadata is provided
            features.extend([0, 0.0, 0.0, 0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        
        return np.array(features).reshape(1, -1)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.feature_names.copy()

class ModelManager:
    """Manages multiple ML models with versioning and evaluation"""
    
    def __init__(self, models_dir: str = "models"):
        self.models_dir = models_dir
        self.models = {}  # Loaded models
        self.model_metadata = {}  # Model metadata
        self.scalers = {}  # Feature scalers
        
        # Create models directory
        os.makedirs(models_dir, exist_ok=True)
        
        # Load existing models
        self._load_models()
    
    def _load_models(self):
        """Load existing models from disk."""
        try:
            # Look for model files
            for filename in os.listdir(self.models_dir):
                if filename.endswith('.pkl') or filename.endswith('.model'):
                    model_path = os.path.join(self.models_dir, filename)
                    self._load_model_from_file(model_path)
        except Exception as e:
            logger.error(f"Failed to load existing models: {e}")
    
    def _load_model_from_file(self, model_path: str):
        """Load a model from file."""
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            model_id = model_data.get('model_id')
            if not model_id:
                # Generate model ID from file hash
                with open(model_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
                model_id = f"model_{file_hash}"
            
            # Load model
            self.models[model_id] = model_data.get('model')
            self.model_metadata[model_id] = model_data.get('metadata', {})
            
            # Load scaler if present
            if 'scaler' in model_data:
                self.scalers[model_id] = model_data.get('scaler')
            
            logger.info(f"Loaded model {model_id} from {model_path}")
            
        except Exception as e:
            logger.error(f"Failed to load model from {model_path}: {e}")
    
    def save_model(self, model, model_id: str, metadata: Dict = None, scaler=None):
        """
        Save a model to disk.
        
        Args:
            model: Trained model object
            model_id: Unique identifier for the model
            metadata: Model metadata (optional)
            scaler: Feature scaler (optional)
        """
        try:
            model_path = os.path.join(self.models_dir, f"{model_id}.pkl")
            
            model_data = {
                'model_id': model_id,
                'model': model,
                'metadata': metadata or {},
                'scaler': scaler
            }
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            # Update in-memory storage
            self.models[model_id] = model
            self.model_metadata[model_id] = metadata or {}
            if scaler:
                self.scalers[model_id] = scaler
            
            logger.info(f"Saved model {model_id} to {model_path}")
            
        except Exception as e:
            logger.error(f"Failed to save model {model_id}: {e}")
    
    def load_model(self, model_id: str):
        """
        Load a specific model.
        
        Args:
            model_id: Model identifier
            
        Returns:
            Model object if found, None otherwise
        """
        if model_id in self.models:
            return self.models[model_id]
        
        # Try to load from disk
        model_path = os.path.join(self.models_dir, f"{model_id}.pkl")
        if os.path.exists(model_path):
            self._load_model_from_file(model_path)
            return self.models.get(model_id)
        
        return None
    
    def get_model_metadata(self, model_id: str) -> Optional[Dict]:
        """
        Get metadata for a model.
        
        Args:
            model_id: Model identifier
            
        Returns:
            Model metadata or None if not found
        """
        return self.model_metadata.get(model_id)
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List all available models.
        
        Returns:
            List of model information
        """
        models_info = []
        for model_id, metadata in self.model_metadata.items():
            model_info = {
                'model_id': model_id,
                'loaded': model_id in self.models,
                'metadata': metadata
            }
            models_info.append(model_info)
        return models_info

class ModelEvaluator:
    """Evaluates model performance with comprehensive metrics"""
    
    def __init__(self):
        pass
    
    def evaluate_model(self, model, X_test: np.ndarray, y_test: np.ndarray, 
                      scaler=None, feature_names: List[str] = None) -> Dict[str, Any]:
        """
        Evaluate model performance with comprehensive metrics.
        
        Args:
            model: Trained model
            X_test: Test features
            y_test: Test labels
            scaler: Feature scaler (optional)
            feature_names: Feature names for importance (optional)
            
        Returns:
            Dictionary of evaluation metrics
        """
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        try:
            # Apply scaling if provided
            if scaler:
                X_test = scaler.transform(X_test)
            
            # Make predictions
            y_pred_proba = model.predict(X_test)
            y_pred = (y_pred_proba > 0.5).astype(int)
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            # ROC AUC (if probabilities are available)
            try:
                roc_auc = roc_auc_score(y_test, y_pred_proba)
            except Exception:
                roc_auc = None
            
            # Feature importance (if available)
            feature_importance = {}
            if hasattr(model, 'feature_importance_') and feature_names:
                importance_scores = model.feature_importance_()
                for i, name in enumerate(feature_names):
                    if i < len(importance_scores):
                        feature_importance[name] = float(importance_scores[i])
            
            evaluation = {
                "accuracy": float(accuracy),
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
                "roc_auc": float(roc_auc) if roc_auc is not None else None,
                "sample_count": len(y_test),
                "feature_importance": feature_importance,
                "evaluation_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            return evaluation
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {"error": str(e)}

class RefinedMLService:
    """Refined AegisAI ML Service with enhanced capabilities"""
    
    def __init__(self, models_dir: str = "models"):
        """
        Initialize the refined ML service.
        
        Args:
            models_dir: Directory to store models
        """
        self.feature_extractor = FeatureExtractor()
        self.model_manager = ModelManager(models_dir)
        self.model_evaluator = ModelEvaluator()
        
        # Current active model
        self.active_model_id = None
        self.active_scaler = None
        
        # Load default model if available
        self._load_default_model()
        
        logger.info("Refined ML Service initialized")
    
    def _load_default_model(self):
        """Load default model if available."""
        models = self.model_manager.list_models()
        if models:
            # Use the first model as default
            default_model = models[0]
            self.active_model_id = default_model['model_id']
            logger.info(f"Loaded default model: {self.active_model_id}")
    
    def extract_features(self, file_data: bytes, metadata: Dict = None) -> np.ndarray:
        """
        Extract features from file data.
        
        Args:
            file_data: Raw file data
            metadata: Additional metadata (optional)
            
        Returns:
            Numpy array of feature values
        """
        return self.feature_extractor.extract_features(file_data, metadata)
    
    def predict(self, features: np.ndarray, model_id: str = None) -> Tuple[float, str]:
        """
        Make a prediction using the model.
        
        Args:
            features: Feature array for prediction
            model_id: Specific model to use (optional, uses active model if not specified)
            
        Returns:
            Tuple of (probability, verdict)
        """
        if not LGBM_AVAILABLE:
            logger.warning("LightGBM not available, returning default prediction")
            return 0.5, "unknown"
        
        # Determine which model to use
        if model_id is None:
            model_id = self.active_model_id
        
        if not model_id:
            logger.warning("No model loaded, returning default prediction")
            return 0.5, "unknown"
        
        # Load model if not already loaded
        model = self.model_manager.load_model(model_id)
        if not model:
            logger.error(f"Model {model_id} not found")
            return 0.5, "unknown"
        
        # Get scaler for this model
        scaler = self.model_manager.scalers.get(model_id)
        
        try:
            # Apply scaling if available
            if scaler:
                features = scaler.transform(features)
            
            # Make prediction
            probability = model.predict(features)[0]
            
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
    
    def train_model(self, training_data: List[Dict], labels: List[int], 
                   model_id: str = None, validation_split: float = 0.2) -> Dict[str, Any]:
        """
        Train a new model with comprehensive evaluation.
        
        Args:
            training_data: List of training data (file bytes and metadata)
            labels: List of labels (0 for benign, 1 for malicious)
            model_id: Model identifier (optional, auto-generated if not provided)
            validation_split: Fraction of data to use for validation
            
        Returns:
            Dictionary with training results and model information
        """
        if not LGBM_AVAILABLE or not SKLEARN_AVAILABLE:
            return {"error": "Required ML libraries not available"}
        
        try:
            logger.info("Starting model training")
            
            # Extract features from training data
            feature_vectors = []
            for data in training_data:
                if isinstance(data, dict):
                    file_data = data.get('file_data', b'')
                    metadata = data.get('metadata', {})
                else:
                    file_data = data
                    metadata = {}
                
                features = self.extract_features(file_data, metadata)
                feature_vectors.append(features.flatten())
            
            X = np.array(feature_vectors)
            y = np.array(labels)
            
            # Split data for validation
            if validation_split > 0:
                X_train, X_val, y_train, y_val = train_test_split(
                    X, y, test_size=validation_split, random_state=42, stratify=y
                )
            else:
                X_train, X_val, y_train, y_val = X, None, y, None
            
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            
            # Create LightGBM dataset
            train_data = lgb.Dataset(X_train_scaled, label=y_train)
            
            # Define parameters
            params = {
                'objective': 'binary',
                'metric': 'binary_logloss',
                'boosting_type': 'gbdt',
                'num_leaves': 31,
                'learning_rate': 0.05,
                'feature_fraction': 0.9,
                'bagging_fraction': 0.8,
                'bagging_freq': 5,
                'min_child_samples': 20,
                'verbose': -1
            }
            
            # Train model
            model = lgb.train(params, train_data, num_boost_round=100)
            
            # Generate model ID if not provided
            if not model_id:
                model_hash = hashlib.sha256(X_train.tobytes() + y_train.tobytes()).hexdigest()[:16]
                model_id = f"model_{datetime.now(timezone.utc).strftime('%Y%m%d')}_{model_hash}"
            
            # Save model
            metadata = {
                'training_samples': len(training_data),
                'features_count': X_train.shape[1],
                'feature_names': self.feature_extractor.get_feature_names(),
                'training_timestamp': datetime.now(timezone.utc).isoformat(),
                'params': params
            }
            
            self.model_manager.save_model(model, model_id, metadata, scaler)
            
            # Evaluate model if validation data is available
            evaluation = None
            if X_val is not None and y_val is not None:
                X_val_scaled = scaler.transform(X_val)
                evaluation = self.model_evaluator.evaluate_model(
                    model, X_val_scaled, y_val, 
                    scaler=None,  # Already scaled
                    feature_names=self.feature_extractor.get_feature_names()
                )
            
            # Set as active model
            self.active_model_id = model_id
            self.active_scaler = scaler
            
            logger.info(f"Model training completed: {model_id}")
            
            return {
                "status": "success",
                "model_id": model_id,
                "evaluation": evaluation,
                "metadata": metadata
            }
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            return {"error": str(e)}
    
    def evaluate_model(self, model_id: str, test_data: List[Dict], labels: List[int]) -> Dict[str, Any]:
        """
        Evaluate a specific model on test data.
        
        Args:
            model_id: Model identifier
            test_data: List of test data
            labels: List of true labels
            
        Returns:
            Dictionary of evaluation metrics
        """
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        try:
            # Load model
            model = self.model_manager.load_model(model_id)
            if not model:
                return {"error": f"Model {model_id} not found"}
            
            # Get scaler
            scaler = self.model_manager.scalers.get(model_id)
            
            # Extract features
            feature_vectors = []
            for data in test_data:
                if isinstance(data, dict):
                    file_data = data.get('file_data', b'')
                    metadata = data.get('metadata', {})
                else:
                    file_data = data
                    metadata = {}
                
                features = self.extract_features(file_data, metadata)
                feature_vectors.append(features.flatten())
            
            X = np.array(feature_vectors)
            y_true = np.array(labels)
            
            # Evaluate model
            evaluation = self.model_evaluator.evaluate_model(
                model, X, y_true, scaler,
                feature_names=self.feature_extractor.get_feature_names()
            )
            
            return evaluation
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {"error": str(e)}
    
    def set_active_model(self, model_id: str) -> bool:
        """
        Set the active model for predictions.
        
        Args:
            model_id: Model identifier
            
        Returns:
            True if successful, False otherwise
        """
        model = self.model_manager.load_model(model_id)
        if not model:
            logger.error(f"Cannot set active model: {model_id} not found")
            return False
        
        self.active_model_id = model_id
        self.active_scaler = self.model_manager.scalers.get(model_id)
        logger.info(f"Set active model to {model_id}")
        return True
    
    def get_model_info(self, model_id: str = None) -> Optional[Dict[str, Any]]:
        """
        Get information about a model.
        
        Args:
            model_id: Model identifier (optional, uses active model if not specified)
            
        Returns:
            Model information or None if not found
        """
        if model_id is None:
            model_id = self.active_model_id
        
        if not model_id:
            return None
        
        metadata = self.model_manager.get_model_metadata(model_id)
        if not metadata:
            return None
        
        return {
            'model_id': model_id,
            'metadata': metadata,
            'is_active': model_id == self.active_model_id
        }
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List all available models.
        
        Returns:
            List of model information
        """
        return self.model_manager.list_models()

# Example usage and testing
async def main():
    """Main function for testing the refined ML service."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create service
    ml_service = RefinedMLService()
    
    # Example feature extraction
    sample_data = b"This is a sample file for testing feature extraction"
    metadata = {
        'sections': [
            {'entropy': 7.2},
            {'entropy': 6.8}
        ],
        'imports': ['kernel32.dll', 'user32.dll'],
        'exports': ['function1', 'function2'],
        'resources': ['icon1', 'string_table']
    }
    
    features = ml_service.extract_features(sample_data, metadata)
    print(f"Extracted features shape: {features.shape}")
    
    # Make prediction (will return default since no model is loaded)
    probability, verdict = ml_service.predict(features)
    print(f"Prediction: {verdict} (probability: {probability})")
    
    # List available models
    models = ml_service.list_models()
    print(f"Available models: {len(models)}")

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())