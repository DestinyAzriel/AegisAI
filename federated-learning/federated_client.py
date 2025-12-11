#!/usr/bin/env python3
"""
AegisAI Federated Learning Client
=================================

Client implementation that demonstrates how endpoint agents would participate
in federated learning while preserving user privacy.
"""

import numpy as np
import json
import hashlib
import logging
import requests
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class LocalTrainingData:
    """Represents local training data"""
    features: np.ndarray
    labels: np.ndarray
    sample_count: int

class PrivacyEngine:
    """Engine for privacy-preserving techniques"""
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize privacy engine.
        
        Args:
            epsilon: Privacy budget parameter
            delta: Privacy failure probability
        """
        self.epsilon = epsilon
        self.delta = delta
        logger.info(f"Initialized privacy engine with ε={epsilon}, δ={delta}")
    
    def add_noise(self, gradients: np.ndarray, sensitivity: float = 1.0) -> np.ndarray:
        """
        Add differential privacy noise to gradients.
        
        Args:
            gradients: Gradients to add noise to
            sensitivity: L2 sensitivity of the gradients
            
        Returns:
            Noisy gradients
        """
        # Calculate noise scale using Gaussian mechanism
        noise_scale = sensitivity * np.sqrt(2 * np.log(1.25 / self.delta)) / self.epsilon
        
        # Add Gaussian noise
        noise = np.random.normal(0, noise_scale, gradients.shape)
        noisy_gradients = gradients + noise
        
        logger.info(f"Added differential privacy noise (scale: {noise_scale:.6f})")
        return noisy_gradients
    
    def clip_gradients(self, gradients: np.ndarray, clip_norm: float = 1.0) -> np.ndarray:
        """
        Clip gradients to limit sensitivity.
        
        Args:
            gradients: Gradients to clip
            clip_norm: Maximum L2 norm
            
        Returns:
            Clipped gradients
        """
        grad_norm = np.linalg.norm(gradients)
        if grad_norm > clip_norm:
            clipped_gradients = gradients * (clip_norm / grad_norm)
            logger.info(f"Clipped gradients from {grad_norm:.4f} to {clip_norm:.4f}")
            return clipped_gradients
        return gradients

class LocalTrainer:
    """Local model trainer for federated learning"""
    
    def __init__(self, model_shape: tuple = (100,), learning_rate: float = 0.01):
        """
        Initialize local trainer.
        
        Args:
            model_shape: Shape of the model weights
            learning_rate: Learning rate for training
        """
        self.model_shape = model_shape
        self.learning_rate = learning_rate
        self.local_model = np.random.normal(0, 0.1, model_shape)
        self.privacy_engine = PrivacyEngine()
        self.training_history = []
        
        logger.info(f"Initialized local trainer with model shape {model_shape}")
    
    def generate_training_data(self, sample_count: int = 100) -> LocalTrainingData:
        """
        Generate synthetic training data for demonstration.
        
        Args:
            sample_count: Number of samples to generate
            
        Returns:
            Generated training data
        """
        # Generate synthetic features (in a real implementation, this would be actual data)
        features = np.random.normal(0, 1, (sample_count, self.model_shape[0] - 1))
        
        # Generate synthetic labels based on a simple rule
        # In a real implementation, this would be based on actual threat detection
        weights = np.random.normal(0, 1, self.model_shape[0] - 1)
        logits = np.dot(features, weights)
        probabilities = 1 / (1 + np.exp(-logits))
        labels = (probabilities > 0.5).astype(int)
        
        logger.info(f"Generated {sample_count} training samples")
        return LocalTrainingData(features, labels, sample_count)
    
    def compute_gradients(self, global_model: np.ndarray, training_data: LocalTrainingData) -> np.ndarray:
        """
        Compute gradients using local training data.
        
        Args:
            global_model: Global model weights
            training_data: Local training data
            
        Returns:
            Computed gradients
        """
        # Simple logistic regression gradient computation
        features = training_data.features
        labels = training_data.labels
        
        # Add bias term
        bias = np.ones((features.shape[0], 1))
        features_with_bias = np.hstack([features, bias])
        
        # Compute predictions
        logits = np.dot(features_with_bias, global_model)
        predictions = 1 / (1 + np.exp(-np.clip(logits, -250, 250)))  # Clip to prevent overflow
        
        # Compute gradients
        errors = predictions - labels
        gradients = np.dot(features_with_bias.T, errors) / len(labels)
        
        # Apply privacy protections
        gradients = self.privacy_engine.clip_gradients(gradients)
        gradients = self.privacy_engine.add_noise(gradients)
        
        logger.info(f"Computed gradients (L2 norm: {np.linalg.norm(gradients):.4f})")
        return gradients
    
    def update_local_model(self, global_model: np.ndarray):
        """
        Update local model with global model.
        
        Args:
            global_model: New global model weights
        """
        self.local_model = np.array(global_model)
        logger.info("Updated local model with global model")

class FederatedLearningClient:
    """Main federated learning client"""
    
    def __init__(self, client_id: str, aggregator_url: str = "http://localhost:8085"):
        """
        Initialize federated learning client.
        
        Args:
            client_id: Unique client identifier
            aggregator_url: URL of the federated learning aggregator
        """
        self.client_id = client_id
        self.aggregator_url = aggregator_url
        self.session = requests.Session()
        self.local_trainer = LocalTrainer()
        self.participation_count = 0
        self.consent_granted = False
        
        logger.info(f"Initialized federated learning client {client_id}")
    
    def request_consent(self) -> bool:
        """
        Request user consent for federated learning participation.
        
        Returns:
            True if consent granted, False otherwise
        """
        # In a real implementation, this would display a consent dialog to the user
        logger.info("Requesting user consent for federated learning...")
        
        # For this prototype, we'll simulate consent being granted
        self.consent_granted = True
        logger.info("User consent granted for federated learning")
        return self.consent_granted
    
    def get_global_model(self) -> Optional[Dict[str, Any]]:
        """
        Get the current global model from the aggregator.
        
        Returns:
            Global model information or None if failed
        """
        try:
            response = self.session.get(f"{self.aggregator_url}/api/v1/model")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get global model: {e}")
            return None
    
    def submit_gradients(self, gradients: np.ndarray, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Submit computed gradients to the aggregator.
        
        Args:
            gradients: Computed gradients
            metadata: Additional metadata
            
        Returns:
            True if submission successful, False otherwise
        """
        try:
            # Prepare submission data
            submission_data = {
                'client_id': self.client_id,
                'gradients': gradients.tolist(),
                'metadata': metadata or {}
            }
            
            response = self.session.post(
                f"{self.aggregator_url}/api/v1/updates",
                json=submission_data
            )
            response.raise_for_status()
            
            logger.info(f"Submitted gradients to aggregator")
            return True
            
        except Exception as e:
            logger.error(f"Failed to submit gradients: {e}")
            return False
    
    def participate_in_round(self) -> bool:
        """
        Participate in a federated learning round.
        
        Returns:
            True if participation successful, False otherwise
        """
        # Check if user has consented
        if not self.consent_granted:
            logger.warning("User has not consented to federated learning")
            return False
        
        self.participation_count += 1
        logger.info(f"Participating in federated learning round {self.participation_count}")
        
        # Get global model
        global_model_info = self.get_global_model()
        if not global_model_info:
            logger.error("Failed to get global model")
            return False
        
        global_model = np.array(global_model_info['weights'])
        logger.info(f"Retrieved global model version {global_model_info['version']}")
        
        # Generate local training data
        training_data = self.local_trainer.generate_training_data(sample_count=50)
        
        # Compute gradients
        gradients = self.local_trainer.compute_gradients(global_model, training_data)
        
        # Submit gradients
        metadata = {
            'sample_count': training_data.sample_count,
            'round': self.participation_count,
            'timestamp': datetime.now().isoformat()
        }
        
        success = self.submit_gradients(gradients, metadata)
        if success:
            logger.info(f"Successfully participated in round {self.participation_count}")
        else:
            logger.error(f"Failed to participate in round {self.participation_count}")
        
        return success
    
    def update_local_model(self) -> bool:
        """
        Update local model with the latest global model.
        
        Returns:
            True if update successful, False otherwise
        """
        # Get global model
        global_model_info = self.get_global_model()
        if not global_model_info:
            logger.error("Failed to get global model for local update")
            return False
        
        global_model = np.array(global_model_info['weights'])
        
        # Update local trainer
        self.local_trainer.update_local_model(global_model)
        
        logger.info(f"Updated local model to version {global_model_info['version']}")
        return True

# Example usage and demonstration
def demonstrate_federated_client():
    """Demonstrate federated learning client functionality."""
    logger.info("Demonstrating federated learning client...")
    
    # Initialize client
    client = FederatedLearningClient("test_client_001", "http://localhost:8085")
    
    # Request consent
    if client.request_consent():
        logger.info("Client is ready to participate in federated learning")
        
        # Participate in a few rounds
        for round_num in range(3):
            logger.info(f"=== Federated Learning Round {round_num + 1} ===")
            
            # Participate in round
            success = client.participate_in_round()
            
            if success:
                # Update local model
                client.update_local_model()
                
                # Simulate some time between rounds
                time.sleep(1)
            else:
                logger.error(f"Failed to participate in round {round_num + 1}")
    else:
        logger.info("Client will not participate in federated learning")

if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        # Run a simple test
        client = FederatedLearningClient("test_client_001", "http://localhost:8085")
        if client.request_consent():
            logger.info("Client test successful")
        else:
            logger.error("Client test failed")
    else:
        demonstrate_federated_client()
