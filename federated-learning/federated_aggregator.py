#!/usr/bin/env python3
"""
AegisAI Federated Learning Aggregator
=====================================

Prototype implementation of a federated learning aggregator that demonstrates
privacy-preserving model training without raw data sharing.
"""

import numpy as np
import json
import hashlib
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import threading
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ClientUpdate:
    """Represents a client update with gradients and metadata"""
    client_id: str
    gradients: np.ndarray
    weights: float
    timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class AggregatedModel:
    """Represents an aggregated model"""
    weights: np.ndarray
    version: str
    timestamp: datetime
    client_count: int
    accuracy: float

class SecureAggregator:
    """Secure aggregator for federated learning"""
    
    def __init__(self, noise_multiplier: float = 0.1):
        """
        Initialize secure aggregator.
        
        Args:
            noise_multiplier: Multiplier for differential privacy noise
        """
        self.noise_multiplier = noise_multiplier
        self.client_updates = []
    
    def add_client_update(self, update: ClientUpdate):
        """
        Add a client update to the aggregator.
        
        Args:
            update: Client update to add
        """
        self.client_updates.append(update)
        logger.info(f"Added update from client {update.client_id}")
    
    def aggregate_updates(self, global_model: np.ndarray) -> AggregatedModel:
        """
        Aggregate client updates using secure aggregation.
        
        Args:
            global_model: Current global model weights
            
        Returns:
            Aggregated model
        """
        if not self.client_updates:
            logger.warning("No client updates to aggregate")
            return AggregatedModel(
                weights=global_model,
                version="0.0.0",
                timestamp=datetime.now(),
                client_count=0,
                accuracy=0.0
            )
        
        logger.info(f"Aggregating updates from {len(self.client_updates)} clients")
        
        # Simple averaging aggregation (in a real implementation, this would use
        # secure multi-party computation and differential privacy)
        weighted_gradients = []
        total_weight = 0.0
        
        for update in self.client_updates:
            weighted_gradients.append(update.gradients * update.weights)
            total_weight += update.weights
        
        if total_weight > 0:
            avg_gradients = sum(weighted_gradients) / total_weight
        else:
            avg_gradients = np.zeros_like(global_model)
        
        # Apply differential privacy noise
        if self.noise_multiplier > 0:
            noise = np.random.normal(0, self.noise_multiplier, avg_gradients.shape)
            avg_gradients += noise
            logger.info(f"Applied differential privacy noise (multiplier: {self.noise_multiplier})")
        
        # Update global model
        new_weights = global_model + avg_gradients
        
        # Create aggregated model
        aggregated_model = AggregatedModel(
            weights=new_weights,
            version=self._generate_version(),
            timestamp=datetime.now(),
            client_count=len(self.client_updates),
            accuracy=self._calculate_accuracy()  # Simulated accuracy
        )
        
        # Clear processed updates
        self.client_updates.clear()
        
        logger.info(f"Aggregated model version {aggregated_model.version} created")
        return aggregated_model
    
    def _generate_version(self) -> str:
        """Generate a version string for the aggregated model."""
        timestamp = int(time.time())
        return f"1.0.{timestamp}"
    
    def _calculate_accuracy(self) -> float:
        """Calculate simulated model accuracy."""
        # In a real implementation, this would be based on validation data
        return np.random.uniform(0.85, 0.95)

class ModelValidator:
    """Validator for model updates"""
    
    def __init__(self, threshold: float = 0.1):
        """
        Initialize model validator.
        
        Args:
            threshold: Threshold for detecting anomalous updates
        """
        self.threshold = threshold
    
    def validate_update(self, update: ClientUpdate, global_model: np.ndarray) -> bool:
        """
        Validate a client update.
        
        Args:
            update: Client update to validate
            global_model: Current global model
            
        Returns:
            True if update is valid, False otherwise
        """
        # Check for anomalous gradients (simple check)
        gradient_norm = np.linalg.norm(update.gradients)
        global_norm = np.linalg.norm(global_model)
        
        if global_norm > 0:
            ratio = gradient_norm / global_norm
            if ratio > self.threshold:
                logger.warning(f"Anomalous update detected from client {update.client_id} (ratio: {ratio})")
                return False
        
        # Check for NaN or infinite values
        if not np.isfinite(update.gradients).all():
            logger.warning(f"Invalid gradients from client {update.client_id}")
            return False
        
        logger.info(f"Update from client {update.client_id} validated successfully")
        return True

class FederatedLearningAggregator:
    """Main federated learning aggregator"""
    
    def __init__(self, model_shape: tuple = (100,), learning_rate: float = 0.01):
        """
        Initialize federated learning aggregator.
        
        Args:
            model_shape: Shape of the model weights
            learning_rate: Learning rate for model updates
        """
        self.model_shape = model_shape
        self.learning_rate = learning_rate
        self.global_model = np.random.normal(0, 0.1, model_shape)
        self.model_version = "0.0.1"
        self.aggregator = SecureAggregator()
        self.validator = ModelValidator()
        self.client_registry = {}
        self.round_count = 0
        
        logger.info(f"Initialized federated learning aggregator with model shape {model_shape}")
    
    def register_client(self, client_id: str, client_info: Dict[str, Any]) -> bool:
        """
        Register a client with the aggregator.
        
        Args:
            client_id: Unique client identifier
            client_info: Client information
            
        Returns:
            True if registration successful, False otherwise
        """
        if client_id in self.client_registry:
            logger.warning(f"Client {client_id} already registered")
            return False
        
        self.client_registry[client_id] = {
            'info': client_info,
            'last_seen': datetime.now(),
            'update_count': 0
        }
        
        logger.info(f"Registered client {client_id}")
        return True
    
    def submit_update(self, client_id: str, gradients: np.ndarray, metadata: Dict[str, Any] = None) -> bool:
        """
        Submit a client update to the aggregator.
        
        Args:
            client_id: Client identifier
            gradients: Client gradients
            metadata: Additional metadata
            
        Returns:
            True if submission successful, False otherwise
        """
        # Verify client is registered
        if client_id not in self.client_registry:
            logger.warning(f"Unregistered client {client_id} attempted to submit update")
            return False
        
        # Update client registry
        self.client_registry[client_id]['last_seen'] = datetime.now()
        self.client_registry[client_id]['update_count'] += 1
        
        # Create client update
        update = ClientUpdate(
            client_id=client_id,
            gradients=gradients,
            weights=1.0,  # In a real implementation, this would be based on data size
            timestamp=datetime.now(),
            metadata=metadata or {}
        )
        
        # Validate update
        if not self.validator.validate_update(update, self.global_model):
            logger.warning(f"Invalid update from client {client_id} rejected")
            return False
        
        # Add to aggregator
        self.aggregator.add_client_update(update)
        logger.info(f"Update from client {client_id} accepted")
        return True
    
    def run_aggregation_round(self) -> Optional[AggregatedModel]:
        """
        Run a federated learning aggregation round.
        
        Returns:
            Aggregated model or None if no updates available
        """
        self.round_count += 1
        logger.info(f"Starting aggregation round {self.round_count}")
        
        # Perform aggregation
        aggregated_model = self.aggregator.aggregate_updates(self.global_model)
        
        if aggregated_model.client_count > 0:
            # Update global model
            self.global_model = aggregated_model.weights
            self.model_version = aggregated_model.version
            
            logger.info(f"Aggregation round {self.round_count} completed")
            logger.info(f"  - Clients: {aggregated_model.client_count}")
            logger.info(f"  - Accuracy: {aggregated_model.accuracy:.4f}")
            logger.info(f"  - Model version: {aggregated_model.version}")
            
            return aggregated_model
        else:
            logger.info(f"Aggregation round {self.round_count} skipped (no updates)")
            return None
    
    def get_model(self) -> Dict[str, Any]:
        """
        Get the current global model.
        
        Returns:
            Current global model information
        """
        return {
            'weights': self.global_model.tolist(),
            'version': self.model_version,
            'shape': self.model_shape,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_client_stats(self) -> Dict[str, Any]:
        """
        Get client statistics.
        
        Returns:
            Client statistics
        """
        total_clients = len(self.client_registry)
        active_clients = sum(1 for client in self.client_registry.values() 
                           if (datetime.now() - client['last_seen']).total_seconds() < 3600)
        
        return {
            'total_clients': total_clients,
            'active_clients': active_clients,
            'round_count': self.round_count
        }

class FederatedClientSimulator:
    """Simulator for federated learning clients"""
    
    def __init__(self, client_id: str, model_shape: tuple = (100,)):
        """
        Initialize client simulator.
        
        Args:
            client_id: Client identifier
            model_shape: Shape of the model
        """
        self.client_id = client_id
        self.model_shape = model_shape
        self.local_model = np.random.normal(0, 0.1, model_shape)
        self.data_size = np.random.randint(100, 1000)
        
        logger.info(f"Initialized client simulator {client_id}")
    
    def compute_gradients(self, global_model: np.ndarray) -> np.ndarray:
        """
        Compute gradients based on local data and global model.
        
        Args:
            global_model: Global model weights
            
        Returns:
            Computed gradients
        """
        # Simulate local training
        # In a real implementation, this would involve actual training on local data
        noise = np.random.normal(0, 0.01, self.model_shape)
        gradients = (self.local_model - global_model) + noise
        
        logger.info(f"Client {self.client_id} computed gradients ({np.linalg.norm(gradients):.4f})")
        return gradients
    
    def update_local_model(self, aggregated_model: np.ndarray):
        """
        Update local model with aggregated model.
        
        Args:
            aggregated_model: Aggregated model weights
        """
        self.local_model = np.array(aggregated_model)
        logger.info(f"Client {self.client_id} updated local model")

# Example usage and demonstration
def demonstrate_federated_learning():
    """Demonstrate federated learning functionality."""
    logger.info("Demonstrating federated learning aggregator...")
    
    # Initialize aggregator
    aggregator = FederatedLearningAggregator(model_shape=(50,), learning_rate=0.01)
    
    # Register clients
    client_ids = [f"client_{i}" for i in range(3)]
    clients = []
    
    for client_id in client_ids:
        # Register client with aggregator
        aggregator.register_client(client_id, {'platform': 'windows', 'version': '1.0.0'})
        
        # Create client simulator
        client = FederatedClientSimulator(client_id, model_shape=(50,))
        clients.append(client)
    
    # Simulate multiple rounds of federated learning
    for round_num in range(3):
        logger.info(f"=== Federated Learning Round {round_num + 1} ===")
        
        # Each client computes and submits gradients
        for client in clients:
            gradients = client.compute_gradients(aggregator.global_model)
            metadata = {
                'data_size': client.data_size,
                'round': round_num + 1
            }
            aggregator.submit_update(client.client_id, gradients, metadata)
        
        # Aggregator runs aggregation round
        aggregated_model = aggregator.run_aggregation_round()
        
        if aggregated_model:
            # Clients update their local models
            for client in clients:
                client.update_local_model(aggregated_model.weights)
            
            # Print round statistics
            stats = aggregator.get_client_stats()
            logger.info(f"Round {round_num + 1} statistics:")
            logger.info(f"  - Clients: {stats['total_clients']}")
            logger.info(f"  - Active: {stats['active_clients']}")
            logger.info(f"  - Model accuracy: {aggregated_model.accuracy:.4f}")
    
    # Print final model information
    model_info = aggregator.get_model()
    logger.info("Final model information:")
    logger.info(f"  - Version: {model_info['version']}")
    logger.info(f"  - Shape: {model_info['shape']}")
    logger.info(f"  - Weight norm: {np.linalg.norm(np.array(model_info['weights'])):.4f}")

if __name__ == "__main__":
    demonstrate_federated_learning()