"""
Behavioral Analysis Optimizer for AegisAI
Optimizes behavioral analysis algorithms for real-time processing
"""

import os
import sys
import time
import logging
import numpy as np
from typing import Dict, List, Any
from pathlib import Path
from collections import deque

# Add the core directory to the path
sys.path.insert(0, str(Path(__file__).parent))

# Try to import required libraries
SKLEARN_AVAILABLE = False
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    logging.warning("Scikit-learn not available. Some optimization features will be disabled.")

logger = logging.getLogger(__name__)

class BehavioralAnalysisOptimizer:
    """Optimize behavioral analysis algorithms for real-time processing"""
    
    def __init__(self):
        """Initialize the behavioral analysis optimizer"""
        self.optimization_settings = {
            'enable_caching': True,
            'cache_size': 1000,
            'enable_batch_processing': True,
            'batch_size': 50,
            'enable_preprocessing_optimization': True,
            'enable_model_compression': True
        }
        
        # Initialize caches
        self.feature_cache = {}
        self.result_cache = {}
        self.cache_timestamps = {}
        
        # For batch processing
        self.batch_queue = deque()
        self.batch_timer = time.time()
        
        # Performance metrics
        self.performance_metrics = {
            'cache_hits': 0,
            'cache_misses': 0,
            'batch_processing_count': 0,
            'optimization_savings': 0.0
        }
    
    def optimize_feature_extraction(self, behavioral_data: Dict) -> Dict:
        """
        Optimize feature extraction for behavioral analysis
        
        Args:
            behavioral_data: Dictionary containing behavioral metrics
            
        Returns:
            Optimized feature vector
        """
        # Create a cache key from the behavioral data
        cache_key = self._create_cache_key(behavioral_data)
        
        # Check if we have this in cache
        if self.optimization_settings['enable_caching'] and cache_key in self.feature_cache:
            self.performance_metrics['cache_hits'] += 1
            return self.feature_cache[cache_key]
        
        self.performance_metrics['cache_misses'] += 1
        
        # Extract features with optimization
        feature_vector = self._extract_optimized_features(behavioral_data)
        
        # Cache the result if caching is enabled
        if self.optimization_settings['enable_caching']:
            self.feature_cache[cache_key] = feature_vector
            self.cache_timestamps[cache_key] = time.time()
            
            # Manage cache size
            if len(self.feature_cache) > self.optimization_settings['cache_size']:
                self._manage_cache()
        
        return feature_vector
    
    def _create_cache_key(self, behavioral_data: Dict) -> str:
        """
        Create a cache key from behavioral data
        
        Args:
            behavioral_data: Dictionary containing behavioral metrics
            
        Returns:
            String cache key
        """
        # Create a simple hash of the behavioral data values
        key_parts = []
        for key in sorted(behavioral_data.keys()):
            key_parts.append(f"{key}:{behavioral_data[key]}")
        return "|".join(key_parts)
    
    def _extract_optimized_features(self, behavioral_data: Dict) -> Dict:
        """
        Extract optimized features from behavioral data
        
        Args:
            behavioral_data: Dictionary containing behavioral metrics
            
        Returns:
            Optimized feature vector
        """
        # Start timing
        start_time = time.time()
        
        # Extract only the most relevant features for performance
        optimized_features = {
            'file_operations': behavioral_data.get('file_operations', 0),
            'network_connections': behavioral_data.get('network_connections', 0),
            'cpu_usage': behavioral_data.get('cpu_usage', 0.0),
            'memory_usage': behavioral_data.get('memory_usage', 0.0),
            'child_processes': behavioral_data.get('child_processes', 0),
            'registry_modifications': behavioral_data.get('registry_modifications', 0)
        }
        
        # Add derived features that are computationally inexpensive
        optimized_features['operations_ratio'] = (
            optimized_features['file_operations'] / max(optimized_features['network_connections'], 1)
        )
        
        optimized_features['resource_usage'] = (
            optimized_features['cpu_usage'] + optimized_features['memory_usage']
        ) / 2.0
        
        # End timing
        extraction_time = time.time() - start_time
        
        # Store timing information
        optimized_features['_extraction_time'] = extraction_time
        
        return optimized_features
    
    def _manage_cache(self):
        """Manage cache size by removing oldest entries"""
        if not self.cache_timestamps:
            return
        
        # Sort cache entries by timestamp
        sorted_entries = sorted(self.cache_timestamps.items(), key=lambda x: x[1])
        
        # Remove oldest entries to maintain cache size
        entries_to_remove = len(sorted_entries) - self.optimization_settings['cache_size']
        for i in range(entries_to_remove):
            key_to_remove = sorted_entries[i][0]
            if key_to_remove in self.feature_cache:
                del self.feature_cache[key_to_remove]
            if key_to_remove in self.cache_timestamps:
                del self.cache_timestamps[key_to_remove]
    
    def optimize_batch_processing(self, behavioral_data: Dict) -> List[Dict]:
        """
        Optimize batch processing of behavioral data
        
        Args:
            behavioral_data: Dictionary containing behavioral metrics
            
        Returns:
            List of processed results
        """
        if not self.optimization_settings['enable_batch_processing']:
            # Process immediately if batch processing is disabled
            return [self.optimize_feature_extraction(behavioral_data)]
        
        # Add to batch queue
        self.batch_queue.append(behavioral_data)
        
        # Check if we should process the batch
        current_time = time.time()
        should_process = (
            len(self.batch_queue) >= self.optimization_settings['batch_size'] or
            (current_time - self.batch_timer) > 5.0  # 5 seconds timeout
        )
        
        if should_process:
            # Process batch
            results = self._process_batch()
            self.batch_timer = current_time
            self.performance_metrics['batch_processing_count'] += 1
            return results
        
        # Return empty list if not processing yet
        return []
    
    def _process_batch(self) -> List[Dict]:
        """
        Process a batch of behavioral data
        
        Returns:
            List of processed results
        """
        if not self.batch_queue:
            return []
        
        results = []
        batch_data = list(self.batch_queue)
        self.batch_queue.clear()
        
        # Process all items in the batch
        for data in batch_data:
            result = self.optimize_feature_extraction(data)
            results.append(result)
        
        return results
    
    def optimize_model_performance(self, model: Any) -> Any:
        """
        Optimize ML model performance for real-time processing
        
        Args:
            model: ML model to optimize
            
        Returns:
            Optimized model
        """
        if not self.optimization_settings['enable_model_compression']:
            return model
        
        # For scikit-learn models, we can try to reduce complexity
        if SKLEARN_AVAILABLE and hasattr(model, 'set_params'):
            try:
                # Reduce the number of estimators for ensemble methods
                if hasattr(model, 'n_estimators'):
                    original_estimators = model.n_estimators
                    model.set_params(n_estimators=max(10, original_estimators // 2))
                    logger.info(f"Reduced model estimators from {original_estimators} to {model.n_estimators}")
                
                # Reduce max depth for tree-based models
                if hasattr(model, 'max_depth') and model.max_depth:
                    original_depth = model.max_depth
                    model.set_params(max_depth=max(3, original_depth // 2))
                    logger.info(f"Reduced model max_depth from {original_depth} to {model.max_depth}")
                    
            except Exception as e:
                logger.warning(f"Failed to optimize model parameters: {e}")
        
        return model
    
    def get_performance_metrics(self) -> Dict:
        """
        Get performance metrics for the optimizer
        
        Returns:
            Dictionary with performance metrics
        """
        metrics = self.performance_metrics.copy()
        
        # Calculate cache hit ratio
        total_cache_ops = metrics['cache_hits'] + metrics['cache_misses']
        if total_cache_ops > 0:
            metrics['cache_hit_ratio'] = metrics['cache_hits'] / total_cache_ops
        else:
            metrics['cache_hit_ratio'] = 0.0
        
        # Calculate average batch size
        if metrics['batch_processing_count'] > 0:
            metrics['average_batch_size'] = len(self.batch_queue) / metrics['batch_processing_count']
        else:
            metrics['average_batch_size'] = 0.0
        
        return metrics
    
    def reset_performance_metrics(self):
        """Reset performance metrics to zero"""
        self.performance_metrics = {
            'cache_hits': 0,
            'cache_misses': 0,
            'batch_processing_count': 0,
            'optimization_savings': 0.0
        }

def main():
    """Main function to demonstrate behavioral analysis optimization"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("           AEGISAI BEHAVIORAL ANALYSIS OPTIMIZER")
    print("=" * 70)
    
    # Initialize optimizer
    optimizer = BehavioralAnalysisOptimizer()
    
    # Test feature extraction optimization
    print("Testing feature extraction optimization...")
    
    # Sample behavioral data
    sample_data = {
        'file_operations': 25,
        'network_connections': 8,
        'cpu_usage': 35.0,
        'memory_usage': 180.0,
        'child_processes': 3,
        'registry_modifications': 2
    }
    
    # Extract features multiple times to test caching
    print("Extracting features (first time - cache miss)...")
    start_time = time.time()
    features1 = optimizer.optimize_feature_extraction(sample_data)
    time1 = time.time() - start_time
    print(f"First extraction took {time1:.6f} seconds")
    
    print("Extracting features (second time - cache hit)...")
    start_time = time.time()
    features2 = optimizer.optimize_feature_extraction(sample_data)
    time2 = time.time() - start_time
    print(f"Second extraction took {time2:.6f} seconds")
    
    print(f"Cache optimization saved {time1 - time2:.6f} seconds")
    
    # Test batch processing
    print("\nTesting batch processing optimization...")
    batch_results = []
    for i in range(10):
        data = sample_data.copy()
        data['file_operations'] += i
        result = optimizer.optimize_batch_processing(data)
        batch_results.extend(result)
    
    print(f"Processed {len(batch_results)} items in batches")
    
    # Show performance metrics
    metrics = optimizer.get_performance_metrics()
    print("\nPerformance Metrics:")
    print(f"  Cache Hits: {metrics['cache_hits']}")
    print(f"  Cache Misses: {metrics['cache_misses']}")
    print(f"  Cache Hit Ratio: {metrics.get('cache_hit_ratio', 0.0):.2f}")
    print(f"  Batch Processing Count: {metrics['batch_processing_count']}")
    
    print("\n" + "=" * 70)
    print("BEHAVIORAL ANALYSIS OPTIMIZATION COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()