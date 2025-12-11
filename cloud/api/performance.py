#!/usr/bin/env python3
"""
AegisAI Performance Optimization Module

This module provides performance optimization features for the AegisAI cloud backend.
"""

import asyncio
import time
import functools
import logging
from typing import Any, Callable, Dict, Optional, Union
from collections import OrderedDict
import json
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PerformanceOptimizer:
    """Performance optimization manager"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the performance optimizer"""
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.cache = {}
        self.expiry_times = {}
        self.local_cache = LRUCache(
            max_size=self.config.get('caching', {}).get('local_cache', {}).get('max_size', 10000)
        )
        self.metrics_collector = MetricsCollector()
        self.rate_limiter = RateLimiter(
            requests_per_minute=self.config.get('api', {}).get('rate_limiting', {}).get('requests_per_minute', 1000)
        )
        
        # Start the rate limiter cleanup task
        # Note: This will be started when the event loop is available
        self._started = False
    
    def start(self):
        """Start the performance optimizer components that require an event loop"""
        if not self._started:
            self.rate_limiter.start_cleanup_task()
            self._started = True
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "database": {
                "connection_pool": {
                    "min_size": 10,
                    "max_size": 30
                }
            },
            "caching": {
                "local_cache": {
                    "max_size": 10000,
                    "ttl": 300
                }
            },
            "api": {
                "rate_limiting": {
                    "requests_per_minute": 1000
                }
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def cache_result(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Cache a result with optional TTL"""
        if ttl is None:
            ttl = self.config.get('caching', {}).get('local_cache', {}).get('ttl', 300)
        # Ensure ttl is an integer
        ttl_int = int(ttl) if ttl is not None else 300
        self.local_cache.put(key, value, ttl_int)
    
    def get_cached_result(self, key: str) -> Optional[Any]:
        """Get a cached result"""
        return self.local_cache.get(key)
    
    def is_rate_limited(self, client_id: str) -> bool:
        """Check if a client is rate limited"""
        return self.rate_limiter.is_limited(client_id)
    
    def record_metric(self, metric_name: str, value: float) -> None:
        """Record a performance metric"""
        self.metrics_collector.record(metric_name, value)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return self.metrics_collector.get_metrics()

class LRUCache:
    """LRU (Least Recently Used) cache implementation"""
    
    def __init__(self, max_size: int = 10000):
        """Initialize the LRU cache"""
        self.max_size = max_size
        self.cache = OrderedDict()
        self.expiry_times = {}
    
    def put(self, key: str, value: Any, ttl: int = 300) -> None:
        """Put a value in the cache"""
        # Remove expired entries
        self._cleanup_expired()
        
        # If cache is full, remove least recently used item
        if len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)
        
        # Add new item
        self.cache[key] = value
        self.expiry_times[key] = time.time() + ttl
        self.cache.move_to_end(key)  # Mark as recently used
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value from the cache"""
        # Remove expired entries
        self._cleanup_expired()
        
        if key in self.cache:
            # Move to end to mark as recently used
            self.cache.move_to_end(key)
            return self.cache[key]
        return None
    
    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache"""
        current_time = time.time()
        expired_keys = [
            key for key, expiry_time in self.expiry_times.items()
            if current_time > expiry_time
        ]
        
        for key in expired_keys:
            del self.cache[key]
            del self.expiry_times[key]

class RateLimiter:
    """Rate limiter implementation"""
    
    def __init__(self, requests_per_minute: int = 1000):
        """Initialize the rate limiter"""
        self.requests_per_minute = requests_per_minute
        self.client_requests = {}
        self.cleanup_task = None
        # We'll start the cleanup task when the event loop is running
    
    def start_cleanup_task(self):
        """Start the cleanup task when the event loop is available"""
        if self.cleanup_task is None:
            self.cleanup_task = asyncio.create_task(self._cleanup_old_requests())
    
    def is_limited(self, client_id: str) -> bool:
        """Check if a client is rate limited"""
        current_time = time.time()
        minute_ago = current_time - 60
        
        # Clean up old requests
        if client_id in self.client_requests:
            self.client_requests[client_id] = [
                timestamp for timestamp in self.client_requests[client_id]
                if timestamp > minute_ago
            ]
        else:
            self.client_requests[client_id] = []
        
        # Check if limit is exceeded
        if len(self.client_requests[client_id]) >= self.requests_per_minute:
            return True
        
        # Record this request
        self.client_requests[client_id].append(current_time)
        return False
    
    async def _cleanup_old_requests(self) -> None:
        """Periodically clean up old request records"""
        while True:
            await asyncio.sleep(300)  # Clean up every 5 minutes
            current_time = time.time()
            minute_ago = current_time - 60
            
            for client_id in list(self.client_requests.keys()):
                self.client_requests[client_id] = [
                    timestamp for timestamp in self.client_requests[client_id]
                    if timestamp > minute_ago
                ]
                
                # Remove empty client records
                if not self.client_requests[client_id]:
                    del self.client_requests[client_id]

class MetricsCollector:
    """Metrics collector for performance monitoring"""
    
    def __init__(self):
        """Initialize the metrics collector"""
        self.metrics = {}
        self.lock = asyncio.Lock()
    
    def record(self, metric_name: str, value: float) -> None:
        """Record a metric value"""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = {
                'count': 0,
                'sum': 0.0,
                'min': float('inf'),
                'max': float('-inf')
            }
        
        metric = self.metrics[metric_name]
        metric['count'] += 1
        metric['sum'] += value
        metric['min'] = min(metric['min'], value)
        metric['max'] = max(metric['max'], value)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        result = {}
        for name, metric in self.metrics.items():
            if metric['count'] > 0:
                result[name] = {
                    'count': metric['count'],
                    'average': metric['sum'] / metric['count'],
                    'min': metric['min'],
                    'max': metric['max'],
                    'sum': metric['sum']
                }
        return result

def performance_monitor(func: Callable) -> Callable:
    """Decorator to monitor function performance"""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            end_time = time.time()
            execution_time = end_time - start_time
            
            # Record metric (in a real implementation, this would use a global optimizer instance)
            logger.info(f"Function {func.__name__} executed in {execution_time:.4f} seconds")
    
    return wrapper

# Global performance optimizer instance
performance_optimizer = PerformanceOptimizer()

# Example usage
if __name__ == "__main__":
    # Create performance optimizer
    optimizer = PerformanceOptimizer()
    
    # Test caching
    optimizer.cache_result("test_key", "test_value", 60)
    cached_value = optimizer.get_cached_result("test_key")
    print(f"Cached value: {cached_value}")
    
    # Test rate limiting
    client_limited = optimizer.is_rate_limited("test_client")
    print(f"Client rate limited: {client_limited}")
    
    # Test metrics
    optimizer.record_metric("test_metric", 1.5)
    optimizer.record_metric("test_metric", 2.0)
    metrics = optimizer.get_metrics()
    print(f"Metrics: {metrics}")