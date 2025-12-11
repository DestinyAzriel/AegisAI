#!/usr/bin/env python3
"""
AegisAI Cache Client
====================

Client implementation that demonstrates how endpoint agents would interact
with the regional cache server for efficient updates and content delivery.
"""

import requests
import json
import hashlib
import time
import logging
from typing import Optional, Dict, Any

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CacheClient:
    """Client for interacting with the regional cache server"""
    
    def __init__(self, cache_server_url: str = "http://localhost:8082"):
        """
        Initialize cache client.
        
        Args:
            cache_server_url: URL of the regional cache server
        """
        self.cache_server_url = cache_server_url
        self.session = requests.Session()
    
    def list_cached_content(self) -> Optional[Dict]:
        """
        List all cached content.
        
        Returns:
            Dictionary of cached content or None if failed
        """
        try:
            response = self.session.get(f"{self.cache_server_url}/api/v1/cache/list")
            response.raise_for_status()
            return response.json().get('cached_content', {})
        except Exception as e:
            logger.error(f"Failed to list cached content: {e}")
            return None
    
    def get_content(self, content_id: str) -> Optional[bytes]:
        """
        Retrieve content from cache.
        
        Args:
            content_id: ID of content to retrieve
            
        Returns:
            Content bytes or None if failed
        """
        try:
            response = self.session.get(f"{self.cache_server_url}/api/v1/cache/content/{content_id}")
            response.raise_for_status()
            return response.content
        except Exception as e:
            logger.error(f"Failed to get content {content_id}: {e}")
            return None
    
    def get_content_metadata(self, content_id: str) -> Optional[Dict]:
        """
        Get metadata for cached content.
        
        Args:
            content_id: ID of content to get metadata for
            
        Returns:
            Content metadata or None if failed
        """
        try:
            response = self.session.get(f"{self.cache_server_url}/api/v1/cache/metadata/{content_id}")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get metadata for {content_id}: {e}")
            return None
    
    def cache_content(self, content_id: str, content: bytes, content_type: str) -> bool:
        """
        Cache content on the server.
        
        Args:
            content_id: ID for the content
            content: Content to cache
            content_type: Type of content
            
        Returns:
            True if successful, False otherwise
        """
        try:
            headers = {
                'X-Content-ID': content_id,
                'X-Content-Type': content_type
            }
            response = self.session.post(
                f"{self.cache_server_url}/api/v1/cache/content",
                data=content,
                headers=headers
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to cache content {content_id}: {e}")
            return False
    
    def get_cache_stats(self) -> Optional[Dict]:
        """
        Get cache statistics.
        
        Returns:
            Cache statistics or None if failed
        """
        try:
            response = self.session.get(f"{self.cache_server_url}/api/v1/cache/stats")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return None

class DeltaUpdateClient:
    """Client for handling delta updates"""
    
    def __init__(self, cache_client: CacheClient):
        """
        Initialize delta update client.
        
        Args:
            cache_client: Cache client instance
        """
        self.cache_client = cache_client
    
    def apply_delta_update(self, old_content_id: str, delta_content_id: str) -> Optional[bytes]:
        """
        Apply delta update to existing content.
        
        Args:
            old_content_id: ID of existing content
            delta_content_id: ID of delta update
            
        Returns:
            Updated content or None if failed
        """
        try:
            # Get the existing content
            old_content = self.cache_client.get_content(old_content_id)
            if old_content is None:
                logger.error(f"Failed to get existing content {old_content_id}")
                return None
            
            # Get the delta update
            delta_content = self.cache_client.get_content(delta_content_id)
            if delta_content is None:
                logger.error(f"Failed to get delta update {delta_content_id}")
                return None
            
            # In a real implementation, this would apply the delta patch
            # For this prototype, we'll just return the delta content
            logger.info(f"Applied delta update from {old_content_id} to {delta_content_id}")
            return delta_content
            
        except Exception as e:
            logger.error(f"Failed to apply delta update: {e}")
            return None
    
    def check_for_updates(self, current_version: str) -> Optional[Dict]:
        """
        Check for available updates.
        
        Args:
            current_version: Current version of content
            
        Returns:
            Update information or None if no updates available
        """
        try:
            # List cached content to find updates
            cached_content = self.cache_client.list_cached_content()
            if cached_content is None:
                return None
            
            # Look for newer versions
            # In a real implementation, this would be more sophisticated
            for content_id, metadata in cached_content.items():
                if content_id.startswith('sig_v') and content_id > f'sig_{current_version}':
                    return {
                        'available': True,
                        'new_version': content_id.replace('sig_', ''),
                        'content_id': content_id,
                        'size': metadata['size'],
                        'checksum': metadata['checksum']
                    }
            
            return {
                'available': False
            }
            
        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return None

class BandwidthOptimizer:
    """Optimizer for bandwidth usage"""
    
    def __init__(self):
        """Initialize bandwidth optimizer."""
        self.total_saved_bytes = 0
    
    def calculate_savings(self, original_size: int, update_size: int) -> Dict:
        """
        Calculate bandwidth savings from delta updates.
        
        Args:
            original_size: Size of original content
            update_size: Size of update (delta)
            
        Returns:
            Savings information
        """
        savings_bytes = original_size - update_size
        savings_percentage = (savings_bytes / original_size) * 100 if original_size > 0 else 0
        
        self.total_saved_bytes += savings_bytes
        
        return {
            'original_size': original_size,
            'update_size': update_size,
            'savings_bytes': savings_bytes,
            'savings_percentage': round(savings_percentage, 2),
            'total_saved_bytes': self.total_saved_bytes
        }

# Example usage and demonstration
def demonstrate_cache_functionality():
    """Demonstrate cache client functionality."""
    logger.info("Demonstrating regional cache client functionality...")
    
    # Initialize client
    cache_client = CacheClient("http://localhost:8082")
    delta_client = DeltaUpdateClient(cache_client)
    bandwidth_optimizer = BandwidthOptimizer()
    
    # Wait a moment for server to start
    time.sleep(2)
    
    # List cached content
    logger.info("Listing cached content...")
    cached_content = cache_client.list_cached_content()
    if cached_content:
        for content_id, metadata in cached_content.items():
            logger.info(f"  - {content_id}: {metadata['size']} bytes, {metadata['content_type']}")
    
    # Get specific content
    logger.info("Retrieving specific content...")
    content = cache_client.get_content('sig_v1.0.1')
    if content:
        logger.info(f"  Retrieved content: {content[:50]}...")
    
    # Check for updates
    logger.info("Checking for updates...")
    update_info = delta_client.check_for_updates('1.0.0')
    if update_info and update_info['available']:
        logger.info(f"  Update available: {update_info['new_version']}")
        
        # Calculate bandwidth savings
        original_size = 1000000  # 1MB original
        update_size = update_info['size']
        savings = bandwidth_optimizer.calculate_savings(original_size, update_size)
        logger.info(f"  Bandwidth savings: {savings['savings_percentage']}% ({savings['savings_bytes']} bytes)")
    
    # Apply delta update
    logger.info("Applying delta update...")
    updated_content = delta_client.apply_delta_update('sig_v1.0.0', 'delta_sig_v1.0.1')
    if updated_content:
        logger.info(f"  Applied delta update: {len(updated_content)} bytes")
    
    # Get cache statistics
    logger.info("Getting cache statistics...")
    stats = cache_client.get_cache_stats()
    if stats:
        logger.info(f"  Total items: {stats['total_items']}")
        logger.info(f"  Total size: {stats['total_size']} bytes")
        logger.info(f"  Total accesses: {stats['total_accesses']}")

if __name__ == "__main__":
    demonstrate_cache_functionality()