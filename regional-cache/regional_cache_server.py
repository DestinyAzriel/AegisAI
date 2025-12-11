#!/usr/bin/env python3
"""
AegisAI Regional Cache Server
=============================

Regional cache server for AegisAI that serves model deltas and signatures locally
to reduce bandwidth usage and latency for emerging markets.
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import threading
import time

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RegionalCacheDatabase:
    """Database for storing cached content and metadata"""
    
    def __init__(self, cache_dir: str = "cache"):
        """
        Initialize regional cache database.
        
        Args:
            cache_dir: Directory to store cached files
        """
        self.cache_dir = cache_dir
        self.metadata_file = os.path.join(cache_dir, "metadata.json")
        
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize metadata if it doesn't exist
        if not os.path.exists(self.metadata_file):
            self._initialize_metadata()
    
    def _initialize_metadata(self):
        """Initialize metadata file."""
        metadata = {
            'version': '1.0.0',
            'last_updated': datetime.now().isoformat(),
            'cached_content': {}
        }
        
        # Save metadata
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("Initialized regional cache metadata")
    
    def _load_metadata(self) -> Dict:
        """
        Load metadata from file.
        
        Returns:
            Metadata dictionary
        """
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
            return {}
    
    def _save_metadata(self, metadata: Dict):
        """
        Save metadata to file.
        
        Args:
            metadata: Metadata dictionary
        """
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def cache_content(self, content_id: str, content: bytes, content_type: str) -> bool:
        """
        Cache content in the regional cache.
        
        Args:
            content_id: Unique identifier for the content
            content: Content to cache
            content_type: Type of content (signature, model, etc.)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Save content to file
            content_file = os.path.join(self.cache_dir, f"{content_id}")
            with open(content_file, 'wb') as f:
                f.write(content)
            
            # Update metadata
            metadata = self._load_metadata()
            metadata['cached_content'][content_id] = {
                'content_type': content_type,
                'size': len(content),
                'checksum': self._calculate_checksum(content),
                'cached_at': datetime.now().isoformat(),
                'access_count': 0
            }
            metadata['last_updated'] = datetime.now().isoformat()
            
            self._save_metadata(metadata)
            
            logger.info(f"Cached content {content_id} ({len(content)} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cache content {content_id}: {e}")
            return False
    
    def get_cached_content(self, content_id: str) -> Optional[bytes]:
        """
        Retrieve cached content.
        
        Args:
            content_id: Unique identifier for the content
            
        Returns:
            Cached content or None if not found
        """
        try:
            content_file = os.path.join(self.cache_dir, f"{content_id}")
            if not os.path.exists(content_file):
                return None
            
            # Read content
            with open(content_file, 'rb') as f:
                content = f.read()
            
            # Update access count
            metadata = self._load_metadata()
            if content_id in metadata['cached_content']:
                metadata['cached_content'][content_id]['access_count'] += 1
                self._save_metadata(metadata)
            
            logger.info(f"Retrieved cached content {content_id} ({len(content)} bytes)")
            return content
            
        except Exception as e:
            logger.error(f"Failed to retrieve cached content {content_id}: {e}")
            return None
    
    def get_content_metadata(self, content_id: str) -> Optional[Dict]:
        """
        Get metadata for cached content.
        
        Args:
            content_id: Unique identifier for the content
            
        Returns:
            Content metadata or None if not found
        """
        try:
            metadata = self._load_metadata()
            return metadata['cached_content'].get(content_id)
        except Exception as e:
            logger.error(f"Failed to get metadata for {content_id}: {e}")
            return None
    
    def list_cached_content(self) -> Dict:
        """
        List all cached content.
        
        Returns:
            Dictionary of cached content metadata
        """
        try:
            metadata = self._load_metadata()
            return metadata['cached_content']
        except Exception as e:
            logger.error(f"Failed to list cached content: {e}")
            return {}
    
    def _calculate_checksum(self, content: bytes) -> str:
        """
        Calculate SHA-256 checksum of content.
        
        Args:
            content: Content to checksum
            
        Returns:
            SHA-256 checksum
        """
        return hashlib.sha256(content).hexdigest()

class DeltaUpdateGenerator:
    """Generator for delta updates"""
    
    def __init__(self):
        """Initialize delta update generator."""
        pass
    
    def generate_delta(self, old_content: bytes, new_content: bytes) -> bytes:
        """
        Generate delta between old and new content.
        
        Args:
            old_content: Old content
            new_content: New content
            
        Returns:
            Delta patch
        """
        # In a real implementation, this would use a binary diff algorithm like bsdiff
        # For this prototype, we'll just return the new content
        logger.info(f"Generated delta update ({len(new_content)} bytes)")
        return new_content
    
    def apply_delta(self, old_content: bytes, delta: bytes) -> bytes:
        """
        Apply delta to old content.
        
        Args:
            old_content: Old content
            delta: Delta patch
            
        Returns:
            Updated content
        """
        # In a real implementation, this would apply the delta patch
        # For this prototype, we'll just return the delta
        logger.info(f"Applied delta update ({len(delta)} bytes)")
        return delta

class RegionalCacheHandler(BaseHTTPRequestHandler):
    """HTTP handler for regional cache server"""
    
    def __init__(self, *args, **kwargs):
        # Initialize components
        self.cache_db = RegionalCacheDatabase()
        self.delta_generator = DeltaUpdateGenerator()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        # API routes
        if path == '/api/v1/cache/list':
            self._handle_list_cache()
        elif path.startswith('/api/v1/cache/content/'):
            content_id = path[len('/api/v1/cache/content/'):]
            self._handle_get_content(content_id)
        elif path.startswith('/api/v1/cache/metadata/'):
            content_id = path[len('/api/v1/cache/metadata/'):]
            self._handle_get_metadata(content_id)
        elif path == '/api/v1/cache/stats':
            self._handle_stats_request()
        else:
            self._handle_not_found()
    
    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/api/v1/cache/content':
            self._handle_cache_content()
        else:
            self._handle_not_found()
    
    def _handle_list_cache(self):
        """Handle list cache request."""
        try:
            cached_content = self.cache_db.list_cached_content()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                'cached_content': cached_content
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to handle list cache request: {e}")
            self._handle_internal_error()
    
    def _handle_get_content(self, content_id: str):
        """Handle get content request."""
        try:
            content = self.cache_db.get_cached_content(content_id)
            
            if content is None:
                self._handle_not_found()
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(content)
            
        except Exception as e:
            logger.error(f"Failed to handle get content request: {e}")
            self._handle_internal_error()
    
    def _handle_get_metadata(self, content_id: str):
        """Handle get metadata request."""
        try:
            metadata = self.cache_db.get_content_metadata(content_id)
            
            if metadata is None:
                self._handle_not_found()
                return
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps(metadata).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to handle get metadata request: {e}")
            self._handle_internal_error()
    
    def _handle_cache_content(self):
        """Handle cache content request."""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Read POST data
            post_data = self.rfile.read(content_length)
            
            # Parse JSON metadata from headers
            content_id = self.headers.get('X-Content-ID', f"content_{int(time.time())}")
            content_type = self.headers.get('X-Content-Type', 'unknown')
            
            # Cache the content
            success = self.cache_db.cache_content(content_id, post_data, content_type)
            
            if success:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                response = {
                    'status': 'success',
                    'content_id': content_id,
                    'message': 'Content cached successfully'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                self._handle_internal_error()
                
        except Exception as e:
            logger.error(f"Failed to handle cache content request: {e}")
            self._handle_internal_error()
    
    def _handle_stats_request(self):
        """Handle statistics request."""
        try:
            cached_content = self.cache_db.list_cached_content()
            
            total_size = sum(item['size'] for item in cached_content.values())
            total_items = len(cached_content)
            total_accesses = sum(item['access_count'] for item in cached_content.values())
            
            stats = {
                'total_items': total_items,
                'total_size': total_size,
                'total_accesses': total_accesses,
                'cached_content': cached_content
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps(stats).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to handle stats request: {e}")
            self._handle_internal_error()
    
    def _handle_not_found(self):
        """Handle 404 Not Found."""
        self.send_response(404)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'error': 'Not Found',
            'message': 'The requested resource was not found'
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def _handle_internal_error(self):
        """Handle 500 Internal Server Error."""
        self.send_response(500)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'error': 'Internal Server Error',
            'message': 'An internal server error occurred'
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(format % args)

class RegionalCacheServer:
    """AegisAI Regional Cache Server"""
    
    def __init__(self, host: str = 'localhost', port: int = 8082):
        """
        Initialize regional cache server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.server = None
        self.cache_db = RegionalCacheDatabase()
        self.delta_generator = DeltaUpdateGenerator()
    
    def start(self):
        """Start the regional cache server."""
        try:
            self.server = HTTPServer((self.host, self.port), RegionalCacheHandler)
            logger.info(f"Regional cache server started on {self.host}:{self.port}")
            logger.info(f"API endpoints:")
            logger.info(f"  - List cache: http://{self.host}:{self.port}/api/v1/cache/list")
            logger.info(f"  - Get content: http://{self.host}:{self.port}/api/v1/cache/content/<id>")
            logger.info(f"  - Get metadata: http://{self.host}:{self.port}/api/v1/cache/metadata/<id>")
            logger.info(f"  - Cache content: POST http://{self.host}:{self.port}/api/v1/cache/content")
            logger.info(f"  - Get stats: http://{self.host}:{self.port}/api/v1/cache/stats")
            
            self.server.serve_forever()
            
        except KeyboardInterrupt:
            logger.info("Regional cache server stopped by user")
        except Exception as e:
            logger.error(f"Failed to start regional cache server: {e}")
        finally:
            if self.server:
                self.server.server_close()
    
    def stop(self):
        """Stop the regional cache server."""
        if self.server:
            self.server.shutdown()
    
    def preload_content(self):
        """Preload some sample content for demonstration."""
        # Preload sample signatures
        signatures = {
            'sig_v1.0.0': b'{"version": "1.0.0", "signatures": {"eicar": "44d88612fea8a8f36de82e1278abb02f"}}',
            'sig_v1.0.1': b'{"version": "1.0.1", "signatures": {"eicar": "44d88612fea8a8f36de82e1278abb02f", "test": "abc123"}}'
        }
        
        for sig_id, sig_content in signatures.items():
            self.cache_db.cache_content(sig_id, sig_content, 'signature')
        
        # Preload sample models
        models = {
            'model_v1.0.0': b'MODEL_CONTENT_V1_0_0',
            'model_v1.0.1': b'MODEL_CONTENT_V1_0_1'
        }
        
        for model_id, model_content in models.items():
            self.cache_db.cache_content(model_id, model_content, 'model')
        
        logger.info("Preloaded sample content")

# Example usage
if __name__ == "__main__":
    # Create and start server
    server = RegionalCacheServer('localhost', 8082)
    
    # Preload some sample content
    server.preload_content()
    
    # Start server in a separate thread so we can demonstrate delta updates
    server_thread = threading.Thread(target=server.start)
    server_thread.daemon = True
    server_thread.start()
    
    # Give server time to start
    time.sleep(1)
    
    # Demonstrate delta update functionality
    logger.info("Demonstrating delta update functionality...")
    
    # In a real implementation, this would be done by the cloud core
    # to generate delta updates for distribution to regional caches
    delta_generator = DeltaUpdateGenerator()
    
    old_model = b"This is the old model content with some data"
    new_model = b"This is the new model content with updated data and more"
    
    delta = delta_generator.generate_delta(old_model, new_model)
    logger.info(f"Generated delta: {len(delta)} bytes")
    
    reconstructed = delta_generator.apply_delta(old_model, delta)
    logger.info(f"Reconstructed content matches: {reconstructed == new_model}")
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping regional cache server...")
        server.stop()