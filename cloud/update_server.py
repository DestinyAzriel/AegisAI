"""
AegisAI Update Server
Simple HTTP server for delivering signature and model updates
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

class UpdateServerHandler(BaseHTTPRequestHandler):
    """HTTP handler for AegisAI update server"""
    
    def __init__(self, *args, **kwargs):
        # Set server directories
        self.signatures_dir = os.path.join(os.path.dirname(__file__), 'signatures')
        self.models_dir = os.path.join(os.path.dirname(__file__), 'models')
        self.metadata_file = os.path.join(os.path.dirname(__file__), 'metadata.json')
        
        # Create directories if they don't exist
        os.makedirs(self.signatures_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        
        # Initialize metadata if it doesn't exist
        if not os.path.exists(self.metadata_file):
            self._initialize_metadata()
        
        super().__init__(*args, **kwargs)
    
    def _initialize_metadata(self):
        """Initialize metadata file."""
        metadata = {
            'version': '1.0.0',
            'last_updated': datetime.now().isoformat(),
            'signatures': {
                'latest': 'signatures_v1.0.0.json',
                'checksum': '',
                'size': 0
            },
            'models': {
                'latest': 'model_v1.0.0.pkl',
                'checksum': '',
                'size': 0
            }
        }
        
        # Create default signature file
        default_signatures = {
            'metadata': {
                'version': '1.0.0',
                'last_updated': datetime.now().isoformat(),
                'signature_count': 1
            },
            'signatures': {
                'eicar_test_signature': {
                    'name': 'EICAR Test File',
                    'hash': '44d88612fea8a8f36de82e1278abb02f',
                    'severity': 'test',
                    'description': 'Standard antivirus test file',
                    'source': 'default'
                }
            }
        }
        
        signature_file = os.path.join(self.signatures_dir, 'signatures_v1.0.0.json')
        with open(signature_file, 'w') as f:
            json.dump(default_signatures, f, indent=2)
        
        # Update metadata
        metadata['signatures']['checksum'] = self._calculate_file_checksum(signature_file)
        metadata['signatures']['size'] = os.path.getsize(signature_file)
        
        # Save metadata
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info("Initialized update server metadata")
    
    def _calculate_file_checksum(self, file_path: str) -> str:
        """
        Calculate SHA-256 checksum of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA-256 checksum
        """
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate checksum for {file_path}: {e}")
            return ''
    
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
    
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        # API routes
        if path == '/api/v1/metadata':
            self._handle_metadata_request()
        elif path == '/api/v1/signatures/latest':
            self._handle_signature_download()
        elif path == '/api/v1/models/latest':
            self._handle_model_download()
        else:
            self._handle_not_found()
    
    def _handle_metadata_request(self):
        """Handle metadata request."""
        try:
            metadata = self._load_metadata()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps(metadata).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to handle metadata request: {e}")
            self._handle_internal_error()
    
    def _handle_signature_download(self):
        """Handle signature file download."""
        try:
            metadata = self._load_metadata()
            signature_file = metadata['signatures']['latest']
            signature_path = os.path.join(self.signatures_dir, signature_file)
            
            if not os.path.exists(signature_path):
                self._handle_not_found()
                return
            
            # Send file
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(os.path.getsize(signature_path)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            with open(signature_path, 'rb') as f:
                self.wfile.write(f.read())
                
        except Exception as e:
            logger.error(f"Failed to handle signature download: {e}")
            self._handle_internal_error()
    
    def _handle_model_download(self):
        """Handle model file download."""
        try:
            metadata = self._load_metadata()
            model_file = metadata['models']['latest']
            model_path = os.path.join(self.models_dir, model_file)
            
            if not os.path.exists(model_path):
                self._handle_not_found()
                return
            
            # Send file
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Length', str(os.path.getsize(model_path)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            with open(model_path, 'rb') as f:
                self.wfile.write(f.read())
                
        except Exception as e:
            logger.error(f"Failed to handle model download: {e}")
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

class UpdateServer:
    """AegisAI Update Server"""
    
    def __init__(self, host: str = 'localhost', port: int = 8080):
        """
        Initialize update server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.server = None
    
    def start(self):
        """Start the update server."""
        try:
            self.server = HTTPServer((self.host, self.port), UpdateServerHandler)
            logger.info(f"Update server started on {self.host}:{self.port}")
            logger.info(f"API endpoints:")
            logger.info(f"  - Metadata: http://{self.host}:{self.port}/api/v1/metadata")
            logger.info(f"  - Signatures: http://{self.host}:{self.port}/api/v1/signatures/latest")
            logger.info(f"  - Models: http://{self.host}:{self.port}/api/v1/models/latest")
            
            self.server.serve_forever()
            
        except KeyboardInterrupt:
            logger.info("Update server stopped by user")
        except Exception as e:
            logger.error(f"Failed to start update server: {e}")
        finally:
            if self.server:
                self.server.server_close()
    
    def stop(self):
        """Stop the update server."""
        if self.server:
            self.server.shutdown()

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start server
    server = UpdateServer('localhost', 8080)
    server.start()