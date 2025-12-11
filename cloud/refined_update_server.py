#!/usr/bin/env python3
"""
AegisAI Refined Update Server
============================

Enhanced update distribution server with improved security,
performance, and reliability features.
"""

import os
import json
import hashlib
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import secrets
import base64

# Web framework
try:
    from aiohttp import web, ClientSession
    AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    ClientSession = None
    AIOHTTP_AVAILABLE = False
    logging.warning("aiohttp not available - web server features disabled")

# Data compression
try:
    import gzip
    GZIP_AVAILABLE = True
except ImportError:
    gzip = None
    GZIP_AVAILABLE = False
    logging.warning("gzip not available - compression features disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UpdateMetadataManager:
    """Manages update metadata with versioning and signing"""
    
    def __init__(self, metadata_file: str = "metadata.json"):
        self.metadata_file = metadata_file
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict:
        """Load metadata from file or create default."""
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
        
        # Return default metadata
        return {
            'version': '1.0.0',
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'signatures': {
                'versions': {},
                'latest': None
            },
            'models': {
                'versions': {},
                'latest': None
            },
            'agent': {
                'versions': {},
                'latest': None
            }
        }
    
    def _save_metadata(self):
        """Save metadata to file."""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def add_signature_version(self, version: str, filename: str, checksum: str, size: int):
        """Add a new signature version."""
        if 'signatures' not in self.metadata:
            self.metadata['signatures'] = {'versions': {}, 'latest': None}
        
        self.metadata['signatures']['versions'][version] = {
            'filename': filename,
            'checksum': checksum,
            'size': size,
            'released': datetime.now(timezone.utc).isoformat()
        }
        
        # Update latest version
        self.metadata['signatures']['latest'] = version
        self.metadata['last_updated'] = datetime.now(timezone.utc).isoformat()
        
        self._save_metadata()
        logger.info(f"Added signature version {version}")
    
    def add_model_version(self, version: str, filename: str, checksum: str, size: int):
        """Add a new model version."""
        if 'models' not in self.metadata:
            self.metadata['models'] = {'versions': {}, 'latest': None}
        
        self.metadata['models']['versions'][version] = {
            'filename': filename,
            'checksum': checksum,
            'size': size,
            'released': datetime.now(timezone.utc).isoformat()
        }
        
        # Update latest version
        self.metadata['models']['latest'] = version
        self.metadata['last_updated'] = datetime.now(timezone.utc).isoformat()
        
        self._save_metadata()
        logger.info(f"Added model version {version}")
    
    def add_agent_version(self, version: str, filename: str, checksum: str, size: int, platform: str):
        """Add a new agent version."""
        if 'agent' not in self.metadata:
            self.metadata['agent'] = {'versions': {}, 'latest': None}
        
        if version not in self.metadata['agent']['versions']:
            self.metadata['agent']['versions'][version] = {}
        
        self.metadata['agent']['versions'][version][platform] = {
            'filename': filename,
            'checksum': checksum,
            'size': size,
            'released': datetime.now(timezone.utc).isoformat()
        }
        
        # Update latest version
        self.metadata['agent']['latest'] = version
        self.metadata['last_updated'] = datetime.now(timezone.utc).isoformat()
        
        self._save_metadata()
        logger.info(f"Added agent version {version} for platform {platform}")
    
    def get_metadata(self) -> Dict:
        """Get current metadata."""
        return self.metadata.copy()
    
    def get_latest_signature_version(self) -> Optional[Dict]:
        """Get the latest signature version info."""
        if (self.metadata.get('signatures', {}).get('latest') and 
            self.metadata['signatures']['latest'] in self.metadata['signatures']['versions']):
            version = self.metadata['signatures']['latest']
            return self.metadata['signatures']['versions'][version]
        return None
    
    def get_latest_model_version(self) -> Optional[Dict]:
        """Get the latest model version info."""
        if (self.metadata.get('models', {}).get('latest') and 
            self.metadata['models']['latest'] in self.metadata['models']['versions']):
            version = self.metadata['models']['latest']
            return self.metadata['models']['versions'][version]
        return None
    
    def get_latest_agent_version(self, platform: str) -> Optional[Dict]:
        """Get the latest agent version info for a platform."""
        if (self.metadata.get('agent', {}).get('latest') and 
            self.metadata['agent']['latest'] in self.metadata['agent']['versions']):
            version = self.metadata['agent']['latest']
            platform_versions = self.metadata['agent']['versions'][version]
            if platform in platform_versions:
                return platform_versions[platform]
        return None

class UpdateSecurity:
    """Security features for update distribution"""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(32)
        self.blocked_ips = set()
        self.rate_limits = {}
    
    def generate_download_token(self, resource: str, expires_in: int = 3600) -> str:
        """
        Generate a time-limited download token.
        
        Args:
            resource: Resource identifier
            expires_in: Token expiration time in seconds
            
        Returns:
            Download token
        """
        expiry = int(datetime.now(timezone.utc).timestamp()) + expires_in
        data = f"{resource}:{expiry}"
        signature = hashlib.sha256(f"{data}:{self.secret_key}".encode()).hexdigest()
        token = f"{base64.b64encode(data.encode()).decode()}.{signature}"
        return token
    
    def verify_download_token(self, token: str, resource: str) -> bool:
        """
        Verify a download token.
        
        Args:
            token: Download token
            resource: Expected resource identifier
            
        Returns:
            True if token is valid, False otherwise
        """
        try:
            # Split token into data and signature
            data_b64, signature = token.split('.')
            data = base64.b64decode(data_b64.encode()).decode()
            
            # Check if resource matches
            token_resource, expiry_str = data.split(':')
            if token_resource != resource:
                return False
            
            # Check if token has expired
            expiry = int(expiry_str)
            if datetime.now(timezone.utc).timestamp() > expiry:
                return False
            
            # Verify signature
            expected_signature = hashlib.sha256(f"{data}:{self.secret_key}".encode()).hexdigest()
            return signature == expected_signature
            
        except Exception:
            return False
    
    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if a client is rate limited.
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if client is allowed, False if rate limited
        """
        current_time = datetime.now(timezone.utc).timestamp()
        window_start = current_time - 60  # 1 minute window
        
        # Clean up old requests
        if client_id in self.rate_limits:
            self.rate_limits[client_id] = [
                timestamp for timestamp in self.rate_limits[client_id]
                if timestamp > window_start
            ]
        else:
            self.rate_limits[client_id] = []
        
        # Check rate limit (10 requests per minute)
        if len(self.rate_limits[client_id]) >= 10:
            logger.warning(f"Rate limit exceeded for update client: {client_id}")
            return False
        
        # Record this request
        self.rate_limits[client_id].append(current_time)
        return True
    
    def check_ip_blocking(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is allowed, False if blocked
        """
        if ip_address in self.blocked_ips:
            logger.warning(f"Blocked update request from IP: {ip_address}")
            return False
        return True

class UpdateCacheManager:
    """Manages caching of update files for performance"""
    
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = cache_dir
        self.cache_metadata = {}
        
        # Create cache directory
        os.makedirs(cache_dir, exist_ok=True)
        
        # Load cache metadata
        self._load_cache_metadata()
    
    def _load_cache_metadata(self):
        """Load cache metadata from file."""
        metadata_file = os.path.join(self.cache_dir, "cache_metadata.json")
        try:
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    self.cache_metadata = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load cache metadata: {e}")
    
    def _save_cache_metadata(self):
        """Save cache metadata to file."""
        metadata_file = os.path.join(self.cache_dir, "cache_metadata.json")
        try:
            with open(metadata_file, 'w') as f:
                json.dump(self.cache_metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache metadata: {e}")
    
    def cache_file(self, file_path: str, cache_key: str) -> bool:
        """
        Cache a file for faster serving.
        
        Args:
            file_path: Path to the file to cache
            cache_key: Key to identify the cached file
            
        Returns:
            True if caching was successful, False otherwise
        """
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                return False
            
            # Create cached file path
            cached_file_path = os.path.join(self.cache_dir, f"{cache_key}.cache")
            
            # Copy file to cache
            with open(file_path, 'rb') as src, open(cached_file_path, 'wb') as dst:
                dst.write(src.read())
            
            # Update metadata
            self.cache_metadata[cache_key] = {
                'original_path': file_path,
                'cached_path': cached_file_path,
                'size': os.path.getsize(file_path),
                'cached_at': datetime.now(timezone.utc).isoformat()
            }
            
            self._save_cache_metadata()
            logger.info(f"Cached file {file_path} with key {cache_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cache file {file_path}: {e}")
            return False
    
    def get_cached_file(self, cache_key: str) -> Optional[str]:
        """
        Get path to cached file.
        
        Args:
            cache_key: Key to identify the cached file
            
        Returns:
            Path to cached file if available, None otherwise
        """
        if cache_key in self.cache_metadata:
            cached_path = self.cache_metadata[cache_key]['cached_path']
            if os.path.exists(cached_path):
                return cached_path
        return None
    
    def invalidate_cache(self, cache_key: str):
        """
        Invalidate a cached file.
        
        Args:
            cache_key: Key to identify the cached file
        """
        if cache_key in self.cache_metadata:
            cached_path = self.cache_metadata[cache_key]['cached_path']
            if os.path.exists(cached_path):
                os.remove(cached_path)
            del self.cache_metadata[cache_key]
            self._save_cache_metadata()
            logger.info(f"Invalidated cache for key {cache_key}")

class RefinedUpdateServer:
    """Refined AegisAI Update Server with enhanced features"""
    
    def __init__(self, host: str = 'localhost', port: int = 8082):
        """
        Initialize update server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.metadata_manager = UpdateMetadataManager()
        self.security = UpdateSecurity()
        self.cache_manager = UpdateCacheManager()
        
        # Set update directories
        self.signatures_dir = os.path.join(os.path.dirname(__file__), 'signatures')
        self.models_dir = os.path.join(os.path.dirname(__file__), 'models')
        self.agent_dir = os.path.join(os.path.dirname(__file__), 'agent')
        
        # Create directories if they don't exist
        os.makedirs(self.signatures_dir, exist_ok=True)
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.agent_dir, exist_ok=True)
        
        # Initialize with default content if needed
        self._initialize_default_content()
        
        self.app = None
        self.runner = None
        self.site = None
    
    def _initialize_default_content(self):
        """Initialize with default content if directories are empty."""
        # Check if signatures directory is empty
        if not os.listdir(self.signatures_dir):
            self._create_default_signatures()
        
        # Check if models directory is empty
        if not os.listdir(self.models_dir):
            self._create_default_model()
        
        # Check if agent directory is empty
        if not os.listdir(self.agent_dir):
            self._create_default_agent()
    
    def _create_default_signatures(self):
        """Create default signature file."""
        default_signatures = {
            'metadata': {
                'version': '1.0.0',
                'last_updated': datetime.now(timezone.utc).isoformat(),
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
        
        # Calculate checksum
        checksum = self._calculate_file_checksum(signature_file)
        size = os.path.getsize(signature_file)
        
        # Add to metadata
        self.metadata_manager.add_signature_version('1.0.0', 'signatures_v1.0.0.json', checksum, size)
        
        logger.info("Created default signature file")
    
    def _create_default_model(self):
        """Create default model file."""
        # Create a simple placeholder model file
        model_content = {
            'model_type': 'placeholder',
            'version': '1.0.0',
            'features': ['size', 'entropy'],
            'description': 'Default placeholder model'
        }
        
        model_file = os.path.join(self.models_dir, 'model_v1.0.0.json')
        with open(model_file, 'w') as f:
            json.dump(model_content, f, indent=2)
        
        # Calculate checksum
        checksum = self._calculate_file_checksum(model_file)
        size = os.path.getsize(model_file)
        
        # Add to metadata
        self.metadata_manager.add_model_version('1.0.0', 'model_v1.0.0.json', checksum, size)
        
        logger.info("Created default model file")
    
    def _create_default_agent(self):
        """Create default agent files for different platforms."""
        platforms = ['windows', 'linux', 'macos']
        
        for platform in platforms:
            # Create a simple placeholder agent file
            agent_content = {
                'agent_type': 'placeholder',
                'platform': platform,
                'version': '1.0.0',
                'description': f'Default placeholder agent for {platform}'
            }
            
            agent_file = os.path.join(self.agent_dir, f'aegisai-agent-{platform}_v1.0.0.json')
            with open(agent_file, 'w') as f:
                json.dump(agent_content, f, indent=2)
            
            # Calculate checksum
            checksum = self._calculate_file_checksum(agent_file)
            size = os.path.getsize(agent_file)
            
            # Add to metadata
            self.metadata_manager.add_agent_version('1.0.0', f'aegisai-agent-{platform}_v1.0.0.json', checksum, size, platform)
        
        logger.info("Created default agent files")
    
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
    
    async def start(self):
        """Start the update server."""
        try:
            if not AIOHTTP_AVAILABLE:
                logger.error("aiohttp not available, cannot start update server")
                return
            
            # Create aiohttp application
            self.app = web.Application()
            
            # Set up routes
            self.app.router.add_get('/api/v1/metadata', self._handle_metadata_request)
            self.app.router.add_get('/api/v1/signatures/latest', self._handle_signature_download)
            self.app.router.add_get('/api/v1/models/latest', self._handle_model_download)
            self.app.router.add_get('/api/v1/agent/latest/{platform}', self._handle_agent_download)
            self.app.router.add_get('/api/v1/signatures/{version}', self._handle_signature_download_version)
            self.app.router.add_get('/api/v1/models/{version}', self._handle_model_download_version)
            self.app.router.add_get('/api/v1/agent/{version}/{platform}', self._handle_agent_download_version)
            
            # Set up middleware
            self.app.middlewares.append(self._security_middleware)
            
            # Start server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            
            logger.info(f"Refined update server started on {self.host}:{self.port}")
            logger.info(f"API endpoints:")
            logger.info(f"  - Metadata: http://{self.host}:{self.port}/api/v1/metadata")
            logger.info(f"  - Latest signatures: http://{self.host}:{self.port}/api/v1/signatures/latest")
            logger.info(f"  - Latest models: http://{self.host}:{self.port}/api/v1/models/latest")
            logger.info(f"  - Latest agent (platform): http://{self.host}:{self.port}/api/v1/agent/latest/{{platform}}")
            
        except Exception as e:
            logger.error(f"Failed to start update server: {e}")
    
    async def stop(self):
        """Stop the update server."""
        try:
            # Stop server
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            
            logger.info("Refined update server stopped")
        except Exception as e:
            logger.error(f"Error stopping update server: {e}")
    
    async def _security_middleware(self, app: web.Application, handler):
        """Security middleware for request validation."""
        async def middleware_handler(request: web.Request):
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            
            # Check if IP is blocked
            if not self.security.check_ip_blocking(client_ip):
                return web.json_response({
                    'error': 'Forbidden',
                    'message': 'IP address blocked'
                }, status=403)
            
            # Check rate limiting
            client_id = request.headers.get('X-Client-ID', 'unknown')
            if not self.security.check_rate_limit(client_id):
                return web.json_response({
                    'error': 'Too Many Requests',
                    'message': 'Rate limit exceeded'
                }, status=429)
            
            return await handler(request)
        
        return middleware_handler
    
    async def _handle_metadata_request(self, request: web.Request) -> web.Response:
        """Handle metadata request."""
        try:
            metadata = self.metadata_manager.get_metadata()
            
            return web.json_response(metadata)
            
        except Exception as e:
            logger.error(f"Failed to handle metadata request: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_signature_download(self, request: web.Request) -> web.Response:
        """Handle latest signature file download."""
        try:
            # Get latest signature version
            signature_info = self.metadata_manager.get_latest_signature_version()
            if not signature_info:
                return web.json_response({
                    'error': 'Not Found',
                    'message': 'No signature versions available'
                }, status=404)
            
            filename = signature_info['filename']
            signature_path = os.path.join(self.signatures_dir, filename)
            
            return await self._serve_file(signature_path, filename, signature_info['checksum'])
                
        except Exception as e:
            logger.error(f"Failed to handle signature download: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_model_download(self, request: web.Request) -> web.Response:
        """Handle latest model file download."""
        try:
            # Get latest model version
            model_info = self.metadata_manager.get_latest_model_version()
            if not model_info:
                return web.json_response({
                    'error': 'Not Found',
                    'message': 'No model versions available'
                }, status=404)
            
            filename = model_info['filename']
            model_path = os.path.join(self.models_dir, filename)
            
            return await self._serve_file(model_path, filename, model_info['checksum'])
                
        except Exception as e:
            logger.error(f"Failed to handle model download: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_agent_download(self, request: web.Request) -> web.Response:
        """Handle latest agent file download for a platform."""
        try:
            platform = request.match_info['platform']
            
            # Get latest agent version for platform
            agent_info = self.metadata_manager.get_latest_agent_version(platform)
            if not agent_info:
                return web.json_response({
                    'error': 'Not Found',
                    'message': f'No agent versions available for platform {platform}'
                }, status=404)
            
            filename = agent_info['filename']
            agent_path = os.path.join(self.agent_dir, filename)
            
            return await self._serve_file(agent_path, filename, agent_info['checksum'])
                
        except Exception as e:
            logger.error(f"Failed to handle agent download: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_signature_download_version(self, request: web.Request) -> web.Response:
        """Handle specific signature version download."""
        try:
            version = request.match_info['version']
            
            # Get signature version info
            metadata = self.metadata_manager.get_metadata()
            if (version not in metadata.get('signatures', {}).get('versions', {})):
                return web.json_response({
                    'error': 'Not Found',
                    'message': f'Signature version {version} not found'
                }, status=404)
            
            signature_info = metadata['signatures']['versions'][version]
            filename = signature_info['filename']
            signature_path = os.path.join(self.signatures_dir, filename)
            
            return await self._serve_file(signature_path, filename, signature_info['checksum'])
                
        except Exception as e:
            logger.error(f"Failed to handle signature version download: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_model_download_version(self, request: web.Request) -> web.Response:
        """Handle specific model version download."""
        try:
            version = request.match_info['version']
            
            # Get model version info
            metadata = self.metadata_manager.get_metadata()
            if (version not in metadata.get('models', {}).get('versions', {})):
                return web.json_response({
                    'error': 'Not Found',
                    'message': f'Model version {version} not found'
                }, status=404)
            
            model_info = metadata['models']['versions'][version]
            filename = model_info['filename']
            model_path = os.path.join(self.models_dir, filename)
            
            return await self._serve_file(model_path, filename, model_info['checksum'])
                
        except Exception as e:
            logger.error(f"Failed to handle model version download: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_agent_download_version(self, request: web.Request) -> web.Response:
        """Handle specific agent version download for a platform."""
        try:
            version = request.match_info['version']
            platform = request.match_info['platform']
            
            # Get agent version info
            metadata = self.metadata_manager.get_metadata()
            if (version not in metadata.get('agent', {}).get('versions', {}) or
                platform not in metadata['agent']['versions'][version]):
                return web.json_response({
                    'error': 'Not Found',
                    'message': f'Agent version {version} for platform {platform} not found'
                }, status=404)
            
            agent_info = metadata['agent']['versions'][version][platform]
            filename = agent_info['filename']
            agent_path = os.path.join(self.agent_dir, filename)
            
            return await self._serve_file(agent_path, filename, agent_info['checksum'])
                
        except Exception as e:
            logger.error(f"Failed to handle agent version download: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _serve_file(self, file_path: str, filename: str, expected_checksum: str) -> web.Response:
        """
        Serve a file with proper headers and checksum verification.
        
        Args:
            file_path: Path to the file to serve
            filename: Name of the file
            expected_checksum: Expected SHA-256 checksum
            
        Returns:
            HTTP response with file content
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return web.json_response({
                'error': 'Not Found',
                'message': 'File not found'
            }, status=404)
        
        # Verify checksum
        actual_checksum = self._calculate_file_checksum(file_path)
        if actual_checksum != expected_checksum:
            logger.error(f"Checksum mismatch for {filename}: expected {expected_checksum}, got {actual_checksum}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'File integrity check failed'
            }, status=500)
        
        # Check if file is cached
        cache_key = f"file_{actual_checksum}"
        cached_path = self.cache_manager.get_cached_file(cache_key)
        
        if cached_path:
            # Serve from cache
            file_path = cached_path
        else:
            # Cache the file for future requests
            self.cache_manager.cache_file(file_path, cache_key)
        
        # Determine content type
        if filename.endswith('.json'):
            content_type = 'application/json'
        elif filename.endswith('.pkl') or filename.endswith('.model'):
            content_type = 'application/octet-stream'
        else:
            content_type = 'application/octet-stream'
        
        # Serve the file
        return web.FileResponse(
            file_path,
            headers={
                'Content-Type': content_type,
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Length': str(os.path.getsize(file_path)),
                'X-Content-SHA256': actual_checksum
            }
        )

# Example usage and testing
async def main():
    """Main function for testing the refined update server."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start server
    server = RefinedUpdateServer('localhost', 8082)
    await server.start()
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Update server stopped by user")
        await server.stop()

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())