#!/usr/bin/env python3
"""
AegisAI Refined Backend Integration Module
========================================

This module provides integration between the existing AegisAI core engine
and the refined backend components, enabling enhanced cloud-assisted
scanning, telemetry collection, and ML-based detection.
"""

import os
import json
import logging
import hashlib
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from datetime import datetime
import threading
import queue

# Import core AegisAI components
from .scanner import FileScanner
from .ml_detector import MLFeatureExtractor
from .config_manager import ConfigManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RefinedBackendClient:
    """Client for communicating with the refined AegisAI backend"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the refined backend client.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.api_url = self.config.get('api_url', 'http://localhost:8080/api/v1')
        self.telemetry_url = self.config.get('telemetry_url', 'http://localhost:8081/api/v1')
        self.update_url = self.config.get('update_url', 'http://localhost:8082/api/v1')
        self.api_key = self.config.get('api_key', '')
        self.session = None
        self.loop = None
        self.agent_id = self._generate_agent_id()
        
        # Initialize asyncio event loop in a separate thread
        self._init_async_loop()
    
    def _generate_agent_id(self) -> str:
        """Generate a unique agent ID."""
        import uuid
        return f"aegisai-agent-{uuid.uuid4().hex[:8]}"
    
    def _init_async_loop(self):
        """Initialize asyncio event loop in a separate thread."""
        def run_loop():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        
        self.loop_thread = threading.Thread(target=run_loop, daemon=True)
        self.loop_thread.start()
        
        # Wait for loop to be ready
        while self.loop is None:
            import time
            time.sleep(0.1)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp client session."""
        if self.session is None or self.session.closed:
            headers = {}
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
                headers['X-API-Key'] = self.api_key
            
            self.session = aiohttp.ClientSession(headers=headers)
        
        return self.session
    
    def _run_async(self, coro):
        """Run async coroutine in the event loop thread."""
        if self.loop is None:
            raise RuntimeError("Event loop not initialized")
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result()
    
    async def _register_agent(self) -> Optional[str]:
        """
        Register this agent with the refined backend.
        
        Returns:
            Authentication token if registration successful, None otherwise
        """
        try:
            session = await self._get_session()
            
            agent_info = {
                'agent_id': self.agent_id,
                'platform': os.name,
                'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                'version': 'AegisAI-Refined-Integration-1.0'
            }
            
            async with session.post(
                f'{self.api_url}/agents/register',
                json=agent_info
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('auth_token')
                else:
                    logger.error(f"Agent registration failed: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Failed to register agent: {e}")
            return None
    
    def register_agent(self) -> Optional[str]:
        """
        Register this agent with the refined backend.
        
        Returns:
            Authentication token if registration successful, None otherwise
        """
        if self.loop is None:
            return None
        return self._run_async(self._register_agent())
    
    async def _submit_file_for_analysis(self, file_path: str, file_features: Dict) -> Optional[Dict]:
        """
        Submit a file for cloud-assisted analysis.
        
        Args:
            file_path: Path to file
            file_features: Extracted file features
            
        Returns:
            Analysis result if successful, None otherwise
        """
        try:
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            if not file_hash:
                return None
            
            session = await self._get_session()
            
            # Prepare analysis request
            analysis_data = {
                'file_hash': file_hash,
                'file_path': file_path,
                'file_features': file_features
            }
            
            async with session.post(
                f'{self.api_url}/analysis/file',
                json=analysis_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('analysis_result')
                else:
                    logger.error(f"File analysis request failed: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Failed to submit file for analysis: {e}")
            return None
    
    def submit_file_for_analysis(self, file_path: str, file_features: Dict) -> Optional[Dict]:
        """
        Submit a file for cloud-assisted analysis.
        
        Args:
            file_path: Path to file
            file_features: Extracted file features
            
        Returns:
            Analysis result if successful, None otherwise
        """
        if self.loop is None:
            return None
        return self._run_async(self._submit_file_for_analysis(file_path, file_features))
    
    async def _submit_telemetry(self, telemetry_data: Dict) -> bool:
        """
        Submit telemetry data to the telemetry collector.
        
        Args:
            telemetry_data: Telemetry data to submit
            
        Returns:
            True if submission successful, False otherwise
        """
        try:
            session = await self._get_session()
            
            # Add agent ID to telemetry data
            telemetry_data['agent_id'] = self.agent_id
            
            async with session.post(
                f'{self.telemetry_url}/telemetry',
                json=telemetry_data
            ) as response:
                return response.status == 200
        except Exception as e:
            logger.error(f"Failed to submit telemetry: {e}")
            return False
    
    def submit_telemetry(self, telemetry_data: Dict) -> bool:
        """
        Submit telemetry data to the telemetry collector.
        
        Args:
            telemetry_data: Telemetry data to submit
            
        Returns:
            True if submission successful, False otherwise
        """
        if self.loop is None:
            return False
        return self._run_async(self._submit_telemetry(telemetry_data))
    
    async def _get_threat_intelligence(self) -> Optional[Dict]:
        """
        Get latest threat intelligence from the backend.
        
        Returns:
            Threat intelligence data if successful, None otherwise
        """
        try:
            session = await self._get_session()
            
            async with session.get(f'{self.api_url}/threat-intel') as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('threat_intel')
                else:
                    logger.error(f"Threat intelligence request failed: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Failed to get threat intelligence: {e}")
            return None
    
    def get_threat_intelligence(self) -> Optional[Dict]:
        """
        Get latest threat intelligence from the backend.
        
        Returns:
            Threat intelligence data if successful, None otherwise
        """
        if self.loop is None:
            return None
        return self._run_async(self._get_threat_intelligence())
    
    async def _get_signature_updates(self) -> Optional[bytes]:
        """
        Get latest signature updates from the update server.
        
        Returns:
            Signature file content if successful, None otherwise
        """
        try:
            session = await self._get_session()
            
            async with session.get(f'{self.update_url}/signatures/latest') as response:
                if response.status == 200:
                    content = await response.read()
                    return content
                else:
                    logger.error(f"Signature update request failed: {response.status}")
                    return None
        except Exception as e:
            logger.error(f"Failed to get signature updates: {e}")
            return None
    
    def get_signature_updates(self) -> Optional[bytes]:
        """
        Get latest signature updates from the update server.
        
        Returns:
            Signature file content if successful, None otherwise
        """
        if self.loop is None:
            return None
        return self._run_async(self._get_signature_updates())
    
    def _calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA-256 hash of file or None if file cannot be read
        """
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return None
    
    def close(self):
        """Close the client and cleanup resources."""
        if self.session:
            async def close_session():
                if self.session and not self.session.closed:
                    await self.session.close()
            
            try:
                if self.loop is not None:
                    self._run_async(close_session())
            except:
                pass

class EnhancedFileScanner(FileScanner):
    """Enhanced file scanner with refined backend integration"""
    
    def __init__(self, signature_db_path: Optional[str] = None, config: Optional[Dict] = None):
        """
        Initialize the enhanced file scanner.
        
        Args:
            signature_db_path: Path to local signature database
            config: Configuration dictionary
        """
        super().__init__(signature_db_path)
        
        # Load configuration properly
        config_manager = ConfigManager()
        self.config = config or config_manager.config
        self.backend_client = RefinedBackendClient(self.config.get('cloud', {}))
        
        # Register agent with backend
        self.auth_token = self.backend_client.register_agent()
        if self.auth_token:
            logger.info("Successfully registered with refined backend")
        else:
            logger.warning("Failed to register with refined backend")
    
    def cloud_scan(self, file_path: str, file_hash: str) -> Optional[Dict]:
        """
        Perform cloud-assisted scanning using the refined backend.
        
        Args:
            file_path: Path to file
            file_hash: SHA-256 hash of file
            
        Returns:
            Threat information if cloud service detects threat, None otherwise
        """
        try:
            # Extract features for cloud analysis
            feature_extractor = MLFeatureExtractor()
            file_features = feature_extractor.extract_features(file_path)
            
            # Submit to refined backend for analysis
            result = self.backend_client.submit_file_for_analysis(file_path, file_features)
            
            if result:
                # Submit telemetry about the analysis
                telemetry_data = {
                    'client_id': self.backend_client.agent_id,
                    'file_hash': file_hash,
                    'file_path': file_path,
                    'detection_result': result.get('verdict', 'unknown'),
                    'threat_type': result.get('threat_level', 'unknown'),
                    'confidence': result.get('confidence', 0.0),
                    'processing_time': 0.0,  # Would be measured in real implementation
                    'system_info': {
                        'os': os.name
                    }
                }
                
                # Submit telemetry asynchronously
                threading.Thread(
                    target=self.backend_client.submit_telemetry,
                    args=(telemetry_data,),
                    daemon=True
                ).start()
                
                return {
                    'type': 'cloud',
                    'name': f"Cloud Detection: {result.get('verdict', 'Unknown')}",
                    'severity': result.get('threat_level', 'unknown'),
                    'confidence': result.get('confidence', 0.0),
                    'description': 'Detected by refined backend cloud analysis',
                    'malware_type': result.get('verdict', 'unknown'),
                    'details': result
                }
            
            return None
        except Exception as e:
            logger.error(f"Cloud scan failed: {e}")
            return None
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Enhanced file scanning with cloud assistance.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Scan result dictionary
        """
        # Use the parent class method for basic scanning
        result = super().scan_file(file_path)
        
        # If no threat was detected by local scanning, try cloud scanning
        if result.get('status') == 'clean' and self.backend_client:
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                cloud_result = self.cloud_scan(file_path, file_hash)
                if cloud_result:
                    # Update result with cloud detection
                    result['status'] = 'threat_detected'
                    result['threat'] = cloud_result
                    self.scan_stats['threats_detected'] += 1
                    self.scan_stats['clean_files'] -= 1  # Adjust statistics
        
        return result

class EnhancedMLDetector:
    """Enhanced ML detector with refined backend integration"""
    
    def __init__(self, model_path: Optional[str] = None, config: Optional[Dict] = None):
        """
        Initialize enhanced ML detector.
        
        Args:
            model_path: Path to trained model file
            config: Configuration dictionary
        """
        self.model_path = model_path
        
        # Load configuration properly
        config_manager = ConfigManager()
        self.config = config or config_manager.config
        self.backend_client = RefinedBackendClient(self.config.get('cloud', {}))
    
    def predict(self, file_path: str) -> Optional[Dict]:
        """
        Predict if a file is malicious using cloud ML models.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary with prediction results or None if prediction failed
        """
        try:
            # Extract features for cloud analysis
            feature_extractor = MLFeatureExtractor()
            file_features = feature_extractor.extract_features(file_path)
            
            # Submit to refined backend for enhanced analysis
            cloud_result = self.backend_client.submit_file_for_analysis(file_path, file_features)
            
            if cloud_result:
                # Format result
                result = {
                    'prediction': cloud_result.get('verdict', 'unknown'),
                    'confidence': cloud_result.get('confidence', 0.0),
                    'malware_probability': cloud_result.get('confidence', 0.0),
                    'malware_type': cloud_result.get('verdict', 'unknown'),
                    'features': file_features,
                    'analysis_source': 'refined_backend',
                    'details': cloud_result
                }
                
                return result
            
            return None
            
        except Exception as e:
            logger.error(f"Enhanced ML prediction failed: {e}")
            return None

class SignatureUpdaterWithRefinedBackend:
    """Signature updater that integrates with the refined backend"""
    
    def __init__(self, signature_db_path: str, config: Optional[Dict] = None):
        """
        Initialize signature updater with refined backend integration.
        
        Args:
            signature_db_path: Path to local signature database
            config: Configuration dictionary
        """
        self.signature_db_path = signature_db_path
        
        # Load configuration properly
        config_manager = ConfigManager()
        self.config = config or config_manager.config
        self.backend_client = RefinedBackendClient(self.config.get('cloud', {}))
        
        # Load existing database
        if os.path.exists(self.signature_db_path):
            with open(self.signature_db_path, 'r') as f:
                self.db = json.load(f)
        else:
            self._create_default_db()
    
    def _create_default_db(self):
        """Create default signature database."""
        self.db = {
            'metadata': {
                'version': '1.0',
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
    
    def update_from_refined_backend(self) -> bool:
        """
        Update signatures from the refined backend.
        
        Returns:
            True if update successful, False otherwise
        """
        try:
            # Get signature updates from refined backend
            signature_content = self.backend_client.get_signature_updates()
            
            if signature_content:
                # Parse the signature file
                try:
                    new_signatures = json.loads(signature_content)
                except json.JSONDecodeError:
                    logger.error("Failed to parse signature updates")
                    return False
                
                # Merge with existing signatures
                new_count = 0
                for sig_id, signature in new_signatures.get('signatures', {}).items():
                    sig_hash = signature.get('hash')
                    if sig_hash and sig_hash not in [s.get('hash') for s in self.db['signatures'].values()]:
                        self.db['signatures'][sig_id] = signature
                        new_count += 1
                
                # Update metadata
                if new_count > 0:
                    self.db['metadata']['last_updated'] = datetime.now().isoformat()
                    self.db['metadata']['signature_count'] = len(self.db['signatures'])
                    
                    # Save updated database
                    with open(self.signature_db_path, 'w') as f:
                        json.dump(self.db, f, indent=2)
                    
                    logger.info(f"Added {new_count} new signatures from refined backend")
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to update from refined backend: {e}")
            return False
    
    def get_signature_count(self) -> int:
        """
        Get current signature count.
        
        Returns:
            Number of signatures in database
        """
        return self.db['metadata']['signature_count']

# Example usage and integration demonstration
def demonstrate_integration():
    """Demonstrate the integration between core AegisAI and refined backend."""
    logger.info("Starting AegisAI refined backend integration demonstration...")
    
    try:
        # Demonstrate enhanced file scanner
        logger.info("Demonstrating enhanced file scanner...")
        scanner = EnhancedFileScanner()
        
        # Demonstrate enhanced ML detector
        logger.info("Demonstrating enhanced ML detector...")
        ml_detector = EnhancedMLDetector()
        
        # Demonstrate signature updater
        logger.info("Demonstrating signature updater...")
        updater = SignatureUpdaterWithRefinedBackend("demo_signatures.db")
        
        logger.info("Integration demonstration completed successfully!")
        
        # Cleanup
        scanner.backend_client.close()
        ml_detector.backend_client.close()
        updater.backend_client.close()
        
        return True
        
    except Exception as e:
        logger.error(f"Integration demonstration failed: {e}")
        return False

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run demonstration
    success = demonstrate_integration()
    
    if success:
        print("AegisAI refined backend integration demonstration completed successfully!")
    else:
        print("AegisAI refined backend integration demonstration failed!")