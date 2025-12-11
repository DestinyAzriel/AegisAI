"""
AegisAI Auto-Updater
Automatically updates the AegisAI engine and signatures
"""

import os
import json
import hashlib
import logging
import requests
import zipfile
import tempfile
import shutil
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class AutoUpdater:
    """Auto-updater for AegisAI"""
    
    def __init__(self, update_server_url: str, install_path: str):
        """
        Initialize auto-updater.
        
        Args:
            update_server_url: URL of the update server
            install_path: Path where AegisAI is installed
        """
        self.update_server_url = update_server_url.rstrip('/')
        self.install_path = install_path
        self.last_check_file = os.path.join(install_path, '.last_update_check')
        self.current_version = self._get_current_version()
    
    def _get_current_version(self) -> str:
        """
        Get current version of AegisAI.
        
        Returns:
            Current version string
        """
        version_file = os.path.join(self.install_path, 'VERSION')
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                return f.read().strip()
        return '1.0.0'  # Default version
    
    def _get_last_check_time(self) -> Optional[datetime]:
        """
        Get last update check time.
        
        Returns:
            Last check time or None if never checked
        """
        if os.path.exists(self.last_check_file):
            try:
                with open(self.last_check_file, 'r') as f:
                    timestamp = f.read().strip()
                    return datetime.fromisoformat(timestamp)
            except Exception as e:
                logger.error(f"Failed to read last check time: {e}")
        return None
    
    def _set_last_check_time(self):
        """Set last update check time to now."""
        try:
            with open(self.last_check_file, 'w') as f:
                f.write(datetime.now().isoformat())
        except Exception as e:
            logger.error(f"Failed to write last check time: {e}")
    
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
    
    def check_for_updates(self) -> Dict:
        """
        Check for available updates.
        
        Returns:
            Dictionary with update information
        """
        try:
            # Check if we should skip update check (less than 1 hour since last check)
            last_check = self._get_last_check_time()
            if last_check:
                time_since_last_check = datetime.now() - last_check
                if time_since_last_check.total_seconds() < 3600:  # 1 hour
                    logger.info("Skipping update check - checked less than 1 hour ago")
                    return {
                        'available': False,
                        'reason': 'Checked recently'
                    }
            
            # Fetch metadata from update server
            metadata_url = f"{self.update_server_url}/api/v1/metadata"
            response = requests.get(metadata_url, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch metadata: {response.status_code}")
                return {
                    'available': False,
                    'reason': f'Failed to fetch metadata: {response.status_code}'
                }
            
            metadata = response.json()
            server_version = metadata.get('version', '1.0.0')
            
            # Compare versions
            if server_version > self.current_version:
                logger.info(f"Update available: {self.current_version} -> {server_version}")
                self._set_last_check_time()
                return {
                    'available': True,
                    'version': server_version,
                    'current_version': self.current_version,
                    'metadata': metadata
                }
            else:
                logger.info("No updates available")
                self._set_last_check_time()
                return {
                    'available': False,
                    'reason': 'Up to date'
                }
                
        except Exception as e:
            logger.error(f"Failed to check for updates: {e}")
            return {
                'available': False,
                'reason': f'Error: {str(e)}'
            }
    
    def update_engine(self) -> bool:
        """
        Update the AegisAI engine.
        
        Returns:
            True if update successful, False otherwise
        """
        try:
            # Check for updates first
            update_info = self.check_for_updates()
            if not update_info.get('available', False):
                logger.info("No updates available")
                return True
            
            metadata = update_info.get('metadata', {})
            new_version = update_info.get('version', '1.0.0')
            
            logger.info(f"Updating AegisAI engine to version {new_version}")
            
            # Download update package (simplified - in practice this would be more complex)
            # For now, we'll just update signatures as an example
            signatures_info = metadata.get('signatures', {})
            signatures_file = signatures_info.get('latest', '')
            expected_checksum = signatures_info.get('checksum', '')
            
            if signatures_file:
                return self._update_signatures(signatures_file, expected_checksum)
            else:
                logger.warning("No signatures file found in metadata")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update engine: {e}")
            return False
    
    def _update_signatures(self, signatures_file: str, expected_checksum: str) -> bool:
        """
        Update signature database.
        
        Args:
            signatures_file: Name of signatures file
            expected_checksum: Expected checksum of file
            
        Returns:
            True if update successful, False otherwise
        """
        try:
            logger.info(f"Updating signatures from {signatures_file}")
            
            # Download signatures file
            download_url = f"{self.update_server_url}/api/v1/signatures/{signatures_file}"
            response = requests.get(download_url, timeout=60)
            
            if response.status_code != 200:
                logger.error(f"Failed to download signatures: {response.status_code}")
                return False
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(response.content)
                temp_file_path = temp_file.name
            
            # Verify checksum
            actual_checksum = self._calculate_file_checksum(temp_file_path)
            if actual_checksum != expected_checksum:
                logger.error("Checksum verification failed")
                os.unlink(temp_file_path)
                return False
            
            # Move to signatures directory
            signatures_path = os.path.join(self.install_path, 'signatures.db')
            
            # Backup current signatures
            if os.path.exists(signatures_path):
                backup_path = f"{signatures_path}.backup"
                shutil.copy2(signatures_path, backup_path)
                logger.info(f"Backed up current signatures to {backup_path}")
            
            # Replace signatures
            shutil.move(temp_file_path, signatures_path)
            logger.info("Signatures updated successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update signatures: {e}")
            return False
    
    def update_ml_model(self) -> bool:
        """
        Update ML model.
        
        Returns:
            True if update successful, False otherwise
        """
        try:
            # Fetch metadata
            metadata_url = f"{self.update_server_url}/api/v1/metadata"
            response = requests.get(metadata_url, timeout=30)
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch metadata: {response.status_code}")
                return False
            
            metadata = response.json()
            models_info = metadata.get('models', {})
            model_file = models_info.get('latest', '')
            expected_checksum = models_info.get('checksum', '')
            
            if not model_file:
                logger.warning("No model file found in metadata")
                return False
            
            logger.info(f"Updating ML model from {model_file}")
            
            # Download model file
            download_url = f"{self.update_server_url}/api/v1/models/{model_file}"
            response = requests.get(download_url, timeout=120)  # Longer timeout for model
            
            if response.status_code != 200:
                logger.error(f"Failed to download model: {response.status_code}")
                return False
            
            # Save to temporary file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(response.content)
                temp_file_path = temp_file.name
            
            # Verify checksum
            actual_checksum = self._calculate_file_checksum(temp_file_path)
            if actual_checksum != expected_checksum:
                logger.error("Checksum verification failed")
                os.unlink(temp_file_path)
                return False
            
            # Move to models directory
            models_path = os.path.join(self.install_path, 'ml_model.pkl')
            
            # Backup current model
            if os.path.exists(models_path):
                backup_path = f"{models_path}.backup"
                shutil.copy2(models_path, backup_path)
                logger.info(f"Backed up current model to {backup_path}")
            
            # Replace model
            shutil.move(temp_file_path, models_path)
            logger.info("ML model updated successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update ML model: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create updater instance
    updater = AutoUpdater("http://localhost:8080", ".")
    
    # Check for updates
    update_info = updater.check_for_updates()
    print(f"Update check result: {update_info}")
    
    # Update engine if updates are available
    if update_info.get('available', False):
        success = updater.update_engine()
        if success:
            print("Engine updated successfully")
        else:
            print("Failed to update engine")