"""
AegisAI Quarantine Manager
========================

This module implements quarantine functionality for AegisAI,
safely isolating infected files and managing quarantined items.
"""

import os
import shutil
import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import hashlib
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuarantineManager:
    """Manages quarantined files for AegisAI"""
    
    def __init__(self, quarantine_path: Optional[str] = None):
        """
        Initialize the quarantine manager.
        
        Args:
            quarantine_path: Path to quarantine directory (default: system-specific)
        """
        if quarantine_path is None:
            # Use a default quarantine path based on the operating system
            if os.name == 'nt':  # Windows
                self.quarantine_path = os.path.join(
                    os.environ.get('PROGRAMDATA', 'C:\\ProgramData'),
                    'AegisAI',
                    'Quarantine'
                )
            else:  # Unix-like systems
                self.quarantine_path = os.path.join(
                    os.path.expanduser('~'),
                    '.aegisai',
                    'quarantine'
                )
        else:
            self.quarantine_path = quarantine_path
        
        # Create quarantine directory if it doesn't exist
        os.makedirs(self.quarantine_path, exist_ok=True)
        
        # Path to quarantine database
        self.database_path = os.path.join(self.quarantine_path, 'quarantine.db')
        
        # Load quarantine database
        self.quarantine_db = self._load_database()
        
        logger.info(f"Quarantine manager initialized at {self.quarantine_path}")
    
    def _load_database(self) -> Dict:
        """
        Load quarantine database from file.
        
        Returns:
            Dictionary with quarantine records
        """
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load quarantine database: {e}")
                return {}
        else:
            # Create empty database
            return {}
    
    def _save_database(self):
        """Save quarantine database to file."""
        try:
            with open(self.database_path, 'w') as f:
                json.dump(self.quarantine_db, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save quarantine database: {e}")
    
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
    
    def _encode_filename(self, filename: str) -> str:
        """
        Encode filename to make it safe for storage.
        
        Args:
            filename: Original filename
            
        Returns:
            Encoded filename
        """
        # Replace problematic characters
        safe_name = filename.replace('/', '_').replace('\\', '_').replace(':', '_')
        # Base64 encode to handle any remaining special characters
        encoded = base64.urlsafe_b64encode(safe_name.encode('utf-8')).decode('utf-8')
        return encoded
    
    def quarantine_file(self, file_path: str, threat_info: Optional[Dict] = None) -> bool:
        """
        Move a file to quarantine.
        
        Args:
            file_path: Path to file to quarantine
            threat_info: Information about the threat detected
            
        Returns:
            True if file was successfully quarantined, False otherwise
        """
        if not os.path.exists(file_path):
            logger.error(f"File does not exist: {file_path}")
            return False
        
        try:
            # Generate a unique quarantine filename
            original_name = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            file_hash = self._calculate_file_hash(file_path)
            
            if not file_hash:
                logger.error(f"Failed to calculate hash for {file_path}")
                return False
            
            # Create quarantine filename: hash_timestamp_originalname
            quarantine_filename = f"{file_hash}_{timestamp}_{self._encode_filename(original_name)}"
            quarantine_path = os.path.join(self.quarantine_path, quarantine_filename)
            
            # Move file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Record in database
            quarantine_record = {
                'original_path': file_path,
                'quarantine_path': quarantine_path,
                'original_name': original_name,
                'file_hash': file_hash,
                'quarantined_at': datetime.now().isoformat(),
                'threat_info': threat_info or {},
                'restored': False
            }
            
            self.quarantine_db[file_hash] = quarantine_record
            self._save_database()
            
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to quarantine file {file_path}: {e}")
            return False
    
    def restore_file(self, file_hash: str) -> bool:
        """
        Restore a quarantined file to its original location.
        
        Args:
            file_hash: Hash of the file to restore
            
        Returns:
            True if file was successfully restored, False otherwise
        """
        if file_hash not in self.quarantine_db:
            logger.error(f"File with hash {file_hash} not found in quarantine")
            return False
        
        record = self.quarantine_db[file_hash]
        
        if record.get('restored', False):
            logger.warning(f"File with hash {file_hash} has already been restored")
            return False
        
        try:
            # Move file back to original location
            original_path = record['original_path']
            quarantine_path = record['quarantine_path']
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Move file back
            shutil.move(quarantine_path, original_path)
            
            # Update database
            record['restored'] = True
            record['restored_at'] = datetime.now().isoformat()
            self._save_database()
            
            logger.info(f"File restored: {quarantine_path} -> {original_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore file with hash {file_hash}: {e}")
            return False
    
    def delete_quarantined_file(self, file_hash: str) -> bool:
        """
        Permanently delete a quarantined file.
        
        Args:
            file_hash: Hash of the file to delete
            
        Returns:
            True if file was successfully deleted, False otherwise
        """
        if file_hash not in self.quarantine_db:
            logger.error(f"File with hash {file_hash} not found in quarantine")
            return False
        
        record = self.quarantine_db[file_hash]
        
        try:
            # Delete the quarantined file
            quarantine_path = record['quarantine_path']
            if os.path.exists(quarantine_path):
                os.remove(quarantine_path)
            
            # Remove from database
            del self.quarantine_db[file_hash]
            self._save_database()
            
            logger.info(f"Quarantined file deleted: {quarantine_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete quarantined file with hash {file_hash}: {e}")
            return False
    
    def get_quarantined_files(self) -> List[Dict]:
        """
        Get list of all quarantined files.
        
        Returns:
            List of quarantine records
        """
        return list(self.quarantine_db.values())
    
    def get_quarantine_statistics(self) -> Dict:
        """
        Get quarantine statistics.
        
        Returns:
            Dictionary with quarantine statistics
        """
        total_quarantined = len(self.quarantine_db)
        restored_count = sum(1 for record in self.quarantine_db.values() if record.get('restored', False))
        active_count = total_quarantined - restored_count
        
        return {
            'total_quarantined': total_quarantined,
            'active_quarantined': active_count,
            'restored_files': restored_count
        }
    
    def clear_quarantine(self) -> bool:
        """
        Permanently delete all quarantined files.
        
        Returns:
            True if all files were successfully deleted, False otherwise
        """
        try:
            # Delete all quarantined files
            for record in self.quarantine_db.values():
                quarantine_path = record['quarantine_path']
                if os.path.exists(quarantine_path):
                    try:
                        os.remove(quarantine_path)
                    except Exception as e:
                        logger.error(f"Failed to delete {quarantine_path}: {e}")
            
            # Clear database
            self.quarantine_db.clear()
            self._save_database()
            
            logger.info("Quarantine cleared")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear quarantine: {e}")
            return False

# Example usage
if __name__ == "__main__":
    # Create quarantine manager instance
    quarantine_manager = QuarantineManager()
    
    # Get quarantine statistics
    stats = quarantine_manager.get_quarantine_statistics()
    print(f"Quarantine statistics: {stats}")
    
    # List quarantined files
    quarantined_files = quarantine_manager.get_quarantined_files()
    print(f"Quarantined files: {len(quarantined_files)}")