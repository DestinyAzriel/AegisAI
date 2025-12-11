"""
Signature Database Updater for AegisAI Core Engine
"""

import os
import json
import hashlib
import logging
import requests
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SignatureUpdater:
    """Service for updating malware signatures from various threat intelligence feeds"""
    
    def __init__(self, signature_db_path: str, config: Optional[Dict] = None):
        """
        Initialize signature updater.
        
        Args:
            signature_db_path: Path to local signature database
            config: Configuration dictionary
        """
        self.signature_db_path = signature_db_path
        self.config = config or {}
        self.feeds = self.config.get('feeds', [
            {
                'name': 'abuse_ch',
                'url': 'https://bazaar.abuse.ch/export/json/recent/',
                'enabled': True
            },
            {
                'name': 'malware_bazaar',
                'url': 'https://mb-api.abuse.ch/api/v1/',
                'enabled': False  # Requires API key
            }
        ])
        
        # Create signature database if it doesn't exist
        if not os.path.exists(self.signature_db_path):
            self._create_default_db()
    
    def _create_default_db(self):
        """Create default signature database."""
        default_db = {
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
        
        with open(self.signature_db_path, 'w') as f:
            json.dump(default_db, f, indent=2)
        
        logger.info(f"Created default signature database at {self.signature_db_path}")
    
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
    
    def update_from_abuse_ch(self) -> bool:
        """
        Update signatures from Abuse.ch Malware Bazaar.
        
        Returns:
            True if update successful, False otherwise
        """
        try:
            # Try to get recent samples
            response = requests.get(
                'https://bazaar.abuse.ch/export/json/recent/',
                timeout=30
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to fetch Abuse.ch data: {response.status_code}")
                return False
            
            data = response.json()
            
            if data.get('query_status') != 'ok':
                logger.error("Abuse.ch API returned error status")
                return False
            
            # Load existing database
            with open(self.signature_db_path, 'r') as f:
                db = json.load(f)
            
            # Process samples
            new_signatures = 0
            for sample in data.get('data', []):
                sha256_hash = sample.get('sha256_hash')
                if not sha256_hash:
                    continue
                
                # Skip if already in database
                if sha256_hash in [s.get('hash') for s in db['signatures'].values()]:
                    continue
                
                # Add new signature
                signature_id = f"abuse_ch_{sha256_hash[:16]}"
                db['signatures'][signature_id] = {
                    'name': sample.get('signature', 'Unknown Malware'),
                    'hash': sha256_hash,
                    'severity': 'malicious',
                    'description': f"Malware sample from Abuse.ch - {sample.get('file_type', 'Unknown')}",
                    'source': 'abuse_ch',
                    'first_seen': sample.get('first_seen', ''),
                    'tags': sample.get('tags', [])
                }
                new_signatures += 1
            
            # Update metadata
            if new_signatures > 0:
                db['metadata']['last_updated'] = datetime.now().isoformat()
                db['metadata']['signature_count'] = len(db['signatures'])
                
                # Save updated database
                with open(self.signature_db_path, 'w') as f:
                    json.dump(db, f, indent=2)
                
                logger.info(f"Added {new_signatures} new signatures from Abuse.ch")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update from Abuse.ch: {e}")
            return False
    
    def update_from_virusshare(self) -> bool:
        """
        Update signatures from VirusShare metadata (placeholder).
        
        Returns:
            True if update successful, False otherwise
        """
        # This would require access to VirusShare datasets
        # Implementation would depend on how the data is provided
        logger.info("VirusShare update not implemented - requires dataset access")
        return False
    
    def update_all_feeds(self) -> Dict[str, bool]:
        """
        Update signatures from all enabled feeds.
        
        Returns:
            Dictionary with feed names and update status
        """
        results = {}
        
        for feed in self.feeds:
            if not feed.get('enabled', False):
                continue
            
            feed_name = feed['name']
            logger.info(f"Updating signatures from {feed_name}")
            
            if feed_name == 'abuse_ch':
                results[feed_name] = self.update_from_abuse_ch()
            elif feed_name == 'malware_bazaar':
                # Would require API key
                results[feed_name] = False
            elif feed_name == 'virusshare':
                results[feed_name] = self.update_from_virusshare()
            else:
                logger.warning(f"Unknown feed: {feed_name}")
                results[feed_name] = False
        
        return results
    
    def get_signature_count(self) -> int:
        """
        Get current signature count.
        
        Returns:
            Number of signatures in database
        """
        try:
            with open(self.signature_db_path, 'r') as f:
                db = json.load(f)
            return db['metadata']['signature_count']
        except Exception as e:
            logger.error(f"Failed to get signature count: {e}")
            return 0

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create updater instance
    updater = SignatureUpdater("signatures.db")
    
    # Update from all feeds
    results = updater.update_all_feeds()
    
    # Print results
    print("Signature update results:")
    for feed, success in results.items():
        status = "SUCCESS" if success else "FAILED"
        print(f"  {feed}: {status}")
    
    # Print signature count
    count = updater.get_signature_count()
    print(f"Total signatures: {count}")