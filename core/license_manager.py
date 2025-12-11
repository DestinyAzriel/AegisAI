"""
AegisAI License Manager
Simple licensing system for AegisAI antivirus
"""

import os
import json
import hashlib
import logging
import secrets
import base64
from typing import Dict, Optional
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

class LicenseManager:
    """License manager for AegisAI"""
    
    def __init__(self, license_file: str = "aegisai.lic"):
        """
        Initialize license manager.
        
        Args:
            license_file: Path to license file
        """
        self.license_file = license_file
        self.encryption_key = self._derive_key("aegisai-license-key")
        self.license_data = self._load_license()
    
    def _derive_key(self, password: str) -> bytes:
        """
        Derive encryption key from password.
        
        Args:
            password: Password to derive key from
            
        Returns:
            Encryption key
        """
        salt = b'aegisai_salt_12345678'  # In practice, this should be random and stored securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_license(self) -> Optional[Dict]:
        """
        Load license from file.
        
        Returns:
            License data dictionary or None if no valid license
        """
        if not os.path.exists(self.license_file):
            return None
        
        try:
            with open(self.license_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt license data
            fernet = Fernet(self.encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            license_data = json.loads(decrypted_data.decode())
            
            # Verify license signature (simplified)
            if self._verify_license(license_data):
                return license_data
            else:
                logger.warning("License verification failed")
                return None
                
        except Exception as e:
            logger.error(f"Failed to load license: {e}")
            return None
    
    def _save_license(self, license_data: Dict) -> bool:
        """
        Save license to file.
        
        Args:
            license_data: License data to save
            
        Returns:
            True if save successful, False otherwise
        """
        try:
            # Add signature
            license_data['signature'] = self._sign_license(license_data)
            
            # Encrypt license data
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(json.dumps(license_data).encode())
            
            # Save to file
            with open(self.license_file, 'wb') as f:
                f.write(encrypted_data)
            
            self.license_data = license_data
            return True
            
        except Exception as e:
            logger.error(f"Failed to save license: {e}")
            return False
    
    def _sign_license(self, license_data: Dict) -> str:
        """
        Sign license data (simplified).
        
        Args:
            license_data: License data to sign
            
        Returns:
            Signature
        """
        # In a real implementation, this would use proper cryptographic signatures
        # For this demo, we'll use a simple hash-based approach
        # We need to remove the signature field before signing to avoid circular dependency
        data_to_sign = license_data.copy()
        data_to_sign.pop('signature', None)
        data_string = json.dumps(data_to_sign, sort_keys=True)
        return hashlib.sha256(data_string.encode()).hexdigest()
    
    def _verify_license(self, license_data: Dict) -> bool:
        """
        Verify license signature.
        
        Args:
            license_data: License data to verify
            
        Returns:
            True if valid, False otherwise
        """
        # Extract signature
        signature = license_data.get('signature', '')
        
        # Create a copy without the signature for verification
        data_to_verify = license_data.copy()
        data_to_verify.pop('signature', None)
        
        # Verify signature
        expected_signature = self._sign_license(data_to_verify)
        
        return signature == expected_signature
    
    def generate_license_key(self, license_type: str, duration_days: int = 365) -> str:
        """
        Generate a license key (for administrative use).
        
        Args:
            license_type: Type of license (free, personal, business, enterprise)
            duration_days: Duration in days
            
        Returns:
            License key
        """
        # Generate random license ID
        license_id = secrets.token_urlsafe(16)
        
        # Create license data
        license_data = {
            'license_id': license_id,
            'license_type': license_type,
            'issued_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=duration_days)).isoformat(),
            'features': self._get_features_for_license_type(license_type)
        }
        
        # Sign license
        license_data['signature'] = self._sign_license(license_data)
        
        # Encode as JSON and base64
        license_json = json.dumps(license_data)
        license_key = base64.urlsafe_b64encode(license_json.encode()).decode()
        
        return license_key
    
    def _get_features_for_license_type(self, license_type: str) -> Dict:
        """
        Get features for license type.
        
        Args:
            license_type: Type of license
            
        Returns:
            Dictionary of features
        """
        # Define the freemium model features
        # Free tier gets access to core antivirus functionality
        features = {
            # Free tier - Core antivirus features
            'manual_scans': True,           # Access to dashboard
            'threat_scanning': True,            # Threat scanning capabilities
            'security_logs': True,              # Security logs access
            'quarantine': True,                 # Quarantine management
            'active_threats': True,             # Active threat monitoring
            
            # Premium features (locked for free tier)
            'advanced_threat_detection': license_type in ['personal', 'business', 'enterprise'],
            'behavioral_analysis': license_type in ['personal', 'business', 'enterprise'],
            'network_protection': license_type in ['personal', 'business', 'enterprise'],
            'identity_protection': license_type in ['business', 'enterprise'],
            'endpoint_management': license_type in ['business', 'enterprise'],
            'cloud_integration': license_type in ['business', 'enterprise'],
            'forensics_tools': license_type in ['business', 'enterprise'],
            'automated_response': license_type in ['business', 'enterprise'],
            'custom_rules': license_type in ['business', 'enterprise'],
            'scheduled_scans': license_type in ['personal', 'business', 'enterprise'],
            'performance_optimization': license_type in ['business', 'enterprise'],
            'privacy_monitoring': license_type in ['business', 'enterprise'],
            'backup_integration': license_type in ['business', 'enterprise'],
            'real_time_protection': True  # Always enabled for simplicity in this demo
        }
        
        return features
    
    def activate_license(self, license_key: str) -> bool:
        """
        Activate a license.
        
        Args:
            license_key: License key to activate
            
        Returns:
            True if activation successful, False otherwise
        """
        try:
            # Decode license key
            license_json = base64.urlsafe_b64decode(license_key.encode()).decode()
            license_data = json.loads(license_json)
            
            # Verify license
            if not self._verify_license(license_data):
                logger.error("Invalid license signature")
                return False
            
            # Check expiration
            expires_at = datetime.fromisoformat(license_data['expires_at'])
            if expires_at < datetime.now():
                logger.error("License has expired")
                return False
            
            # Save license
            if self._save_license(license_data):
                logger.info(f"License activated: {license_data['license_id']}")
                return True
            else:
                logger.error("Failed to save license")
                return False
                
        except Exception as e:
            logger.error(f"Failed to activate license: {e}")
            return False
    
    def is_licensed(self) -> bool:
        """
        Check if product is licensed.
        
        Returns:
            True if licensed, False otherwise
        """
        return self.license_data is not None
    
    def is_feature_enabled(self, feature: str) -> bool:
        """
        Check if a feature is enabled.
        
        Args:
            feature: Feature to check
            
        Returns:
            True if feature is enabled, False otherwise
        """
        # For free tier, certain features are always available
        free_tier_features = {
            'manual_scans': True,
            'real_time_protection': True,  # Always enabled in this demo
            'cloud_scanning': False,
            'ai_detection': False,
            'yara_scanning': False,
            'priority_support': False,
            'centralized_management': False
        }
        
        if not self.is_licensed() or self.license_data is None:
            # Return default free tier feature availability
            return free_tier_features.get(feature, False)
        
        # Check expiration
        if 'expires_at' in self.license_data:
            try:
                expires_at = datetime.fromisoformat(self.license_data['expires_at'])
                if expires_at < datetime.now():
                    # If license is expired, fall back to free tier features
                    return free_tier_features.get(feature, False)
            except (ValueError, TypeError):
                # If we can't parse the expiration date, fall back to free tier
                return free_tier_features.get(feature, False)
        
        features = self.license_data.get('features', {}) if self.license_data else {}
        return features.get(feature, free_tier_features.get(feature, False))
    
    def get_license_info(self) -> Dict:
        """
        Get license information.
        
        Returns:
            Dictionary with license information
        """
        # For free tier, certain features are always available
        free_tier_features = {
            'manual_scans': True,
            'real_time_protection': True,  # Always enabled in this demo
            'cloud_scanning': False,
            'ai_detection': False,
            'yara_scanning': False,
            'priority_support': False,
            'centralized_management': False
        }
        
        if not self.is_licensed() or self.license_data is None:
            return {
                'licensed': False,
                'license_type': 'free',
                'features': free_tier_features
            }
        
        # Check expiration
        is_expired = False
        if 'expires_at' in self.license_data:
            try:
                expires_at = datetime.fromisoformat(self.license_data['expires_at'])
                is_expired = expires_at < datetime.now()
            except (ValueError, TypeError):
                is_expired = True
        
        return {
            'licensed': True,
            'license_type': self.license_data.get('license_type', 'unknown') if self.license_data else 'unknown',
            'license_id': self.license_data.get('license_id', 'unknown') if self.license_data else 'unknown',
            'issued_at': self.license_data.get('issued_at', '') if self.license_data else '',
            'expires_at': self.license_data.get('expires_at', '') if self.license_data else '',
            'is_expired': is_expired,
            'features': self.license_data.get('features', free_tier_features) if self.license_data else free_tier_features
        }