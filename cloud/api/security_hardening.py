#!/usr/bin/env python3
"""
Security hardening for AegisAI cloud backend

This module implements additional security hardening measures for the AegisAI cloud backend.
"""

import asyncio
import json
import os
import logging
import hashlib
import secrets
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityHardening:
    """Security hardening measures for AegisAI cloud backend"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize security hardening"""
        self.config = self._load_config(config_path)
        self.threat_intel = {}
        self.suspicious_activities = []
        self.blocked_ips = set()
        self.rate_limits = {}
        
        logger.info("Security hardening initialized")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "security": {
                "rate_limiting": {
                    "requests_per_minute": 1000,
                    "burst_limit": 200
                },
                "ip_blocking": {
                    "max_failed_attempts": 5,
                    "block_duration_minutes": 60
                },
                "input_validation": {
                    "max_request_size": 1048576,  # 1MB
                    "allowed_content_types": [
                        "application/json",
                        "application/x-www-form-urlencoded"
                    ]
                },
                "threat_detection": {
                    "suspicious_patterns": [
                        r"(\b|\d)union(\b|\d).*select",
                        r"(\b|\d)drop(\b|\d)",
                        r"(\b|\d)delete(\b|\d).*from",
                        r"(\b|\d)insert(\b|\d).*into",
                        r"(\b|\d)update(\b|\d).*set",
                        r"<script.*?>.*?</script>",
                        r"javascript:",
                        r"vbscript:",
                        r"onload=",
                        r"onerror=",
                        r"onmouseover="
                    ]
                }
            }
        }
        
        if not config_path:
            # Look for security config in infra directory
            config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'infra', 'security-config.json')
        
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
                logger.error(f"Error loading security config: {e}")
        
        return default_config
    
    def validate_input(self, data: str, content_type: str = "application/json") -> bool:
        """
        Validate input data for security issues
        
        Args:
            data: Input data to validate
            content_type: Content type of the data
            
        Returns:
            True if data is valid, False otherwise
        """
        # Check content type
        allowed_types = self.config.get('security', {}).get('input_validation', {}).get('allowed_content_types', [])
        if content_type not in allowed_types:
            logger.warning(f"Blocked request with content type: {content_type}")
            return False
        
        # Check request size
        max_size = self.config.get('security', {}).get('input_validation', {}).get('max_request_size', 1048576)
        if len(data.encode('utf-8')) > max_size:
            logger.warning(f"Blocked request exceeding size limit: {len(data)} bytes")
            return False
        
        # Check for suspicious patterns
        suspicious_patterns = self.config.get('security', {}).get('threat_detection', {}).get('suspicious_patterns', [])
        for pattern in suspicious_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                logger.warning(f"Blocked request with suspicious pattern: {pattern}")
                return False
        
        return True
    
    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if a client is rate limited
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if client is allowed, False if rate limited
        """
        current_time = datetime.now()
        minute_ago = current_time - timedelta(minutes=1)
        
        # Clean up old requests
        if client_id in self.rate_limits:
            self.rate_limits[client_id] = [
                timestamp for timestamp in self.rate_limits[client_id]
                if timestamp > minute_ago
            ]
        else:
            self.rate_limits[client_id] = []
        
        # Check rate limit
        rate_limit = self.config.get('security', {}).get('rate_limiting', {}).get('requests_per_minute', 1000)
        if len(self.rate_limits[client_id]) >= rate_limit:
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            return False
        
        # Record this request
        self.rate_limits[client_id].append(current_time)
        return True
    
    def check_ip_blocking(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is allowed, False if blocked
        """
        if ip_address in self.blocked_ips:
            logger.warning(f"Blocked request from IP: {ip_address}")
            return False
        return True
    
    def record_failed_attempt(self, ip_address: str):
        """
        Record a failed authentication attempt
        
        Args:
            ip_address: IP address of the attempt
        """
        # In a real implementation, this would track failed attempts per IP
        # and block after a certain threshold
        pass
    
    def block_ip(self, ip_address: str):
        """
        Block an IP address
        
        Args:
            ip_address: IP address to block
        """
        self.blocked_ips.add(ip_address)
        logger.info(f"Blocked IP address: {ip_address}")
        
        # Schedule unblocking
        block_duration = self.config.get('security', {}).get('ip_blocking', {}).get('block_duration_minutes', 60)
        
        async def unblock_later():
            await asyncio.sleep(block_duration * 60)
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                logger.info(f"Unblocked IP address: {ip_address}")
        
        # Run unblocking task in background
        asyncio.create_task(unblock_later())
    
    def detect_suspicious_activity(self, activity: Dict[str, Any]) -> bool:
        """
        Detect suspicious activity
        
        Args:
            activity: Activity data to analyze
            
        Returns:
            True if activity is suspicious, False otherwise
        """
        # In a real implementation, this would use more sophisticated detection
        # For now, we'll just log the activity
        self.suspicious_activities.append(activity)
        logger.info(f"Suspicious activity detected: {activity}")
        return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure token
        
        Args:
            length: Length of the token in bytes
            
        Returns:
            Secure token as hex string
        """
        return secrets.token_hex(length)
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> str:
        """
        Hash a password with salt
        
        Args:
            password: Password to hash
            salt: Salt to use (optional, will generate if not provided)
            
        Returns:
            Hashed password with salt
        """
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 for password hashing
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return f"{salt}${password_hash.hex()}"
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash
        
        Args:
            password: Password to verify
            hashed_password: Hashed password to compare against
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            salt, password_hash = hashed_password.split('$')
            computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
            return computed_hash.hex() == password_hash
        except Exception:
            return False
    
    def get_security_report(self) -> Dict[str, Any]:
        """
        Get security report
        
        Returns:
            Security report as dictionary
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'blocked_ips_count': len(self.blocked_ips),
            'suspicious_activities_count': len(self.suspicious_activities),
            'active_rate_limits': len([client for client, timestamps in self.rate_limits.items() if len(timestamps) > 0]),
            'blocked_ips': list(self.blocked_ips),
            'recent_suspicious_activities': self.suspicious_activities[-10:]  # Last 10 activities
        }

# Global security hardening instance
security_hardening = SecurityHardening()

# Example usage
if __name__ == "__main__":
    # Example of how to use the security hardening module
    # This would be integrated into the main application
    
    # Validate input
    is_valid = security_hardening.validate_input('{"test": "data"}', "application/json")
    print(f"Input validation result: {is_valid}")
    
    # Check rate limit
    is_allowed = security_hardening.check_rate_limit("test_client")
    print(f"Rate limit check result: {is_allowed}")
    
    # Generate secure token
    token = security_hardening.generate_secure_token()
    print(f"Generated secure token: {token}")
    
    # Hash and verify password
    password = "test_password"
    hashed = security_hardening.hash_password(password)
    is_valid = security_hardening.verify_password(password, hashed)
    print(f"Password verification result: {is_valid}")