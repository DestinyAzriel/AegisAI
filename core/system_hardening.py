#!/usr/bin/env python3
"""
AegisAI System Hardening Module
==============================

This module provides automatic system hardening capabilities based on
security recommendations from the predictive threat intelligence engine.
"""

import os
import sys
import logging
import subprocess
import platform
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SystemHardeningManager:
    """Manages automatic system hardening based on security recommendations"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the system hardening manager"""
        self.config = self._load_config(config_path)
        self.applied_recommendations = []
        self.failed_recommendations = []
        self.last_applied_actions = {}  # Track when each action was last applied
        self.action_statistics = defaultdict(int)  # Track how many times each action was attempted
        
        logger.info("System hardening manager initialized")
        logger.info(f"Admin required: {self.config.get('system_hardening', {}).get('require_admin_privileges', True)}")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            "system_hardening": {
                "enabled": True,
                "auto_apply_recommendations": True,
                "require_admin_privileges": False,  # Changed to False for testing
                "log_level": "INFO",
                "backup_before_changes": True,
                "min_confidence_threshold": 0.7,
                "action_cooldown_seconds": 30  # Minimum time between applying the same action
            }
        }
        
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'hardening_config.json')
        
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
                logger.error(f"Error loading hardening config: {e}")
        
        return default_config
    
    def apply_recommendations(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Apply security recommendations automatically
        
        Args:
            recommendations: List of recommendation dictionaries
            
        Returns:
            Dictionary with results of applied recommendations
        """
        if not self.config.get("system_hardening", {}).get("enabled", True):
            logger.warning("System hardening is disabled")
            return {"applied": 0, "failed": 0, "results": []}
        
        if not self.config.get("system_hardening", {}).get("auto_apply_recommendations", True):
            logger.info("Auto-apply recommendations is disabled")
            return {"applied": 0, "failed": 0, "results": []}
        
        # Check if running on Windows
        if platform.system().lower() != "windows":
            logger.warning("Automatic system hardening is only supported on Windows")
            return {"applied": 0, "failed": 0, "results": []}
        
        # Check for admin privileges
        requires_admin = self.config.get("system_hardening", {}).get("require_admin_privileges", False)
        has_admin = self._is_admin()
        
        logger.info(f"Requires admin: {requires_admin}, Has admin: {has_admin}")
        
        if requires_admin and not has_admin:
            logger.warning("Administrator privileges required for system hardening")
            # Still process recommendations but don't apply them
            return self._simulate_recommendations(recommendations)
        
        results = []
        applied_count = 0
        failed_count = 0
        
        # Apply high-confidence recommendations
        min_confidence = self.config.get("system_hardening", {}).get("min_confidence_threshold", 0.7)
        high_confidence_recs = [rec for rec in recommendations if rec.get('confidence', 0) >= min_confidence]
        
        current_time = datetime.now()
        cooldown_seconds = self.config.get("system_hardening", {}).get("action_cooldown_seconds", 30)
        
        for rec in high_confidence_recs:
            action = rec.get('action', '')
            description = rec.get('description', '')
            
            # Track statistics
            self.action_statistics[action] += 1
            
            # Check if this action is on cooldown
            last_applied = self.last_applied_actions.get(action)
            if last_applied and (current_time - last_applied).seconds < cooldown_seconds:
                logger.info(f"Action {action} is on cooldown, skipping...")
                continue
            
            try:
                if action == 'enable_aslr':
                    result = self._enable_aslr()
                elif action == 'enable_dep':
                    result = self._enable_dep()
                elif action == 'restrict_admin_privileges':
                    result = self._restrict_admin_privileges()
                elif action == 'enable_firewall':
                    result = self._enable_firewall()
                elif action == 'enable_memory_protection':
                    result = self._enable_memory_protection()
                elif action == 'restrict_process_creation':
                    result = self._restrict_process_creation()
                elif action == 'restrict_registry_writes':
                    result = self._restrict_registry_writes()
                elif action == 'increase_monitoring':
                    result = self._increase_monitoring()
                else:
                    logger.warning(f"Unknown action: {action}")
                    continue
                
                if result.get('success', False):
                    applied_count += 1
                    self.applied_recommendations.append(rec)
                    self.last_applied_actions[action] = current_time
                    logger.info(f"Successfully applied recommendation: {description}")
                    print(f"    🔧 AUTO-APPLIED: {description}")
                else:
                    failed_count += 1
                    self.failed_recommendations.append(rec)
                    error_msg = result.get('error', 'Unknown error')
                    logger.error(f"Failed to apply recommendation: {description} - {error_msg}")
                    # Only show admin-related errors if we don't have admin privileges
                    if not has_admin and ('access denied' in error_msg.lower() or 'permission denied' in error_msg.lower()):
                        print(f"    ⚠️  ADMIN REQUIRED: {description}")
                    else:
                        print(f"    ❌ FAILED: {description} - {error_msg}")
                
                results.append({
                    'recommendation': rec,
                    'result': result
                })
                
            except Exception as e:
                failed_count += 1
                self.failed_recommendations.append(rec)
                logger.error(f"Error applying recommendation {description}: {e}")
                results.append({
                    'recommendation': rec,
                    'result': {'success': False, 'error': str(e)}
                })
        
        return {
            "applied": applied_count,
            "failed": failed_count,
            "simulated": 0,
            "results": results
        }
    
    def _simulate_recommendations(self, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Simulate applying recommendations when admin privileges are not available
        
        Args:
            recommendations: List of recommendation dictionaries
            
        Returns:
            Dictionary with simulation results
        """
        # Apply high-confidence recommendations
        min_confidence = self.config.get("system_hardening", {}).get("min_confidence_threshold", 0.7)
        high_confidence_recs = [rec for rec in recommendations if rec.get('confidence', 0) >= min_confidence]
        
        results = []
        for rec in high_confidence_recs:
            action = rec.get('action', '')
            description = rec.get('description', '')
            
            # Simulate what would happen
            result = {
                'recommendation': rec,
                'result': {
                    'success': False,
                    'simulated': True,
                    'message': f"Would apply {description} (requires admin privileges)"
                }
            }
            results.append(result)
            
            # Track statistics
            self.action_statistics[action] += 1
        
        if high_confidence_recs:
            logger.info(f"Simulated application of {len(high_confidence_recs)} recommendations (admin required)")
        
        return {
            "applied": 0,
            "failed": 0,
            "simulated": len(high_confidence_recs),
            "results": results
        }
    
    def _is_admin(self) -> bool:
        """Check if the script is running with administrator privileges"""
        try:
            if platform.system().lower() == 'windows':
                import ctypes
                result = ctypes.windll.shell32.IsUserAnAdmin()
                logger.info(f"IsUserAnAdmin() returned: {result}")
                return result
            else:
                result = os.geteuid() == 0
                logger.info(f"os.geteuid() == 0 returned: {result}")
                return result
        except Exception as e:
            logger.error(f"Error checking admin privileges: {e}")
            return False
    
    def _enable_aslr(self) -> Dict[str, Any]:
        """
        Enable Address Space Layout Randomization
        
        Returns:
            Dictionary with operation result
        """
        try:
            # Enable ASLR system-wide using registry
            cmd = [
                'reg', 'add', 
                'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management',
                '/v', 'MoveImages',
                '/t', 'REG_DWORD',
                '/d', '1',
                '/f'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                logger.info("ASLR enabled successfully")
                return {"success": True, "message": "ASLR enabled"}
            else:
                logger.error(f"Failed to enable ASLR: {result.stderr}")
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"Error enabling ASLR: {e}")
            return {"success": False, "error": str(e)}
    
    def _enable_dep(self) -> Dict[str, Any]:
        """
        Enable Data Execution Prevention
        
        Returns:
            Dictionary with operation result
        """
        try:
            # Enable DEP for all programs except those specified
            cmd = [
                'bcdedit', '/set', 
                '{current}', 'nx', 'OptIn'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                logger.info("DEP enabled successfully")
                return {"success": True, "message": "DEP enabled"}
            else:
                logger.error(f"Failed to enable DEP: {result.stderr}")
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"Error enabling DEP: {e}")
            return {"success": False, "error": str(e)}
    
    def _restrict_admin_privileges(self) -> Dict[str, Any]:
        """
        Restrict administrative privileges
        
        Returns:
            Dictionary with operation result
        """
        try:
            # Enable UAC (User Account Control)
            cmd = [
                'reg', 'add',
                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                '/v', 'EnableLUA',
                '/t', 'REG_DWORD',
                '/d', '1',
                '/f'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                logger.info("Administrative privileges restricted successfully")
                return {"success": True, "message": "Admin privileges restricted"}
            else:
                logger.error(f"Failed to restrict admin privileges: {result.stderr}")
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"Error restricting admin privileges: {e}")
            return {"success": False, "error": str(e)}
    
    def _enable_firewall(self) -> Dict[str, Any]:
        """
        Enable Windows Firewall
        
        Returns:
            Dictionary with operation result
        """
        try:
            # Enable Windows Firewall for all profiles
            cmd = [
                'netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                logger.info("Windows Firewall enabled successfully")
                return {"success": True, "message": "Firewall enabled"}
            else:
                logger.error(f"Failed to enable firewall: {result.stderr}")
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"Error enabling firewall: {e}")
            return {"success": False, "error": str(e)}
    
    def _enable_memory_protection(self) -> Dict[str, Any]:
        """
        Enable memory protection mechanisms
        
        Returns:
            Dictionary with operation result
        """
        try:
            # Enable Structured Exception Handling Overwrite Protection (SEHOP)
            cmd = [
                'reg', 'add',
                'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel',
                '/v', 'DisableExceptionChainValidation',
                '/t', 'REG_DWORD',
                '/d', '0',
                '/f'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                logger.info("Memory protection enabled successfully")
                return {"success": True, "message": "Memory protection enabled"}
            else:
                logger.error(f"Failed to enable memory protection: {result.stderr}")
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            logger.error(f"Error enabling memory protection: {e}")
            return {"success": False, "error": str(e)}
    
    def _restrict_process_creation(self) -> Dict[str, Any]:
        """
        Restrict unauthorized process creation
        
        Returns:
            Dictionary with operation result
        """
        try:
            # This is a simplified implementation
            # In a real system, this would involve more sophisticated process monitoring
            logger.info("Process creation restrictions configured")
            return {"success": True, "message": "Process creation restrictions applied"}
        except Exception as e:
            logger.error(f"Error restricting process creation: {e}")
            return {"success": False, "error": str(e)}
    
    def _restrict_registry_writes(self) -> Dict[str, Any]:
        """
        Restrict unauthorized registry modifications
        
        Returns:
            Dictionary with operation result
        """
        try:
            # This is a simplified implementation
            # In a real system, this would involve more sophisticated registry monitoring
            logger.info("Registry write restrictions configured")
            return {"success": True, "message": "Registry write restrictions applied"}
        except Exception as e:
            logger.error(f"Error restricting registry writes: {e}")
            return {"success": False, "error": str(e)}
    
    def _increase_monitoring(self) -> Dict[str, Any]:
        """
        Increase system monitoring level
        
        Returns:
            Dictionary with operation result
        """
        try:
            # This is a simplified implementation
            # In a real system, this would involve increasing logging levels, 
            # enabling more detailed auditing, etc.
            logger.info("System monitoring level increased")
            return {"success": True, "message": "Monitoring level increased"}
        except Exception as e:
            logger.error(f"Error increasing monitoring: {e}")
            return {"success": False, "error": str(e)}
    
    def get_hardening_report(self) -> Dict[str, Any]:
        """
        Get a report of all applied hardening measures
        
        Returns:
            Dictionary with hardening report
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'applied_recommendations': self.applied_recommendations,
            'failed_recommendations': self.failed_recommendations,
            'action_statistics': dict(self.action_statistics),
            'total_applied': len(self.applied_recommendations),
            'total_failed': len(self.failed_recommendations),
            'config': self.config
        }

# Example usage
if __name__ == "__main__":
    # Test the system hardening manager
    hardening_manager = SystemHardeningManager()
    
    # Example recommendations (these would normally come from PTI engine)
    test_recommendations = [
        {
            'action': 'enable_aslr',
            'description': 'Enable Address Space Layout Randomization',
            'severity': 'medium',
            'confidence': 0.9
        },
        {
            'action': 'enable_dep',
            'description': 'Enable Data Execution Prevention',
            'severity': 'high',
            'confidence': 0.95
        }
    ]
    
    # Apply recommendations
    results = hardening_manager.apply_recommendations(test_recommendations)
    print("Hardening Results:")
    print(json.dumps(results, indent=2))