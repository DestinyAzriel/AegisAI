"""
AegisAI Unified Configuration Manager
===================================

This module provides a unified configuration system that manages settings
across all AegisAI components including the Rust agent, Python core,
and Electron frontend.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class ConfigManager:
    """Unified configuration manager for AegisAI system."""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()
        self._validate_config()
    
    def _get_default_config_path(self) -> str:
        """
        Get the default configuration file path.
        
        Returns:
            Path to the default configuration file
        """
        # Try to find existing config file
        possible_paths = [
            Path("aegisai_config.json"),
            Path("config/aegisai_config.json"),
            Path.home() / ".aegisai" / "config.json"
        ]
        
        for path in possible_paths:
            if path.exists():
                return str(path)
        
        # Return default path
        return str(Path("aegisai_config.json"))
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file or use defaults.
        
        Returns:
            Configuration dictionary
        """
        default_config = self._get_default_config()
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                # Merge with default config
                self._merge_config(default_config, user_config)
                logger.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logger.error(f"Failed to load configuration from {self.config_path}: {e}")
        
        return default_config
    
    def _get_default_config(self) -> Dict[str, Any]:
        """
        Get the default configuration.
        
        Returns:
            Default configuration dictionary
        """
        return {
            "version": "1.0",
            "system": {
                "log_level": "INFO",
                "data_directory": str(Path.home() / ".aegisai"),
                "temp_directory": str(Path.home() / ".aegisai" / "temp"),
                "quarantine_directory": str(Path.home() / ".aegisai" / "quarantine")
            },
            "core": {
                "signature_db_path": "signatures.db",
                "enable_realtime": True,
                "enable_quarantine": True,
                "enable_behavioral_analysis": True,
                "enable_threat_intel": True,
                "scan_timeout": 30,
                "watch_directories": [
                    str(Path.home()),
                    str(Path.home() / "Downloads"),
                    str(Path.home() / "Documents"),
                    str(Path.home() / "Desktop")
                ]
            },
            "behavioral": {
                "enabled": True,
                "baseline_duration_minutes": 5,
                "anomaly_threshold": 0.7,
                "monitor_processes": True,
                "monitor_network": True,
                "monitor_file_access": True,
                "suspicious_patterns": {
                    "file_operations": {
                        "high_frequency": 50
                    },
                    "network_activity": {
                        "connections_per_minute": 20
                    },
                    "process_behavior": {
                        "child_processes": 10
                    },
                    "registry_activity": {
                        "modifications_per_minute": 30
                    }
                }
            },
            "rust_agent": {
                "enabled": True,
                "executable_path": None,
                "config_path": None,
                "scanner": {
                    "max_file_size": 104857600,  # 100MB
                    "excluded_paths": [
                        "/tmp",
                        "/var/tmp",
                        "/proc"
                    ],
                    "excluded_extensions": [
                        ".tmp",
                        ".log"
                    ]
                },
                "behavior": {
                    "monitor_processes": True,
                    "monitor_network": True,
                    "monitor_file_access": True
                },
                "ml": {
                    "model_path": "models/test_model.onnx",
                    "enable_local_inference": True,
                    "enable_cloud_inference": True
                },
                "decision": {
                    "threshold_suspicious": 0.3,
                    "threshold_malicious": 0.7,
                    "enable_quarantine": True
                },
                "update": {
                    "server_url": "https://updates.aegisai.local",
                    "check_interval": 3600,
                    "enable_delta_updates": True
                },
                "security": {
                    "server_url": "https://api.aegisai.local",
                    "server_certificate": "certs/server.crt",
                    "client_certificate": "certs/client.crt",
                    "client_private_key": "certs/client.key",
                    "enable_mtls": True,
                    "rate_limit": 100
                },
                "privacy": {
                    "enable_telemetry": True,
                    "telemetry_consent": False,
                    "anonymize_data": True
                }
            },
            "frontend": {
                "theme": "dark",
                "notifications": True,
                "start_minimized": False,
                "smart_scheduling": True,
                "resource_throttling": True
            },
            "cloud": {
                "api_url": "https://api.aegisai.local",
                "telemetry_url": "https://telemetry.aegisai.local",
                "update_url": "https://updates.aegisai.local",
                "enable_cloud_sync": True
            },
            "features": {
                "manual_scans": True,
                "real_time_protection": False,
                "cloud_scanning": False,
                "ai_detection": False,
                "yara_scanning": False,
                "priority_support": False,
                "centralized_management": False
            }
        }
    
    def _merge_config(self, base_config: Dict[str, Any], user_config: Dict[str, Any]) -> None:
        """
        Recursively merge user configuration with base configuration.
        
        Args:
            base_config: Base configuration dictionary
            user_config: User configuration dictionary
        """
        for key, value in user_config.items():
            if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
                self._merge_config(base_config[key], value)
            else:
                base_config[key] = value
    
    def _validate_config(self) -> None:
        """Validate the configuration and set defaults for missing values."""
        # Ensure required directories exist
        data_dir = Path(self.config["system"]["data_directory"])
        temp_dir = Path(self.config["system"]["temp_directory"])
        quarantine_dir = Path(self.config["system"]["quarantine_directory"])
        
        for directory in [data_dir, temp_dir, quarantine_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to the configuration value (e.g., "core.enable_realtime")
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set a configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to the configuration value
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
    
    def save(self) -> bool:
        """
        Save the current configuration to file.
        
        Returns:
            True if save successful, False otherwise
        """
        try:
            # Create directory if it doesn't exist
            config_path = Path(self.config_path)
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save configuration
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2, default=str)
            
            logger.info(f"Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get_rust_config(self) -> Dict[str, Any]:
        """
        Get configuration specifically for the Rust agent.
        
        Returns:
            Rust agent configuration dictionary
        """
        return self.config.get("rust_agent", {})
    
    def get_core_config(self) -> Dict[str, Any]:
        """
        Get configuration specifically for the Python core.
        
        Returns:
            Python core configuration dictionary
        """
        return self.config.get("core", {})
    
    def get_frontend_config(self) -> Dict[str, Any]:
        """
        Get configuration specifically for the frontend.
        
        Returns:
            Frontend configuration dictionary
        """
        return self.config.get("frontend", {})
    
    def get_cloud_config(self) -> Dict[str, Any]:
        """
        Get configuration specifically for cloud services.
        
        Returns:
            Cloud configuration dictionary
        """
        return self.config.get("cloud", {})
    
    def get_feature_config(self) -> Dict[str, Any]:
        """
        Get feature configuration based on license.
        
        Returns:
            Feature configuration dictionary
        """
        return self.config.get("features", {})
    
    def update_from_dict(self, config_dict: Dict[str, Any]) -> None:
        """
        Update configuration from a dictionary.
        
        Args:
            config_dict: Dictionary containing configuration updates
        """
        self._merge_config(self.config, config_dict)
    
    def reload(self) -> None:
        """Reload configuration from file."""
        self.config = self._load_config()
        self._validate_config()
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get the entire configuration.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()

# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None

def get_config_manager(config_path: Optional[str] = None) -> ConfigManager:
    """
    Get the global configuration manager instance.
    
    Args:
        config_path: Path to the configuration file (optional)
        
    Returns:
        Configuration manager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager

# Convenience functions
def get_config(key_path: str, default: Any = None) -> Any:
    """
    Get a configuration value using dot notation.
    
    Args:
        key_path: Dot-separated path to the configuration value
        default: Default value if key is not found
        
    Returns:
        Configuration value or default
    """
    return get_config_manager().get(key_path, default)

def set_config(key_path: str, value: Any) -> None:
    """
    Set a configuration value using dot notation.
    
    Args:
        key_path: Dot-separated path to the configuration value
        value: Value to set
    """
    get_config_manager().set(key_path, value)

def save_config() -> bool:
    """
    Save the current configuration.
    
    Returns:
        True if save successful, False otherwise
    """
    return get_config_manager().save()

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Get configuration manager
    config_manager = get_config_manager()
    
    # Print some configuration values
    print("System data directory:", config_manager.get("system.data_directory"))
    print("Real-time protection enabled:", config_manager.get("core.enable_realtime"))
    print("Rust agent enabled:", config_manager.get("rust_agent.enabled"))
    
    # Update a configuration value
    config_manager.set("core.enable_realtime", False)
    print("Real-time protection enabled:", config_manager.get("core.enable_realtime"))
    
    # Save configuration
    config_manager.save()