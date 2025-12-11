"""
AegisAI Cloud Backend Configuration
"""

import os

class Config:
    # Server configuration
    HOST = os.environ.get('AEGISAI_HOST', '0.0.0.0')
    PORT = int(os.environ.get('AEGISAI_PORT', 8080))
    
    # Security configuration
    SECRET_KEY = os.environ.get('AEGISAI_SECRET_KEY', 'aegisai-secret-key-change-in-production')
    
    # Database configuration (for future use)
    DATABASE_URL = os.environ.get('AEGISAI_DATABASE_URL', 'sqlite:///aegisai.db')
    
    # ML model paths
    ML_MODEL_PATH = os.environ.get('AEGISAI_ML_MODEL_PATH', './models')
    
    # YARA rules path
    YARA_RULES_PATH = os.environ.get('AEGISAI_YARA_RULES_PATH', './rules')
    
    # Logging configuration
    LOG_LEVEL = os.environ.get('AEGISAI_LOG_LEVEL', 'INFO')
    
    # WebSocket configuration
    WEBSOCKET_TIMEOUT = int(os.environ.get('AEGISAI_WEBSOCKET_TIMEOUT', 60))
    
    # Threat intelligence configuration
    THREAT_INTEL_UPDATE_INTERVAL = int(os.environ.get('AEGISAI_THREAT_INTEL_INTERVAL', 3600))  # 1 hour
    
class DevelopmentConfig(Config):
    DEBUG = True
    LOG_LEVEL = 'DEBUG'
    
class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get('AEGISAI_SECRET_KEY', '')
    
class TestingConfig(Config):
    TESTING = True
    DATABASE_URL = 'sqlite:///:memory:'
    
# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}