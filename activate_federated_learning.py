#!/usr/bin/env python3
"""
AegisAI Federated Learning Activation Script
==========================================

This script activates the federated learning system for AegisAI,
enabling privacy-preserving collaborative model training.
"""

import os
import sys
import json
import logging
import subprocess
import time
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FederatedLearningActivator:
    """Activator for federated learning system"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.federated_dir = self.project_root / "federated-learning"
        self.aggregator_script = self.federated_dir / "federated_aggregator.py"
        self.client_script = self.federated_dir / "federated_client.py"
        self.requirements_file = self.federated_dir / "requirements.txt"
        
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met"""
        logger.info("Checking federated learning prerequisites...")
        
        # Check if federated learning directory exists
        if not self.federated_dir.exists():
            logger.error("Federated learning directory not found")
            return False
            
        # Check if required scripts exist
        if not self.aggregator_script.exists():
            logger.error("Federated aggregator script not found")
            return False
            
        if not self.client_script.exists():
            logger.error("Federated client script not found")
            return False
            
        # Check if requirements file exists
        if not self.requirements_file.exists():
            logger.warning("Requirements file not found, creating default...")
            self._create_default_requirements()
            
        logger.info("All prerequisites met")
        return True
    
    def _create_default_requirements(self):
        """Create default requirements file"""
        default_requirements = [
            "numpy>=1.21.0",
            "flask>=2.0.0",
            "requests>=2.25.0",
            "cryptography>=3.4.0"
        ]
        
        with open(self.requirements_file, 'w') as f:
            f.write('\n'.join(default_requirements))
        
        logger.info("Created default requirements file")
    
    def install_dependencies(self) -> bool:
        """Install federated learning dependencies"""
        logger.info("Installing federated learning dependencies...")
        
        try:
            # Install requirements
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", str(self.requirements_file)
            ], check=True, capture_output=True, text=True)
            
            logger.info("Dependencies installed successfully")
            logger.debug(f"Installation output: {result.stdout}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {e}")
            logger.error(f"Error output: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Error installing dependencies: {e}")
            return False
    
    def start_aggregator(self) -> bool:
        """Start the federated learning aggregator"""
        logger.info("Starting federated learning aggregator...")
        
        try:
            # Start aggregator in background
            process = subprocess.Popen([
                sys.executable, str(self.aggregator_script)
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Give it a moment to start
            time.sleep(2)
            
            # Check if process is still running
            if process.poll() is None:
                logger.info("Federated learning aggregator started successfully")
                logger.info(f"Aggregator PID: {process.pid}")
                return True
            else:
                # Process has terminated
                stdout, stderr = process.communicate()
                logger.error("Federated learning aggregator failed to start")
                logger.error(f"Stdout: {stdout.decode()}")
                logger.error(f"Stderr: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting aggregator: {e}")
            return False
    
    def test_client_connection(self) -> bool:
        """Test client connection to aggregator"""
        logger.info("Testing federated learning client connection...")
        
        try:
            # Run client in test mode
            result = subprocess.run([
                sys.executable, str(self.client_script), "--test"
            ], check=True, capture_output=True, text=True, timeout=30)
            
            logger.info("Client connection test successful")
            logger.debug(f"Test output: {result.stdout}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Client connection test failed: {e}")
            logger.error(f"Error output: {e.stderr}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Client connection test timed out")
            return False
        except Exception as e:
            logger.error(f"Error testing client connection: {e}")
            return False
    
    def create_configuration(self) -> bool:
        """Create federated learning configuration"""
        logger.info("Creating federated learning configuration...")
        
        try:
            config_dir = self.federated_dir / "config"
            config_dir.mkdir(exist_ok=True)
            
            # Create default configuration
            config = {
                "aggregator": {
                    "host": "localhost",
                    "port": 8085,
                    "ssl_enabled": False,
                    "max_clients": 1000,
                    "round_duration": 3600  # 1 hour
                },
                "privacy": {
                    "epsilon": 1.0,
                    "delta": 1e-5,
                    "clip_norm": 1.0
                },
                "model": {
                    "input_shape": [100],
                    "learning_rate": 0.01,
                    "batch_size": 32
                }
            }
            
            config_file = config_dir / "federated_config.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info("Federated learning configuration created")
            return True
            
        except Exception as e:
            logger.error(f"Error creating configuration: {e}")
            return False
    
    def activate(self) -> bool:
        """Activate the federated learning system"""
        logger.info("Starting federated learning activation...")
        
        # Check prerequisites
        if not self.check_prerequisites():
            logger.error("Prerequisites not met, cannot activate federated learning")
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            logger.error("Failed to install dependencies")
            return False
        
        # Create configuration
        if not self.create_configuration():
            logger.error("Failed to create configuration")
            return False
        
        # Start aggregator
        if not self.start_aggregator():
            logger.error("Failed to start aggregator")
            return False
        
        # Test client connection
        if not self.test_client_connection():
            logger.error("Client connection test failed")
            return False
        
        logger.info("✅ Federated learning system activated successfully!")
        logger.info("")
        logger.info("Next steps:")
        logger.info("1. Configure federated learning parameters in federated-learning/config/")
        logger.info("2. Deploy aggregator to production server")
        logger.info("3. Enable federated learning in endpoint agents")
        logger.info("4. Monitor system performance and privacy metrics")
        
        return True

def main():
    """Main activation function"""
    logger.info("=" * 60)
    logger.info("AEGISAI FEDERATED LEARNING ACTIVATION")
    logger.info("=" * 60)
    
    # Create activator
    activator = FederatedLearningActivator()
    
    # Activate system
    success = activator.activate()
    
    if success:
        logger.info("\n🎉 Federated learning activation completed successfully!")
        return 0
    else:
        logger.error("\n❌ Federated learning activation failed!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)