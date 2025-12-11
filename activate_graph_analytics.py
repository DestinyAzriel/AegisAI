#!/usr/bin/env python3
"""
AegisAI Graph Analytics Activation Script
=======================================

This script activates the graph analytics system for AegisAI,
enabling advanced threat detection through relationship mapping.
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

class GraphAnalyticsActivator:
    """Activator for graph analytics system"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.graph_dir = self.project_root / "graph-analytics"
        self.pipeline_script = self.graph_dir / "graph_analytics_pipeline.py"
        self.client_script = self.graph_dir / "graph_client.py"
        self.requirements_file = self.graph_dir / "requirements.txt"
        
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met"""
        logger.info("Checking graph analytics prerequisites...")
        
        # Check if graph analytics directory exists
        if not self.graph_dir.exists():
            logger.error("Graph analytics directory not found")
            return False
            
        # Check if required scripts exist
        if not self.pipeline_script.exists():
            logger.error("Graph analytics pipeline script not found")
            return False
            
        if not self.client_script.exists():
            logger.error("Graph client script not found")
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
            "networkx>=2.6.0",
            "numpy>=1.21.0",
            "pandas>=1.3.0",
            "flask>=2.0.0",
            "requests>=2.25.0"
        ]
        
        with open(self.requirements_file, 'w') as f:
            f.write('\n'.join(default_requirements))
        
        logger.info("Created default requirements file")
    
    def install_dependencies(self) -> bool:
        """Install graph analytics dependencies"""
        logger.info("Installing graph analytics dependencies...")
        
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
    
    def start_pipeline(self) -> bool:
        """Start the graph analytics pipeline"""
        logger.info("Starting graph analytics pipeline...")
        
        try:
            # Start pipeline in background
            process = subprocess.Popen([
                sys.executable, str(self.pipeline_script)
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Give it a moment to start
            time.sleep(2)
            
            # Check if process is still running
            if process.poll() is None:
                logger.info("Graph analytics pipeline started successfully")
                logger.info(f"Pipeline PID: {process.pid}")
                return True
            else:
                # Process has terminated
                stdout, stderr = process.communicate()
                logger.error("Graph analytics pipeline failed to start")
                logger.error(f"Stdout: {stdout.decode()}")
                logger.error(f"Stderr: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting pipeline: {e}")
            return False
    
    def test_client_connection(self) -> bool:
        """Test client connection to pipeline"""
        logger.info("Testing graph analytics client connection...")
        
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
        """Create graph analytics configuration"""
        logger.info("Creating graph analytics configuration...")
        
        try:
            config_dir = self.graph_dir / "config"
            config_dir.mkdir(exist_ok=True)
            
            # Create default configuration
            config = {
                "pipeline": {
                    "host": "localhost",
                    "port": 8086,
                    "ssl_enabled": False,
                    "max_events": 10000,
                    "campaign_detection_threshold": 3
                },
                "graph": {
                    "node_types": ["event", "device", "file", "process", "network"],
                    "relationship_types": ["temporal", "file_propagation", "process_hierarchy", "network_communication"],
                    "time_window_hours": 24
                },
                "campaign_detection": {
                    "min_campaign_size": 3,
                    "confidence_threshold": 0.7,
                    "temporal_clustering_enabled": True
                }
            }
            
            config_file = config_dir / "graph_config.json"
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info("Graph analytics configuration created")
            return True
            
        except Exception as e:
            logger.error(f"Error creating configuration: {e}")
            return False
    
    def activate(self) -> bool:
        """Activate the graph analytics system"""
        logger.info("Starting graph analytics activation...")
        
        # Check prerequisites
        if not self.check_prerequisites():
            logger.error("Prerequisites not met, cannot activate graph analytics")
            return False
        
        # Install dependencies
        if not self.install_dependencies():
            logger.error("Failed to install dependencies")
            return False
        
        # Create configuration
        if not self.create_configuration():
            logger.error("Failed to create configuration")
            return False
        
        # Start pipeline
        if not self.start_pipeline():
            logger.error("Failed to start pipeline")
            return False
        
        # Test client connection
        if not self.test_client_connection():
            logger.error("Client connection test failed")
            return False
        
        logger.info("✅ Graph analytics system activated successfully!")
        logger.info("")
        logger.info("Next steps:")
        logger.info("1. Configure graph analytics parameters in graph-analytics/config/")
        logger.info("2. Deploy pipeline to production server")
        logger.info("3. Enable graph analytics in endpoint agents")
        logger.info("4. Monitor campaign detection performance")
        
        return True

def main():
    """Main activation function"""
    logger.info("=" * 60)
    logger.info("AEGISAI GRAPH ANALYTICS ACTIVATION")
    logger.info("=" * 60)
    
    # Create activator
    activator = GraphAnalyticsActivator()
    
    # Activate system
    success = activator.activate()
    
    if success:
        logger.info("\n🎉 Graph analytics activation completed successfully!")
        return 0
    else:
        logger.error("\n❌ Graph analytics activation failed!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)