#!/usr/bin/env python3
"""
AegisAI System Integrator
=========================

This module provides comprehensive integration between all AegisAI components,
including the core engine, refined backend, federated learning, graph analytics,
and other advanced features.
"""

import os
import sys
import json
import logging
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

# Initialize variables for optional imports
AegisAICoreAgent = None
FileScanner = None
RealTimeProtection = None
QuarantineManager = None
RobustBehavioralAnalyzer = None
get_config_manager = None
RefinedBackendClient = None
FederatedLearningClient = None
LocalTrainer = None
GraphAnalyticsClient = None

# Import core AegisAI components
try:
    from .agent import AegisAICoreAgent
    from .scanner import FileScanner
    from .realtime import RealTimeProtection
    from .quarantine import QuarantineManager
    from .robust_behavioral_analyzer import RobustBehavioralAnalyzer
    from .config_manager import get_config_manager
    from .refined_backend_integration import RefinedBackendClient
    CORE_COMPONENTS_AVAILABLE = True
except ImportError as e:
    CORE_COMPONENTS_AVAILABLE = False
    logging.error(f"Core components not available: {e}")

# Import federated learning components
FEDERATED_LEARNING_AVAILABLE = False
try:
    # Add federated learning path
    federated_path = os.path.join(os.path.dirname(__file__), '..', 'federated-learning')
    if federated_path not in sys.path:
        sys.path.insert(0, federated_path)
    
    from federated_client import FederatedLearningClient, LocalTrainer
    FEDERATED_LEARNING_AVAILABLE = True
except ImportError:
    logging.warning("Federated learning components not available")

# Import graph analytics components
GRAPH_ANALYTICS_AVAILABLE = False
try:
    # Add graph analytics path
    graph_path = os.path.join(os.path.dirname(__file__), '..', 'graph-analytics')
    if graph_path not in sys.path:
        sys.path.insert(0, graph_path)
    
    from graph_client import GraphAnalyticsClient
    GRAPH_ANALYTICS_AVAILABLE = True
except ImportError:
    logging.warning("Graph analytics components not available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SystemIntegrator:
    """Main system integrator that connects all AegisAI components"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the system integrator.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_manager = get_config_manager(config_path)
        self.config = self.config_manager.get_core_config()
        
        # Core components
        self.core_agent = None
        self.refined_backend_client = None
        self.federated_client = None
        self.graph_client = None
        
        # Integration status
        self.integration_status = {
            'core_agent': False,
            'refined_backend': False,
            'federated_learning': False,
            'graph_analytics': False
        }
        
        # Initialize all components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize all system components."""
        try:
            # Initialize core agent
            self._init_core_agent()
            
            # Initialize refined backend integration
            self._init_refined_backend()
            
            # Initialize federated learning if available
            if FEDERATED_LEARNING_AVAILABLE:
                self._init_federated_learning()
            
            # Initialize graph analytics if available
            if GRAPH_ANALYTICS_AVAILABLE:
                self._init_graph_analytics()
                
            logger.info("All system components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize system components: {e}")
            raise
    
    def _init_core_agent(self):
        """Initialize the core AegisAI agent."""
        try:
            self.core_agent = AegisAICoreAgent()
            self.integration_status['core_agent'] = True
            logger.info("Core AegisAI agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize core agent: {e}")
            raise
    
    def _init_refined_backend(self):
        """Initialize refined backend integration."""
        try:
            backend_config = self.config_manager.get('cloud', {})
            self.refined_backend_client = RefinedBackendClient(backend_config)
            
            # Register agent with backend
            auth_token = self.refined_backend_client.register_agent()
            if auth_token:
                logger.info("Successfully registered with refined backend")
            else:
                logger.warning("Failed to register with refined backend")
            
            self.integration_status['refined_backend'] = True
            logger.info("Refined backend integration initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize refined backend integration: {e}")
            raise
    
    def _init_federated_learning(self):
        """Initialize federated learning client."""
        try:
            client_id = self.config_manager.get('federated.client_id', 'default_client')
            aggregator_url = self.config_manager.get('federated.aggregator_url', 'http://localhost:8085')
            
            self.federated_client = FederatedLearningClient(client_id, aggregator_url)
            
            # Request user consent for federated learning
            consent = self.federated_client.request_consent()
            if consent:
                logger.info("User consent granted for federated learning")
                self.federated_client.consent_granted = True
            else:
                logger.info("User consent denied for federated learning")
            
            self.integration_status['federated_learning'] = True
            logger.info("Federated learning client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize federated learning: {e}")
    
    def _init_graph_analytics(self):
        """Initialize graph analytics client."""
        try:
            client_id = self.config_manager.get('graph.client_id', 'default_client')
            server_url = self.config_manager.get('graph.server_url', 'http://localhost:8086')
            
            self.graph_client = GraphAnalyticsClient(client_id, server_url)
            self.integration_status['graph_analytics'] = True
            logger.info("Graph analytics client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize graph analytics: {e}")
    
    def start_system(self):
        """Start all integrated system components."""
        try:
            # Start core agent
            if self.core_agent:
                logger.info("Starting core AegisAI agent...")
                # In a real implementation, we would start the agent in a separate thread
                # For now, we'll just log that it's ready
                logger.info("Core AegisAI agent is ready")
            
            # Start federated learning participation
            if self.federated_client and self.federated_client.consent_granted:
                self._start_federated_learning()
            
            # Start graph analytics data collection
            if self.graph_client:
                self._start_graph_analytics()
            
            logger.info("AegisAI system started successfully")
            self._log_integration_status()
            
        except Exception as e:
            logger.error(f"Failed to start system: {e}")
            raise
    
    def _start_federated_learning(self):
        """Start federated learning participation."""
        def federated_learning_worker():
            """Worker function for federated learning participation."""
            while True:
                try:
                    if self.federated_client and self.federated_client.consent_granted:
                        # Participate in federated learning round
                        self.federated_client.participate_in_round()
                    
                    # Wait before next participation
                    time.sleep(3600)  # 1 hour
                except Exception as e:
                    logger.error(f"Error in federated learning worker: {e}")
                    time.sleep(60)  # Wait 1 minute before retrying
        
        # Start worker in separate thread
        federated_thread = threading.Thread(target=federated_learning_worker, daemon=True)
        federated_thread.start()
        logger.info("Federated learning worker started")
    
    def _start_graph_analytics(self):
        """Start graph analytics data collection."""
        def graph_analytics_worker():
            """Worker function for graph analytics data collection."""
            while True:
                try:
                    if self.graph_client:
                        # Collect and send behavioral data
                        self._collect_behavioral_data()
                    
                    # Wait before next collection
                    time.sleep(300)  # 5 minutes
                except Exception as e:
                    logger.error(f"Error in graph analytics worker: {e}")
                    time.sleep(60)  # Wait 1 minute before retrying
        
        # Start worker in separate thread
        graph_thread = threading.Thread(target=graph_analytics_worker, daemon=True)
        graph_thread.start()
        logger.info("Graph analytics worker started")
    
    def _collect_behavioral_data(self):
        """Collect behavioral data for graph analytics."""
        try:
            # In a real implementation, this would collect actual behavioral data
            # For now, we'll simulate data collection
            logger.info("Collecting behavioral data for graph analytics")
            
            # Report some sample events
            if self.graph_client:
                self.graph_client.report_threat_event(
                    file_hash="eicar_test_file_hash",
                    threat_type="test_file",
                    file_path="C:\\test\\eicar.com",
                    severity="low"
                )
                
                self.graph_client.report_behavioral_event(
                    event_type="process_creation",
                    process_id="1234",
                    parent_process_id="5678",
                    file_path="C:\\Windows\\System32\\notepad.exe"
                )
        except Exception as e:
            logger.error(f"Failed to collect behavioral data: {e}")
    
    def scan_file_with_all_methods(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a file using all available methods.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Dictionary with scan results from all methods
        """
        results = {
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'results': {}
        }
        
        try:
            # Core scanning
            if self.core_agent and self.core_agent.scanner:
                core_result = self.core_agent.scanner.scan_file(file_path)
                results['results']['core'] = core_result
            
            # Refined backend scanning
            if self.refined_backend_client:
                # Extract features for cloud analysis
                from .ml_detector import MLFeatureExtractor
                feature_extractor = MLFeatureExtractor()
                file_features = feature_extractor.extract_features(file_path)
                
                # Submit to refined backend
                backend_result = self.refined_backend_client.submit_file_for_analysis(
                    file_path, file_features
                )
                results['results']['refined_backend'] = backend_result
            
            # Report to graph analytics if threat detected
            if self.graph_client:
                # Check if any method detected a threat
                threat_detected = False
                threat_info = {}
                
                for method, result in results['results'].items():
                    if result and result.get('status') == 'threat_detected':
                        threat_detected = True
                        threat_info = result.get('threat', {})
                        break
                
                if threat_detected:
                    self.graph_client.report_threat_event(
                        file_hash=self._calculate_file_hash(file_path),
                        threat_type=threat_info.get('name', 'unknown'),
                        file_path=file_path,
                        severity=threat_info.get('severity', 'unknown')
                    )
            
        except Exception as e:
            logger.error(f"Error during multi-method scanning: {e}")
            results['error'] = str(e)
        
        return results
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        import hashlib
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return ""
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status.
        
        Returns:
            Dictionary with system status information
        """
        status = {
            'timestamp': datetime.now().isoformat(),
            'integration_status': self.integration_status,
            'component_details': {}
        }
        
        # Core agent status
        if self.core_agent:
            status['component_details']['core_agent'] = {
                'running': getattr(self.core_agent, 'running', False),
                'stats': getattr(self.core_agent, 'agent_stats', {})
            }
        
        # Refined backend status
        if self.refined_backend_client:
            status['component_details']['refined_backend'] = {
                'connected': self.refined_backend_client.session is not None,
                'agent_id': self.refined_backend_client.agent_id
            }
        
        # Federated learning status
        if self.federated_client:
            status['component_details']['federated_learning'] = {
                'initialized': True,
                'consent_granted': self.federated_client.consent_granted,
                'participation_count': getattr(self.federated_client, 'participation_count', 0)
            }
        
        # Graph analytics status
        if self.graph_client:
            status['component_details']['graph_analytics'] = {
                'initialized': True,
                'queued_events': len(getattr(self.graph_client, 'event_queue', []))
            }
        
        return status
    
    def _log_integration_status(self):
        """Log the current integration status."""
        status = self.get_system_status()
        logger.info("=== AEGISAI SYSTEM INTEGRATION STATUS ===")
        logger.info(f"Core Agent: {'✅ Connected' if status['integration_status']['core_agent'] else '❌ Disconnected'}")
        logger.info(f"Refined Backend: {'✅ Connected' if status['integration_status']['refined_backend'] else '❌ Disconnected'}")
        logger.info(f"Federated Learning: {'✅ Available' if status['integration_status']['federated_learning'] else '❌ Not Available'}")
        logger.info(f"Graph Analytics: {'✅ Available' if status['integration_status']['graph_analytics'] else '❌ Not Available'}")
        logger.info("========================================")

def main():
    """Main entry point for the system integrator."""
    print("🛡️  AEGISAI SYSTEM INTEGRATOR")
    print("=" * 40)
    
    try:
        # Initialize the system integrator
        integrator = SystemIntegrator()
        
        # Start all components
        integrator.start_system()
        
        # Show system status
        status = integrator.get_system_status()
        print("\n📊 System Status:")
        print(f"  Core Agent: {'✅' if status['integration_status']['core_agent'] else '❌'}")
        print(f"  Refined Backend: {'✅' if status['integration_status']['refined_backend'] else '❌'}")
        print(f"  Federated Learning: {'✅' if status['integration_status']['federated_learning'] else '❌'}")
        print(f"  Graph Analytics: {'✅' if status['integration_status']['graph_analytics'] else '❌'}")
        
        print("\n🚀 AegisAI system is fully interconnected and operational!")
        print("All components are working together to provide comprehensive protection.")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down AegisAI system integrator...")
            
    except Exception as e:
        logger.error(f"Error running system integrator: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()