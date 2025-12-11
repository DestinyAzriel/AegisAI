#!/usr/bin/env python3
"""
AegisAI Graph Analytics Client
============================

Client implementation that demonstrates how endpoint agents would contribute
data to the graph analytics pipeline for campaign detection.
"""

import json
import logging
import requests
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import time
import uuid

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class DeviceInfo:
    """Information about the device"""
    device_id: str
    hostname: str
    os_version: str
    agent_version: str
    ip_address: str

@dataclass
class ThreatEvent:
    """Represents a threat detection event"""
    event_id: str
    file_hash: str
    device_id: str
    timestamp: str  # ISO format string
    threat_type: str
    severity: str
    file_path: str
    process_id: Optional[str] = None
    parent_process_id: Optional[str] = None
    network_connections: Optional[List[Dict[str, Any]]] = None

@dataclass
class BehavioralEvent:
    """Represents a behavioral event"""
    event_id: str
    device_id: str
    timestamp: str  # ISO format string
    event_type: str
    process_id: Optional[str] = None
    parent_process_id: Optional[str] = None
    file_path: Optional[str] = None
    network_info: Optional[Dict[str, Any]] = None

class GraphAnalyticsClient:
    """Client for contributing data to the graph analytics pipeline"""
    
    def __init__(self, client_id: str, server_url: str = "http://localhost:8086"):
        """
        Initialize graph analytics client.
        
        Args:
            client_id: Unique client identifier
            server_url: URL of the graph analytics server
        """
        self.client_id = client_id
        self.server_url = server_url
        self.session = requests.Session()
        self.device_info = self._collect_device_info()
        self.event_queue = []
        self.max_queue_size = 100
        self.batch_size = 10
        
        logger.info(f"Initialized graph analytics client {client_id}")
    
    def _collect_device_info(self) -> DeviceInfo:
        """
        Collect device information.
        
        Returns:
            Device information
        """
        # In a real implementation, this would collect actual device information
        # For this prototype, we'll generate simulated data
        hostname = f"device-{uuid.uuid4().hex[:8]}"
        device_id = hashlib.md5(hostname.encode()).hexdigest()
        
        return DeviceInfo(
            device_id=device_id,
            hostname=hostname,
            os_version="Windows 10.0.19042",
            agent_version="1.0.0",
            ip_address="192.168.1.100"
        )
    
    def report_threat_event(self, file_hash: str, threat_type: str, 
                          file_path: str, severity: str = "medium",
                          process_id: Optional[str] = None,
                          parent_process_id: Optional[str] = None,
                          network_connections: Optional[List[Dict[str, Any]]] = None):
        """
        Report a threat detection event.
        
        Args:
            file_hash: Hash of the detected file
            threat_type: Type of threat detected
            file_path: Path to the file
            severity: Severity level
            process_id: ID of the process that triggered the event
            parent_process_id: ID of the parent process
            network_connections: Network connections associated with the event
        """
        event = ThreatEvent(
            event_id=f"threat_{uuid.uuid4().hex}",
            file_hash=file_hash,
            device_id=self.device_info.device_id,
            timestamp=datetime.now().isoformat(),
            threat_type=threat_type,
            severity=severity,
            file_path=file_path,
            process_id=process_id,
            parent_process_id=parent_process_id,
            network_connections=network_connections
        )
        
        self.event_queue.append(event)
        logger.info(f"Queued threat event: {threat_type} ({file_hash[:8]}...)")
        
        # Send batch if queue is full
        if len(self.event_queue) >= self.max_queue_size:
            self._send_batch()
    
    def report_behavioral_event(self, event_type: str,
                              process_id: Optional[str] = None,
                              parent_process_id: Optional[str] = None,
                              file_path: Optional[str] = None,
                              network_info: Optional[Dict[str, Any]] = None):
        """
        Report a behavioral event.
        
        Args:
            event_type: Type of behavioral event
            process_id: ID of the process
            parent_process_id: ID of the parent process
            file_path: Path to file involved in the event
            network_info: Network information
        """
        event = BehavioralEvent(
            event_id=f"behavior_{uuid.uuid4().hex}",
            device_id=self.device_info.device_id,
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            process_id=process_id,
            parent_process_id=parent_process_id,
            file_path=file_path,
            network_info=network_info
        )
        
        self.event_queue.append(event)
        logger.info(f"Queued behavioral event: {event_type}")
        
        # Send batch if queue is full
        if len(self.event_queue) >= self.max_queue_size:
            self._send_batch()
    
    def _send_batch(self):
        """Send a batch of events to the server."""
        if not self.event_queue:
            return
        
        # Take a batch of events
        batch = self.event_queue[:self.batch_size]
        remaining = self.event_queue[self.batch_size:]
        
        try:
            # Prepare batch data
            batch_data = {
                'device_info': asdict(self.device_info),
                'events': [asdict(event) for event in batch]
            }
            
            # Send to server
            response = self.session.post(
                f"{self.server_url}/api/v1/events",
                json=batch_data
            )
            response.raise_for_status()
            
            logger.info(f"Sent batch of {len(batch)} events to server")
            
            # Keep remaining events
            self.event_queue = remaining
            
        except Exception as e:
            logger.error(f"Failed to send batch to server: {e}")
            # Keep all events in queue for retry
    
    def flush_events(self):
        """Send all queued events to the server."""
        while self.event_queue:
            self._send_batch()
            # Small delay to avoid overwhelming the server
            time.sleep(0.1)
    
    def register_device(self) -> bool:
        """
        Register device with the graph analytics server.
        
        Returns:
            True if registration successful, False otherwise
        """
        try:
            registration_data = {
                'device_info': asdict(self.device_info),
                'registration_time': datetime.now().isoformat()
            }
            
            response = self.session.post(
                f"{self.server_url}/api/v1/register",
                json=registration_data
            )
            response.raise_for_status()
            
            logger.info(f"Registered device {self.device_info.device_id} with server")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register device: {e}")
            return False

class ThreatSimulator:
    """Simulator for generating threat events"""
    
    def __init__(self, client: GraphAnalyticsClient):
        """
        Initialize threat simulator.
        
        Args:
            client: Graph analytics client
        """
        self.client = client
        self.simulation_count = 0
    
    def simulate_threat_activity(self):
        """Simulate threat detection activity."""
        self.simulation_count += 1
        logger.info(f"Running threat simulation #{self.simulation_count}")
        
        # Simulate different types of threat events
        threat_types = ["trojan", "ransomware", "worm", "backdoor", "rootkit"]
        file_paths = [
            "C:\\temp\\malware.exe",
            "C:\\Users\\User\\Downloads\\suspicious.pdf",
            "C:\\Windows\\Temp\\backdoor.dll",
            "C:\\ProgramData\\ransomware.exe"
        ]
        
        # Generate some threat events
        for i in range(3):
            file_hash = hashlib.md5(f"file_{self.simulation_count}_{i}".encode()).hexdigest()
            threat_type = threat_types[i % len(threat_types)]
            file_path = file_paths[i % len(file_paths)]
            severity = "high" if i == 0 else "medium"
            
            self.client.report_threat_event(
                file_hash=file_hash,
                threat_type=threat_type,
                file_path=file_path,
                severity=severity,
                process_id=f"process_{i}",
                parent_process_id="explorer.exe" if i > 0 else None
            )
        
        # Generate some behavioral events
        behavior_types = ["process_creation", "file_access", "network_connection", "registry_modification"]
        for i in range(2):
            behavior_type = behavior_types[i % len(behavior_types)]
            
            self.client.report_behavioral_event(
                event_type=behavior_type,
                process_id=f"process_{i}",
                parent_process_id="explorer.exe",
                file_path=file_paths[i] if i < len(file_paths) else None,
                network_info={"destination": "192.168.1.100", "port": 443} if behavior_type == "network_connection" else None
            )
        
        # Flush events
        self.client.flush_events()
        
        logger.info(f"Completed threat simulation #{self.simulation_count}")

# Example usage and demonstration
def demonstrate_graph_client():
    """Demonstrate graph analytics client functionality."""
    logger.info("Demonstrating graph analytics client...")
    
    # Initialize client
    client = GraphAnalyticsClient("test_client_001", "http://localhost:8086")
    
    # Register device
    if client.register_device():
        logger.info("Device registered successfully")
        
        # Create threat simulator
        simulator = ThreatSimulator(client)
        
        # Run a few simulations
        for i in range(3):
            simulator.simulate_threat_activity()
            client.flush_events()
            time.sleep(1)
        
        logger.info("Graph client demonstration completed")
    else:
        logger.error("Failed to register device")

if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        # Run a simple test
        client = GraphAnalyticsClient("test_client_001", "http://localhost:8086")
        if client.register_device():
            logger.info("Client test successful")
        else:
            logger.error("Client test failed")
    else:
        demonstrate_graph_client()