#!/usr/bin/env python3
"""
AegisAI Graph Analytics Pipeline
===============================

Implementation of a graph analytics pipeline for campaign detection that identifies
related threats and lateral movement patterns rather than only scoring files independently.
"""

import networkx as nx
import numpy as np
import pandas as pd
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ThreatEvent:
    """Represents a threat detection event"""
    event_id: str
    file_hash: str
    device_id: str
    timestamp: datetime
    threat_type: str
    severity: str
    file_path: str
    process_id: Optional[str] = None
    parent_process_id: Optional[str] = None
    network_connections: Optional[List[Dict[str, Any]]] = None

@dataclass
class Campaign:
    """Represents a detected campaign"""
    campaign_id: str
    threat_events: List[ThreatEvent]
    devices_involved: List[str]
    files_involved: List[str]
    start_time: datetime
    end_time: datetime
    confidence: float
    description: str

class ThreatGraph:
    """Graph representation of threat events and relationships"""
    
    def __init__(self):
        """Initialize threat graph."""
        self.graph = nx.MultiDiGraph()
        self.event_index = {}  # Map event_id to node_id
        self.device_index = {}  # Map device_id to node_ids
        self.file_index = {}  # Map file_hash to node_ids
        
        logger.info("Initialized threat graph")
    
    def add_threat_event(self, event: ThreatEvent):
        """
        Add a threat event to the graph.
        
        Args:
            event: Threat event to add
        """
        # Create node for the event
        node_id = f"event_{event.event_id}"
        node_attrs = {
            'type': 'event',
            'event_id': event.event_id,
            'file_hash': event.file_hash,
            'device_id': event.device_id,
            'timestamp': event.timestamp,
            'threat_type': event.threat_type,
            'severity': event.severity,
            'file_path': event.file_path
        }
        
        self.graph.add_node(node_id, **node_attrs)
        
        # Update indices
        self.event_index[event.event_id] = node_id
        
        if event.device_id not in self.device_index:
            self.device_index[event.device_id] = []
        self.device_index[event.device_id].append(node_id)
        
        if event.file_hash not in self.file_index:
            self.file_index[event.file_hash] = []
        self.file_index[event.file_hash].append(node_id)
        
        # Add edges for relationships
        self._add_device_relationship(event, node_id)
        self._add_file_relationship(event, node_id)
        self._add_process_relationship(event, node_id)
        self._add_network_relationship(event, node_id)
        
        logger.info(f"Added threat event {event.event_id} to graph")
    
    def _add_device_relationship(self, event: ThreatEvent, node_id: str):
        """Add device relationship edges."""
        # Connect to previous events on the same device
        if event.device_id in self.device_index:
            for prev_node_id in self.device_index[event.device_id]:
                if prev_node_id != node_id:
                    prev_timestamp = self.graph.nodes[prev_node_id]['timestamp']
                    time_diff = abs((event.timestamp - prev_timestamp).total_seconds())
                    # Add temporal edge (more recent events point to older ones)
                    if event.timestamp > prev_timestamp:
                        self.graph.add_edge(node_id, prev_node_id, 
                                          relationship='temporal', 
                                          time_diff=time_diff)
    
    def _add_file_relationship(self, event: ThreatEvent, node_id: str):
        """Add file relationship edges."""
        # Connect to previous events involving the same file
        if event.file_hash in self.file_index:
            for prev_node_id in self.file_index[event.file_hash]:
                if prev_node_id != node_id:
                    self.graph.add_edge(node_id, prev_node_id, 
                                      relationship='file_propagation')
    
    def _add_process_relationship(self, event: ThreatEvent, node_id: str):
        """Add process relationship edges."""
        if event.process_id and event.parent_process_id:
            # Connect to parent process if we have it
            # This would require tracking process events separately
            pass
    
    def _add_network_relationship(self, event: ThreatEvent, node_id: str):
        """Add network relationship edges."""
        if event.network_connections:
            for conn in event.network_connections:
                # Connect to events with similar network patterns
                # This is a simplified implementation
                pass
    
    def get_device_subgraph(self, device_id: str) -> nx.MultiDiGraph:
        """
        Get subgraph for a specific device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Subgraph for the device
        """
        if device_id not in self.device_index:
            return nx.MultiDiGraph()
        
        node_ids = self.device_index[device_id]
        return self.graph.subgraph(node_ids)
    
    def get_file_subgraph(self, file_hash: str) -> nx.MultiDiGraph:
        """
        Get subgraph for a specific file.
        
        Args:
            file_hash: File hash
            
        Returns:
            Subgraph for the file
        """
        if file_hash not in self.file_index:
            return nx.MultiDiGraph()
        
        node_ids = self.file_index[file_hash]
        return self.graph.subgraph(node_ids)
    
    def get_graph_statistics(self) -> Dict[str, Any]:
        """
        Get graph statistics.
        
        Returns:
            Graph statistics
        """
        return {
            'nodes': self.graph.number_of_nodes(),
            'edges': self.graph.number_of_edges(),
            'devices': len(self.device_index),
            'files': len(self.file_index),
            'events': len(self.event_index)
        }

class CampaignDetector:
    """Detector for threat campaigns using graph analytics"""
    
    def __init__(self, min_campaign_size: int = 3, time_window_hours: int = 24):
        """
        Initialize campaign detector.
        
        Args:
            min_campaign_size: Minimum number of events for a campaign
            time_window_hours: Time window for campaign detection (hours)
        """
        self.min_campaign_size = min_campaign_size
        self.time_window = timedelta(hours=time_window_hours)
        self.detected_campaigns = []
        
        logger.info(f"Initialized campaign detector (min_size={min_campaign_size}, time_window={time_window_hours}h)")
    
    def detect_campaigns(self, threat_graph: ThreatGraph) -> List[Campaign]:
        """
        Detect campaigns in the threat graph.
        
        Args:
            threat_graph: Threat graph to analyze
            
        Returns:
            List of detected campaigns
        """
        logger.info("Detecting campaigns in threat graph...")
        
        # Find connected components (potential campaigns)
        undirected_graph = threat_graph.graph.to_undirected()
        connected_components = list(nx.connected_components(undirected_graph))
        
        campaigns = []
        for i, component in enumerate(connected_components):
            if len(component) >= self.min_campaign_size:
                campaign = self._analyze_component(threat_graph, component, i)
                if campaign:
                    campaigns.append(campaign)
        
        logger.info(f"Detected {len(campaigns)} campaigns")
        self.detected_campaigns.extend(campaigns)
        return campaigns
    
    def _analyze_component(self, threat_graph: ThreatGraph, component: set, campaign_index: int) -> Optional[Campaign]:
        """
        Analyze a connected component for campaign characteristics.
        
        Args:
            threat_graph: Threat graph
            component: Connected component nodes
            campaign_index: Index for campaign ID
            
        Returns:
            Campaign object or None if not a valid campaign
        """
        # Extract events from component
        events = []
        devices = set()
        files = set()
        timestamps = []
        
        for node_id in component:
            node_data = threat_graph.graph.nodes[node_id]
            if node_data.get('type') == 'event':
                event = ThreatEvent(
                    event_id=node_data['event_id'],
                    file_hash=node_data['file_hash'],
                    device_id=node_data['device_id'],
                    timestamp=node_data['timestamp'],
                    threat_type=node_data['threat_type'],
                    severity=node_data['severity'],
                    file_path=node_data['file_path']
                )
                events.append(event)
                devices.add(event.device_id)
                files.add(event.file_hash)
                timestamps.append(event.timestamp)
        
        if len(events) < self.min_campaign_size:
            return None
        
        # Calculate campaign statistics
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
        
        # Check if events are within time window
        if duration > self.time_window:
            # This might be multiple campaigns or a long-running campaign
            # For now, we'll still consider it but with lower confidence
            confidence = 0.6
        else:
            confidence = 0.9
        
        # Calculate campaign description
        threat_types = list(set(event.threat_type for event in events))
        description = f"Campaign involving {len(devices)} devices and {len(files)} files with threats: {', '.join(threat_types)}"
        
        campaign = Campaign(
            campaign_id=f"campaign_{campaign_index}_{int(start_time.timestamp())}",
            threat_events=events,
            devices_involved=list(devices),
            files_involved=list(files),
            start_time=start_time,
            end_time=end_time,
            confidence=confidence,
            description=description
        )
        
        return campaign
    
    def get_campaign_statistics(self) -> Dict[str, Any]:
        """
        Get campaign detection statistics.
        
        Returns:
            Campaign statistics
        """
        if not self.detected_campaigns:
            return {'total_campaigns': 0}
        
        total_events = sum(len(c.threat_events) for c in self.detected_campaigns)
        total_devices = sum(len(c.devices_involved) for c in self.detected_campaigns)
        total_files = sum(len(c.files_involved) for c in self.detected_campaigns)
        
        return {
            'total_campaigns': len(self.detected_campaigns),
            'total_events': total_events,
            'total_devices': total_devices,
            'total_files': total_files,
            'avg_events_per_campaign': total_events / len(self.detected_campaigns),
            'avg_devices_per_campaign': total_devices / len(self.detected_campaigns),
            'avg_files_per_campaign': total_files / len(self.detected_campaigns)
        }

class GraphAnalyticsPipeline:
    """Main graph analytics pipeline"""
    
    def __init__(self):
        """Initialize graph analytics pipeline."""
        self.threat_graph = ThreatGraph()
        self.campaign_detector = CampaignDetector()
        self.processed_events = 0
        self.detected_campaigns = []
        
        logger.info("Initialized graph analytics pipeline")
    
    def process_threat_events(self, events: List[ThreatEvent]):
        """
        Process threat events and update graph.
        
        Args:
            events: List of threat events to process
        """
        logger.info(f"Processing {len(events)} threat events...")
        
        for event in events:
            self.threat_graph.add_threat_event(event)
            self.processed_events += 1
        
        logger.info(f"Processed {len(events)} threat events (total: {self.processed_events})")
    
    def run_campaign_detection(self) -> List[Campaign]:
        """
        Run campaign detection on the current graph.
        
        Returns:
            List of detected campaigns
        """
        logger.info("Running campaign detection...")
        
        campaigns = self.campaign_detector.detect_campaigns(self.threat_graph)
        self.detected_campaigns.extend(campaigns)
        
        logger.info(f"Detected {len(campaigns)} campaigns")
        return campaigns
    
    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """
        Get pipeline statistics.
        
        Returns:
            Pipeline statistics
        """
        graph_stats = self.threat_graph.get_graph_statistics()
        campaign_stats = self.campaign_detector.get_campaign_statistics()
        
        return {
            'graph': graph_stats,
            'campaigns': campaign_stats,
            'processed_events': self.processed_events
        }
    
    def export_graph(self, filename: str):
        """
        Export graph to file for visualization.
        
        Args:
            filename: Output filename
        """
        try:
            # Export to GraphML format
            nx.write_graphml(self.threat_graph.graph, filename)
            logger.info(f"Exported graph to {filename}")
        except Exception as e:
            logger.error(f"Failed to export graph: {e}")

# Example usage and demonstration
def generate_sample_events(count: int = 20) -> List[ThreatEvent]:
    """Generate sample threat events for demonstration."""
    events = []
    
    # Generate some devices and files
    device_ids = [f"device_{i}" for i in range(5)]
    file_hashes = [hashlib.md5(f"file_{i}".encode()).hexdigest() for i in range(10)]
    threat_types = ["trojan", "ransomware", "worm", "backdoor"]
    
    base_time = datetime.now() - timedelta(hours=12)
    
    for i in range(count):
        event = ThreatEvent(
            event_id=f"event_{i}",
            file_hash=file_hashes[i % len(file_hashes)],
            device_id=device_ids[i % len(device_ids)],
            timestamp=base_time + timedelta(minutes=i * 30),
            threat_type=threat_types[i % len(threat_types)],
            severity="high" if i % 3 == 0 else "medium",
            file_path=f"C:\\temp\\file_{i}.exe"
        )
        events.append(event)
    
    # Create some related events to form campaigns
    # Device 0 has multiple events in a short time (campaign 1)
    for i in range(5):
        event = ThreatEvent(
            event_id=f"campaign1_event_{i}",
            file_hash=file_hashes[0],
            device_id=device_ids[0],
            timestamp=base_time + timedelta(minutes=10 + i * 5),
            threat_type="trojan",
            severity="high",
            file_path=f"C:\\temp\\campaign_file_{i}.exe"
        )
        events.append(event)
    
    # Same file on multiple devices (campaign 2)
    for i in range(4):
        event = ThreatEvent(
            event_id=f"campaign2_event_{i}",
            file_hash=file_hashes[1],
            device_id=device_ids[i],
            timestamp=base_time + timedelta(minutes=200 + i * 15),
            threat_type="worm",
            severity="high",
            file_path=f"C:\\temp\\spread_file.exe"
        )
        events.append(event)
    
    return events

def demonstrate_graph_analytics():
    """Demonstrate graph analytics pipeline functionality."""
    logger.info("Demonstrating graph analytics pipeline...")
    
    # Initialize pipeline
    pipeline = GraphAnalyticsPipeline()
    
    # Generate sample events
    events = generate_sample_events(30)
    logger.info(f"Generated {len(events)} sample events")
    
    # Process events
    pipeline.process_threat_events(events)
    
    # Run campaign detection
    campaigns = pipeline.run_campaign_detection()
    
    # Display results
    logger.info("=== Campaign Detection Results ===")
    for campaign in campaigns:
        logger.info(f"Campaign: {campaign.campaign_id}")
        logger.info(f"  Description: {campaign.description}")
        logger.info(f"  Confidence: {campaign.confidence:.2f}")
        logger.info(f"  Devices: {len(campaign.devices_involved)}")
        logger.info(f"  Files: {len(campaign.files_involved)}")
        logger.info(f"  Duration: {campaign.end_time - campaign.start_time}")
        logger.info(f"  Events: {len(campaign.threat_events)}")
        logger.info("")
    
    # Display statistics
    stats = pipeline.get_pipeline_statistics()
    logger.info("=== Pipeline Statistics ===")
    logger.info(f"Processed Events: {stats['processed_events']}")
    logger.info(f"Graph Nodes: {stats['graph']['nodes']}")
    logger.info(f"Graph Edges: {stats['graph']['edges']}")
    logger.info(f"Devices in Graph: {stats['graph']['devices']}")
    logger.info(f"Files in Graph: {stats['graph']['files']}")
    logger.info(f"Detected Campaigns: {stats['campaigns']['total_campaigns']}")
    
    if stats['campaigns']['total_campaigns'] > 0:
        logger.info(f"Avg Events per Campaign: {stats['campaigns']['avg_events_per_campaign']:.2f}")
        logger.info(f"Avg Devices per Campaign: {stats['campaigns']['avg_devices_per_campaign']:.2f}")
        logger.info(f"Avg Files per Campaign: {stats['campaigns']['avg_files_per_campaign']:.2f}")
    
    # Export graph for visualization
    pipeline.export_graph("threat_graph.graphml")
    logger.info("Exported threat graph to threat_graph.graphml")

if __name__ == "__main__":
    demonstrate_graph_analytics()