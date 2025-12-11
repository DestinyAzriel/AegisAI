# AegisAI Graph Analytics Implementation

This directory contains the implementation of the graph analytics pipeline for AegisAI, which identifies related threats and lateral movement patterns rather than only scoring files independently.

## Overview

The graph analytics system addresses the industry weakness of signature-first detection by:

1. **Building a device/file graph** to detect campaigns and relationships
2. **Using graph analytics** to find patterns rather than independent file scoring
3. **Implementing behavioral correlation** to identify lateral movement
4. **Providing campaign detection** capabilities for advanced threats

## Components

### 1. Graph Analytics Pipeline (`graph_analytics_pipeline.py`)

The main pipeline implementation that:

- Builds and maintains a threat graph
- Detects campaigns using connected components
- Analyzes temporal and relational patterns
- Exports graphs for visualization

### 2. Graph Client (`graph_client.py`)

Client implementation that demonstrates how endpoint agents would contribute data:

- Reports threat detection events
- Submits behavioral events
- Registers devices with the system
- Queues and batches events for efficient transmission

### 3. Threat Graph

Component that represents threat events and relationships:

- Multi-dimensional graph structure
- Temporal relationship tracking
- Device and file correlation
- Network pattern analysis

### 4. Campaign Detector

Component that identifies threat campaigns:

- Connected component analysis
- Temporal clustering
- Confidence scoring
- Campaign characterization

## Key Features

### 1. Graph-Based Threat Detection

- **Device/File Graph**: Build relationships between threats
- **Temporal Analysis**: Identify time-based patterns
- **Propagation Tracking**: Follow threat spread
- **Lateral Movement**: Detect cross-device activity

### 2. Campaign Detection

- **Connected Components**: Find related threat events
- **Pattern Recognition**: Identify common characteristics
- **Confidence Scoring**: Assess detection reliability
- **Campaign Characterization**: Describe threat activities

### 3. Behavioral Correlation

- **Process Relationships**: Track parent-child processes
- **File Propagation**: Follow file movement
- **Network Patterns**: Analyze communication patterns
- **Registry Changes**: Monitor system modifications

## Implementation Details

### Graph Structure

The threat graph uses a multi-dimensional directed graph with:

- **Event Nodes**: Represent individual threat detections
- **Device Nodes**: Represent endpoint devices
- **File Nodes**: Represent malicious files
- **Process Nodes**: Represent running processes
- **Network Nodes**: Represent network endpoints

### Relationship Types

- **Temporal**: Time-based relationships between events
- **File Propagation**: File movement between devices
- **Process Hierarchy**: Parent-child process relationships
- **Network Communication**: Device-to-device communication
- **Registry Changes**: System modification tracking

### Campaign Detection Algorithm

1. **Graph Construction**: Build threat graph from events
2. **Connected Components**: Find groups of related events
3. **Temporal Analysis**: Check time constraints
4. **Pattern Matching**: Identify campaign characteristics
5. **Confidence Scoring**: Assess detection reliability
6. **Campaign Creation**: Generate campaign objects

### Data Model

#### ThreatEvent
- `event_id`: Unique event identifier
- `file_hash`: Hash of the detected file
- `device_id`: Device where detection occurred
- `timestamp`: When the event occurred
- `threat_type`: Type of threat detected
- `severity`: Severity level
- `file_path`: Path to the file
- `process_id`: Associated process ID
- `parent_process_id`: Parent process ID
- `network_connections`: Network activity

#### Campaign
- `campaign_id`: Unique campaign identifier
- `threat_events`: List of events in the campaign
- `devices_involved`: Devices participating in the campaign
- `files_involved`: Files involved in the campaign
- `start_time`: Campaign start time
- `end_time`: Campaign end time
- `confidence`: Confidence score
- `description`: Campaign description

## Privacy Considerations

### Data Minimization

- **Hashed Identifiers**: Use hashes instead of raw data
- **Limited Metadata**: Only collect necessary information
- **Aggregated Reporting**: Report patterns rather than raw events
- **User Consent**: Require explicit opt-in

### Secure Transmission

- **Encrypted Communication**: TLS for all data transmission
- **Authentication**: Verify client identity
- **Integrity Checking**: Validate data integrity
- **Rate Limiting**: Prevent abuse

## Performance Optimization

### Efficient Graph Operations

- **Indexing**: Fast lookup of events, devices, and files
- **Incremental Updates**: Update graph without full rebuild
- **Memory Management**: Efficient storage of graph data
- **Batch Processing**: Process events in batches

### Scalability Features

- **Distributed Processing**: Handle large-scale deployments
- **Hierarchical Analysis**: Multi-level campaign detection
- **Streaming Analytics**: Real-time processing capabilities
- **Load Balancing**: Distribute processing across nodes

## Integration Points

### Endpoint Agents

- **Event Reporting**: Submit threat and behavioral events
- **Device Registration**: Register with analytics system
- **Configuration Management**: Receive analysis parameters
- **Campaign Alerts**: Receive campaign notifications

### Cloud Backend

- **Data Ingestion**: Receive events from agents
- **Graph Storage**: Persistent graph storage
- **Analysis Engine**: Campaign detection algorithms
- **Visualization API**: Graph export and querying

### User Interface

- **Campaign Dashboard**: View detected campaigns
- **Graph Visualization**: Interactive threat graphs
- **Alert Management**: Campaign notifications
- **Investigation Tools**: Deep dive capabilities

## Benefits Over Traditional Approaches

### Beyond Signature-Based Detection

- **Behavioral Analysis**: Identify patterns rather than signatures
- **Campaign Detection**: Find related threats
- **Lateral Movement**: Track cross-device activity
- **Advanced Threats**: Detect APTs and zero-days

### Improved Accuracy

- **Reduced False Positives**: Context-aware detection
- **Better Correlation**: Combine multiple signals
- **Temporal Analysis**: Consider timing relationships
- **Confidence Scoring**: Assess detection reliability

### Enhanced Response

- **Campaign-Level Response**: Address entire campaigns
- **Containment Strategies**: Prevent lateral spread
- **Forensic Analysis**: Detailed investigation data
- **Threat Intelligence**: Share campaign information

## Next Steps for Production Implementation

### 1. Advanced Graph Algorithms

- Implement Graph Neural Networks (GNNs)
- Add community detection algorithms
- Integrate with graph databases (Neo4j, Amazon Neptune)
- Optimize for large-scale graphs

### 2. Real-Time Processing

- Implement streaming analytics
- Add real-time campaign detection
- Integrate with message queues (Kafka, Pulsar)
- Optimize for low-latency processing

### 3. Enhanced Visualization

- Create interactive graph visualizations
- Add timeline views
- Implement drill-down capabilities
- Integrate with existing dashboards

### 4. Machine Learning Integration

- Train models on graph features
- Implement anomaly detection
- Add predictive capabilities
- Integrate with existing ML services

## Usage

To run the graph analytics pipeline:

```bash
python3 graph_analytics_pipeline.py
```

To run the graph analytics client demonstration:

```bash
python3 graph_client.py
```

## API Endpoints

### Graph Analytics Server API

- `POST /api/v1/register` - Register new device
- `POST /api/v1/events` - Submit threat/behavioral events
- `GET /api/v1/campaigns` - Get detected campaigns
- `GET /api/v1/graph` - Get graph data for visualization

## Conclusion

The graph analytics implementation provides a foundation for advanced threat detection that goes beyond traditional signature-based approaches. By identifying relationships between threats and detecting campaigns, it enables more effective response to advanced threats while maintaining user privacy through careful data handling and minimization.

The modular design allows for easy extension with advanced analytics and visualization capabilities, while the prototype demonstrates the feasibility of the approach for production implementation.