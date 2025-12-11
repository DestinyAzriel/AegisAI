#!/usr/bin/env python3
"""
AegisAI XDR Demo Script
=======================

This script demonstrates the Extended Detection and Response (XDR) capabilities
of the AegisAI system, including:
- Cross-platform telemetry collection (endpoint, network, cloud)
- Real-time threat correlation
- Automated response actions
- SIEM integration
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
import sys
import os

# Add the project root to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from cloud.refined_telemetry_collector import RefinedTelemetryCollector
from cloud.siem_integration.siem_connector import (
    SIEMIntegrationManager, 
    SIEMEvent, 
    XDRThreatCorrelation,
    AutomatedResponseAction
)

async def demonstrate_xdr_capabilities():
    """Demonstrate XDR capabilities of AegisAI"""
    print("🛡️  AegisAI Extended Detection and Response (XDR) Demo")
    print("=" * 60)
    
    # Initialize telemetry collector
    print("\n1. Initializing Telemetry Collector...")
    collector = RefinedTelemetryCollector('localhost', 8081)
    await collector.start()
    
    # Initialize SIEM integration
    print("\n2. Initializing SIEM Integration...")
    siem_manager = SIEMIntegrationManager()
    await siem_manager.initialize_connectors()
    
    # Create a test client ID
    client_id = f"test-client-{uuid.uuid4().hex[:8]}"
    session_id = uuid.uuid4().hex
    
    # Simulate endpoint telemetry data
    print("\n3. Sending Endpoint Telemetry Data...")
    endpoint_data = {
        'client_id': client_id,
        'session_id': session_id,
        'file_hash': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'file_features': {
            'size': 1024000,
            'entropy': 7.2,
            'sections': 3,
            'imports': ['CreateFile', 'WriteFile', 'RegSetValue']
        },
        'detection_result': 'suspicious',
        'threat_type': 'trojan',
        'confidence': 0.85,
        'file_path': 'C:\\Users\\Test\\Downloads\\suspicious.exe',
        'system_info': {
            'os': 'Windows 11',
            'architecture': 'x64',
            'agent_version': '1.0.0'
        }
    }
    
    # Insert endpoint telemetry
    success = collector.db.insert_telemetry(endpoint_data)
    print(f"   Endpoint telemetry inserted: {'✅ Success' if success else '❌ Failed'}")
    
    # Simulate network telemetry data
    print("\n4. Sending Network Telemetry Data...")
    network_data = {
        'client_id': client_id,
        'session_id': session_id,
        'source_ip': '192.168.1.100',
        'destination_ip': '10.0.0.1',
        'source_port': 12345,
        'destination_port': 443,
        'protocol': 'TCP',
        'bytes_sent': 102400,
        'bytes_received': 51200,
        'connection_status': 'established',
        'threat_indicators': ['suspicious_traffic', 'encrypted_tunnel'],
        'risk_score': 0.75
    }
    
    # Insert network telemetry
    success = collector.db.insert_network_telemetry(network_data)
    print(f"   Network telemetry inserted: {'✅ Success' if success else '❌ Failed'}")
    
    # Simulate cloud telemetry data
    print("\n5. Sending Cloud Telemetry Data...")
    cloud_data = {
        'client_id': client_id,
        'session_id': session_id,
        'cloud_provider': 'aws',
        'resource_type': 'ec2_instance',
        'resource_id': 'i-1234567890abcdef0',
        'operation_type': 'TerminateInstances',
        'user_identity': 'arn:aws:iam::123456789012:user/suspicious-user',
        'source_ip': '203.0.113.1',
        'user_agent': 'aws-cli/2.0.0 Python/3.8.0',
        'risk_indicators': ['unusual_activity', 'suspicious_user'],
        'compliance_status': 'violated'
    }
    
    # Insert cloud telemetry
    success = collector.db.insert_cloud_telemetry(cloud_data)
    print(f"   Cloud telemetry inserted: {'✅ Success' if success else '❌ Failed'}")
    
    # Create XDR correlation
    print("\n6. Creating XDR Threat Correlation...")
    correlation_id = uuid.uuid4().hex
    correlated_events = [
        {
            'event_type': 'endpoint_threat',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': endpoint_data
        },
        {
            'event_type': 'network_suspicious',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': network_data
        },
        {
            'event_type': 'cloud_unauthorized',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': cloud_data
        }
    ]
    
    xdr_correlation = XDRThreatCorrelation(
        correlation_id=correlation_id,
        threat_score=0.92,
        threat_category='advanced_persistent_threat',
        correlated_events=correlated_events,
        client_id=client_id
    )
    
    # Insert XDR correlation
    xdr_data = {
        'correlation_id': correlation_id,
        'threat_score': 0.92,
        'threat_category': 'advanced_persistent_threat',
        'correlated_events': correlated_events,
        'client_id': client_id
    }
    
    success = collector.db.insert_xdr_correlation(xdr_data)
    print(f"   XDR correlation inserted: {'✅ Success' if success else '❌ Failed'}")
    
    # Send XDR correlation to SIEM
    print("\n7. Sending XDR Correlation to SIEM...")
    siem_success = await siem_manager.send_xdr_correlation(xdr_correlation)
    print(f"   XDR correlation sent to SIEM: {'✅ Success' if siem_success else '❌ Failed'}")
    
    # Demonstrate automated response actions
    print("\n8. Demonstrating Automated Response Actions...")
    
    # Create an automated response action
    isolate_action = AutomatedResponseAction(
        action_type='isolate_endpoint',
        target=client_id,
        parameters={'duration': 3600},  # 1 hour
        condition='critical_threat',
        severity_threshold='critical'
    )
    
    # Register the action
    if siem_manager.default_connector:
        await siem_manager.default_connector.register_automated_action(isolate_action)
        print("   Registered automated endpoint isolation action")
    
    # Simulate a critical threat event that would trigger the action
    critical_event = SIEMEvent(
        event_type='critical_threat_detected',
        severity='critical',
        source=client_id,
        threat_name='Advanced Persistent Threat',
        description='Multi-stage attack detected across endpoint, network, and cloud',
        correlation_id=correlation_id
    )
    
    # Send the critical event (this should trigger automated response)
    event_success = await siem_manager.send_security_event(critical_event)
    print(f"   Critical threat event sent to SIEM: {'✅ Success' if event_success else '❌ Failed'}")
    
    # Show XDR statistics
    print("\n9. Retrieving XDR Statistics...")
    xdr_stats = collector.db.get_xdr_stats(days=7)
    print("   XDR Statistics (Last 7 Days):")
    print(f"     Total Correlations: {xdr_stats.get('total_correlations', 0)}")
    print(f"     High-Risk Detections: {xdr_stats.get('high_risk_detections', 0)}")
    print(f"     Medium-Risk Detections: {xdr_stats.get('medium_risk_detections', 0)}")
    print(f"     Resolved Incidents: {xdr_stats.get('resolved_incidents', 0)}")
    
    # Show correlations
    print("\n10. Retrieving XDR Correlations...")
    correlations = collector.db.get_xdr_correlations(limit=5)
    print(f"    Retrieved {len(correlations)} recent correlations:")
    for corr in correlations:
        print(f"      - {corr.get('correlation_id', 'N/A')}: {corr.get('threat_category', 'N/A')} "
              f"(Score: {corr.get('threat_score', 0.0):.2f})")
    
    # Clean up
    print("\n11. Cleaning Up...")
    await siem_manager.shutdown_connectors()
    await collector.stop()
    
    print("\n🎉 XDR Demo Completed Successfully!")
    print("\nKey XDR Capabilities Demonstrated:")
    print("  • Cross-platform telemetry collection (endpoint, network, cloud)")
    print("  • Real-time threat correlation across multiple data sources")
    print("  • Automated response actions based on threat severity")
    print("  • SIEM integration for centralized security monitoring")
    print("  • Comprehensive threat statistics and reporting")

if __name__ == "__main__":
    # Run the demo
    asyncio.run(demonstrate_xdr_capabilities())