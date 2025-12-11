#!/usr/bin/env python3
"""
Test script for the Enterprise Dashboard API
"""

import sys
import os

# Add the API directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__)))

from dashboard_api import EnterpriseDashboardAPI

def test_dashboard_api():
    """Test the dashboard API"""
    print("Testing Enterprise Dashboard API...")
    
    # Create dashboard API instance
    dashboard = EnterpriseDashboardAPI()
    
    print("Dashboard API created successfully")
    print(f"Threat Intel Service Available: {dashboard.threat_intel_service is not None}")
    print(f"Compliance Reporting Available: {dashboard.compliance_reporting is not None}")
    print(f"Incident Response Engine Available: {dashboard.incident_response_engine is not None}")
    
    # Test mock data
    print("\nMock Agents:")
    for agent_id, agent_data in dashboard.mock_agents.items():
        print(f"  {agent_id}: {agent_data['hostname']} ({agent_data['status']})")
    
    print("\nMock Threats:")
    for threat_id, threat_data in dashboard.mock_threats.items():
        print(f"  {threat_id}: {threat_data['threat_name']} ({threat_data['severity']})")
    
    print("\nMock Incidents:")
    for incident_id, incident_data in dashboard.mock_incidents.items():
        print(f"  {incident_id}: {incident_data['type']} ({incident_data['status']})")
    
    print("\nDashboard API test completed successfully!")

if __name__ == "__main__":
    test_dashboard_api()