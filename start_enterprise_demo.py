#!/usr/bin/env python3
"""
AegisAI Enterprise Demo Startup Script
=====================================

This script demonstrates how to start the enhanced AegisAI with all enterprise features.
"""

import sys
import os
import asyncio
import logging
from datetime import datetime

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def demonstrate_enterprise_features():
    """Demonstrate the enterprise features that have been implemented"""
    print("=" * 60)
    print("AEGISAI ENTERPRISE SECURITY PLATFORM")
    print("=" * 60)
    print(f"Demo Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 1. Threat Intelligence Enhancements
    print("1. ADVANCED THREAT INTELLIGENCE")
    print("-" * 30)
    print("✓ Commercial Threat Feed Integration")
    print("  • Recorded Future (real-time threat intelligence)")
    print("  • ThreatConnect (contextual threat intelligence)")
    print("  • Anomali (comprehensive threat intelligence)")
    print()
    print("✓ Threat Intelligence Correlation Engine")
    print("  • Machine learning-based campaign detection")
    print("  • TF-IDF vectorization and DBSCAN clustering")
    print("  • Related indicator identification")
    print()
    
    # 2. Compliance Reporting
    print("2. ENHANCED COMPLIANCE REPORTING")
    print("-" * 30)
    print("✓ Automated Compliance Reporting")
    print("  • GDPR, CCPA, SOC 2, ISO 27001 support")
    print("  • Scheduled report generation")
    print("  • Automated email delivery")
    print()
    print("✓ Advanced Compliance Metrics")
    print("  • Real-time compliance KPI tracking")
    print("  • Consent rate monitoring")
    print("  • Data subject request tracking")
    print()
    
    # 3. Incident Response
    print("3. ADVANCED INCIDENT RESPONSE")
    print("-" * 30)
    print("✓ Enterprise Incident Workflows")
    print("  • Malware response orchestration")
    print("  • Unauthorized access response")
    print("  • Data exfiltration response")
    print()
    print("✓ Integration Capabilities")
    print("  • DLP system engagement")
    print("  • Forensic investigation workflows")
    print("  • Evidence preservation")
    print()
    
    # 4. Dashboard and Reporting
    print("4. ENTERPRISE DASHBOARD & REPORTING")
    print("-" * 30)
    print("✓ Comprehensive Executive Dashboard")
    print("  • Real-time security posture scoring")
    print("  • Threat intelligence overview")
    print("  • Compliance status monitoring")
    print()
    print("✓ Specialized Dashboards")
    print("  • Threat intelligence dashboard")
    print("  • Compliance dashboard")
    print("  • Incident response dashboard")
    print("  • Endpoint security dashboard")
    print()
    
    # 5. API Endpoints
    print("5. ENTERPRISE API ENDPOINTS")
    print("-" * 30)
    print("✓ RESTful API for all dashboard functionality")
    print("✓ Real-time data streaming capabilities")
    print("✓ Authentication and authorization")
    print("✓ Rate limiting and security controls")
    print()
    
    # 6. Global Deployment
    print("6. GLOBAL DEPLOYMENT & SCALABILITY")
    print("-" * 30)
    print("✓ Regional cache optimization")
    print("✓ Performance optimization")
    print("✓ Database connection pooling")
    print("✓ Asynchronous processing")
    print()

async def test_dashboard_api():
    """Test the dashboard API functionality"""
    print("TESTING DASHBOARD API")
    print("-" * 20)
    
    try:
        # Import the dashboard API
        from cloud.api.dashboard_api import EnterpriseDashboardAPI
        
        # Create dashboard instance
        dashboard = EnterpriseDashboardAPI()
        print("✓ Dashboard API imported successfully")
        print(f"✓ Threat Intel Service Available: {dashboard.threat_intel_service is not None}")
        print(f"✓ Compliance Reporting Available: {dashboard.compliance_reporting is not None}")
        print(f"✓ Incident Response Engine Available: {dashboard.incident_response_engine is not None}")
        
        # Show mock data
        print("\nMOCK DATA SAMPLES:")
        print("-" * 15)
        print(f"Agents: {len(dashboard.mock_agents)}")
        print(f"Threats: {len(dashboard.mock_threats)}")
        print(f"Incidents: {len(dashboard.mock_incidents)}")
        
        print("\nDashboard API test completed successfully!")
        
    except Exception as e:
        print(f"Error testing dashboard API: {e}")
        return False
    
    return True

def show_api_endpoints():
    """Show available API endpoints"""
    print("\nAVAILABLE API ENDPOINTS")
    print("-" * 22)
    endpoints = [
        "POST  /api/v1/agents/register",
        "POST  /api/v1/agents/heartbeat",
        "POST  /api/v1/analysis/file",
        "GET   /api/v1/threat-intel",
        "POST  /api/v1/threat-intel/update",
        "GET   /api/v1/threat-intel/stats",
        "GET   /api/v1/policies/{agent_id}",
        "POST  /api/v1/policies/update",
        "GET   /api/v1/compliance/report",
        "GET   /api/v1/privacy",
        "GET   /api/v1/ccpa",
        "POST  /api/v1/data-access",
        "POST  /api/v1/data-erasure",
        "POST  /api/v1/incidents/report",
        "GET   /api/v1/ws/{agent_id}",
        "GET   /api/v1/dashboard/executive",
        "GET   /api/v1/dashboard/threat-intel",
        "GET   /api/v1/dashboard/compliance",
        "GET   /api/v1/dashboard/incident-response",
        "GET   /api/v1/dashboard/endpoints"
    ]
    
    for endpoint in endpoints:
        print(f"  {endpoint}")

def main():
    """Main function to run the demo"""
    print("AegisAI Enterprise Demo Startup")
    print("=" * 35)
    
    # Demonstrate enterprise features
    demonstrate_enterprise_features()
    
    # Test dashboard API
    success = asyncio.run(test_dashboard_api())
    
    if success:
        # Show API endpoints
        show_api_endpoints()
        
        print("\n" + "=" * 60)
        print("AEGISAI ENTERPRISE DEMO READY")
        print("=" * 60)
        print("To start the full API server, run:")
        print("  cd cloud/api && python main.py")
        print()
        print("API endpoints will be available at http://localhost:8080")
        print("=" * 60)
    else:
        print("Demo startup failed. Please check the error messages above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())