#!/usr/bin/env python3
"""
Test script to verify the AegisAI API endpoints
"""

import requests
import json

def test_api_endpoints():
    """Test the API endpoints"""
    base_url = "http://localhost:8080"
    
    print("Testing AegisAI API Endpoints")
    print("=" * 40)
    
    # Test executive dashboard endpoint
    try:
        response = requests.get(f"{base_url}/api/v1/dashboard/executive")
        print(f"Executive Dashboard: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Status: {data.get('status')}")
            print(f"  Data keys: {list(data.get('data', {}).keys())}")
        else:
            print(f"  Error: {response.text}")
    except Exception as e:
        print(f"Executive Dashboard: Connection failed - {e}")
    
    # Test threat intelligence endpoint
    try:
        response = requests.get(f"{base_url}/api/v1/threat-intel/stats")
        print(f"Threat Intel Stats: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Status: {data.get('status')}")
        else:
            print(f"  Error: {response.text}")
    except Exception as e:
        print(f"Threat Intel Stats: Connection failed - {e}")
    
    # Test agent registration endpoint
    try:
        response = requests.post(f"{base_url}/api/v1/agents/register", json={
            "agent_id": "test-agent-001",
            "agent_info": {
                "hostname": "test-workstation",
                "os": "Windows 11"
            }
        })
        print(f"Agent Registration: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"  Status: {data.get('status')}")
            print(f"  Agent ID: {data.get('agent_id')}")
        else:
            print(f"  Error: {response.text}")
    except Exception as e:
        print(f"Agent Registration: Connection failed - {e}")

if __name__ == "__main__":
    test_api_endpoints()