#!/usr/bin/env python3
"""
Test script for AegisAI monitoring endpoints
Tests the new Prometheus metrics and cluster status endpoints
"""

import asyncio
import aiohttp
import sys
import os

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def test_monitoring_endpoints():
    """Test the new monitoring endpoints"""
    base_url = "http://localhost:8080"
    
    async with aiohttp.ClientSession() as session:
        try:
            # Test Prometheus metrics endpoint
            print("Testing Prometheus metrics endpoint...")
            async with session.get(f"{base_url}/metrics") as resp:
                if resp.status == 200:
                    metrics = await resp.text()
                    print("✓ Prometheus metrics endpoint is working")
                    print(f"  Content-Type: {resp.headers.get('content-type')}")
                    print(f"  Metrics lines: {len(metrics.splitlines())}")
                else:
                    print(f"✗ Prometheus metrics endpoint failed with status {resp.status}")
            
            # Test cluster status endpoint
            print("\nTesting cluster status endpoint...")
            async with session.get(f"{base_url}/api/v1/cluster/status") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print("✓ Cluster status endpoint is working")
                    print(f"  Status: {data.get('status')}")
                    if 'cluster_info' in data:
                        cluster_info = data['cluster_info']
                        print(f"  Cluster status: {cluster_info.get('status')}")
                        print(f"  Node count: {cluster_info.get('node_count', 0)}")
                else:
                    print(f"✗ Cluster status endpoint failed with status {resp.status}")
                    
        except Exception as e:
            print(f"Error testing endpoints: {e}")

if __name__ == "__main__":
    asyncio.run(test_monitoring_endpoints())