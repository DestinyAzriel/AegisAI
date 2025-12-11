#!/usr/bin/env python3
"""
Integration test for AegisAI Web Protection Features
"""

import sys
import os
import threading
import time

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from core.web_protection import WebProtectionEngine
from core.dns_blocking import DNSBlockingServer
from core.http_proxy import HTTPProxyServer

def test_web_protection_engine():
    """Test the web protection engine."""
    print("Testing Web Protection Engine...")
    engine = WebProtectionEngine()
    
    # Test some domains
    test_domains = [
        ("doubleclick.net", True),      # Should be blocked (ad)
        ("github.com", False),          # Should be allowed
        ("facebook.com", True),         # Should be blocked (ad/tracking)
        ("google-analytics.com", True)  # Should be blocked (tracking)
    ]
    
    all_passed = True
    for domain, should_block in test_domains:
        blocked, reason, rule = engine.check_domain(domain)
        if blocked == should_block:
            print(f"  ✅ {domain}: {'BLOCKED' if blocked else 'ALLOWED'} ({reason})")
        else:
            print(f"  ❌ {domain}: Expected {'BLOCKED' if should_block else 'ALLOWED'}, got {'BLOCKED' if blocked else 'ALLOWED'}")
            all_passed = False
    
    return all_passed

def test_dns_blocking():
    """Test DNS blocking server."""
    print("\nTesting DNS Blocking Server...")
    dns_server = DNSBlockingServer(listen_address="127.0.0.1", listen_port=5354)
    
    # Start server in background
    server_thread = threading.Thread(target=dns_server.start, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Check if server is running
    stats = dns_server.get_statistics()
    if stats['uptime_seconds'] > 0:
        print("  ✅ DNS Blocking Server started successfully")
        dns_server.stop()
        return True
    else:
        print("  ❌ DNS Blocking Server failed to start")
        dns_server.stop()
        return False

def test_http_proxy():
    """Test HTTP proxy server."""
    print("\nTesting HTTP Proxy Server...")
    proxy_server = HTTPProxyServer(listen_address="127.0.0.1", listen_port=8081)
    
    # Start server in background
    server_thread = threading.Thread(target=proxy_server.start, daemon=True)
    server_thread.start()
    
    # Wait for server to start
    time.sleep(1)
    
    # Check if server is running
    stats = proxy_server.get_statistics()
    if stats['uptime_seconds'] > 0:
        print("  ✅ HTTP Proxy Server started successfully")
        proxy_server.stop()
        return True
    else:
        print("  ❌ HTTP Proxy Server failed to start")
        proxy_server.stop()
        return False

def main():
    """Run all integration tests."""
    print("🛡️  AegisAI Integration Test")
    print("=" * 40)
    
    # Test individual components
    web_test_passed = test_web_protection_engine()
    dns_test_passed = test_dns_blocking()
    proxy_test_passed = test_http_proxy()
    
    # Summary
    print("\n" + "=" * 40)
    print("Integration Test Results:")
    print(f"  Web Protection Engine: {'✅ PASSED' if web_test_passed else '❌ FAILED'}")
    print(f"  DNS Blocking Server: {'✅ PASSED' if dns_test_passed else '❌ FAILED'}")
    print(f"  HTTP Proxy Server: {'✅ PASSED' if proxy_test_passed else '❌ FAILED'}")
    
    if web_test_passed and dns_test_passed and proxy_test_passed:
        print("\n🎉 All integration tests passed!")
        return 0
    else:
        print("\n💥 Some integration tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())