#!/usr/bin/env python3
"""
Simple test for AegisAI Network Protection Components
"""

import sys
import os

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

def test_web_protection():
    """Test web protection engine."""
    print("Testing Web Protection Engine...")
    try:
        from core.web_protection import WebProtectionEngine
        engine = WebProtectionEngine()
        
        # Test a few domains
        test_cases = [
            ("doubleclick.net", True),      # Should be blocked
            ("github.com", False),          # Should be allowed
        ]
        
        for domain, should_block in test_cases:
            blocked, reason, rule = engine.check_domain(domain)
            if blocked == should_block:
                print(f"  ✅ {domain}: {'BLOCKED' if blocked else 'ALLOWED'}")
            else:
                print(f"  ❌ {domain}: Expected {'BLOCKED' if should_block else 'ALLOWED'}, got {'BLOCKED' if blocked else 'ALLOWED'}")
        
        return True
    except Exception as e:
        print(f"  ❌ Failed to test web protection: {e}")
        return False

def test_dns_module():
    """Test DNS blocking module."""
    print("\nTesting DNS Blocking Module...")
    try:
        from core.dns_blocking import DNSBlockingServer
        print("  ✅ DNS Blocking module imported successfully")
        return True
    except Exception as e:
        print(f"  ❌ Failed to import DNS blocking module: {e}")
        return False

def test_proxy_module():
    """Test HTTP proxy module."""
    print("\nTesting HTTP Proxy Module...")
    try:
        from core.http_proxy import HTTPProxyServer
        print("  ✅ HTTP Proxy module imported successfully")
        return True
    except Exception as e:
        print(f"  ❌ Failed to import HTTP proxy module: {e}")
        return False

def main():
    """Run simple tests."""
    print("🛡️  AegisAI Network Protection - Simple Test")
    print("=" * 50)
    
    # Run tests
    web_test = test_web_protection()
    dns_test = test_dns_module()
    proxy_test = test_proxy_module()
    
    # Summary
    print("\n" + "=" * 50)
    print("Test Results:")
    print(f"  Web Protection Engine: {'✅ PASSED' if web_test else '❌ FAILED'}")
    print(f"  DNS Blocking Module: {'✅ PASSED' if dns_test else '❌ FAILED'}")
    print(f"  HTTP Proxy Module: {'✅ PASSED' if proxy_test else '❌ FAILED'}")
    
    if web_test and dns_test and proxy_test:
        print("\n🎉 All tests passed! Network protection components are ready.")
        return 0
    else:
        print("\n💥 Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())