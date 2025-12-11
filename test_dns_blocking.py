#!/usr/bin/env python3
"""
Test script for DNS blocking functionality
"""

import sys
import os
import socket
import time

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

def test_dns_resolution(domain):
    """Test DNS resolution for a domain"""
    try:
        print(f"Resolving {domain}...")
        result = socket.gethostbyname(domain)
        print(f"  -> {domain} resolves to {result}")
        return result
    except Exception as e:
        print(f"  -> Failed to resolve {domain}: {e}")
        return None

def main():
    """Test DNS blocking functionality"""
    print("🧪 Testing DNS Blocking Functionality")
    print("=" * 40)
    
    # Test domains - some should be blocked, some should resolve
    test_domains = [
        "google.com",           # Should resolve normally
        "doubleclick.net",      # Should be blocked (ad domain)
        "facebook.com",         # Should resolve normally
        "adservice.google.com", # Should be blocked (ad domain)
        "github.com",           # Should resolve normally
        "facebook.net",         # Should be blocked (tracking domain)
    ]
    
    print("Testing DNS resolution for various domains:")
    for domain in test_domains:
        test_dns_resolution(domain)
        time.sleep(1)  # Small delay between requests
    
    print("\nIf DNS blocking is working:")
    print("- Normal domains should resolve to IP addresses")
    print("- Ad/tracking domains should fail to resolve or timeout")

if __name__ == "__main__":
    main()