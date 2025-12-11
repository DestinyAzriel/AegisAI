#!/usr/bin/env python3
"""
Test script for web protection functionality
"""

import sys
import os
import requests
import time

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

try:
    from web_protection import WebProtectionEngine
    print("✅ Web protection module loaded successfully")
except ImportError as e:
    print(f"❌ Failed to import web protection module: {e}")
    sys.exit(1)

def test_domain_blocking():
    """Test domain blocking functionality"""
    print("\n🔍 Testing domain blocking...")
    
    # Create web protection engine
    web_protection = WebProtectionEngine()
    
    # Test domains
    test_domains = [
        ("google.com", "Normal domain"),
        ("doubleclick.net", "Ad domain"),
        ("adservice.google.com", "Ad domain"),
        ("facebook.net", "Tracking domain"),
        ("malware-domain-list.com", "Malware domain"),
        ("github.com", "Normal domain"),
    ]
    
    for domain, description in test_domains:
        should_block, reason, rule = web_protection.check_domain(domain)
        status = "BLOCKED" if should_block else "ALLOWED"
        print(f"  {domain:<25} | {status:<8} | {description}")
        if should_block:
            print(f"    Reason: {reason}")
            if rule:
                print(f"    Rule: {rule.category} - {rule.pattern}")

def test_url_blocking():
    """Test URL blocking functionality"""
    print("\n🔗 Testing URL blocking...")
    
    # Create web protection engine
    web_protection = WebProtectionEngine()
    
    # Test URLs
    test_urls = [
        ("https://google.com", "Normal URL"),
        ("https://doubleclick.net/ads/banner", "Ad URL"),
        ("https://facebook.com/tracking/pixel", "Tracking URL"),
        ("https://malicious-site.com/malware.exe", "Malware URL"),
    ]
    
    for url, description in test_urls:
        should_block, reason, rule = web_protection.check_url(url)
        status = "BLOCKED" if should_block else "ALLOWED"
        print(f"  {url:<35} | {status:<8} | {description}")
        if should_block:
            print(f"    Reason: {reason}")
            if rule:
                print(f"    Rule: {rule.category} - {rule.pattern}")

def main():
    """Main test function"""
    print("🛡️  AegisAI Web Protection Test")
    print("=" * 50)
    
    test_domain_blocking()
    test_url_blocking()
    
    print("\n📋 Test Summary:")
    print("If web protection is working correctly:")
    print("- Normal domains/URLs should be ALLOWED")
    print("- Ad/tracking/malware domains/URLs should be BLOCKED")
    print("- Each blocked item should have a reason and rule")

if __name__ == "__main__":
    main()