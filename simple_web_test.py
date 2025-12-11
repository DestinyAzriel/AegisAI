#!/usr/bin/env python3
"""
Simple test for AegisAI Web Protection
"""

import sys
import os

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from core.web_protection import WebProtectionEngine

def test_web_protection():
    """Test web protection functionality"""
    print("🛡️  AegisAI Web Protection Test")
    print("=" * 40)
    
    # Create web protection engine
    engine = WebProtectionEngine()
    
    # Test a few specific domains
    test_domains = [
        "doubleclick.net",           # Ad domain
        "google-analytics.com",      # Tracking domain
        "facebook.com",              # Social media
        "github.com",                # Legitimate domain
    ]
    
    print("Testing domain blocking:")
    for domain in test_domains:
        should_block, reason, rule = engine.check_domain(domain)
        status = "BLOCKED" if should_block else "ALLOWED"
        category = rule.category if rule else "N/A"
        print(f"  {domain:<25} - {status:<8} ({reason}) [{category}]")
    
    print("\nWeb Protection Statistics:")
    stats = engine.get_statistics()
    print(f"  Ads blocked: {stats['stats']['blocked_ads']}")
    print(f"  Malware blocked: {stats['stats']['blocked_malware']}")
    print(f"  Tracking blocked: {stats['stats']['blocked_tracking']}")
    print(f"  Social media blocked: {stats['stats']['blocked_social']}")
    
    # Test adding a custom rule
    print("\nTesting custom rule addition:")
    engine.add_filter_rule("custom-test-domain.com", "domain", "block", "ads", 
                          description="Custom test rule")
    
    should_block, reason, rule = engine.check_domain("custom-test-domain.com")
    status = "BLOCKED" if should_block else "ALLOWED"
    print(f"  Custom domain: {status} ({reason})")
    
    # Test content filtering
    print("\nTesting content filtering:")
    test_content = "This page contains doubleclick.net tracking code"
    should_block, reason, rule = engine.check_content(test_content)
    status = "BLOCKED" if should_block else "ALLOWED"
    print(f"  Content filtering: {status} ({reason})")

if __name__ == "__main__":
    test_web_protection()