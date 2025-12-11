#!/usr/bin/env python3
"""
Practical example of using AegisAI Web Protection
"""

import sys
import os

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from core.web_protection import WebProtectionEngine

def main():
    """Demonstrate practical usage of web protection"""
    print("🛡️  AegisAI Web Protection - Practical Example")
    print("=" * 50)
    
    # Initialize the web protection engine
    print("Initializing web protection engine...")
    engine = WebProtectionEngine()
    print("✅ Engine initialized successfully\n")
    
    # Example 1: Check popular ad domains
    print("Example 1: Checking ad domains")
    print("-" * 30)
    ad_domains = [
        "doubleclick.net",
        "googleadservices.com",
        "facebook.com"  # Also serves ads
    ]
    
    for domain in ad_domains:
        should_block, reason, rule = engine.check_domain(domain)
        status = "BLOCKED" if should_block else "ALLOWED"
        print(f"  {domain:<25} → {status} ({reason})")
    
    print()
    
    # Example 2: Check tracking domains
    print("Example 2: Checking tracking domains")
    print("-" * 30)
    tracking_domains = [
        "google-analytics.com",
        "facebook.net",  # Tracking
        "analytics.google.com"
    ]
    
    for domain in tracking_domains:
        should_block, reason, rule = engine.check_domain(domain)
        status = "BLOCKED" if should_block else "ALLOWED"
        print(f"  {domain:<25} → {status} ({reason})")
    
    print()
    
    # Example 3: Check legitimate domains (should be allowed)
    print("Example 3: Checking legitimate domains")
    print("-" * 30)
    legit_domains = [
        "github.com",
        "google.com",
        "microsoft.com",
        "stackoverflow.com"
    ]
    
    for domain in legit_domains:
        should_block, reason, rule = engine.check_domain(domain)
        status = "BLOCKED" if should_block else "ALLOWED"
        print(f"  {domain:<25} → {status} ({reason})")
    
    print()
    
    # Example 4: Add custom rules
    print("Example 4: Adding custom rules")
    print("-" * 30)
    engine.add_filter_rule(
        pattern="custom-annoying-ads.com",
        rule_type="domain",
        action="block",
        category="ads",
        description="Custom rule for annoying ads"
    )
    print("  ✅ Added custom rule for 'custom-annoying-ads.com'")
    
    # Test the custom rule
    should_block, reason, rule = engine.check_domain("custom-annoying-ads.com")
    status = "BLOCKED" if should_block else "ALLOWED"
    print(f"  Testing custom rule: {status} ({reason})")
    
    print()
    
    # Example 5: Show statistics
    print("Example 5: Protection statistics")
    print("-" * 30)
    stats = engine.get_statistics()
    print(f"  Total rules loaded: {stats['total_rules']}")
    print(f"  Domains blocked: {stats['blocked_domains_count']}")
    print(f"  Ads blocked: {stats['stats']['blocked_ads']}")
    print(f"  Tracking blocked: {stats['stats']['blocked_tracking']}")
    print(f"  Malware blocked: {stats['stats']['blocked_malware']}")
    print(f"  Social media blocked: {stats['stats']['blocked_social']}")
    print(f"  Total blocked requests: {stats['stats']['blocked_requests']}")
    print(f"  Allowed requests: {stats['stats']['allowed_requests']}")
    
    print()
    
    # Example 6: Export rules
    print("Example 6: Exporting rules")
    print("-" * 30)
    json_export = engine.export_rules("json")
    csv_export = engine.export_rules("csv")
    print(f"  JSON export size: {len(json_export)} characters")
    print(f"  CSV export size: {len(csv_export)} characters")
    print("  ✅ Rules exported successfully")
    
    print()
    print("✨ AegisAI Web Protection is ready to provide clean, secure browsing!")

if __name__ == "__main__":
    main()