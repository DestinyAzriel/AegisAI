#!/usr/bin/env python3
"""
Test script to verify ad blocking functionality
"""

import sys
import os
import time

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

def test_hosts_file_blocking():
    """Test if hosts file blocking is working"""
    print("🔍 Testing Hosts File Ad Blocking...")
    
    # Check if hosts file exists
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    if not os.path.exists(hosts_path):
        print("❌ Hosts file not found")
        return False
    
    try:
        with open(hosts_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check if AegisAI section exists
        if "# AegisAI Ad Blocker - Start" in content:
            print("✅ AegisAI ad blocking entries found in hosts file")
            
            # Count blocked domains
            blocked_domains = 0
            in_aegisai_section = False
            for line in content.split('\n'):
                if line.strip() == "# AegisAI Ad Blocker - Start":
                    in_aegisai_section = True
                elif line.strip() == "# AegisAI Ad Blocker - End":
                    in_aegisai_section = False
                elif in_aegisai_section and ('127.0.0.1' in line or '0.0.0.0' in line):
                    blocked_domains += 1
                    
            print(f"📊 Number of domains blocked: {blocked_domains}")
            return True
        else:
            print("⚠️  AegisAI ad blocking entries not found in hosts file")
            return False
            
    except Exception as e:
        print(f"❌ Error reading hosts file: {e}")
        return False

def test_domain_resolution(domain):
    """Test DNS resolution for a domain"""
    import socket
    try:
        result = socket.gethostbyname(domain)
        return result
    except:
        return None

def main():
    """Main test function"""
    print("🛡️  AegisAI Ad Blocking Test")
    print("=" * 40)
    
    # Test hosts file blocking
    test_hosts_file_blocking()
    
    print("\n🌐 Testing Domain Resolution...")
    print("(This may take a few seconds)")
    
    # Test some common ad domains
    test_domains = [
        ("google.com", "Normal domain"),
        ("doubleclick.net", "Ad domain"),
        ("adservice.google.com", "Ad domain"),
        ("facebook.com", "Normal domain"),
        ("ads.facebook.com", "Ad domain")
    ]
    
    for domain, description in test_domains:
        result = test_domain_resolution(domain)
        if result:
            if "ad" in description.lower() and result == "127.0.0.1":
                status = "BLOCKED ✅"
            elif "ad" in description.lower():
                status = "NOT BLOCKED ⚠️"
            else:
                status = "RESOLVED ✅"
            print(f"  {domain:<25} → {result:<15} ({status})")
        else:
            print(f"  {domain:<25} → FAILED TO RESOLVE")
        time.sleep(0.5)
    
    print("\n📋 Test Summary:")
    print("If ad blocking is working correctly:")
    print("- Ad domains should resolve to 127.0.0.1 (blocked)")
    print("- Normal domains should resolve to their actual IP addresses")
    print("- The hosts file should contain AegisAI blocking entries")

if __name__ == "__main__":
    main()