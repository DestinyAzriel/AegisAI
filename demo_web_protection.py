#!/usr/bin/env python3
"""
Demo script showing AegisAI web protection features
"""

import sys
import os
import time
import threading

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

# Initialize global variables for modules
WebProtectionEngine = None
DNSBlockingServer = None
HTTPProxyServer = None
dns_message = None

# Try to import protection modules
try:
    from core.web_protection import WebProtectionEngine as WPE
    WebProtectionEngine = WPE
    print("✅ Web protection module loaded successfully")
except ImportError as e:
    print(f"⚠️  Web protection module not available: {e}")

# Try to import DNS blocking module
try:
    from core.dns_blocking import DNSBlockingServer as DBS
    DNSBlockingServer = DBS
    print("✅ DNS blocking module loaded successfully")
except ImportError as e:
    print(f"⚠️  DNS blocking module not available: {e}")

# Try to import HTTP proxy module
try:
    from core.http_proxy import HTTPProxyServer as HPS
    HTTPProxyServer = HPS
    print("✅ HTTP proxy module loaded successfully")
except ImportError as e:
    print(f"⚠️  HTTP proxy module not available: {e}")

# Check if DNS modules are available
try:
    import dns.message as dm
    dns_message = dm
    print("✅ DNS modules available")
except ImportError:
    print("⚠️  DNS modules not available. Install with: pip install dnspython")

def demo_domain_blocking():
    """Demonstrate domain blocking functionality"""
    print("\n🔍 Domain Blocking Demo")
    print("-" * 30)
    
    if WebProtectionEngine is None:
        print("Web protection module not available")
        return
    
    # Create web protection engine
    web_protection = WebProtectionEngine()
    
    # Test domains
    test_domains = [
        "google.com",              # Should be allowed
        "doubleclick.net",         # Should be blocked (ads)
        "google-analytics.com",    # Should be blocked (tracking)
        "malware-domain-list.com", # Should be blocked (malware)
        "github.com",              # Should be allowed
    ]
    
    for domain in test_domains:
        should_block, reason, rule = web_protection.check_domain(domain)
        status = "BLOCKED" if should_block else "ALLOWED"
        print(f"  {domain:<25} → {status}")
        if should_block:
            print(f"    Reason: {reason} ({rule.category if rule else 'Unknown'})")
        time.sleep(0.1)  # Small delay

def demo_dns_blocking():
    """Demonstrate DNS blocking server"""
    print("\n🌐 DNS Blocking Demo")
    print("-" * 30)
    
    if DNSBlockingServer is None:
        print("DNS blocking module not available")
        return
    
    if dns_message is None:
        print("DNS modules not available. Install with: pip install dnspython")
        return
    
    print("Starting DNS blocking server on 127.0.0.1:5353 (non-privileged port)")
    print("In a real deployment, this would run on port 53")
    
    # Create DNS blocking server (using non-privileged port for demo)
    dns_server = DNSBlockingServer(listen_address="127.0.0.1", listen_port=5353)
    
    # Start server in background thread
    dns_thread = threading.Thread(target=dns_server.start, daemon=True)
    dns_thread.start()
    
    print("DNS server started. Press Enter to continue...")
    input()
    
    # Stop server
    dns_server.stop()
    dns_thread.join(timeout=2)
    print("DNS server stopped.")

def demo_http_proxy():
    """Demonstrate HTTP proxy functionality"""
    print("\n🔒 HTTP Proxy Demo")
    print("-" * 30)
    
    if HTTPProxyServer is None:
        print("HTTP proxy module not available")
        return
    
    print("Starting HTTP proxy server on 127.0.0.1:8080")
    
    # Create HTTP proxy server
    proxy_server = HTTPProxyServer(listen_address="127.0.0.1", listen_port=8080)
    
    # Start server in background thread
    proxy_thread = threading.Thread(target=proxy_server.start, daemon=True)
    proxy_thread.start()
    
    print("HTTP proxy server started. Configure your browser to use:")
    print("  Proxy: 127.0.0.1:8080")
    print("Press Enter to continue...")
    input()
    
    # Stop server
    proxy_server.stop()
    proxy_thread.join(timeout=2)
    print("HTTP proxy server stopped.")

def main():
    """Main demo function"""
    print("🛡️  AegisAI Web Protection Demo")
    print("=" * 40)
    print("This demo shows the web protection features of AegisAI")
    
    demo_domain_blocking()
    demo_dns_blocking()
    demo_http_proxy()
    
    print("\n📋 Protection Features Summary:")
    print("1. Domain Blocking: Blocks ads, tracking, and malware domains at DNS level")
    print("2. DNS Blocking: Intercepts DNS queries and blocks malicious domains")
    print("3. HTTP Proxy: Filters web traffic and blocks ads/malware in HTTP content")
    print("4. Automatic Quarantine: Moves detected threats to secure quarantine area")
    print("\nWhen deployed system-wide, these features work together to provide")
    print("comprehensive web protection and automatic threat handling.")

if __name__ == "__main__":
    main()