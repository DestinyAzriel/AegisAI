#!/usr/bin/env python3
"""
AegisAI DNS Blocking Module
==========================

This module provides DNS-level ad blocking by intercepting DNS queries
and returning localhost for blocked domains.
"""

import os
import sys
import json
import logging
import threading
import time
import socket
from typing import Dict, Set, Optional
from datetime import datetime

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from web_protection import WebProtectionEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check if DNS modules are available
DNS_AVAILABLE = False
try:
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.rdataclass
    from dns import resolver
    DNS_AVAILABLE = True
    logger.info("DNS modules loaded successfully")
except ImportError:
    logger.warning("DNS modules not available - DNS blocking will be disabled")

class DNSBlockingServer:
    """DNS server that blocks ads and malicious domains"""
    
    def __init__(self, listen_address: str = "127.0.0.1", listen_port: int = 53, 
                 upstream_dns: str = "8.8.8.8"):
        """
        Initialize DNS blocking server.
        
        Args:
            listen_address: IP address to listen on
            listen_port: Port to listen on (default 53 for DNS)
            upstream_dns: Upstream DNS server for non-blocked queries
        """
        if not DNS_AVAILABLE:
            logger.error("DNS modules not available. Cannot initialize DNS blocking server.")
            return
            
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.web_protection = WebProtectionEngine()
        self.running = False
        self.server_socket = None
        self.stats = {
            'queries_processed': 0,
            'blocked_queries': 0,
            'allowed_queries': 0,
            'start_time': datetime.now()
        }
        
    def start(self):
        """Start the DNS blocking server."""
        if not DNS_AVAILABLE:
            logger.error("DNS modules not available. Cannot start DNS blocking server.")
            return
            
        try:
            # Create UDP socket for DNS
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.bind((self.listen_address, self.listen_port))
            
            self.running = True
            logger.info(f"DNS Blocking Server started on {self.listen_address}:{self.listen_port}")
            logger.info("Blocking ads, tracking, and malware domains")
            
            while self.running:
                try:
                    # Receive DNS query
                    data, addr = self.server_socket.recvfrom(512)  # DNS max packet size
                    self.stats['queries_processed'] += 1
                    
                    # Process query in a separate thread to avoid blocking
                    thread = threading.Thread(
                        target=self._handle_dns_query, 
                        args=(data, addr),
                        daemon=True
                    )
                    thread.start()
                    
                except socket.error as e:
                    if self.running:  # Only log if we're still supposed to be running
                        logger.error(f"Socket error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start DNS server: {e}")
            raise
        finally:
            self.stop()
    
    def stop(self):
        """Stop the DNS blocking server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("DNS Blocking Server stopped")
    
    def _handle_dns_query(self, data: bytes, addr: tuple):
        """
        Handle a DNS query.
        
        Args:
            data: DNS query data
            addr: Client address (IP, port)
        """
        if not DNS_AVAILABLE:
            return
            
        try:
            # Parse DNS query
            query = dns.message.from_wire(data)
            
            # Extract domain name from query
            if query.question:
                domain = str(query.question[0].name).rstrip('.')
                
                # Check if domain should be blocked
                should_block, reason, rule = self.web_protection.check_domain(domain)
                
                if should_block:
                    # Block the domain by returning NXDOMAIN
                    response = self._create_blocked_response(query)
                    self.stats['blocked_queries'] += 1
                    logger.info(f"BLOCKED: {domain} ({reason})")
                else:
                    # Forward to upstream DNS
                    response = self._forward_to_upstream(query)
                    self.stats['allowed_queries'] += 1
                    logger.debug(f"ALLOWED: {domain}")
                
                # Send response back to client
                if response and self.server_socket:
                    self.server_socket.sendto(response.to_wire(), addr)
                    
        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")
    
    def _create_blocked_response(self, query):
        """
        Create a DNS response that blocks a domain.
        
        Args:
            query: Original DNS query
            
        Returns:
            DNS response message
        """
        if not DNS_AVAILABLE:
            return None
            
        try:
            response = dns.message.make_response(query)
            response.flags |= dns.message.flags.AA | dns.message.flags.RA
            
            # Return NXDOMAIN for blocked domains (more effective than localhost)
            response.set_rcode(dns.rcode.NXDOMAIN)
            
            # Add SOA record for NXDOMAIN responses
            if query.question:
                soa_rrset = dns.rrset.from_text(
                    query.question[0].name,
                    300,  # TTL
                    dns.rdataclass.IN,
                    dns.rdatatype.SOA,
                    "localhost. hostmaster.localhost. 1 3600 1800 604800 300"
                )
                response.authority.append(soa_rrset)
            
            return response
        except Exception as e:
            logger.error(f"Error creating blocked response: {e}")
            return None
    
    def _forward_to_upstream(self, query):
        """
        Forward DNS query to upstream DNS server.
        
        Args:
            query: DNS query to forward
            
        Returns:
            DNS response from upstream server, or None if failed
        """
        if not DNS_AVAILABLE:
            return None
            
        try:
            # Create a resolver for the upstream DNS
            upstream_resolver = dns.resolver.Resolver()
            upstream_resolver.nameservers = [self.upstream_dns]
            upstream_resolver.timeout = 3
            upstream_resolver.lifetime = 3
            
            # Convert query to wire format and send to upstream
            query_wire = query.to_wire()
            
            # Create socket for upstream connection
            upstream_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            upstream_socket.settimeout(3)
            
            try:
                # Send query to upstream DNS
                upstream_socket.sendto(query_wire, (self.upstream_dns, 53))
                
                # Receive response
                response_data, _ = upstream_socket.recvfrom(512)
                
                # Parse response
                response = dns.message.from_wire(response_data)
                return response
                
            finally:
                upstream_socket.close()
                
        except Exception as e:
            logger.error(f"Failed to forward query to upstream DNS: {e}")
            # Return a SERVFAIL response
            try:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)
                return response
            except:
                return None
    
    def get_statistics(self) -> Dict:
        """
        Get DNS blocking statistics.
        
        Returns:
            Dictionary with statistics
        """
        if not DNS_AVAILABLE:
            return {}
            
        uptime = datetime.now() - self.stats['start_time']
        return {
            "uptime_seconds": uptime.total_seconds(),
            "queries_processed": self.stats['queries_processed'],
            "blocked_queries": self.stats['blocked_queries'],
            "allowed_queries": self.stats['allowed_queries'],
            "block_rate": (
                self.stats['blocked_queries'] / self.stats['queries_processed'] * 100
                if self.stats['queries_processed'] > 0 else 0
            )
        }

def main():
    """Main function to run DNS blocking server."""
    print("🛡️  AegisAI DNS Blocking Server")
    print("=" * 40)
    
    if not DNS_AVAILABLE:
        print("❌ DNS modules not available. Please install dnspython: pip install dnspython")
        return
    
    # Create DNS blocking server
    dns_server = DNSBlockingServer()
    
    # Set up signal handler for graceful shutdown
    import signal
    
    def signal_handler(sig, frame):
        print("\n🛑 Stopping DNS Blocking Server...")
        dns_server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start server
    try:
        print(f"Starting DNS server on {dns_server.listen_address}:{dns_server.listen_port}")
        print("Press Ctrl+C to stop")
        dns_server.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping DNS Blocking Server...")
        dns_server.stop()
    except Exception as e:
        print(f"❌ Error: {e}")
        dns_server.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()