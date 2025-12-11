#!/usr/bin/env python3
"""
AegisAI HTTP Proxy Module
========================

This module provides HTTP proxy functionality with ad and malware blocking.
"""

import os
import sys
import logging
import threading
import time
import socket
import urllib.parse
from typing import Dict, Optional
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from web_protection import WebProtectionEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads."""
    daemon_threads = True

class HTTPProxyHandler(BaseHTTPRequestHandler):
    """HTTP proxy request handler."""
    
    def __init__(self, *args, **kwargs):
        # Initialize web protection engine
        self.web_protection = WebProtectionEngine()
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(f"{self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests."""
        self._handle_request()
    
    def do_POST(self):
        """Handle POST requests."""
        self._handle_request()
    
    def _handle_request(self):
        """Handle HTTP request."""
        try:
            # Parse the URL
            parsed_url = urllib.parse.urlparse(self.path)
            host = parsed_url.netloc or self.headers.get('Host', '')
            
            # Check if the domain should be blocked
            should_block, reason, rule = self.web_protection.check_domain(host)
            
            if should_block:
                # Block the request
                self._send_blocked_response(host, reason)
                logger.info(f"BLOCKED: {host} ({reason})")
                return
            
            # Forward the request to the destination
            self._forward_request()
            
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def _send_blocked_response(self, domain: str, reason: str):
        """Send a blocked response to the client."""
        blocked_page = self.web_protection.get_blocked_page()
        
        self.send_response(403)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Connection', 'close')
        self.end_headers()
        
        # Send blocked page
        self.wfile.write(blocked_page.encode('utf-8'))
    
    def _forward_request(self):
        """Forward the request to the destination server."""
        try:
            # Parse the URL
            parsed_url = urllib.parse.urlparse(self.path)
            host = parsed_url.netloc or self.headers.get('Host', '')
            path = parsed_url.path or '/'
            query = parsed_url.query
            
            # Create the full path
            if query:
                full_path = f"{path}?{query}"
            else:
                full_path = path
            
            # Connect to the destination server
            dest_port = 443 if parsed_url.scheme == 'https' else 80
            dest_socket = socket.create_connection((host, dest_port), timeout=10)
            
            # Send the request
            request_line = f"{self.command} {full_path} {self.request_version}\r\n"
            dest_socket.send(request_line.encode('utf-8'))
            
            # Send headers
            for header, value in self.headers.items():
                dest_socket.send(f"{header}: {value}\r\n".encode('utf-8'))
            dest_socket.send(b"\r\n")
            
            # If there's a body (for POST requests), send it
            if 'Content-Length' in self.headers:
                content_length = int(self.headers['Content-Length'])
                body = self.rfile.read(content_length)
                dest_socket.send(body)
            
            # Receive the response
            response = dest_socket.recv(4096)
            self.wfile.write(response)
            
            # Continue receiving until done
            while response:
                try:
                    response = dest_socket.recv(4096)
                    if response:
                        self.wfile.write(response)
                    else:
                        break
                except socket.timeout:
                    break
            
            dest_socket.close()
            
        except Exception as e:
            logger.error(f"Error forwarding request: {e}")
            self.send_error(502, f"Bad gateway: {e}")

class HTTPProxyServer:
    """HTTP proxy server with ad blocking."""
    
    def __init__(self, listen_address: str = "127.0.0.1", listen_port: int = 8080):
        """
        Initialize HTTP proxy server.
        
        Args:
            listen_address: IP address to listen on
            listen_port: Port to listen on
        """
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.server = None
        self.running = False
        self.stats = {
            'requests_processed': 0,
            'blocked_requests': 0,
            'allowed_requests': 0,
            'start_time': datetime.now()
        }
    
    def start(self):
        """Start the HTTP proxy server."""
        try:
            # Create and start the server
            self.server = ThreadedHTTPServer(
                (self.listen_address, self.listen_port), 
                HTTPProxyHandler
            )
            self.running = True
            
            logger.info(f"HTTP Proxy Server started on {self.listen_address}:{self.listen_port}")
            logger.info("Blocking ads, tracking, and malware domains")
            
            # Start serving requests
            self.server.serve_forever()
            
        except Exception as e:
            logger.error(f"Failed to start HTTP proxy server: {e}")
            raise
    
    def stop(self):
        """Stop the HTTP proxy server."""
        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        logger.info("HTTP Proxy Server stopped")
    
    def get_statistics(self) -> Dict:
        """
        Get proxy statistics.
        
        Returns:
            Dictionary with statistics
        """
        uptime = datetime.now() - self.stats['start_time']
        return {
            "uptime_seconds": uptime.total_seconds(),
            "requests_processed": self.stats['requests_processed'],
            "blocked_requests": self.stats['blocked_requests'],
            "allowed_requests": self.stats['allowed_requests'],
            "block_rate": (
                self.stats['blocked_requests'] / self.stats['requests_processed'] * 100
                if self.stats['requests_processed'] > 0 else 0
            )
        }

def main():
    """Main function to run HTTP proxy server."""
    print("🛡️  AegisAI HTTP Proxy Server")
    print("=" * 40)
    
    # Create HTTP proxy server
    proxy_server = HTTPProxyServer()
    
    # Set up signal handler for graceful shutdown
    import signal
    
    def signal_handler(sig, frame):
        print("\n🛑 Stopping HTTP Proxy Server...")
        proxy_server.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start server
    try:
        print(f"Starting HTTP proxy on {proxy_server.listen_address}:{proxy_server.listen_port}")
        print("Press Ctrl+C to stop")
        proxy_server.start()
    except KeyboardInterrupt:
        print("\n🛑 Stopping HTTP Proxy Server...")
        proxy_server.stop()
    except Exception as e:
        print(f"❌ Error: {e}")
        proxy_server.stop()
        sys.exit(1)

if __name__ == "__main__":
    main()