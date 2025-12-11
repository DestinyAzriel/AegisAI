"""
AegisAI Telemetry Collector
Collects anonymous telemetry data from clients for threat intelligence
"""

import os
import json
import logging
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

logger = logging.getLogger(__name__)

class TelemetryDatabase:
    """Database for storing telemetry data"""
    
    def __init__(self, db_path: str = "telemetry.db"):
        """
        Initialize telemetry database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create telemetry table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    file_hash TEXT,
                    file_features TEXT,
                    detection_result TEXT,
                    threat_type TEXT,
                    confidence REAL,
                    file_path TEXT,
                    system_info TEXT
                )
            ''')
            
            # Create index for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_client_id ON telemetry(client_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON telemetry(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_type ON telemetry(threat_type)
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info("Telemetry database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize telemetry database: {e}")
    
    def insert_telemetry(self, data: Dict) -> bool:
        """
        Insert telemetry data into database.
        
        Args:
            data: Telemetry data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO telemetry (
                    timestamp, client_id, file_hash, file_features, detection_result,
                    threat_type, confidence, file_path, system_info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', datetime.now().isoformat()),
                data.get('client_id', ''),
                data.get('file_hash', ''),
                json.dumps(data.get('file_features', {})),
                data.get('detection_result', ''),
                data.get('threat_type', ''),
                data.get('confidence', 0.0),
                data.get('file_path', ''),
                json.dumps(data.get('system_info', {}))
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Telemetry data inserted for client {data.get('client_id', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to insert telemetry data: {e}")
            return False
    
    def get_telemetry_stats(self) -> Dict:
        """
        Get telemetry statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total records
            cursor.execute('SELECT COUNT(*) FROM telemetry')
            total_records = cursor.fetchone()[0]
            
            # Records by threat type
            cursor.execute('''
                SELECT threat_type, COUNT(*) 
                FROM telemetry 
                WHERE threat_type IS NOT NULL AND threat_type != ''
                GROUP BY threat_type
            ''')
            threat_types = dict(cursor.fetchall())
            
            # Unique clients
            cursor.execute('SELECT COUNT(DISTINCT client_id) FROM telemetry')
            unique_clients = cursor.fetchone()[0]
            
            # Recent activity (last 24 hours)
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE timestamp > datetime('now', '-1 day')
            ''')
            recent_activity = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_records': total_records,
                'threat_types': threat_types,
                'unique_clients': unique_clients,
                'recent_activity': recent_activity
            }
            
        except Exception as e:
            logger.error(f"Failed to get telemetry stats: {e}")
            return {}

class TelemetryHandler(BaseHTTPRequestHandler):
    """HTTP handler for telemetry collection"""
    
    def __init__(self, *args, **kwargs):
        # Initialize database
        self.db = TelemetryDatabase()
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle POST requests."""
        if self.path == '/api/v1/telemetry':
            self._handle_telemetry_submission()
        else:
            self._handle_not_found()
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/api/v1/stats':
            self._handle_stats_request()
        else:
            self._handle_not_found()
    
    def _handle_telemetry_submission(self):
        """Handle telemetry data submission."""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Read POST data
            post_data = self.rfile.read(content_length)
            
            # Parse JSON data
            telemetry_data = json.loads(post_data.decode('utf-8'))
            
            # Insert into database
            success = self.db.insert_telemetry(telemetry_data)
            
            if success:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                
                response = {
                    'status': 'success',
                    'message': 'Telemetry data received'
                }
                self.wfile.write(json.dumps(response).encode('utf-8'))
            else:
                self._handle_internal_error()
                
        except json.JSONDecodeError:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to handle telemetry submission: {e}")
            self._handle_internal_error()
    
    def _handle_stats_request(self):
        """Handle statistics request."""
        try:
            stats = self.db.get_telemetry_stats()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps(stats).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to handle stats request: {e}")
            self._handle_internal_error()
    
    def _handle_not_found(self):
        """Handle 404 Not Found."""
        self.send_response(404)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'error': 'Not Found',
            'message': 'The requested resource was not found'
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def _handle_internal_error(self):
        """Handle 500 Internal Server Error."""
        self.send_response(500)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            'error': 'Internal Server Error',
            'message': 'An internal server error occurred'
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))
    
    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info(format % args)

class TelemetryCollector:
    """AegisAI Telemetry Collector"""
    
    def __init__(self, host: str = 'localhost', port: int = 8081):
        """
        Initialize telemetry collector.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.server = None
    
    def start(self):
        """Start the telemetry collector."""
        try:
            self.server = HTTPServer((self.host, self.port), TelemetryHandler)
            logger.info(f"Telemetry collector started on {self.host}:{self.port}")
            logger.info(f"API endpoints:")
            logger.info(f"  - Submit telemetry: http://{self.host}:{self.port}/api/v1/telemetry")
            logger.info(f"  - Get stats: http://{self.host}:{self.port}/api/v1/stats")
            
            self.server.serve_forever()
            
        except KeyboardInterrupt:
            logger.info("Telemetry collector stopped by user")
        except Exception as e:
            logger.error(f"Failed to start telemetry collector: {e}")
        finally:
            if self.server:
                self.server.server_close()
    
    def stop(self):
        """Stop the telemetry collector."""
        if self.server:
            self.server.shutdown()

# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start collector
    collector = TelemetryCollector('localhost', 8081)
    collector.start()