#!/usr/bin/env python3
"""
AegisAI Refined Telemetry Collector
==================================

Enhanced telemetry collection system with improved performance,
security, and scalability features.
"""

import os
import json
import logging
import sqlite3
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from contextlib import asynccontextmanager
import hashlib
import secrets

# Web framework
try:
    from aiohttp import web, ClientSession
    AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    ClientSession = None
    AIOHTTP_AVAILABLE = False
    logging.warning("aiohttp not available - web server features disabled")

# Data compression
try:
    import gzip
    GZIP_AVAILABLE = True
except ImportError:
    gzip = None
    GZIP_AVAILABLE = False
    logging.warning("gzip not available - compression features disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TelemetryDatabase:
    """Enhanced database for storing telemetry data with optimized performance"""
    
    def __init__(self, db_path: str = "telemetry.db"):
        """
        Initialize telemetry database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._initialize_database()
        self._optimize_database()
    
    def _initialize_database(self):
        """Initialize database tables with proper constraints."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode for better concurrency
            conn.execute("PRAGMA synchronous=NORMAL")  # Balance between performance and durability
            conn.execute("PRAGMA cache_size=10000")  # Increase cache size
            conn.execute("PRAGMA temp_store=MEMORY")  # Use memory for temporary tables
            
            cursor = conn.cursor()
            
            # Create telemetry table with proper constraints
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    file_hash TEXT,
                    file_features TEXT,
                    detection_result TEXT,
                    threat_type TEXT,
                    confidence REAL,
                    file_path TEXT,
                    system_info TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    processing_time REAL
                )
            ''')
            
            # Create network telemetry table for XDR capabilities
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    connection_status TEXT,
                    threat_indicators TEXT,
                    risk_score REAL
                )
            ''')
            
            # Create cloud telemetry table for XDR capabilities
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cloud_telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    cloud_provider TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    operation_type TEXT,
                    user_identity TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    risk_indicators TEXT,
                    compliance_status TEXT
                )
            ''')
            
            # Create XDR correlation table for cross-platform threat detection
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS xdr_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_id TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    threat_score REAL,
                    threat_category TEXT,
                    correlated_events TEXT,
                    investigation_status TEXT DEFAULT 'open',
                    assigned_to TEXT,
                    resolution_notes TEXT
                )
            ''')
            
            # Create indexes for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_client_id ON telemetry(client_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON telemetry(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_threat_type ON telemetry(threat_type)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_session_id ON telemetry(session_id)
            ''')
            
            # Indexes for XDR tables
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_network_client_id ON network_telemetry(client_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_network_timestamp ON network_telemetry(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cloud_client_id ON cloud_telemetry(client_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_cloud_timestamp ON cloud_telemetry(timestamp)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_xdr_correlation_id ON xdr_correlations(correlation_id)
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_xdr_client_id ON xdr_correlations(client_id)
            ''')
            
            # Create aggregated statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS telemetry_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL UNIQUE,
                    total_records INTEGER NOT NULL DEFAULT 0,
                    threat_detections INTEGER NOT NULL DEFAULT 0,
                    unique_clients INTEGER NOT NULL DEFAULT 0,
                    avg_confidence REAL NOT NULL DEFAULT 0.0,
                    last_updated TEXT NOT NULL
                )
            ''')
            
            # Create XDR statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS xdr_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL UNIQUE,
                    total_correlations INTEGER NOT NULL DEFAULT 0,
                    high_risk_detections INTEGER NOT NULL DEFAULT 0,
                    medium_risk_detections INTEGER NOT NULL DEFAULT 0,
                    low_risk_detections INTEGER NOT NULL DEFAULT 0,
                    resolved_incidents INTEGER NOT NULL DEFAULT 0,
                    avg_response_time REAL NOT NULL DEFAULT 0.0,
                    last_updated TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info("Telemetry database initialized with XDR capabilities")
            
        except Exception as e:
            logger.error(f"Failed to initialize telemetry database: {e}")
    
    def _optimize_database(self):
        """Apply additional database optimizations."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Analyze tables for query optimization
            cursor.execute("ANALYZE")
            
            # Set auto-vacuum to incremental for better performance
            cursor.execute("PRAGMA auto_vacuum=INCREMENTAL")
            
            conn.commit()
            conn.close()
            
            logger.info("Telemetry database optimized")
            
        except Exception as e:
            logger.error(f"Failed to optimize telemetry database: {e}")
    
    def insert_telemetry(self, data: Dict) -> bool:
        """
        Insert telemetry data into database with batch processing support.
        
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
                    timestamp, client_id, session_id, file_hash, file_features, detection_result,
                    threat_type, confidence, file_path, system_info, ip_address, user_agent, processing_time
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                data.get('client_id', ''),
                data.get('session_id', secrets.token_hex(16)),
                data.get('file_hash', ''),
                json.dumps(data.get('file_features', {})),
                data.get('detection_result', ''),
                data.get('threat_type', ''),
                data.get('confidence', 0.0),
                data.get('file_path', ''),
                json.dumps(data.get('system_info', {})),
                data.get('ip_address', ''),
                data.get('user_agent', ''),
                data.get('processing_time', 0.0)
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Telemetry data inserted for client {data.get('client_id', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to insert telemetry data: {e}")
            return False
    
    def batch_insert_telemetry(self, data_list: List[Dict]) -> int:
        """
        Insert multiple telemetry records in a batch for better performance.
        
        Args:
            data_list: List of telemetry data dictionaries
            
        Returns:
            Number of records successfully inserted
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            inserted_count = 0
            for data in data_list:
                try:
                    cursor.execute('''
                        INSERT INTO telemetry (
                            timestamp, client_id, session_id, file_hash, file_features, detection_result,
                            threat_type, confidence, file_path, system_info, ip_address, user_agent, processing_time
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                        data.get('client_id', ''),
                        data.get('session_id', secrets.token_hex(16)),
                        data.get('file_hash', ''),
                        json.dumps(data.get('file_features', {})),
                        data.get('detection_result', ''),
                        data.get('threat_type', ''),
                        data.get('confidence', 0.0),
                        data.get('file_path', ''),
                        json.dumps(data.get('system_info', {})),
                        data.get('ip_address', ''),
                        data.get('user_agent', ''),
                        data.get('processing_time', 0.0)
                    ))
                    inserted_count += 1
                except Exception as e:
                    logger.warning(f"Failed to insert individual telemetry record: {e}")
            
            conn.commit()
            conn.close()
            
            logger.info(f"Batch inserted {inserted_count} telemetry records")
            return inserted_count
            
        except Exception as e:
            logger.error(f"Failed to batch insert telemetry data: {e}")
            return 0
    
    def get_telemetry_stats(self, days: int = 30) -> Dict:
        """
        Get telemetry statistics for the specified number of days.
        
        Args:
            days: Number of days to include in statistics
            
        Returns:
            Dictionary with statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            
            # Total records in date range
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            total_records = cursor.fetchone()[0]
            
            # Records by threat type
            cursor.execute('''
                SELECT threat_type, COUNT(*) 
                FROM telemetry 
                WHERE threat_type IS NOT NULL AND threat_type != '' 
                AND timestamp >= ? AND timestamp <= ?
                GROUP BY threat_type
            ''', (start_date.isoformat(), end_date.isoformat()))
            threat_types = dict(cursor.fetchall())
            
            # Unique clients
            cursor.execute('''
                SELECT COUNT(DISTINCT client_id) FROM telemetry
                WHERE timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            unique_clients = cursor.fetchone()[0]
            
            # Recent activity (last 24 hours)
            recent_end = datetime.now(timezone.utc)
            recent_start = recent_end - timedelta(hours=24)
            
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE timestamp >= ? AND timestamp <= ?
            ''', (recent_start.isoformat(), recent_end.isoformat()))
            recent_activity = cursor.fetchone()[0]
            
            # Average confidence
            cursor.execute('''
                SELECT AVG(confidence) FROM telemetry
                WHERE confidence IS NOT NULL
                AND timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            avg_confidence = cursor.fetchone()[0] or 0.0
            
            # Top threats by detection count
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM telemetry
                WHERE threat_type IS NOT NULL AND threat_type != ''
                AND timestamp >= ? AND timestamp <= ?
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 10
            ''', (start_date.isoformat(), end_date.isoformat()))
            top_threats = cursor.fetchall()
            
            conn.close()
            
            return {
                'period_days': days,
                'period_start': start_date.isoformat(),
                'period_end': end_date.isoformat(),
                'total_records': total_records,
                'threat_types': threat_types,
                'unique_clients': unique_clients,
                'recent_activity_24h': recent_activity,
                'average_confidence': round(avg_confidence, 4),
                'top_threats': [{'type': row[0], 'count': row[1]} for row in top_threats]
            }
            
        except Exception as e:
            logger.error(f"Failed to get telemetry stats: {e}")
            return {}
    
    def get_client_stats(self, client_id: str, days: int = 30) -> Dict:
        """
        Get statistics for a specific client.
        
        Args:
            client_id: Client identifier
            days: Number of days to include in statistics
            
        Returns:
            Dictionary with client statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            
            # Total records for client
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE client_id = ? AND timestamp >= ? AND timestamp <= ?
            ''', (client_id, start_date.isoformat(), end_date.isoformat()))
            total_records = cursor.fetchone()[0]
            
            # Threat detections for client
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE client_id = ? AND threat_type IS NOT NULL AND threat_type != ''
                AND timestamp >= ? AND timestamp <= ?
            ''', (client_id, start_date.isoformat(), end_date.isoformat()))
            threat_detections = cursor.fetchone()[0]
            
            # Average confidence for client
            cursor.execute('''
                SELECT AVG(confidence) FROM telemetry
                WHERE client_id = ? AND confidence IS NOT NULL
                AND timestamp >= ? AND timestamp <= ?
            ''', (client_id, start_date.isoformat(), end_date.isoformat()))
            avg_confidence = cursor.fetchone()[0] or 0.0
            
            # Most common threat types for client
            cursor.execute('''
                SELECT threat_type, COUNT(*) as count
                FROM telemetry
                WHERE client_id = ? AND threat_type IS NOT NULL AND threat_type != ''
                AND timestamp >= ? AND timestamp <= ?
                GROUP BY threat_type
                ORDER BY count DESC
                LIMIT 5
            ''', (client_id, start_date.isoformat(), end_date.isoformat()))
            common_threats = cursor.fetchall()
            
            conn.close()
            
            return {
                'client_id': client_id,
                'period_days': days,
                'total_records': total_records,
                'threat_detections': threat_detections,
                'detection_rate': round(threat_detections / max(total_records, 1), 4),
                'average_confidence': round(avg_confidence, 4),
                'common_threats': [{'type': row[0], 'count': row[1]} for row in common_threats]
            }
            
        except Exception as e:
            logger.error(f"Failed to get client stats: {e}")
            return {}
    
    def insert_network_telemetry(self, data: Dict) -> bool:
        """
        Insert network telemetry data into database for XDR capabilities.
        
        Args:
            data: Network telemetry data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_telemetry (
                    timestamp, client_id, session_id, source_ip, destination_ip,
                    source_port, destination_port, protocol, bytes_sent, bytes_received,
                    connection_status, threat_indicators, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                data.get('client_id', ''),
                data.get('session_id', secrets.token_hex(16)),
                data.get('source_ip', ''),
                data.get('destination_ip', ''),
                data.get('source_port', 0),
                data.get('destination_port', 0),
                data.get('protocol', ''),
                data.get('bytes_sent', 0),
                data.get('bytes_received', 0),
                data.get('connection_status', ''),
                json.dumps(data.get('threat_indicators', [])),
                data.get('risk_score', 0.0)
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Network telemetry data inserted for client {data.get('client_id', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to insert network telemetry data: {e}")
            return False
    
    def insert_cloud_telemetry(self, data: Dict) -> bool:
        """
        Insert cloud telemetry data into database for XDR capabilities.
        
        Args:
            data: Cloud telemetry data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO cloud_telemetry (
                    timestamp, client_id, session_id, cloud_provider, resource_type,
                    resource_id, operation_type, user_identity, source_ip, user_agent,
                    risk_indicators, compliance_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                data.get('client_id', ''),
                data.get('session_id', secrets.token_hex(16)),
                data.get('cloud_provider', ''),
                data.get('resource_type', ''),
                data.get('resource_id', ''),
                data.get('operation_type', ''),
                data.get('user_identity', ''),
                data.get('source_ip', ''),
                data.get('user_agent', ''),
                json.dumps(data.get('risk_indicators', [])),
                data.get('compliance_status', 'unknown')
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cloud telemetry data inserted for client {data.get('client_id', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to insert cloud telemetry data: {e}")
            return False
    
    def insert_xdr_correlation(self, data: Dict) -> bool:
        """
        Insert XDR correlation data into database for cross-platform threat detection.
        
        Args:
            data: XDR correlation data dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO xdr_correlations (
                    correlation_id, timestamp, client_id, threat_score, threat_category,
                    correlated_events, investigation_status, assigned_to, resolution_notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                data.get('correlation_id', secrets.token_hex(16)),
                data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                data.get('client_id', ''),
                data.get('threat_score', 0.0),
                data.get('threat_category', ''),
                json.dumps(data.get('correlated_events', [])),
                data.get('investigation_status', 'open'),
                data.get('assigned_to', ''),
                data.get('resolution_notes', '')
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"XDR correlation data inserted for client {data.get('client_id', 'unknown')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to insert XDR correlation data: {e}")
            return False
    
    def get_xdr_correlations(self, client_id: str = None, threat_category: str = None, 
                            status: str = None, limit: int = 100) -> List[Dict]:
        """
        Get XDR correlations with optional filtering.
        
        Args:
            client_id: Filter by client ID
            threat_category: Filter by threat category
            status: Filter by investigation status
            limit: Maximum number of results to return
            
        Returns:
            List of XDR correlation records
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query with optional filters
            query = "SELECT * FROM xdr_correlations WHERE 1=1"
            params = []
            
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
            
            if threat_category:
                query += " AND threat_category = ?"
                params.append(threat_category)
            
            if status:
                query += " AND investigation_status = ?"
                params.append(status)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Get column names
            columns = [description[0] for description in cursor.description]
            
            # Convert to list of dictionaries
            results = []
            for row in rows:
                record = dict(zip(columns, row))
                # Parse JSON fields
                try:
                    record['correlated_events'] = json.loads(record['correlated_events'])
                except:
                    record['correlated_events'] = []
                results.append(record)
            
            conn.close()
            return results
            
        except Exception as e:
            logger.error(f"Failed to get XDR correlations: {e}")
            return []
    
    def update_xdr_investigation_status(self, correlation_id: str, status: str, 
                                      assigned_to: str = None, resolution_notes: str = None) -> bool:
        """
        Update XDR investigation status.
        
        Args:
            correlation_id: Correlation ID to update
            status: New investigation status
            assigned_to: User assigned to investigate
            resolution_notes: Notes about the resolution
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build update query with optional fields
            query = "UPDATE xdr_correlations SET investigation_status = ?, "
            params = [status]
            
            if assigned_to is not None:
                query += "assigned_to = ?, "
                params.append(assigned_to)
            
            if resolution_notes is not None:
                query += "resolution_notes = ?, "
                params.append(resolution_notes)
            
            # Remove trailing comma and space, add WHERE clause
            query = query.rstrip(", ") + " WHERE correlation_id = ?"
            params.append(correlation_id)
            
            cursor.execute(query, params)
            conn.commit()
            conn.close()
            
            logger.info(f"Updated XDR investigation status for correlation {correlation_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update XDR investigation status: {e}")
            return False
    
    def get_xdr_stats(self, days: int = 30) -> Dict:
        """
        Get XDR statistics for the specified number of days.
        
        Args:
            days: Number of days to include in statistics
            
        Returns:
            Dictionary with XDR statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate date range
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=days)
            
            # Total correlations in date range
            cursor.execute('''
                SELECT COUNT(*) FROM xdr_correlations 
                WHERE timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            total_correlations = cursor.fetchone()[0]
            
            # Correlations by threat category
            cursor.execute('''
                SELECT threat_category, COUNT(*) 
                FROM xdr_correlations 
                WHERE threat_category IS NOT NULL AND threat_category != '' 
                AND timestamp >= ? AND timestamp <= ?
                GROUP BY threat_category
            ''', (start_date.isoformat(), end_date.isoformat()))
            threat_categories = dict(cursor.fetchall())
            
            # Correlations by investigation status
            cursor.execute('''
                SELECT investigation_status, COUNT(*) 
                FROM xdr_correlations 
                WHERE investigation_status IS NOT NULL
                AND timestamp >= ? AND timestamp <= ?
                GROUP BY investigation_status
            ''', (start_date.isoformat(), end_date.isoformat()))
            investigation_statuses = dict(cursor.fetchall())
            
            # High-risk correlations (>0.8)
            cursor.execute('''
                SELECT COUNT(*) FROM xdr_correlations 
                WHERE threat_score >= 0.8
                AND timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            high_risk = cursor.fetchone()[0]
            
            # Medium-risk correlations (0.5-0.8)
            cursor.execute('''
                SELECT COUNT(*) FROM xdr_correlations 
                WHERE threat_score >= 0.5 AND threat_score < 0.8
                AND timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            medium_risk = cursor.fetchone()[0]
            
            # Low-risk correlations (<0.5)
            cursor.execute('''
                SELECT COUNT(*) FROM xdr_correlations 
                WHERE threat_score < 0.5
                AND timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            low_risk = cursor.fetchone()[0]
            
            # Resolved incidents
            cursor.execute('''
                SELECT COUNT(*) FROM xdr_correlations 
                WHERE investigation_status = 'resolved'
                AND timestamp >= ? AND timestamp <= ?
            ''', (start_date.isoformat(), end_date.isoformat()))
            resolved_incidents = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'period_days': days,
                'period_start': start_date.isoformat(),
                'period_end': end_date.isoformat(),
                'total_correlations': total_correlations,
                'threat_categories': threat_categories,
                'investigation_statuses': investigation_statuses,
                'high_risk_detections': high_risk,
                'medium_risk_detections': medium_risk,
                'low_risk_detections': low_risk,
                'resolved_incidents': resolved_incidents
            }
            
        except Exception as e:
            logger.error(f"Failed to get XDR stats: {e}")
            return {}
    
    def cleanup_old_data(self, days_to_keep: int = 90) -> int:
        """
        Clean up old telemetry data to manage database size.
        
        Args:
            days_to_keep: Number of days of data to keep
            
        Returns:
            Number of records deleted
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Calculate cutoff date
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)
            
            # Delete old records
            cursor.execute('''
                DELETE FROM telemetry WHERE timestamp < ?
            ''', (cutoff_date.isoformat(),))
            
            deleted_count = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            logger.info(f"Cleaned up {deleted_count} old telemetry records")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to clean up old telemetry data: {e}")
            return 0

class TelemetrySecurity:
    """Security features for telemetry collection"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = {}
        self.api_keys = set()
        
        # Load API keys from environment or file
        api_key = os.getenv('TELEMETRY_API_KEY')
        if api_key:
            self.api_keys.add(api_key)
    
    def validate_api_key(self, api_key: str) -> bool:
        """
        Validate API key for telemetry submission.
        
        Args:
            api_key: API key to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not self.api_keys:
            # If no API keys configured, allow all (for development)
            return True
        
        return api_key in self.api_keys
    
    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if a client is rate limited.
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if client is allowed, False if rate limited
        """
        current_time = datetime.now(timezone.utc).timestamp()
        window_start = current_time - 60  # 1 minute window
        
        # Clean up old requests
        if client_id in self.rate_limits:
            self.rate_limits[client_id] = [
                timestamp for timestamp in self.rate_limits[client_id]
                if timestamp > window_start
            ]
        else:
            self.rate_limits[client_id] = []
        
        # Check rate limit (100 requests per minute)
        if len(self.rate_limits[client_id]) >= 100:
            logger.warning(f"Rate limit exceeded for telemetry client: {client_id}")
            return False
        
        # Record this request
        self.rate_limits[client_id].append(current_time)
        return True
    
    def check_ip_blocking(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is allowed, False if blocked
        """
        if ip_address in self.blocked_ips:
            logger.warning(f"Blocked telemetry request from IP: {ip_address}")
            return False
        return True
    
    def validate_data(self, data: Dict) -> bool:
        """
        Validate telemetry data for security issues.
        
        Args:
            data: Telemetry data to validate
            
        Returns:
            True if data is valid, False otherwise
        """
        # Check required fields
        required_fields = ['client_id']
        for field in required_fields:
            if field not in data or not data[field]:
                logger.warning(f"Telemetry data missing required field: {field}")
                return False
        
        # Check data size
        data_size = len(json.dumps(data).encode('utf-8'))
        if data_size > 1024 * 100:  # 100KB limit
            logger.warning(f"Telemetry data too large: {data_size} bytes")
            return False
        
        return True

class TelemetryAggregator:
    """Aggregates telemetry data for efficient querying and reporting"""
    
    def __init__(self, db: TelemetryDatabase):
        self.db = db
        self.aggregation_task = None
    
    async def start_aggregation(self):
        """Start periodic aggregation task."""
        self.aggregation_task = asyncio.create_task(self._aggregate_periodically())
        logger.info("Telemetry aggregation started")
    
    async def stop_aggregation(self):
        """Stop aggregation task."""
        if self.aggregation_task:
            self.aggregation_task.cancel()
            try:
                await self.aggregation_task
            except asyncio.CancelledError:
                pass
            logger.info("Telemetry aggregation stopped")
    
    async def _aggregate_periodically(self):
        """Periodically aggregate telemetry data."""
        while True:
            try:
                await self._aggregate_daily_stats()
                await asyncio.sleep(3600)  # Run every hour
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in telemetry aggregation: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retrying
    
    async def _aggregate_daily_stats(self):
        """Aggregate daily statistics."""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            # Get yesterday's date
            yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
            
            # Check if stats already exist for yesterday
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry_stats WHERE date = ?
            ''', (yesterday,))
            
            if cursor.fetchone()[0] > 0:
                # Stats already exist, skip aggregation
                conn.close()
                return
            
            # Calculate statistics for yesterday
            start_time = datetime.fromisoformat(yesterday).replace(tzinfo=timezone.utc)
            end_time = start_time + timedelta(days=1)
            
            # Total records
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE timestamp >= ? AND timestamp < ?
            ''', (start_time.isoformat(), end_time.isoformat()))
            total_records = cursor.fetchone()[0]
            
            # Threat detections
            cursor.execute('''
                SELECT COUNT(*) FROM telemetry 
                WHERE threat_type IS NOT NULL AND threat_type != ''
                AND timestamp >= ? AND timestamp < ?
            ''', (start_time.isoformat(), end_time.isoformat()))
            threat_detections = cursor.fetchone()[0]
            
            # Unique clients
            cursor.execute('''
                SELECT COUNT(DISTINCT client_id) FROM telemetry
                WHERE timestamp >= ? AND timestamp < ?
            ''', (start_time.isoformat(), end_time.isoformat()))
            unique_clients = cursor.fetchone()[0]
            
            # Average confidence
            cursor.execute('''
                SELECT AVG(confidence) FROM telemetry
                WHERE confidence IS NOT NULL
                AND timestamp >= ? AND timestamp < ?
            ''', (start_time.isoformat(), end_time.isoformat()))
            avg_confidence = cursor.fetchone()[0] or 0.0
            
            # Insert aggregated stats
            cursor.execute('''
                INSERT OR REPLACE INTO telemetry_stats 
                (date, total_records, threat_detections, unique_clients, avg_confidence, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                yesterday,
                total_records,
                threat_detections,
                unique_clients,
                round(avg_confidence, 4),
                datetime.now(timezone.utc).isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Aggregated telemetry stats for {yesterday}")
            
        except Exception as e:
            logger.error(f"Failed to aggregate daily stats: {e}")

class RefinedTelemetryCollector:
    """Refined AegisAI Telemetry Collector with enhanced features"""
    
    def __init__(self, host: str = 'localhost', port: int = 8081, db_path: str = "telemetry.db"):
        """
        Initialize telemetry collector.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            db_path: Path to SQLite database file
        """
        self.host = host
        self.port = port
        self.db = TelemetryDatabase(db_path)
        self.security = TelemetrySecurity()
        self.aggregator = TelemetryAggregator(self.db)
        self.app = None
        self.runner = None
        self.site = None
    
    async def start(self):
        """Start the telemetry collector."""
        try:
            if not AIOHTTP_AVAILABLE:
                logger.error("aiohttp not available, cannot start telemetry collector")
                return
            
            # Create aiohttp application
            self.app = web.Application()
            
            # Set up routes
            self.app.router.add_post('/api/v1/telemetry', self._handle_telemetry_submission)
            self.app.router.add_get('/api/v1/stats', self._handle_stats_request)
            self.app.router.add_get('/api/v1/client/{client_id}/stats', self._handle_client_stats_request)
            self.app.router.add_post('/api/v1/batch', self._handle_batch_submission)
            
            # XDR endpoints
            self.app.router.add_post('/api/v1/network-telemetry', self._handle_network_telemetry_submission)
            self.app.router.add_post('/api/v1/cloud-telemetry', self._handle_cloud_telemetry_submission)
            self.app.router.add_post('/api/v1/xdr-correlations', self._handle_xdr_correlation_submission)
            self.app.router.add_get('/api/v1/xdr-correlations', self._handle_xdr_correlations_request)
            self.app.router.add_put('/api/v1/xdr-correlations/{correlation_id}', self._handle_xdr_correlation_update)
            self.app.router.add_get('/api/v1/xdr-stats', self._handle_xdr_stats_request)
            
            # Set up middleware
            self.app.middlewares.append(self._security_middleware)
            
            # Start aggregation
            await self.aggregator.start_aggregation()
            
            # Start server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            
            logger.info(f"Refined telemetry collector started on {self.host}:{self.port}")
            logger.info(f"API endpoints:")
            logger.info(f"  - Submit telemetry: http://{self.host}:{self.port}/api/v1/telemetry")
            logger.info(f"  - Batch submission: http://{self.host}:{self.port}/api/v1/batch")
            logger.info(f"  - Get stats: http://{self.host}:{self.port}/api/v1/stats")
            logger.info(f"  - Client stats: http://{self.host}:{self.port}/api/v1/client/{{client_id}}/stats")
            logger.info(f"  - Submit network telemetry: http://{self.host}:{self.port}/api/v1/network-telemetry")
            logger.info(f"  - Submit cloud telemetry: http://{self.host}:{self.port}/api/v1/cloud-telemetry")
            logger.info(f"  - Submit XDR correlations: http://{self.host}:{self.port}/api/v1/xdr-correlations")
            logger.info(f"  - Get XDR correlations: http://{self.host}:{self.port}/api/v1/xdr-correlations")
            logger.info(f"  - Update XDR correlation: http://{self.host}:{self.port}/api/v1/xdr-correlations/{{correlation_id}}")
            logger.info(f"  - Get XDR stats: http://{self.host}:{self.port}/api/v1/xdr-stats")
            
        except Exception as e:
            logger.error(f"Failed to start telemetry collector: {e}")
    
    async def stop(self):
        """Stop the telemetry collector."""
        try:
            # Stop aggregation
            await self.aggregator.stop_aggregation()
            
            # Stop server
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            
            logger.info("Refined telemetry collector stopped")
        except Exception as e:
            logger.error(f"Error stopping telemetry collector: {e}")
    
    async def _security_middleware(self, app: web.Application, handler):
        """Security middleware for request validation."""
        async def middleware_handler(request: web.Request):
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            
            # Check if IP is blocked
            if not self.security.check_ip_blocking(client_ip):
                return web.json_response({
                    'error': 'Forbidden',
                    'message': 'IP address blocked'
                }, status=403)
            
            # Check rate limiting
            client_id = request.headers.get('X-Client-ID', 'unknown')
            if not self.security.check_rate_limit(client_id):
                return web.json_response({
                    'error': 'Too Many Requests',
                    'message': 'Rate limit exceeded'
                }, status=429)
            
            return await handler(request)
        
        return middleware_handler
    
    async def _handle_telemetry_submission(self, request: web.Request) -> web.Response:
        """Handle telemetry data submission."""
        start_time = datetime.now(timezone.utc).timestamp()
        
        try:
            # Validate API key
            api_key = request.headers.get('X-API-Key')
            if api_key and not self.security.validate_api_key(api_key):
                return web.json_response({
                    'error': 'Unauthorized',
                    'message': 'Invalid API key'
                }, status=401)
            
            # Get content
            content_type = request.headers.get('Content-Type', '')
            if 'gzip' in content_type:
                if not GZIP_AVAILABLE:
                    return web.json_response({
                        'error': 'Unsupported Media Type',
                        'message': 'GZIP compression not supported'
                    }, status=415)
                
                # Decompress gzipped content
                compressed_data = await request.read()
                data_bytes = gzip.decompress(compressed_data)
                telemetry_data = json.loads(data_bytes.decode('utf-8'))
            else:
                # Read JSON data
                telemetry_data = await request.json()
            
            # Add client IP and user agent
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            user_agent = request.headers.get('User-Agent', '')
            
            telemetry_data['ip_address'] = client_ip
            telemetry_data['user_agent'] = user_agent
            
            # Validate data
            if not self.security.validate_data(telemetry_data):
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'Invalid telemetry data'
                }, status=400)
            
            # Add processing time
            processing_time = datetime.now(timezone.utc).timestamp() - start_time
            telemetry_data['processing_time'] = processing_time
            
            # Insert into database
            success = self.db.insert_telemetry(telemetry_data)
            
            if success:
                return web.json_response({
                    'status': 'success',
                    'message': 'Telemetry data received',
                    'processing_time': round(processing_time, 4)
                })
            else:
                return web.json_response({
                    'error': 'Internal Server Error',
                    'message': 'Failed to store telemetry data'
                }, status=500)
                
        except json.JSONDecodeError:
            return web.json_response({
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Failed to handle telemetry submission: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_batch_submission(self, request: web.Request) -> web.Response:
        """Handle batch telemetry data submission."""
        start_time = datetime.now(timezone.utc).timestamp()
        
        try:
            # Validate API key
            api_key = request.headers.get('X-API-Key')
            if api_key and not self.security.validate_api_key(api_key):
                return web.json_response({
                    'error': 'Unauthorized',
                    'message': 'Invalid API key'
                }, status=401)
            
            # Get content
            content_type = request.headers.get('Content-Type', '')
            if 'gzip' in content_type:
                if not GZIP_AVAILABLE:
                    return web.json_response({
                        'error': 'Unsupported Media Type',
                        'message': 'GZIP compression not supported'
                    }, status=415)
                
                # Decompress gzipped content
                compressed_data = await request.read()
                data_bytes = gzip.decompress(compressed_data)
                batch_data = json.loads(data_bytes.decode('utf-8'))
            else:
                # Read JSON data
                batch_data = await request.json()
            
            # Validate batch data
            if not isinstance(batch_data, list):
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'Batch data must be an array'
                }, status=400)
            
            if len(batch_data) > 1000:
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'Batch size limit exceeded (max 1000 records)'
                }, status=400)
            
            # Add client IP and user agent to each record
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            user_agent = request.headers.get('User-Agent', '')
            
            for data in batch_data:
                data['ip_address'] = client_ip
                data['user_agent'] = user_agent
            
            # Validate each record
            valid_data = []
            for data in batch_data:
                if self.security.validate_data(data):
                    valid_data.append(data)
                else:
                    logger.warning(f"Invalid telemetry data in batch: {data}")
            
            if not valid_data:
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'No valid telemetry data in batch'
                }, status=400)
            
            # Insert into database
            inserted_count = self.db.batch_insert_telemetry(valid_data)
            
            # Calculate processing time
            processing_time = datetime.now(timezone.utc).timestamp() - start_time
            
            return web.json_response({
                'status': 'success',
                'message': f'Batch telemetry data received ({inserted_count}/{len(valid_data)} records)',
                'processing_time': round(processing_time, 4),
                'records_processed': inserted_count
            })
                
        except json.JSONDecodeError:
            return web.json_response({
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Failed to handle batch telemetry submission: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_stats_request(self, request: web.Request) -> web.Response:
        """Handle statistics request."""
        try:
            # Get days parameter
            days = int(request.query.get('days', 30))
            if days < 1 or days > 365:
                days = 30
            
            stats = self.db.get_telemetry_stats(days)
            
            return web.json_response(stats)
            
        except Exception as e:
            logger.error(f"Failed to handle stats request: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_client_stats_request(self, request: web.Request) -> web.Response:
        """Handle client statistics request."""
        try:
            client_id = request.match_info['client_id']
            
            # Get days parameter
            days = int(request.query.get('days', 30))
            if days < 1 or days > 365:
                days = 30
            
            stats = self.db.get_client_stats(client_id, days)
            
            return web.json_response(stats)
            
        except Exception as e:
            logger.error(f"Failed to handle client stats request: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_network_telemetry_submission(self, request: web.Request) -> web.Response:
        """Handle network telemetry data submission."""
        start_time = datetime.now(timezone.utc).timestamp()
        
        try:
            # Validate API key
            api_key = request.headers.get('X-API-Key')
            if api_key and not self.security.validate_api_key(api_key):
                return web.json_response({
                    'error': 'Unauthorized',
                    'message': 'Invalid API key'
                }, status=401)
            
            # Get content
            content_type = request.headers.get('Content-Type', '')
            if 'gzip' in content_type:
                if not GZIP_AVAILABLE:
                    return web.json_response({
                        'error': 'Unsupported Media Type',
                        'message': 'GZIP compression not supported'
                    }, status=415)
                
                # Decompress gzipped content
                compressed_data = await request.read()
                data_bytes = gzip.decompress(compressed_data)
                telemetry_data = json.loads(data_bytes.decode('utf-8'))
            else:
                # Read JSON data
                telemetry_data = await request.json()
            
            # Add client IP and user agent
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            user_agent = request.headers.get('User-Agent', '')
            
            telemetry_data['ip_address'] = client_ip
            telemetry_data['user_agent'] = user_agent
            
            # Validate data
            if not self.security.validate_data(telemetry_data):
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'Invalid telemetry data'
                }, status=400)
            
            # Add processing time
            processing_time = datetime.now(timezone.utc).timestamp() - start_time
            telemetry_data['processing_time'] = processing_time
            
            # Insert into database
            success = self.db.insert_network_telemetry(telemetry_data)
            
            if success:
                return web.json_response({
                    'status': 'success',
                    'message': 'Network telemetry data received',
                    'processing_time': round(processing_time, 4)
                })
            else:
                return web.json_response({
                    'error': 'Internal Server Error',
                    'message': 'Failed to store network telemetry data'
                }, status=500)
                
        except json.JSONDecodeError:
            return web.json_response({
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Failed to handle network telemetry submission: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_cloud_telemetry_submission(self, request: web.Request) -> web.Response:
        """Handle cloud telemetry data submission."""
        start_time = datetime.now(timezone.utc).timestamp()
        
        try:
            # Validate API key
            api_key = request.headers.get('X-API-Key')
            if api_key and not self.security.validate_api_key(api_key):
                return web.json_response({
                    'error': 'Unauthorized',
                    'message': 'Invalid API key'
                }, status=401)
            
            # Get content
            content_type = request.headers.get('Content-Type', '')
            if 'gzip' in content_type:
                if not GZIP_AVAILABLE:
                    return web.json_response({
                        'error': 'Unsupported Media Type',
                        'message': 'GZIP compression not supported'
                    }, status=415)
                
                # Decompress gzipped content
                compressed_data = await request.read()
                data_bytes = gzip.decompress(compressed_data)
                telemetry_data = json.loads(data_bytes.decode('utf-8'))
            else:
                # Read JSON data
                telemetry_data = await request.json()
            
            # Add client IP and user agent
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            user_agent = request.headers.get('User-Agent', '')
            
            telemetry_data['ip_address'] = client_ip
            telemetry_data['user_agent'] = user_agent
            
            # Validate data
            if not self.security.validate_data(telemetry_data):
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'Invalid telemetry data'
                }, status=400)
            
            # Add processing time
            processing_time = datetime.now(timezone.utc).timestamp() - start_time
            telemetry_data['processing_time'] = processing_time
            
            # Insert into database
            success = self.db.insert_cloud_telemetry(telemetry_data)
            
            if success:
                return web.json_response({
                    'status': 'success',
                    'message': 'Cloud telemetry data received',
                    'processing_time': round(processing_time, 4)
                })
            else:
                return web.json_response({
                    'error': 'Internal Server Error',
                    'message': 'Failed to store cloud telemetry data'
                }, status=500)
                
        except json.JSONDecodeError:
            return web.json_response({
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Failed to handle cloud telemetry submission: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_xdr_correlation_submission(self, request: web.Request) -> web.Response:
        """Handle XDR correlation data submission."""
        start_time = datetime.now(timezone.utc).timestamp()
        
        try:
            # Validate API key
            api_key = request.headers.get('X-API-Key')
            if api_key and not self.security.validate_api_key(api_key):
                return web.json_response({
                    'error': 'Unauthorized',
                    'message': 'Invalid API key'
                }, status=401)
            
            # Get content
            content_type = request.headers.get('Content-Type', '')
            if 'gzip' in content_type:
                if not GZIP_AVAILABLE:
                    return web.json_response({
                        'error': 'Unsupported Media Type',
                        'message': 'GZIP compression not supported'
                    }, status=415)
                
                # Decompress gzipped content
                compressed_data = await request.read()
                data_bytes = gzip.decompress(compressed_data)
                telemetry_data = json.loads(data_bytes.decode('utf-8'))
            else:
                # Read JSON data
                telemetry_data = await request.json()
            
            # Add client IP and user agent
            client_ip = request.headers.get('X-Forwarded-For', request.remote)
            user_agent = request.headers.get('User-Agent', '')
            
            telemetry_data['ip_address'] = client_ip
            telemetry_data['user_agent'] = user_agent
            
            # Validate data
            if not self.security.validate_data(telemetry_data):
                return web.json_response({
                    'error': 'Bad Request',
                    'message': 'Invalid telemetry data'
                }, status=400)
            
            # Add processing time
            processing_time = datetime.now(timezone.utc).timestamp() - start_time
            telemetry_data['processing_time'] = processing_time
            
            # Insert into database
            success = self.db.insert_xdr_correlation(telemetry_data)
            
            if success:
                return web.json_response({
                    'status': 'success',
                    'message': 'XDR correlation data received',
                    'processing_time': round(processing_time, 4)
                })
            else:
                return web.json_response({
                    'error': 'Internal Server Error',
                    'message': 'Failed to store XDR correlation data'
                }, status=500)
                
        except json.JSONDecodeError:
            return web.json_response({
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Failed to handle XDR correlation submission: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_xdr_correlations_request(self, request: web.Request) -> web.Response:
        """Handle XDR correlations request."""
        try:
            # Get query parameters
            client_id = request.query.get('client_id')
            threat_category = request.query.get('threat_category')
            status = request.query.get('status')
            limit = int(request.query.get('limit', 100))
            
            # Ensure limit is reasonable
            if limit > 1000:
                limit = 1000
            
            correlations = self.db.get_xdr_correlations(
                client_id=client_id,
                threat_category=threat_category,
                status=status,
                limit=limit
            )
            
            return web.json_response({
                'status': 'success',
                'correlations': correlations,
                'count': len(correlations)
            })
            
        except Exception as e:
            logger.error(f"Failed to handle XDR correlations request: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_xdr_correlation_update(self, request: web.Request) -> web.Response:
        """Handle XDR correlation update request."""
        try:
            correlation_id = request.match_info['correlation_id']
            
            # Get content
            update_data = await request.json()
            
            # Extract update fields
            status = update_data.get('status')
            assigned_to = update_data.get('assigned_to')
            resolution_notes = update_data.get('resolution_notes')
            
            # Update database
            success = self.db.update_xdr_investigation_status(
                correlation_id=correlation_id,
                status=status,
                assigned_to=assigned_to,
                resolution_notes=resolution_notes
            )
            
            if success:
                return web.json_response({
                    'status': 'success',
                    'message': 'XDR correlation updated successfully'
                })
            else:
                return web.json_response({
                    'error': 'Internal Server Error',
                    'message': 'Failed to update XDR correlation'
                }, status=500)
                
        except json.JSONDecodeError:
            return web.json_response({
                'error': 'Bad Request',
                'message': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Failed to handle XDR correlation update: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)
    
    async def _handle_xdr_stats_request(self, request: web.Request) -> web.Response:
        """Handle XDR statistics request."""
        try:
            # Get days parameter
            days = int(request.query.get('days', 30))
            if days < 1 or days > 365:
                days = 30
            
            stats = self.db.get_xdr_stats(days)
            
            return web.json_response(stats)
            
        except Exception as e:
            logger.error(f"Failed to handle XDR stats request: {e}")
            return web.json_response({
                'error': 'Internal Server Error',
                'message': 'An internal server error occurred'
            }, status=500)

# Example usage and testing
async def main():
    """Main function for testing the refined telemetry collector."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start collector
    collector = RefinedTelemetryCollector('localhost', 8081)
    await collector.start()
    
    # Keep running
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Telemetry collector stopped by user")
        await collector.stop()

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())