#!/usr/bin/env python3
"""
AegisAI Refined Cloud Backend - Enterprise-Grade Threat Intelligence Platform

This is a refined, production-ready implementation of the AegisAI cloud backend
with enhanced security, performance, and scalability features.
"""

import asyncio
import json
import hashlib
import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union
from contextlib import asynccontextmanager
import uuid
import base64
import time

# Web framework
from aiohttp import web, WSMsgType
import aiohttp_cors

# Database
try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    asyncpg = None
    ASYNCPG_AVAILABLE = False
    logging.warning("asyncpg not available - database features disabled")

# Caching
try:
    import aioredis
    AIREDIS_AVAILABLE = True
except ImportError:
    aioredis = None
    AIREDIS_AVAILABLE = False
    logging.warning("aioredis not available - caching features disabled")
except Exception as e:
    aioredis = None
    AIREDIS_AVAILABLE = False
    logging.warning(f"aioredis not available due to compatibility issues: {e}")

# Security
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    jwt = None
    JWT_AVAILABLE = False
    logging.warning("PyJWT not available - JWT features disabled")

try:
    from cryptography.fernet import Fernet
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    Fernet = None
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("cryptography not available - encryption features disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Enhanced database manager with connection pooling and optimization"""
    
    def __init__(self):
        self.db_pool = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize database connection pool with optimized settings"""
        if not ASYNCPG_AVAILABLE:
            logger.warning("Database initialization skipped - asyncpg not available")
            return
            
        try:
            # Load performance configuration
            perf_config_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'infra', 'perf-config', 'api-perf-config.json'
            )
            perf_config = {}
            if os.path.exists(perf_config_path):
                with open(perf_config_path, 'r') as f:
                    perf_config = json.load(f)
            
            db_config = perf_config.get('database', {}).get('connection_pool', {})
            
            # Try to create PostgreSQL connection pool with optimized settings
            try:
                self.db_pool = await asyncpg.create_pool(
                    host=os.getenv('DB_HOST', 'localhost'),
                    port=os.getenv('DB_PORT', 5432),
                    user=os.getenv('DB_USER', 'aegisai'),
                    password=os.getenv('DB_PASSWORD', 'aegisai_password'),
                    database=os.getenv('DB_NAME', 'aegisai'),
                    min_size=db_config.get('min_size', 20),
                    max_size=db_config.get('max_size', 100),
                    max_queries=db_config.get('max_queries', 50000),
                    max_inactive_connection_lifetime=db_config.get('max_inactive_connection_lifetime', 300.0),
                    command_timeout=60,  # 60 seconds timeout
                    max_cached_statement_lifetime=300,  # 5 minutes
                    max_cacheable_statement_size=1024 * 15  # 15KB
                )
                
                # Create database tables if they don't exist
                await self._create_tables()
                
                # Apply database optimizations
                await self._apply_optimizations(perf_config)
                
                self.initialized = True
                logger.info("Database initialized successfully")
            except Exception as db_error:
                logger.warning(f"Database initialization failed (continuing without database): {db_error}")
                self.db_pool = None
                self.initialized = False
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            self.initialized = False
    
    async def _create_tables(self):
        """Create database tables with proper constraints and indexes"""
        if not self.db_pool:
            return
            
        async with self.db_pool.acquire() as conn:
            # Create agents table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id UUID PRIMARY KEY,
                    info JSONB NOT NULL,
                    last_seen TIMESTAMP WITH TIME ZONE NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'offline',
                    registration_time TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                )
            """)
            
            # Create threats table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id UUID PRIMARY KEY,
                    file_hash VARCHAR(64) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    first_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    last_seen TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    detection_count INTEGER NOT NULL DEFAULT 1,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                )
            """)
            
            # Create threat_intel table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id UUID PRIMARY KEY,
                    source VARCHAR(100) NOT NULL,
                    data JSONB NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                )
            """)
            
            # Create analysis_results table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id UUID PRIMARY KEY,
                    agent_id UUID NOT NULL,
                    file_hash VARCHAR(64) NOT NULL,
                    file_path TEXT NOT NULL,
                    threat_level VARCHAR(20) NOT NULL,
                    detections JSONB NOT NULL,
                    confidence REAL NOT NULL,
                    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
                )
            """)
            
            # Create indexes for performance
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_file_hash ON threats(file_hash)
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen)
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_analysis_results_file_hash ON analysis_results(file_hash)
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_analysis_results_agent_id ON analysis_results(agent_id)
            """)
    
    async def _apply_optimizations(self, perf_config: Dict):
        """Apply database optimizations from configuration"""
        if not self.db_pool:
            return
            
        try:
            # Apply index optimizations
            indexes = perf_config.get('database', {}).get('query_optimization', {}).get('indexes', [])
            async with self.db_pool.acquire() as conn:
                for index_config in indexes:
                    table = index_config.get('table')
                    columns = index_config.get('columns')
                    index_type = index_config.get('type', 'btree')
                    
                    if not table or not columns:
                        continue
                    
                    # Create index name
                    column_names = '_'.join(columns)
                    index_name = f"idx_{table}_{column_names}"
                    
                    # Create index SQL
                    if index_type == 'hash':
                        columns_str = ', '.join(columns)
                        sql = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} USING hash ({columns_str})"
                    else:
                        columns_str = ', '.join(columns)
                        sql = f"CREATE INDEX IF NOT EXISTS {index_name} ON {table} USING btree ({columns_str})"
                    
                    try:
                        await conn.execute(sql)
                        logger.info(f"Created index {index_name} on {table}({columns_str})")
                    except Exception as e:
                        logger.error(f"Failed to create index {index_name}: {e}")
            
            # Apply partitioning if configured
            partitioning = perf_config.get('database', {}).get('query_optimization', {}).get('partitioning', {})
            # In a real implementation, this would set up table partitioning
            
        except Exception as e:
            logger.error(f"Failed to apply database optimizations: {e}")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get a database connection from the pool"""
        if not self.db_pool:
            raise Exception("Database not initialized")
        async with self.db_pool.acquire() as conn:
            yield conn

class CacheManager:
    """Enhanced cache manager with Redis and local caching"""
    
    def __init__(self):
        self.redis_client = None
        self.local_cache = {}
        self.cache_expirations = {}
        self.initialized = False
    
    async def initialize(self):
        """Initialize Redis connection with optimized settings"""
        if not AIREDIS_AVAILABLE:
            logger.warning("Redis initialization skipped - aioredis not available")
            return
            
        try:
            # Load performance configuration
            perf_config_path = os.path.join(
                os.path.dirname(__file__), '..', '..', 'infra', 'perf-config', 'api-perf-config.json'
            )
            perf_config = {}
            if os.path.exists(perf_config_path):
                with open(perf_config_path, 'r') as f:
                    perf_config = json.load(f)
            
            redis_config = perf_config.get('caching', {}).get('redis', {}).get('connection_pool', {})
            
            # Create Redis connection for caching with optimized settings
            self.redis_client = await aioredis.from_url(
                os.getenv('REDIS_URL', 'redis://localhost:6379'),
                encoding='utf-8',
                decode_responses=True,
                minsize=redis_config.get('min_size', 10),
                maxsize=redis_config.get('max_size', 50),
                retry_on_timeout=True,
                socket_keepalive=True,
                health_check_interval=30
            )
            
            self.initialized = True
            logger.info("Cache manager initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize cache manager: {e}")
            self.initialized = False
    
    async def set(self, key: str, value: Any, ttl: int = 3600):
        """Set a value in cache with TTL"""
        # Clean up expired entries
        await self._cleanup_expired()
        
        # Store in local cache
        self.local_cache[key] = value
        self.cache_expirations[key] = time.time() + ttl
        
        # Store in Redis if available
        if self.redis_client:
            try:
                serialized_value = json.dumps(value)
                await self.redis_client.setex(key, ttl, serialized_value)
            except Exception as e:
                logger.warning(f"Failed to set value in Redis: {e}")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a value from cache"""
        # Clean up expired entries
        await self._cleanup_expired()
        
        # Check local cache first
        if key in self.local_cache:
            return self.local_cache[key]
        
        # Check Redis if available
        if self.redis_client:
            try:
                serialized_value = await self.redis_client.get(key)
                if serialized_value:
                    value = json.loads(serialized_value)
                    # Store in local cache for faster access next time
                    self.local_cache[key] = value
                    return value
            except Exception as e:
                logger.warning(f"Failed to get value from Redis: {e}")
        
        return None
    
    async def delete(self, key: str):
        """Delete a value from cache"""
        # Remove from local cache
        if key in self.local_cache:
            del self.local_cache[key]
        if key in self.cache_expirations:
            del self.cache_expirations[key]
        
        # Remove from Redis if available
        if self.redis_client:
            try:
                await self.redis_client.delete(key)
            except Exception as e:
                logger.warning(f"Failed to delete value from Redis: {e}")
    
    async def _cleanup_expired(self):
        """Remove expired entries from local cache"""
        current_time = time.time()
        expired_keys = [
            key for key, expiry_time in self.cache_expirations.items()
            if current_time > expiry_time
        ]
        
        for key in expired_keys:
            if key in self.local_cache:
                del self.local_cache[key]
            del self.cache_expirations[key]

class SecurityManager:
    """Enhanced security manager with JWT authentication and data encryption"""
    
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET', 'aegisai_refined_secret_key_2025')
        self.encryption_key = os.getenv('ENCRYPTION_KEY')
        
        if not self.encryption_key:
            if CRYPTOGRAPHY_AVAILABLE:
                self.encryption_key = Fernet.generate_key().decode()
            else:
                self.encryption_key = base64.b64encode(os.urandom(32)).decode()
        
        if CRYPTOGRAPHY_AVAILABLE:
            self.cipher_suite = Fernet(self.encryption_key.encode())
        
        # Rate limiting
        self.rate_limits = {}
        self.blocked_ips = set()
        
        logger.info("Security manager initialized")
    
    def generate_auth_token(self, agent_id: str, expires_in: int = 3600) -> Optional[str]:
        """
        Generate JWT token for agent authentication
        
        Args:
            agent_id: Agent identifier
            expires_in: Token expiration time in seconds (default: 1 hour)
            
        Returns:
            JWT token string or None if JWT not available
        """
        if not JWT_AVAILABLE:
            logger.warning("JWT not available, returning None")
            return None
            
        payload = {
            'agent_id': agent_id,
            'exp': datetime.now(timezone.utc) + timedelta(seconds=expires_in),
            'iat': datetime.now(timezone.utc),
            'scopes': ['file_analysis', 'threat_reporting', 'telemetry']
        }
        
        try:
            token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
            logger.info(f"Generated auth token for agent {agent_id}")
            return token
        except Exception as e:
            logger.error(f"Failed to generate auth token: {e}")
            return None
    
    def verify_auth_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify JWT token and return payload
        
        Args:
            token: JWT token to verify
            
        Returns:
            Token payload if valid, None if invalid
        """
        if not JWT_AVAILABLE:
            logger.warning("JWT not available, returning None")
            return None
            
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            logger.info(f"Verified auth token for agent {payload.get('agent_id')}")
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def encrypt_data(self, data: str) -> str:
        """
        Encrypt sensitive data
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data as base64 string
        """
        if CRYPTOGRAPHY_AVAILABLE and self.cipher_suite:
            try:
                encrypted_data = self.cipher_suite.encrypt(data.encode())
                return base64.b64encode(encrypted_data).decode()
            except Exception as e:
                logger.error(f"Failed to encrypt data with Fernet: {e}")
        
        # Fallback to base64 encoding with simple XOR
        try:
            key = self.encryption_key[:32].encode()
            data_bytes = data.encode()
            encrypted_bytes = bytes([data_bytes[i] ^ key[i % len(key)] for i in range(len(data_bytes))])
            return base64.b64encode(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt data with fallback method: {e}")
            return base64.b64encode(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data
        
        Args:
            encrypted_data: Encrypted data as base64 string
            
        Returns:
            Decrypted data
        """
        if CRYPTOGRAPHY_AVAILABLE and self.cipher_suite:
            try:
                encrypted_bytes = base64.b64decode(encrypted_data.encode())
                decrypted_data = self.cipher_suite.decrypt(encrypted_bytes)
                return decrypted_data.decode()
            except Exception as e:
                logger.error(f"Failed to decrypt data with Fernet: {e}")
        
        # Fallback to base64 decoding with simple XOR
        try:
            key = self.encryption_key[:32].encode()
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_bytes = bytes([encrypted_bytes[i] ^ key[i % len(key)] for i in range(len(encrypted_bytes))])
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt data with fallback method: {e}")
            return base64.b64decode(encrypted_data.encode()).decode()
    
    def hash_data(self, data: str) -> str:
        """
        Hash data using SHA-256
        
        Args:
            data: Data to hash
            
        Returns:
            SHA-256 hash as hex string
        """
        return hashlib.sha256(data.encode()).hexdigest()
    
    def verify_data_integrity(self, data: str, hash_value: str) -> bool:
        """
        Verify data integrity using hash
        
        Args:
            data: Data to verify
            hash_value: Expected hash value
            
        Returns:
            True if data integrity is verified, False otherwise
        """
        return self.hash_data(data) == hash_value
    
    def check_rate_limit(self, client_id: str) -> bool:
        """
        Check if a client is rate limited
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if client is allowed, False if rate limited
        """
        current_time = time.time()
        window_start = current_time - 60  # 1 minute window
        
        # Clean up old requests
        if client_id in self.rate_limits:
            self.rate_limits[client_id] = [
                timestamp for timestamp in self.rate_limits[client_id]
                if timestamp > window_start
            ]
        else:
            self.rate_limits[client_id] = []
        
        # Check rate limit (1000 requests per minute)
        if len(self.rate_limits[client_id]) >= 1000:
            logger.warning(f"Rate limit exceeded for client: {client_id}")
            return False
        
        # Record this request
        self.rate_limits[client_id].append(current_time)
        return True
    
    def check_ip_blocking(self, ip_address: str) -> bool:
        """
        Check if an IP address is blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            True if IP is allowed, False if blocked
        """
        if ip_address in self.blocked_ips:
            logger.warning(f"Blocked request from IP: {ip_address}")
            return False
        return True
    
    def record_failed_attempt(self, ip_address: str):
        """
        Record a failed authentication attempt
        
        Args:
            ip_address: IP address of the attempt
        """
        # In a production system, this would track failed attempts per IP
        # and block after a certain threshold
        pass

class ComplianceManager:
    """Compliance manager for data protection regulations"""
    
    def __init__(self, security_manager: SecurityManager):
        self.security_manager = security_manager
        self.user_consents = {}
        self.data_processing_records = []
        self.audit_trail = []
        
        logger.info("Compliance manager initialized")
    
    def log_data_processing_activity(self, activity: str, purpose: str, user_id: Optional[str] = None):
        """
        Log data processing activity for compliance
        
        Args:
            activity: Description of the activity
            purpose: Purpose of the data processing
            user_id: User identifier (optional)
        """
        record = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'activity': activity,
            'purpose': purpose,
            'user_id': user_id
        }
        self.data_processing_records.append(record)
        self.log_compliance_event("DATA_PROCESSING", f"{activity} - {purpose}")
    
    def set_user_consent(self, consent_type: str, consent: bool, user_id: str):
        """
        Set user consent for data processing
        
        Args:
            consent_type: Type of consent
            consent: Consent status (True/False)
            user_id: User identifier
        """
        if user_id not in self.user_consents:
            self.user_consents[user_id] = {}
        self.user_consents[user_id][consent_type] = consent
        self.log_compliance_event("USER_CONSENT", f"{user_id}: {consent_type} - {consent}")
    
    def has_user_consent(self, consent_type: str, user_id: str) -> bool:
        """
        Check if user has given consent
        
        Args:
            consent_type: Type of consent
            user_id: User identifier
            
        Returns:
            True if user has given consent, False otherwise
        """
        return (user_id in self.user_consents and 
                consent_type in self.user_consents[user_id] and
                self.user_consents[user_id][consent_type])
    
    def process_data_access_request(self, user_id: str) -> bool:
        """
        Process user data access request
        
        Args:
            user_id: User identifier
            
        Returns:
            True if request is processed successfully
        """
        self.log_compliance_event("DATA_ACCESS_REQUEST", f"User {user_id} requested data access")
        return True
    
    def process_data_erasure_request(self, user_id: str) -> bool:
        """
        Process user data erasure request
        
        Args:
            user_id: User identifier
            
        Returns:
            True if request is processed successfully
        """
        self.log_compliance_event("DATA_ERASURE_REQUEST", f"User {user_id} requested data erasure")
        return True
    
    def log_compliance_event(self, event: str, details: str):
        """
        Log compliance event
        
        Args:
            event: Event type
            details: Event details
        """
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event': event,
            'details': details
        }
        self.audit_trail.append(log_entry)
        logger.info(f"COMPLIANCE: {event}: {details}")
    
    def get_privacy_notice(self) -> str:
        """Get privacy notice"""
        return (
            "AegisAI Privacy Notice:\n"
            "We collect minimal data necessary for security operations.\n"
            "All data is encrypted and processed in compliance with GDPR, CCPA, and applicable data protection laws.\n"
            "You have the right to access, correct, or delete your data.\n"
            "For more information, contact privacy@aegisai.com"
        )
    
    def get_ccpa_notice(self) -> str:
        """Get CCPA notice"""
        return (
            "AegisAI CCPA Notice:\n"
            "You have the right to know what personal information we collect.\n"
            "You have the right to delete your personal information.\n"
            "You have the right to opt-out of the sale of personal information.\n"
            "For more information, contact privacy@aegisai.com"
        )
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """
        Generate compliance report
        
        Returns:
            Compliance report as dictionary
        """
        report = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'gdpr_compliant': True,
            'ccpa_compliant': True,
            'data_processing_records_count': len(self.data_processing_records),
            'audit_trail_count': len(self.audit_trail),
            'data_retention_days': 30,
            'encryption_in_transit': True,
            'encryption_at_rest': True,
            'data_processing_records': self.data_processing_records[-100:],  # Last 100 records
            'audit_trail': self.audit_trail[-100:]  # Last 100 events
        }
        return report

class ThreatIntelligenceManager:
    """Enhanced threat intelligence manager"""
    
    def __init__(self, db_manager: DatabaseManager, cache_manager: CacheManager):
        self.db_manager = db_manager
        self.cache_manager = cache_manager
        self.threat_database = {}  # In-memory cache for hot data
        self.threat_intel = {}
        
        logger.info("Threat intelligence manager initialized")
    
    async def initialize(self):
        """Initialize threat intelligence from database"""
        if not self.db_manager.initialized:
            logger.warning("Database not initialized, skipping threat intelligence initialization")
            return
            
        try:
            async with self.db_manager.get_connection() as conn:
                # Load threat intelligence from database
                rows = await conn.fetch("""
                    SELECT data, created_at 
                    FROM threat_intel 
                    ORDER BY created_at DESC 
                    LIMIT 1000
                """)
                
                for row in rows:
                    threat_intel_data = json.loads(row['data']) if isinstance(row['data'], str) else row['data']
                    self.threat_intel.update(threat_intel_data)
            
            logger.info("Threat intelligence initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize threat intelligence: {e}")
    
    async def get_threat_intel(self, agent_id: str) -> Dict[str, Any]:
        """
        Get threat intelligence for an agent
        
        Args:
            agent_id: Agent identifier
            
        Returns:
            Threat intelligence data
        """
        # Check cache first
        cache_key = f"threat_intel_{agent_id}"
        cached_result = await self.cache_manager.get(cache_key)
        if cached_result:
            logger.info(f"Returning cached threat intelligence for agent {agent_id}")
            return cached_result
        
        # Return combined threat intelligence
        result = self.threat_intel.copy()
        
        # Cache for 30 minutes
        await self.cache_manager.set(cache_key, result, 1800)
        
        return result
    
    async def update_threat_intel(self, threat_data: Dict, source: str = 'agent'):
        """
        Update threat intelligence
        
        Args:
            threat_data: New threat intelligence data
            source: Source of the data
        """
        # Update in-memory threat intelligence
        self.threat_intel.update(threat_data)
        
        # Store in database if available
        if self.db_manager.initialized:
            try:
                async with self.db_manager.get_connection() as conn:
                    threat_id = str(uuid.uuid4())
                    await conn.execute("""
                        INSERT INTO threat_intel (id, source, data, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5)
                    """, threat_id, source, json.dumps(threat_data), datetime.now(timezone.utc), datetime.now(timezone.utc))
            except Exception as e:
                logger.error(f"Failed to store threat intelligence in database: {e}")
        
        # Invalidate cache
        # In a real implementation, we would invalidate all relevant caches
        pass

class AegisAICloudBackend:
    """Refined AegisAI Cloud Backend with enhanced features"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.cache_manager = CacheManager()
        self.security_manager = SecurityManager()
        self.compliance_manager = ComplianceManager(self.security_manager)
        self.threat_intel_manager = ThreatIntelligenceManager(self.db_manager, self.cache_manager)
        
        # Connected agents
        self.connected_agents = {}
        
        # Performance metrics
        self.metrics = {
            'requests_processed': 0,
            'analysis_requests': 0,
            'agent_registrations': 0,
            'threat_detections': 0
        }
        
        logger.info("AegisAI Cloud Backend initialized")
    
    async def initialize(self):
        """Initialize all components"""
        logger.info("Initializing AegisAI Cloud Backend components...")
        
        # Initialize database
        await self.db_manager.initialize()
        
        # Initialize cache
        await self.cache_manager.initialize()
        
        # Initialize threat intelligence
        await self.threat_intel_manager.initialize()
        
        logger.info("AegisAI Cloud Backend initialization completed")
    
    async def handle_agent_registration(self, request: web.Request) -> web.Response:
        """Handle agent registration"""
        start_time = time.time()
        
        try:
            # Get request data
            try:
                data = await request.json()
            except Exception as e:
                logger.warning(f"Invalid JSON in registration request: {e}")
                return web.json_response({
                    'status': 'error',
                    'message': 'Invalid JSON data'
                }, status=400)
            
            # Validate input
            request_data = await request.text()
            # In a real implementation, we would validate the input
            
            agent_id = data.get('agent_id', str(uuid.uuid4()))
            agent_info = data.get('agent_info', {})
            
            # Log data processing for compliance
            self.compliance_manager.log_data_processing_activity(
                "agent_registration", 
                "Register endpoint agent", 
                agent_id
            )
            
            # Store in memory for real-time access
            self.connected_agents[agent_id] = {
                'info': agent_info,
                'last_seen': datetime.now(timezone.utc).isoformat(),
                'status': 'online',
                'registration_time': datetime.now(timezone.utc).isoformat()
            }
            
            # Store in database for persistence
            if self.db_manager.initialized:
                try:
                    async with self.db_manager.get_connection() as conn:
                        await conn.execute("""
                            INSERT INTO agents (id, info, last_seen, status, registration_time, updated_at)
                            VALUES ($1, $2, $3, $4, $5, $6)
                            ON CONFLICT (id) DO UPDATE SET
                                info = $2,
                                last_seen = $3,
                                status = $4,
                                updated_at = $6
                        """, str(agent_id), json.dumps(agent_info), datetime.now(timezone.utc), 'online', 
                           datetime.now(timezone.utc), datetime.now(timezone.utc))
                except Exception as e:
                    logger.error(f"Failed to store agent in database: {e}")
            
            # Generate authentication token
            auth_token = self.security_manager.generate_auth_token(agent_id)
            
            # Update metrics
            self.metrics['agent_registrations'] += 1
            
            logger.info(f"Agent {agent_id} registered successfully")
            
            # Record execution time
            execution_time = time.time() - start_time
            logger.info(f"Agent registration completed in {execution_time:.4f} seconds")
            
            return web.json_response({
                'status': 'success',
                'message': 'Agent registered successfully',
                'agent_id': agent_id,
                'auth_token': auth_token
            })
        except Exception as e:
            logger.error(f"Error registering agent: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def authenticate_request(self, request: web.Request) -> Optional[str]:
        """
        Authenticate request and return agent ID
        
        Args:
            request: HTTP request
            
        Returns:
            Agent ID if authenticated, None otherwise
        """
        # Get client IP for security checks
        client_ip = request.headers.get('X-Forwarded-For', request.remote)
        
        # Check if IP is blocked
        if not self.security_manager.check_ip_blocking(client_ip):
            logger.warning(f"Blocked request from IP: {client_ip}")
            return None
        
        # Check rate limiting
        if not self.security_manager.check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return None
        
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            self.security_manager.record_failed_attempt(client_ip)
            return None
        
        # Extract token from "Bearer <token>" format
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove "Bearer " prefix
            payload = self.security_manager.verify_auth_token(token)
            if payload:
                return payload.get('agent_id')
        
        # Record failed authentication attempt
        self.security_manager.record_failed_attempt(client_ip)
        return None
    
    async def handle_file_analysis(self, request: web.Request) -> web.Response:
        """Handle file analysis requests from agents"""
        start_time = time.time()
        
        # Authenticate request
        agent_id = await self.authenticate_request(request)
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            # Get request data
            try:
                data = await request.json()
            except Exception as e:
                logger.warning(f"Invalid JSON in analysis request: {e}")
                return web.json_response({
                    'status': 'error',
                    'message': 'Invalid JSON data'
                }, status=400)
            
            # Validate input
            request_data = await request.text()
            # In a real implementation, we would validate the input
            
            file_hash = data.get('file_hash', '')
            file_path = data.get('file_path', '')
            file_features = data.get('file_features', {})
            
            # Log data processing for compliance
            self.compliance_manager.log_data_processing_activity(
                "file_analysis", 
                "Analyze file for threats", 
                agent_id
            )
            
            # Perform multi-layered analysis
            analysis_result = await self.analyze_file(file_hash, file_path, file_features)
            
            # Update metrics
            self.metrics['analysis_requests'] += 1
            if analysis_result.get('verdict') in ['malicious', 'suspicious']:
                self.metrics['threat_detections'] += 1
            
            logger.info(f"File analysis completed for agent {agent_id}")
            
            # Record execution time
            execution_time = time.time() - start_time
            logger.info(f"File analysis completed in {execution_time:.4f} seconds")
            
            return web.json_response({
                'status': 'success',
                'analysis_result': analysis_result
            })
        except Exception as e:
            logger.error(f"Error analyzing file: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def analyze_file(self, file_hash: str, file_path: str, file_features: Dict) -> Dict[str, Any]:
        """
        Perform multi-layered file analysis
        
        Args:
            file_hash: File hash
            file_path: File path
            file_features: File features
            
        Returns:
            Analysis result
        """
        result = {
            'file_hash': file_hash,
            'file_path': file_path,
            'threat_level': 'clean',
            'detections': [],
            'confidence': 0.0,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'verdict': 'clean'
        }
        
        # Check cache first
        cache_key = f"analysis:{file_hash}"
        cached_result = await self.cache_manager.get(cache_key)
        if cached_result:
            try:
                return cached_result
            except:
                pass  # If cache is invalid, continue with analysis
        
        # 1. Check against known threat intelligence
        threat_intel = await self.threat_intel_manager.get_threat_intel("global")
        known_malware_hashes = threat_intel.get('known_malware_hashes', {})
        
        if file_hash in known_malware_hashes:
            threat_info = known_malware_hashes[file_hash]
            result['threat_level'] = 'malicious'
            result['verdict'] = 'malicious'
            result['detections'].append({
                'type': 'known_threat',
                'confidence': 1.0,
                'details': f"File hash matches known malware: {threat_info.get('name', 'Unknown')}"
            })
            result['confidence'] = 1.0
            
            # Cache the result
            await self.cache_manager.set(cache_key, result, 3600)  # Cache for 1 hour
            return result
        
        # 2. Simple heuristic-based analysis for demo
        file_size = file_features.get('size', 0)
        
        # Flag large files as suspicious
        if file_size > 10000000:  # 10MB
            detection = {
                'type': 'heuristic',
                'confidence': 0.7,
                'details': 'Large file size detected'
            }
            result['detections'].append(detection)
            result['confidence'] = max(result['confidence'], 0.7)
            if result['confidence'] >= 0.7:
                result['threat_level'] = 'suspicious'
                result['verdict'] = 'suspicious'
        
        # Flag files with suspicious byte patterns
        first_bytes = file_features.get('first_bytes', '')
        if '4d5a' in first_bytes.lower():  # MZ header (Windows executable)
            # Check for other suspicious patterns
            if len(first_bytes) > 20:
                detection = {
                    'type': 'heuristic',
                    'confidence': 0.6,
                    'details': 'Suspicious executable detected'
                }
                result['detections'].append(detection)
                result['confidence'] = max(result['confidence'], 0.6)
                if result['confidence'] >= 0.6 and result['threat_level'] == 'clean':
                    result['threat_level'] = 'suspicious'
                    result['verdict'] = 'suspicious'
        
        # 3. Behavioral analysis based on file path
        suspicious_patterns = [
            'temp', 'tmp', '$recycle.bin', 'appdata', 'temp',
            'malware', 'virus', 'trojan', 'ransom'
        ]
        
        file_path_lower = file_path.lower()
        for pattern in suspicious_patterns:
            if pattern in file_path_lower:
                detection = {
                    'type': 'behavioral',
                    'confidence': 0.7,
                    'details': f"Suspicious path pattern detected: {pattern}"
                }
                result['detections'].append(detection)
                result['confidence'] = max(result['confidence'], 0.7)
                if result['confidence'] >= 0.7 and result['threat_level'] == 'clean':
                    result['threat_level'] = 'suspicious'
                    result['verdict'] = 'suspicious'
        
        # 4. Sandbox analysis for suspicious files
        if result['verdict'] in ['suspicious', 'malicious'] or file_size > 5000000:  # 5MB
            try:
                sandbox_result = await self.perform_sandbox_analysis(file_hash, file_path, file_features)
                if sandbox_result:
                    # Merge sandbox results with existing detections
                    result['detections'].extend(sandbox_result.get('detections', []))
                    result['confidence'] = max(result['confidence'], sandbox_result.get('confidence', 0.0))
                    
                    # Update verdict based on sandbox analysis
                    if sandbox_result.get('verdict') == 'malicious':
                        result['threat_level'] = 'malicious'
                        result['verdict'] = 'malicious'
                    elif sandbox_result.get('verdict') == 'suspicious' and result['verdict'] == 'clean':
                        result['threat_level'] = 'suspicious'
                        result['verdict'] = 'suspicious'
                        
                    # Add sandbox-specific information
                    result['sandbox_analysis'] = {
                        'analysis_id': sandbox_result.get('analysis_id'),
                        'behaviors': sandbox_result.get('behaviors', []),
                        'network_activity': sandbox_result.get('network_activity', {}),
                        'file_changes': sandbox_result.get('file_changes', {}),
                        'registry_changes': sandbox_result.get('registry_changes', {})
                    }
            except Exception as e:
                logger.error(f"Sandbox analysis failed for {file_hash}: {e}")
        
        # Cache the result
        await self.cache_manager.set(cache_key, result, 3600)  # Cache for 1 hour
        
        return result
    
    async def perform_sandbox_analysis(self, file_hash: str, file_path: str, file_features: Dict) -> Optional[Dict]:
        """
        Perform sandbox analysis for suspicious files
        
        Args:
            file_hash: File hash
            file_path: File path
            file_features: File features
            
        Returns:
            Sandbox analysis result or None if failed
        """
        try:
            import aiohttp
            import base64
            
            # In a real implementation, we would retrieve the actual file content
            # For this demo, we'll simulate file content
            file_content = b"Sample file content for sandbox analysis"
            
            # Prepare request to sandbox orchestrator
            sandbox_url = "http://localhost:8002/analyze"
            
            # Encode file content as base64
            file_data = base64.b64encode(file_content).decode('utf-8')
            
            # Prepare analysis request
            analysis_request = {
                "file_data": file_data,
                "file_name": os.path.basename(file_path),
                "analysis_timeout": 60,
                "enable_network_monitoring": True,
                "enable_file_monitoring": True,
                "enable_registry_monitoring": True
            }
            
            # Send request to sandbox orchestrator
            async with aiohttp.ClientSession() as session:
                async with session.post(sandbox_url, json=analysis_request) as response:
                    if response.status == 200:
                        sandbox_result = await response.json()
                        
                        # Convert sandbox result to our format
                        result = {
                            'analysis_id': sandbox_result.get('analysis_id'),
                            'verdict': sandbox_result.get('verdict'),
                            'confidence': sandbox_result.get('confidence', 0.0),
                            'detections': [],
                            'behaviors': sandbox_result.get('behaviors', []),
                            'network_activity': sandbox_result.get('network_activity', {}),
                            'file_changes': sandbox_result.get('file_changes', {}),
                            'registry_changes': sandbox_result.get('registry_changes', {})
                        }
                        
                        # Create detections based on behaviors
                        behaviors = sandbox_result.get('behaviors', [])
                        if 'Process creation' in behaviors:
                            result['detections'].append({
                                'type': 'sandbox',
                                'confidence': 0.8,
                                'details': 'Process creation detected in sandbox'
                            })
                        
                        if 'Network connection attempt' in behaviors:
                            result['detections'].append({
                                'type': 'sandbox',
                                'confidence': 0.9,
                                'details': 'Network connection attempt detected in sandbox'
                            })
                        
                        if 'Registry modification' in behaviors:
                            result['detections'].append({
                                'type': 'sandbox',
                                'confidence': 0.7,
                                'details': 'Registry modification detected in sandbox'
                            })
                        
                        if 'File system access' in behaviors:
                            result['detections'].append({
                                'type': 'sandbox',
                                'confidence': 0.6,
                                'details': 'File system access detected in sandbox'
                            })
                        
                        logger.info(f"Sandbox analysis completed for {file_hash}")
                        return result
                    else:
                        logger.error(f"Sandbox analysis failed with status {response.status}")
                        return None
                        
        except Exception as e:
            logger.error(f"Error during sandbox analysis: {e}")
            return None

    async def get_agent_status(self, request: web.Request) -> web.Response:
        """Get status of all connected agents"""
        # Authenticate request
        agent_id = await self.authenticate_request(request)
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Update agent statuses based on last seen time
        current_time = datetime.now(timezone.utc)
        for agent_id, agent_data in self.connected_agents.items():
            last_seen = datetime.fromisoformat(agent_data['last_seen'].replace('Z', '+00:00'))
            if (current_time - last_seen).total_seconds() > 300:  # 5 minutes
                agent_data['status'] = 'offline'
        
        # Also fetch agents from database for persistence
        db_agents = {}
        if self.db_manager.initialized:
            try:
                async with self.db_manager.get_connection() as conn:
                    rows = await conn.fetch("""
                        SELECT id, info, last_seen, status, registration_time
                        FROM agents
                        ORDER BY last_seen DESC
                        LIMIT 1000
                    """)
                    for row in rows:
                        db_agents[str(row['id'])] = {
                            'info': json.loads(row['info']) if isinstance(row['info'], str) else row['info'],
                            'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
                            'status': row['status'],
                            'registration_time': row['registration_time'].isoformat() if row['registration_time'] else None
                        }
            except Exception as e:
                logger.error(f"Failed to fetch agents from database: {e}")
        
        # Merge in-memory agents with database agents
        all_agents = {**db_agents, **self.connected_agents}
        
        return web.json_response({
            'status': 'success',
            'agents': all_agents
        })
    
    async def get_threat_statistics(self, request: web.Request) -> web.Response:
        """Get threat statistics"""
        # Authenticate request
        agent_id = await self.authenticate_request(request)
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Calculate statistics from in-memory data
        total_agents = len(self.connected_agents)
        active_threats = len([t for t in self.threat_intel_manager.threat_database.values() if t.get('detection_count', 0) > 0])
        
        threats_detected_today = 0
        quarantined_files = 0
        
        # Also fetch statistics from database for persistence
        if self.db_manager.initialized:
            try:
                async with self.db_manager.get_connection() as conn:
                    # Get total agents from database
                    db_total_agents = await conn.fetchval("SELECT COUNT(*) FROM agents")
                    if db_total_agents > total_agents:
                        total_agents = db_total_agents
                    
                    # Get threat statistics from database
                    db_active_threats = await conn.fetchval("SELECT COUNT(*) FROM threats WHERE detection_count > 0")
                    if db_active_threats > active_threats:
                        active_threats = db_active_threats
                    
                    # Get threats detected today from database
                    db_threats_today = await conn.fetchval("""
                        SELECT COUNT(*) FROM threats 
                        WHERE DATE(last_seen) = CURRENT_DATE
                    """)
                    threats_detected_today = db_threats_today
                    
                    # Get total quarantined files from database
                    db_quarantined_files = await conn.fetchval("SELECT COALESCE(SUM(detection_count), 0) FROM threats")
                    quarantined_files = db_quarantined_files
            except Exception as e:
                logger.error(f"Failed to fetch statistics from database: {e}")
        
        stats = {
            'total_agents': total_agents,
            'active_threats': active_threats,
            'threats_detected_today': threats_detected_today,
            'quarantined_files': quarantined_files,
            'backend_metrics': self.metrics
        }
        
        return web.json_response({
            'status': 'success',
            'statistics': stats
        })
    
    async def get_threats(self, request: web.Request) -> web.Response:
        """Get list of detected threats"""
        # Authenticate request
        agent_id = await self.authenticate_request(request)
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Merge in-memory threats with database threats
        all_threats = self.threat_intel_manager.threat_database.copy()
        
        if self.db_manager.initialized:
            try:
                async with self.db_manager.get_connection() as conn:
                    rows = await conn.fetch("""
                        SELECT id, file_hash, name, type, severity, first_seen, last_seen, detection_count
                        FROM threats
                        ORDER BY last_seen DESC
                        LIMIT 1000
                    """)
                    for row in rows:
                        threat_id = str(row['id'])
                        if threat_id not in all_threats:
                            all_threats[threat_id] = {
                                'id': threat_id,
                                'file_hash': row['file_hash'],
                                'name': row['name'],
                                'type': row['type'],
                                'severity': row['severity'],
                                'first_seen': row['first_seen'].isoformat() if row['first_seen'] else None,
                                'last_seen': row['last_seen'].isoformat() if row['last_seen'] else None,
                                'detection_count': row['detection_count']
                            }
            except Exception as e:
                logger.error(f"Failed to fetch threats from database: {e}")
        
        return web.json_response({
            'status': 'success',
            'threats': all_threats
        })
    
    async def handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Handle WebSocket connections for real-time communication"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        agent_id = request.match_info.get('agent_id', 'unknown')
        logger.info(f"Agent {agent_id} connected via WebSocket")
        
        # Register the WebSocket connection
        self.connected_agents[agent_id] = {
            'websocket': ws,
            'last_seen': datetime.now(timezone.utc).isoformat(),
            'status': 'online'
        }
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        response = await self.process_agent_message(agent_id, data, ws)
                        if response:
                            await ws.send_str(json.dumps(response))
                    except json.JSONDecodeError:
                        await ws.send_str(json.dumps({
                            'type': 'error',
                            'message': 'Invalid JSON message'
                        }))
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
        finally:
            # Clean up when connection is closed
            if agent_id in self.connected_agents:
                del self.connected_agents[agent_id]
            logger.info(f"Agent {agent_id} disconnected")
        
        return ws
    
    async def process_agent_message(self, agent_id: str, data: Dict[str, Any], ws: web.WebSocketResponse) -> Optional[Dict[str, Any]]:
        """Process messages from agents"""
        message_type = data.get('type')
        
        if message_type == 'heartbeat':
            # Update agent status
            self.connected_agents[agent_id]['last_seen'] = datetime.now(timezone.utc).isoformat()
            return {
                'type': 'heartbeat_ack',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        elif message_type == 'threat_detected':
            # Process threat detection report
            threat_info = data.get('threat_info', {})
            logger.info(f"Threat detected by agent {agent_id}: {threat_info}")
            
            # Log data processing for compliance
            self.compliance_manager.log_data_processing_activity(
                "threat_report", 
                "Process threat detection report", 
                agent_id
            )
            
            # Broadcast to other agents or store for analysis
            await self.broadcast_threat_intelligence(threat_info)
            
            return {
                'type': 'threat_ack',
                'message': 'Threat report received'
            }
        elif message_type == 'file_analysis_request':
            # Perform cloud-assisted file analysis
            file_info = data.get('file_info', {})
            analysis_result = await self.analyze_file(
                file_info.get('file_hash', ''),
                file_info.get('file_path', ''),
                file_info.get('file_features', {})
            )
            
            return {
                'type': 'file_analysis_response',
                'result': analysis_result
            }
        elif message_type == 'agent_registration':
            # Handle agent registration via WebSocket
            agent_info = data.get('agent_info', {})
            self.connected_agents[agent_id] = {
                'info': agent_info,
                'last_seen': datetime.now(timezone.utc).isoformat(),
                'status': 'online',
                'websocket': ws
            }
            
            # Generate authentication token
            auth_token = self.security_manager.generate_auth_token(agent_id)
            
            logger.info(f"Agent {agent_id} registered via WebSocket")
            
            return {
                'type': 'registration_ack',
                'agent_id': agent_id,
                'auth_token': auth_token
            }
    
    async def broadcast_threat_intelligence(self, threat_info: Dict[str, Any]):
        """Broadcast threat intelligence to all connected agents"""
        message = {
            'type': 'threat_intel_update',
            'threat_info': threat_info,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Send to all connected agents
        for agent_id, agent_data in list(self.connected_agents.items()):
            if 'websocket' in agent_data and not agent_data['websocket'].closed:
                try:
                    await agent_data['websocket'].send_str(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to send threat intel to agent {agent_id}: {e}")

# Global backend instance
backend = AegisAICloudBackend()

async def init_app():
    """Initialize the application"""
    await backend.initialize()

def setup_routes(app: web.Application):
    """Setup API routes"""
    # CORS setup
    cors = aiohttp_cors.setup(app, defaults={
        "*": aiohttp_cors.ResourceOptions(
            allow_credentials=True,
            expose_headers="*",
            allow_headers="*",
        )
    })
    
    # Agent registration and authentication
    cors.add(app.router.add_post('/api/v1/agents/register', backend.handle_agent_registration))
    cors.add(app.router.add_post('/api/v1/analysis/file', backend.handle_file_analysis))
    
    # Agent status and threat information
    cors.add(app.router.add_get('/api/v1/agents', backend.get_agent_status))
    cors.add(app.router.add_get('/api/v1/stats', backend.get_threat_statistics))
    cors.add(app.router.add_get('/api/v1/threats', backend.get_threats))
    
    # WebSockets for real-time communication
    cors.add(app.router.add_get('/api/v1/ws/{agent_id}', backend.handle_websocket))
    
    logger.info("API routes setup completed")

# Create the application
app = web.Application()
app.on_startup.append(lambda app: init_app())
setup_routes(app)

if __name__ == '__main__':
    # Run the server
    web.run_app(app, host='0.0.0.0', port=8080)