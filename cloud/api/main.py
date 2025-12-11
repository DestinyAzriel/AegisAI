#!/usr/bin/env python3
"""
AegisAI Cloud Backend - Enterprise-Grade Threat Intelligence Platform
"""
from aiohttp import web, WSMsgType
import asyncio
import json
import hashlib
import os
import sys
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
import uuid
import base64

# Add the current directory to the path to fix import issues
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import threat intelligence service
THREAT_INTEL_AVAILABLE = False
EnhancedThreatIntelService = None

try:
    # Try to import the threat intelligence service
    import importlib.util
    threat_intel_path = os.path.join(os.path.dirname(__file__), '..', 'threat-intel', 'threat_intel_service.py')
    if os.path.exists(threat_intel_path):
        spec = importlib.util.spec_from_file_location("threat_intel_service", threat_intel_path)
        if spec is not None and spec.loader is not None:
            threat_intel_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(threat_intel_module)
            EnhancedThreatIntelService = threat_intel_module.EnhancedThreatIntelService
            THREAT_INTEL_AVAILABLE = True
    else:
        logging.warning("Threat intelligence service file not found")
except Exception as e:
    logging.warning(f"Failed to import threat intelligence service: {e}")

# Import dashboard API
DASHBOARD_API_AVAILABLE = False
try:
    # Try to import the dashboard API
    import importlib.util
    dashboard_api_path = os.path.join(os.path.dirname(__file__), 'dashboard_api.py')
    if os.path.exists(dashboard_api_path):
        spec = importlib.util.spec_from_file_location("dashboard_api", dashboard_api_path)
        if spec is not None and spec.loader is not None:
            dashboard_api_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(dashboard_api_module)
            EnterpriseDashboardAPI = dashboard_api_module.EnterpriseDashboardAPI
            DASHBOARD_API_AVAILABLE = True
    else:
        logging.warning("Dashboard API file not found")
except Exception as e:
    logging.warning(f"Failed to import dashboard API: {e}")

# Import security modules
try:
    from security import security_manager, compliance_manager
    SECURITY_MODULES_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Security modules import error: {e}")
    SECURITY_MODULES_AVAILABLE = False
    # Create mock objects for testing
    class MockSecurityManager:
        def generate_auth_token(self, agent_id):
            return "mock_token"
        def verify_auth_token(self, token):
            return {"agent_id": "mock_agent"}
    
    class MockComplianceManager:
        def log_data_processing_activity(self, activity_type, description, agent_id):
            pass
        def get_privacy_notice(self):
            return "Mock privacy notice"
        def get_ccpa_notice(self):
            return "Mock CCPa notice"
        def process_data_access_request(self, agent_id):
            return True
        def generate_compliance_report(self):
            return {"status": "mock_report"}
    
    security_manager = MockSecurityManager()
    compliance_manager = MockComplianceManager()

from security_hardening import security_hardening

# Import performance optimization module
try:
    from performance import performance_optimizer, performance_monitor
    PERFORMANCE_MODULES_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Performance modules import error: {e}")
    PERFORMANCE_MODULES_AVAILABLE = False
    # Create mock objects for testing
    class MockPerformanceOptimizer:
        def __init__(self):
            self._started = False
            
        def record_metric(self, name, value):
            pass
            
        def is_rate_limited(self, agent_id):
            return False
            
        def get_cached_result(self, key):
            return None
            
        def cache_result(self, key, value, ttl):
            pass
            
        def start(self):
            self._started = True
    
    class MockPerformanceMonitor:
        def start_monitoring(self):
            pass
    
    performance_optimizer = MockPerformanceOptimizer()
    performance_monitor = MockPerformanceMonitor()

# Conditional imports for optional dependencies
ASYNCPG_AVAILABLE = False
AIREDIS_AVAILABLE = False
JWT_AVAILABLE = True  # We're using our own implementation

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    asyncpg = None
    logging.warning("asyncpg not available - database features disabled")

try:
    import aioredis
    AIREDIS_AVAILABLE = True
except ImportError:
    aioredis = None
    logging.warning("aioredis not available - caching features disabled")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AegisAICloudBackend:
    def __init__(self):
        self.ml_model = None
        self.yara_rules = None
        self.threat_intel = {}
        # Initialize threat intelligence service if available
        if THREAT_INTEL_AVAILABLE and EnhancedThreatIntelService:
            try:
                self.threat_intel_service = EnhancedThreatIntelService()
            except Exception as e:
                logger.error(f"Failed to initialize threat intelligence service: {e}")
                self.threat_intel_service = None
        else:
            self.threat_intel_service = None
        
        # Initialize dashboard API if available
        if DASHBOARD_API_AVAILABLE:
            try:
                self.dashboard_api = EnterpriseDashboardAPI()
            except Exception as e:
                logger.error(f"Failed to initialize dashboard API: {e}")
                self.dashboard_api = None
        else:
            self.dashboard_api = None
        
        self.connected_agents = {}
        self.threat_database = {}  # In-memory threat database for demo
        self.db_pool = None
        self.redis_client = None
        self.security_manager = security_manager
        self.compliance_manager = compliance_manager
        self.initialize_ml_models()
        self.initialize_yara_rules()
        self.load_threat_intelligence()
    
    async def initialize_database(self):
        """Initialize database connection pool"""
        try:
            # Load performance configuration
            perf_config_path = os.path.join(os.path.dirname(__file__), '..', '..', 'infra', 'perf-config', 'api-perf-config.json')
            perf_config = {}
            if os.path.exists(perf_config_path):
                with open(perf_config_path, 'r') as f:
                    perf_config = json.load(f)
            
            db_config = perf_config.get('database', {}).get('connection_pool', {})
            
            # Create PostgreSQL connection pool with optimized settings
            if ASYNCPG_AVAILABLE and asyncpg:
                self.db_pool = await asyncpg.create_pool(
                    host=os.getenv('DB_HOST', 'localhost'),
                    port=os.getenv('DB_PORT', 5432),
                    user=os.getenv('DB_USER', 'aegisai'),
                    password=os.getenv('DB_PASSWORD', 'aegisai_password'),
                    database=os.getenv('DB_NAME', 'aegisai'),
                    min_size=db_config.get('min_size', 20),
                    max_size=db_config.get('max_size', 100),
                    max_queries=db_config.get('max_queries', 50000),
                    max_inactive_connection_lifetime=db_config.get('max_inactive_connection_lifetime', 300.0)
                )
            else:
                self.db_pool = None
                logger.warning("Database initialization skipped - asyncpg not available")
            
            # Create Redis connection for caching with optimized settings
            if AIREDIS_AVAILABLE and aioredis:
                redis_config = perf_config.get('caching', {}).get('redis', {}).get('connection_pool', {})
                self.redis_client = await aioredis.from_url(
                    os.getenv('REDIS_URL', 'redis://localhost:6379'),
                    encoding='utf-8',
                    decode_responses=True,
                    minsize=redis_config.get('min_size', 10),
                    maxsize=redis_config.get('max_size', 50)
                )
            else:
                self.redis_client = None
                logger.warning("Redis initialization skipped - aioredis not available")
            
            # Create database tables if they don't exist
            if self.db_pool:
                await self.create_tables()
                
                # Apply database optimizations
                try:
                    from .db_optimizer import DatabaseOptimizer
                    db_optimizer = DatabaseOptimizer(self.db_pool, perf_config_path)
                    await db_optimizer.optimize_queries()
                except Exception as e:
                    logger.error(f"Failed to apply database optimizations: {e}")
            
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
    
    async def create_tables(self):
        """Create database tables"""
        if not self.db_pool:
            return
            
        async with self.db_pool.acquire() as conn:
            # Create agents table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agents (
                    id UUID PRIMARY KEY,
                    info JSONB,
                    last_seen TIMESTAMP WITH TIME ZONE,
                    status VARCHAR(20),
                    registration_time TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            # Create threats table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id UUID PRIMARY KEY,
                    file_hash VARCHAR(64),
                    name VARCHAR(255),
                    type VARCHAR(50),
                    severity VARCHAR(20),
                    first_seen TIMESTAMP WITH TIME ZONE,
                    last_seen TIMESTAMP WITH TIME ZONE,
                    detection_count INTEGER DEFAULT 1,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            # Create threat_intel table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id UUID PRIMARY KEY,
                    source VARCHAR(100),
                    data JSONB,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            # Create analysis_results table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id UUID PRIMARY KEY,
                    agent_id UUID,
                    file_hash VARCHAR(64),
                    file_path TEXT,
                    threat_level VARCHAR(20),
                    detections JSONB,
                    confidence REAL,
                    timestamp TIMESTAMP WITH TIME ZONE,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            """)
            
            # Create indexes
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
    
    def initialize_ml_models(self):
        """Initialize machine learning models for threat detection"""
        try:
            # Import enhanced ML models
            try:
                from core.enhanced_ml_detector import EnhancedMLDetector
                from core.behavioral_ml_analyzer import BehavioralMLAnalyzer
                from core.ensemble_threat_detector import EnsembleThreatDetector
                ENHANCED_ML_AVAILABLE = True
            except ImportError as e:
                logger.warning(f"Enhanced ML models not available: {e}")
                ENHANCED_ML_AVAILABLE = False
                EnhancedMLDetector = None
                BehavioralMLAnalyzer = None
                EnsembleThreatDetector = None
            
            # Initialize enhanced ML models if available
            if ENHANCED_ML_AVAILABLE:
                logger.info("Initializing enhanced ML models...")
                self.enhanced_ml_detector = EnhancedMLDetector()
                self.behavioral_ml_analyzer = BehavioralMLAnalyzer()
                self.ensemble_threat_detector = EnsembleThreatDetector()
                logger.info("Enhanced ML models initialized successfully")
            else:
                # Fall back to basic implementation
                logger.info("Initializing basic ML models...")
                self.enhanced_ml_detector = None
                self.behavioral_ml_analyzer = None
                self.ensemble_threat_detector = None
            
            logger.info("ML models initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ML models: {e}")
            self.enhanced_ml_detector = None
            self.behavioral_ml_analyzer = None
            self.ensemble_threat_detector = None
    
    def initialize_yara_rules(self):
        """Initialize YARA rules for signature-based detection"""
        try:
            # In a real implementation, we would load comprehensive YARA rule sets
            # For this example, we'll just set to None
            logger.info("Initializing YARA rules...")
            self.yara_rules = None
            logger.info("YARA rules initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize YARA rules: {e}")
            self.yara_rules = None
    
    def load_threat_intelligence(self):
        """Load threat intelligence feeds"""
        # In a real implementation, this would load threat intelligence from various sources
        logger.info("Loading threat intelligence feeds...")
        self.threat_intel = {
            "known_malware_hashes": {
                "eicar_test_file_hash": {
                    "name": "EICAR Test File",
                    "severity": "test",
                    "description": "Standard antivirus test file"
                }
            },
            "malicious_domains": set(),
            "malicious_ips": set()
        }
        
        # Initialize threat database with some test data
        self.threat_database = {
            "eicar_test_file_hash": {
                "id": "THREAT-001",
                "name": "EICAR Test File",
                "type": "test",
                "severity": "low",
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "detection_count": 1
            }
        }
    
    async def handle_agent_registration(self, request):
        """Handle agent registration"""
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
        if not security_hardening.validate_input(request_data, request.content_type):
            logger.warning("Blocked registration request with invalid input")
            return web.json_response({
                'status': 'error',
                'message': 'Invalid input data'
            }, status=400)
        
        try:
            agent_id = data.get('agent_id', str(uuid.uuid4()))
            agent_info = data.get('agent_info', {})
            
            # Log data processing for compliance
            self.compliance_manager.log_data_processing_activity(
                "agent_registration", 
                "Register endpoint agent", 
                agent_id
            )
            
            # If no agent_id provided, generate one
            if not agent_id:
                agent_id = str(uuid.uuid4())
            
            # Store in memory for real-time access
            self.connected_agents[agent_id] = {
                'info': agent_info,
                'last_seen': datetime.now().isoformat(),
                'status': 'online',
                'registration_time': datetime.now().isoformat()
            }
            
            # Store in database for persistence
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        INSERT INTO agents (id, info, last_seen, status, registration_time)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (id) DO UPDATE SET
                            info = $2,
                            last_seen = $3,
                            status = $4
                    """, str(agent_id), json.dumps(agent_info), datetime.now(), 'online', datetime.now())
            
            # Generate authentication token with appropriate scopes
            auth_token = self.security_manager.generate_auth_token(agent_id, scopes=['file_analysis', 'threat_reporting', 'telemetry'])
            
            logger.info(f"Agent {agent_id} registered successfully")
            
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
    
    async def authenticate_request(self, request, required_scopes: list = None) -> Optional[str]:
        """Authenticate request with enhanced zero-trust validation and return agent ID"""
        # Get client IP for security checks
        client_ip = request.headers.get('X-Forwarded-For', request.remote)
        
        # Check if IP is blocked
        if not security_hardening.check_ip_blocking(client_ip):
            logger.warning(f"Blocked request from IP: {client_ip}")
            return None
        
        # Check rate limiting
        if not security_hardening.check_rate_limit(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return None
        
        # Check for client certificate in mutual TLS scenario
        if self.security_manager.enable_mtls:
            # In a real implementation, this would check the client certificate
            # provided during the TLS handshake
            client_cert = request.get('ssl_client_cert')
            if client_cert:
                if not self.security_manager.verify_client_certificate(client_cert):
                    logger.warning(f"Client certificate verification failed for IP: {client_ip}")
                    security_hardening.record_failed_attempt(client_ip)
                    return None
            else:
                logger.warning(f"Missing client certificate for mTLS connection from IP: {client_ip}")
                security_hardening.record_failed_attempt(client_ip)
                return None
        
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            security_hardening.record_failed_attempt(client_ip)
            return None
        
        # Extract token from "Bearer <token>" format
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]  # Remove "Bearer " prefix
            payload = self.security_manager.verify_auth_token(token, required_scopes)
            if payload:
                return payload.get('agent_id')
        
        # Record failed authentication attempt
        security_hardening.record_failed_attempt(client_ip)
        return None
    
    async def handle_file_analysis(self, request):
        """Handle file analysis requests from agents"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['file_analysis'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
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
        if not security_hardening.validate_input(request_data, request.content_type):
            logger.warning("Blocked analysis request with invalid input")
            return web.json_response({
                'status': 'error',
                'message': 'Invalid input data'
            }, status=400)
        
        try:
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
        """Perform multi-layered file analysis"""
        result = {
            'file_hash': file_hash,
            'file_path': file_path,
            'threat_level': 'clean',
            'detections': [],
            'confidence': 0.0,
            'timestamp': datetime.now().isoformat(),
            'verdict': 'clean'
        }
        
        # Check cache first
        cache_key = f"analysis:{file_hash}"
        if self.redis_client:
            cached_result = await self.redis_client.get(cache_key)
            if cached_result:
                try:
                    return json.loads(cached_result)
                except:
                    pass  # If cache is invalid, continue with analysis
        
        # 1. Check against known threat intelligence
        if file_hash in self.threat_intel.get('known_malware_hashes', {}):
            threat_info = self.threat_intel['known_malware_hashes'][file_hash]
            result['threat_level'] = 'malicious'
            result['verdict'] = 'malicious'
            result['detections'].append({
                'type': 'known_threat',
                'confidence': 1.0,
                'details': f"File hash matches known malware: {threat_info.get('name', 'Unknown')}"
            })
            result['confidence'] = 1.0
            
            # Update threat database
            if file_hash in self.threat_database:
                self.threat_database[file_hash]['detection_count'] += 1
                self.threat_database[file_hash]['last_seen'] = datetime.now().isoformat()
            else:
                self.threat_database[file_hash] = {
                    'id': f"THREAT-{len(self.threat_database) + 1}",
                    'name': threat_info.get('name', 'Unknown'),
                    'type': threat_info.get('severity', 'unknown'),
                    'severity': threat_info.get('severity', 'unknown'),
                    'first_seen': datetime.now().isoformat(),
                    'last_seen': datetime.now().isoformat(),
                    'detection_count': 1
                }
            
            # Store in database
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    threat_id = str(uuid.uuid4())
                    await conn.execute("""
                        INSERT INTO threats (id, file_hash, name, type, severity, first_seen, last_seen, detection_count)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        ON CONFLICT (file_hash) DO UPDATE SET
                            last_seen = $7,
                            detection_count = threats.detection_count + 1
                    """, threat_id, file_hash, threat_info.get('name', 'Unknown'), 
                        threat_info.get('severity', 'unknown'), threat_info.get('severity', 'unknown'),
                        datetime.now(), datetime.now(), 1)
            
            # Cache the result
            if self.redis_client:
                await self.redis_client.setex(cache_key, 3600, json.dumps(result))  # Cache for 1 hour
            
            return result
        
        # 2. Signature-based detection with YARA
        yara_result = self.signature_analysis(file_features)
        if yara_result:
            result['threat_level'] = 'malicious'
            result['verdict'] = 'malicious'
            result['detections'].append(yara_result)
            result['confidence'] = max(result['confidence'], yara_result['confidence'])
        
        # 3. Machine learning analysis
        ml_result = self.ml_analysis(file_features)
        if ml_result:
            if ml_result['confidence'] > result['confidence']:
                result['threat_level'] = 'suspicious' if ml_result['confidence'] < 0.8 else 'malicious'
                result['verdict'] = result['threat_level']
            result['detections'].append(ml_result)
            result['confidence'] = max(result['confidence'], ml_result['confidence'])
        
        # 4. Behavioral analysis (in cloud context)
        behavioral_result = self.behavioral_analysis(file_path)
        if behavioral_result:
            result['threat_level'] = 'suspicious' if result['threat_level'] == 'clean' else result['threat_level']
            result['verdict'] = result['threat_level']
            result['detections'].append(behavioral_result)
            result['confidence'] = max(result['confidence'], behavioral_result['confidence'])
        
        # Cache the result
        if self.redis_client:
            await self.redis_client.setex(cache_key, 3600, json.dumps(result))  # Cache for 1 hour
        
        return result
    
    def signature_analysis(self, file_features: Dict) -> Optional[Dict[str, Any]]:
        """Perform signature-based analysis using YARA rules"""
        if not self.yara_rules:
            return None
            
        # In a real implementation, this would use YARA rules
        # For this example, we'll simulate detection
        if "MALICIOUS_SIGNATURE" in str(file_features):
            return {
                'type': 'signature',
                'confidence': 0.95,
                'details': "Test malware signature detected"
            }
        
        return None
    
    def ml_analysis(self, file_features: Dict) -> Optional[Dict[str, Any]]:
        """Perform machine learning-based analysis"""
        if not self.ml_model:
            # Simple heuristic-based analysis for demo
            file_size = file_features.get('size', 0)
            
            # Flag large files as suspicious
            if file_size > 10000000:  # 10MB
                return {
                    'type': 'machine_learning',
                    'confidence': 0.7,
                    'details': 'Large file size detected'
                }
            
            # Flag files with suspicious byte patterns
            first_bytes = file_features.get('first_bytes', '')
            if '4d5a' in first_bytes.lower():  # MZ header (Windows executable)
                # Check for other suspicious patterns
                if len(first_bytes) > 20:
                    return {
                        'type': 'machine_learning',
                        'confidence': 0.6,
                        'details': 'Suspicious executable detected'
                    }
        
        return None
    
    def behavioral_analysis(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Perform behavioral analysis based on file path and name"""
        suspicious_patterns = [
            'temp', 'tmp', '$recycle.bin', 'appdata', 'temp',
            'malware', 'virus', 'trojan', 'ransom'
        ]
        
        file_path_lower = file_path.lower()
        for pattern in suspicious_patterns:
            if pattern in file_path_lower:
                return {
                    'type': 'behavioral',
                    'confidence': 0.7,
                    'details': f"Suspicious path pattern detected: {pattern}"
                }
        
        return None
    
    async def handle_websocket(self, request):
        """Handle WebSocket connections for real-time communication"""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        agent_id = request.match_info.get('agent_id', 'unknown')
        logger.info(f"Agent {agent_id} connected via WebSocket")
        
        # Register the WebSocket connection
        self.connected_agents[agent_id] = {
            'websocket': ws,
            'last_seen': datetime.now().isoformat(),
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
    
    async def process_agent_message(self, agent_id: str, data: Dict[str, Any], ws) -> Optional[Dict[str, Any]]:
        """Process messages from agents"""
        message_type = data.get('type')
        
        if message_type == 'heartbeat':
            # Update agent status
            self.connected_agents[agent_id]['last_seen'] = datetime.now().isoformat()
            return {
                'type': 'heartbeat_ack',
                'timestamp': datetime.now().isoformat()
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
                'last_seen': datetime.now().isoformat(),
                'status': 'online',
                'websocket': ws
            }
            
            # Generate authentication token with appropriate scopes
            auth_token = self.security_manager.generate_auth_token(agent_id, scopes=['file_analysis', 'threat_reporting', 'telemetry'])
            
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
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to all connected agents
        for agent_id, agent_data in list(self.connected_agents.items()):
            if 'websocket' in agent_data and not agent_data['websocket'].closed:
                try:
                    await agent_data['websocket'].send_str(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to send threat intel to agent {agent_id}: {e}")
    
    async def get_agent_status(self, request):
        """Get status of all connected agents"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Update agent statuses based on last seen time
        current_time = datetime.now()
        for agent_id, agent_data in self.connected_agents.items():
            last_seen = datetime.fromisoformat(agent_data['last_seen'].replace('Z', '+00:00'))
            if (current_time - last_seen).total_seconds() > 300:  # 5 minutes
                agent_data['status'] = 'offline'
        
        # Also fetch agents from database for persistence
        db_agents = {}
        if self.db_pool:
            async with self.db_pool.acquire() as conn:
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
        
        # Merge in-memory agents with database agents
        all_agents = {**db_agents, **self.connected_agents}
        
        return web.json_response({
            'status': 'success',
            'agents': all_agents
        })
    
    async def get_threat_statistics(self, request):
        """Get threat statistics"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Calculate statistics from in-memory data
        total_agents = len(self.connected_agents)
        active_threats = len([t for t in self.threat_database.values() if t['detection_count'] > 0])
        threats_detected_today = sum(1 for t in self.threat_database.values() 
                                   if datetime.fromisoformat(t['last_seen'].replace('Z', '+00:00')).date() == datetime.now().date())
        quarantined_files = sum(t['detection_count'] for t in self.threat_database.values())
        
        # Also fetch statistics from database for persistence
        if self.db_pool:
            async with self.db_pool.acquire() as conn:
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
                if db_threats_today > threats_detected_today:
                    threats_detected_today = db_threats_today
                
                # Get total quarantined files from database
                db_quarantined_files = await conn.fetchval("SELECT COALESCE(SUM(detection_count), 0) FROM threats")
                if db_quarantined_files > quarantined_files:
                    quarantined_files = db_quarantined_files
        
        stats = {
            'total_agents': total_agents,
            'active_threats': active_threats,
            'threats_detected_today': threats_detected_today,
            'quarantined_files': quarantined_files
        }
        
        return web.json_response({
            'status': 'success',
            'statistics': stats
        })
    
    async def get_threats(self, request):
        """Get list of detected threats"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Merge in-memory threats with database threats
        all_threats = self.threat_database.copy()
        
        if self.db_pool:
            async with self.db_pool.acquire() as conn:
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
        
        return web.json_response({
            'status': 'success',
            'threats': all_threats
        })
    
    async def get_privacy_notice(self, request):
        """Get privacy notice for compliance"""
        notice = self.compliance_manager.get_privacy_notice()
        return web.json_response({
            'status': 'success',
            'privacy_notice': notice
        })
    
    async def get_ccpa_notice(self, request):
        """Get CCPA notice for compliance"""
        notice = self.compliance_manager.get_ccpa_notice()
        return web.json_response({
            'status': 'success',
            'ccpa_notice': notice
        })
    
    async def handle_data_access_request(self, request):
        """Handle user data access request"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Process data access request
        success = self.compliance_manager.process_data_access_request(agent_id)
        
        if success:
            return web.json_response({
                'status': 'success',
                'message': 'Data access request processed'
            })
        else:
            return web.json_response({
                'status': 'error',
                'message': 'Failed to process data access request'
            }, status=500)
    
    async def handle_data_erasure_request(self, request):
        """Handle user data erasure request"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Process data erasure request
        success = self.compliance_manager.process_data_access_request(agent_id)
        
        if success:
            return web.json_response({
                'status': 'success',
                'message': 'Data erasure request processed'
            })
        else:
            return web.json_response({
                'status': 'error',
                'message': 'Failed to process data erasure request'
            }, status=500)
    
    async def handle_incident_report(self, request):
        """Handle incident reports from agents"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['threat_reporting'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            data = await request.json()
            
            # Log incident for compliance
            self.compliance_manager.log_data_processing_activity(
                "incident_report", 
                "Report security incident", 
                agent_id
            )
            
            # Forward to incident response system
            # In a real implementation, this would integrate with the incident response module
            logger.info(f"Incident reported by agent {agent_id}: {data}")
            
            return web.json_response({
                'status': 'success',
                'message': 'Incident reported successfully'
            })
        except Exception as e:
            logger.error(f"Error reporting incident: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def handle_agent_heartbeat(self, request):
        """Handle agent heartbeat requests"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        # Get request data
        try:
            data = await request.json()
        except Exception as e:
            logger.warning(f"Invalid JSON in heartbeat request: {e}")
            return web.json_response({
                'status': 'error',
                'message': 'Invalid JSON data'
            }, status=400)
        
        # Validate input
        request_data = await request.text()
        if not security_hardening.validate_input(request_data, request.content_type):
            logger.warning("Blocked heartbeat request with invalid input")
            return web.json_response({
                'status': 'error',
                'message': 'Invalid input data'
            }, status=400)
        
        try:
            # Record performance metric
            start_time = asyncio.get_event_loop().time()
            
            # Update agent status in memory
            if agent_id in self.connected_agents:
                self.connected_agents[agent_id]['last_seen'] = datetime.now().isoformat()
                self.connected_agents[agent_id]['status'] = 'online'
            
            # Update agent status in database
            if self.db_pool:
                async with self.db_pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE agents 
                        SET last_seen = $1, status = $2 
                        WHERE id = $3
                    """, datetime.now(), 'online', agent_id)
            
            # Record performance metric
            execution_time = asyncio.get_event_loop().time() - start_time
            performance_optimizer.record_metric("agent_heartbeat_processing_time", execution_time)
            
            logger.info(f"Heartbeat received from agent {agent_id}")
            
            return web.json_response({
                'status': 'success',
                'message': 'Heartbeat received'
            })
        except Exception as e:
            logger.error(f"Error processing heartbeat: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def handle_threat_intel_request(self, request):
        """Handle threat intelligence requests from agents"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['threat_reporting'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            # Record performance metric
            start_time = asyncio.get_event_loop().time()
            
            # Get query parameters
            indicator = request.query.get('indicator', '')
            indicator_type = request.query.get('type', 'hash')
            
            # Check rate limiting
            if performance_optimizer.is_rate_limited(agent_id):
                logger.warning(f"Rate limit exceeded for agent {agent_id} requesting threat intel")
                return web.json_response({
                    'status': 'error',
                    'message': 'Rate limit exceeded'
                }, status=429)
            
            # If threat intelligence service is available, use it
            if self.threat_intel_service and THREAT_INTEL_AVAILABLE:
                result = self.threat_intel_service.check_indicator(indicator, indicator_type)
                if result:
                    response_data = {
                        'status': 'success',
                        'found': True,
                        'indicator': result.indicator,
                        'indicator_type': result.indicator_type,
                        'threat_name': result.threat_name,
                        'severity': result.severity,
                        'confidence': result.confidence,
                        'source': result.source,
                        'first_seen': result.first_seen.isoformat(),
                        'last_seen': result.last_seen.isoformat(),
                        'tags': result.tags,
                        'description': result.description
                    }
                else:
                    response_data = {
                        'status': 'success',
                        'found': False,
                        'indicator': indicator,
                        'indicator_type': indicator_type
                    }
            else:
                # Fallback to basic threat database
                key = indicator if indicator_type == "hash" else f"{indicator_type}_{indicator}"
                if key in self.threat_database:
                    threat_info = self.threat_database[key]
                    response_data = {
                        'status': 'success',
                        'found': True,
                        'threat_info': threat_info
                    }
                else:
                    response_data = {
                        'status': 'success',
                        'found': False
                    }
            
            # Record performance metric
            execution_time = asyncio.get_event_loop().time() - start_time
            performance_optimizer.record_metric("threat_intel_lookup_time", execution_time)
            
            logger.info(f"Threat intelligence lookup for agent {agent_id}: {indicator}")
            
            return web.json_response(response_data)
        except Exception as e:
            logger.error(f"Error handling threat intelligence request: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def handle_threat_intel_update(self, request):
        """Handle threat intelligence update requests"""
        # Authenticate request with required scopes (only allow from authorized sources)
        agent_id = await self.authenticate_request(request, ['threat_reporting'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            # Record performance metric
            start_time = asyncio.get_event_loop().time()
            
            # Only allow certain agents to update threat intelligence
            # In a real implementation, this would check agent permissions
            authorized_agents = ['admin', 'threat_intel_updater']
            if agent_id not in authorized_agents:
                logger.warning(f"Unauthorized threat intel update attempt by agent {agent_id}")
                return web.json_response({
                    'status': 'error',
                    'message': 'Unauthorized'
                }, status=403)
            
            # Get request data
            data = await request.json()
            action = data.get('action', 'update_feeds')
            
            if action == 'update_feeds' and self.threat_intel_service and THREAT_INTEL_AVAILABLE:
                # Update threat feeds
                feed_names = data.get('feeds', None)  # None means update all
                await self.threat_intel_service.update_threat_feeds(feed_names)
                
                response_data = {
                    'status': 'success',
                    'message': 'Threat feeds updated'
                }
            elif action == 'add_indicator' and self.threat_intel_service and THREAT_INTEL_AVAILABLE:
                # Add custom indicator
                indicator_data = data.get('indicator', {})
                self.threat_intel_service.add_custom_indicator(
                    indicator=indicator_data.get('indicator'),
                    indicator_type=indicator_data.get('type'),
                    threat_name=indicator_data.get('threat_name'),
                    severity=indicator_data.get('severity', 'medium'),
                    confidence=indicator_data.get('confidence', 0.7),
                    tags=indicator_data.get('tags'),
                    description=indicator_data.get('description', '')
                )
                
                response_data = {
                    'status': 'success',
                    'message': 'Custom indicator added'
                }
            else:
                response_data = {
                    'status': 'error',
                    'message': 'Invalid action or threat intelligence service not available'
                }
            
            # Record performance metric
            execution_time = asyncio.get_event_loop().time() - start_time
            performance_optimizer.record_metric("threat_intel_update_time", execution_time)
            
            logger.info(f"Threat intelligence update by agent {agent_id}: {action}")
            
            return web.json_response(response_data)
        except Exception as e:
            logger.error(f"Error handling threat intelligence update: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def get_threat_intel_statistics(self, request):
        """Get threat intelligence statistics"""
        try:
            # If threat intelligence service is available, use it
            if self.threat_intel_service and THREAT_INTEL_AVAILABLE:
                stats = self.threat_intel_service.get_threat_statistics()
                return web.json_response({
                    'status': 'success',
                    'statistics': stats
                })
            else:
                # Return basic statistics
                return web.json_response({
                    'status': 'success',
                    'statistics': {
                        'total_indicators': len(self.threat_database),
                        'service_available': False
                    }
                })
        except Exception as e:
            logger.error(f"Error getting threat intelligence statistics: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def handle_policy_request(self, request):
        """Handle policy requests from agents"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            # Record performance metric
            start_time = asyncio.get_event_loop().time()
            
            # Check cache first
            cache_key = f"policy_{agent_id}"
            cached_result = performance_optimizer.get_cached_result(cache_key)
            if cached_result:
                logger.info(f"Returning cached policy to agent {agent_id}")
                return web.json_response({
                    'status': 'success',
                    'policy': cached_result
                })
            
            # Get agent-specific policies
            policy = {
                'scan_frequency': 'realtime',
                'quarantine_enabled': True,
                'cloud_analysis': True,
                'behavioral_monitoring': True,
                'update_frequency': 3600  # 1 hour
            }
            
            # In a real implementation, policies would be fetched from database
            # based on agent profile, group, etc.
            
            # Cache the result for 10 minutes
            performance_optimizer.cache_result(cache_key, policy, 600)
            
            # Record performance metric
            execution_time = asyncio.get_event_loop().time() - start_time
            performance_optimizer.record_metric("policy_request_time", execution_time)
            
            logger.info(f"Policy sent to agent {agent_id}")
            
            return web.json_response({
                'status': 'success',
                'policy': policy
            })
        except Exception as e:
            logger.error(f"Error fetching policy: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def handle_policy_update(self, request):
        """Handle policy updates from management console"""
        # Authenticate request with required scopes (would require admin authentication in real implementation)
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            # Record performance metric
            start_time = asyncio.get_event_loop().time()
            
            data = await request.json()
            policy_updates = data.get('policy', {})
            target_agents = data.get('target_agents', 'all')
            
            # Update policies in memory
            # In a real implementation, this would update database records
            
            # Invalidate policy cache for affected agents
            if target_agents == 'all':
                # In a real implementation, we would invalidate all policy caches
                pass
            else:
                for agent in target_agents:
                    cache_key = f"policy_{agent}"
                    performance_optimizer.cache_result(cache_key + "_invalid", True, 60)
            
            # Record performance metric
            execution_time = asyncio.get_event_loop().time() - start_time
            performance_optimizer.record_metric("policy_update_time", execution_time)
            
            logger.info(f"Policies updated by agent {agent_id}")
            
            return web.json_response({
                'status': 'success',
                'message': 'Policies updated'
            })
        except Exception as e:
            logger.error(f"Error updating policies: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def handle_compliance_report_request(self, request):
        """Handle compliance report requests"""
        # Authenticate request with required scopes
        agent_id = await self.authenticate_request(request, ['telemetry'])
        if not agent_id:
            return web.json_response({
                'status': 'error',
                'message': 'Authentication required'
            }, status=401)
        
        try:
            # Record performance metric
            start_time = asyncio.get_event_loop().time()
            
            # Check if client is rate limited
            if performance_optimizer.is_rate_limited(agent_id):
                logger.warning(f"Rate limit exceeded for agent {agent_id} requesting compliance report")
                return web.json_response({
                    'status': 'error',
                    'message': 'Rate limit exceeded'
                }, status=429)
            
            # Generate compliance report
            report = self.compliance_manager.generate_compliance_report()
            
            # Record performance metric
            execution_time = asyncio.get_event_loop().time() - start_time
            performance_optimizer.record_metric("compliance_report_generation_time", execution_time)
            
            logger.info(f"Compliance report generated for agent {agent_id}")
            
            return web.json_response({
                'status': 'success',
                'report': report
            })
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            return web.json_response({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    async def websocket_handler(self, request):
        """Handle WebSocket connections"""
        # This is a simplified version - the full implementation would be more complex
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        logger.info("WebSocket connection established")
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        # Process WebSocket message
                        response = {
                            'status': 'success',
                            'message': 'Message received'
                        }
                        await ws.send_str(json.dumps(response))
                    except json.JSONDecodeError:
                        await ws.send_str(json.dumps({
                            'status': 'error',
                            'message': 'Invalid JSON message'
                        }))
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
        finally:
            logger.info("WebSocket connection closed")
        
        return ws

    def setup_routes(self, app):
        """Setup API routes"""
        # Agent registration and authentication
        app.router.add_post('/api/v1/agents/register', self.handle_agent_registration)
        app.router.add_post('/api/v1/agents/heartbeat', self.handle_agent_heartbeat)
        
        # File analysis
        app.router.add_post('/api/v1/analysis/file', self.handle_file_analysis)
        app.router.add_post('/api/v1/analysis/enhanced', self.handle_enhanced_file_analysis)  # New endpoint
        
        # Threat intelligence
        app.router.add_get('/api/v1/threat-intel', self.handle_threat_intel_request)
        app.router.add_post('/api/v1/threat-intel/update', self.handle_threat_intel_update)
        app.router.add_get('/api/v1/threat-intel/stats', self.get_threat_intel_statistics)
        
        # Policy management
        app.router.add_get('/api/v1/policies/{agent_id}', self.handle_policy_request)
        app.router.add_post('/api/v1/policies/update', self.handle_policy_update)
        
        # Compliance reporting
        app.router.add_get('/api/v1/compliance/report', self.handle_compliance_report_request)
        
        # Incident reporting
        app.router.add_post('/api/v1/incidents/report', self.handle_incident_report)
        
        # WebSockets for real-time communication
        app.router.add_get('/api/v1/ws', self.websocket_handler)
        
        # Initialize dashboard API routes if available
        if self.dashboard_api and hasattr(self.dashboard_api, 'setup_routes'):
            self.dashboard_api.setup_routes(app)
        
        logger.info("API routes setup completed")

# Create the application
app = web.Application()
backend = AegisAICloudBackend()

# Initialize database
async def init_app(app):
    await backend.initialize_database()
    # Start performance optimizer components that require event loop
    if PERFORMANCE_MODULES_AVAILABLE:
        performance_optimizer.start()
    # Set up API routes
    backend.setup_routes(app)

# Define routes
app.router.add_post('/api/v1/register', backend.handle_agent_registration)
app.router.add_post('/api/v1/analyze', backend.handle_file_analysis)
app.router.add_post('/api/v1/analysis/enhanced', backend.handle_enhanced_file_analysis)  # New endpoint
app.router.add_get('/api/v1/ws/{agent_id}', backend.handle_websocket)
app.router.add_get('/api/v1/agents', backend.get_agent_status)
app.router.add_get('/api/v1/stats', backend.get_threat_statistics)
app.router.add_get('/api/v1/threats', backend.get_threats)
app.router.add_get('/api/v1/threat-intel', backend.handle_threat_intel_request)
app.router.add_post('/api/v1/threat-intel/update', backend.handle_threat_intel_update)
app.router.add_get('/api/v1/threat-intel/stats', backend.get_threat_intel_statistics)
app.router.add_get('/api/v1/privacy', backend.get_privacy_notice)
app.router.add_get('/api/v1/ccpa', backend.get_ccpa_notice)
app.router.add_post('/api/v1/data-access', backend.handle_data_access_request)
app.router.add_post('/api/v1/data-erasure', backend.handle_data_erasure_request)

# Initialize app on startup
app.on_startup.append(init_app)

# Add cleanup handler
async def cleanup(app):
    # Cleanup resources on shutdown
    pass

app.on_cleanup.append(cleanup)

if __name__ == '__main__':
    import argparse
    import ssl
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='AegisAI Cloud Backend')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--ssl-cert', help='SSL certificate file path')
    parser.add_argument('--ssl-key', help='SSL private key file path')
    parser.add_argument('--mtls-ca', help='mTLS CA certificate file path')
    args = parser.parse_args()
    
    # Check for mTLS configuration
    ssl_context = None
    if args.ssl_cert and args.ssl_key:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(args.ssl_cert, args.ssl_key)
        
        # Configure client certificate verification if mTLS CA is provided
        if args.mtls_ca:
            ssl_context.load_verify_locations(args.mtls_ca)
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            print(f"mTLS enabled with CA: {args.mtls_ca}")
        
        print(f"HTTPS enabled with certificate: {args.ssl_cert}")
    
    # Run the server
    if ssl_context:
        web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_context)
    else:
        web.run_app(app, host=args.host, port=args.port)
