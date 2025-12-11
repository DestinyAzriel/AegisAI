#!/usr/bin/env python3
"""
AegisAI Refined Backend Manager
==============================

Centralized manager for all refined backend components with
orchestration, monitoring, and administration capabilities.
"""

import os
import json
import logging
import asyncio
import signal
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import subprocess

# Import refined components
try:
    from .refined_backend import RefinedTelemetryCollector
    TELEMETRY_AVAILABLE = True
except ImportError:
    RefinedTelemetryCollector = None
    TELEMETRY_AVAILABLE = False
    logging.warning("Refined telemetry collector not available")

try:
    from .refined_update_server import RefinedUpdateServer
    UPDATE_SERVER_AVAILABLE = True
except ImportError:
    RefinedUpdateServer = None
    UPDATE_SERVER_AVAILABLE = False
    logging.warning("Refined update server not available")

try:
    from .ml.refined_ml_service import RefinedMLService
    ML_SERVICE_AVAILABLE = True
except ImportError:
    RefinedMLService = None
    ML_SERVICE_AVAILABLE = False
    logging.warning("Refined ML service not available")

# Web framework for admin interface
try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except ImportError:
    web = None
    AIOHTTP_AVAILABLE = False
    logging.warning("aiohttp not available - admin interface disabled")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BackendManager:
    """Centralized manager for all refined backend components"""
    
    def __init__(self, config_path: str = "backend_config.json"):
        """
        Initialize the backend manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config = self._load_config(config_path)
        self.components = {}
        self.running = False
        self.shutdown_event = asyncio.Event()
        self._api_runner = None
        self._api_site = None
        
        # Initialize components based on configuration
        self._initialize_components()
        
        logger.info("Backend Manager initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file or use defaults."""
        default_config = {
            "api": {
                "host": "0.0.0.0",
                "port": 8080
            },
            "telemetry": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8081
            },
            "updates": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8082
            },
            "ml": {
                "enabled": True,
                "models_dir": "models"
            },
            "database": {
                "telemetry_db": "telemetry.db"
            },
            "security": {
                "api_keys": []
            }
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
    def _initialize_components(self):
        """Initialize backend components based on configuration."""
        # Initialize API backend (always enabled)
        try:
            from .api.refined_backend import AegisAICloudBackend
            self.components['api'] = AegisAICloudBackend()
            logger.info("API backend initialized")
        except Exception as e:
            logger.error(f"Failed to initialize API backend: {e}")
        
        # Initialize telemetry collector
        if self.config['telemetry']['enabled'] and TELEMETRY_AVAILABLE:
            try:
                telemetry_config = self.config['telemetry']
                self.components['telemetry'] = RefinedTelemetryCollector(
                    host=telemetry_config['host'],
                    port=telemetry_config['port'],
                    db_path=self.config['database']['telemetry_db']
                )
                logger.info("Telemetry collector initialized")
            except Exception as e:
                logger.error(f"Failed to initialize telemetry collector: {e}")
        
        # Initialize update server
        if self.config['updates']['enabled'] and UPDATE_SERVER_AVAILABLE:
            try:
                updates_config = self.config['updates']
                self.components['updates'] = RefinedUpdateServer(
                    host=updates_config['host'],
                    port=updates_config['port']
                )
                logger.info("Update server initialized")
            except Exception as e:
                logger.error(f"Failed to initialize update server: {e}")
        
        # Initialize ML service
        if self.config['ml']['enabled'] and ML_SERVICE_AVAILABLE:
            try:
                ml_config = self.config['ml']
                self.components['ml'] = RefinedMLService(
                    models_dir=ml_config['models_dir']
                )
                logger.info("ML service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize ML service: {e}")
    
    async def start(self):
        """Start all enabled backend components."""
        if self.running:
            logger.warning("Backend manager is already running")
            return
        
        logger.info("Starting backend components...")
        
        try:
            # Start API backend
            if 'api' in self.components:
                await self.components['api'].initialize()
                # Start the API web server
                if web is not None:
                    from .api.refined_backend import app as api_app
                    self._api_runner = web.AppRunner(api_app)
                    await self._api_runner.setup()
                    api_config = self.config.get('api', {'host': '0.0.0.0', 'port': 8080})
                    self._api_site = web.TCPSite(self._api_runner, api_config['host'], api_config['port'])
                    await self._api_site.start()
                    logger.info(f"API backend started on {api_config['host']}:{api_config['port']}")
            
            # Start telemetry collector
            if 'telemetry' in self.components:
                await self.components['telemetry'].start()
                logger.info("Telemetry collector started")
            
            # Start update server
            if 'updates' in self.components:
                await self.components['updates'].start()
                logger.info("Update server started")
            
            # ML service doesn't need explicit start
            
            self.running = True
            logger.info("All backend components started successfully")
            
            # Wait for shutdown signal
            await self.shutdown_event.wait()
            
        except Exception as e:
            logger.error(f"Error starting backend components: {e}")
            await self.stop()
    
    async def stop(self):
        """Stop all backend components."""
        if not self.running:
            logger.warning("Backend manager is not running")
            return
        
        logger.info("Stopping backend components...")
        
        try:
            # Stop API backend web server
            if self._api_site:
                await self._api_site.stop()
            if self._api_runner:
                await self._api_runner.cleanup()
            
            # Stop telemetry collector
            if 'telemetry' in self.components:
                await self.components['telemetry'].stop()
                logger.info("Telemetry collector stopped")
            
            # Stop update server
            if 'updates' in self.components:
                await self.components['updates'].stop()
                logger.info("Update server stopped")
            
            # API backend and ML service don't need explicit stop
            
            self.running = False
            logger.info("All backend components stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping backend components: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.shutdown_event.set()
    
    async def get_status(self) -> Dict[str, Any]:
        """
        Get status of all backend components.
        
        Returns:
            Dictionary with component status information
        """
        status = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'running': self.running,
            'components': {}
        }
        
        # API backend status
        if 'api' in self.components:
            status['components']['api'] = {
                'status': 'running' if self.running else 'initialized',
                'type': 'AegisAICloudBackend'
            }
        
        # Telemetry collector status
        if 'telemetry' in self.components:
            status['components']['telemetry'] = {
                'status': 'running' if self.running else 'initialized',
                'type': 'RefinedTelemetryCollector'
            }
        
        # Update server status
        if 'updates' in self.components:
            status['components']['updates'] = {
                'status': 'running' if self.running else 'initialized',
                'type': 'RefinedUpdateServer'
            }
        
        # ML service status
        if 'ml' in self.components:
            status['components']['ml'] = {
                'status': 'initialized',
                'type': 'RefinedMLService'
            }
        
        return status

class AdminInterface:
    """Web-based administration interface for the backend manager"""
    
    def __init__(self, manager: BackendManager, host: str = 'localhost', port: int = 8083):
        """
        Initialize admin interface.
        
        Args:
            manager: Backend manager instance
            host: Host to bind to
            port: Port to listen on
        """
        self.manager = manager
        self.host = host
        self.port = port
        self.app = None
        self.runner = None
        self.site = None
    
    async def start(self):
        """Start the admin interface."""
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available, cannot start admin interface")
            return
        
        try:
            # Create aiohttp application
            self.app = web.Application()
            
            # Set up routes
            self.app.router.add_get('/', self._handle_index)
            self.app.router.add_get('/api/status', self._handle_status)
            self.app.router.add_get('/api/components', self._handle_components)
            self.app.router.add_post('/api/shutdown', self._handle_shutdown)
            
            # Serve static files (if any)
            static_dir = os.path.join(os.path.dirname(__file__), 'admin', 'static')
            if os.path.exists(static_dir):
                self.app.router.add_static('/static/', static_dir)
            
            # Start server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            self.site = web.TCPSite(self.runner, self.host, self.port)
            await self.site.start()
            
            logger.info(f"Admin interface started on {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start admin interface: {e}")
    
    async def stop(self):
        """Stop the admin interface."""
        try:
            # Stop server
            if self.site:
                await self.site.stop()
            if self.runner:
                await self.runner.cleanup()
            
            logger.info("Admin interface stopped")
        except Exception as e:
            logger.error(f"Error stopping admin interface: {e}")
    
    async def _handle_index(self, request: web.Request) -> web.Response:
        """Handle index page request."""
        status = await self.manager.get_status()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AegisAI Backend Manager</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .status {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .component {{ margin: 10px 0; padding: 10px; border-left: 4px solid #007acc; }}
                .running {{ border-left-color: #4CAF50; }}
                .stopped {{ border-left-color: #f44336; }}
                button {{ background: #007acc; color: white; border: none; padding: 10px 20px; cursor: pointer; }}
                button:hover {{ background: #005a9e; }}
            </style>
        </head>
        <body>
            <h1>AegisAI Backend Manager</h1>
            <div class="status">
                <h2>System Status</h2>
                <p><strong>Timestamp:</strong> {status['timestamp']}</p>
                <p><strong>Status:</strong> {'Running' if status['running'] else 'Stopped'}</p>
            </div>
            
            <h2>Components</h2>
            {''.join([
                f'<div class="component {"running" if component["status"] == "running" else "stopped"}">' +
                f'<h3>{component_type}</h3>' +
                f'<p><strong>Type:</strong> {component["type"]}</p>' +
                f'<p><strong>Status:</strong> {component["status"]}</p>' +
                '</div>'
                for component_type, component in status['components'].items()
            ])}
            
            <button onclick="shutdownSystem()">Shutdown System</button>
            
            <script>
                function shutdownSystem() {{
                    if (confirm('Are you sure you want to shutdown the system?')) {{
                        fetch('/api/shutdown', {{ method: 'POST' }})
                            .then(response => response.json())
                            .then(data => {{
                                alert(data.message);
                                location.reload();
                            }})
                            .catch(error => {{
                                alert('Error: ' + error);
                            }});
                    }}
                }}
            </script>
        </body>
        </html>
        """
        
        return web.Response(text=html_content, content_type='text/html')
    
    async def _handle_status(self, request: web.Request) -> web.Response:
        """Handle status API request."""
        status = await self.manager.get_status()
        return web.json_response(status)
    
    async def _handle_components(self, request: web.Request) -> web.Response:
        """Handle components API request."""
        components = {}
        for name, component in self.manager.components.items():
            components[name] = {
                'type': type(component).__name__,
                'status': 'running' if self.manager.running else 'initialized'
            }
        return web.json_response(components)
    
    async def _handle_shutdown(self, request: web.Request) -> web.Response:
        """Handle shutdown API request."""
        if self.manager.running:
            # Trigger shutdown in background
            asyncio.create_task(self.manager.stop())
            return web.json_response({
                'status': 'success',
                'message': 'Shutdown initiated'
            })
        else:
            return web.json_response({
                'status': 'error',
                'message': 'System is not running'
            }, status=400)

async def main():
    """Main function to run the refined backend manager."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create backend manager
    manager = BackendManager()
    
    # Set up signal handlers for graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, manager.signal_handler, sig, None)
    
    # Create admin interface
    admin_interface = AdminInterface(manager, 'localhost', 8083)
    await admin_interface.start()
    
    # Start backend components
    try:
        await manager.start()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        # Stop admin interface
        await admin_interface.stop()
        
        # Ensure all components are stopped
        if manager.running:
            await manager.stop()
    
    logger.info("Backend manager shutdown complete")

def create_default_config():
    """Create a default configuration file."""
    default_config = {
        "api": {
            "host": "0.0.0.0",
            "port": 8080
        },
        "telemetry": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 8081
        },
        "updates": {
            "enabled": True,
            "host": "0.0.0.0",
            "port": 8082
        },
        "ml": {
            "enabled": True,
            "models_dir": "models"
        },
        "database": {
            "telemetry_db": "telemetry.db"
        },
        "security": {
            "api_keys": []
        }
    }
    
    config_path = "backend_config.json"
    with open(config_path, 'w') as f:
        json.dump(default_config, f, indent=2)
    
    logger.info(f"Created default configuration file: {config_path}")

if __name__ == "__main__":
    # Check if configuration file exists, create if not
    if not os.path.exists("backend_config.json"):
        create_default_config()
    
    # Run the main function
    asyncio.run(main())