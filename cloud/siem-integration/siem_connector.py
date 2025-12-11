#!/usr/bin/env python3
"""
AegisAI SIEM Integration Module

This module provides integration with Security Information and Event Management (SIEM) systems
for enterprise environments. It supports multiple SIEM platforms including Splunk, ELK, QRadar,
and custom solutions through standardized APIs.
"""

import json
import logging
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SIEMType(Enum):
    """Supported SIEM types"""
    SPLUNK = "splunk"
    ELK = "elk"  # Elasticsearch, Logstash, Kibana
    QRADAR = "qradar"
    CUSTOM = "custom"

class SIEMEvent:
    """Represents a security event to be sent to SIEM"""
    
    def __init__(self, event_type: str, severity: str, source: str, 
                 timestamp: Optional[str] = None, **kwargs):
        """
        Initialize SIEM event
        
        Args:
            event_type: Type of security event
            severity: Event severity (low, medium, high, critical)
            source: Source of the event (agent ID, system, etc.)
            timestamp: Event timestamp (ISO format)
            **kwargs: Additional event data
        """
        self.event_type = event_type
        self.severity = severity
        self.source = source
        self.timestamp = timestamp or datetime.now().isoformat()
        self.data = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary format"""
        return {
            'event_type': self.event_type,
            'severity': self.severity,
            'source': self.source,
            'timestamp': self.timestamp,
            'data': self.data
        }

class XDRThreatCorrelation:
    """Represents an XDR threat correlation event for SIEM integration"""
    
    def __init__(self, correlation_id: str, threat_score: float, threat_category: str,
                 correlated_events: List[Dict], client_id: str, 
                 timestamp: Optional[str] = None):
        """
        Initialize XDR threat correlation event
        
        Args:
            correlation_id: Unique identifier for the correlation
            threat_score: Risk score (0.0 - 1.0)
            threat_category: Category of threat (e.g., 'malware', 'intrusion', 'data_exfiltration')
            correlated_events: List of events that contributed to this correlation
            client_id: Client/agent identifier
            timestamp: Event timestamp (ISO format)
        """
        self.correlation_id = correlation_id
        self.threat_score = threat_score
        self.threat_category = threat_category
        self.correlated_events = correlated_events
        self.client_id = client_id
        self.timestamp = timestamp or datetime.now().isoformat()
    
    def to_siem_event(self) -> 'SIEMEvent':
        """Convert to SIEM event for sending to SIEM systems"""
        severity = 'low'
        if self.threat_score >= 0.8:
            severity = 'critical'
        elif self.threat_score >= 0.6:
            severity = 'high'
        elif self.threat_score >= 0.4:
            severity = 'medium'
        
        return SIEMEvent(
            event_type='xdr_threat_correlation',
            severity=severity,
            source=self.client_id,
            timestamp=self.timestamp,
            correlation_id=self.correlation_id,
            threat_score=self.threat_score,
            threat_category=self.threat_category,
            correlated_events_count=len(self.correlated_events),
            correlated_event_types=[event.get('event_type', 'unknown') for event in self.correlated_events[:5]]
        )

class AutomatedResponseAction:
    """Represents an automated response action to be executed based on SIEM events"""
    
    def __init__(self, action_type: str, target: str, parameters: Dict[str, Any],
                 condition: str, severity_threshold: str = 'high'):
        """
        Initialize automated response action
        
        Args:
            action_type: Type of action (e.g., 'isolate_endpoint', 'block_ip', 'quarantine_file')
            target: Target of the action (e.g., endpoint ID, IP address, file path)
            parameters: Additional parameters for the action
            condition: Condition that triggers this action
            severity_threshold: Minimum severity to trigger this action
        """
        self.action_type = action_type
        self.target = target
        self.parameters = parameters
        self.condition = condition
        self.severity_threshold = severity_threshold
        self.enabled = True
    
    async def execute(self, siem_connector: 'SIEMConnector') -> bool:
        """
        Execute the automated response action
        
        Args:
            siem_connector: SIEM connector instance
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Log the action
            logger.info(f"Executing automated response action: {self.action_type} on {self.target}")
            
            # In a real implementation, this would:
            # 1. Connect to the appropriate system (endpoint, network device, etc.)
            # 2. Execute the action
            # 3. Report results back to SIEM
            
            # For now, we'll simulate the execution
            action_result = {
                'action_type': self.action_type,
                'target': self.target,
                'status': 'executed',
                'timestamp': datetime.now().isoformat(),
                'parameters': self.parameters
            }
            
            # Send action result to SIEM
            result_event = SIEMEvent(
                event_type='automated_response_result',
                severity='info',
                source='siem_connector',
                action_type=self.action_type,
                target=self.target,
                status='executed',
                parameters=self.parameters
            )
            
            await siem_connector.send_event(result_event)
            
            return True
        except Exception as e:
            logger.error(f"Failed to execute automated response action: {e}")
            return False

class SIEMConnector:
    """SIEM integration connector for enterprise environments"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SIEM connector
        
        Args:
            config: SIEM configuration including type, URL, credentials, etc.
        """
        self.config = config
        self.siem_type = SIEMType(config.get('type', 'custom'))
        self.enabled = config.get('enabled', False)
        self.siem_url = config.get('url', '')
        self.api_key = config.get('api_key', '')
        self.auth_token = config.get('auth_token', '')
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.index = config.get('index', 'aegisai')
        self.session = None
        self.automated_actions = []  # List of automated response actions
        self.xdr_enabled = config.get('xdr_enabled', True)  # Enable XDR features
        
        logger.info(f"SIEM connector initialized for {self.siem_type.value}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
    
    async def connect(self):
        """Establish connection to SIEM system"""
        if not self.enabled:
            logger.info("SIEM integration is disabled")
            return
        
        # Initialize HTTP session
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        logger.info(f"Connected to SIEM at {self.siem_url}")
    
    async def disconnect(self):
        """Close connection to SIEM system"""
        if self.session:
            await self.session.close()
            self.session = None
            logger.info("Disconnected from SIEM")
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """
        Send security event to SIEM
        
        Args:
            event: Security event to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled or not self.session:
            return False
        
        try:
            # Format event for specific SIEM type
            formatted_event = self._format_event_for_siem(event)
            
            # Send event based on SIEM type
            if self.siem_type == SIEMType.SPLUNK:
                success = await self._send_to_splunk(formatted_event)
            elif self.siem_type == SIEMType.ELK:
                success = await self._send_to_elk(formatted_event)
            elif self.siem_type == SIEMType.QRADAR:
                success = await self._send_to_qradar(formatted_event)
            else:
                success = await self._send_to_custom(formatted_event)
            
            if success:
                logger.info(f"Successfully sent {event.event_type} event to SIEM")
            else:
                logger.error(f"Failed to send {event.event_type} event to SIEM")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending event to SIEM: {e}")
            return False
    
    def _format_event_for_siem(self, event: SIEMEvent) -> Dict[str, Any]:
        """
        Format event for specific SIEM type
        
        Args:
            event: Security event
            
        Returns:
            Dict: Formatted event data
        """
        event_dict = event.to_dict()
        
        # Add common fields
        formatted_event = {
            'timestamp': event_dict['timestamp'],
            'event_type': event_dict['event_type'],
            'severity': event_dict['severity'],
            'source': event_dict['source'],
            'aegisai_version': '1.0.0'
        }
        
        # Add event-specific data
        formatted_event.update(event_dict['data'])
        
        # Add SIEM-specific formatting
        if self.siem_type == SIEMType.SPLUNK:
            formatted_event['sourcetype'] = 'aegisai:security'
            formatted_event['index'] = self.index
        elif self.siem_type == SIEMType.ELK:
            formatted_event['@timestamp'] = event_dict['timestamp']
            formatted_event['_index'] = self.index
        elif self.siem_type == SIEMType.QRADAR:
            formatted_event['logSource'] = 'AegisAI'
            formatted_event['category'] = 'Security'
        
        return formatted_event
    
    async def _send_to_splunk(self, event: Dict[str, Any]) -> bool:
        """
        Send event to Splunk HTTP Event Collector
        
        Args:
            event: Formatted event data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.siem_url or not self.api_key:
            logger.error("Splunk configuration missing URL or API key")
            return False
        
        try:
            headers = {
                'Authorization': f'Splunk {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Splunk HEC expects events in a specific format
            payload = {
                'event': event,
                'sourcetype': event.get('sourcetype', 'aegisai:security'),
                'index': event.get('index', self.index),
                'time': datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')).timestamp()
            }
            
            async with self.session.post(
                f"{self.siem_url}/services/collector/event",
                headers=headers,
                json=payload
            ) as response:
                if response.status == 200:
                    return True
                else:
                    logger.error(f"Splunk API error: {response.status} - {await response.text()}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to Splunk: {e}")
            return False
    
    async def _send_to_elk(self, event: Dict[str, Any]) -> bool:
        """
        Send event to Elasticsearch
        
        Args:
            event: Formatted event data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.siem_url:
            logger.error("Elasticsearch configuration missing URL")
            return False
        
        try:
            headers = {
                'Content-Type': 'application/json'
            }
            
            # Add authentication if provided
            if self.auth_token:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            elif self.username and self.password:
                import base64
                auth_string = f"{self.username}:{self.password}"
                auth_b64 = base64.b64encode(auth_string.encode()).decode()
                headers['Authorization'] = f'Basic {auth_b64}'
            
            index_name = event.get('_index', self.index)
            timestamp = event.get('@timestamp', datetime.now().isoformat())
            date_part = timestamp.split('T')[0]  # Extract date part for daily indices
            index_with_date = f"{index_name}-{date_part}"
            
            async with self.session.post(
                f"{self.siem_url}/{index_with_date}/_doc",
                headers=headers,
                json=event
            ) as response:
                if response.status in [200, 201]:
                    return True
                else:
                    logger.error(f"Elasticsearch API error: {response.status} - {await response.text()}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to Elasticsearch: {e}")
            return False
    
    async def _send_to_qradar(self, event: Dict[str, Any]) -> bool:
        """
        Send event to IBM QRadar
        
        Args:
            event: Formatted event data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.siem_url or not self.api_key:
            logger.error("QRadar configuration missing URL or API key")
            return False
        
        try:
            headers = {
                'SEC': self.api_key,  # QRadar uses 'SEC' header for API key
                'Content-Type': 'application/json',
                'Version': '12.0'
            }
            
            # QRadar expects events in a specific format
            payload = {
                'events': [event]
            }
            
            async with self.session.post(
                f"{self.siem_url}/api/siem/events",
                headers=headers,
                json=payload
            ) as response:
                if response.status == 201:
                    return True
                else:
                    logger.error(f"QRadar API error: {response.status} - {await response.text()}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to QRadar: {e}")
            return False
    
    async def _send_to_custom(self, event: Dict[str, Any]) -> bool:
        """
        Send event to custom SIEM via generic HTTP endpoint
        
        Args:
            event: Formatted event data
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.siem_url:
            logger.error("Custom SIEM configuration missing URL")
            return False
        
        try:
            headers = {
                'Content-Type': 'application/json'
            }
            
            # Add authentication if provided
            if self.api_key:
                headers['X-API-Key'] = self.api_key
            elif self.auth_token:
                headers['Authorization'] = f'Bearer {self.auth_token}'
            elif self.username and self.password:
                import base64
                auth_string = f"{self.username}:{self.password}"
                auth_b64 = base64.b64encode(auth_string.encode()).decode()
                headers['Authorization'] = f'Basic {auth_b64}'
            
            async with self.session.post(
                self.siem_url,
                headers=headers,
                json=event
            ) as response:
                if response.status in [200, 201, 202]:
                    return True
                else:
                    logger.error(f"Custom SIEM API error: {response.status} - {await response.text()}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to custom SIEM: {e}")
            return False
    
    async def send_xdr_correlation(self, correlation: XDRThreatCorrelation) -> bool:
        """
        Send XDR threat correlation to SIEM for real-time threat correlation.
        
        Args:
            correlation: XDR threat correlation to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled or not self.session or not self.xdr_enabled:
            return False
        
        try:
            # Convert to SIEM event
            siem_event = correlation.to_siem_event()
            
            # Send event
            success = await self.send_event(siem_event)
            
            if success:
                logger.info(f"Successfully sent XDR correlation {correlation.correlation_id} to SIEM")
            else:
                logger.error(f"Failed to send XDR correlation {correlation.correlation_id} to SIEM")
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending XDR correlation to SIEM: {e}")
            return False
    
    async def register_automated_action(self, action: AutomatedResponseAction):
        """
        Register an automated response action.
        
        Args:
            action: Automated response action to register
        """
        self.automated_actions.append(action)
        logger.info(f"Registered automated action: {action.action_type}")
    
    async def process_threat_event(self, event: SIEMEvent) -> bool:
        """
        Process a threat event and potentially trigger automated response actions.
        
        Args:
            event: Threat event to process
            
        Returns:
            bool: True if actions were triggered, False otherwise
        """
        if not self.enabled or not self.session:
            return False
        
        try:
            # Check if any automated actions should be triggered
            actions_triggered = False
            
            for action in self.automated_actions:
                if not action.enabled:
                    continue
                
                # Check severity threshold
                severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
                event_severity = severity_order.get(event.severity, 0)
                threshold_severity = severity_order.get(action.severity_threshold, 2)
                
                if event_severity >= threshold_severity:
                    # Check condition
                    # In a real implementation, this would be more sophisticated
                    if action.condition in str(event.to_dict()):
                        # Execute action
                        success = await action.execute(self)
                        if success:
                            actions_triggered = True
                            logger.info(f"Triggered automated action: {action.action_type}")
                        else:
                            logger.error(f"Failed to execute automated action: {action.action_type}")
            
            return actions_triggered
            
        except Exception as e:
            logger.error(f"Error processing threat event: {e}")
            return False
    
    async def send_automated_response_result(self, action_type: str, target: str, 
                                           status: str, details: Dict[str, Any] = None) -> bool:
        """
        Send automated response result to SIEM.
        
        Args:
            action_type: Type of action executed
            target: Target of the action
            status: Status of the action
            details: Additional details about the action
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled or not self.session:
            return False
        
        try:
            event = SIEMEvent(
                event_type='automated_response_result',
                severity='info',
                source='siem_connector',
                timestamp=datetime.now().isoformat(),
                action_type=action_type,
                target=target,
                status=status,
                details=details or {}
            )
            
            return await self.send_event(event)
            
        except Exception as e:
            logger.error(f"Error sending automated response result: {e}")
            return False
    
    async def bulk_send_events(self, events: List[SIEMEvent]) -> Dict[str, int]:
        """
        Send multiple events to SIEM in bulk
        
        Args:
            events: List of security events
            
        Returns:
            Dict: Statistics about sent events {sent: int, failed: int}
        """
        if not self.enabled or not self.session:
            return {'sent': 0, 'failed': len(events)}
        
        sent_count = 0
        failed_count = 0
        
        # Send events concurrently
        tasks = [self.send_event(event) for event in events]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error sending event: {result}")
                failed_count += 1
            elif result:
                sent_count += 1
            else:
                failed_count += 1
        
        logger.info(f"Bulk send completed: {sent_count} sent, {failed_count} failed")
        return {'sent': sent_count, 'failed': failed_count}
    
    async def test_connection(self) -> bool:
        """
        Test connection to SIEM system
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        if not self.enabled:
            return True
        
        try:
            if not self.session:
                await self.connect()
            
            if self.siem_type == SIEMType.SPLUNK:
                # Test Splunk HEC connectivity
                headers = {'Authorization': f'Splunk {self.api_key}'}
                async with self.session.get(
                    f"{self.siem_url}/services/collector/health",
                    headers=headers
                ) as response:
                    return response.status == 200
                    
            elif self.siem_type == SIEMType.ELK:
                # Test Elasticsearch connectivity
                headers = {}
                if self.auth_token:
                    headers['Authorization'] = f'Bearer {self.auth_token}'
                elif self.username and self.password:
                    import base64
                    auth_string = f"{self.username}:{self.password}"
                    auth_b64 = base64.b64encode(auth_string.encode()).decode()
                    headers['Authorization'] = f'Basic {auth_b64}'
                
                async with self.session.get(
                    f"{self.siem_url}/_cluster/health",
                    headers=headers
                ) as response:
                    return response.status == 200
                    
            elif self.siem_type == SIEMType.QRADAR:
                # Test QRadar connectivity
                headers = {'SEC': self.api_key}
                async with self.session.get(
                    f"{self.siem_url}/api/siem/events",
                    headers=headers
                ) as response:
                    return response.status in [200, 405]  # 405 is expected for GET on events endpoint
                    
            else:
                # Test generic HTTP connectivity
                async with self.session.get(self.siem_url) as response:
                    return response.status in [200, 401, 403]  # 401/403 indicate authentication needed
                    
        except Exception as e:
            logger.error(f"SIEM connection test failed: {e}")
            return False

# SIEM Integration Manager
class SIEMIntegrationManager:
    """Manages SIEM integration for the entire AegisAI system"""
    
    def __init__(self, config_path: str = "config/siem_config.json"):
        """
        Initialize SIEM integration manager
        
        Args:
            config_path: Path to SIEM configuration file
        """
        self.config_path = config_path
        self.connectors = {}
        self.default_connector = None
        self._load_configuration()
        
        logger.info("SIEM integration manager initialized")
    
    def _load_configuration(self):
        """Load SIEM configuration from file"""
        try:
            # Default configuration
            default_config = {
                "connectors": {
                    "primary": {
                        "type": "custom",
                        "enabled": False,
                        "url": "",
                        "api_key": "",
                        "username": "",
                        "password": "",
                        "index": "aegisai",
                        "xdr_enabled": True
                    }
                },
                "default_connector": "primary"
            }
            
            # Try to load from file
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
            except FileNotFoundError:
                # Create default config file
                config = default_config
                with open(self.config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                logger.info(f"Created default SIEM config at {self.config_path}")
            
            # Initialize connectors
            for name, connector_config in config.get('connectors', {}).items():
                self.connectors[name] = SIEMConnector(connector_config)
            
            # Set default connector
            default_name = config.get('default_connector', 'primary')
            if default_name in self.connectors:
                self.default_connector = self.connectors[default_name]
                
        except Exception as e:
            logger.error(f"Error loading SIEM configuration: {e}")
    
    async def initialize_connectors(self):
        """Initialize all enabled connectors"""
        for name, connector in self.connectors.items():
            if connector.enabled:
                try:
                    await connector.connect()
                    logger.info(f"Initialized SIEM connector: {name}")
                    
                    # Register default automated actions
                    await self._register_default_automated_actions(connector)
                except Exception as e:
                    logger.error(f"Failed to initialize SIEM connector {name}: {e}")
    
    async def _register_default_automated_actions(self, connector: SIEMConnector):
        """Register default automated response actions"""
        # Isolate endpoint action for critical threats
        isolate_action = AutomatedResponseAction(
            action_type='isolate_endpoint',
            target='{endpoint_id}',
            parameters={'duration': 3600},  # 1 hour
            condition='critical_threat',
            severity_threshold='critical'
        )
        await connector.register_automated_action(isolate_action)
        
        # Block malicious IP action
        block_ip_action = AutomatedResponseAction(
            action_type='block_ip',
            target='{source_ip}',
            parameters={},
            condition='malicious_ip',
            severity_threshold='high'
        )
        await connector.register_automated_action(block_ip_action)
        
        # Quarantine suspicious file action
        quarantine_action = AutomatedResponseAction(
            action_type='quarantine_file',
            target='{file_path}',
            parameters={},
            condition='suspicious_file',
            severity_threshold='medium'
        )
        await connector.register_automated_action(quarantine_action)
    
    async def shutdown_connectors(self):
        """Shutdown all connectors"""
        for name, connector in self.connectors.items():
            try:
                await connector.disconnect()
                logger.info(f"Shutdown SIEM connector: {name}")
            except Exception as e:
                logger.error(f"Error shutting down SIEM connector {name}: {e}")
    
    async def send_security_event(self, event: SIEMEvent, connector_name: str = None) -> bool:
        """
        Send security event to SIEM
        
        Args:
            event: Security event to send
            connector_name: Specific connector to use (None for default)
            
        Returns:
            bool: True if successful, False otherwise
        """
        connector = None
        if connector_name and connector_name in self.connectors:
            connector = self.connectors[connector_name]
        elif self.default_connector:
            connector = self.default_connector
        else:
            logger.warning("No SIEM connector available to send event")
            return False
        
        success = await connector.send_event(event)
        
        # Process threat events for automated response
        if success and event.severity in ['medium', 'high', 'critical']:
            await connector.process_threat_event(event)
        
        return success
    
    async def send_xdr_correlation(self, correlation: XDRThreatCorrelation, 
                                 connector_name: str = None) -> bool:
        """
        Send XDR threat correlation to SIEM
        
        Args:
            correlation: XDR threat correlation to send
            connector_name: Specific connector to use (None for default)
            
        Returns:
            bool: True if successful, False otherwise
        """
        connector = None
        if connector_name and connector_name in self.connectors:
            connector = self.connectors[connector_name]
        elif self.default_connector:
            connector = self.default_connector
        else:
            logger.warning("No SIEM connector available to send XDR correlation")
            return False
        
        return await connector.send_xdr_correlation(correlation)
    
    async def send_apt_event(self, agent_id: str, apt_result: Dict[str, Any]) -> bool:
        """
        Send APT detection event to SIEM
        
        Args:
            agent_id: Agent identifier
            apt_result: APT detection results
            
        Returns:
            bool: True if successful, False otherwise
        """
        event = SIEMEvent(
            event_type='apt_detection',
            severity='critical' if apt_result.get('apt_detected') else 'medium',
            source=agent_id,
            apt_detected=apt_result.get('apt_detected', False),
            apt_score=apt_result.get('overall_score', 0.0),
            confidence=apt_result.get('confidence', 0.0),
            techniques=apt_result.get('techniques', []),
            evidence_count=len(apt_result.get('evidence', []))
        )
        
        return await self.send_security_event(event)
    
    async def send_incident_event(self, incident_id: str, incident_data: Dict[str, Any]) -> bool:
        """
        Send incident response event to SIEM
        
        Args:
            incident_id: Incident identifier
            incident_data: Incident data
            
        Returns:
            bool: True if successful, False otherwise
        """
        event = SIEMEvent(
            event_type='security_incident',
            severity=incident_data.get('severity', 'medium'),
            source=incident_data.get('agent_id', 'unknown'),
            incident_id=incident_id,
            incident_type=incident_data.get('type', 'unknown'),
            actions_taken=len(incident_data.get('actions_taken', [])),
            status=incident_data.get('status', 'unknown')
        )
        
        return await self.send_security_event(event)
    
    async def send_behavioral_event(self, agent_id: str, analysis_result: Dict[str, Any]) -> bool:
        """
        Send behavioral analysis event to SIEM
        
        Args:
            agent_id: Agent identifier
            analysis_result: Behavioral analysis results
            
        Returns:
            bool: True if successful, False otherwise
        """
        event = SIEMEvent(
            event_type='behavioral_analysis',
            severity='high' if analysis_result.get('threat_detected') else 'low',
            source=agent_id,
            anomaly_score=analysis_result.get('anomaly_score', 0.0),
            is_anomaly=analysis_result.get('is_anomaly', False),
            confidence=analysis_result.get('confidence', 0.0),
            threat_detected=analysis_result.get('threat_detected', False)
        )
        
        return await self.send_security_event(event)
    
    async def send_xdr_event(self, agent_id: str, xdr_data: Dict[str, Any]) -> bool:
        """
        Send XDR event to SIEM for real-time threat correlation
        
        Args:
            agent_id: Agent identifier
            xdr_data: XDR correlation data
            
        Returns:
            bool: True if successful, False otherwise
        """
        correlation = XDRThreatCorrelation(
            correlation_id=xdr_data.get('correlation_id', ''),
            threat_score=xdr_data.get('threat_score', 0.0),
            threat_category=xdr_data.get('threat_category', 'unknown'),
            correlated_events=xdr_data.get('correlated_events', []),
            client_id=agent_id
        )
        
        return await self.send_xdr_correlation(correlation)
    
    async def send_automated_response_result(self, action_type: str, target: str, 
                                          status: str, details: Dict[str, Any] = None,
                                          connector_name: str = None) -> bool:
        """
        Send automated response result to SIEM
        
        Args:
            action_type: Type of action executed
            target: Target of the action
            status: Status of the action
            details: Additional details about the action
            connector_name: Specific connector to use (None for default)
            
        Returns:
            bool: True if successful, False otherwise
        """
        connector = None
        if connector_name and connector_name in self.connectors:
            connector = self.connectors[connector_name]
        elif self.default_connector:
            connector = self.default_connector
        else:
            logger.warning("No SIEM connector available to send automated response result")
            return False
        
        return await connector.send_automated_response_result(action_type, target, status, details)
    
    async def test_all_connections(self) -> Dict[str, bool]:
        """
        Test connections to all configured SIEM systems
        
        Returns:
            Dict: Connection test results for each connector
        """
        results = {}
        for name, connector in self.connectors.items():
            try:
                results[name] = await connector.test_connection()
            except Exception as e:
                logger.error(f"Connection test failed for {name}: {e}")
                results[name] = False
        
        return results

# Example usage and testing
if __name__ == "__main__":
    # Example configuration
    config = {
        "type": "custom",
        "enabled": True,
        "url": "https://siem.example.com/api/events",
        "api_key": "test-api-key",
        "index": "aegisai"
    }
    
    async def main():
        # Create SIEM connector
        connector = SIEMConnector(config)
        await connector.connect()
        
        # Create test event
        event = SIEMEvent(
            event_type="test_event",
            severity="medium",
            source="test-agent-001",
            description="This is a test event",
            data={"test_field": "test_value"}
        )
        
        # Send event
        success = await connector.send_event(event)
        print(f"Event sent successfully: {success}")
        
        # Test connection
        connected = await connector.test_connection()
        print(f"Connection test result: {connected}")
        
        await connector.disconnect()
    
    # Run async main
    asyncio.run(main())