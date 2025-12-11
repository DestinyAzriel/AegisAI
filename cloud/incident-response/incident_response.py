#!/usr/bin/env python3
"""
AegisAI Incident Response Module

This module provides automated incident response capabilities for security incidents.
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import asyncio
import uuid

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import forensic analyzer
from forensics.forensic_analyzer import ForensicAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IncidentResponseEngine:
    """Automated incident response engine"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the incident response engine"""
        self.config = self._load_config(config_path)
        self.playbooks = self._load_playbooks()
        self.forensic_analyzer = ForensicAnalyzer(self.config.get('evidence_dir', '/var/evidence'))
        self.notification_system = NotificationSystem(self.config.get('notifications', {}))
        self.active_incidents = {}
        
        logger.info("Incident response engine initialized")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            'evidence_dir': '/var/evidence',
            'playbooks_dir': 'playbooks',
            'notifications': {
                'email_enabled': True,
                'slack_enabled': False,
                'webhook_enabled': False
            },
            'containment': {
                'isolate_endpoint': True,
                'kill_processes': True,
                'quarantine_files': True
            }
        }
        
        if config_path and os.path.exists(config_path):
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
    
    def _load_playbooks(self) -> Dict[str, Any]:
        """Load incident response playbooks"""
        playbooks_dir = self.config.get('playbooks_dir', 'playbooks')
        playbooks = {}
        
        # Create playbooks directory if it doesn't exist
        Path(playbooks_dir).mkdir(parents=True, exist_ok=True)
        
        # Load default playbooks
        default_playbooks = {
            'malware_detected': {
                'name': 'Malware Detected Response',
                'description': 'Response playbook for malware detection incidents',
                'steps': [
                    {'action': 'isolate_endpoint', 'description': 'Isolate affected endpoint'},
                    {'action': 'collect_evidence', 'description': 'Collect forensic evidence'},
                    {'action': 'kill_malicious_processes', 'description': 'Terminate malicious processes'},
                    {'action': 'quarantine_files', 'description': 'Quarantine malicious files'},
                    {'action': 'notify_team', 'description': 'Notify security team'},
                    {'action': 'remediate', 'description': 'Apply remediation measures'}
                ],
                'severity_mapping': {
                    'critical': ['isolate_endpoint', 'collect_evidence', 'kill_malicious_processes', 'quarantine_files', 'notify_team', 'remediate'],
                    'high': ['isolate_endpoint', 'collect_evidence', 'kill_malicious_processes', 'quarantine_files', 'notify_team'],
                    'medium': ['collect_evidence', 'notify_team'],
                    'low': ['collect_evidence']
                }
            },
            'unauthorized_access': {
                'name': 'Unauthorized Access Response',
                'description': 'Response playbook for unauthorized access incidents',
                'steps': [
                    {'action': 'isolate_endpoint', 'description': 'Isolate affected endpoint'},
                    {'action': 'collect_evidence', 'description': 'Collect forensic evidence'},
                    {'action': 'disable_accounts', 'description': 'Disable compromised accounts'},
                    {'action': 'reset_passwords', 'description': 'Reset passwords for affected accounts'},
                    {'action': 'notify_team', 'description': 'Notify security team'},
                    {'action': 'audit_logs', 'description': 'Audit system logs'}
                ],
                'severity_mapping': {
                    'critical': ['isolate_endpoint', 'collect_evidence', 'disable_accounts', 'reset_passwords', 'notify_team', 'audit_logs'],
                    'high': ['isolate_endpoint', 'collect_evidence', 'disable_accounts', 'notify_team', 'audit_logs'],
                    'medium': ['collect_evidence', 'notify_team', 'audit_logs'],
                    'low': ['collect_evidence', 'notify_team']
                }
            },
            'data_exfiltration': {
                'name': 'Data Exfiltration Response',
                'description': 'Response playbook for data exfiltration incidents',
                'steps': [
                    {'action': 'block_network', 'description': 'Block suspicious network connections'},
                    {'action': 'isolate_endpoint', 'description': 'Isolate affected endpoint'},
                    {'action': 'collect_evidence', 'description': 'Collect forensic evidence'},
                    {'action': 'notify_team', 'description': 'Notify security team'},
                    {'action': 'audit_data_access', 'description': 'Audit data access logs'}
                ],
                'severity_mapping': {
                    'critical': ['block_network', 'isolate_endpoint', 'collect_evidence', 'notify_team', 'audit_data_access'],
                    'high': ['block_network', 'isolate_endpoint', 'collect_evidence', 'notify_team'],
                    'medium': ['block_network', 'collect_evidence', 'notify_team'],
                    'low': ['collect_evidence', 'notify_team']
                }
            }
        }
        
        # Save default playbooks to files
        for name, playbook in default_playbooks.items():
            playbook_file = os.path.join(playbooks_dir, f"{name}.json")
            if not os.path.exists(playbook_file):
                try:
                    with open(playbook_file, 'w') as f:
                        json.dump(playbook, f, indent=2)
                except Exception as e:
                    logger.error(f"Error saving playbook {name}: {e}")
        
        # Load playbooks from files
        for filename in os.listdir(playbooks_dir):
            if filename.endswith('.json'):
                try:
                    with open(os.path.join(playbooks_dir, filename), 'r') as f:
                        playbook = json.load(f)
                        playbook_name = filename.replace('.json', '')
                        playbooks[playbook_name] = playbook
                except Exception as e:
                    logger.error(f"Error loading playbook {filename}: {e}")
        
        return playbooks
    
    def handle_incident(self, incident_data: Dict[str, Any]) -> str:
        """
        Handle a security incident
        
        Args:
            incident_data: Incident information
            
        Returns:
            str: Incident ID
        """
        # Generate incident ID
        incident_id = f"INC-{int(datetime.now().timestamp())}"
        
        # Store incident data
        self.active_incidents[incident_id] = {
            'id': incident_id,
            'data': incident_data,
            'status': 'new',
            'created_at': datetime.now().isoformat(),
            'actions_taken': []
        }
        
        logger.info(f"Handling incident: {incident_id}")
        
        # Determine incident type and severity
        incident_type = incident_data.get('type', 'unknown')
        severity = incident_data.get('severity', 'medium')
        
        # Execute appropriate response playbook
        asyncio.create_task(self._execute_playbook(incident_id, incident_type, severity))
        
        return incident_id
    
    async def _execute_playbook(self, incident_id: str, incident_type: str, severity: str):
        """
        Execute incident response playbook
        
        Args:
            incident_id: Incident identifier
            incident_type: Type of incident
            severity: Incident severity
        """
        # Get playbook for incident type
        playbook = self.playbooks.get(incident_type)
        if not playbook:
            logger.warning(f"No playbook found for incident type: {incident_type}")
            # Use default playbook
            playbook = self.playbooks.get('malware_detected', {})
        
        # Get actions for severity level
        severity_actions = playbook.get('severity_mapping', {}).get(severity, [])
        if not severity_actions:
            # Default to all actions if no severity mapping
            severity_actions = [step['action'] for step in playbook.get('steps', [])]
        
        logger.info(f"Executing playbook '{playbook.get('name', 'Unknown')}' for incident {incident_id}")
        
        # Update incident status
        self.active_incidents[incident_id]['status'] = 'in_progress'
        
        # Execute each action
        for action in severity_actions:
            try:
                await self._execute_action(incident_id, action)
                # Record action taken
                self.active_incidents[incident_id]['actions_taken'].append({
                    'action': action,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'completed'
                })
            except Exception as e:
                logger.error(f"Error executing action {action} for incident {incident_id}: {e}")
                # Record failed action
                self.active_incidents[incident_id]['actions_taken'].append({
                    'action': action,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'failed',
                    'error': str(e)
                })
        
        # Update incident status
        self.active_incidents[incident_id]['status'] = 'completed'
        self.active_incidents[incident_id]['completed_at'] = datetime.now().isoformat()
        
        logger.info(f"Playbook execution completed for incident {incident_id}")
    
    async def _execute_action(self, incident_id: str, action: str):
        """
        Execute a specific incident response action
        
        Args:
            incident_id: Incident identifier
            action: Action to execute
        """
        incident_data = self.active_incidents[incident_id]['data']
        agent_id = incident_data.get('agent_id')
        
        logger.info(f"Executing action '{action}' for incident {incident_id}")
        
        if action == 'isolate_endpoint':
            await self._isolate_endpoint(agent_id)
        elif action == 'collect_evidence':
            await self._collect_evidence(incident_id, agent_id, incident_data)
        elif action == 'kill_malicious_processes':
            await self._kill_malicious_processes(agent_id, incident_data)
        elif action == 'quarantine_files':
            await self._quarantine_files(agent_id, incident_data)
        elif action == 'notify_team':
            await self._notify_team(incident_id, incident_data)
        elif action == 'disable_accounts':
            await self._disable_accounts(incident_data)
        elif action == 'reset_passwords':
            await self._reset_passwords(incident_data)
        elif action == 'audit_logs':
            await self._audit_logs(incident_data)
        elif action == 'block_network':
            await self._block_network(incident_data)
        elif action == 'audit_data_access':
            await self._audit_data_access(incident_data)
        elif action == 'remediate':
            await self._remediate(incident_data)
        else:
            logger.warning(f"Unknown action: {action}")
    
    async def _isolate_endpoint(self, agent_id: str):
        """Isolate an endpoint from the network"""
        logger.info(f"Isolating endpoint {agent_id}")
        # In a real implementation, this would send a command to the agent
        # to block network connections
        await asyncio.sleep(0.1)  # Simulate network operation
    
    async def _collect_evidence(self, incident_id: str, agent_id: str, incident_data: Dict[str, Any]):
        """Collect forensic evidence"""
        logger.info(f"Collecting evidence for incident {incident_id} from agent {agent_id}")
        
        # Start forensic investigation
        case_number = f"CASE-{incident_id}"
        description = f"Automated incident response for {incident_data.get('type', 'Unknown')}"
        investigation_id = self.forensic_analyzer.start_investigation(case_number, description)
        
        # Collect memory dump if available
        if 'memory_data' in incident_data:
            self.forensic_analyzer.collect_memory_dump(agent_id, incident_data['memory_data'])
        
        # Collect file evidence if available
        if 'file_path' in incident_data:
            self.forensic_analyzer.collect_file_evidence(agent_id, incident_data['file_path'], incident_data['file_path'])
        
        # Collect process evidence if available
        if 'process_info' in incident_data:
            self.forensic_analyzer.collect_process_evidence(agent_id, incident_data['process_info'])
        
        # Generate evidence package
        package_path = self.forensic_analyzer.generate_evidence_package()
        logger.info(f"Evidence package generated: {package_path}")
    
    async def _kill_malicious_processes(self, agent_id: str, incident_data: Dict[str, Any]):
        """Kill malicious processes"""
        logger.info(f"Terminating malicious processes on agent {agent_id}")
        # In a real implementation, this would send a command to the agent
        # to terminate specific processes
        await asyncio.sleep(0.1)  # Simulate network operation
    
    async def _quarantine_files(self, agent_id: str, incident_data: Dict[str, Any]):
        """Quarantine malicious files"""
        logger.info(f"Quarantining malicious files on agent {agent_id}")
        # In a real implementation, this would send a command to the agent
        # to move suspicious files to quarantine
        await asyncio.sleep(0.1)  # Simulate network operation
    
    async def _notify_team(self, incident_id: str, incident_data: Dict[str, Any]):
        """Notify security team"""
        logger.info(f"Notifying security team about incident {incident_id}")
        await self.notification_system.send_notification(incident_id, incident_data)
    
    async def _disable_accounts(self, incident_data: Dict[str, Any]):
        """Disable compromised accounts"""
        logger.info("Disabling compromised accounts")
        # In a real implementation, this would integrate with identity management systems
        await asyncio.sleep(0.1)  # Simulate operation
    
    async def _reset_passwords(self, incident_data: Dict[str, Any]):
        """Reset passwords for affected accounts"""
        logger.info("Resetting passwords for affected accounts")
        # In a real implementation, this would integrate with identity management systems
        await asyncio.sleep(0.1)  # Simulate operation
    
    async def _audit_logs(self, incident_data: Dict[str, Any]):
        """Audit system logs"""
        logger.info("Auditing system logs")
        # In a real implementation, this would collect and analyze logs
        await asyncio.sleep(0.1)  # Simulate operation
    
    async def _block_network(self, incident_data: Dict[str, Any]):
        """Block suspicious network connections"""
        logger.info("Blocking suspicious network connections")
        # In a real implementation, this would update firewall rules
        await asyncio.sleep(0.1)  # Simulate operation
    
    async def _audit_data_access(self, incident_data: Dict[str, Any]):
        """Audit data access logs"""
        logger.info("Auditing data access logs")
        # In a real implementation, this would analyze data access patterns
        await asyncio.sleep(0.1)  # Simulate operation
    
    async def _remediate(self, incident_data: Dict[str, Any]):
        """Apply remediation measures"""
        logger.info("Applying remediation measures")
        # In a real implementation, this would apply patches, updates, or other fixes
        await asyncio.sleep(0.1)  # Simulate operation
    
    def get_incident_status(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of an incident
        
        Args:
            incident_id: Incident identifier
            
        Returns:
            Incident status information or None if not found
        """
        return self.active_incidents.get(incident_id)
    
    def get_active_incidents(self) -> List[Dict[str, Any]]:
        """
        Get all active incidents
        
        Returns:
            List of active incidents
        """
        return [incident for incident in self.active_incidents.values() 
                if incident['status'] in ['new', 'in_progress']]

class NotificationSystem:
    """Notification system for incident alerts"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize notification system"""
        self.config = config
        logger.info("Notification system initialized")
    
    async def send_notification(self, incident_id: str, incident_data: Dict[str, Any]):
        """
        Send notification about incident
        
        Args:
            incident_id: Incident identifier
            incident_data: Incident information
        """
        message = self._format_notification_message(incident_id, incident_data)
        
        # Send email notification
        if self.config.get('email_enabled', False):
            await self._send_email_notification(message)
        
        # Send Slack notification
        if self.config.get('slack_enabled', False):
            await self._send_slack_notification(message)
        
        # Send webhook notification
        if self.config.get('webhook_enabled', False):
            await self._send_webhook_notification(message)
    
    def _format_notification_message(self, incident_id: str, incident_data: Dict[str, Any]) -> str:
        """Format notification message"""
        incident_type = incident_data.get('type', 'Unknown')
        severity = incident_data.get('severity', 'Unknown')
        description = incident_data.get('description', 'No description provided')
        
        return f"""
AegisAI Security Alert

Incident ID: {incident_id}
Type: {incident_type}
Severity: {severity}
Description: {description}
Time: {datetime.now().isoformat()}

Please review and take appropriate action.
        """.strip()
    
    async def _send_email_notification(self, message: str):
        """Send email notification"""
        logger.info("Sending email notification")
        # In a real implementation, this would send an actual email
        await asyncio.sleep(0.1)  # Simulate network operation
    
    async def _send_slack_notification(self, message: str):
        """Send Slack notification"""
        logger.info("Sending Slack notification")
        # In a real implementation, this would send a Slack message
        await asyncio.sleep(0.1)  # Simulate network operation
    
    async def _send_webhook_notification(self, message: str):
        """Send webhook notification"""
        logger.info("Sending webhook notification")
        # In a real implementation, this would send a webhook request
        await asyncio.sleep(0.1)  # Simulate network operation

# Example usage
if __name__ == "__main__":
    # Create incident response engine
    engine = IncidentResponseEngine()
    
    # Simulate an incident
    incident_data = {
        'type': 'malware_detected',
        'severity': 'high',
        'agent_id': 'agent-001',
        'file_path': '/tmp/malicious_file.exe',
        'description': 'Malware detected on endpoint',
        'process_info': {
            'pid': 1234,
            'name': 'malicious_process.exe',
            'cmdline': '/tmp/malicious_file.exe --payload'
        }
    }
    
    # Handle the incident
    incident_id = engine.handle_incident(incident_data)
    print(f"Created incident: {incident_id}")
    
    # Wait for async operations to complete
    asyncio.run(asyncio.sleep(2))
    
    # Check incident status
    status = engine.get_incident_status(incident_id)
    if status:
        print(f"Incident status: {status['status']}")
    else:
        print("Incident status: Not found")