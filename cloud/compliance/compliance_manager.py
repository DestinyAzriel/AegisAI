#!/usr/bin/env python3
"""
AegisAI Compliance Manager

This module handles compliance with data protection regulations (GDPR, CCPA)
and prepares for security certifications (SOC 2, ISO 27001).
"""

import json
import logging
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum
import asyncio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ComplianceStandard(Enum):
    """Supported compliance standards"""
    GDPR = "gdpr"
    CCPA = "ccpa"
    SOC2 = "soc2"
    ISO27001 = "iso27001"

class DataSubjectRequestType(Enum):
    """Types of data subject requests"""
    RIGHT_TO_ACCESS = "right_to_access"
    RIGHT_TO_ERASURE = "right_to_erasure"
    RIGHT_TO_PORTABILITY = "right_to_portability"
    RIGHT_TO_RECTIFICATION = "right_to_rectification"
    RIGHT_TO_RESTRICT = "right_to_restrict"
    RIGHT_TO_OBJECT = "right_to_object"

class ComplianceManager:
    """Manages compliance with data protection regulations and security standards"""
    
    def __init__(self, config_path: str = "config/compliance_config.json"):
        """
        Initialize compliance manager
        
        Args:
            config_path: Path to compliance configuration file
        """
        self.config_path = config_path
        self.config = self._load_configuration()
        self.audit_log = []
        self.data_inventory = {}
        self.consent_records = {}
        self.dsr_requests = {}
        
        logger.info("Compliance manager initialized")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load compliance configuration from file"""
        try:
            # Default configuration
            default_config = {
                "gdpr": {
                    "enabled": True,
                    "data_retention_days": 1825,  # 5 years
                    "consent_required": True,
                    "privacy_notice_url": "https://aegisai.com/privacy",
                    "dpa_required": True
                },
                "ccpa": {
                    "enabled": True,
                    "sale_opt_out": True,
                    "data_retention_days": 1825,  # 5 years
                    "privacy_notice_url": "https://aegisai.com/privacy"
                },
                "soc2": {
                    "enabled": True,
                    "audit_frequency": "quarterly",
                    "controls": {
                        "security": True,
                        "availability": True,
                        "processing_integrity": True,
                        "confidentiality": True,
                        "privacy": True
                    }
                },
                "iso27001": {
                    "enabled": True,
                    "audit_frequency": "annually",
                    "controls": {
                        "A.5": True,  # Information security policies
                        "A.6": True,  # Organization of information security
                        "A.7": True,  # Human resource security
                        "A.8": True,  # Asset management
                        "A.9": True,  # Access control
                        "A.10": True, # Cryptography
                        "A.11": True, # Physical and environmental security
                        "A.12": True, # Operations security
                        "A.13": True, # Communications security
                        "A.14": True, # System acquisition, development and maintenance
                        "A.15": True, # Supplier relationships
                        "A.16": True, # Information security incident management
                        "A.17": True, # Business continuity management
                        "A.18": True  # Compliance
                    }
                }
            }
            
            # Try to load from file
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
            except FileNotFoundError:
                # Create default config file
                config = default_config
                # Create config directory if it doesn't exist
                import os
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                logger.info(f"Created default compliance config at {self.config_path}")
            
            return config
            
        except Exception as e:
            logger.error(f"Error loading compliance configuration: {e}")
            return {}
    
    def register_data_processing(self, data_type: str, purpose: str, 
                                data_subjects: List[str], retention_period: int = None) -> str:
        """
        Register data processing activities for compliance tracking
        
        Args:
            data_type: Type of data being processed
            purpose: Purpose of processing
            data_subjects: Categories of data subjects
            retention_period: Data retention period in days
            
        Returns:
            str: Processing activity ID
        """
        activity_id = f"DPA-{int(datetime.now().timestamp())}"
        
        # Determine retention period
        if retention_period is None:
            # Use default retention period based on enabled standards
            if self.config.get('gdpr', {}).get('enabled', False):
                retention_period = self.config['gdpr'].get('data_retention_days', 1825)
            elif self.config.get('ccpa', {}).get('enabled', False):
                retention_period = self.config['ccpa'].get('data_retention_days', 1825)
            else:
                retention_period = 1825  # Default 5 years
        
        # Register processing activity
        self.data_inventory[activity_id] = {
            'id': activity_id,
            'data_type': data_type,
            'purpose': purpose,
            'data_subjects': data_subjects,
            'retention_period': retention_period,
            'registered_at': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat()
        }
        
        # Log the activity
        self._log_compliance_event('data_processing_registered', {
            'activity_id': activity_id,
            'data_type': data_type,
            'purpose': purpose
        })
        
        logger.info(f"Registered data processing activity: {activity_id}")
        return activity_id
    
    def record_consent(self, user_id: str, consent_types: List[str], 
                      granted: bool = True, timestamp: str = None) -> str:
        """
        Record user consent for data processing
        
        Args:
            user_id: User identifier
            consent_types: Types of consent (e.g., 'marketing', 'analytics', 'essential')
            granted: Whether consent is granted or revoked
            timestamp: When consent was given (ISO format)
            
        Returns:
            str: Consent record ID
        """
        consent_id = f"CON-{hashlib.md5(f'{user_id}-{consent_types}-{timestamp or datetime.now().isoformat()}'.encode()).hexdigest()[:12]}"
        
        # Record consent
        self.consent_records[consent_id] = {
            'id': consent_id,
            'user_id': user_id,
            'consent_types': consent_types,
            'granted': granted,
            'timestamp': timestamp or datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=365*2)).isoformat()  # 2-year expiry
        }
        
        # Log the consent
        self._log_compliance_event('consent_recorded', {
            'consent_id': consent_id,
            'user_id': user_id,
            'consent_types': consent_types,
            'granted': granted
        })
        
        logger.info(f"Recorded {'granted' if granted else 'revoked'} consent: {consent_id}")
        return consent_id
    
    def handle_data_subject_request(self, request_type: DataSubjectRequestType, 
                                  user_id: str, details: Dict[str, Any] = None) -> str:
        """
        Handle data subject requests (DSR) for GDPR/CCPA compliance
        
        Args:
            request_type: Type of data subject request
            user_id: User identifier
            details: Additional request details
            
        Returns:
            str: Request ID
        """
        request_id = f"DSR-{int(datetime.now().timestamp())}"
        
        # Create DSR record
        self.dsr_requests[request_id] = {
            'id': request_id,
            'type': request_type.value,
            'user_id': user_id,
            'details': details or {},
            'status': 'pending',
            'submitted_at': datetime.now().isoformat(),
            'processed_at': None,
            'response_sent_at': None
        }
        
        # Log the request
        self._log_compliance_event('dsr_submitted', {
            'request_id': request_id,
            'type': request_type.value,
            'user_id': user_id
        })
        
        logger.info(f"Handled data subject request: {request_id}")
        return request_id
    
    def process_data_subject_request(self, request_id: str) -> Dict[str, Any]:
        """
        Process a data subject request
        
        Args:
            request_id: Request identifier
            
        Returns:
            Dict: Processing results
        """
        if request_id not in self.dsr_requests:
            raise ValueError(f"Request {request_id} not found")
        
        request = self.dsr_requests[request_id]
        request_type = DataSubjectRequestType(request['type'])
        
        # Process based on request type
        result = {}
        if request_type == DataSubjectRequestType.RIGHT_TO_ACCESS:
            result = self._process_right_to_access(request['user_id'])
        elif request_type == DataSubjectRequestType.RIGHT_TO_ERASURE:
            result = self._process_right_to_erasure(request['user_id'])
        elif request_type == DataSubjectRequestType.RIGHT_TO_PORTABILITY:
            result = self._process_right_to_portability(request['user_id'])
        elif request_type == DataSubjectRequestType.RIGHT_TO_RECTIFICATION:
            result = self._process_right_to_rectification(request['user_id'], request['details'])
        elif request_type == DataSubjectRequestType.RIGHT_TO_RESTRICT:
            result = self._process_right_to_restrict(request['user_id'])
        elif request_type == DataSubjectRequestType.RIGHT_TO_OBJECT:
            result = self._process_right_to_object(request['user_id'], request['details'])
        
        # Update request status
        request['status'] = 'processed'
        request['processed_at'] = datetime.now().isoformat()
        
        # Log the processing
        self._log_compliance_event('dsr_processed', {
            'request_id': request_id,
            'type': request_type.value,
            'result': result
        })
        
        return result
    
    def _process_right_to_access(self, user_id: str) -> Dict[str, Any]:
        """Process right to access request"""
        # In a real implementation, this would retrieve user data
        user_data = {
            'user_id': user_id,
            'personal_data': {
                'name': 'John Doe',
                'email': 'john.doe@example.com',
                'registration_date': '2023-01-01T00:00:00Z'
            },
            'processing_activities': [
                activity for activity in self.data_inventory.values()
                if user_id in str(activity)
            ],
            'consent_records': [
                record for record in self.consent_records.values()
                if record['user_id'] == user_id
            ]
        }
        return user_data
    
    def _process_right_to_erasure(self, user_id: str) -> Dict[str, Any]:
        """Process right to erasure request"""
        # In a real implementation, this would delete user data
        deleted_data = {
            'user_id': user_id,
            'deleted_records': 5,  # Simulated count
            'retained_records': 2   # Records retained for legal compliance
        }
        return deleted_data
    
    def _process_right_to_portability(self, user_id: str) -> Dict[str, Any]:
        """Process right to data portability request"""
        # In a real implementation, this would export user data in structured format
        exported_data = {
            'user_id': user_id,
            'format': 'json',
            'data': {
                'profile': {'name': 'John Doe', 'email': 'john.doe@example.com'},
                'activity': [{'type': 'scan', 'timestamp': '2023-01-01T00:00:00Z'}]
            }
        }
        return exported_data
    
    def _process_right_to_rectification(self, user_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Process right to rectification request"""
        # In a real implementation, this would update user data
        updated_fields = details.get('fields', {})
        return {
            'user_id': user_id,
            'updated_fields': list(updated_fields.keys()),
            'status': 'completed'
        }
    
    def _process_right_to_restrict(self, user_id: str) -> Dict[str, Any]:
        """Process right to restriction of processing request"""
        # In a real implementation, this would restrict processing of user data
        return {
            'user_id': user_id,
            'processing_restricted': True,
            'restriction_type': 'processing_suspended'
        }
    
    def _process_right_to_object(self, user_id: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Process right to object request"""
        # In a real implementation, this would handle objection to processing
        objection_type = details.get('objection_type', 'marketing')
        return {
            'user_id': user_id,
            'objection_type': objection_type,
            'processing_restricted': True,
            'status': 'completed'
        }
    
    def auto_delete_expired_data(self) -> Dict[str, int]:
        """
        Automatically delete data that has exceeded retention periods
        
        Returns:
            Dict: Statistics about deleted data
        """
        deleted_count = 0
        retained_count = 0
        
        # Check data inventory for expired data
        now = datetime.now()
        expired_activities = []
        
        for activity_id, activity in self.data_inventory.items():
            registered_at = datetime.fromisoformat(activity['registered_at'])
            retention_period = timedelta(days=activity['retention_period'])
            expiry_date = registered_at + retention_period
            
            if now > expiry_date:
                expired_activities.append(activity_id)
        
        # Delete expired activities
        for activity_id in expired_activities:
            del self.data_inventory[activity_id]
            deleted_count += 1
        
        # Log the deletion
        self._log_compliance_event('auto_delete_expired_data', {
            'deleted_count': deleted_count,
            'retained_count': retained_count
        })
        
        logger.info(f"Auto-deleted {deleted_count} expired data activities")
        return {'deleted': deleted_count, 'retained': retained_count}
    
    def generate_privacy_report(self, user_id: str = None) -> Dict[str, Any]:
        """
        Generate privacy compliance report
        
        Args:
            user_id: Optional user ID to generate user-specific report
            
        Returns:
            Dict: Privacy compliance report
        """
        if user_id:
            # Generate user-specific report
            user_consent = [
                record for record in self.consent_records.values()
                if record['user_id'] == user_id
            ]
            user_dsrs = [
                request for request in self.dsr_requests.values()
                if request['user_id'] == user_id
            ]
            
            report = {
                'report_type': 'user_privacy_report',
                'user_id': user_id,
                'generated_at': datetime.now().isoformat(),
                'consent_records': user_consent,
                'data_subject_requests': user_dsrs,
                'data_processing_activities': [
                    activity for activity in self.data_inventory.values()
                    if user_id in str(activity)
                ]
            }
        else:
            # Generate system-wide report
            report = {
                'report_type': 'system_privacy_report',
                'generated_at': datetime.now().isoformat(),
                'total_data_processing_activities': len(self.data_inventory),
                'total_consent_records': len(self.consent_records),
                'total_dsr_requests': len(self.dsr_requests),
                'active_standards': [
                    standard.value for standard in ComplianceStandard
                    if self.config.get(standard.value, {}).get('enabled', False)
                ],
                'compliance_status': self._calculate_compliance_status()
            }
        
        return report
    
    def _calculate_compliance_status(self) -> Dict[str, Any]:
        """Calculate overall compliance status"""
        status = {}
        
        for standard in ComplianceStandard:
            standard_config = self.config.get(standard.value, {})
            status[standard.value] = {
                'enabled': standard_config.get('enabled', False),
                'compliant': True,  # In a real implementation, this would be based on actual compliance checks
                'last_audit': None,  # Would be populated with actual audit dates
                'next_audit': None   # Would be populated with next audit dates
            }
        
        return status
    
    def generate_soc2_report(self) -> Dict[str, Any]:
        """
        Generate SOC 2 compliance report
        
        Returns:
            Dict: SOC 2 compliance report
        """
        soc2_config = self.config.get('soc2', {})
        
        report = {
            'standard': 'SOC 2',
            'generated_at': datetime.now().isoformat(),
            'organization': 'AegisAI',
            'reporting_period': 'Annual',
            'trust_services_criteria': {},
            'controls': {}
        }
        
        # Add trust services criteria status
        for criterion, enabled in soc2_config.get('controls', {}).items():
            report['trust_services_criteria'][criterion] = {
                'implemented': enabled,
                'effectiveness': 'high' if enabled else 'not_implemented',
                'description': self._get_criterion_description(criterion)
            }
        
        # Add control implementation status
        report['controls'] = self._assess_soc2_controls()
        
        return report
    
    def _get_criterion_description(self, criterion: str) -> str:
        """Get description for SOC 2 trust services criterion"""
        descriptions = {
            'security': 'Protection of system resources against unauthorized access',
            'availability': 'System accessibility for operation and use as committed or agreed',
            'processing_integrity': 'System processing is complete, valid, accurate, timely, and authorized',
            'confidentiality': 'Protection of information designated as confidential',
            'privacy': 'Protection of personal information'
        }
        return descriptions.get(criterion, 'Unknown criterion')
    
    def _assess_soc2_controls(self) -> Dict[str, Any]:
        """Assess implementation of SOC 2 controls"""
        # In a real implementation, this would assess actual control implementation
        return {
            'access_controls': {
                'implemented': True,
                'effectiveness': 'high',
                'evidence': ['Access logs', 'Authentication records']
            },
            'data_encryption': {
                'implemented': True,
                'effectiveness': 'high',
                'evidence': ['Encryption certificates', 'Key management records']
            },
            'incident_response': {
                'implemented': True,
                'effectiveness': 'high',
                'evidence': ['Incident response procedures', 'Training records']
            },
            'change_management': {
                'implemented': True,
                'effectiveness': 'high',
                'evidence': ['Change logs', 'Approval records']
            }
        }
    
    def generate_iso27001_report(self) -> Dict[str, Any]:
        """
        Generate ISO 27001 compliance report
        
        Returns:
            Dict: ISO 27001 compliance report
        """
        iso_config = self.config.get('iso27001', {})
        
        report = {
            'standard': 'ISO 27001',
            'generated_at': datetime.now().isoformat(),
            'organization': 'AegisAI',
            'reporting_period': 'Annual',
            'controls': {}
        }
        
        # Add control implementation status
        for control, enabled in iso_config.get('controls', {}).items():
            report['controls'][control] = {
                'implemented': enabled,
                'effectiveness': 'high' if enabled else 'not_implemented',
                'description': self._get_iso_control_description(control)
            }
        
        return report
    
    def _get_iso_control_description(self, control: str) -> str:
        """Get description for ISO 27001 control"""
        descriptions = {
            'A.5': 'Information security policies',
            'A.6': 'Organization of information security',
            'A.7': 'Human resource security',
            'A.8': 'Asset management',
            'A.9': 'Access control',
            'A.10': 'Cryptography',
            'A.11': 'Physical and environmental security',
            'A.12': 'Operations security',
            'A.13': 'Communications security',
            'A.14': 'System acquisition, development and maintenance',
            'A.15': 'Supplier relationships',
            'A.16': 'Information security incident management',
            'A.17': 'Business continuity management',
            'A.18': 'Compliance'
        }
        return descriptions.get(control, 'Unknown control')
    
    def _log_compliance_event(self, event_type: str, details: Dict[str, Any]):
        """
        Log compliance-related events
        
        Args:
            event_type: Type of compliance event
            details: Event details
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        self.audit_log.append(log_entry)
        
        # Keep only recent logs (last 1000 entries)
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-500:]
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get compliance audit log
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List: Audit log entries
        """
        return self.audit_log[-limit:]
    
    def export_compliance_data(self, format: str = 'json') -> str:
        """
        Export compliance data for third-party assessments
        
        Args:
            format: Export format (json, csv)
            
        Returns:
            str: Exported data
        """
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'data_inventory': self.data_inventory,
            'consent_records': self.consent_records,
            'dsr_requests': self.dsr_requests,
            'audit_log': self.audit_log[-100:],  # Last 100 entries
            'configuration': self.config
        }
        
        if format.lower() == 'json':
            return json.dumps(export_data, indent=2)
        else:
            # For other formats, return JSON as default
            return json.dumps(export_data, indent=2)

# Compliance API for integration with other services
class ComplianceAPI:
    """API for compliance services"""
    
    def __init__(self, compliance_manager: ComplianceManager):
        """
        Initialize compliance API
        
        Args:
            compliance_manager: Compliance manager instance
        """
        self.compliance_manager = compliance_manager
    
    def register_data_processing_api(self, data_type: str, purpose: str, 
                                   data_subjects: List[str], retention_period: int = None) -> Dict[str, Any]:
        """API endpoint for registering data processing"""
        try:
            activity_id = self.compliance_manager.register_data_processing(
                data_type, purpose, data_subjects, retention_period
            )
            return {
                'success': True,
                'activity_id': activity_id,
                'message': 'Data processing activity registered successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to register data processing activity'
            }
    
    def record_consent_api(self, user_id: str, consent_types: List[str], 
                          granted: bool = True) -> Dict[str, Any]:
        """API endpoint for recording consent"""
        try:
            consent_id = self.compliance_manager.record_consent(
                user_id, consent_types, granted
            )
            return {
                'success': True,
                'consent_id': consent_id,
                'message': f'Consent {"granted" if granted else "revoked"} successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to record consent'
            }
    
    def submit_dsr_api(self, request_type: str, user_id: str, 
                      details: Dict[str, Any] = None) -> Dict[str, Any]:
        """API endpoint for submitting data subject requests"""
        try:
            # Convert string to enum
            request_type_enum = DataSubjectRequestType(request_type.lower())
            request_id = self.compliance_manager.handle_data_subject_request(
                request_type_enum, user_id, details
            )
            return {
                'success': True,
                'request_id': request_id,
                'message': 'Data subject request submitted successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to submit data subject request'
            }
    
    def process_dsr_api(self, request_id: str) -> Dict[str, Any]:
        """API endpoint for processing data subject requests"""
        try:
            result = self.compliance_manager.process_data_subject_request(request_id)
            return {
                'success': True,
                'result': result,
                'message': 'Data subject request processed successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to process data subject request'
            }
    
    def get_privacy_report_api(self, user_id: str = None) -> Dict[str, Any]:
        """API endpoint for generating privacy reports"""
        try:
            report = self.compliance_manager.generate_privacy_report(user_id)
            return {
                'success': True,
                'report': report,
                'message': 'Privacy report generated successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to generate privacy report'
            }
    
    def get_compliance_status_api(self) -> Dict[str, Any]:
        """API endpoint for getting compliance status"""
        try:
            report = self.compliance_manager.generate_privacy_report()
            return {
                'success': True,
                'status': report.get('compliance_status', {}),
                'message': 'Compliance status retrieved successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve compliance status'
            }

# Example usage and testing
if __name__ == "__main__":
    # Create compliance manager
    compliance_manager = ComplianceManager()
    
    # Register data processing
    activity_id = compliance_manager.register_data_processing(
        data_type="security_logs",
        purpose="threat_detection",
        data_subjects=["end_users"],
        retention_period=365  # 1 year
    )
    print(f"Registered data processing activity: {activity_id}")
    
    # Record consent
    consent_id = compliance_manager.record_consent(
        user_id="user-001",
        consent_types=["essential", "analytics"],
        granted=True
    )
    print(f"Recorded consent: {consent_id}")
    
    # Handle DSR request
    request_id = compliance_manager.handle_data_subject_request(
        request_type=DataSubjectRequestType.RIGHT_TO_ACCESS,
        user_id="user-001",
        details={"reason": "user_request"}
    )
    print(f"Handled DSR request: {request_id}")
    
    # Process DSR request
    result = compliance_manager.process_data_subject_request(request_id)
    print(f"Processed DSR request: {result}")
    
    # Generate privacy report
    report = compliance_manager.generate_privacy_report()
    print(f"Privacy report: {json.dumps(report, indent=2)}")
    
    # Auto-delete expired data
    deletion_stats = compliance_manager.auto_delete_expired_data()
    print(f"Auto-deletion stats: {deletion_stats}")