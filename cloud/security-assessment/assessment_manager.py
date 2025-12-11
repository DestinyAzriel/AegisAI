#!/usr/bin/env python3
"""
AegisAI Third-Party Security Assessment Manager

This module manages third-party security assessments, vulnerability scanning,
and preparation for security certifications.
"""

import json
import logging
import hashlib
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum
import asyncio
import subprocess
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AssessmentType(Enum):
    """Types of security assessments"""
    VULNERABILITY_SCAN = "vulnerability_scan"
    PENETRATION_TEST = "penetration_test"
    CODE_REVIEW = "code_review"
    INFRASTRUCTURE_AUDIT = "infrastructure_audit"
    COMPLIANCE_AUDIT = "compliance_audit"

class AssessmentStatus(Enum):
    """Assessment statuses"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class SecurityAssessmentManager:
    """Manages third-party security assessments and vulnerability management"""
    
    def __init__(self, config_path: str = "config/assessment_config.json"):
        """
        Initialize security assessment manager
        
        Args:
            config_path: Path to assessment configuration file
        """
        self.config_path = config_path
        self.config = self._load_configuration()
        self.assessments = {}
        self.findings = {}
        self.remediation_tasks = {}
        
        logger.info("Security assessment manager initialized")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load assessment configuration from file"""
        try:
            # Default configuration
            default_config = {
                "tools": {
                    "nmap": {
                        "enabled": True,
                        "path": "/usr/bin/nmap",
                        "arguments": "-sV -sC -p-"
                    },
                    "owasp_zap": {
                        "enabled": True,
                        "path": "/usr/bin/zap-cli",
                        "arguments": "scan -r"
                    },
                    "bandit": {
                        "enabled": True,
                        "path": "/usr/bin/bandit",
                        "arguments": "-r ."
                    }
                },
                "schedules": {
                    "vulnerability_scans": "weekly",
                    "penetration_tests": "quarterly",
                    "code_reviews": "on_commit"
                },
                "remediation": {
                    "auto_assign": True,
                    "priority_threshold": "high",
                    "sla_days": {
                        "critical": 1,
                        "high": 3,
                        "medium": 7,
                        "low": 30
                    }
                },
                "reporting": {
                    "format": "json",
                    "storage_path": "/var/assessments/reports",
                    "retention_days": 365
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
                os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
                with open(self.config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                logger.info(f"Created default assessment config at {self.config_path}")
            
            return config
            
        except Exception as e:
            logger.error(f"Error loading assessment configuration: {e}")
            return {}
    
    def schedule_assessment(self, assessment_type: AssessmentType, 
                          target: str, schedule: str = None, 
                          priority: str = "medium") -> str:
        """
        Schedule a security assessment
        
        Args:
            assessment_type: Type of assessment
            target: Target of assessment (IP, domain, code path, etc.)
            schedule: When to run assessment (cron format or "immediate")
            priority: Priority level (low, medium, high, critical)
            
        Returns:
            str: Assessment ID
        """
        assessment_id = f"AST-{int(datetime.now().timestamp())}"
        
        # Create assessment record
        self.assessments[assessment_id] = {
            'id': assessment_id,
            'type': assessment_type.value,
            'target': target,
            'schedule': schedule or "immediate",
            'priority': priority,
            'status': AssessmentStatus.PENDING.value,
            'created_at': datetime.now().isoformat(),
            'scheduled_at': datetime.now().isoformat(),
            'started_at': None,
            'completed_at': None,
            'findings': []
        }
        
        # Log the scheduling
        self._log_assessment_event('assessment_scheduled', {
            'assessment_id': assessment_id,
            'type': assessment_type.value,
            'target': target
        })
        
        logger.info(f"Scheduled {assessment_type.value} assessment: {assessment_id}")
        
        # If immediate, start the assessment
        if schedule == "immediate":
            asyncio.create_task(self._run_assessment(assessment_id))
        
        return assessment_id
    
    async def _run_assessment(self, assessment_id: str):
        """
        Run a security assessment
        
        Args:
            assessment_id: Assessment identifier
        """
        if assessment_id not in self.assessments:
            logger.error(f"Assessment {assessment_id} not found")
            return
        
        assessment = self.assessments[assessment_id]
        assessment_type = AssessmentType(assessment['type'])
        
        # Update status
        assessment['status'] = AssessmentStatus.IN_PROGRESS.value
        assessment['started_at'] = datetime.now().isoformat()
        
        # Log the start
        self._log_assessment_event('assessment_started', {
            'assessment_id': assessment_id,
            'type': assessment_type.value
        })
        
        try:
            # Run assessment based on type
            findings = []
            if assessment_type == AssessmentType.VULNERABILITY_SCAN:
                findings = await self._run_vulnerability_scan(assessment['target'])
            elif assessment_type == AssessmentType.PENETRATION_TEST:
                findings = await self._run_penetration_test(assessment['target'])
            elif assessment_type == AssessmentType.CODE_REVIEW:
                findings = await self._run_code_review(assessment['target'])
            elif assessment_type == AssessmentType.INFRASTRUCTURE_AUDIT:
                findings = await self._run_infrastructure_audit(assessment['target'])
            elif assessment_type == AssessmentType.COMPLIANCE_AUDIT:
                findings = await self._run_compliance_audit(assessment['target'])
            
            # Store findings
            assessment['findings'] = findings
            assessment['status'] = AssessmentStatus.COMPLETED.value
            assessment['completed_at'] = datetime.now().isoformat()
            
            # Create remediation tasks for findings
            for finding in findings:
                self._create_remediation_task(finding, assessment_id)
            
            # Log the completion
            self._log_assessment_event('assessment_completed', {
                'assessment_id': assessment_id,
                'type': assessment_type.value,
                'finding_count': len(findings)
            })
            
            logger.info(f"Completed {assessment_type.value} assessment: {assessment_id}")
            
        except Exception as e:
            logger.error(f"Error running assessment {assessment_id}: {e}")
            assessment['status'] = AssessmentStatus.FAILED.value
            assessment['completed_at'] = datetime.now().isoformat()
            
            # Log the failure
            self._log_assessment_event('assessment_failed', {
                'assessment_id': assessment_id,
                'type': assessment_type.value,
                'error': str(e)
            })
    
    async def _run_vulnerability_scan(self, target: str) -> List[Dict[str, Any]]:
        """
        Run vulnerability scan using Nmap and other tools
        
        Args:
            target: Target to scan (IP, domain, network range)
            
        Returns:
            List: Vulnerability findings
        """
        findings = []
        
        # Check if Nmap is enabled and available
        nmap_config = self.config.get('tools', {}).get('nmap', {})
        if nmap_config.get('enabled', False):
            try:
                # Run Nmap scan
                cmd = [nmap_config['path']] + nmap_config['arguments'].split() + [target]
                logger.info(f"Running Nmap scan: {' '.join(cmd)}")
                
                # In a real implementation, this would actually run the scan
                # For now, we'll simulate findings
                findings.extend([
                    {
                        'id': f"FND-{int(datetime.now().timestamp())}-001",
                        'type': 'vulnerability',
                        'severity': 'high',
                        'title': 'Open SSH Port',
                        'description': 'SSH service is running on port 22',
                        'recommendation': 'Ensure SSH is properly configured with key-based authentication',
                        'cvss_score': 5.0,
                        'detected_at': datetime.now().isoformat()
                    },
                    {
                        'id': f"FND-{int(datetime.now().timestamp())}-002",
                        'type': 'vulnerability',
                        'severity': 'medium',
                        'title': 'Open HTTP Port',
                        'description': 'HTTP service is running on port 80',
                        'recommendation': 'Consider redirecting HTTP to HTTPS',
                        'cvss_score': 4.3,
                        'detected_at': datetime.now().isoformat()
                    }
                ])
                
            except Exception as e:
                logger.error(f"Error running Nmap scan: {e}")
        
        return findings
    
    async def _run_penetration_test(self, target: str) -> List[Dict[str, Any]]:
        """
        Run penetration test
        
        Args:
            target: Target to test
            
        Returns:
            List: Penetration test findings
        """
        # In a real implementation, this would run actual penetration testing tools
        # For now, we'll simulate findings
        return [
            {
                'id': f"FND-{int(datetime.now().timestamp())}-003",
                'type': 'penetration_test',
                'severity': 'critical',
                'title': 'Weak Password Found',
                'description': 'Default password detected on administrative interface',
                'recommendation': 'Change default passwords immediately and implement strong password policy',
                'cvss_score': 9.8,
                'detected_at': datetime.now().isoformat()
            }
        ]
    
    async def _run_code_review(self, target: str) -> List[Dict[str, Any]]:
        """
        Run code security review
        
        Args:
            target: Code path to review
            
        Returns:
            List: Code review findings
        """
        findings = []
        
        # Check if Bandit is enabled and available for Python code review
        bandit_config = self.config.get('tools', {}).get('bandit', {})
        if bandit_config.get('enabled', False):
            try:
                # Run Bandit scan
                cmd = [bandit_config['path']] + bandit_config['arguments'].split() + [target]
                logger.info(f"Running Bandit scan: {' '.join(cmd)}")
                
                # In a real implementation, this would actually run the scan
                # For now, we'll simulate findings
                findings.extend([
                    {
                        'id': f"FND-{int(datetime.now().timestamp())}-004",
                        'type': 'code_review',
                        'severity': 'high',
                        'title': 'Hardcoded Password',
                        'description': 'Password found in source code',
                        'recommendation': 'Use environment variables or secure vault for credentials',
                        'cvss_score': 7.5,
                        'detected_at': datetime.now().isoformat()
                    },
                    {
                        'id': f"FND-{int(datetime.now().timestamp())}-005",
                        'type': 'code_review',
                        'severity': 'medium',
                        'title': 'Weak Cryptographic Algorithm',
                        'description': 'MD5 hash function used',
                        'recommendation': 'Replace MD5 with SHA-256 or stronger algorithm',
                        'cvss_score': 5.0,
                        'detected_at': datetime.now().isoformat()
                    }
                ])
                
            except Exception as e:
                logger.error(f"Error running Bandit scan: {e}")
        
        return findings
    
    async def _run_infrastructure_audit(self, target: str) -> List[Dict[str, Any]]:
        """
        Run infrastructure security audit
        
        Args:
            target: Infrastructure to audit
            
        Returns:
            List: Infrastructure audit findings
        """
        # In a real implementation, this would audit infrastructure configuration
        # For now, we'll simulate findings
        return [
            {
                'id': f"FND-{int(datetime.now().timestamp())}-006",
                'type': 'infrastructure_audit',
                'severity': 'high',
                'title': 'Unencrypted Data Storage',
                'description': 'Database connections not using SSL/TLS',
                'recommendation': 'Enable SSL/TLS for all database connections',
                'cvss_score': 6.5,
                'detected_at': datetime.now().isoformat()
            }
        ]
    
    async def _run_compliance_audit(self, target: str) -> List[Dict[str, Any]]:
        """
        Run compliance audit
        
        Args:
            target: System to audit for compliance
            
        Returns:
            List: Compliance audit findings
        """
        # In a real implementation, this would check compliance with standards
        # For now, we'll simulate findings
        return [
            {
                'id': f"FND-{int(datetime.now().timestamp())}-007",
                'type': 'compliance_audit',
                'severity': 'medium',
                'title': 'Missing Data Retention Policy',
                'description': 'No documented data retention policy found',
                'recommendation': 'Create and implement data retention policy',
                'cvss_score': 3.0,
                'detected_at': datetime.now().isoformat()
            }
        ]
    
    def _create_remediation_task(self, finding: Dict[str, Any], assessment_id: str):
        """
        Create remediation task for a security finding
        
        Args:
            finding: Security finding
            assessment_id: Assessment identifier
        """
        task_id = f"RTK-{int(datetime.now().timestamp())}"
        
        # Determine priority based on severity
        severity = finding.get('severity', 'low')
        priority = 'low'
        if severity == 'critical':
            priority = 'critical'
        elif severity == 'high':
            priority = 'high'
        elif severity == 'medium':
            priority = 'medium'
        
        # Get SLA days from config
        sla_days = self.config.get('remediation', {}).get('sla_days', {})
        due_days = sla_days.get(severity, 30)
        due_date = datetime.now() + timedelta(days=due_days)
        
        # Create remediation task
        self.remediation_tasks[task_id] = {
            'id': task_id,
            'finding_id': finding['id'],
            'assessment_id': assessment_id,
            'title': finding.get('title', 'Security Remediation Task'),
            'description': finding.get('description', ''),
            'recommendation': finding.get('recommendation', ''),
            'severity': severity,
            'priority': priority,
            'status': 'open',
            'assigned_to': None,
            'created_at': datetime.now().isoformat(),
            'due_date': due_date.isoformat(),
            'completed_at': None
        }
        
        # Log the task creation
        self._log_assessment_event('remediation_task_created', {
            'task_id': task_id,
            'finding_id': finding['id'],
            'severity': severity,
            'priority': priority
        })
        
        logger.info(f"Created remediation task: {task_id}")
    
    def get_assessment_status(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of an assessment
        
        Args:
            assessment_id: Assessment identifier
            
        Returns:
            Dict: Assessment status information or None if not found
        """
        return self.assessments.get(assessment_id)
    
    def get_all_assessments(self) -> List[Dict[str, Any]]:
        """
        Get all assessments
        
        Returns:
            List: All assessments
        """
        return list(self.assessments.values())
    
    def get_findings(self, assessment_id: str = None) -> List[Dict[str, Any]]:
        """
        Get security findings
        
        Args:
            assessment_id: Optional assessment ID to filter findings
            
        Returns:
            List: Security findings
        """
        if assessment_id:
            if assessment_id in self.assessments:
                return self.assessments[assessment_id].get('findings', [])
            else:
                return []
        else:
            # Return all findings from all assessments
            all_findings = []
            for assessment in self.assessments.values():
                all_findings.extend(assessment.get('findings', []))
            return all_findings
    
    def get_remediation_tasks(self, status: str = None) -> List[Dict[str, Any]]:
        """
        Get remediation tasks
        
        Args:
            status: Optional status to filter tasks
            
        Returns:
            List: Remediation tasks
        """
        if status:
            return [task for task in self.remediation_tasks.values() if task['status'] == status]
        else:
            return list(self.remediation_tasks.values())
    
    def update_remediation_task(self, task_id: str, status: str = None, 
                              assigned_to: str = None) -> bool:
        """
        Update remediation task
        
        Args:
            task_id: Task identifier
            status: New status
            assigned_to: User assigned to task
            
        Returns:
            bool: True if successful, False otherwise
        """
        if task_id not in self.remediation_tasks:
            return False
        
        task = self.remediation_tasks[task_id]
        
        # Update fields if provided
        if status:
            task['status'] = status
            if status == 'completed':
                task['completed_at'] = datetime.now().isoformat()
        
        if assigned_to:
            task['assigned_to'] = assigned_to
        
        # Log the update
        self._log_assessment_event('remediation_task_updated', {
            'task_id': task_id,
            'status': status,
            'assigned_to': assigned_to
        })
        
        logger.info(f"Updated remediation task: {task_id}")
        return True
    
    def generate_assessment_report(self, assessment_id: str = None) -> Dict[str, Any]:
        """
        Generate security assessment report
        
        Args:
            assessment_id: Optional specific assessment ID
            
        Returns:
            Dict: Assessment report
        """
        if assessment_id:
            # Generate report for specific assessment
            if assessment_id not in self.assessments:
                raise ValueError(f"Assessment {assessment_id} not found")
            
            assessment = self.assessments[assessment_id]
            findings = assessment.get('findings', [])
        else:
            # Generate summary report for all assessments
            assessment = None
            findings = self.get_findings()
        
        # Categorize findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Get remediation tasks
        open_tasks = self.get_remediation_tasks('open')
        completed_tasks = self.get_remediation_tasks('completed')
        
        report = {
            'report_type': 'specific_assessment' if assessment_id else 'summary',
            'generated_at': datetime.now().isoformat(),
            'assessment_info': assessment,
            'total_findings': len(findings),
            'findings_by_severity': severity_counts,
            'findings': findings,
            'remediation_summary': {
                'open_tasks': len(open_tasks),
                'completed_tasks': len(completed_tasks),
                'total_tasks': len(self.remediation_tasks)
            },
            'risk_score': self._calculate_risk_score(findings)
        }
        
        return report
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """
        Calculate overall risk score based on findings
        
        Args:
            findings: List of security findings
            
        Returns:
            float: Risk score (0-10)
        """
        if not findings:
            return 0.0
        
        # Weighted scoring based on severity
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total_score = 0
        max_possible_score = 0
        
        for finding in findings:
            severity = finding.get('severity', 'low')
            weight = severity_weights.get(severity, 1)
            total_score += weight
            max_possible_score += 10  # Max weight per finding
        
        # Normalize to 0-10 scale
        if max_possible_score > 0:
            return (total_score / max_possible_score) * 10
        else:
            return 0.0
    
    def _log_assessment_event(self, event_type: str, details: Dict[str, Any]):
        """
        Log assessment-related events
        
        Args:
            event_type: Type of assessment event
            details: Event details
        """
        # In a real implementation, this would log to a persistent store
        logger.info(f"Assessment Event: {event_type} - {details}")
    
    def export_assessment_data(self, format: str = 'json') -> str:
        """
        Export assessment data for third-party review
        
        Args:
            format: Export format (json, csv)
            
        Returns:
            str: Exported data
        """
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'assessments': self.assessments,
            'findings': self.get_findings(),
            'remediation_tasks': self.remediation_tasks,
            'configuration': self.config
        }
        
        if format.lower() == 'json':
            return json.dumps(export_data, indent=2)
        else:
            # For other formats, return JSON as default
            return json.dumps(export_data, indent=2)

# Assessment API for integration with other services
class AssessmentAPI:
    """API for security assessment services"""
    
    def __init__(self, assessment_manager: SecurityAssessmentManager):
        """
        Initialize assessment API
        
        Args:
            assessment_manager: Assessment manager instance
        """
        self.assessment_manager = assessment_manager
    
    def schedule_assessment_api(self, assessment_type: str, target: str, 
                              schedule: str = None, priority: str = "medium") -> Dict[str, Any]:
        """API endpoint for scheduling assessments"""
        try:
            # Convert string to enum
            assessment_type_enum = AssessmentType(assessment_type.lower())
            assessment_id = self.assessment_manager.schedule_assessment(
                assessment_type_enum, target, schedule, priority
            )
            return {
                'success': True,
                'assessment_id': assessment_id,
                'message': 'Assessment scheduled successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to schedule assessment'
            }
    
    def get_assessment_status_api(self, assessment_id: str) -> Dict[str, Any]:
        """API endpoint for getting assessment status"""
        try:
            status = self.assessment_manager.get_assessment_status(assessment_id)
            if status:
                return {
                    'success': True,
                    'status': status,
                    'message': 'Assessment status retrieved successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Assessment not found',
                    'message': f'Assessment {assessment_id} not found'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve assessment status'
            }
    
    def get_findings_api(self, assessment_id: str = None) -> Dict[str, Any]:
        """API endpoint for getting security findings"""
        try:
            findings = self.assessment_manager.get_findings(assessment_id)
            return {
                'success': True,
                'findings': findings,
                'count': len(findings),
                'message': 'Findings retrieved successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to retrieve findings'
            }
    
    def update_remediation_task_api(self, task_id: str, status: str = None, 
                                  assigned_to: str = None) -> Dict[str, Any]:
        """API endpoint for updating remediation tasks"""
        try:
            success = self.assessment_manager.update_remediation_task(
                task_id, status, assigned_to
            )
            if success:
                return {
                    'success': True,
                    'message': 'Remediation task updated successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Task not found',
                    'message': f'Remediation task {task_id} not found'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to update remediation task'
            }
    
    def generate_report_api(self, assessment_id: str = None) -> Dict[str, Any]:
        """API endpoint for generating assessment reports"""
        try:
            report = self.assessment_manager.generate_assessment_report(assessment_id)
            return {
                'success': True,
                'report': report,
                'message': 'Assessment report generated successfully'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to generate assessment report'
            }

# Example usage and testing
if __name__ == "__main__":
    # Create assessment manager
    assessment_manager = SecurityAssessmentManager()
    
    # Schedule a vulnerability scan
    assessment_id = assessment_manager.schedule_assessment(
        assessment_type=AssessmentType.VULNERABILITY_SCAN,
        target="192.168.1.0/24",
        schedule="immediate",
        priority="high"
    )
    print(f"Scheduled vulnerability scan: {assessment_id}")
    
    # Schedule a code review
    code_review_id = assessment_manager.schedule_assessment(
        assessment_type=AssessmentType.CODE_REVIEW,
        target="./src",
        schedule="immediate",
        priority="medium"
    )
    print(f"Scheduled code review: {code_review_id}")
    
    # Wait for async operations to complete
    asyncio.run(asyncio.sleep(5))
    
    # Get assessment status
    status = assessment_manager.get_assessment_status(assessment_id)
    print(f"Assessment status: {status['status']}")
    
    # Get findings
    findings = assessment_manager.get_findings()
    print(f"Total findings: {len(findings)}")
    
    # Generate report
    report = assessment_manager.generate_assessment_report()
    print(f"Risk score: {report['risk_score']}")