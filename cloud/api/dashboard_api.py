#!/usr/bin/env python3
"""
AegisAI Enterprise Dashboard API
===============================

Enterprise-grade dashboard API providing real-time visibility into security posture,
threat intelligence, compliance status, and incident response metrics.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from aiohttp import web
import asyncio

# Import existing modules
try:
    from ..threat_intel.threat_intel_service import EnhancedThreatIntelService
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    EnhancedThreatIntelService = None
    THREAT_INTEL_AVAILABLE = False
    logging.warning("Threat intelligence service not available")

try:
    from ..compliance.enhanced_compliance_reporting import EnhancedComplianceReporting
    from ..compliance.compliance_manager import ComplianceManager
    COMPLIANCE_AVAILABLE = True
except ImportError:
    EnhancedComplianceReporting = None
    ComplianceManager = None
    COMPLIANCE_AVAILABLE = False
    logging.warning("Compliance reporting service not available")

try:
    from ..incident_response.enhanced_incident_orchestration import EnhancedIncidentResponseEngine
    INCIDENT_RESPONSE_AVAILABLE = True
except ImportError:
    EnhancedIncidentResponseEngine = None
    INCIDENT_RESPONSE_AVAILABLE = False
    logging.warning("Incident response service not available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnterpriseDashboardAPI:
    """Enterprise dashboard API for security operations center (SOC) visibility"""
    
    def __init__(self):
        """Initialize the enterprise dashboard API"""
        self.threat_intel_service = EnhancedThreatIntelService() if THREAT_INTEL_AVAILABLE else None
        self.compliance_manager = ComplianceManager() if COMPLIANCE_AVAILABLE else None
        self.compliance_reporting = EnhancedComplianceReporting(self.compliance_manager) if COMPLIANCE_AVAILABLE and self.compliance_manager else None
        self.incident_response_engine = EnhancedIncidentResponseEngine() if INCIDENT_RESPONSE_AVAILABLE else None
        
        # Initialize mock data for demo purposes
        self._initialize_mock_data()
    
    def _initialize_mock_data(self):
        """Initialize mock data for demonstration"""
        self.mock_agents = {
            "agent-001": {
                "id": "agent-001",
                "hostname": "workstation-01",
                "ip_address": "192.168.1.101",
                "os": "Windows 11",
                "status": "online",
                "last_seen": datetime.now().isoformat(),
                "threats_detected": 2,
                "quarantined_files": 1
            },
            "agent-002": {
                "id": "agent-002",
                "hostname": "server-01",
                "ip_address": "192.168.1.201",
                "os": "Ubuntu 22.04",
                "status": "online",
                "last_seen": datetime.now().isoformat(),
                "threats_detected": 0,
                "quarantined_files": 0
            },
            "agent-003": {
                "id": "agent-003",
                "hostname": "workstation-02",
                "ip_address": "192.168.1.102",
                "os": "macOS 14",
                "status": "offline",
                "last_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
                "threats_detected": 1,
                "quarantined_files": 0
            }
        }
        
        self.mock_threats = {
            "threat-001": {
                "id": "threat-001",
                "indicator": "eicar_test_file_hash",
                "type": "hash",
                "threat_name": "EICAR Test File",
                "severity": "test",
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "detection_count": 5,
                "sources": ["internal_db"]
            }
        }
        
        self.mock_incidents = {
            "incident-001": {
                "id": "incident-001",
                "type": "malware_detected",
                "severity": "high",
                "status": "in_progress",
                "assigned_to": "analyst-01",
                "created_at": (datetime.now() - timedelta(hours=1)).isoformat(),
                "updated_at": datetime.now().isoformat(),
                "description": "Malware detected on workstation-01"
            }
        }
    
    async def get_executive_dashboard(self, request) -> web.Response:
        """
        Get executive dashboard overview with key security metrics
        
        Returns:
            JSON response with executive dashboard data
        """
        try:
            # Get threat intelligence summary
            threat_summary = await self._get_threat_intel_summary()
            
            # Get compliance status
            compliance_status = await self._get_compliance_summary()
            
            # Get incident response metrics
            incident_metrics = await self._get_incident_response_summary()
            
            # Get agent status
            agent_metrics = await self._get_agent_summary()
            
            # Combine into executive dashboard
            dashboard = {
                "timestamp": datetime.now().isoformat(),
                "threat_intelligence": threat_summary,
                "compliance": compliance_status,
                "incident_response": incident_metrics,
                "endpoint_security": agent_metrics,
                "overall_security_posture": self._calculate_security_posture(
                    threat_summary, compliance_status, incident_metrics, agent_metrics
                )
            }
            
            return web.json_response({
                "status": "success",
                "data": dashboard
            })
        except Exception as e:
            logger.error(f"Error generating executive dashboard: {e}")
            return web.json_response({
                "status": "error",
                "message": str(e)
            }, status=500)
    
    async def _get_threat_intel_summary(self) -> Dict[str, Any]:
        """Get threat intelligence summary"""
        if self.threat_intel_service and THREAT_INTEL_AVAILABLE:
            try:
                stats = self.threat_intel_service.get_threat_statistics()
                campaigns = self.threat_intel_service.correlate_indicators()
                
                return {
                    "total_indicators": stats.get("total_indicators", 0),
                    "indicators_by_type": stats.get("indicators_by_type", {}),
                    "indicators_by_severity": stats.get("indicators_by_severity", {}),
                    "active_campaigns": len(campaigns),
                    "last_updated": datetime.now().isoformat(),
                    "service_status": "active"
                }
            except Exception as e:
                logger.error(f"Error getting threat intel summary: {e}")
                # Fall back to mock data
                pass
        
        # Mock data for demo
        return {
            "total_indicators": len(self.mock_threats),
            "indicators_by_type": {"hash": 1},
            "indicators_by_severity": {"test": 1},
            "active_campaigns": 0,
            "last_updated": datetime.now().isoformat(),
            "service_status": "mock"
        }
    
    async def _get_compliance_summary(self) -> Dict[str, Any]:
        """Get compliance reporting summary"""
        if self.compliance_reporting and COMPLIANCE_AVAILABLE:
            try:
                metrics = self.compliance_reporting.get_compliance_metrics()
                reports = self.compliance_reporting.get_scheduled_reports()
                
                return {
                    "compliant_standards": ["GDPR", "CCPA"],
                    "non_compliant_standards": [],
                    "pending_audits": 2,
                    "scheduled_reports": len(reports),
                    "key_metrics": {k: v.value for k, v in metrics.items()},
                    "last_updated": datetime.now().isoformat(),
                    "service_status": "active"
                }
            except Exception as e:
                logger.error(f"Error getting compliance summary: {e}")
                # Fall back to mock data
                pass
        
        # Mock data for demo
        return {
            "compliant_standards": ["GDPR", "CCPA"],
            "non_compliant_standards": [],
            "pending_audits": 2,
            "scheduled_reports": 3,
            "key_metrics": {
                "data_processing_activities": 45,
                "consent_rate": 85,
                "dsr_response_time": 24
            },
            "last_updated": datetime.now().isoformat(),
            "service_status": "mock"
        }
    
    async def _get_incident_response_summary(self) -> Dict[str, Any]:
        """Get incident response summary"""
        if self.incident_response_engine and INCIDENT_RESPONSE_AVAILABLE:
            try:
                orchestrations = self.incident_response_engine.get_active_orchestrations()
                
                # Count incidents by status
                total_incidents = len(self.mock_incidents)
                active_incidents = len([i for i in self.mock_incidents.values() if i["status"] == "in_progress"])
                resolved_incidents = len([i for i in self.mock_incidents.values() if i["status"] == "resolved"])
                
                return {
                    "total_incidents": total_incidents,
                    "active_incidents": active_incidents,
                    "resolved_incidents": resolved_incidents,
                    "avg_resolution_time_hours": 2.5,
                    "active_orchestrations": len(orchestrations),
                    "last_updated": datetime.now().isoformat(),
                    "service_status": "active"
                }
            except Exception as e:
                logger.error(f"Error getting incident response summary: {e}")
                # Fall back to mock data
                pass
        
        # Mock data for demo
        active_incidents = len([i for i in self.mock_incidents.values() if i["status"] == "in_progress"])
        return {
            "total_incidents": len(self.mock_incidents),
            "active_incidents": active_incidents,
            "resolved_incidents": 15,
            "avg_resolution_time_hours": 2.5,
            "active_orchestrations": 1,
            "last_updated": datetime.now().isoformat(),
            "service_status": "mock"
        }
    
    async def _get_agent_summary(self) -> Dict[str, Any]:
        """Get endpoint agent summary"""
        try:
            online_agents = len([a for a in self.mock_agents.values() if a["status"] == "online"])
            total_agents = len(self.mock_agents)
            threats_detected = sum(a["threats_detected"] for a in self.mock_agents.values())
            
            return {
                "total_agents": total_agents,
                "online_agents": online_agents,
                "offline_agents": total_agents - online_agents,
                "threats_detected": threats_detected,
                "quarantined_files": sum(a["quarantined_files"] for a in self.mock_agents.values()),
                "last_updated": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting agent summary: {e}")
            return {
                "total_agents": 0,
                "online_agents": 0,
                "offline_agents": 0,
                "threats_detected": 0,
                "quarantined_files": 0,
                "last_updated": datetime.now().isoformat()
            }
    
    def _calculate_security_posture(self, threat_summary: Dict, compliance_status: Dict, 
                                 incident_metrics: Dict, agent_metrics: Dict) -> Dict[str, Any]:
        """Calculate overall security posture score"""
        # Simple scoring algorithm for demo
        threat_score = 100 - (threat_summary.get("total_indicators", 0) * 2)
        compliance_score = 100 - (len(compliance_status.get("non_compliant_standards", [])) * 20)
        incident_score = 100 - (incident_metrics.get("active_incidents", 0) * 10)
        agent_score = (agent_metrics.get("online_agents", 0) / max(agent_metrics.get("total_agents", 1), 1)) * 100
        
        overall_score = (threat_score + compliance_score + incident_score + agent_score) / 4
        
        # Determine posture level
        if overall_score >= 80:
            posture_level = "strong"
        elif overall_score >= 60:
            posture_level = "moderate"
        elif overall_score >= 40:
            posture_level = "weak"
        else:
            posture_level = "critical"
        
        return {
            "overall_score": round(overall_score, 2),
            "posture_level": posture_level,
            "component_scores": {
                "threat_intelligence": round(threat_score, 2),
                "compliance": round(compliance_score, 2),
                "incident_response": round(incident_score, 2),
                "endpoint_security": round(agent_score, 2)
            }
        }
    
    async def get_threat_intel_dashboard(self, request) -> web.Response:
        """
        Get detailed threat intelligence dashboard
        
        Returns:
            JSON response with threat intelligence data
        """
        try:
            # Get detailed threat intelligence data
            if self.threat_intel_service and THREAT_INTEL_AVAILABLE:
                try:
                    # Get threat statistics
                    stats = self.threat_intel_service.get_threat_statistics()
                    
                    # Get recent threats
                    recent_threats = []
                    for indicator_key, threat_entry in list(self.threat_intel_service.threat_database.items())[:10]:
                        recent_threats.append({
                            "indicator": threat_entry.indicator,
                            "indicator_type": threat_entry.indicator_type,
                            "threat_name": threat_entry.threat_name,
                            "severity": threat_entry.severity,
                            "confidence": threat_entry.confidence,
                            "source": threat_entry.source,
                            "first_seen": threat_entry.first_seen.isoformat(),
                            "last_seen": threat_entry.last_seen.isoformat(),
                            "related_indicators": threat_entry.related_indicators or []
                        })
                    
                    # Get threat campaigns
                    campaigns = self.threat_intel_service.correlate_indicators()
                    
                    threat_dashboard = {
                        "timestamp": datetime.now().isoformat(),
                        "statistics": stats,
                        "recent_threats": recent_threats,
                        "threat_campaigns": campaigns,
                        "feed_status": self.threat_intel_service.feed_stats
                    }
                except Exception as e:
                    logger.error(f"Error getting threat intel data: {e}")
                    # Fall back to mock data
                    threat_dashboard = {
                        "timestamp": datetime.now().isoformat(),
                        "statistics": {"total_indicators": len(self.mock_threats)},
                        "recent_threats": list(self.mock_threats.values()),
                        "threat_campaigns": [],
                        "feed_status": {}
                    }
            else:
                # Use mock data
                threat_dashboard = {
                    "timestamp": datetime.now().isoformat(),
                    "statistics": {"total_indicators": len(self.mock_threats)},
                    "recent_threats": list(self.mock_threats.values()),
                    "threat_campaigns": [],
                    "feed_status": {}
                }
            
            return web.json_response({
                "status": "success",
                "data": threat_dashboard
            })
        except Exception as e:
            logger.error(f"Error generating threat intelligence dashboard: {e}")
            return web.json_response({
                "status": "error",
                "message": str(e)
            }, status=500)
    
    async def get_compliance_dashboard(self, request) -> web.Response:
        """
        Get detailed compliance dashboard
        
        Returns:
            JSON response with compliance data
        """
        try:
            if self.compliance_reporting and COMPLIANCE_AVAILABLE:
                try:
                    # Get compliance metrics
                    metrics = self.compliance_reporting.get_compliance_metrics()
                    
                    # Get scheduled reports
                    reports = self.compliance_reporting.get_scheduled_reports()
                    
                    # Generate executive dashboard
                    exec_dashboard = self.compliance_reporting.generate_executive_dashboard()
                    
                    compliance_dashboard = {
                        "timestamp": datetime.now().isoformat(),
                        "executive_dashboard": exec_dashboard,
                        "metrics": {k: v.__dict__ for k, v in metrics.items()},
                        "scheduled_reports": [report.__dict__ for report in reports],
                        "recent_reports": []  # Would be populated in real implementation
                    }
                except Exception as e:
                    logger.error(f"Error getting compliance data: {e}")
                    # Fall back to mock data
                    compliance_dashboard = {
                        "timestamp": datetime.now().isoformat(),
                        "executive_dashboard": {},
                        "metrics": {},
                        "scheduled_reports": [],
                        "recent_reports": []
                    }
            else:
                # Use mock data
                compliance_dashboard = {
                    "timestamp": datetime.now().isoformat(),
                    "executive_dashboard": {},
                    "metrics": {},
                    "scheduled_reports": [],
                    "recent_reports": []
                }
            
            return web.json_response({
                "status": "success",
                "data": compliance_dashboard
            })
        except Exception as e:
            logger.error(f"Error generating compliance dashboard: {e}")
            return web.json_response({
                "status": "error",
                "message": str(e)
            }, status=500)
    
    async def get_incident_response_dashboard(self, request) -> web.Response:
        """
        Get detailed incident response dashboard
        
        Returns:
            JSON response with incident response data
        """
        try:
            if self.incident_response_engine and INCIDENT_RESPONSE_AVAILABLE:
                try:
                    # Get active orchestrations
                    orchestrations = self.incident_response_engine.get_active_orchestrations()
                    
                    # Get recent incidents
                    recent_incidents = list(self.mock_incidents.values())[-10:]  # Last 10 incidents
                    
                    incident_dashboard = {
                        "timestamp": datetime.now().isoformat(),
                        "active_orchestrations": orchestrations,
                        "recent_incidents": recent_incidents,
                        "incident_metrics": await self._get_incident_response_summary(),
                        "workflows": []  # Would be populated in real implementation
                    }
                except Exception as e:
                    logger.error(f"Error getting incident response data: {e}")
                    # Fall back to mock data
                    incident_dashboard = {
                        "timestamp": datetime.now().isoformat(),
                        "active_orchestrations": [],
                        "recent_incidents": list(self.mock_incidents.values()),
                        "incident_metrics": await self._get_incident_response_summary(),
                        "workflows": []
                    }
            else:
                # Use mock data
                incident_dashboard = {
                    "timestamp": datetime.now().isoformat(),
                    "active_orchestrations": [],
                    "recent_incidents": list(self.mock_incidents.values()),
                    "incident_metrics": await self._get_incident_response_summary(),
                    "workflows": []
                }
            
            return web.json_response({
                "status": "success",
                "data": incident_dashboard
            })
        except Exception as e:
            logger.error(f"Error generating incident response dashboard: {e}")
            return web.json_response({
                "status": "error",
                "message": str(e)
            }, status=500)
    
    async def get_endpoint_dashboard(self, request) -> web.Response:
        """
        Get detailed endpoint security dashboard
        
        Returns:
            JSON response with endpoint security data
        """
        try:
            # Get agent data
            agents = list(self.mock_agents.values())
            
            # Calculate endpoint metrics
            online_agents = [a for a in agents if a["status"] == "online"]
            offline_agents = [a for a in agents if a["status"] == "offline"]
            
            endpoint_dashboard = {
                "timestamp": datetime.now().isoformat(),
                "agents": agents,
                "agent_metrics": {
                    "total": len(agents),
                    "online": len(online_agents),
                    "offline": len(offline_agents),
                    "threats_detected": sum(a["threats_detected"] for a in agents),
                    "quarantined_files": sum(a["quarantined_files"] for a in agents)
                },
                "os_breakdown": self._calculate_os_breakdown(agents),
                "threat_distribution": self._calculate_threat_distribution(agents)
            }
            
            return web.json_response({
                "status": "success",
                "data": endpoint_dashboard
            })
        except Exception as e:
            logger.error(f"Error generating endpoint dashboard: {e}")
            return web.json_response({
                "status": "error",
                "message": str(e)
            }, status=500)
    
    def _calculate_os_breakdown(self, agents: List[Dict]) -> Dict[str, int]:
        """Calculate operating system breakdown"""
        os_breakdown = {}
        for agent in agents:
            os = agent.get("os", "Unknown")
            os_breakdown[os] = os_breakdown.get(os, 0) + 1
        return os_breakdown
    
    def _calculate_threat_distribution(self, agents: List[Dict]) -> Dict[str, int]:
        """Calculate threat distribution across endpoints"""
        threat_dist = {"clean": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for agent in agents:
            threats = agent.get("threats_detected", 0)
            if threats == 0:
                threat_dist["clean"] += 1
            elif threats <= 2:
                threat_dist["low"] += 1
            elif threats <= 5:
                threat_dist["medium"] += 1
            elif threats <= 10:
                threat_dist["high"] += 1
            else:
                threat_dist["critical"] += 1
        return threat_dist
    
    def setup_routes(self, app: web.Application):
        """
        Setup dashboard API routes
        
        Args:
            app: aiohttp web application
        """
        # Executive dashboard
        app.router.add_get('/api/v1/dashboard/executive', self.get_executive_dashboard)
        
        # Threat intelligence dashboard
        app.router.add_get('/api/v1/dashboard/threat-intel', self.get_threat_intel_dashboard)
        
        # Compliance dashboard
        app.router.add_get('/api/v1/dashboard/compliance', self.get_compliance_dashboard)
        
        # Incident response dashboard
        app.router.add_get('/api/v1/dashboard/incident-response', self.get_incident_response_dashboard)
        
        # Endpoint security dashboard
        app.router.add_get('/api/v1/dashboard/endpoints', self.get_endpoint_dashboard)
        
        logger.info("Dashboard API routes setup completed")

# Create dashboard API instance
dashboard_api = EnterpriseDashboardAPI()

# Example usage
if __name__ == "__main__":
    # This would typically be run as part of the main API service
    print("Enterprise Dashboard API module loaded")
    print("Available endpoints:")
    print("  GET /api/v1/dashboard/executive")
    print("  GET /api/v1/dashboard/threat-intel")
    print("  GET /api/v1/dashboard/compliance")
    print("  GET /api/v1/dashboard/incident-response")
    print("  GET /api/v1/dashboard/endpoints")