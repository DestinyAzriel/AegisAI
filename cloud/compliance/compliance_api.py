#!/usr/bin/env python3
"""
AegisAI Compliance API

REST API for compliance services including GDPR/CCPA compliance,
security certifications (SOC 2, ISO 27001), and third-party assessments.
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import asyncio
import logging
import json
import os

from compliance_manager import ComplianceManager, ComplianceAPI, DataSubjectRequestType
from enhanced_compliance_reporting import EnhancedComplianceReporting, EnhancedComplianceAPI, ReportType, ReportFrequency

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AegisAI Compliance Service",
    description="Compliance service for GDPR/CCA, SOC 2, ISO 27001, and third-party assessments",
    version="0.1.0"
)

# Global compliance manager and API instances
compliance_manager = None
compliance_api = None
enhanced_reporting = None
enhanced_compliance_api = None

# Pydantic models
class DataProcessingRequest(BaseModel):
    data_type: str
    purpose: str
    data_subjects: List[str]
    retention_period: Optional[int] = None

class ConsentRequest(BaseModel):
    user_id: str
    consent_types: List[str]
    granted: bool = True

class DSRRequest(BaseModel):
    request_type: str
    user_id: str
    details: Optional[Dict] = None

class DSRProcessRequest(BaseModel):
    request_id: str

class ComplianceResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict] = None
    error: Optional[str] = None

class PrivacyReportRequest(BaseModel):
    user_id: Optional[str] = None

class ExportRequest(BaseModel):
    format: str = "json"

# Enhanced reporting models
class ReportGenerationRequest(BaseModel):
    report_type: str
    parameters: Optional[Dict] = None

class ScheduledReportRequest(BaseModel):
    id: str
    report_type: str
    frequency: str
    recipients: List[str]
    enabled: bool = True
    parameters: Optional[Dict] = None

# Initialize compliance manager on startup
@app.on_event("startup")
async def startup_event():
    global compliance_manager, compliance_api, enhanced_reporting, enhanced_compliance_api
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config", "compliance_config.json")
        compliance_manager = ComplianceManager(config_path)
        compliance_api = ComplianceAPI(compliance_manager)
        enhanced_reporting = EnhancedComplianceReporting(compliance_manager)
        enhanced_compliance_api = EnhancedComplianceAPI(enhanced_reporting)
        logger.info("Compliance manager and API initialized")
    except Exception as e:
        logger.error(f"Failed to initialize compliance manager: {e}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "AegisAI Compliance Service",
        "timestamp": "2025-09-23T12:00:00Z"
    }

@app.post("/data-processing", response_model=ComplianceResponse)
async def register_data_processing(request: DataProcessingRequest):
    """
    Register data processing activities for compliance tracking
    
    Args:
        request: Data processing registration request
        
    Returns:
        ComplianceResponse: Result of registration
    """
    if not compliance_api:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        result = compliance_api.register_data_processing_api(
            data_type=request.data_type,
            purpose=request.purpose,
            data_subjects=request.data_subjects,
            retention_period=request.retention_period
        )
        
        return ComplianceResponse(**result)
            
    except Exception as e:
        logger.error(f"Error registering data processing: {e}")
        raise HTTPException(status_code=500, detail=f"Error registering data processing: {str(e)}")

@app.post("/consent", response_model=ComplianceResponse)
async def record_consent(request: ConsentRequest):
    """
    Record user consent for data processing
    
    Args:
        request: Consent recording request
        
    Returns:
        ComplianceResponse: Result of consent recording
    """
    if not compliance_api:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        result = compliance_api.record_consent_api(
            user_id=request.user_id,
            consent_types=request.consent_types,
            granted=request.granted
        )
        
        return ComplianceResponse(**result)
            
    except Exception as e:
        logger.error(f"Error recording consent: {e}")
        raise HTTPException(status_code=500, detail=f"Error recording consent: {str(e)}")

@app.post("/dsr", response_model=ComplianceResponse)
async def submit_dsr(request: DSRRequest):
    """
    Submit data subject request (DSR) for GDPR/CCPA compliance
    
    Args:
        request: Data subject request submission
        
    Returns:
        ComplianceResponse: Result of DSR submission
    """
    if not compliance_api:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        result = compliance_api.submit_dsr_api(
            request_type=request.request_type,
            user_id=request.user_id,
            details=request.details
        )
        
        return ComplianceResponse(**result)
            
    except Exception as e:
        logger.error(f"Error submitting DSR: {e}")
        raise HTTPException(status_code=500, detail=f"Error submitting DSR: {str(e)}")

@app.post("/dsr/process", response_model=ComplianceResponse)
async def process_dsr(request: DSRProcessRequest):
    """
    Process a data subject request
    
    Args:
        request: DSR processing request
        
    Returns:
        ComplianceResponse: Result of DSR processing
    """
    if not compliance_api:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        result = compliance_api.process_dsr_api(request.request_id)
        
        return ComplianceResponse(**result)
            
    except Exception as e:
        logger.error(f"Error processing DSR: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing DSR: {str(e)}")

@app.get("/reports/privacy", response_model=ComplianceResponse)
async def get_privacy_report(user_id: Optional[str] = None):
    """
    Generate privacy compliance report
    
    Args:
        user_id: Optional user ID for user-specific report
        
    Returns:
        ComplianceResponse: Privacy compliance report
    """
    if not compliance_api:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        result = compliance_api.get_privacy_report_api(user_id)
        
        return ComplianceResponse(**result)
            
    except Exception as e:
        logger.error(f"Error generating privacy report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating privacy report: {str(e)}")

@app.get("/reports/soc2", response_model=ComplianceResponse)
async def get_soc2_report():
    """
    Generate SOC 2 compliance report
    
    Returns:
        ComplianceResponse: SOC 2 compliance report
    """
    if not compliance_manager:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        report = compliance_manager.generate_soc2_report()
        
        return ComplianceResponse(
            success=True,
            message="SOC 2 report generated successfully",
            data=report
        )
            
    except Exception as e:
        logger.error(f"Error generating SOC 2 report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating SOC 2 report: {str(e)}")

@app.get("/reports/iso27001", response_model=ComplianceResponse)
async def get_iso27001_report():
    """
    Generate ISO 27001 compliance report
    
    Returns:
        ComplianceResponse: ISO 27001 compliance report
    """
    if not compliance_manager:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        report = compliance_manager.generate_iso27001_report()
        
        return ComplianceResponse(
            success=True,
            message="ISO 27001 report generated successfully",
            data=report
        )
            
    except Exception as e:
        logger.error(f"Error generating ISO 27001 report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating ISO 27001 report: {str(e)}")

@app.get("/status", response_model=ComplianceResponse)
async def get_compliance_status():
    """
    Get current compliance status
    
    Returns:
        ComplianceResponse: Current compliance status
    """
    if not compliance_api:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        result = compliance_api.get_compliance_status_api()
        
        return ComplianceResponse(**result)
            
    except Exception as e:
        logger.error(f"Error getting compliance status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting compliance status: {str(e)}")

@app.post("/auto-delete", response_model=ComplianceResponse)
async def auto_delete_expired_data():
    """
    Automatically delete data that has exceeded retention periods
    
    Returns:
        ComplianceResponse: Statistics about deleted data
    """
    if not compliance_manager:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        stats = compliance_manager.auto_delete_expired_data()
        
        return ComplianceResponse(
            success=True,
            message=f"Auto-deleted {stats['deleted']} expired data activities",
            data=stats
        )
            
    except Exception as e:
        logger.error(f"Error auto-deleting expired data: {e}")
        raise HTTPException(status_code=500, detail=f"Error auto-deleting expired data: {str(e)}")

@app.post("/export", response_model=ComplianceResponse)
async def export_compliance_data(request: ExportRequest):
    """
    Export compliance data for third-party assessments
    
    Args:
        request: Export request with format specification
        
    Returns:
        ComplianceResponse: Exported compliance data
    """
    if not compliance_manager:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        exported_data = compliance_manager.export_compliance_data(request.format)
        
        return ComplianceResponse(
            success=True,
            message=f"Compliance data exported successfully in {request.format} format",
            data={"exported_data": exported_data}
        )
            
    except Exception as e:
        logger.error(f"Error exporting compliance data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting compliance data: {str(e)}")

@app.get("/audit-log")
async def get_audit_log(limit: int = 100):
    """
    Get compliance audit log
    
    Args:
        limit: Maximum number of entries to return
        
    Returns:
        Dict: Audit log entries
    """
    if not compliance_manager:
        raise HTTPException(status_code=503, detail="Compliance service not initialized")
    
    try:
        audit_log = compliance_manager.get_audit_log(limit)
        
        return {
            "success": True,
            "audit_log": audit_log,
            "count": len(audit_log)
        }
            
    except Exception as e:
        logger.error(f"Error retrieving audit log: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving audit log: {str(e)}")

@app.get("/reports/metrics", response_model=ComplianceResponse)
async def get_compliance_metrics():
    """
    Get compliance metrics for dashboard integration
    
    Returns:
        ComplianceResponse: Current compliance metrics
    """
    if not enhanced_compliance_api:
        raise HTTPException(status_code=503, detail="Enhanced compliance service not initialized")
    
    try:
        result = enhanced_compliance_api.get_compliance_metrics_api()
        return ComplianceResponse(**result)
    except Exception as e:
        logger.error(f"Error getting compliance metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting compliance metrics: {str(e)}")

@app.post("/reports/generate", response_model=ComplianceResponse)
async def generate_report(request: ReportGenerationRequest):
    """
    Generate compliance report of specified type
    
    Args:
        request: Report generation request
        
    Returns:
        ComplianceResponse: Generated report
    """
    if not enhanced_compliance_api:
        raise HTTPException(status_code=503, detail="Enhanced compliance service not initialized")
    
    try:
        result = enhanced_compliance_api.generate_report_api(
            report_type=request.report_type,
            parameters=request.parameters
        )
        return ComplianceResponse(**result)
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@app.post("/reports/schedule", response_model=ComplianceResponse)
async def schedule_report(request: ScheduledReportRequest):
    """
    Schedule automated compliance report generation
    
    Args:
        request: Scheduled report configuration
        
    Returns:
        ComplianceResponse: Schedule result
    """
    if not enhanced_compliance_api:
        raise HTTPException(status_code=503, detail="Enhanced compliance service not initialized")
    
    try:
        result = enhanced_compliance_api.schedule_report_api(request.dict())
        return ComplianceResponse(**result)
    except Exception as e:
        logger.error(f"Error scheduling report: {e}")
        raise HTTPException(status_code=500, detail=f"Error scheduling report: {str(e)}")

@app.get("/reports/scheduled", response_model=ComplianceResponse)
async def get_scheduled_reports():
    """
    Get all scheduled compliance reports
    
    Returns:
        ComplianceResponse: Scheduled reports
    """
    if not enhanced_compliance_api:
        raise HTTPException(status_code=503, detail="Enhanced compliance service not initialized")
    
    try:
        result = enhanced_compliance_api.get_scheduled_reports_api()
        return ComplianceResponse(**result)
    except Exception as e:
        logger.error(f"Error getting scheduled reports: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting scheduled reports: {str(e)}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AegisAI Compliance Service",
        "version": "0.1.0",
        "documentation": "/docs",
        "endpoints": {
            "health_check": "/health",
            "register_data_processing": "/data-processing",
            "record_consent": "/consent",
            "submit_dsr": "/dsr",
            "process_dsr": "/dsr/process",
            "get_privacy_report": "/reports/privacy",
            "get_soc2_report": "/reports/soc2",
            "get_iso27001_report": "/reports/iso27001",
            "get_compliance_status": "/status",
            "auto_delete_expired_data": "/auto-delete",
            "export_compliance_data": "/export",
            "get_audit_log": "/audit-log"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8004)