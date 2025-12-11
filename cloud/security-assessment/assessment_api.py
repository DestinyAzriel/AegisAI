#!/usr/bin/env python3
"""
AegisAI Security Assessment API

REST API for third-party security assessments, vulnerability management,
and preparation for security certifications.
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import asyncio
import logging
import json
import os

from assessment_manager import SecurityAssessmentManager, AssessmentAPI, AssessmentType

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AegisAI Security Assessment Service",
    description="Security assessment service for third-party assessments and vulnerability management",
    version="0.1.0"
)

# Global assessment manager and API instances
assessment_manager = None
assessment_api = None

# Pydantic models
class AssessmentRequest(BaseModel):
    assessment_type: str
    target: str
    schedule: Optional[str] = "immediate"
    priority: Optional[str] = "medium"

class AssessmentStatusResponse(BaseModel):
    success: bool
    message: str
    status: Optional[Dict] = None
    error: Optional[str] = None

class FindingsResponse(BaseModel):
    success: bool
    message: str
    findings: List[Dict]
    count: int
    error: Optional[str] = None

class RemediationTaskUpdate(BaseModel):
    task_id: str
    status: Optional[str] = None
    assigned_to: Optional[str] = None

class ReportResponse(BaseModel):
    success: bool
    message: str
    report: Optional[Dict] = None
    error: Optional[str] = None

class ExportRequest(BaseModel):
    format: str = "json"

# Initialize assessment manager on startup
@app.on_event("startup")
async def startup_event():
    global assessment_manager, assessment_api
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config", "assessment_config.json")
        assessment_manager = SecurityAssessmentManager(config_path)
        assessment_api = AssessmentAPI(assessment_manager)
        logger.info("Security assessment manager and API initialized")
    except Exception as e:
        logger.error(f"Failed to initialize assessment manager: {e}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "AegisAI Security Assessment Service",
        "timestamp": "2025-09-23T12:00:00Z"
    }

@app.post("/assessments", response_model=AssessmentStatusResponse)
async def schedule_assessment(request: AssessmentRequest):
    """
    Schedule a security assessment
    
    Args:
        request: Assessment scheduling request
        
    Returns:
        AssessmentStatusResponse: Result of scheduling
    """
    if not assessment_api:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        result = assessment_api.schedule_assessment_api(
            assessment_type=request.assessment_type,
            target=request.target,
            schedule=request.schedule,
            priority=request.priority
        )
        
        return AssessmentStatusResponse(**result)
            
    except Exception as e:
        logger.error(f"Error scheduling assessment: {e}")
        raise HTTPException(status_code=500, detail=f"Error scheduling assessment: {str(e)}")

@app.get("/assessments/{assessment_id}", response_model=AssessmentStatusResponse)
async def get_assessment_status(assessment_id: str):
    """
    Get the status of an assessment
    
    Args:
        assessment_id: Assessment identifier
        
    Returns:
        AssessmentStatusResponse: Assessment status
    """
    if not assessment_api:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        result = assessment_api.get_assessment_status_api(assessment_id)
        
        return AssessmentStatusResponse(**result)
            
    except Exception as e:
        logger.error(f"Error getting assessment status: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting assessment status: {str(e)}")

@app.get("/findings", response_model=FindingsResponse)
async def get_findings(assessment_id: Optional[str] = None):
    """
    Get security findings
    
    Args:
        assessment_id: Optional assessment ID to filter findings
        
    Returns:
        FindingsResponse: Security findings
    """
    if not assessment_api:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        result = assessment_api.get_findings_api(assessment_id)
        
        return FindingsResponse(**result)
            
    except Exception as e:
        logger.error(f"Error getting findings: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting findings: {str(e)}")

@app.put("/remediation-tasks", response_model=AssessmentStatusResponse)
async def update_remediation_task(request: RemediationTaskUpdate):
    """
    Update remediation task
    
    Args:
        request: Remediation task update request
        
    Returns:
        AssessmentStatusResponse: Result of update
    """
    if not assessment_api:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        result = assessment_api.update_remediation_task_api(
            task_id=request.task_id,
            status=request.status,
            assigned_to=request.assigned_to
        )
        
        return AssessmentStatusResponse(**result)
            
    except Exception as e:
        logger.error(f"Error updating remediation task: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating remediation task: {str(e)}")

@app.get("/reports", response_model=ReportResponse)
async def generate_report(assessment_id: Optional[str] = None):
    """
    Generate security assessment report
    
    Args:
        assessment_id: Optional specific assessment ID
        
    Returns:
        ReportResponse: Assessment report
    """
    if not assessment_api:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        result = assessment_api.generate_report_api(assessment_id)
        
        return ReportResponse(**result)
            
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating report: {str(e)}")

@app.get("/remediation-tasks")
async def get_remediation_tasks(status: Optional[str] = None):
    """
    Get remediation tasks
    
    Args:
        status: Optional status to filter tasks
        
    Returns:
        Dict: Remediation tasks
    """
    if not assessment_manager:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        tasks = assessment_manager.get_remediation_tasks(status)
        
        return {
            "success": True,
            "tasks": tasks,
            "count": len(tasks)
        }
            
    except Exception as e:
        logger.error(f"Error getting remediation tasks: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting remediation tasks: {str(e)}")

@app.post("/export", response_model=ReportResponse)
async def export_assessment_data(request: ExportRequest):
    """
    Export assessment data for third-party review
    
    Args:
        request: Export request with format specification
        
    Returns:
        ReportResponse: Exported assessment data
    """
    if not assessment_manager:
        raise HTTPException(status_code=503, detail="Assessment service not initialized")
    
    try:
        exported_data = assessment_manager.export_assessment_data(request.format)
        
        return ReportResponse(
            success=True,
            message=f"Assessment data exported successfully in {request.format} format",
            report={"exported_data": exported_data}
        )
            
    except Exception as e:
        logger.error(f"Error exporting assessment data: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting assessment data: {str(e)}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AegisAI Security Assessment Service",
        "version": "0.1.0",
        "documentation": "/docs",
        "endpoints": {
            "health_check": "/health",
            "schedule_assessment": "/assessments",
            "get_assessment_status": "/assessments/{assessment_id}",
            "get_findings": "/findings",
            "update_remediation_task": "/remediation-tasks",
            "generate_report": "/reports",
            "get_remediation_tasks": "/remediation-tasks",
            "export_assessment_data": "/export"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8005)