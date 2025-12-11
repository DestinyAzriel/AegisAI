#!/usr/bin/env python3
"""
AegisAI SIEM Integration API

REST API for SIEM integration services in enterprise environments.
"""

import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
import asyncio
import logging
import json
import os

from siem_connector import SIEMIntegrationManager, SIEMEvent

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AegisAI SIEM Integration Service",
    description="SIEM integration service for AegisAI enterprise environments",
    version="0.1.0"
)

# Global SIEM manager instance
siem_manager = None

# Pydantic models
class SIEMConfig(BaseModel):
    type: str
    enabled: bool
    url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    index: Optional[str] = "aegisai"
    auth_token: Optional[str] = None

class SIEMEventRequest(BaseModel):
    event_type: str
    severity: str
    source: str
    timestamp: Optional[str] = None
    data: Dict[str, any]

class SIEMEventResponse(BaseModel):
    success: bool
    message: str

class BulkSIEMEventRequest(BaseModel):
    events: List[SIEMEventRequest]

class BulkSIEMEventResponse(BaseModel):
    sent: int
    failed: int
    total: int

class ConnectionTestResponse(BaseModel):
    connector: str
    connected: bool
    message: str

class ConnectionTestAllResponse(BaseModel):
    results: Dict[str, bool]

# Initialize SIEM manager on startup
@app.on_event("startup")
async def startup_event():
    global siem_manager
    try:
        config_path = os.path.join(os.path.dirname(__file__), "config", "siem_config.json")
        siem_manager = SIEMIntegrationManager(config_path)
        await siem_manager.initialize_connectors()
        logger.info("SIEM integration manager initialized")
    except Exception as e:
        logger.error(f"Failed to initialize SIEM manager: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    global siem_manager
    if siem_manager:
        await siem_manager.shutdown_connectors()
        logger.info("SIEM integration manager shutdown")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "AegisAI SIEM Integration",
        "timestamp": "2025-09-23T12:00:00Z"
    }

@app.post("/events", response_model=SIEMEventResponse)
async def send_event(request: SIEMEventRequest):
    """
    Send a security event to SIEM
    
    Args:
        request: SIEM event request
        
    Returns:
        SIEMEventResponse: Result of event sending
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    try:
        # Create SIEM event
        event = SIEMEvent(
            event_type=request.event_type,
            severity=request.severity,
            source=request.source,
            timestamp=request.timestamp,
            **request.data
        )
        
        # Send event
        success = await siem_manager.send_security_event(event)
        
        if success:
            return SIEMEventResponse(
                success=True,
                message=f"Event sent successfully to SIEM"
            )
        else:
            return SIEMEventResponse(
                success=False,
                message="Failed to send event to SIEM"
            )
            
    except Exception as e:
        logger.error(f"Error sending event: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending event: {str(e)}")

@app.post("/events/bulk", response_model=BulkSIEMEventResponse)
async def send_bulk_events(request: BulkSIEMEventRequest):
    """
    Send multiple security events to SIEM in bulk
    
    Args:
        request: Bulk SIEM events request
        
    Returns:
        BulkSIEMEventResponse: Statistics about sent events
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    try:
        # Create SIEM events
        events = []
        for event_request in request.events:
            event = SIEMEvent(
                event_type=event_request.event_type,
                severity=event_request.severity,
                source=event_request.source,
                timestamp=event_request.timestamp,
                **event_request.data
            )
            events.append(event)
        
        # Send events in bulk
        stats = await siem_manager.send_bulk_events(events)
        
        return BulkSIEMEventResponse(
            sent=stats['sent'],
            failed=stats['failed'],
            total=len(events)
        )
            
    except Exception as e:
        logger.error(f"Error sending bulk events: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending bulk events: {str(e)}")

@app.post("/events/apt", response_model=SIEMEventResponse)
async def send_apt_event(agent_id: str, apt_result: Dict):
    """
    Send APT detection event to SIEM
    
    Args:
        agent_id: Agent identifier
        apt_result: APT detection results
        
    Returns:
        SIEMEventResponse: Result of event sending
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    try:
        # Send APT event
        success = await siem_manager.send_apt_event(agent_id, apt_result)
        
        if success:
            return SIEMEventResponse(
                success=True,
                message=f"APT event sent successfully to SIEM for agent {agent_id}"
            )
        else:
            return SIEMEventResponse(
                success=False,
                message=f"Failed to send APT event to SIEM for agent {agent_id}"
            )
            
    except Exception as e:
        logger.error(f"Error sending APT event: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending APT event: {str(e)}")

@app.post("/events/incident", response_model=SIEMEventResponse)
async def send_incident_event(incident_id: str, incident_data: Dict):
    """
    Send incident response event to SIEM
    
    Args:
        incident_id: Incident identifier
        incident_data: Incident data
        
    Returns:
        SIEMEventResponse: Result of event sending
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    try:
        # Send incident event
        success = await siem_manager.send_incident_event(incident_id, incident_data)
        
        if success:
            return SIEMEventResponse(
                success=True,
                message=f"Incident event sent successfully to SIEM for incident {incident_id}"
            )
        else:
            return SIEMEventResponse(
                success=False,
                message=f"Failed to send incident event to SIEM for incident {incident_id}"
            )
            
    except Exception as e:
        logger.error(f"Error sending incident event: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending incident event: {str(e)}")

@app.post("/events/behavioral", response_model=SIEMEventResponse)
async def send_behavioral_event(agent_id: str, analysis_result: Dict):
    """
    Send behavioral analysis event to SIEM
    
    Args:
        agent_id: Agent identifier
        analysis_result: Behavioral analysis results
        
    Returns:
        SIEMEventResponse: Result of event sending
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    try:
        # Send behavioral event
        success = await siem_manager.send_behavioral_event(agent_id, analysis_result)
        
        if success:
            return SIEMEventResponse(
                success=True,
                message=f"Behavioral event sent successfully to SIEM for agent {agent_id}"
            )
        else:
            return SIEMEventResponse(
                success=False,
                message=f"Failed to send behavioral event to SIEM for agent {agent_id}"
            )
            
    except Exception as e:
        logger.error(f"Error sending behavioral event: {e}")
        raise HTTPException(status_code=500, detail=f"Error sending behavioral event: {str(e)}")

@app.get("/connectors/test", response_model=ConnectionTestAllResponse)
async def test_all_connections():
    """
    Test connections to all configured SIEM systems
    
    Returns:
        ConnectionTestAllResponse: Connection test results
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    try:
        results = await siem_manager.test_all_connections()
        return ConnectionTestAllResponse(results=results)
            
    except Exception as e:
        logger.error(f"Error testing connections: {e}")
        raise HTTPException(status_code=500, detail=f"Error testing connections: {str(e)}")

@app.get("/connectors/test/{connector_name}", response_model=ConnectionTestResponse)
async def test_connection(connector_name: str):
    """
    Test connection to a specific SIEM system
    
    Args:
        connector_name: Name of the connector to test
        
    Returns:
        ConnectionTestResponse: Connection test result
    """
    if not siem_manager:
        raise HTTPException(status_code=503, detail="SIEM manager not initialized")
    
    if connector_name not in siem_manager.connectors:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_name}' not found")
    
    try:
        connector = siem_manager.connectors[connector_name]
        connected = await connector.test_connection()
        
        return ConnectionTestResponse(
            connector=connector_name,
            connected=connected,
            message=f"Connection {'successful' if connected else 'failed'}"
        )
            
    except Exception as e:
        logger.error(f"Error testing connection: {e}")
        raise HTTPException(status_code=500, detail=f"Error testing connection: {str(e)}")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AegisAI SIEM Integration Service",
        "version": "0.1.0",
        "documentation": "/docs",
        "endpoints": {
            "health_check": "/health",
            "send_event": "/events",
            "send_bulk_events": "/events/bulk",
            "send_apt_event": "/events/apt",
            "send_incident_event": "/events/incident",
            "send_behavioral_event": "/events/behavioral",
            "test_all_connections": "/connectors/test",
            "test_connection": "/connectors/test/{connector_name}"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)