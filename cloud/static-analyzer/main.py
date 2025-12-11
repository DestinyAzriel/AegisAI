"""
AegisAI Static Analyzer API
==========================

REST API for the AegisAI static analyzer service.
"""

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging
import json
import base64

# Import our static analyzer
try:
    from analyzer import StaticAnalyzer
    STATIC_ANALYZER_AVAILABLE = True
except ImportError:
    logging.warning("Static analyzer dependencies not available")
    STATIC_ANALYZER_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AegisAI Static Analyzer",
    description="Static analysis service for AegisAI",
    version="0.1.0"
)

# Pydantic models
class AnalysisRequest(BaseModel):
    file_data: str  # Base64 encoded file data
    file_name: Optional[str] = None

class AnalysisResponse(BaseModel):
    file_hash: str
    ember_features: Dict
    yara_matches: List[str]
    threat_intel_matches: List[Dict]
    analysis_timestamp: str

class HealthResponse(BaseModel):
    status: str
    static_analyzer_available: bool
    timestamp: str

# Initialize static analyzer
if STATIC_ANALYZER_AVAILABLE:
    # Try to load YARA rules if they exist
    yara_rules_path = "yara_rules/rules.yar"
    import os
    if not os.path.exists(yara_rules_path):
        yara_rules_path = None
    
    static_analyzer = StaticAnalyzer(yara_rules_path=yara_rules_path)
else:
    static_analyzer = None

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        static_analyzer_available=STATIC_ANALYZER_AVAILABLE,
        timestamp="2025-09-23T12:00:00Z"
    )

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_file(request: AnalysisRequest):
    """
    Analyze a file for threats
    
    Args:
        request: Analysis request with file data
        
    Returns:
        Analysis results
    """
    if not STATIC_ANALYZER_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="Static analyzer not available - dependencies missing"
        )
    
    try:
        # Decode base64 file data
        file_bytes = base64.b64decode(request.file_data)
        
        # Analyze file
        results = static_analyzer.analyze_file(file_bytes)
        
        return AnalysisResponse(
            file_hash=results['file_hash'],
            ember_features=results['ember_features'],
            yara_matches=results['yara_matches'],
            threat_intel_matches=results['threat_intel_matches'],
            analysis_timestamp="2025-09-23T12:00:00Z"
        )
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Analysis failed: {str(e)}"
        )

@app.post("/analyze-file")
async def analyze_uploaded_file(file: UploadFile = File(...)):
    """
    Analyze an uploaded file for threats
    
    Args:
        file: Uploaded file
        
    Returns:
        Analysis results
    """
    if not STATIC_ANALYZER_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="Static analyzer not available - dependencies missing"
        )
    
    try:
        # Read file content
        file_bytes = await file.read()
        
        # Analyze file
        results = static_analyzer.analyze_file(file_bytes)
        
        return results
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Analysis failed: {str(e)}"
        )

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AegisAI Static Analyzer",
        "version": "0.1.0",
        "documentation": "/docs"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)