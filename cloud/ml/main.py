"""
AegisAI ML Service API
=====================

REST API for the AegisAI machine learning service.
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import numpy as np
import logging
import json
import os

# Import our ML services
try:
    from enhanced_ml_service import EnhancedMLService
    ML_SERVICE_AVAILABLE = True
except ImportError:
    logging.warning("Enhanced ML service dependencies not available")
    ML_SERVICE_AVAILABLE = False

try:
    from apt_detection import APTDetectionEngine
    APT_DETECTION_AVAILABLE = True
except ImportError:
    logging.warning("APT detection dependencies not available")
    APT_DETECTION_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AegisAI ML Service",
    description="Machine learning service for AegisAI",
    version="0.1.0"
)

# Pydantic models
class PredictionRequest(BaseModel):
    features: Dict
    file_hash: str
    file_data: Optional[str] = None  # Base64 encoded file data

class PredictionResponse(BaseModel):
    file_hash: str
    probability: float
    verdict: str
    explanation: str

class TrainingRequest(BaseModel):
    training_data: List[Dict]
    labels: List[int]

class EvaluationRequest(BaseModel):
    test_data: List[Dict]
    labels: List[int]

class EvaluationResponse(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    sample_count: int

class APTAnalysisRequest(BaseModel):
    agent_id: str
    endpoint_data: Dict

class APTAnalysisResponse(BaseModel):
    agent_id: str
    apt_detected: bool
    overall_score: float
    confidence: float
    techniques: List[str]
    evidence: List[Dict]

class APTReportRequest(BaseModel):
    agent_id: str
    time_range_hours: Optional[int] = 24

class APTReportResponse(BaseModel):
    agent_id: str
    time_range_hours: int
    total_detections: int
    detections: List[Dict]
    technique_analysis: Dict[str, int]
    risk_level: str
    recommendations: List[str]

# Initialize ML services
if ML_SERVICE_AVAILABLE:
    ml_service = EnhancedMLService()
else:
    ml_service = None

if APT_DETECTION_AVAILABLE:
    apt_engine = APTDetectionEngine()
else:
    apt_engine = None

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy", 
        "ml_service_available": ML_SERVICE_AVAILABLE,
        "apt_detection_available": APT_DETECTION_AVAILABLE,
        "timestamp": "2025-09-23T12:00:00Z"
    }

@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    """
    Make a prediction for file features
    
    Args:
        request: Prediction request with features
        
    Returns:
        Prediction result with probability and verdict
    """
    if not ML_SERVICE_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="ML service not available - dependencies missing"
        )
    
    try:
        # Extract features
        if hasattr(request, 'file_data') and request.file_data:
            # Decode base64 file data
            import base64
            file_bytes = base64.b64decode(request.file_data)
            features = ml_service.extract_advanced_features(file_bytes)
        else:
            features = request.features
        
        # Make prediction
        probability, verdict = ml_service.predict(features)
        
        # Create explanation
        if verdict == "clean":
            explanation = "File appears to be clean based on ML analysis"
        elif verdict == "suspicious":
            explanation = "File has suspicious characteristics requiring further analysis"
        elif verdict == "malicious":
            explanation = "File is likely malicious based on ML analysis"
        else:
            explanation = "File classification is uncertain"
        
        return PredictionResponse(
            file_hash=request.file_hash,
            probability=probability,
            verdict=verdict,
            explanation=explanation
        )
        
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Prediction failed: {str(e)}"
        )

@app.post("/train")
async def train_model(request: TrainingRequest):
    """
    Train a new model
    
    Args:
        request: Training request with data and labels
        
    Returns:
        Training status
    """
    if not ML_SERVICE_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="ML service not available - dependencies missing"
        )
    
    try:
        # Train model
        ml_service.train_model(request.training_data, request.labels)
        
        # Save model
        model_path = "models/model.bin"
        ml_service.save_model(model_path)
        
        return {
            "status": "success",
            "message": "Model trained and saved successfully",
            "model_path": model_path
        }
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Training failed: {str(e)}"
        )

@app.post("/evaluate", response_model=EvaluationResponse)
async def evaluate_model(request: EvaluationRequest):
    """
    Evaluate the model on test data
    
    Args:
        request: Evaluation request with test data and labels
        
    Returns:
        Evaluation metrics
    """
    if not ML_SERVICE_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="ML service not available - dependencies missing"
        )
    
    try:
        # Evaluate model
        metrics = ml_service.evaluate_model(request.test_data, request.labels)
        
        return EvaluationResponse(**metrics)
        
    except Exception as e:
        logger.error(f"Evaluation failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Evaluation failed: {str(e)}"
        )

@app.post("/apt/analyze", response_model=APTAnalysisResponse)
async def analyze_apt(request: APTAnalysisRequest):
    """
    Analyze endpoint data for APT activity
    
    Args:
        request: APT analysis request with endpoint data
        
    Returns:
        APT analysis results
    """
    if not APT_DETECTION_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="APT detection service not available - dependencies missing"
        )
    
    try:
        # Analyze endpoint for APT activity
        result = apt_engine.analyze_endpoint(request.agent_id, request.endpoint_data)
        
        return APTAnalysisResponse(**result)
        
    except Exception as e:
        logger.error(f"APT analysis failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"APT analysis failed: {str(e)}"
        )

@app.post("/apt/report", response_model=APTReportResponse)
async def generate_apt_report(request: APTReportRequest):
    """
    Generate APT analysis report
    
    Args:
        request: APT report request
        
    Returns:
        APT analysis report
    """
    if not APT_DETECTION_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="APT detection service not available - dependencies missing"
        )
    
    try:
        # Generate APT report
        report = apt_engine.generate_apt_report(
            request.agent_id, 
            request.time_range_hours or 24
        )
        
        return APTReportResponse(**report)
        
    except Exception as e:
        logger.error(f"APT report generation failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"APT report generation failed: {str(e)}"
        )

@app.post("/apt/threat-intel")
async def update_threat_intel(threat_intel: Dict):
    """
    Update threat intelligence feeds
    
    Args:
        threat_intel: New threat intelligence data
        
    Returns:
        Update status
    """
    if not APT_DETECTION_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="APT detection service not available - dependencies missing"
        )
    
    try:
        # Update threat intelligence
        apt_engine.update_threat_intel(threat_intel)
        
        return {
            "status": "success",
            "message": "Threat intelligence updated successfully"
        }
        
    except Exception as e:
        logger.error(f"Threat intelligence update failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Threat intelligence update failed: {str(e)}"
        )

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AegisAI ML Service",
        "version": "0.1.0",
        "documentation": "/docs",
        "services": {
            "ml_prediction": "/predict",
            "ml_training": "/train",
            "ml_evaluation": "/evaluate",
            "apt_analysis": "/apt/analyze",
            "apt_reporting": "/apt/report",
            "threat_intel": "/apt/threat-intel"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)