"""
AegisAI Sandbox Orchestrator
============================

Orchestrates secure malware analysis in isolated environments.
"""

import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging
import json
import base64
import os
import hashlib
import tempfile
import subprocess
import time
import threading
import docker
from datetime import datetime
import psutil
import yara

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models
class SandboxAnalysisRequest(BaseModel):
    file_data: str  # Base64 encoded file data
    file_name: Optional[str] = None
    analysis_timeout: Optional[int] = 60  # Default 60 seconds
    enable_network_monitoring: Optional[bool] = True
    enable_file_monitoring: Optional[bool] = True
    enable_registry_monitoring: Optional[bool] = True

class SandboxAnalysisResponse(BaseModel):
    analysis_id: str
    file_hash: str
    status: str
    verdict: str
    confidence: float
    behaviors: List[str]
    network_activity: Dict
    file_changes: Dict
    registry_changes: Dict
    screenshots: List[str]
    memory_dumps: List[str]
    analysis_timestamp: str
    analysis_duration: float

class HealthResponse(BaseModel):
    status: str
    sandbox_available: bool
    docker_available: bool
    timestamp: str

# Initialize FastAPI app
app = FastAPI(
    title="AegisAI Sandbox Orchestrator",
    description="Secure malware analysis service for AegisAI",
    version="0.1.0"
)

# Global variables
docker_client = None
try:
    docker_client = docker.from_env()
    DOCKER_AVAILABLE = True
    logger.info("Docker client initialized successfully")
except Exception as e:
    DOCKER_AVAILABLE = False
    logger.error(f"Docker not available: {e}")

# Analysis storage
analysis_results = {}

class SandboxOrchestrator:
    """Manages sandbox environments for malware analysis"""
    
    def __init__(self):
        self.sandbox_images = {
            "windows": "aegisai/windows-sandbox:latest",
            "linux": "aegisai/linux-sandbox:latest"
        }
        self.analysis_containers = {}
        self.yara_rules = None
        self.load_yara_rules()
    
    def load_yara_rules(self):
        """Load YARA rules for behavior detection"""
        try:
            # In a real implementation, this would load actual YARA rules
            # For this demo, we'll create a simple rule
            rule_content = """
            rule SuspiciousProcessCreation {
                strings:
                    $createproc = "CreateProcess"
                    $winexec = "WinExec"
                condition:
                    any of them
            }
            
            rule NetworkConnection {
                strings:
                    $connect = "connect"
                    $socket = "socket"
                condition:
                    any of them
            }
            """
            self.yara_rules = yara.compile(source=rule_content)
            logger.info("YARA rules loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
    
    def calculate_file_hash(self, file_data: bytes) -> str:
        """Calculate SHA256 hash of file data"""
        return hashlib.sha256(file_data).hexdigest()
    
    def create_analysis_environment(self, analysis_id: str, os_type: str = "windows") -> Optional[str]:
        """
        Create a secure analysis environment
        
        Args:
            analysis_id: Unique identifier for this analysis
            os_type: Type of OS environment to create
            
        Returns:
            Container ID if successful, None otherwise
        """
        if not DOCKER_AVAILABLE:
            logger.error("Docker not available for sandbox creation")
            return None
        
        try:
            # Create container with restricted resources
            container = docker_client.containers.run(
                self.sandbox_images.get(os_type, "aegisai/windows-sandbox:latest"),
                name=f"aegisai-sandbox-{analysis_id}",
                detach=True,
                auto_remove=False,  # Keep container for analysis
                network_disabled=not True,  # Enable network for monitoring
                mem_limit="1g",  # Limit memory to 1GB
                cpu_quota=50000,  # Limit CPU to 50%
                security_opt=["no-new-privileges"],  # Security enhancement
                volumes={
                    "/analysis/samples": {"bind": "/samples", "mode": "ro"},
                    "/analysis/results": {"bind": "/results", "mode": "rw"}
                }
            )
            
            container_id = container.id
            self.analysis_containers[analysis_id] = container_id
            logger.info(f"Created analysis environment {container_id} for analysis {analysis_id}")
            return container_id
            
        except Exception as e:
            logger.error(f"Failed to create analysis environment: {e}")
            return None
    
    def execute_sample_in_sandbox(self, analysis_id: str, file_path: str, 
                                timeout: int = 60) -> Dict:
        """
        Execute sample in sandbox environment and monitor behavior
        
        Args:
            analysis_id: Analysis identifier
            file_path: Path to sample file
            timeout: Execution timeout in seconds
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            "behaviors": [],
            "network_activity": {},
            "file_changes": {},
            "registry_changes": {},
            "screenshots": [],
            "memory_dumps": [],
            "execution_time": 0
        }
        
        start_time = time.time()
        
        try:
            # In a real implementation, this would:
            # 1. Copy file to sandbox environment
            # 2. Start monitoring tools (Process Monitor, Network Monitor, etc.)
            # 3. Execute the sample
            # 4. Monitor for specified timeout
            # 5. Collect results
            
            # For this demo, we'll simulate the analysis
            logger.info(f"Executing sample in sandbox for analysis {analysis_id}")
            
            # Simulate execution time
            time.sleep(min(timeout, 10))  # Don't sleep too long in demo
            
            # Simulate detected behaviors
            results["behaviors"] = [
                "Process creation",
                "File system access",
                "Registry modification",
                "Network connection attempt"
            ]
            
            # Simulate network activity
            results["network_activity"] = {
                "connections": [
                    {"remote_ip": "192.168.1.100", "remote_port": 80, "protocol": "TCP"},
                    {"remote_ip": "10.0.0.1", "remote_port": 443, "protocol": "TCP"}
                ],
                "dns_queries": ["malicious-domain.com", "c2-server.net"]
            }
            
            # Simulate file changes
            results["file_changes"] = {
                "created": ["/temp/malware.exe", "/temp/config.dat"],
                "modified": ["/windows/system32/drivers/etc/hosts"],
                "deleted": ["/temp/old_file.txt"]
            }
            
            # Simulate registry changes
            results["registry_changes"] = {
                "created": [
                    "HKCU\\Software\\Malware\\Startup",
                    "HKLM\\Software\\Malware\\Config"
                ],
                "modified": [
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                ]
            }
            
            results["execution_time"] = time.time() - start_time
            
            logger.info(f"Sample execution completed for analysis {analysis_id}")
            
        except Exception as e:
            logger.error(f"Error during sample execution: {e}")
            results["error"] = str(e)
        
        return results
    
    def analyze_behavior(self, file_data: bytes, execution_results: Dict) -> Dict:
        """
        Analyze detected behaviors to determine threat level
        
        Args:
            file_data: Original file data
            execution_results: Results from sandbox execution
            
        Returns:
            Dictionary with verdict and confidence
        """
        verdict = "clean"
        confidence = 0.0
        behaviors = execution_results.get("behaviors", [])
        
        # Check for suspicious behaviors
        suspicious_indicators = 0
        
        # Network activity analysis
        network_activity = execution_results.get("network_activity", {})
        if network_activity.get("connections") or network_activity.get("dns_queries"):
            suspicious_indicators += 1
            
        # File system changes
        file_changes = execution_results.get("file_changes", {})
        if file_changes.get("created") or file_changes.get("modified"):
            suspicious_indicators += 1
            
        # Registry changes
        registry_changes = execution_results.get("registry_changes", {})
        if registry_changes.get("created") or registry_changes.get("modified"):
            suspicious_indicators += 1
            
        # YARA rule matching on behaviors
        if self.yara_rules:
            try:
                behavior_text = " ".join(behaviors)
                matches = self.yara_rules.match(data=behavior_text.encode())
                if matches:
                    suspicious_indicators += len(matches)
            except Exception as e:
                logger.error(f"YARA matching failed: {e}")
        
        # Determine verdict based on suspicious indicators
        if suspicious_indicators >= 3:
            verdict = "malicious"
            confidence = 0.9
        elif suspicious_indicators >= 1:
            verdict = "suspicious"
            confidence = 0.6
        else:
            verdict = "clean"
            confidence = 0.95
            
        return {
            "verdict": verdict,
            "confidence": confidence,
            "suspicious_indicators": suspicious_indicators
        }
    
    def cleanup_analysis_environment(self, analysis_id: str):
        """
        Clean up analysis environment after completion
        
        Args:
            analysis_id: Analysis identifier
        """
        if analysis_id in self.analysis_containers:
            container_id = self.analysis_containers[analysis_id]
            try:
                container = docker_client.containers.get(container_id)
                container.stop(timeout=10)
                container.remove()
                del self.analysis_containers[analysis_id]
                logger.info(f"Cleaned up analysis environment for {analysis_id}")
            except Exception as e:
                logger.error(f"Error cleaning up container {container_id}: {e}")

# Initialize orchestrator
orchestrator = SandboxOrchestrator()

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        sandbox_available=True,
        docker_available=DOCKER_AVAILABLE,
        timestamp=datetime.now().isoformat()
    )

@app.post("/analyze", response_model=SandboxAnalysisResponse)
async def analyze_sample(request: SandboxAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analyze a file sample in a secure sandbox environment
    
    Args:
        request: Analysis request with file data
        background_tasks: FastAPI background tasks for async processing
        
    Returns:
        Analysis results
    """
    if not DOCKER_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="Sandbox not available - Docker not running"
        )
    
    start_time = time.time()
    
    try:
        # Decode base64 file data
        file_bytes = base64.b64decode(request.file_data)
        file_hash = orchestrator.calculate_file_hash(file_bytes)
        
        # Generate unique analysis ID
        analysis_id = hashlib.sha256(
            f"{file_hash}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        logger.info(f"Starting sandbox analysis {analysis_id} for file {file_hash[:16]}...")
        
        # Save file to temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{request.file_name or 'sample'}") as tmp_file:
            tmp_file.write(file_bytes)
            sample_path = tmp_file.name
        
        # Create analysis environment
        container_id = orchestrator.create_analysis_environment(analysis_id)
        if not container_id:
            raise HTTPException(
                status_code=500,
                detail="Failed to create analysis environment"
            )
        
        # Execute sample in sandbox
        execution_results = orchestrator.execute_sample_in_sandbox(
            analysis_id, 
            sample_path, 
            request.analysis_timeout
        )
        
        # Analyze behaviors
        behavior_analysis = orchestrator.analyze_behavior(file_bytes, execution_results)
        
        # Prepare response
        analysis_duration = time.time() - start_time
        
        response = SandboxAnalysisResponse(
            analysis_id=analysis_id,
            file_hash=file_hash,
            status="completed",
            verdict=behavior_analysis["verdict"],
            confidence=behavior_analysis["confidence"],
            behaviors=execution_results.get("behaviors", []),
            network_activity=execution_results.get("network_activity", {}),
            file_changes=execution_results.get("file_changes", {}),
            registry_changes=execution_results.get("registry_changes", {}),
            screenshots=execution_results.get("screenshots", []),
            memory_dumps=execution_results.get("memory_dumps", []),
            analysis_timestamp=datetime.now().isoformat(),
            analysis_duration=analysis_duration
        )
        
        # Store results for later retrieval
        analysis_results[analysis_id] = response.dict()
        
        # Schedule cleanup
        background_tasks.add_task(orchestrator.cleanup_analysis_environment, analysis_id)
        
        # Clean up temporary file
        try:
            os.unlink(sample_path)
        except Exception as e:
            logger.error(f"Failed to clean up temporary file: {e}")
        
        logger.info(f"Analysis {analysis_id} completed with verdict: {behavior_analysis['verdict']}")
        
        return response
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(
            status_code=500, 
            detail=f"Analysis failed: {str(e)}"
        )

@app.get("/results/{analysis_id}", response_model=SandboxAnalysisResponse)
async def get_analysis_results(analysis_id: str):
    """
    Retrieve results for a completed analysis
    
    Args:
        analysis_id: Analysis identifier
        
    Returns:
        Analysis results
    """
    if analysis_id not in analysis_results:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found"
        )
    
    return SandboxAnalysisResponse(**analysis_results[analysis_id])

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "AegisAI Sandbox Orchestrator",
        "version": "0.1.0",
        "documentation": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)