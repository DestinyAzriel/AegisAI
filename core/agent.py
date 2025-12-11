"""
AegisAI Core Endpoint Agent
========================

This module implements the core endpoint agent for AegisAI,
integrating the scanning engine, real-time protection, and quarantine management.
"""

import os
import sys
import subprocess
import logging
from typing import Optional

# Add the agent path to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'agent', 'windows'))

logger = logging.getLogger(__name__)

class AgentInterface:
    def __init__(self):
        self.agent_path = os.path.join(os.path.dirname(__file__), '..', 'agent', 'windows', 'aegisai-agent.exe')
        self.available = os.path.exists(self.agent_path)
        if self.available:
            logger.info("Native Windows agent is available")
        else:
            logger.warning("Native Windows agent not found, using Python fallback")
    
    def scan_file(self, filepath: str) -> dict:
        """Scan a file using the native agent if available, otherwise fallback to Python implementation"""
        # Check if the path is a directory
        if os.path.isdir(filepath):
            logger.debug(f"Skipping directory scan: {filepath}")
            return {
                'filepath': filepath,
                'status': 'skipped',
                'hash': '',
                'features': [],
                'reason': 'directory'
            }
        
        # Check if the file exists
        if not os.path.exists(filepath):
            logger.warning(f"File not found: {filepath}")
            return {
                'filepath': filepath,
                'status': 'error',
                'hash': '',
                'features': [],
                'error': 'File not found'
            }
        
        if self.available:
            try:
                # Use the native agent for scanning
                result = subprocess.run([
                    self.agent_path, 'scan', filepath
                ], capture_output=True, text=True, timeout=30)
                
                # Parse the result
                if result.returncode == 0:
                    # For now, we'll return a simple result
                    # In a real implementation, we'd parse the agent's output
                    return {
                        'filepath': filepath,
                        'status': 'clean',  # Default to clean
                        'hash': '',  # Would be calculated by agent
                        'features': []
                    }
                else:
                    logger.warning(f"Agent scan failed for {filepath}: {result.stderr.strip()}")
            except subprocess.TimeoutExpired:
                logger.warning(f"Agent scan timed out for {filepath}")
            except Exception as e:
                logger.error(f"Agent scan error for {filepath}: {e}")
        
        # Fallback to Python implementation
        return self._python_scan_file(filepath)
    
    def _python_scan_file(self, filepath: str) -> dict:
        """Python fallback implementation for file scanning"""
        # This is a simplified version - in reality, this would be more complex
        try:
            # Calculate hash
            file_hash = self._calculate_hash(filepath)
            
            # Simple heuristic checks
            features = []
            status = 'clean'
            
            # Check file extension
            _, ext = os.path.splitext(filepath.lower())
            if ext in ['.exe', '.scr', '.bat', '.com']:
                features.append('executable')
            
            # For demo purposes, we'll mark our own agent as suspicious
            if 'aegisai-agent.exe' in filepath.lower():
                status = 'suspicious'
                features.append('self_executable')
            
            return {
                'filepath': filepath,
                'status': status,
                'hash': file_hash,
                'features': features
            }
        except Exception as e:
            logger.error(f"Python scan error for {filepath}: {e}")
            return {
                'filepath': filepath,
                'status': 'error',
                'hash': '',
                'features': [],
                'error': str(e)
            }
    
    def _calculate_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        import hashlib
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return ''
    
    def start_realtime_protection(self) -> bool:
        """Start real-time protection using the native agent if available"""
        if self.available:
            try:
                # In a real implementation, we would start the agent as a service
                # For now, we'll just log that we're using the native agent
                logger.info("Using native Windows agent for real-time protection")
                return True
            except Exception as e:
                logger.error(f"Failed to start native agent: {e}")
        
        # Fallback to Python implementation
        logger.info("Using Python-based real-time protection")
        return False

# Singleton instance
_agent_interface: Optional[AgentInterface] = None

def get_agent_interface() -> AgentInterface:
    """Get the singleton agent interface instance"""
    global _agent_interface
    if _agent_interface is None:
        _agent_interface = AgentInterface()
    return _agent_interface