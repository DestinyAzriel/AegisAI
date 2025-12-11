"""
Predictive Threat Intelligence Integration for AegisAI
=====================================================

This module integrates the predictive threat intelligence engine with the
existing AegisAI system components.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__)))

from predictive_threat_intelligence import PredictiveThreatIntelligenceEngine

logger = logging.getLogger(__name__)

class PTIIntegration:
    """Integration layer for predictive threat intelligence"""
    
    def __init__(self):
        """Initialize the PTI integration"""
        self.pti_engine = PredictiveThreatIntelligenceEngine()
        self.enabled = True
        self.analysis_interval = 10  # Analyze every 10 threat detections
        self.detection_count = 0
        
    def process_threat_detection(self, detection_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process a threat detection result through the predictive intelligence engine.
        
        Args:
            detection_result: Dictionary with threat detection results
            
        Returns:
            Dictionary with predictive intelligence insights or None
        """
        if not self.enabled:
            return None
            
        try:
            # Process the threat detection
            threat_info = self.pti_engine.process_threat_detection(detection_result)
            
            # Increment detection counter
            self.detection_count += 1
            
            # Generate intelligence periodically
            if self.detection_count % self.analysis_interval == 0:
                intelligence = self.pti_engine.generate_predictive_intelligence()
                return intelligence
                
            return None
            
        except Exception as e:
            logger.error(f"Error processing threat detection in PTI: {e}")
            return None
    
    def get_current_intelligence(self) -> Dict[str, Any]:
        """
        Get current predictive threat intelligence.
        
        Returns:
            Dictionary with current intelligence
        """
        try:
            return self.pti_engine.generate_predictive_intelligence()
        except Exception as e:
            logger.error(f"Error generating predictive intelligence: {e}")
            return {}
    
    def get_threat_evolution_report(self) -> Dict[str, Any]:
        """
        Get threat evolution report.
        
        Returns:
            Dictionary with threat evolution information
        """
        try:
            return self.pti_engine.get_threat_evolution_report()
        except Exception as e:
            logger.error(f"Error generating threat evolution report: {e}")
            return {}
    
    def enable(self):
        """Enable predictive threat intelligence"""
        self.enabled = True
        logger.info("Predictive Threat Intelligence enabled")
    
    def disable(self):
        """Disable predictive threat intelligence"""
        self.enabled = False
        logger.info("Predictive Threat Intelligence disabled")
    
    def set_analysis_interval(self, interval: int):
        """
        Set the analysis interval.
        
        Args:
            interval: Number of detections between analyses
        """
        self.analysis_interval = max(1, interval)
        logger.info(f"Analysis interval set to {self.analysis_interval}")

# Global PTI integration instance
_pti_integration: Optional[PTIIntegration] = None

def get_pti_integration() -> PTIIntegration:
    """Get the global PTI integration instance"""
    global _pti_integration
    if _pti_integration is None:
        _pti_integration = PTIIntegration()
    return _pti_integration

def integrate_with_scanner(scanner_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Integrate PTI with the file scanner.
    
    Args:
        scanner_result: Dictionary with scanner results
        
    Returns:
        Dictionary with enhanced results including PTI insights
    """
    # Get PTI integration instance
    pti = get_pti_integration()
    
    # Process threat detection if threat was found
    if scanner_result.get('status') == 'threat_detected':
        intelligence = pti.process_threat_detection(scanner_result)
        if intelligence:
            scanner_result['predictive_intelligence'] = intelligence
    
    return scanner_result

def integrate_with_ml_detector(ml_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Integrate PTI with the ML detector.
    
    Args:
        ml_result: Dictionary with ML detection results
        
    Returns:
        Dictionary with enhanced results including PTI insights
    """
    # Get PTI integration instance
    pti = get_pti_integration()
    
    # Process threat detection
    intelligence = pti.process_threat_detection(ml_result)
    if intelligence:
        ml_result['predictive_intelligence'] = intelligence
    
    return ml_result

def integrate_with_yara_scanner(yara_result: Dict[str, Any], file_path: str) -> Dict[str, Any]:
    """
    Integrate PTI with the YARA scanner.
    
    Args:
        yara_result: Dictionary with YARA scan results
        file_path: Path to the scanned file
        
    Returns:
        Dictionary with enhanced results including PTI insights
    """
    # Get PTI integration instance
    pti = get_pti_integration()
    
    # Process threat detection if matches were found
    first_match = None
    if yara_result and isinstance(yara_result, list) and len(yara_result) > 0:
        for match in yara_result:
            first_match = match
            break
            
        # Create a detection result format compatible with PTI
        detection_result = {
            'file_path': file_path,
            'scan_time': datetime.now().isoformat(),
            'threat': {
                'type': 'yara',
                'name': first_match.get('rule', 'Unknown') if isinstance(first_match, dict) else 'Unknown',
                'severity': 'malicious',
                'confidence': 0.9,
                'malware_type': first_match.get('namespace', 'unknown') if isinstance(first_match, dict) else 'unknown',
                'description': 'Matched YARA rule'
            },
            'yara_matches': yara_result
        }
        
        intelligence = pti.process_threat_detection(detection_result)
        if intelligence:
            return {
                'yara_matches': yara_result,
                'predictive_intelligence': intelligence
            }
    
    return {
        'yara_matches': yara_result
    }

def get_system_hardening_recommendations() -> Dict[str, Any]:
    """
    Get system hardening recommendations based on current threat intelligence.
    
    Returns:
        Dictionary with hardening recommendations
    """
    pti = get_pti_integration()
    intelligence = pti.get_current_intelligence()
    
    return {
        'timestamp': datetime.now().isoformat(),
        'recommendations': intelligence.get('hardening_recommendations', []),
        'emerging_threats': intelligence.get('emerging_threats', []),
        'attack_patterns': intelligence.get('attack_patterns', {})
    }

def save_intelligence_report(filepath: str = "threat_intelligence_report.json"):
    """
    Save a comprehensive threat intelligence report to a file.
    
    Args:
        filepath: Path to save the report
    """
    pti = get_pti_integration()
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'predictive_intelligence': pti.get_current_intelligence(),
        'threat_evolution': pti.get_threat_evolution_report()
    }
    
    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Threat intelligence report saved to {filepath}")
    except Exception as e:
        logger.error(f"Failed to save threat intelligence report: {e}")

# Example of how to integrate with the main AegisAI orchestrator
def enhance_aegisai_orchestrator(orchestrator):
    """
    Enhance the AegisAI orchestrator with predictive threat intelligence.
    
    Args:
        orchestrator: AegisAIOrchestrator instance
    """
    # Monkey patch the scan_file method to include PTI
    original_scan_file = orchestrator.scan_file
    
    def enhanced_scan_file(file_path: str) -> Dict[str, Any]:
        # Call original scan method
        result = original_scan_file(file_path)
        
        # Integrate with PTI
        enhanced_result = integrate_with_scanner(result)
        
        return enhanced_result
    
    # Replace the method
    orchestrator.scan_file = enhanced_scan_file
    
    # Add PTI status to system status
    original_get_status = orchestrator.get_status
    
    def enhanced_get_status() -> Dict[str, Any]:
        status = original_get_status()
        
        # Add PTI status
        pti = get_pti_integration()
        status['predictive_intelligence'] = {
            'enabled': pti.enabled,
            'detections_processed': pti.detection_count,
            'analysis_interval': pti.analysis_interval
        }
        
        return status
    
    # Replace the method
    orchestrator.get_status = enhanced_get_status
    
    logger.info("AegisAI orchestrator enhanced with Predictive Threat Intelligence")

if __name__ == "__main__":
    # Demo the integration
    print("🛡️  AEGISAI Predictive Threat Intelligence Integration Demo")
    print("=" * 60)
    
    # Create integration instance
    pti_integration = PTIIntegration()
    
    # Simulate threat detections
    sample_detections = [
        {
            "file_path": "C:\\Users\\Test\\Downloads\\trojan.exe",
            "scan_time": "2025-10-15T10:30:00Z",
            "status": "threat_detected",
            "threat": {
                "type": "signature",
                "name": "Trojan.Generic.12345",
                "severity": "malicious",
                "confidence": 0.95,
                "malware_type": "trojan",
                "description": "Generic trojan detected"
            }
        },
        {
            "file_path": "C:\\Users\\Test\\Documents\\ransomware.exe",
            "scan_time": "2025-10-15T11:15:00Z",
            "status": "threat_detected",
            "threat": {
                "type": "heuristic",
                "name": "Suspicious File Encryption",
                "severity": "malicious",
                "confidence": 0.85,
                "malware_type": "ransomware",
                "description": "File exhibits ransomware characteristics"
            }
        }
    ]
    
    print("Processing sample threat detections...")
    for i, detection in enumerate(sample_detections):
        print(f"\nProcessing detection {i+1}:")
        intelligence = pti_integration.process_threat_detection(detection)
        
        if intelligence and i == len(sample_detections) - 1:  # Show intelligence on last detection
            print("  📊 Generated Predictive Intelligence:")
            emerging = intelligence.get('emerging_threats', [])
            if emerging:
                print(f"    Emerging Threats: {len(emerging)}")
            recommendations = intelligence.get('hardening_recommendations', [])
            if recommendations:
                print(f"    Hardening Recommendations: {len(recommendations)}")
    
    print("\n✅ Integration demo completed successfully!")
    print("\n💡 The Predictive Threat Intelligence engine is now ready to be")
    print("   integrated with the main AegisAI system for proactive threat")
    print("   detection and prevention!")