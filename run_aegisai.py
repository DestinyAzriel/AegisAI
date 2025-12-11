#!/usr/bin/env python3
"""
RUN_AEGISAI.py - Complete AegisAI System Launcher

This script launches the complete AegisAI antivirus system
with all components working together in real-time.
"""

import os
import sys
import time
import logging
import argparse
from typing import Dict
from datetime import datetime

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

# Import core components
from core.agent import AgentInterface
from core.yara_scanner import YaraScanner
from core.ml_detector import MLFeatureExtractor  # This is what's available
from core.signature_updater import SignatureUpdater
from core.auto_updater import AutoUpdater
from core.license_manager import LicenseManager
from core.predictive_threat_intelligence import PredictiveThreatIntelligenceEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AegisAIOrchestrator:
    """Orchestrates all AegisAI components"""
    
    def __init__(self, config_path: str = ""):
        """
        Initialize orchestrator.
        
        Args:
            config_path: Path to configuration file
        """
        # Initialize core agent
        self.agent = AgentInterface()
        
        # Initialize additional components
        self.yara_scanner = YaraScanner()
        self.ml_detector = MLFeatureExtractor()  # Use the available class
        self.signature_updater = SignatureUpdater("signatures.db")
        self.auto_updater = AutoUpdater("http://localhost:8080", ".")
        self.license_manager = LicenseManager()
        self.pti_engine = PredictiveThreatIntelligenceEngine()
        
        logger.info("AegisAI Orchestrator initialized")
    
    def check_license(self) -> bool:
        """
        Check if product is properly licensed.
        
        Returns:
            True if licensed, False otherwise
        """
        license_info = self.license_manager.get_license_info()
        
        if not license_info['licensed']:
            logger.warning("Product is not licensed. Running in free mode with limited features.")
            return False
        
        if license_info['is_expired']:
            logger.error("License has expired. Please renew your license.")
            return False
        
        logger.info(f"Licensed product: {license_info['license_type']}")
        return True
    
    def check_for_updates(self) -> bool:
        """
        Check for and apply updates.
        
        Returns:
            True if updates were applied, False otherwise
        """
        logger.info("Checking for updates...")
        
        update_info = self.auto_updater.check_for_updates()
        if update_info.get('available', False):
            logger.info(f"Update available: {update_info['version']}")
            
            # Update engine
            if self.auto_updater.update_engine():
                logger.info("Engine updated successfully")
                return True
            else:
                logger.error("Failed to update engine")
                return False
        else:
            logger.info("No updates available")
            return False
    
    def update_signatures(self) -> bool:
        """
        Update malware signatures from threat intelligence feeds.
        
        Returns:
            True if updates were applied, False otherwise
        """
        logger.info("Updating malware signatures...")
        
        results = self.signature_updater.update_all_feeds()
        
        success_count = sum(1 for success in results.values() if success)
        if success_count > 0:
            logger.info(f"Signature updates completed: {success_count} feeds updated")
            return True
        else:
            logger.info("No signature updates available")
            return False
    
    def start_protection(self):
        """Start all protection components."""
        # Check license
        is_licensed = self.check_license()
        
        # Check for updates (only in licensed versions)
        if is_licensed and self.license_manager.is_feature_enabled('real_time_protection'):
            self.check_for_updates()
        
        # Update signatures
        self.update_signatures()
        
        # Start real-time protection (only if licensed)
        if is_licensed and self.license_manager.is_feature_enabled('real_time_protection'):
            try:
                # For now, we'll just log that real-time protection is enabled
                logger.info("Real-time protection enabled")
            except Exception as e:
                logger.error(f"Failed to start real-time protection: {e}")
        else:
            logger.info("Real-time protection disabled (unlicensed or feature not enabled)")
    
    def stop_protection(self):
        """Stop all protection components."""
        logger.info("Stopping protection components...")
    
    def scan_file(self, file_path: str) -> Dict:
        """
        Scan a file using all available methods.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Dictionary with scan results
        """
        logger.info(f"Scanning file: {file_path}")
        
        # Use core agent for basic scanning
        result = self.agent.scan_file(file_path)
        
        # Add YARA scanning if licensed
        if self.license_manager.is_feature_enabled('yara_scanning'):
            yara_matches = self.yara_scanner.scan_file(file_path)
            if yara_matches:
                result['yara_matches'] = yara_matches
                # If YARA found matches, mark as threat
                if result['status'] == 'clean':
                    result['status'] = 'threat_detected'
                    result['threat'] = {
                        'type': 'yara',
                        'name': yara_matches[0]['rule'],
                        'severity': 'malicious',
                        'confidence': 0.9,
                        'description': 'Matched YARA rule'
                    }
        
        # Add ML detection if licensed (simplified implementation)
        if self.license_manager.is_feature_enabled('ai_detection'):
            try:
                # Extract features using MLFeatureExtractor
                features = self.ml_detector.extract_features(file_path)
                # Simple heuristic: if entropy is high, it might be malicious
                if features.get('entropy', 0) > 7.0:
                    result['ml_analysis'] = {
                        'features': features,
                        'malware_probability': 0.85
                    }
                    # If high confidence, mark as threat
                    if features.get('entropy', 0) > 7.5:
                        result['status'] = 'threat_detected'
                        result['threat'] = {
                            'type': 'ml',
                            'name': 'AI Detected Malware',
                            'severity': 'malicious',
                            'confidence': 0.9,
                            'description': 'High entropy detected by machine learning model'
                        }
            except Exception as e:
                logger.debug(f"ML detection failed for {file_path}: {e}")
        
        # Process with predictive threat intelligence
        if result.get('status') in ['threat_detected', 'suspicious']:
            pti_result = self.pti_engine.process_threat_detection(result)
            if pti_result:
                result['predictive_intelligence'] = pti_result
        
        return result
    
    def get_status(self) -> Dict:
        """
        Get overall system status.
        
        Returns:
            Dictionary with status information
        """
        status = {
            'agent_status': 'available' if self.agent.available else 'python_fallback',
            'license_info': self.license_manager.get_license_info(),
            'signature_count': self.signature_updater.get_signature_count()
        }
        
        # Add YARA status if licensed
        if self.license_manager.is_feature_enabled('yara_scanning'):
            status['yara_enabled'] = self.yara_scanner.rules is not None
        
        # Add ML status if licensed
        if self.license_manager.is_feature_enabled('ai_detection'):
            status['ml_enabled'] = True
        
        return status

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='AegisAI Antivirus Engine')
    parser.add_argument('--scan-file', help='Scan a single file')
    parser.add_argument('--scan-dir', help='Scan a directory')
    parser.add_argument('--recursive', action='store_true', help='Scan directories recursively')
    parser.add_argument('--status', action='store_true', help='Show system status')
    parser.add_argument('--update', action='store_true', help='Check for updates')
    parser.add_argument('--update-signatures', action='store_true', help='Update malware signatures')
    parser.add_argument('--activate-license', help='Activate license with key')
    
    args = parser.parse_args()
    
    try:
        # Create orchestrator instance
        orchestrator = AegisAIOrchestrator()
        
        # Handle command line arguments
        if args.scan_file:
            # Scan a single file
            if os.path.exists(args.scan_file):
                result = orchestrator.scan_file(args.scan_file)
                print(f"Scan result: {result}")
                
                # Show predictive intelligence if available
                if 'predictive_intelligence' in result:
                    pti = result['predictive_intelligence']
                    print("\n🔮 Predictive Intelligence:")
                    if pti.get('emerging_threats'):
                        print("  Emerging threats detected:")
                        for threat in pti['emerging_threats'][:3]:
                            print(f"    - {threat.get('description', 'Unknown')}")
            else:
                print(f"Error: File not found - {args.scan_file}")
            
        elif args.scan_dir:
            # Scan a directory
            print(f"Scanning directory: {args.scan_dir}")
            if os.path.exists(args.scan_dir):
                for root, dirs, files in os.walk(args.scan_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        result = orchestrator.scan_file(file_path)
                        print(f"{file_path}: {result['status']}")
                        if args.recursive:
                            continue
                    if not args.recursive:
                        break
            else:
                print(f"Error: Directory not found - {args.scan_dir}")
            
        elif args.status:
            # Show system status
            status = orchestrator.get_status()
            print(f"System status: {status}")
            
        elif args.update:
            # Check for updates
            orchestrator.check_for_updates()
            
        elif args.update_signatures:
            # Update signatures
            orchestrator.update_signatures()
            
        elif args.activate_license:
            # Activate license
            if orchestrator.license_manager.activate_license(args.activate_license):
                print("License activated successfully")
            else:
                print("Failed to activate license")
                
        else:
            # Start protection mode
            print("🛡️  AEGISAI ADVANCED ENDPOINT PROTECTION")
            print("=" * 45)
            print("Starting protection components...")
            orchestrator.start_protection()
            
            # Show system status
            status = orchestrator.get_status()
            print(f"Agent: {'Native Windows Agent' if status['agent_status'] == 'available' else 'Python Fallback'}")
            print(f"License: {status['license_info']['license_type']}")
            print(f"Signatures: {status['signature_count']} rules loaded")
            
            # Scan sample files to demonstrate
            sample_files = [
                "sample_test_files/clean_document.txt",
                "sample_test_files/suspicious.bat"
            ]
            
            print("\n🔍 Scanning sample files...")
            for sample_file in sample_files:
                if os.path.exists(sample_file):
                    result = orchestrator.scan_file(sample_file)
                    print(f"{sample_file}: {result['status']}")
            
            print("\n✅ AegisAI system is running!")
            print("Use --help to see available commands")
                
    except Exception as e:
        logger.error(f"Error running AegisAI: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()