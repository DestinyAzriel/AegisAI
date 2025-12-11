#!/usr/bin/env python3
"""
Run AegisAI Prototype
=====================

This script runs the AegisAI system as a prototype on your PC.
"""

import os
import sys
import time
import logging
from datetime import datetime

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

# Import core components
from core.scanner import FileScanner
from core.yara_scanner import YaraScanner
from core.behavioral_analyzer import BehavioralAnalyzer
from core.agent import AgentInterface
from core.predictive_threat_intelligence import PredictiveThreatIntelligenceEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """Main function to run the AegisAI prototype"""
    print("🛡️  AEGISAI PROTOTYPE SYSTEM")
    print("=" * 40)
    print()
    
    # Initialize components
    print("🚀 Initializing AegisAI components...")
    
    # Initialize file scanner
    scanner = FileScanner()
    print("✅ File scanner initialized")
    
    # Initialize YARA scanner
    yara_scanner = YaraScanner()
    print("✅ YARA scanner initialized")
    
    # Initialize behavioral analyzer
    behavioral_analyzer = BehavioralAnalyzer()
    print("✅ Behavioral analyzer initialized")
    
    # Initialize agent interface
    agent_interface = AgentInterface()
    print(f"✅ Agent interface initialized (Native agent: {'Available' if agent_interface.available else 'Not available'})")
    
    # Initialize predictive threat intelligence engine
    pti_engine = PredictiveThreatIntelligenceEngine()
    print("✅ Predictive threat intelligence engine initialized")
    
    print()
    print("✅ All components initialized successfully!")
    print()
    
    # Scan test files
    test_files = [
        "sample_test_files/clean_document.txt",
        "sample_test_files/clean_script.py",
        "sample_test_files/suspicious.bat",
        "sample_test_files/data.json"
    ]
    
    print("🔍 Scanning test files...")
    print()
    
    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"Scanning: {test_file}")
            
            # Use the agent interface to scan the file
            result = agent_interface.scan_file(test_file)
            print(f"  Status: {result.get('status', 'unknown')}")
            
            if 'hash' in result and result['hash']:
                print(f"  File Hash: {result['hash'][:16]}...")
            
            if 'error' in result:
                print(f"  Error: {result['error']}")
            
            # Process with predictive threat intelligence
            if result.get('status') == 'threat_detected' or result.get('status') == 'suspicious':
                pti_result = pti_engine.process_threat_detection(result)
                if pti_result:
                    print("  📊 Predictive Intelligence: Threat pattern analyzed")
            
            print()
        else:
            print(f"⚠️  File not found: {test_file}")
            print()
    
    # Demonstrate predictive intelligence
    print("🔮 Generating predictive threat intelligence...")
    intelligence = pti_engine.generate_predictive_intelligence()
    
    print("\n🚨 EMERGING THREAT PATTERNS:")
    emerging = intelligence.get('emerging_threats', [])
    if emerging:
        for threat in emerging[:3]:  # Show top 3
            print(f"  • {threat.get('description', 'Unknown pattern')}")
    else:
        print("  No emerging threat patterns detected")
    
    print("\n🔧 SYSTEM HARDENING RECOMMENDATIONS:")
    recommendations = intelligence.get('hardening_recommendations', [])
    if recommendations:
        for rec in recommendations[:3]:  # Show top 3
            severity = rec.get('severity', 'unknown').upper()
            print(f"  [{severity}] {rec.get('description', 'Unknown recommendation')}")
    else:
        print("  No specific hardening recommendations")
    
    print("\n✅ AegisAI prototype demonstration complete!")
    print()
    print("The system has successfully demonstrated:")
    print("  • Multi-layered file scanning")
    print("  • Predictive threat intelligence")
    print("  • Proactive security recommendations")
    print()
    print("🛡️  AegisAI - Beyond Traditional Antivirus")

if __name__ == "__main__":
    main()