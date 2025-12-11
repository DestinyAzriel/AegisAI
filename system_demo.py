#!/usr/bin/env python3
"""
AegisAI System Demo
Demonstrates the full capabilities of the AegisAI antivirus system
"""

import sys
import os
import time
import logging

# Suppress logging output
logging.getLogger().setLevel(logging.CRITICAL)

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

def demo_system_overview():
    """Demonstrate the AegisAI system overview"""
    print("AegisAI Advanced Endpoint Protection System")
    print("=" * 50)
    
    # Import and initialize components
    try:
        from core.agent import AgentInterface
        from core.yara_scanner import YaraScanner
        from core.ml_detector import MLFeatureExtractor
        from core.signature_updater import SignatureUpdater
        from core.predictive_threat_intelligence import PredictiveThreatIntelligenceEngine
        from core.realtime import RealTimeBehavioralMonitor
        
        print("✅ All core components imported successfully")
        
        # Initialize components
        agent = AgentInterface()
        yara_scanner = YaraScanner()
        ml_detector = MLFeatureExtractor()
        signature_updater = SignatureUpdater("signatures.db")
        pti_engine = PredictiveThreatIntelligenceEngine()
        behavioral_monitor = RealTimeBehavioralMonitor()
        
        print("✅ All core components initialized successfully")
        
        # Show system capabilities
        print("\n🛡️  AegisAI Core Capabilities:")
        print("  • Real-time file monitoring")
        print("  • Multi-layered threat detection")
        print("  • Behavioral analysis")
        print("  • Predictive threat intelligence")
        print("  • Machine learning-based classification")
        print("  • YARA pattern matching")
        print("  • Signature-based detection")
        
        # Show available test files
        test_files_dir = "sample_test_files"
        if os.path.exists(test_files_dir):
            test_files = os.listdir(test_files_dir)
            print(f"\n📁 Available test files ({len(test_files)}):")
            for file in test_files:
                print(f"  • {file}")
        
        # Demonstrate file scanning
        print("\n🔍 Demonstrating file scanning capabilities...")
        
        # Scan a clean file
        clean_file = os.path.join(test_files_dir, "clean_document.txt")
        if os.path.exists(clean_file):
            result = agent.scan_file(clean_file)
            print(f"  Clean file scan result: {result['status']}")
        
        # Scan a suspicious file
        susp_file = os.path.join(test_files_dir, "suspicious.bat")
        if os.path.exists(susp_file):
            result = agent.scan_file(susp_file)
            print(f"  Suspicious file scan result: {result['status']}")
            
            # Apply ML detection
            ml_features = ml_detector.extract_features(susp_file)
            print(f"  ML feature extraction: {ml_features.get('features_extracted', False)}")
            if 'entropy' in ml_features:
                print(f"  File entropy: {ml_features['entropy']:.2f}")
        
        # Demonstrate behavioral monitoring
        print("\n👁️  Demonstrating real-time behavioral monitoring...")
        stats = behavioral_monitor.get_statistics()
        print(f"  Monitoring status: {stats['monitoring_active']}")
        print(f"  Monitored paths: {len(stats['monitored_paths'])}")
        
        # Demonstrate predictive threat intelligence
        print("\n🔮 Demonstrating predictive threat intelligence...")
        intelligence = pti_engine.generate_predictive_intelligence()
        emerging_threats = intelligence.get('emerging_threats', [])
        print(f"  Emerging threats detected: {len(emerging_threats)}")
        
        print("\n🎉 AegisAI System Demo Completed Successfully!")
        print("\nTo run full protection mode, use: python run_aegisai.py")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = demo_system_overview()
    sys.exit(0 if success else 1)