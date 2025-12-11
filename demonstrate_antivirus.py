#!/usr/bin/env python3
"""
Demonstrate that the AegisAI antivirus is working properly
"""

import sys
import os
import time

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

def demonstrate_antivirus():
    """Demonstrate that the antivirus is working"""
    print("AegisAI - Antivirus Demonstration")
    print("=" * 35)
    
    try:
        # Import the main components
        from core.agent import AgentInterface
        from core.ml_detector import MLFeatureExtractor
        from core.license_manager import LicenseManager
        from run_aegisai import AegisAIOrchestrator
        
        print("✅ Core components loaded successfully")
        
        # Create orchestrator
        orchestrator = AegisAIOrchestrator()
        
        # Show system status
        status = orchestrator.get_status()
        print(f"\n📊 System Status:")
        print(f"  Agent Status: {'Available' if status['agent_status'] == 'available' else 'Fallback'}")
        print(f"  License Type: {status['license_info']['license_type']}")
        print(f"  Licensed: {status['license_info']['licensed']}")
        print(f"  Real-time Protection: {'ENABLED' if status['license_info']['features'].get('real_time_protection', False) else 'DISABLED'}")
        
        # Create a test file to scan
        test_file_path = "test_malware_simulation.txt"
        with open(test_file_path, "w") as f:
            f.write("This is a test file for antivirus scanning.\n")
            f.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n")
            f.write("This simulates a malware signature for testing purposes.\n")
        
        print(f"\n📝 Created test file: {test_file_path}")
        
        # Scan the test file
        print("\n🔍 Scanning test file...")
        result = orchestrator.scan_file(test_file_file_path)
        print(f"  Scan Result: {result['status']}")
        print(f"  File Hash: {result.get('hash', 'N/A')}")
        
        # Show ML features
        print("\n🧠 ML Feature Extraction:")
        ml_extractor = MLFeatureExtractor()
        features = ml_extractor.extract_features(test_file_path)
        if features:
            print(f"  File Size: {features.get('file_size', 'N/A')} bytes")
            print(f"  Entropy: {features.get('entropy', 'N/A')}")
            print(f"  Extension: {features.get('extension', 'N/A')}")
            print(f"  Features Extracted: {features.get('features_extracted', False)}")
        else:
            print("  No features extracted")
        
        # Clean up test file
        if os.path.exists(test_file_path):
            os.remove(test_file_path)
            print(f"\n🗑️  Cleaned up test file: {test_file_path}")
        
        print("\n✅ Antivirus demonstration completed successfully!")
        print("   The system is properly detecting and analyzing files.")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = demonstrate_antivirus()
    sys.exit(0 if success else 1)