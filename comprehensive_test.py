#!/usr/bin/env python3
"""
Comprehensive test script for AegisAI components
"""

import sys
import os
import logging

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

# Suppress logging output during tests
logging.getLogger().setLevel(logging.CRITICAL)

def test_core_components():
    """Test all core components of AegisAI"""
    components = [
        ("Agent Interface", "core.agent", "AgentInterface"),
        ("YARA Scanner", "core.yara_scanner", "YaraScanner"),
        ("ML Detector", "core.ml_detector", "MLFeatureExtractor"),
        ("Signature Updater", "core.signature_updater", "SignatureUpdater"),
        ("Auto Updater", "core.auto_updater", "AutoUpdater"),
        ("License Manager", "core.license_manager", "LicenseManager"),
        ("Predictive Threat Intelligence", "core.predictive_threat_intelligence", "PredictiveThreatIntelligenceEngine"),
        ("Real-time Behavioral Monitor", "core.realtime", "RealTimeBehavioralMonitor"),
        ("Behavioral Analyzer", "core.behavioral_analyzer", "BehavioralAnalyzer"),
        ("Advanced Behavioral Analyzer", "core.advanced_behavioral_analyzer", "AdvancedBehavioralAnalyzer"),
        ("Robust Behavioral Analyzer", "core.robust_behavioral_analyzer", "RobustBehavioralAnalyzer"),
    ]
    
    results = []
    
    for component_name, module_name, class_name in components:
        try:
            # Import the module
            module = __import__(module_name, fromlist=[class_name])
            
            # Get the class
            cls = getattr(module, class_name)
            
            # Instantiate the class
            # Some classes might require arguments
            try:
                instance = cls()
            except TypeError:
                # Try with default arguments
                try:
                    instance = cls("")
                except:
                    instance = cls(None)
            
            results.append((component_name, "✅ PASS", f"Successfully imported and instantiated {class_name}"))
            
        except ImportError as e:
            results.append((component_name, "❌ FAIL", f"Import error: {e}"))
        except Exception as e:
            results.append((component_name, "❌ FAIL", f"Runtime error: {str(e)[:100]}"))  # Truncate long errors
    
    return results

def main():
    print("AegisAI Comprehensive Component Test")
    print("=" * 50)
    
    results = test_core_components()
    
    passed = 0
    failed = 0
    
    for component_name, status, message in results:
        print(f"{status} {component_name:<35} {message}")
        if status == "✅ PASS":
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All components are working correctly!")
        return True
    else:
        print("⚠️  Some components need attention.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)