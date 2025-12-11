#!/usr/bin/env python3
"""
AegisAI ML Enhancement Demo
===========================

This script demonstrates the enhanced machine learning capabilities
of the AegisAI system, including:
- Enhanced file classification using deep learning
- Behavioral analysis using ML models
- Ensemble threat detection combining multiple models
"""

import os
import sys
import json
from datetime import datetime

# Add the project root to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from core.enhanced_ml_detector import EnhancedMLDetector
from core.behavioral_ml_analyzer import BehavioralMLAnalyzer
from core.ensemble_threat_detector import EnsembleThreatDetector

def demonstrate_ml_enhancements():
    """Demonstrate the enhanced ML capabilities"""
    print("🛡️  AegisAI Enhanced ML Detection Demo")
    print("=" * 50)
    
    # Initialize enhanced ML components
    print("\n1. Initializing Enhanced ML Components...")
    file_detector = EnhancedMLDetector()
    behavioral_analyzer = BehavioralMLAnalyzer()
    ensemble_detector = EnsembleThreatDetector()
    
    print("   ✅ Enhanced ML Detector initialized")
    print("   ✅ Behavioral ML Analyzer initialized")
    print("   ✅ Ensemble Threat Detector initialized")
    
    # Demonstrate file feature extraction
    print("\n2. Demonstrating Enhanced File Feature Extraction...")
    
    # Test with this script file
    test_file = __file__
    features = file_detector.extract_enhanced_features(test_file)
    
    print(f"   File: {test_file}")
    print(f"   File Size: {features.get('file_size', 0)} bytes")
    print(f"   Entropy: {features.get('entropy', 0):.2f}")
    print(f"   Extension: {features.get('extension', 'N/A')}")
    print(f"   Byte Mean: {features.get('byte_mean', 0):.4f}")
    print(f"   Byte Std Dev: {features.get('byte_std', 0):.4f}")
    
    # Demonstrate file threat detection
    print("\n3. Demonstrating File Threat Detection...")
    
    # Test with this script file (should be clean)
    file_result = file_detector.predict_file_threat(test_file)
    print(f"   File: {test_file}")
    print(f"   Is Threat: {file_result.get('is_threat', False)}")
    print(f"   Confidence: {file_result.get('confidence', 0):.2f}")
    print(f"   Method: {file_result.get('method', 'N/A')}")
    
    # Demonstrate behavioral analysis
    print("\n4. Demonstrating Behavioral Analysis...")
    
    # Simulate some behavior recording
    entity_id = "demo_process_123"
    
    # Record normal behavior
    for i in range(5):
        behavioral_analyzer.record_behavior(entity_id, "file_operation")
        behavioral_analyzer.record_behavior(entity_id, "network_connection")
    
    # Get behavior summary
    behavior_summary = behavioral_analyzer.get_behavior_summary(entity_id)
    print(f"   Entity: {entity_id}")
    print(f"   Total Events: {behavior_summary.get('total_events', 0)}")
    print(f"   Event Distribution: {behavior_summary.get('event_distribution', {})}")
    
    # Detect anomalous behavior
    anomaly_result = behavioral_analyzer.detect_anomalous_behavior(entity_id)
    print(f"   Is Anomalous: {anomaly_result.get('is_anomalous', False)}")
    print(f"   Anomaly Score: {anomaly_result.get('anomaly_score', 0):.2f}")
    print(f"   Method: {anomaly_result.get('method', 'N/A')}")
    
    # Demonstrate ensemble threat detection
    print("\n5. Demonstrating Ensemble Threat Detection...")
    
    # Test ensemble detection
    ensemble_result = ensemble_detector.detect_threat(test_file, entity_id)
    print(f"   File: {test_file}")
    print(f"   Entity: {entity_id}")
    print(f"   Is Threat: {ensemble_result.get('is_threat', False)}")
    print(f"   Confidence: {ensemble_result.get('confidence', 0):.2f}")
    print(f"   Ensemble Score: {ensemble_result.get('ensemble_score', 0):.2f}")
    
    # Show individual model scores
    individual_scores = ensemble_result.get('individual_scores', {})
    print("   Individual Model Scores:")
    for model, score in individual_scores.items():
        print(f"     {model}: {score:.2f}")
    
    # Get comprehensive threat intelligence
    print("\n6. Getting Comprehensive Threat Intelligence...")
    
    intelligence = ensemble_detector.get_threat_intelligence(test_file, entity_id)
    threat_intel = intelligence.get('threat_intelligence', {})
    
    print(f"   Overall Assessment: {threat_intel.get('overall_assessment', 'N/A')}")
    print(f"   Confidence Level: {threat_intel.get('confidence_level', 0):.2f}")
    
    risk_factors = threat_intel.get('risk_factors', [])
    if risk_factors:
        print("   Risk Factors:")
        for factor in risk_factors:
            print(f"     - {factor}")
    
    recommendations = threat_intel.get('recommendations', [])
    if recommendations:
        print("   Recommendations:")
        for rec in recommendations:
            print(f"     - {rec}")
    
    print("\n🎉 ML Enhancement Demo Completed Successfully!")
    print("\nKey Enhanced ML Capabilities Demonstrated:")
    print("  • Deep feature extraction for files")
    print("  • Statistical analysis of file characteristics")
    print("  • Behavioral pattern analysis")
    print("  • Ensemble threat detection combining multiple models")
    print("  • Comprehensive threat intelligence reporting")

if __name__ == "__main__":
    # Run the demo
    demonstrate_ml_enhancements()