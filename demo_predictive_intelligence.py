#!/usr/bin/env python3
"""
AegisAI Predictive Intelligence Demonstration
============================================

This script demonstrates the predictive threat intelligence capabilities
that make AegisAI different from traditional antivirus solutions.
"""

import os
import sys
import json
import time
import random
from datetime import datetime

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from core.predictive_threat_intelligence import PredictiveThreatIntelligenceEngine

def generate_sample_threats():
    """Generate sample threat detections to demonstrate predictive intelligence"""
    threats = []
    
    # Sample threat data
    threat_types = [
        {
            "name": "Trojan.Generic",
            "type": "trojan",
            "malware_family": "trojan",
            "attack_techniques": ["CreateProcess", "WriteProcessMemory", "RegSetValue"],
            "file_characteristics": {"size": 1024000, "entropy": 7.2}
        },
        {
            "name": "Ransomware.Crypt",
            "type": "ransomware",
            "malware_family": "ransomware",
            "attack_techniques": ["encrypt", "WriteFile", "CreateFile"],
            "file_characteristics": {"size": 2048000, "entropy": 7.9}
        },
        {
            "name": "Worm.Network",
            "type": "worm",
            "malware_family": "worm",
            "attack_techniques": ["WSAStartup", "connect", "send"],
            "file_characteristics": {"size": 512000, "entropy": 6.8}
        },
        {
            "name": "Keylogger.Stealth",
            "type": "keylogger",
            "malware_family": "keylogger",
            "attack_techniques": ["GetAsyncKeyState", "GetKeyboardState", "WriteFile"],
            "file_characteristics": {"size": 256000, "entropy": 5.5}
        }
    ]
    
    # Generate 20 sample threats with some repetition to show patterns
    for i in range(20):
        threat_template = random.choice(threat_types)
        threat_id = f"{threat_template['name']}.{random.randint(1000, 9999)}"
        
        threat = {
            "file_path": f"C:\\Users\\User\\Downloads\\{threat_id}.exe",
            "scan_time": datetime.now().isoformat(),
            "status": "threat_detected",
            "threat": {
                "type": threat_template["type"],
                "name": threat_id,
                "severity": random.choice(["suspicious", "malicious"]),
                "confidence": random.uniform(0.7, 0.99),
                "malware_type": threat_template["malware_family"],
                "description": f"Detected {threat_template['malware_family']} malware"
            },
            "file_size": threat_template["file_characteristics"]["size"],
            "entropy": threat_template["file_characteristics"]["entropy"],
            "analysis": {
                "indicators": random.sample(threat_template["attack_techniques"], 
                                          random.randint(1, len(threat_template["attack_techniques"])))
            }
        }
        threats.append(threat)
    
    return threats

def main():
    """Main demonstration function"""
    print("🛡️  AEGISAI PREDICTIVE THREAT INTELLIGENCE DEMONSTRATION")
    print("=" * 60)
    print()
    print("Traditional antivirus: Scans files → Detects threats → Quarantines")
    print("AegisAI: Scans files → Predicts threats → Hardens system → Prevents attacks")
    print()
    
    # Initialize the predictive threat intelligence engine
    print("🚀 Initializing Predictive Threat Intelligence Engine...")
    pti_engine = PredictiveThreatIntelligenceEngine()
    time.sleep(1)
    print("✅ Engine initialized")
    print()
    
    # Generate sample threats
    print("📊 Generating sample threat detections...")
    sample_threats = generate_sample_threats()
    print(f"✅ Generated {len(sample_threats)} sample threats")
    print()
    
    # Process threats and show intelligence building
    print("🔍 Processing threats and building predictive intelligence...")
    for i, threat in enumerate(sample_threats):
        # Process each threat
        pti_engine.process_threat_detection(threat)
        
        # Show progress
        if (i + 1) % 5 == 0:
            print(f"  Processed {i + 1}/{len(sample_threats)} threats...")
        
        # Occasionally show emerging intelligence
        if (i + 1) % 10 == 0:
            intelligence = pti_engine.generate_predictive_intelligence()
            emerging = intelligence.get('emerging_threats', [])
            if emerging:
                print(f"  🚨 Detected {len(emerging)} emerging threat patterns")
    
    print()
    print("✅ All threats processed successfully")
    print()
    
    # Generate comprehensive predictive intelligence report
    print("📈 GENERATING PREDICTIVE INTELLIGENCE REPORT")
    print("=" * 45)
    intelligence = pti_engine.generate_predictive_intelligence()
    
    # Display emerging threats
    print("\n🚨 EMERGING THREAT PATTERNS")
    print("-" * 25)
    emerging_threats = intelligence.get('emerging_threats', [])
    if emerging_threats:
        for threat in emerging_threats[:5]:  # Show top 5
            confidence = threat.get('confidence', 0) * 100
            print(f"  🔥 {threat.get('description', 'Unknown pattern')}")
            print(f"     Confidence: {confidence:.1f}%")
            if 'family' in threat:
                print(f"     Family: {threat['family']}")
            print()
    else:
        print("  No emerging threat patterns detected at this time.")
    
    # Display attack pattern insights
    print("\n🎯 ATTACK PATTERN ANALYSIS")
    print("-" * 23)
    attack_patterns = intelligence.get('attack_patterns', {})
    technique_dist = attack_patterns.get('technique_distribution', {})
    
    if technique_dist:
        print("  Most Common Attack Techniques:")
        sorted_techniques = sorted(technique_dist.items(), key=lambda x: x[1], reverse=True)
        for technique, count in sorted_techniques[:5]:
            print(f"    {technique}: {count} occurrences")
    else:
        print("  No attack patterns identified.")
    
    # Display hardening recommendations
    print("\n🔧 PROACTIVE SYSTEM HARDENING RECOMMENDATIONS")
    print("-" * 43)
    recommendations = intelligence.get('hardening_recommendations', [])
    
    if recommendations:
        # Group by severity
        critical = [r for r in recommendations if r.get('severity') == 'critical']
        high = [r for r in recommendations if r.get('severity') == 'high']
        medium = [r for r in recommendations if r.get('severity') == 'medium']
        
        for rec_group, group_name in [(critical, "CRITICAL"), (high, "HIGH"), (medium, "MEDIUM")]:
            if rec_group:
                print(f"\n  [{group_name}] Priority Recommendations:")
                for rec in rec_group[:2]:  # Show top 2 per severity
                    print(f"    • {rec.get('description', 'Unknown recommendation')}")
    else:
        print("  No specific hardening recommendations at this time.")
    
    # Display threat statistics
    print("\n📊 THREAT INTELLIGENCE STATISTICS")
    print("-" * 33)
    stats = intelligence.get('threat_statistics', {})
    for key, value in stats.items():
        formatted_key = key.replace('_', ' ').title()
        print(f"  {formatted_key}: {value}")
    
    print("\n" + "=" * 60)
    print("✨ AEGISAI PREDICTIVE INTELLIGENCE SUMMARY")
    print("=" * 60)
    print()
    print("What makes AegisAI different:")
    print("  🔮 Predictive Threat Intelligence - Anticipate future attacks")
    print("  🧠 Attack Pattern Analysis - Understand how malware evolves")
    print("  🛡️ Proactive Hardening - Strengthen your system before attacks")
    print("  🎯 Targeted Recommendations - Actionable security improvements")
    print()
    print("This transforms AegisAI from reactive antivirus to proactive")
    print("cybersecurity intelligence platform!")
    print()
    print("The future of endpoint protection is here. 🚀")

if __name__ == "__main__":
    main()