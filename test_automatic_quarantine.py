#!/usr/bin/env python3
"""
Test script for automatic quarantine functionality
"""

import sys
import os
import tempfile
import shutil

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

try:
    from quarantine import QuarantineManager
    print("✅ Quarantine manager loaded successfully")
except ImportError as e:
    print(f"❌ Failed to import quarantine manager: {e}")
    sys.exit(1)

def create_test_file(content, filename="test_malware.bat"):
    """Create a test file with suspicious content"""
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, filename)
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Created test file: {file_path}")
    return file_path

def test_quarantine_functionality():
    """Test automatic quarantine functionality"""
    print("\n🛡️  Testing automatic quarantine...")
    
    # Create quarantine manager
    quarantine_manager = QuarantineManager()
    print(f"Quarantine path: {quarantine_manager.quarantine_path}")
    
    # Create a test file with suspicious content
    suspicious_content = """
@echo off
echo Malicious script detected
reg add HKCU\\Software\\Malware /v Test /t REG_SZ /d "Malicious"
"""
    
    test_file = create_test_file(suspicious_content, "test_suspicious.bat")
    
    # Test quarantine
    threat_info = {
        'type': 'Suspicious Script',
        'severity': 'SUSPICIOUS',
        'confidence': 85.0,
        'detection_methods': ['Behavioral: suspicious patterns'],
        'description': 'Script contains registry modification commands'
    }
    
    print(f"Quarantining file: {test_file}")
    result = quarantine_manager.quarantine_file(test_file, threat_info)
    
    if result:
        print("✅ File successfully quarantined")
        
        # Show quarantine database
        print("\nQuarantine database entries:")
        for file_hash, record in quarantine_manager.quarantine_db.items():
            print(f"  Hash: {file_hash[:16]}...")
            print(f"    Original: {record['original_name']}")
            print(f"    Threat type: {record['threat_info'].get('type', 'Unknown')}")
            print(f"    Severity: {record['threat_info'].get('severity', 'Unknown')}")
    else:
        print("❌ Failed to quarantine file")
    
    # Clean up
    try:
        os.remove(test_file)
        print(f"Cleaned up test file: {test_file}")
    except:
        pass

def main():
    """Main test function"""
    print("🧪 AegisAI Automatic Quarantine Test")
    print("=" * 40)
    
    test_quarantine_functionality()
    
    print("\n📋 Test Summary:")
    print("If automatic quarantine is working correctly:")
    print("- Suspicious files should be moved to quarantine")
    print("- Quarantine database should record the threat information")
    print("- Original file path and metadata should be preserved")
    print("- Files should be encrypted/securly stored in quarantine")

if __name__ == "__main__":
    main()