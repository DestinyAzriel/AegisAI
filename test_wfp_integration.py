#!/usr/bin/env python3
"""
Test script for AegisAI WFP Integration
"""

import sys
import os
import subprocess
import time

def test_wfp_build():
    """Test building the WFP filter."""
    print("Testing WFP filter build...")
    
    # Navigate to the Windows agent directory
    agent_dir = os.path.join(os.path.dirname(__file__), 'agent', 'windows')
    
    # Run the build script
    try:
        result = subprocess.run(['build.bat'], cwd=agent_dir, capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            print("✅ WFP filter build successful")
            return True
        else:
            print(f"❌ WFP filter build failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ WFP filter build timed out")
        return False
    except Exception as e:
        print(f"❌ WFP filter build error: {e}")
        return False

def test_wfp_functionality():
    """Test WFP filter functionality."""
    print("\nTesting WFP filter functionality...")
    
    # Navigate to the Windows agent directory
    agent_dir = os.path.join(os.path.dirname(__file__), 'agent', 'windows')
    build_dir = os.path.join(agent_dir, 'build', 'Release')
    test_exe = os.path.join(build_dir, 'test-wfp.exe')
    
    # Check if test executable exists
    if not os.path.exists(test_exe):
        print("❌ WFP test executable not found")
        return False
    
    # Run the test
    try:
        result = subprocess.run([test_exe], cwd=build_dir, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ WFP filter functionality test passed")
            print(result.stdout)
            return True
        else:
            print(f"❌ WFP filter functionality test failed: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("❌ WFP filter functionality test timed out")
        return False
    except Exception as e:
        print(f"❌ WFP filter functionality test error: {e}")
        return False

def main():
    """Run WFP integration tests."""
    print("🛡️  AegisAI WFP Integration Test")
    print("=" * 40)
    
    # Test WFP build
    build_success = test_wfp_build()
    
    # Test WFP functionality (only if build succeeded)
    functionality_success = False
    if build_success:
        functionality_success = test_wfp_functionality()
    
    # Summary
    print("\n" + "=" * 40)
    print("WFP Integration Test Results:")
    print(f"  Build Test: {'✅ PASSED' if build_success else '❌ FAILED'}")
    print(f"  Functionality Test: {'✅ PASSED' if functionality_success else '❌ FAILED'}")
    
    if build_success and functionality_success:
        print("\n🎉 All WFP integration tests passed!")
        return 0
    else:
        print("\n💥 Some WFP integration tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())