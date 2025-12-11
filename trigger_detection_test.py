#!/usr/bin/env python3
"""
Test script to trigger AegisAI detections
==============================

This script creates files that will trigger AegisAI detections
to demonstrate the real-time protection system.
"""

import os
import time
import random

def create_suspicious_file(filename):
    """Create a file that looks suspicious to trigger detection"""
    suspicious_content = f"""@echo off
REM This is a suspicious batch file
echo "Suspicious Activity"
REM CreateProcess
REM WriteFile
REM RegSetValue
REM Network connection simulation
ping -n 1 127.0.0.1 > nul
echo Malicious activity detected >> log.txt
"""
    
    with open(filename, 'w') as f:
        f.write(suspicious_content)
    
    print(f"Created suspicious file: {filename}")

def create_clean_file(filename):
    """Create a clean file that should not trigger detection"""
    clean_content = f"""# This is a clean Python file
# It contains no malicious code
def hello_world():
    print("Hello, World!")
    return True

if __name__ == "__main__":
    hello_world()
"""
    
    with open(filename, 'w') as f:
        f.write(clean_content)
    
    print(f"Created clean file: {filename}")

def create_test_files():
    """Create a series of test files to trigger detections"""
    print("Creating test files to trigger AegisAI detections...")
    
    # Create suspicious files
    for i in range(3):
        filename = f"suspicious_test_{i+1}.bat"
        create_suspicious_file(filename)
        time.sleep(1)  # Wait a second between files
    
    # Create clean files
    for i in range(2):
        filename = f"clean_test_{i+1}.py"
        create_clean_file(filename)
        time.sleep(1)
    
    # Create another suspicious file
    create_suspicious_file("malicious_activity.bat")
    
    print("Test files created successfully!")

def cleanup_test_files():
    """Clean up test files"""
    test_files = [
        "suspicious_test_1.bat",
        "suspicious_test_2.bat", 
        "suspicious_test_3.bat",
        "clean_test_1.py",
        "clean_test_2.py",
        "malicious_activity.bat"
    ]
    
    for filename in test_files:
        if os.path.exists(filename):
            try:
                os.remove(filename)
                print(f"Removed: {filename}")
            except Exception as e:
                print(f"Failed to remove {filename}: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        cleanup_test_files()
    else:
        create_test_files()
        print("\nNow run 'python realtime_aegisai.py' in another terminal to see real-time detection!")
        print("Press Enter when you're done testing to clean up files...")
        input()
        cleanup_test_files()