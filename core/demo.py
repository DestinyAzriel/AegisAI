"""
Demo script for AegisAI Core Engine
"""

import os
import tempfile
import time
import sys

# Add the current directory to the path to allow imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import AegisAICoreAgent

def main():
    print("AegisAI Core Engine Demo")
    print("========================")
    
    # Create a temporary directory for our demo
    demo_dir = tempfile.mkdtemp()
    print(f"Demo directory: {demo_dir}")
    
    # Create some test files
    clean_file = os.path.join(demo_dir, "clean_document.txt")
    with open(clean_file, "w") as f:
        f.write("This is a clean document file.")
    
    executable_file = os.path.join(demo_dir, "suspicious.exe")
    with open(executable_file, "wb") as f:
        f.write(b"MZ")  # Windows executable signature
        f.write(b"This is a suspicious executable file.")
    
    large_file = os.path.join(demo_dir, "large_file.dat")
    with open(large_file, "wb") as f:
        f.write(b"0" * (50 * 1024 * 1024))  # 50MB file
    
    print(f"Created test files:")
    print(f"  - Clean file: {clean_file}")
    print(f"  - Executable file: {executable_file}")
    print(f"  - Large file: {large_file}")
    
    # Create agent instance
    agent = AegisAICoreAgent()
    
    print("\nScanning individual files:")
    
    # Scan clean file
    print("\n1. Scanning clean file...")
    result = agent.scan_file(clean_file)
    print(f"   Result: {result['status']}")
    
    # Scan executable file (should be flagged as suspicious)
    print("\n2. Scanning executable file...")
    result = agent.scan_file(executable_file)
    print(f"   Result: {result['status']}")
    if result['status'] == 'suspicious':
        analysis = result.get('analysis', {})
        print(f"   Threat: {analysis.get('name', 'Unknown')}")
        print(f"   Severity: {analysis.get('severity', 'Unknown')}")
    
    # Scan large file (should be flagged as suspicious)
    print("\n3. Scanning large file...")
    result = agent.scan_file(large_file)
    print(f"   Result: {result['status']}")
    if result['status'] == 'suspicious':
        analysis = result.get('analysis', {})
        print(f"   Threat: {analysis.get('name', 'Unknown')}")
        print(f"   Severity: {analysis.get('severity', 'Unknown')}")
    
    # Show agent status
    print("\nAgent Status:")
    status = agent.get_agent_status()
    agent_stats = status.get('agent_stats', {})
    scanner_stats = status.get('scanner_stats', {})
    
    print(f"  Scans performed: {agent_stats.get('scans_performed', 0)}")
    print(f"  Threats detected: {agent_stats.get('threats_detected', 0)}")
    print(f"  Files quarantined: {agent_stats.get('files_quarantined', 0)}")
    print(f"  Files scanned: {scanner_stats.get('files_scanned', 0)}")
    print(f"  Clean files: {scanner_stats.get('clean_files', 0)}")
    print(f"  Suspicious files: {scanner_stats.get('suspicious_files', 0)}")
    print(f"  Threats detected: {scanner_stats.get('threats_detected', 0)}")
    
    # Clean up
    import shutil
    shutil.rmtree(demo_dir, ignore_errors=True)
    
    print("\nDemo completed successfully!")

if __name__ == "__main__":
    main()