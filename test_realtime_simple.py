#!/usr/bin/env python3
"""
Simple test for real-time behavioral monitoring
"""

import os
import sys
import time

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from core.realtime import RealTimeBehavioralMonitor

def behavioral_callback(data):
    """Handle suspicious behavioral data"""
    if data.get('suspicious', False):
        print(f"🚨 SUSPICIOUS BEHAVIOR DETECTED: {data.get('description', 'Unknown activity')}")
        print(f"   Activity Type: {data.get('activity_type', 'Unknown')}")
        print(f"   Timestamp: {data.get('timestamp', 'Unknown')}")

def main():
    """Test real-time behavioral monitoring"""
    print("=" * 60)
    print("           AEGISAI REAL-TIME BEHAVIORAL MONITORING TEST")
    print("=" * 60)
    
    # Initialize monitor
    monitor = RealTimeBehavioralMonitor()
    monitor.add_callback(behavioral_callback)
    
    # Start monitoring
    print("Starting real-time behavioral monitoring...")
    success = monitor.start_monitoring([os.path.abspath(".")])  # Monitor current directory
    
    if success:
        print("✅ Real-time behavioral monitoring started")
        print("Monitoring for 60 seconds...")
        print("Try creating/deleting files in this directory to see monitoring in action")
        
        # Monitor for 60 seconds
        for i in range(60):
            if i % 10 == 0:  # Every 10 seconds
                stats = monitor.get_statistics()
                print(f"📊 Status: {stats['statistics']['file_operations']} file operations, {stats['statistics']['process_creations']} process creations")
            time.sleep(1)
        
        # Stop monitoring
        monitor.stop_monitoring()
        print("\n⏹️  Real-time behavioral monitoring stopped")
    else:
        print("❌ Failed to start real-time behavioral monitoring")

if __name__ == "__main__":
    main()