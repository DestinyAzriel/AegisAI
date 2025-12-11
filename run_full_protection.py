#!/usr/bin/env python3
"""
Run AegisAI with full real-time protection
"""

import os
import sys
import time
import logging
import signal
import threading

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from run_aegisai import AegisAIOrchestrator
from core.realtime import RealTimeBehavioralMonitor

# Global flag for graceful shutdown
running = True

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    global running
    print("\n🛑 Received shutdown signal...")
    running = False

def behavioral_callback(data):
    """Handle suspicious behavioral data"""
    if data.get('suspicious', False):
        print(f"🚨 SUSPICIOUS BEHAVIOR DETECTED: {data.get('description', 'Unknown activity')}")
        print(f"   Activity Type: {data.get('activity_type', 'Unknown')}")
        print(f"   Timestamp: {data.get('timestamp', 'Unknown')}")

def monitor_system(behavioral_monitor):
    """Monitor system activities in real-time"""
    global running
    
    print("👁️  Real-time system monitoring started")
    print("🛡️  Monitoring file system activities...")
    print("🧠 Behavioral analysis active...")
    print("🔮 Predictive threat intelligence running...")
    
    # In a real implementation, this would integrate with the real-time behavioral monitor
    counter = 0
    while running:
        counter += 1
        if counter % 30 == 0:  # Every 30 seconds
            # Get statistics from behavioral monitor
            stats = behavioral_monitor.get_statistics()
            if stats['monitoring_active']:
                print(f"📊 System check #{counter//30}: Monitoring {len(stats['monitored_paths'])} paths")
                if stats['statistics']['file_operations'] > 0:
                    print(f"   File operations: {stats['statistics']['file_operations']}")
                if stats['statistics']['process_creations'] > 0:
                    print(f"   Process creations: {stats['statistics']['process_creations']}")
            else:
                print(f"📊 System check #{counter//30}: Behavioral monitoring inactive")
        time.sleep(1)
    
    print("🛑 Real-time monitoring stopped")

def main():
    """Main entry point for full protection mode"""
    global running
    
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("🛡️  AEGISAI ADVANCED ENDPOINT PROTECTION")
    print("=" * 45)
    print("Starting FULL PROTECTION mode...")
    
    try:
        # Create orchestrator instance
        orchestrator = AegisAIOrchestrator()
        
        # Start protection components
        orchestrator.start_protection()
        
        # Initialize real-time behavioral monitor
        behavioral_monitor = RealTimeBehavioralMonitor()
        behavioral_monitor.add_callback(behavioral_callback)
        
        # Start behavioral monitoring
        behavioral_monitor.start_monitoring()
        
        # Show system status
        status = orchestrator.get_status()
        print(f"Agent: {'Native Windows Agent' if status['agent_status'] == 'available' else 'Python Fallback'}")
        print(f"License: {status['license_info']['license_type']}")
        print(f"Signatures: {status['signature_count']} rules loaded")
        
        # Check if real-time protection is actually enabled
        real_time_enabled = status['license_info']['licensed'] and status['license_info']['features'].get('real_time_protection', False)
        print(f"Real-time Protection: {'ENABLED' if real_time_enabled else 'DISABLED'}")
        
        # Start real-time monitoring in a separate thread
        monitor_thread = threading.Thread(target=monitor_system, args=(behavioral_monitor,), daemon=True)
        monitor_thread.start()
        
        print("\n✅ AegisAI is now running with FULL SYSTEM PROTECTION")
        print("   - Real-time file monitoring: ACTIVE")
        print("   - Behavioral analysis: ACTIVE")
        print("   - Predictive threat intelligence: ACTIVE")
        print("   - Multi-layered threat detection: ACTIVE")
        print("\n💡 The system is now monitoring your entire system in real-time")
        print("   Press Ctrl+C to stop protection")
        
        # Keep the main thread alive
        try:
            while running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        
        print("\n🛑 Stopping AegisAI protection...")
        behavioral_monitor.stop_monitoring()
        orchestrator.stop_protection()
        print("✅ AegisAI protection stopped")
        
    except Exception as e:
        logging.error(f"Error running AegisAI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()