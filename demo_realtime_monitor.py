#!/usr/bin/env python3
"""
Demo script for AegisAI Real-time Behavioral Monitor
"""

import sys
import os
import time

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

def demo_realtime_monitor():
    """Demonstrate the real-time behavioral monitor"""
    try:
        from core.realtime import RealTimeBehavioralMonitor
        print("✅ Real-time Behavioral Monitor imported successfully")
        
        # Create monitor instance
        monitor = RealTimeBehavioralMonitor()
        print("✅ Real-time Behavioral Monitor instantiated successfully")
        
        # Add callback for suspicious behavior
        def suspicious_behavior_callback(data):
            if data.get('suspicious', False):
                print(f"🚨 Suspicious behavior detected: {data.get('description', 'Unknown')}")
        
        monitor.add_callback(suspicious_behavior_callback)
        
        # Start monitoring
        print("\nStarting real-time behavioral monitoring...")
        success = monitor.start_monitoring()
        
        if success:
            print("✅ Real-time behavioral monitoring started")
            print("Monitoring for 10 seconds...")
            
            # Monitor for 10 seconds
            time.sleep(10)
            
            # Show statistics
            stats = monitor.get_statistics()
            print("\n📊 Monitoring Statistics:")
            print(f"  Monitoring active: {stats['monitoring_active']}")
            print(f"  Monitored paths: {stats['monitored_paths']}")
            print(f"  File operations: {stats['statistics']['file_operations']}")
            print(f"  Process creations: {stats['statistics']['process_creations']}")
            if stats['rates']:
                print(f"  File operations rate: {stats['rates']['file_operations_per_minute']:.2f}/min")
                print(f"  Process creation rate: {stats['rates']['process_creations_per_minute']:.2f}/min")
            
            # Stop monitoring
            monitor.stop_monitoring()
            print("\n⏹️  Real-time behavioral monitoring stopped")
        else:
            print("❌ Failed to start real-time behavioral monitoring")
            
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("❌ Real-time Behavioral Monitor not available")
        print("\nTo install required dependencies, run:")
        print("  pip install -r core/requirements_realtime.txt")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("AegisAI Real-time Behavioral Monitor Demo")
    print("=" * 50)
    
    success = demo_realtime_monitor()
    
    if success:
        print("\n✅ Real-time Behavioral Monitor demo completed successfully")
    else:
        print("\n❌ Real-time Behavioral Monitor demo encountered issues")
        
    sys.exit(0 if success else 1)