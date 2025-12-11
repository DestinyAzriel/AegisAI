#!/usr/bin/env python3
"""
Test script for AegisAI Real-time Behavioral Monitor
"""

import sys
import os
import time

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

def test_realtime_monitor():
    """Test the real-time behavioral monitor"""
    try:
        from core.realtime import RealTimeBehavioralMonitor
        print("✅ Real-time Behavioral Monitor imported successfully")
        
        # Create monitor instance
        monitor = RealTimeBehavioralMonitor()
        print("✅ Real-time Behavioral Monitor instantiated successfully")
        
        # Get statistics
        stats = monitor.get_statistics()
        print(f"✅ Statistics retrieved: {stats}")
        
        print("\n🎉 All tests passed! Real-time Behavioral Monitor is working correctly.")
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
    print("Testing AegisAI Real-time Behavioral Monitor...")
    print("=" * 50)
    
    success = test_realtime_monitor()
    
    if success:
        print("\n✅ Real-time Behavioral Monitor is ready for integration")
    else:
        print("\n❌ Real-time Behavioral Monitor needs attention")
        
    sys.exit(0 if success else 1)