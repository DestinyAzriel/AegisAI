#!/usr/bin/env python3
import ctypes
import platform

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        if platform.system().lower() == 'windows':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            import os
            return os.geteuid() == 0
    except:
        return False

if __name__ == "__main__":
    admin_status = is_admin()
    print(f"Running with administrator privileges: {admin_status}")
    if admin_status:
        print("✅ You are running with administrator privileges")
    else:
        print("❌ You are NOT running with administrator privileges")
        print("To run with admin privileges:")
        print("1. Close this window")
        print("2. Right-click on Command Prompt and select 'Run as administrator'")
        print("3. Navigate to D:\\AegisAI")
        print("4. Run: python realtime_aegisai.py")