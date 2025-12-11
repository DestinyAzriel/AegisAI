#!/usr/bin/env python3
"""
Build executable for AegisAI antivirus
"""

import sys
import os
import subprocess
import shutil

def install_pyinstaller():
    """Install PyInstaller if not already installed"""
    try:
        import PyInstaller
        print("✅ PyInstaller already installed")
        return True
    except ImportError:
        print("📦 Installing PyInstaller...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
            print("✅ PyInstaller installed successfully")
            return True
        except Exception as e:
            print(f"❌ Failed to install PyInstaller: {e}")
            return False

def build_executable():
    """Build executable for AegisAI"""
    print("🔨 Building AegisAI Executable")
    print("=" * 30)
    
    # Install PyInstaller if needed
    if not install_pyinstaller():
        return False
    
    # Create spec file content
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['run_aegisai.py'],
    pathex=[],
    binaries=[],
    datas=[('core/*', 'core'), ('sample_test_files/*', 'sample_test_files')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AegisAI',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''
    
    # Write spec file
    with open('AegisAI.spec', 'w') as f:
        f.write(spec_content)
    
    print("📝 Spec file created")
    
    # Build executable
    print("🚀 Building executable...")
    try:
        # Run PyInstaller
        subprocess.check_call([
            sys.executable, "-m", "PyInstaller", 
            "--onefile", 
            "--name", "AegisAI",
            "--add-data", "core;core",
            "--add-data", "sample_test_files;sample_test_files",
            "run_aegisai.py"
        ])
        
        print("✅ Executable built successfully")
        
        # Copy to root directory
        if os.path.exists('dist/AegisAI.exe'):
            shutil.copy('dist/AegisAI.exe', 'AegisAI.exe')
            print("📋 Executable copied to project root")
            
        print("\n🎉 AegisAI executable is ready!")
        print("📁 Location: AegisAI.exe")
        print("\nTo run the antivirus:")
        print("  Double-click AegisAI.exe or run from command line:")
        print("  AegisAI.exe")
        print("\nFor command line options:")
        print("  AegisAI.exe --help")
        print("  AegisAI.exe --scan-file <file>")
        print("  AegisAI.exe --status")
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to build executable: {e}")
        return False

if __name__ == "__main__":
    success = build_executable()
    sys.exit(0 if success else 1)