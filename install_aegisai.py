#!/usr/bin/env python3
"""
AegisAI Installation Script
==========================

This script installs all required dependencies for AegisAI and sets up the system.
"""

import os
import sys
import subprocess
import platform
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        logger.error("Python 3.7 or higher is required")
        return False
    logger.info(f"Python version {version.major}.{version.minor}.{version.micro} detected")
    return True

def install_package(package_name, version=None):
    """Install a Python package using pip"""
    package = package_name
    try:
        if version:
            package = f"{package_name}>={version}"
            
        logger.info(f"Installing {package}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        logger.info(f"Successfully installed {package}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install {package}: {e}")
        return False

def install_requirements(requirements_file):
    """Install packages from a requirements file"""
    try:
        logger.info(f"Installing packages from {requirements_file}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_file])
        logger.info(f"Successfully installed packages from {requirements_file}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install packages from {requirements_file}: {e}")
        return False

def check_and_install_dependencies():
    """Check and install all required dependencies"""
    logger.info("Checking and installing AegisAI dependencies...")
    
    # Install core requirements
    core_requirements = [
        ("watchdog", "2.1.0"),
        ("yara-python", "4.0.0"),
        ("requests", "2.25.0"),
        ("scikit-learn", "1.0.0"),
        ("numpy", "1.21.0"),
        ("cryptography", "3.4.0")
    ]
    
    # Try to install from requirements file first
    if os.path.exists("core/requirements.txt"):
        if not install_requirements("core/requirements.txt"):
            logger.warning("Failed to install from requirements.txt, trying individual packages...")
            for package, version in core_requirements:
                if not install_package(package, version):
                    logger.error(f"Critical dependency {package} failed to install")
                    return False
    
    logger.info("All dependencies installed successfully")
    return True

def verify_installation():
    """Verify that all components are properly installed"""
    logger.info("Verifying installation...")
    
    # Test imports
    required_modules = [
        "watchdog",
        "yara",
        "requests",
        "sklearn",
        "numpy",
        "cryptography"
    ]
    
    for module in required_modules:
        try:
            __import__(module)
            logger.info(f"✓ {module} imported successfully")
        except ImportError as e:
            logger.error(f"✗ Failed to import {module}: {e}")
            return False
    
    logger.info("All modules imported successfully")
    return True

def setup_native_agent():
    """Setup native agent if available"""
    logger.info("Setting up native agent...")
    
    # Check if Windows agent exists
    agent_path = os.path.join("agent", "windows", "aegisai-agent.exe")
    if os.path.exists(agent_path):
        logger.info(f"✓ Native Windows agent found at {agent_path}")
        return True
    else:
        logger.warning("Native Windows agent not found, will use Python fallback")
        return True

def create_startup_script():
    """Create a startup script for easy launching"""
    logger.info("Creating startup script...")
    
    startup_content = """@echo off
REM AegisAI Startup Script
echo 🛡️  Starting AegisAI Advanced Endpoint Protection
echo ===============================================
python run_prototype.py
pause
"""
    
    try:
        with open("start-aegisai.bat", "w") as f:
            f.write(startup_content)
        logger.info("✓ Startup script created: start-aegisai.bat")
        return True
    except Exception as e:
        logger.error(f"Failed to create startup script: {e}")
        return False

def main():
    """Main installation function"""
    print("🛡️  AEGISAI INSTALLATION")
    print("=" * 30)
    print()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Check platform
    system = platform.system()
    logger.info(f"Running on {system}")
    
    # Install dependencies
    if not check_and_install_dependencies():
        logger.error("Failed to install dependencies")
        sys.exit(1)
    
    # Verify installation
    if not verify_installation():
        logger.error("Installation verification failed")
        sys.exit(1)
    
    # Setup native agent
    if not setup_native_agent():
        logger.warning("Native agent setup failed")
    
    # Create startup script
    if not create_startup_script():
        logger.warning("Failed to create startup script")
    
    print()
    print("✅ AEGISAI INSTALLATION COMPLETE!")
    print()
    print("You can now run AegisAI using:")
    print("  python run_prototype.py")
    print()
    print("Or double-click on start-aegisai.bat")
    print()
    print("For a full demonstration of predictive intelligence:")
    print("  python demo_predictive_intelligence.py")
    print()
    print("🛡️  AegisAI - Beyond Traditional Antivirus")

if __name__ == "__main__":
    main()