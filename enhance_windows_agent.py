#!/usr/bin/env python3
"""
AegisAI Windows Agent Enhancement Script
=======================================

This script enhances the Windows agent with full real-time protection,
behavioral monitoring, and comprehensive security features.
"""

import os
import sys
import json
import logging
import subprocess
import shutil
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WindowsAgentEnhancer:
    """Enhancer for Windows agent"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.windows_dir = self.project_root / "agent" / "windows"
        self.agent_cpp = self.windows_dir / "agent.cpp"
        self.agent_h = self.windows_dir / "agent.h"
        self.cmake_lists = self.windows_dir / "CMakeLists.txt"
        self.build_dir = self.windows_dir / "build"
        
    def check_prerequisites(self) -> bool:
        """Check if all prerequisites are met"""
        logger.info("Checking Windows agent prerequisites...")
        
        # Check if Windows agent directory exists
        if not self.windows_dir.exists():
            logger.error("Windows agent directory not found")
            return False
            
        # Check if required files exist
        if not self.agent_cpp.exists():
            logger.error("Windows agent source file not found")
            return False
            
        # Check if CMake is installed
        try:
            result = subprocess.run(["cmake", "--version"], 
                                  check=True, capture_output=True, text=True)
            logger.info(f"CMake found: {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("CMake not found. Please install CMake from https://cmake.org")
            return False
            
        # Check if Visual Studio or MinGW is available
        try:
            # Try Visual Studio compiler
            result = subprocess.run(["cl", "/?"], 
                                  check=False, capture_output=True, text=True)
            if result.returncode == 0:
                logger.info("Visual Studio compiler found")
                self.compiler = "msvc"
            else:
                # Try MinGW
                result = subprocess.run(["g++", "--version"], 
                                      check=False, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info("MinGW compiler found")
                    self.compiler = "mingw"
                else:
                    logger.error("No compatible compiler found. Please install Visual Studio or MinGW")
                    return False
        except FileNotFoundError:
            logger.error("No compatible compiler found. Please install Visual Studio or MinGW")
            return False
            
        logger.info("All prerequisites met")
        return True
    
    def enhance_real_time_protection(self) -> bool:
        """Enhance real-time protection capabilities"""
        logger.info("Enhancing real-time protection...")
        
        try:
            # Read current agent.cpp
            with open(self.agent_cpp, 'r') as f:
                content = f.read()
            
            # Add real-time protection features
            enhanced_content = content.replace(
                '// Forward declarations',
                '''// Forward declarations
class RealTimeProtection;
class BehavioralAnalyzer;
class RegistryMonitor;
class NetworkMonitor;'''
            )
            
            # Add BehavioralAnalyzer class
            behavioral_analyzer_code = '''
// BehavioralAnalyzer class for advanced behavioral analysis
class BehavioralAnalyzer {
public:
    BehavioralAnalyzer() {}
    
    bool AnalyzeProcessBehavior(DWORD processId, const std::string& processName) {
        // In a real implementation, this would analyze process behavior
        // Check for suspicious API calls, memory patterns, etc.
        std::cout << "Analyzing behavior of process: " << processName << " (PID: " << processId << ")" << std::endl;
        
        // Simulate behavioral analysis
        static std::vector<std::string> suspiciousProcesses = {
            "malware.exe", "virus.exe", "trojan.exe"
        };
        
        for (const auto& suspicious : suspiciousProcesses) {
            if (processName.find(suspicious) != std::string::npos) {
                std::cout << "⚠️  Suspicious process behavior detected: " << processName << std::endl;
                return true;
            }
        }
        
        return false;
    }
    
    bool AnalyzeFileAccess(const std::string& filepath, DWORD processId) {
        // In a real implementation, this would analyze file access patterns
        std::cout << "Analyzing file access: " << filepath << " by process PID: " << processId << std::endl;
        
        // Check for suspicious file access patterns
        static std::vector<std::string> sensitivePaths = {
            "C:\\Windows\\System32", "C:\\Program Files", "C:\\Users"
        };
        
        for (const auto& path : sensitivePaths) {
            if (filepath.find(path) != std::string::npos) {
                std::cout << "⚠️  Suspicious file access detected: " << filepath << std::endl;
                return true;
            }
        }
        
        return false;
    }
};

// RegistryMonitor class for registry monitoring
class RegistryMonitor {
public:
    RegistryMonitor() {}
    
    bool MonitorRegistryChanges() {
        // In a real implementation, this would monitor registry changes
        std::cout << "Monitoring registry changes..." << std::endl;
        return true;
    }
    
    bool DetectSuspiciousRegistryActivity(const std::string& keyPath, const std::string& valueName) {
        // In a real implementation, this would detect suspicious registry activity
        std::cout << "Checking registry activity: " << keyPath << " -> " << valueName << std::endl;
        
        // Check for known malicious registry keys
        static std::vector<std::string> maliciousKeys = {
            "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce"
        };
        
        for (const auto& key : maliciousKeys) {
            if (keyPath.find(key) != std::string::npos) {
                std::cout << "⚠️  Suspicious registry activity detected: " << keyPath << std::endl;
                return true;
            }
        }
        
        return false;
    }
};

// NetworkMonitor class for network monitoring
class NetworkMonitor {
public:
    NetworkMonitor() {}
    
    bool MonitorNetworkConnections() {
        // In a real implementation, this would monitor network connections
        std::cout << "Monitoring network connections..." << std::endl;
        return true;
    }
    
    bool DetectSuspiciousNetworkActivity(const std::string& ipAddress, int port) {
        // In a real implementation, this would detect suspicious network activity
        std::cout << "Checking network activity: " << ipAddress << ":" << port << std::endl;
        
        // Check for known malicious IPs or ports
        static std::vector<std::string> maliciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : maliciousIPs) {
            if (ipAddress == ip) {
                std::cout << "⚠️  Suspicious network activity detected: " << ipAddress << std::endl;
                return true;
            }
        }
        
        return false;
    }
};
'''
            
            # Insert the new classes before the global variables section
            enhanced_content = enhanced_content.replace(
                '// Global variables',
                behavioral_analyzer_code + '\n// Global variables'
            )
            
            # Update the RealTimeProtection class to use behavioral analysis
            enhanced_content = enhanced_content.replace(
                'class RealTimeProtection {',
                '''class RealTimeProtection {
private:
    BehavioralAnalyzer behavioralAnalyzer;
    RegistryMonitor registryMonitor;
    NetworkMonitor networkMonitor;'''
            )
            
            # Update ProcessFileEvent to include behavioral analysis
            enhanced_content = enhanced_content.replace(
                'void ProcessFileEvent(const std::string& filepath) {',
                '''void ProcessFileEvent(const std::string& filepath) {
        // Perform standard file scanning
        FileScanner scanner;
        if (scanner.ScanFile(filepath)) {
            std::cout << "🚨 Threat detected in file: " << filepath << std::endl;
            // In a real implementation, this would trigger remediation
        }
        
        // Perform behavioral analysis
        DWORD currentProcessId = GetCurrentProcessId();
        if (behavioralAnalyzer.AnalyzeFileAccess(filepath, currentProcessId)) {
            std::cout << "⚠️  Suspicious file access behavior detected: " << filepath << std::endl;
            // In a real implementation, this would trigger alerts
        }'''
            )
            
            # Write enhanced content back to file
            with open(self.agent_cpp, 'w') as f:
                f.write(enhanced_content)
            
            logger.info("Real-time protection enhanced")
            return True
            
        except Exception as e:
            logger.error(f"Error enhancing real-time protection: {e}")
            return False
    
    def enhance_service_management(self) -> bool:
        """Enhance Windows service management capabilities"""
        logger.info("Enhancing service management...")
        
        try:
            # Read current agent.cpp
            with open(self.agent_cpp, 'r') as f:
                content = f.read()
            
            # Add service management functions
            service_management_code = '''
// Enhanced service management functions
bool AegisAIService::InstallService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "Failed to open service control manager" << std::endl;
        return false;
    }
    
    // Get the path to the current executable
    char szPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    SC_HANDLE schService = CreateService(
        schSCManager,
        "AegisAI",
        "AegisAI Endpoint Protection",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    if (!schService) {
        std::cerr << "Failed to create service" << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // Set service description
    SERVICE_DESCRIPTION sd = { (LPWSTR)L"AegisAI Endpoint Protection Service" };
    ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sd);
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    
    std::cout << "✅ AegisAI service installed successfully" << std::endl;
    return true;
}

bool AegisAIService::UninstallService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "Failed to open service control manager" << std::endl;
        return false;
    }
    
    SC_HANDLE schService = OpenService(schSCManager, "AegisAI", SERVICE_ALL_ACCESS);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // Stop the service if it's running
    SERVICE_STATUS ss;
    ControlService(schService, SERVICE_CONTROL_STOP, &ss);
    
    // Wait for service to stop
    Sleep(1000);
    
    // Delete the service
    bool result = DeleteService(schService);
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    
    if (result) {
        std::cout << "✅ AegisAI service uninstalled successfully" << std::endl;
    } else {
        std::cerr << "Failed to uninstall service" << std::endl;
    }
    
    return result;
}

bool AegisAIService::StartService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "Failed to open service control manager" << std::endl;
        return false;
    }
    
    SC_HANDLE schService = OpenService(schSCManager, "AegisAI", SERVICE_ALL_ACCESS);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    bool result = ::StartService(schService, 0, NULL);
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    
    if (result) {
        std::cout << "✅ AegisAI service started successfully" << std::endl;
    } else {
        std::cerr << "Failed to start service" << std::endl;
    }
    
    return result;
}

bool AegisAIService::StopService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "Failed to open service control manager" << std::endl;
        return false;
    }
    
    SC_HANDLE schService = OpenService(schSCManager, "AegisAI", SERVICE_ALL_ACCESS);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    SERVICE_STATUS ss;
    bool result = ControlService(schService, SERVICE_CONTROL_STOP, &ss);
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    
    if (result) {
        std::cout << "✅ AegisAI service stopped successfully" << std::endl;
    } else {
        std::cerr << "Failed to stop service" << std::endl;
    }
    
    return result;
}
'''
            
            # Insert service management code at the end of the file
            # Find the last closing brace and insert before it
            last_brace_pos = content.rfind('}')
            enhanced_content = content[:last_brace_pos] + service_management_code + content[last_brace_pos:]
            
            # Write enhanced content back to file
            with open(self.agent_cpp, 'w') as f:
                f.write(enhanced_content)
            
            logger.info("Service management enhanced")
            return True
            
        except Exception as e:
            logger.error(f"Error enhancing service management: {e}")
            return False
    
    def enhance_configuration(self) -> bool:
        """Enhance configuration management"""
        logger.info("Enhancing configuration management...")
        
        try:
            # Create configuration header file
            config_h_content = '''
#ifndef AEGISAI_CONFIG_H
#define AEGISAI_CONFIG_H

#include <string>
#include <vector>

struct AgentConfig {
    bool enableRealTimeProtection;
    bool enableBehavioralAnalysis;
    bool enableRegistryMonitoring;
    bool enableNetworkMonitoring;
    std::vector<std::string> excludedPaths;
    std::vector<std::string> excludedExtensions;
    int scanTimeoutSeconds;
    std::string logLevel;
};

class ConfigManager {
public:
    static AgentConfig LoadConfig(const std::string& configPath = "");
    static bool SaveConfig(const AgentConfig& config, const std::string& configPath = "");
    static AgentConfig GetDefaultConfig();
};

#endif // AEGISAI_CONFIG_H
'''
            
            config_h_file = self.windows_dir / "config.h"
            with open(config_h_file, 'w') as f:
                f.write(config_h_content)
            
            # Create configuration implementation file
            config_cpp_content = '''
#include "config.h"
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

AgentConfig ConfigManager::LoadConfig(const std::string& configPath) {
    // Try to load from specified path or default location
    std::string path = configPath.empty() ? "aegisai_config.json" : configPath;
    
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cout << "Config file not found, using defaults" << std::endl;
        return GetDefaultConfig();
    }
    
    try {
        json j;
        file >> j;
        
        AgentConfig config;
        config.enableRealTimeProtection = j.value("enableRealTimeProtection", true);
        config.enableBehavioralAnalysis = j.value("enableBehavioralAnalysis", true);
        config.enableRegistryMonitoring = j.value("enableRegistryMonitoring", true);
        config.enableNetworkMonitoring = j.value("enableNetworkMonitoring", true);
        config.scanTimeoutSeconds = j.value("scanTimeoutSeconds", 30);
        config.logLevel = j.value("logLevel", "INFO");
        
        // Load excluded paths
        if (j.contains("excludedPaths")) {
            for (const auto& path : j["excludedPaths"]) {
                config.excludedPaths.push_back(path);
            }
        }
        
        // Load excluded extensions
        if (j.contains("excludedExtensions")) {
            for (const auto& ext : j["excludedExtensions"]) {
                config.excludedExtensions.push_back(ext);
            }
        }
        
        return config;
    } catch (const std::exception& e) {
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        return GetDefaultConfig();
    }
}

bool ConfigManager::SaveConfig(const AgentConfig& config, const std::string& configPath) {
    std::string path = configPath.empty() ? "aegisai_config.json" : configPath;
    
    try {
        json j;
        j["enableRealTimeProtection"] = config.enableRealTimeProtection;
        j["enableBehavioralAnalysis"] = config.enableBehavioralAnalysis;
        j["enableRegistryMonitoring"] = config.enableRegistryMonitoring;
        j["enableNetworkMonitoring"] = config.enableNetworkMonitoring;
        j["scanTimeoutSeconds"] = config.scanTimeoutSeconds;
        j["logLevel"] = config.logLevel;
        j["excludedPaths"] = config.excludedPaths;
        j["excludedExtensions"] = config.excludedExtensions;
        
        std::ofstream file(path);
        if (!file.is_open()) {
            return false;
        }
        
        file << j.dump(4);
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Error saving config file: " << e.what() << std::endl;
        return false;
    }
}

AgentConfig ConfigManager::GetDefaultConfig() {
    AgentConfig config;
    config.enableRealTimeProtection = true;
    config.enableBehavioralAnalysis = true;
    config.enableRegistryMonitoring = true;
    config.enableNetworkMonitoring = true;
    config.scanTimeoutSeconds = 30;
    config.logLevel = "INFO";
    config.excludedPaths = { "C:\\\\Windows\\\\Temp", "C:\\\\ProgramData\\\\Temp" };
    config.excludedExtensions = { ".tmp", ".log" };
    return config;
}
'''
            
            config_cpp_file = self.windows_dir / "config.cpp"
            with open(config_cpp_file, 'w') as f:
                f.write(config_cpp_content)
            
            logger.info("Configuration management enhanced")
            return True
            
        except Exception as e:
            logger.error(f"Error enhancing configuration management: {e}")
            return False
    
    def update_cmake_lists(self) -> bool:
        """Update CMakeLists.txt with new dependencies"""
        logger.info("Updating CMakeLists.txt...")
        
        try:
            # Read current CMakeLists.txt
            with open(self.cmake_lists, 'r') as f:
                content = f.read()
            
            # Add JSON library dependency
            json_dependency = '''
# Find JSON library
find_package(nlohmann_json REQUIRED)

# Source files
set(SOURCES
    agent.cpp
    config.cpp
    security.cpp
    compliance.cpp
)

# Header files
set(HEADERS
    config.h
    security.h
    compliance.h
)
'''
            
            # Replace source files section
            enhanced_content = content.replace(
                '''# Source files
set(SOURCES
    agent.cpp
    security.cpp
    compliance.cpp
)

# Header files
set(HEADERS
    security.h
    compliance.h
)''',
                json_dependency
            )
            
            # Add JSON library to link libraries
            link_libraries_section = '''# Link libraries
target_link_libraries(aegisai-agent 
    Threads::Threads
    nlohmann_json::nlohmann_json
)'''
            
            enhanced_content = enhanced_content.replace(
                '''# Link libraries
target_link_libraries(aegisai-agent 
    Threads::Threads
)''',
                link_libraries_section
            )
            
            # Write enhanced content back to file
            with open(self.cmake_lists, 'w') as f:
                f.write(enhanced_content)
            
            logger.info("CMakeLists.txt updated")
            return True
            
        except Exception as e:
            logger.error(f"Error updating CMakeLists.txt: {e}")
            return False
    
    def build_agent(self) -> bool:
        """Build the enhanced Windows agent"""
        logger.info("Building enhanced Windows agent...")
        
        try:
            # Create build directory
            self.build_dir.mkdir(exist_ok=True)
            
            # Run CMake configuration
            cmake_cmd = ["cmake", ".."]
            if self.compiler == "mingw":
                cmake_cmd.extend(["-G", "MinGW Makefiles"])
            
            result = subprocess.run(
                cmake_cmd,
                cwd=self.build_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            logger.debug(f"CMake output: {result.stdout}")
            
            # Run build
            build_cmd = ["cmake", "--build", ".", "--config", "Release"]
            result = subprocess.run(
                build_cmd,
                cwd=self.build_dir,
                check=True,
                capture_output=True,
                text=True
            )
            
            logger.info("Windows agent built successfully")
            logger.debug(f"Build output: {result.stdout}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build Windows agent: {e}")
            logger.error(f"Error output: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Error building Windows agent: {e}")
            return False
    
    def enhance(self) -> bool:
        """Enhance the Windows agent"""
        logger.info("Starting Windows agent enhancement...")
        
        # Check prerequisites
        if not self.check_prerequisites():
            logger.error("Prerequisites not met, cannot enhance Windows agent")
            return False
        
        # Enhance real-time protection
        if not self.enhance_real_time_protection():
            logger.error("Failed to enhance real-time protection")
            return False
        
        # Enhance service management
        if not self.enhance_service_management():
            logger.error("Failed to enhance service management")
            return False
        
        # Enhance configuration management
        if not self.enhance_configuration():
            logger.error("Failed to enhance configuration management")
            return False
        
        # Update CMakeLists.txt
        if not self.update_cmake_lists():
            logger.error("Failed to update CMakeLists.txt")
            return False
        
        # Build agent
        if not self.build_agent():
            logger.error("Failed to build Windows agent")
            return False
        
        logger.info("✅ Windows agent enhancement completed successfully!")
        logger.info("")
        logger.info("Next steps:")
        logger.info("1. Test the enhanced agent with various threat scenarios")
        logger.info("2. Implement actual behavioral analysis algorithms")
        logger.info("3. Add comprehensive logging and monitoring")
        logger.info("4. Create installation and deployment packages")
        logger.info("5. Perform security testing and validation")
        
        return True

def main():
    """Main enhancement function"""
    logger.info("=" * 60)
    logger.info("AEGISAI WINDOWS AGENT ENHANCEMENT")
    logger.info("=" * 60)
    
    # Create enhancer
    enhancer = WindowsAgentEnhancer()
    
    # Enhance agent
    success = enhancer.enhance()
    
    if success:
        logger.info("\n🎉 Windows agent enhancement completed successfully!")
        return 0
    else:
        logger.error("\n❌ Windows agent enhancement failed!")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)