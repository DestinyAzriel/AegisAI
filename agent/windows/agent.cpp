// AegisAI Windows Agent
// =====================

// Define _WINSOCKAPI_ before including windows.h to prevent winsock.h conflicts
#define _WINSOCKAPI_
// Silence experimental filesystem deprecation warning
#define _SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
// Include winsock2.h after defining _WINSOCKAPI_
#include <winsock2.h>
#include <ws2tcpip.h>
// Removed ATL headers that require additional components
// #include <atlbase.h>
// #include <atlstr.h>
#include <wincrypt.h>

// Filesystem implementation - use experimental filesystem for compatibility
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;

// Forward declarations
class FileScanner;
class NetworkClient;
class QuarantineManager;
class RealTimeProtection;

class AegisAIService {
public:
    static bool InstallService();
    static bool UninstallService();
    static bool StartService();
    static bool StopService();
    static void RunService();
    
private:
    static SERVICE_STATUS ServiceStatus;
    static SERVICE_STATUS_HANDLE ServiceStatusHandle;
    static void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
    static void WINAPI ServiceCtrlHandler(DWORD CtrlCode);
    static bool ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
};

class RealTimeProtection {
public:
    RealTimeProtection();
    ~RealTimeProtection();
    bool StartMonitoring();
    void StopMonitoring();
    
private:
    bool monitoring;
    std::thread monitoringThread;
    static void MonitoringThread(RealTimeProtection* self);
    void ProcessFileEvent(const std::string& filepath);
};

// Enhanced real-time protection with kernel monitoring
class EnhancedRealTimeProtection {
public:
    EnhancedRealTimeProtection();
    ~EnhancedRealTimeProtection();
    bool StartMonitoring();
    void StopMonitoring();
    bool IsKernelMonitoringAvailable() const;
    
private:
    // Kernel monitoring would be implemented here
    // For this demo, we'll simulate the interface
    bool m_kernelAvailable;
    bool m_kernelMonitoring;
};

// Constructor
EnhancedRealTimeProtection::EnhancedRealTimeProtection() : m_kernelAvailable(false), m_kernelMonitoring(false) {
    // In a real implementation, this would check for kernel driver availability
    // For demo purposes, we'll simulate that it's available
    m_kernelAvailable = true;
}

// Destructor
EnhancedRealTimeProtection::~EnhancedRealTimeProtection() {
    StopMonitoring();
}

// Check if kernel monitoring is available
bool EnhancedRealTimeProtection::IsKernelMonitoringAvailable() const {
    return m_kernelAvailable;
}

// Start enhanced monitoring
bool EnhancedRealTimeProtection::StartMonitoring() {
    if (m_kernelAvailable) {
        m_kernelMonitoring = true;
        std::cout << "Kernel-level monitoring started" << std::endl;
        return true;
    }
    
    std::cout << "Kernel-level monitoring not available, using user-mode monitoring" << std::endl;
    return false;
}

// Stop enhanced monitoring
void EnhancedRealTimeProtection::StopMonitoring() {
    if (m_kernelMonitoring) {
        m_kernelMonitoring = false;
        std::cout << "Kernel-level monitoring stopped" << std::endl;
    }
}

// Global variables
static bool g_running = true;
static FileScanner* g_scanner = nullptr;
static NetworkClient* g_network = nullptr;
static QuarantineManager* g_quarantine = nullptr;
static RealTimeProtection* g_realtime = nullptr;

// Utility function to calculate SHA256 hash using Windows Crypto API
std::string CalculateSHA256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }
    
    // Read file content
    std::ostringstream ss;
    ss << file.rdbuf();
    std::string fileContent = ss.str();
    
    // Calculate SHA256 using Windows Crypto API
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    // Acquire cryptographic provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    
    // Create hash object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Hash the file content
    if (!CryptHashData(hHash, (BYTE*)fileContent.c_str(), fileContent.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Get the hash value
    BYTE hashValue[32];
    DWORD hashLen = 32;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    
    // Convert to hex string
    std::stringstream ssHash;
    for(DWORD i = 0; i < hashLen; i++) {
        ssHash << std::hex << std::setw(2) << std::setfill('0') << (int)hashValue[i];
    }
    
    // Cleanup
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return ssHash.str();
}

// QuarantineManager class for managing quarantined files
class QuarantineManager {
private:
    std::string quarantinePath;
    
public:
    QuarantineManager() : quarantinePath("C:\\ProgramData\\AegisAI\\Quarantine") {
        // Create quarantine directory if it doesn't exist
        fs::create_directories(fs::path(quarantinePath));
    }
    
    bool QuarantineFile(const std::string& filepath) {
        try {
            std::string filename = fs::path(filepath).filename().string();
            std::string quarantinedPath = quarantinePath + "\\" + filename + ".quarantined";
            
            // Move file to quarantine
            fs::rename(fs::path(filepath), fs::path(quarantinedPath));
            
            std::cout << "File quarantined: " << filepath << " -> " << quarantinedPath << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error quarantining file: " << e.what() << std::endl;
            return false;
        }
    }
};

// FileScanner class for scanning files
class FileScanner {
public:
    struct ScanResult {
        std::string filepath;
        std::string hash;
        std::string status; // "clean", "suspicious", "malware"
        std::vector<std::string> features;
    };
    
    ScanResult ScanFile(const std::string& filepath) {
        ScanResult result;
        result.filepath = filepath;
        result.hash = CalculateSHA256(filepath);
        result.status = "clean"; // Default to clean
        
        // Simple heuristic scanning
        std::ifstream file(filepath, std::ios::binary);
        if (file.is_open()) {
            // Read file content
            std::ostringstream ss;
            ss << file.rdbuf();
            std::string content = ss.str();
            
            // Check for suspicious patterns
            if (content.find("CreateFile") != std::string::npos && 
                content.find("WriteFile") != std::string::npos) {
                result.status = "suspicious";
                result.features.push_back("file_operations");
            }
            
            if (content.find("RegSetValue") != std::string::npos) {
                result.status = "suspicious";
                result.features.push_back("registry_modification");
            }
            
            // Check file extension
            std::string extension = filepath.substr(filepath.find_last_of(".") + 1);
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
            
            if (extension == "exe" || extension == "scr" || extension == "bat" || extension == "com") {
                result.features.push_back("executable");
            }
        }
        
        return result;
    }
    
    std::vector<ScanResult> ScanDirectory(const std::string& dirpath) {
        std::vector<ScanResult> results;
        
        try {
            // Iterate through directory
            for (const auto& entry : fs::recursive_directory_iterator(fs::path(dirpath))) {
                if (fs::is_regular_file(entry)) {
                    std::string filepath = entry.path().string();
                    ScanResult result = ScanFile(filepath);
                    results.push_back(result);
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error scanning directory: " << e.what() << std::endl;
        }
        
        return results;
    }
};

// NetworkClient class for cloud communication
class NetworkClient {
public:
    std::string SubmitFeatures(const std::string& fileHash, const std::string& filepath, 
                              const std::vector<std::string>& features) {
        // In a real implementation, this would communicate with the cloud backend
        // For demo purposes, we'll simulate a response
        
        // Simulate network delay
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
        // Simulate verdict based on features
        if (std::find(features.begin(), features.end(), "registry_modification") != features.end()) {
            return "malware";
        } else if (std::find(features.begin(), features.end(), "file_operations") != features.end()) {
            return "suspicious";
        }
        
        return "clean";
    }
};

// Global service status variables
SERVICE_STATUS AegisAIService::ServiceStatus = {0};
SERVICE_STATUS_HANDLE AegisAIService::ServiceStatusHandle = NULL;

// Service control handler
void WINAPI AegisAIService::ServiceCtrlHandler(DWORD CtrlCode) {
    switch(CtrlCode) {
        case SERVICE_CONTROL_STOP:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
            g_running = false;
            ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
            break;
            
        case SERVICE_CONTROL_INTERROGATE:
            break;
            
        default:
            break;
    }
}

// Report service status
bool AegisAIService::ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;
    
    // Fill in the SERVICE_STATUS structure
    ServiceStatus.dwCurrentState = dwCurrentState;
    ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    ServiceStatus.dwWaitHint = dwWaitHint;
    
    if (dwCurrentState == SERVICE_START_PENDING) {
        ServiceStatus.dwControlsAccepted = 0;
    } else {
        ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }
    
    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED)) {
        ServiceStatus.dwCheckPoint = 0;
    } else {
        ServiceStatus.dwCheckPoint = dwCheckPoint++;
    }
    
    // Report the status of the service to the SCM
    return SetServiceStatus(ServiceStatusHandle, &ServiceStatus);
}

// Service main function
void WINAPI AegisAIService::ServiceMain(DWORD argc, LPTSTR* argv) {
    // Register the handler function for the service
    ServiceStatusHandle = RegisterServiceCtrlHandler("AegisAI", ServiceCtrlHandler);
    
    if (!ServiceStatusHandle) {
        return;
    }
    
    // Initialize service status
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    
    // Report initial status to the SCM
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    
    // Create scanner, network client, and quarantine manager
    FileScanner scanner;
    NetworkClient network;
    QuarantineManager quarantine;
    
    g_scanner = &scanner;
    g_network = &network;
    g_quarantine = &quarantine;
    
    // Report running status to the SCM
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    
    // Main service loop
    while (g_running) {
        // Service work would go here
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // Cleanup
    g_scanner = nullptr;
    g_network = nullptr;
    g_quarantine = nullptr;
}

// Install service
bool AegisAIService::InstallService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    
    // Get the path to the current executable
    char szPath[MAX_PATH];
    if (!GetModuleFileName(NULL, szPath, MAX_PATH)) {
        std::cerr << "GetModuleFileName failed: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // Create the service
    SC_HANDLE schService = CreateService(
        schSCManager,              // SCM database
        "AegisAI",                 // Name of service
        "AegisAI Antivirus",       // Service name to display
        SERVICE_ALL_ACCESS,        // Desired access
        SERVICE_WIN32_OWN_PROCESS, // Service type
        SERVICE_DEMAND_START,      // Start type
        SERVICE_ERROR_NORMAL,      // Error control type
        szPath,                    // Path to service's binary
        NULL,                      // No load ordering group
        NULL,                      // No tag identifier
        NULL,                      // No dependencies
        NULL,                      // LocalSystem account
        NULL                       // No password
    );
    
    if (!schService) {
        std::cerr << "CreateService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    std::cout << "Service installed successfully" << std::endl;
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return true;
}

// Uninstall service
bool AegisAIService::UninstallService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    
    // Open the service
    SC_HANDLE schService = OpenService(schSCManager, "AegisAI", SERVICE_STOP | DELETE);
    if (!schService) {
        std::cerr << "OpenService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // Try to stop the service
    SERVICE_STATUS ss;
    if (ControlService(schService, SERVICE_CONTROL_STOP, &ss)) {
        std::cout << "Stopping service..." << std::endl;
        Sleep(1000);
        
        while (QueryServiceStatus(schService, &ss) && ss.dwCurrentState == SERVICE_STOP_PENDING) {
            Sleep(1000);
        }
        
        if (ss.dwCurrentState == SERVICE_STOPPED) {
            std::cout << "Service stopped" << std::endl;
        } else {
            std::cerr << "Service failed to stop" << std::endl;
        }
    }
    
    // Delete the service
    bool deleted = DeleteService(schService);
    if (deleted) {
        std::cout << "Service deleted successfully" << std::endl;
    } else {
        std::cerr << "DeleteService failed: " << GetLastError() << std::endl;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return deleted;
}

// Start service
bool AegisAIService::StartService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    
    // Open the service
    SC_HANDLE schService = OpenService(schSCManager, "AegisAI", SERVICE_START);
    if (!schService) {
        std::cerr << "OpenService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // Start the service
    bool started = ::StartService(schService, 0, NULL);
    if (started) {
        std::cout << "Service started successfully" << std::endl;
    } else {
        std::cerr << "StartService failed: " << GetLastError() << std::endl;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return started;
}

// Stop service
bool AegisAIService::StopService() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        std::cerr << "OpenSCManager failed: " << GetLastError() << std::endl;
        return false;
    }
    
    // Open the service
    SC_HANDLE schService = OpenService(schSCManager, "AegisAI", SERVICE_STOP);
    if (!schService) {
        std::cerr << "OpenService failed: " << GetLastError() << std::endl;
        CloseServiceHandle(schSCManager);
        return false;
    }
    
    // Stop the service
    SERVICE_STATUS ss;
    bool stopped = ControlService(schService, SERVICE_CONTROL_STOP, &ss);
    if (stopped) {
        std::cout << "Service stopped successfully" << std::endl;
    } else {
        std::cerr << "ControlService failed: " << GetLastError() << std::endl;
    }
    
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return stopped;
}

// Run service
void AegisAIService::RunService() {
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {"AegisAI", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };
    
    // Start the service control dispatcher
    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        std::cerr << "StartServiceCtrlDispatcher failed: " << GetLastError() << std::endl;
    }
}

// RealTimeProtection constructor
RealTimeProtection::RealTimeProtection() : monitoring(false) {}

// RealTimeProtection destructor
RealTimeProtection::~RealTimeProtection() {
    StopMonitoring();
}

// Start monitoring
bool RealTimeProtection::StartMonitoring() {
    if (monitoring) {
        return true;
    }
    
    monitoring = true;
    monitoringThread = std::thread(MonitoringThread, this);
    
    std::cout << "Real-time protection started" << std::endl;
    return true;
}

// Stop monitoring
void RealTimeProtection::StopMonitoring() {
    if (!monitoring) {
        return;
    }
    
    monitoring = false;
    if (monitoringThread.joinable()) {
        monitoringThread.join();
    }
    
    std::cout << "Real-time protection stopped" << std::endl;
}

// Monitoring thread function
void RealTimeProtection::MonitoringThread(RealTimeProtection* self) {
    // In a real implementation, this would monitor file system events
    // For demo purposes, we'll just simulate monitoring
    while (self->monitoring) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Process file event
void RealTimeProtection::ProcessFileEvent(const std::string& filepath) {
    if (!g_scanner) return;
    
    // Scan the file
    FileScanner::ScanResult result = g_scanner->ScanFile(filepath);
    
    std::cout << "File scanned: " << filepath << " (" << result.status << ")" << std::endl;
    
    // If threat detected, take action
    if (result.status == "malware" && g_quarantine) {
        g_quarantine->QuarantineFile(filepath);
    } else if (result.status == "suspicious" && g_network) {
        // Submit to cloud for further analysis
        std::string verdict = g_network->SubmitFeatures(result.hash, filepath, result.features);
        std::cout << "Cloud verdict for " << filepath << ": " << verdict << std::endl;
        
        if (verdict == "malware" && g_quarantine) {
            g_quarantine->QuarantineFile(filepath);
        }
    }
}

// Main function
int main(int argc, char* argv[]) {
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (result != 0) {
        std::cerr << "WSAStartup failed: " << result << std::endl;
        return 1;
    }
    
    // Check command line arguments
    if (argc > 1) {
        std::string command = argv[1];
        
        if (command == "install") {
            return AegisAIService::InstallService() ? 0 : 1;
        } else if (command == "uninstall") {
            return AegisAIService::UninstallService() ? 0 : 1;
        } else if (command == "start") {
            return AegisAIService::StartService() ? 0 : 1;
        } else if (command == "stop") {
            return AegisAIService::StopService() ? 0 : 1;
        } else if (command == "service") {
            AegisAIService::RunService();
            return 0;
        } else if (command == "scan") {
            if (argc < 3) {
                std::cerr << "Usage: " << argv[0] << " scan <file|directory>" << std::endl;
                return 1;
            }
            
            std::string target = argv[2];
            FileScanner scanner;
            
            if (fs::is_regular_file(fs::path(target))) {
                // Scan single file
                FileScanner::ScanResult result = scanner.ScanFile(target);
                std::cout << "File: " << result.filepath << std::endl;
                std::cout << "Hash: " << result.hash << std::endl;
                std::cout << "Status: " << result.status << std::endl;
            } else if (fs::is_directory(fs::path(target))) {
                // Scan directory
                std::vector<FileScanner::ScanResult> results = scanner.ScanDirectory(target);
                for (const auto& result : results) {
                    std::cout << result.filepath << " - " << result.status << std::endl;
                }
            } else {
                std::cerr << "Invalid target: " << target << std::endl;
                return 1;
            }
            
            return 0;
        } else {
            std::cerr << "Unknown command: " << command << std::endl;
            std::cerr << "Usage: " << argv[0] << " [install|uninstall|start|stop|service|scan <file|directory>]" << std::endl;
            return 1;
        }
    }
    
    // Default behavior - start real-time protection
    std::cout << "AegisAI Windows Agent" << std::endl;
    std::cout << "Starting real-time protection..." << std::endl;
    
    // Create components
    FileScanner scanner;
    NetworkClient network;
    QuarantineManager quarantine;
    RealTimeProtection realtime;
    EnhancedRealTimeProtection enhancedRealtime;
    
    // Store global pointers
    g_scanner = &scanner;
    g_network = &network;
    g_quarantine = &quarantine;
    g_realtime = &realtime;
    
    // Start enhanced real-time protection (with kernel monitoring if available)
    if (enhancedRealtime.IsKernelMonitoringAvailable()) {
        enhancedRealtime.StartMonitoring();
    } else {
        // Fallback to standard real-time protection
        realtime.StartMonitoring();
    }
    
    // Wait for user input to exit
    std::cout << "Press Enter to stop..." << std::endl;
    std::cin.get();
    
    // Stop protection
    enhancedRealtime.StopMonitoring();
    realtime.StopMonitoring();
    
    // Cleanup global pointers
    g_scanner = nullptr;
    g_network = nullptr;
    g_quarantine = nullptr;
    g_realtime = nullptr;
    
    // Cleanup Winsock
    WSACleanup();
    
    std::cout << "AegisAI agent stopped" << std::endl;
    return 0;
}

// AegisAI Windows Agent Implementation
// ====================================

#include "security.h"
#include "wfp_filter.h"
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

// Global instances
SecurityManager* g_securityManager = nullptr;
WFPNetworkFilter* g_wfpFilter = nullptr;

// Agent configuration
struct AgentConfig {
    bool enableFileMonitoring;
    bool enableNetworkFiltering;
    bool enableRealtimeProtection;
    std::string logFilePath;
};

// Function declarations
void InitializeAgent();
void CleanupAgent();
void StartRealtimeProtection();
void StopRealtimeProtection();
DWORD GetProcessIdByName(const std::string& processName);
std::string GetProcessName(DWORD processId);
void LogMessage(const std::string& message);

// Global variables
static bool g_agentRunning = false;
static std::thread g_protectionThread;
static AgentConfig g_config;

int main() {
    std::cout << "🛡️  AegisAI Windows Agent" << std::endl;
    std::cout << "========================" << std::endl;
    
    // Initialize agent
    InitializeAgent();
    
    // Start protection
    StartRealtimeProtection();
    
    // Wait for user input to stop
    std::cout << "Press Enter to stop protection..." << std::endl;
    std::cin.get();
    
    // Stop protection
    StopRealtimeProtection();
    
    // Cleanup
    CleanupAgent();
    
    std::cout << "✅ AegisAI Agent stopped" << std::endl;
    return 0;
}

void InitializeAgent() {
    // Initialize configuration
    g_config.enableFileMonitoring = true;
    g_config.enableNetworkFiltering = true;
    g_config.enableRealtimeProtection = true;
    g_config.logFilePath = "C:\\Temp\\AegisAI_Agent.log";
    
    // Initialize security manager
    g_securityManager = new SecurityManager();
    
    // Initialize WFP filter
    g_wfpFilter = new WFPNetworkFilter();
    
    LogMessage("Agent initialized");
}

void CleanupAgent() {
    if (g_securityManager) {
        delete g_securityManager;
        g_securityManager = nullptr;
    }
    
    if (g_wfpFilter) {
        delete g_wfpFilter;
        g_wfpFilter = nullptr;
    }
    
    LogMessage("Agent cleaned up");
}

void StartRealtimeProtection() {
    if (g_agentRunning) {
        return;
    }
    
    g_agentRunning = true;
    
    // Start file monitoring
    if (g_config.enableFileMonitoring) {
        std::cout << "🔍 File monitoring enabled" << std::endl;
    }
    
    // Start network filtering
    if (g_config.enableNetworkFiltering) {
        if (g_wfpFilter->Initialize() && g_wfpFilter->StartFiltering()) {
            std::cout << "🌐 Network filtering enabled" << std::endl;
        } else {
            std::cerr << "❌ Failed to start network filtering" << std::endl;
        }
    }
    
    // Start protection thread
    g_protectionThread = std::thread([]() {
        while (g_agentRunning) {
            // Perform periodic checks
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
    
    LogMessage("Real-time protection started");
}

void StopRealtimeProtection() {
    if (!g_agentRunning) {
        return;
    }
    
    g_agentRunning = false;
    
    // Stop network filtering
    if (g_wfpFilter) {
        g_wfpFilter->StopFiltering();
    }
    
    // Wait for protection thread to finish
    if (g_protectionThread.joinable()) {
        g_protectionThread.join();
    }
    
    LogMessage("Real-time protection stopped");
}

DWORD GetProcessIdByName(const std::string& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }
    
    do {
        std::string currentProcess(entry.szExeFile);
        std::transform(currentProcess.begin(), currentProcess.end(), currentProcess.begin(), ::tolower);
        std::string targetProcess = processName;
        std::transform(targetProcess.begin(), targetProcess.end(), targetProcess.begin(), ::tolower);
        
        if (currentProcess == targetProcess) {
            CloseHandle(snapshot);
            return entry.th32ProcessID;
        }
    } while (Process32Next(snapshot, &entry));
    
    CloseHandle(snapshot);
    return 0;
}

std::string GetProcessName(DWORD processId) {
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (process == nullptr) {
        return "Unknown";
    }
    
    char processName[MAX_PATH];
    DWORD size = MAX_PATH;
    
    if (QueryFullProcessImageNameA(process, 0, processName, &size)) {
        std::string fullPath(processName);
        size_t pos = fullPath.find_last_of("\\");
        if (pos != std::string::npos) {
            CloseHandle(process);
            return fullPath.substr(pos + 1);
        }
    }
    
    CloseHandle(process);
    return "Unknown";
}

void LogMessage(const std::string& message) {
    try {
        std::ofstream logFile(g_config.logFilePath, std::ios::app);
        if (logFile.is_open()) {
            // Get current time
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            
            logFile << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                   << message << std::endl;
            logFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error logging message: " << e.what() << std::endl;
    }
}
