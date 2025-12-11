// AegisAI Kernel-Level File System Monitor
// =======================================

#include <windows.h>
#include <winnt.h>
#include <fltUser.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <fstream>
#include <sstream>
#include <ctime>

#pragma comment(lib, "fltLib.lib")
#pragma comment(lib, "psapi.lib")

// Define NTSTATUS if not already defined
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// Forward declarations
class KernelFileMonitor;

// Global variables
static KernelFileMonitor* g_kernelMonitor = nullptr;
static bool g_monitoring = false;

// File operation types
enum class FileOperation {
    CREATE,
    WRITE,
    DELETE_FILE,
    RENAME,
    SET_INFORMATION
};

// File event structure
struct FileEvent {
    FileOperation operation;
    std::wstring filePath;
    std::wstring processName;
    DWORD processId;
    LARGE_INTEGER timestamp;
    DWORD fileSize;
    bool isSuspicious;
};

// Kernel-level file system monitor using minifilter driver
class KernelFileMonitor {
public:
    KernelFileMonitor();
    ~KernelFileMonitor();
    
    bool Initialize();
    bool StartMonitoring();
    void StopMonitoring();
    void ProcessEvents();
    
    // Event callback
    static NTSTATUS MessageCallback(
        _In_         HANDLE ClientPort,
        _In_opt_     PVOID ServerPortCookie,
        _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
        _In_         ULONG SizeOfContext,
        _Inout_opt_  PVOID ConnectionPortCookie
    );
    
    // Get statistics
    size_t GetEventCount() const { return m_processedEvents; }
    size_t GetSuspiciousEventCount() const { return m_suspiciousEvents; }
    
private:
    HANDLE m_filterHandle;
    HANDLE m_clientPort;
    std::thread m_workerThread;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;
    std::queue<FileEvent> m_eventQueue;
    bool m_running;
    size_t m_processedEvents;
    size_t m_suspiciousEvents;
    std::wstring m_logFilePath;
    
    void WorkerThread();
    void HandleFileEvent(const FileEvent& event);
    void LogEvent(const FileEvent& event);
    bool IsSuspiciousFile(const std::wstring& filePath, FileOperation operation);
    std::wstring GetProcessName(DWORD processId);
};

// Constructor
KernelFileMonitor::KernelFileMonitor() 
    : m_filterHandle(INVALID_HANDLE_VALUE), 
      m_clientPort(INVALID_HANDLE_VALUE),
      m_running(false),
      m_processedEvents(0),
      m_suspiciousEvents(0) {
    // Set log file path
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    m_logFilePath = std::wstring(tempPath) + L"AegisAI_KernelMonitor.log";
}

// Destructor
KernelFileMonitor::~KernelFileMonitor() {
    StopMonitoring();
}

// Initialize the kernel monitor
bool KernelFileMonitor::Initialize() {
    HRESULT hr;
    
    // Connect to the minifilter driver
    hr = FilterConnectCommunicationPort(
        L"\\AegisAIFilterPort",
        0,
        NULL,
        0,
        NULL,
        &m_clientPort
    );
    
    if (FAILED(hr)) {
        std::wcerr << L"Failed to connect to minifilter driver. Error: 0x" << std::hex << hr << std::endl;
        return false;
    }
    
    std::wcout << L"Connected to minifilter driver successfully" << std::endl;
    return true;
}

// Start monitoring file system events
bool KernelFileMonitor::StartMonitoring() {
    if (m_running) {
        return true;
    }
    
    // Start worker thread to process events
    m_running = true;
    m_workerThread = std::thread(&KernelFileMonitor::WorkerThread, this);
    
    std::wcout << L"Kernel-level file monitoring started" << std::endl;
    return true;
}

// Stop monitoring
void KernelFileMonitor::StopMonitoring() {
    if (m_running) {
        m_running = false;
        m_queueCondition.notify_all();
        
        if (m_workerThread.joinable()) {
            m_workerThread.join();
        }
    }
    
    if (m_clientPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_clientPort);
        m_clientPort = INVALID_HANDLE_VALUE;
    }
    
    std::wcout << L"Kernel-level file monitoring stopped" << std::endl;
}

// Worker thread to process file events
void KernelFileMonitor::WorkerThread() {
    while (m_running) {
        // Wait for events
        std::unique_lock<std::mutex> lock(m_queueMutex);
        m_queueCondition.wait(lock, [this] { return !m_eventQueue.empty() || !m_running; });
        
        // Process all queued events
        while (!m_eventQueue.empty() && m_running) {
            FileEvent event = m_eventQueue.front();
            m_eventQueue.pop();
            lock.unlock();
            
            HandleFileEvent(event);
            m_processedEvents++;
            
            lock.lock();
        }
    }
}

// Handle file system events
void KernelFileMonitor::HandleFileEvent(const FileEvent& event) {
    // Convert wide string to narrow string for logging
    std::string filePath(event.filePath.begin(), event.filePath.end());
    std::string processName(event.processName.begin(), event.processName.end());
    
    // Log the event
    std::cout << "File Event - Operation: ";
    switch (event.operation) {
        case FileOperation::CREATE:
            std::cout << "CREATE";
            break;
        case FileOperation::WRITE:
            std::cout << "WRITE";
            break;
        case FileOperation::DELETE_FILE:
            std::cout << "DELETE";
            break;
        case FileOperation::RENAME:
            std::cout << "RENAME";
            break;
        case FileOperation::SET_INFORMATION:
            std::cout << "SET_INFORMATION";
            break;
        default:
            std::cout << "UNKNOWN";
            break;
    }
    std::cout << ", File: " << filePath 
              << ", Process: " << processName 
              << ", PID: " << event.processId 
              << ", Size: " << event.fileSize << std::endl;
    
    // Log to file
    LogEvent(event);
    
    // Check if file is suspicious
    if (event.isSuspicious) {
        m_suspiciousEvents++;
        std::cout << "SUSPICIOUS FILE DETECTED: " << filePath << std::endl;
        
        // In a real implementation, this would:
        // 1. Send alert to user-mode service
        // 2. Quarantine the file
        // 3. Log security event
        // 4. Notify cloud service
    }
}

// Log event to file
void KernelFileMonitor::LogEvent(const FileEvent& event) {
    try {
        std::wofstream logFile(m_logFilePath, std::ios::app);
        if (logFile.is_open()) {
            // Get current time
            time_t now = time(0);
            wchar_t timeStr[100];
            wcsftime(timeStr, sizeof(timeStr), L"%Y-%m-%d %H:%M:%S", localtime(&now));
            
            // Convert operation to string
            std::wstring operationStr;
            switch (event.operation) {
                case FileOperation::CREATE:
                    operationStr = L"CREATE";
                    break;
                case FileOperation::WRITE:
                    operationStr = L"WRITE";
                    break;
                case FileOperation::DELETE_FILE:
                    operationStr = L"DELETE";
                    break;
                case FileOperation::RENAME:
                    operationStr = L"RENAME";
                    break;
                case FileOperation::SET_INFORMATION:
                    operationStr = L"SET_INFORMATION";
                    break;
                default:
                    operationStr = L"UNKNOWN";
                    break;
            }
            
            // Write to log
            logFile << timeStr << L" | " << operationStr << L" | " 
                    << event.filePath << L" | " << event.processName 
                    << L" | PID:" << event.processId << L" | Size:" << event.fileSize;
            
            if (event.isSuspicious) {
                logFile << L" | SUSPICIOUS";
            }
            logFile << std::endl;
            logFile.close();
        }
    } catch (...) {
        // Ignore logging errors
    }
}

// Check if file is suspicious
bool KernelFileMonitor::IsSuspiciousFile(const std::wstring& filePath, FileOperation operation) {
    // Check file extension
    std::wstring extension;
    size_t dotPos = filePath.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        extension = filePath.substr(dotPos);
    }
    
    // Suspicious extensions
    static const std::vector<std::wstring> suspiciousExtensions = {
        L".exe", L".dll", L".sys", L".bat", L".cmd", L".com", L".scr", L".pif", L".vbs",
        L".js", L".jse", L".wsf", L".wsh", L".msc", L".msi", L".msp", L".mst"
    };
    
    // Check if extension is suspicious
    for (const auto& ext : suspiciousExtensions) {
        if (_wcsicmp(extension.c_str(), ext.c_str()) == 0) {
            return true;
        }
    }
    
    // Suspicious operations
    if (operation == FileOperation::SET_INFORMATION) {
        return true;
    }
    
    return false;
}

// Get process name from PID
std::wstring KernelFileMonitor::GetProcessName(DWORD processId) {
    std::wstring processName = L"Unknown";
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess != NULL) {
        wchar_t buffer[MAX_PATH];
        DWORD length = GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH);
        if (length > 0) {
            // Extract just the filename
            std::wstring fullPath(buffer, length);
            size_t slashPos = fullPath.find_last_of(L"\\");
            if (slashPos != std::wstring::npos) {
                processName = fullPath.substr(slashPos + 1);
            } else {
                processName = fullPath;
            }
        }
        CloseHandle(hProcess);
    }
    
    return processName;
}

// Message callback from minifilter driver
NTSTATUS KernelFileMonitor::MessageCallback(
    _In_         HANDLE ClientPort,
    _In_opt_     PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_         ULONG SizeOfContext,
    _Inout_opt_  PVOID ConnectionPortCookie
) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    UNREFERENCED_PARAMETER(ClientPort);
    
    // In a real implementation, this would handle messages from the minifilter driver
    // For now, we'll just acknowledge the connection
    return STATUS_SUCCESS;
}

// Enhanced real-time protection with kernel monitoring
class EnhancedRealTimeProtection {
public:
    EnhancedRealTimeProtection();
    ~EnhancedRealTimeProtection();
    
    bool StartMonitoring();
    void StopMonitoring();
    bool IsKernelMonitoringAvailable() const;
    std::pair<size_t, size_t> GetStatistics() const;
    
private:
    std::unique_ptr<KernelFileMonitor> m_kernelMonitor;
    bool m_kernelAvailable;
};

// Constructor
EnhancedRealTimeProtection::EnhancedRealTimeProtection() : m_kernelAvailable(false) {
    // Try to initialize kernel-level monitoring
    try {
        m_kernelMonitor = std::make_unique<KernelFileMonitor>();
        if (m_kernelMonitor->Initialize()) {
            m_kernelAvailable = true;
            std::cout << "Kernel-level monitoring is available" << std::endl;
        } else {
            std::cout << "Kernel-level monitoring is not available" << std::endl;
        }
    } catch (...) {
        std::cout << "Kernel-level monitoring initialization failed" << std::endl;
        m_kernelAvailable = false;
    }
}

// Destructor
EnhancedRealTimeProtection::~EnhancedRealTimeProtection() {
    StopMonitoring();
}

// Check if kernel monitoring is available
bool EnhancedRealTimeProtection::IsKernelMonitoringAvailable() const {
    return m_kernelAvailable;
}

// Get monitoring statistics
std::pair<size_t, size_t> EnhancedRealTimeProtection::GetStatistics() const {
    if (m_kernelMonitor && m_kernelAvailable) {
        return std::make_pair(
            m_kernelMonitor->GetEventCount(),
            m_kernelMonitor->GetSuspiciousEventCount()
        );
    }
    return std::make_pair(0, 0);
}

// Start enhanced monitoring
bool EnhancedRealTimeProtection::StartMonitoring() {
    if (m_kernelAvailable && m_kernelMonitor) {
        return m_kernelMonitor->StartMonitoring();
    }
    
    // Fall back to user-mode monitoring if kernel monitoring is not available
    std::cout << "Falling back to user-mode monitoring" << std::endl;
    return false;
}

// Stop enhanced monitoring
void EnhancedRealTimeProtection::StopMonitoring() {
    if (m_kernelMonitor) {
        m_kernelMonitor->StopMonitoring();
    }
}

// Example usage function
void DemonstrateKernelMonitoring() {
    std::cout << "=== AegisAI Kernel-Level Monitoring Demo ===" << std::endl;
    
    // Create enhanced real-time protection instance
    EnhancedRealTimeProtection protection;
    
    if (protection.IsKernelMonitoringAvailable()) {
        std::cout << "Starting kernel-level monitoring..." << std::endl;
        
        if (protection.StartMonitoring()) {
            std::cout << "Kernel monitoring started successfully" << std::endl;
            
            // Monitor for 30 seconds
            std::cout << "Monitoring file system events for 30 seconds..." << std::endl;
            for (int i = 0; i < 30; i++) {
                Sleep(1000);
                auto stats = protection.GetStatistics();
                std::cout << "Events processed: " << stats.first 
                          << ", Suspicious events: " << stats.second << std::endl;
            }
            
            // Stop monitoring
            protection.StopMonitoring();
            std::cout << "Monitoring stopped" << std::endl;
        } else {
            std::cout << "Failed to start kernel monitoring" << std::endl;
        }
    } else {
        std::cout << "Kernel-level monitoring is not available on this system" << std::endl;
        std::cout << "This typically requires:" << std::endl;
        std::cout << "  1. A compatible minifilter driver to be installed" << std::endl;
        std::cout << "  2. Appropriate system privileges" << std::endl;
        std::cout << "  3. Windows Vista or later" << std::endl;
    }
}

// Main function for testing
#ifdef KERNEL_MONITOR_STANDALONE
int main() {
    DemonstrateKernelMonitoring();
    return 0;
}
#endif