/*
 * AegisAI Kernel-Level Monitor for Linux
 * Enhanced file system and process monitoring using inotify and proc filesystem
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <queue>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <signal.h>
#include <proc/readproc.h>

// File operation types
enum class FileOperation {
    CREATE,
    WRITE,
    DELETE,
    MODIFY,
    ACCESS
};

// File event structure
struct FileEvent {
    FileOperation operation;
    std::string filePath;
    std::string processName;
    pid_t processId;
    std::chrono::steady_clock::time_point timestamp;
    size_t fileSize;
    bool isSuspicious;
};

// Process event structure
struct ProcessEvent {
    pid_t pid;
    pid_t ppid;
    std::string processName;
    std::string cmdline;
    std::chrono::steady_clock::time_point timestamp;
    std::string eventType; // fork, exec, exit
};

// Kernel-level monitor class
class LinuxKernelMonitor {
public:
    LinuxKernelMonitor();
    ~LinuxKernelMonitor();
    
    bool Initialize();
    bool StartMonitoring();
    void StopMonitoring();
    
    // Statistics
    size_t GetFileEventCount() const { return m_fileEventCount; }
    size_t GetSuspiciousFileEventCount() const { return m_suspiciousFileEvents; }
    size_t GetProcessEventCount() const { return m_processEventCount; }
    
private:
    int m_inotifyFd;
    std::vector<int> m_watchDescriptors;
    std::vector<std::string> m_watchPaths;
    std::thread m_fileMonitorThread;
    std::thread m_processMonitorThread;
    std::mutex m_queueMutex;
    std::queue<FileEvent> m_fileEventQueue;
    std::queue<ProcessEvent> m_processEventQueue;
    bool m_running;
    std::string m_logFilePath;
    
    // Statistics
    size_t m_fileEventCount;
    size_t m_suspiciousFileEvents;
    size_t m_processEventCount;
    
    // Worker threads
    void FileMonitorWorker();
    void ProcessMonitorWorker();
    
    // Event handlers
    void HandleFileEvent(const FileEvent& event);
    void HandleProcessEvent(const ProcessEvent& event);
    
    // Utility functions
    void LogEvent(const std::string& message);
    bool IsSuspiciousFile(const std::string& filePath, FileOperation operation);
    std::string GetProcessName(pid_t pid);
    std::string GetProcessCmdline(pid_t pid);
    pid_t GetProcessParentPid(pid_t pid);
};

// Constructor
LinuxKernelMonitor::LinuxKernelMonitor() 
    : m_inotifyFd(-1),
      m_running(false),
      m_fileEventCount(0),
      m_suspiciousFileEvents(0),
      m_processEventCount(0) {
    // Set log file path
    m_logFilePath = "/tmp/aegisai_kernel_monitor.log";
    
    // Default watch paths
    m_watchPaths = {
        "/home",
        "/tmp",
        "/var/log",
        "/etc"
    };
}

// Destructor
LinuxKernelMonitor::~LinuxKernelMonitor() {
    StopMonitoring();
}

// Initialize the kernel monitor
bool LinuxKernelMonitor::Initialize() {
    // Create inotify instance
    m_inotifyFd = inotify_init1(IN_NONBLOCK);
    if (m_inotifyFd == -1) {
        std::cerr << "Failed to initialize inotify" << std::endl;
        return false;
    }
    
    // Add watches for directories
    for (const auto& path : m_watchPaths) {
        if (access(path.c_str(), F_OK) == 0) {
            int wd = inotify_add_watch(m_inotifyFd, path.c_str(), 
                IN_CREATE | IN_DELETE | IN_MODIFY | IN_ACCESS | IN_MOVED_FROM | IN_MOVED_TO);
            if (wd != -1) {
                m_watchDescriptors.push_back(wd);
                std::cout << "Watching directory: " << path << std::endl;
            } else {
                std::cerr << "Failed to watch directory: " << path << std::endl;
            }
        }
    }
    
    std::cout << "Linux kernel monitor initialized successfully" << std::endl;
    return true;
}

// Start monitoring
bool LinuxKernelMonitor::StartMonitoring() {
    if (m_running) {
        return true;
    }
    
    m_running = true;
    
    // Start file monitor thread
    m_fileMonitorThread = std::thread(&LinuxKernelMonitor::FileMonitorWorker, this);
    
    // Start process monitor thread
    m_processMonitorThread = std::thread(&LinuxKernelMonitor::ProcessMonitorWorker, this);
    
    std::cout << "Linux kernel monitoring started" << std::endl;
    return true;
}

// Stop monitoring
void LinuxKernelMonitor::StopMonitoring() {
    if (!m_running) {
        return;
    }
    
    m_running = false;
    
    // Remove all watches
    for (int wd : m_watchDescriptors) {
        inotify_rm_watch(m_inotifyFd, wd);
    }
    m_watchDescriptors.clear();
    
    // Close inotify
    if (m_inotifyFd != -1) {
        close(m_inotifyFd);
        m_inotifyFd = -1;
    }
    
    // Join threads
    if (m_fileMonitorThread.joinable()) {
        m_fileMonitorThread.join();
    }
    
    if (m_processMonitorThread.joinable()) {
        m_processMonitorThread.join();
    }
    
    std::cout << "Linux kernel monitoring stopped" << std::endl;
}

// File monitor worker thread
void LinuxKernelMonitor::FileMonitorWorker() {
    const size_t BUFFER_SIZE = 4096;
    char buffer[BUFFER_SIZE];
    
    while (m_running) {
        // Read events from inotify
        ssize_t length = read(m_inotifyFd, buffer, BUFFER_SIZE);
        if (length < 0) {
            if (errno != EAGAIN) {
                std::cerr << "Error reading inotify events" << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        if (length == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        
        // Process events
        for (char* ptr = buffer; ptr < buffer + length; ) {
            const struct inotify_event* event = reinterpret_cast<const struct inotify_event*>(ptr);
            
            // Create file event
            FileEvent fileEvent;
            fileEvent.timestamp = std::chrono::steady_clock::now();
            fileEvent.processId = getpid(); // In a real implementation, we'd get the actual process ID
            fileEvent.processName = GetProcessName(fileEvent.processId);
            
            // Determine operation type
            if (event->mask & IN_CREATE) {
                fileEvent.operation = FileOperation::CREATE;
            } else if (event->mask & IN_DELETE) {
                fileEvent.operation = FileOperation::DELETE;
            } else if (event->mask & IN_MODIFY) {
                fileEvent.operation = FileOperation::MODIFY;
            } else if (event->mask & IN_ACCESS) {
                fileEvent.operation = FileOperation::ACCESS;
            } else {
                fileEvent.operation = FileOperation::MODIFY;
            }
            
            // Get file path
            fileEvent.filePath = std::string(buffer + event->wd) + "/" + std::string(event->name);
            
            // Check if file is suspicious
            fileEvent.isSuspicious = IsSuspiciousFile(fileEvent.filePath, fileEvent.operation);
            
            // Get file size
            struct stat statbuf;
            if (stat(fileEvent.filePath.c_str(), &statbuf) == 0) {
                fileEvent.fileSize = statbuf.st_size;
            } else {
                fileEvent.fileSize = 0;
            }
            
            // Handle the event
            HandleFileEvent(fileEvent);
            m_fileEventCount++;
            
            if (fileEvent.isSuspicious) {
                m_suspiciousFileEvents++;
            }
            
            ptr += sizeof(struct inotify_event) + event->len;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// Process monitor worker thread
void LinuxKernelMonitor::ProcessMonitorWorker() {
    std::vector<pid_t> previousProcesses;
    
    while (m_running) {
        // Get current processes
        std::vector<pid_t> currentProcesses;
        DIR* procDir = opendir("/proc");
        if (procDir) {
            struct dirent* entry;
            while ((entry = readdir(procDir)) != nullptr) {
                if (entry->d_type == DT_DIR) {
                    pid_t pid = atoi(entry->d_name);
                    if (pid > 0) {
                        currentProcesses.push_back(pid);
                    }
                }
            }
            closedir(procDir);
        }
        
        // Check for new processes
        for (pid_t pid : currentProcesses) {
            if (std::find(previousProcesses.begin(), previousProcesses.end(), pid) == previousProcesses.end()) {
                // New process detected
                ProcessEvent event;
                event.pid = pid;
                event.ppid = GetProcessParentPid(pid);
                event.processName = GetProcessName(pid);
                event.cmdline = GetProcessCmdline(pid);
                event.timestamp = std::chrono::steady_clock::now();
                event.eventType = "fork";
                
                HandleProcessEvent(event);
                m_processEventCount++;
            }
        }
        
        previousProcesses = currentProcesses;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

// Handle file event
void LinuxKernelMonitor::HandleFileEvent(const FileEvent& event) {
    // Log the event
    std::ostringstream logMessage;
    logMessage << "File Event - Operation: ";
    
    switch (event.operation) {
        case FileOperation::CREATE:
            logMessage << "CREATE";
            break;
        case FileOperation::WRITE:
            logMessage << "WRITE";
            break;
        case FileOperation::DELETE:
            logMessage << "DELETE";
            break;
        case FileOperation::MODIFY:
            logMessage << "MODIFY";
            break;
        case FileOperation::ACCESS:
            logMessage << "ACCESS";
            break;
    }
    
    logMessage << ", File: " << event.filePath
               << ", Process: " << event.processName
               << ", PID: " << event.processId
               << ", Size: " << event.fileSize;
    
    if (event.isSuspicious) {
        logMessage << " [SUSPICIOUS]";
    }
    
    LogEvent(logMessage.str());
    
    // In a real implementation, this would:
    // 1. Send alert to user-mode service
    // 2. Quarantine the file if suspicious
    // 3. Log security event
    // 4. Notify cloud service
}

// Handle process event
void LinuxKernelMonitor::HandleProcessEvent(const ProcessEvent& event) {
    // Log the event
    std::ostringstream logMessage;
    logMessage << "Process Event - Type: " << event.eventType
               << ", PID: " << event.pid
               << ", PPID: " << event.ppid
               << ", Process: " << event.processName
               << ", Command: " << event.cmdline;
    
    LogEvent(logMessage.str());
    
    // Check for suspicious processes
    std::vector<std::string> suspiciousNames = {
        "malware", "virus", "trojan", "rootkit", "backdoor"
    };
    
    for (const auto& name : suspiciousNames) {
        if (event.processName.find(name) != std::string::npos ||
            event.cmdline.find(name) != std::string::npos) {
            std::ostringstream alertMessage;
            alertMessage << "SUSPICIOUS PROCESS DETECTED: " << event.processName
                         << " (PID: " << event.pid << ")";
            LogEvent(alertMessage.str());
            break;
        }
    }
}

// Log event to file
void LinuxKernelMonitor::LogEvent(const std::string& message) {
    try {
        std::ofstream logFile(m_logFilePath, std::ios::app);
        if (logFile.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            logFile << std::ctime(&time_t) << " - " << message << std::endl;
            logFile.close();
        }
    } catch (...) {
        // Ignore logging errors
    }
    
    // Also print to console
    std::cout << message << std::endl;
}

// Check if file is suspicious
bool LinuxKernelMonitor::IsSuspiciousFile(const std::string& filePath, FileOperation operation) {
    // Check file extension
    std::string extension;
    size_t dotPos = filePath.find_last_of('.');
    if (dotPos != std::string::npos) {
        extension = filePath.substr(dotPos);
    }
    
    // Suspicious extensions
    static const std::vector<std::string> suspiciousExtensions = {
        ".sh", ".bash", ".zsh", ".py", ".pl", ".rb", ".php",
        ".elf", ".so", ".ko", ".bin", ".out"
    };
    
    // Check if extension is suspicious
    for (const auto& ext : suspiciousExtensions) {
        if (extension == ext) {
            return true;
        }
    }
    
    // Suspicious operations
    if (operation == FileOperation::CREATE || operation == FileOperation::WRITE) {
        // Check if file is being written to sensitive locations
        if (filePath.find("/tmp/") != std::string::npos ||
            filePath.find("/var/tmp/") != std::string::npos) {
            // Additional checks could be added here
        }
    }
    
    return false;
}

// Get process name from PID
std::string LinuxKernelMonitor::GetProcessName(pid_t pid) {
    std::string procPath = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream commFile(procPath);
    std::string processName;
    
    if (commFile.is_open()) {
        std::getline(commFile, processName);
        commFile.close();
    }
    
    return processName.empty() ? "unknown" : processName;
}

// Get process command line from PID
std::string LinuxKernelMonitor::GetProcessCmdline(pid_t pid) {
    std::string procPath = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmdlineFile(procPath);
    std::string cmdline;
    
    if (cmdlineFile.is_open()) {
        std::getline(cmdlineFile, cmdline);
        cmdlineFile.close();
        
        // Replace null characters with spaces
        std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
    }
    
    return cmdline.empty() ? "unknown" : cmdline;
}

// Get process parent PID from PID
pid_t LinuxKernelMonitor::GetProcessParentPid(pid_t pid) {
    std::string procPath = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream statFile(procPath);
    
    if (statFile.is_open()) {
        std::string line;
        std::getline(statFile, line);
        statFile.close();
        
        // Parse the stat file to get parent PID (4th field)
        std::istringstream iss(line);
        std::string token;
        for (int i = 0; i < 4; ++i) {
            iss >> token;
        }
        
        return atoi(token.c_str());
    }
    
    return 0;
}

// Enhanced kernel monitoring class
class EnhancedLinuxKernelMonitoring {
public:
    EnhancedLinuxKernelMonitoring();
    ~EnhancedLinuxKernelMonitoring();
    
    bool StartMonitoring();
    void StopMonitoring();
    bool IsKernelMonitoringAvailable() const;
    std::tuple<size_t, size_t, size_t> GetStatistics() const;
    
private:
    std::unique_ptr<LinuxKernelMonitor> m_kernelMonitor;
    bool m_kernelAvailable;
};

// Constructor
EnhancedLinuxKernelMonitoring::EnhancedLinuxKernelMonitoring() : m_kernelAvailable(false) {
    // Try to initialize kernel-level monitoring
    try {
        m_kernelMonitor = std::make_unique<LinuxKernelMonitor>();
        if (m_kernelMonitor->Initialize()) {
            m_kernelAvailable = true;
            std::cout << "Linux kernel-level monitoring is available" << std::endl;
        } else {
            std::cout << "Linux kernel-level monitoring is not available" << std::endl;
        }
    } catch (...) {
        std::cout << "Linux kernel-level monitoring initialization failed" << std::endl;
        m_kernelAvailable = false;
    }
}

// Destructor
EnhancedLinuxKernelMonitoring::~EnhancedLinuxKernelMonitoring() {
    StopMonitoring();
}

// Check if kernel monitoring is available
bool EnhancedLinuxKernelMonitoring::IsKernelMonitoringAvailable() const {
    return m_kernelAvailable;
}

// Get monitoring statistics
std::tuple<size_t, size_t, size_t> EnhancedLinuxKernelMonitoring::GetStatistics() const {
    if (m_kernelMonitor && m_kernelAvailable) {
        return std::make_tuple(
            m_kernelMonitor->GetFileEventCount(),
            m_kernelMonitor->GetSuspiciousFileEventCount(),
            m_kernelMonitor->GetProcessEventCount()
        );
    }
    return std::make_tuple(0, 0, 0);
}

// Start enhanced monitoring
bool EnhancedLinuxKernelMonitoring::StartMonitoring() {
    if (m_kernelAvailable && m_kernelMonitor) {
        return m_kernelMonitor->StartMonitoring();
    }
    
    std::cout << "Falling back to user-mode monitoring" << std::endl;
    return false;
}

// Stop enhanced monitoring
void EnhancedLinuxKernelMonitoring::StopMonitoring() {
    if (m_kernelMonitor) {
        m_kernelMonitor->StopMonitoring();
    }
}

// Example usage function
void DemonstrateLinuxKernelMonitoring() {
    std::cout << "=== AegisAI Linux Kernel-Level Monitoring Demo ===" << std::endl;
    
    // Create enhanced kernel monitoring instance
    EnhancedLinuxKernelMonitoring monitoring;
    
    if (monitoring.IsKernelMonitoringAvailable()) {
        std::cout << "Starting Linux kernel-level monitoring..." << std::endl;
        
        if (monitoring.StartMonitoring()) {
            std::cout << "Linux kernel monitoring started successfully" << std::endl;
            
            // Monitor for 30 seconds
            std::cout << "Monitoring system events for 30 seconds..." << std::endl;
            for (int i = 0; i < 30; i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto stats = monitoring.GetStatistics();
                std::cout << "Events - Files: " << std::get<0>(stats)
                          << ", Suspicious: " << std::get<1>(stats)
                          << ", Processes: " << std::get<2>(stats) << std::endl;
            }
            
            // Stop monitoring
            monitoring.StopMonitoring();
            std::cout << "Monitoring stopped" << std::endl;
        } else {
            std::cout << "Failed to start Linux kernel monitoring" << std::endl;
        }
    } else {
        std::cout << "Linux kernel-level monitoring is not available on this system" << std::endl;
        std::cout << "This typically requires:" << std::endl;
        std::cout << "  1. Appropriate system privileges" << std::endl;
        std::cout << "  2. Access to /proc filesystem" << std::endl;
        std::cout << "  3. inotify support" << std::endl;
    }
}

// Main function for testing
#ifdef KERNEL_MONITOR_STANDALONE
int main() {
    DemonstrateLinuxKernelMonitoring();
    return 0;
}
#endif