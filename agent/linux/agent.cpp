#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <sys/stat.h>
#include <openssl/sha.h>
#include "security.h"
#include "compliance.h"

#include <proc/readproc.h>
#include <signal.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class NetworkMonitor {
private:
    bool monitoring;
    
public:
    NetworkMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🌐 Starting network monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping network monitoring..." << std::endl;
    }
    
    void MonitorNetworkConnections() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor network connections
        std::cout << "Network monitoring in progress..." << std::endl;
        
        // For demonstration, we'll simulate network activity
        static std::vector<std::string> suspiciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : suspiciousIPs) {
            std::cout << "🔍 Checking connection to: " << ip << std::endl;
            // In a real implementation, this would check actual connections
        }
    }
    
    bool BlockIP(const std::string& ipAddress) {
        // In a real implementation, this would block malicious IPs
        std::cout << "Blocking IP address: " << ipAddress << std::endl;
        // Example: system(("iptables -A INPUT -s " + ipAddress + " -j DROP").c_str());
        return true;
    }
};

class ProcessMonitor {
private:
    bool monitoring;
    
public:
    ProcessMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🚀 Starting process monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping process monitoring..." << std::endl;
    }
    
    void MonitorProcesses() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor processes continuously
        // For now, we'll simulate monitoring
        std::cout << "sPid monitoring in progress..." << std::endl;
        
        // Get process list
        PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);
        if (!proc) {
            std::cerr << "Failed to open process table" << std::endl;
            return;
        }
        
        proc_t process;
        while (readproc(proc, &process) != NULL) {
            // Analyze each process
            AnalyzeProcess(&process);
        }
        
        closeproc(proc);
    }
    
    void AnalyzeProcess(proc_t* process) {
        // In a real implementation, this would analyze process behavior
        std::cout << "Analyzing process: " << process->cmd << " (PID: " << process->tid << ")" << std::endl;
        
        // Check for suspicious processes
        static std::vector<std::string> suspiciousNames = {
            "malware", "virus", "trojan", "rootkit"
        };
        
        for (const auto& name : suspiciousNames) {
            if (std::string(process->cmd).find(name) != std::string::npos) {
                std::cout << "⚠️  Suspicious process detected: " << process->cmd << std::endl;
                // In a real implementation, this would trigger alerts
            }
        }
        
        // Check for high CPU usage
        if (process->pcpu > 90.0) {
            std::cout << "⚠️  High CPU usage detected: " << process->cmd << " (" << process->pcpu << "%)" << std::endl;
        }
    }
    
    bool KillProcess(pid_t pid) {
        // In a real implementation, this would kill malicious processes
        std::cout << "Terminating process PID: " << pid << std::endl;
        return kill(pid, SIGTERM) == 0;
    }
};


#include <proc/readproc.h>
#include <signal.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class NetworkMonitor {
private:
    bool monitoring;
    
public:
    NetworkMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🌐 Starting network monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping network monitoring..." << std::endl;
    }
    
    void MonitorNetworkConnections() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor network connections
        std::cout << "Network monitoring in progress..." << std::endl;
        
        // For demonstration, we'll simulate network activity
        static std::vector<std::string> suspiciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : suspiciousIPs) {
            std::cout << "🔍 Checking connection to: " << ip << std::endl;
            // In a real implementation, this would check actual connections
        }
    }
    
    bool BlockIP(const std::string& ipAddress) {
        // In a real implementation, this would block malicious IPs
        std::cout << "Blocking IP address: " << ipAddress << std::endl;
        // Example: system(("iptables -A INPUT -s " + ipAddress + " -j DROP").c_str());
        return true;
    }
};


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class NetworkMonitor {
private:
    bool monitoring;
    
public:
    NetworkMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🌐 Starting network monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping network monitoring..." << std::endl;
    }
    
    void MonitorNetworkConnections() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor network connections
        std::cout << "Network monitoring in progress..." << std::endl;
        
        // For demonstration, we'll simulate network activity
        static std::vector<std::string> suspiciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : suspiciousIPs) {
            std::cout << "🔍 Checking connection to: " << ip << std::endl;
            // In a real implementation, this would check actual connections
        }
    }
    
    bool BlockIP(const std::string& ipAddress) {
        // In a real implementation, this would block malicious IPs
        std::cout << "Blocking IP address: " << ipAddress << std::endl;
        // Example: system(("iptables -A INPUT -s " + ipAddress + " -j DROP").c_str());
        return true;
    }
};

class ProcessMonitor {
private:
    bool monitoring;
    
public:
    ProcessMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🚀 Starting process monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping process monitoring..." << std::endl;
    }
    
    void MonitorProcesses() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor processes continuously
        // For now, we'll simulate monitoring
        std::cout << "sPid monitoring in progress..." << std::endl;
        
        // Get process list
        PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);
        if (!proc) {
            std::cerr << "Failed to open process table" << std::endl;
            return;
        }
        
        proc_t process;
        while (readproc(proc, &process) != NULL) {
            // Analyze each process
            AnalyzeProcess(&process);
        }
        
        closeproc(proc);
    }
    
    void AnalyzeProcess(proc_t* process) {
        // In a real implementation, this would analyze process behavior
        std::cout << "Analyzing process: " << process->cmd << " (PID: " << process->tid << ")" << std::endl;
        
        // Check for suspicious processes
        static std::vector<std::string> suspiciousNames = {
            "malware", "virus", "trojan", "rootkit"
        };
        
        for (const auto& name : suspiciousNames) {
            if (std::string(process->cmd).find(name) != std::string::npos) {
                std::cout << "⚠️  Suspicious process detected: " << process->cmd << std::endl;
                // In a real implementation, this would trigger alerts
            }
        }
        
        // Check for high CPU usage
        if (process->pcpu > 90.0) {
            std::cout << "⚠️  High CPU usage detected: " << process->cmd << " (" << process->pcpu << "%)" << std::endl;
        }
    }
    
    bool KillProcess(pid_t pid) {
        // In a real implementation, this would kill malicious processes
        std::cout << "Terminating process PID: " << pid << std::endl;
        return kill(pid, SIGTERM) == 0;
    }
};


#include <proc/readproc.h>
#include <signal.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class NetworkMonitor {
private:
    bool monitoring;
    
public:
    NetworkMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🌐 Starting network monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping network monitoring..." << std::endl;
    }
    
    void MonitorNetworkConnections() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor network connections
        std::cout << "Network monitoring in progress..." << std::endl;
        
        // For demonstration, we'll simulate network activity
        static std::vector<std::string> suspiciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : suspiciousIPs) {
            std::cout << "🔍 Checking connection to: " << ip << std::endl;
            // In a real implementation, this would check actual connections
        }
    }
    
    bool BlockIP(const std::string& ipAddress) {
        // In a real implementation, this would block malicious IPs
        std::cout << "Blocking IP address: " << ipAddress << std::endl;
        // Example: system(("iptables -A INPUT -s " + ipAddress + " -j DROP").c_str());
        return true;
    }
};


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class NetworkMonitor {
private:
    bool monitoring;
    
public:
    NetworkMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🌐 Starting network monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping network monitoring..." << std::endl;
    }
    
    void MonitorNetworkConnections() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor network connections
        std::cout << "Network monitoring in progress..." << std::endl;
        
        // For demonstration, we'll simulate network activity
        static std::vector<std::string> suspiciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : suspiciousIPs) {
            std::cout << "🔍 Checking connection to: " << ip << std::endl;
            // In a real implementation, this would check actual connections
        }
    }
    
    bool BlockIP(const std::string& ipAddress) {
        // In a real implementation, this would block malicious IPs
        std::cout << "Blocking IP address: " << ipAddress << std::endl;
        // Example: system(("iptables -A INPUT -s " + ipAddress + " -j DROP").c_str());
        return true;
    }
};


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

class NetworkMonitor {
private:
    bool monitoring;
    
public:
    NetworkMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🌐 Starting network monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping network monitoring..." << std::endl;
    }
    
    void MonitorNetworkConnections() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor network connections
        std::cout << "Network monitoring in progress..." << std::endl;
        
        // For demonstration, we'll simulate network activity
        static std::vector<std::string> suspiciousIPs = {
            "192.168.1.100", "10.0.0.1"
        };
        
        for (const auto& ip : suspiciousIPs) {
            std::cout << "🔍 Checking connection to: " << ip << std::endl;
            // In a real implementation, this would check actual connections
        }
    }
    
    bool BlockIP(const std::string& ipAddress) {
        // In a real implementation, this would block malicious IPs
        std::cout << "Blocking IP address: " << ipAddress << std::endl;
        // Example: system(("iptables -A INPUT -s " + ipAddress + " -j DROP").c_str());
        return true;
    }
};

class ProcessMonitor {
private:
    bool monitoring;
    
public:
    ProcessMonitor() : monitoring(false) {}
    
    bool StartMonitoring() {
        monitoring = true;
        std::cout << "🚀 Starting process monitoring..." << std::endl;
        return true;
    }
    
    void StopMonitoring() {
        monitoring = false;
        std::cout << "🛑 Stopping process monitoring..." << std::endl;
    }
    
    void MonitorProcesses() {
        if (!monitoring) return;
        
        // In a real implementation, this would monitor processes continuously
        // For now, we'll simulate monitoring
        std::cout << "sPid monitoring in progress..." << std::endl;
        
        // Get process list
        PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS);
        if (!proc) {
            std::cerr << "Failed to open process table" << std::endl;
            return;
        }
        
        proc_t process;
        while (readproc(proc, &process) != NULL) {
            // Analyze each process
            AnalyzeProcess(&process);
        }
        
        closeproc(proc);
    }
    
    void AnalyzeProcess(proc_t* process) {
        // In a real implementation, this would analyze process behavior
        std::cout << "Analyzing process: " << process->cmd << " (PID: " << process->tid << ")" << std::endl;
        
        // Check for suspicious processes
        static std::vector<std::string> suspiciousNames = {
            "malware", "virus", "trojan", "rootkit"
        };
        
        for (const auto& name : suspiciousNames) {
            if (std::string(process->cmd).find(name) != std::string::npos) {
                std::cout << "⚠️  Suspicious process detected: " << process->cmd << std::endl;
                // In a real implementation, this would trigger alerts
            }
        }
        
        // Check for high CPU usage
        if (process->pcpu > 90.0) {
            std::cout << "⚠️  High CPU usage detected: " << process->cmd << " (" << process->pcpu << "%)" << std::endl;
        }
    }
    
    bool KillProcess(pid_t pid) {
        // In a real implementation, this would kill malicious processes
        std::cout << "Terminating process PID: " << pid << std::endl;
        return kill(pid, SIGTERM) == 0;
    }
};


#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))

class LinuxAgent {
private:
    int inotify_fd;
    int watch_fd;
    std::string watch_path;
    SecurityManager security_manager;
    ComplianceManager compliance_manager;
    ProcessMonitor process_monitor;
    NetworkMonitor network_monitor;
    bool running;
private:
    int inotify_fd;
    int watch_fd;
    std::string watch_path;
    SecurityManager security_manager;
    ComplianceManager compliance_manager;
    ProcessMonitor process_monitor;
    NetworkMonitor network_monitor;
    NetworkMonitor network_monitor;
    bool running;
private:
    int inotify_fd;
    int watch_fd;
    std::string watch_path;
    SecurityManager security_manager;
    ComplianceManager compliance_manager;
    ProcessMonitor process_monitor;
    NetworkMonitor network_monitor;
    NetworkMonitor network_monitor;
    NetworkMonitor network_monitor;
    bool running;
private:
    int inotify_fd;
    int watch_fd;
    std::string watch_path;
    SecurityManager security_manager;
    ComplianceManager compliance_manager;
    bool running;

public:
    LinuxAgent(const std::string& path) : watch_path(path), running(false) {
        // Initialize network monitoring
        // Initialize network monitoring
        // Initialize network monitoring
        inotify_fd = inotify_init();
        if (inotify_fd < 0) {
            throw std::runtime_error("Failed to initialize inotify");
        }
        
        // Make inotify non-blocking
        int flags = fcntl(inotify_fd, F_GETFL, 0);
        fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK);
        
        watch_fd = inotify_add_watch(inotify_fd, watch_path.c_str(), 
                                    IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO);
        if (watch_fd < 0) {
            close(inotify_fd);
            throw std::runtime_error("Failed to add watch");
        }
        
        std::cout << "🛡️  AegisAI Linux Agent initialized" << std::endl;
        std::cout << "👀 Monitoring path: " << watch_path << std::endl;
    }
    
    ~LinuxAgent() {
        if (watch_fd >= 0) {
            inotify_rm_watch(inotify_fd, watch_fd);
        }
        if (inotify_fd >= 0) {
            close(inotify_fd);
        }
    }
    
    void start() {
        std::cout << "🚀 Starting AegisAI Linux Agent..." << std::endl;
        running = true;
        
        // Register with cloud backend
        std::string agent_id = "linux-agent-" + std::to_string(getpid());
        std::string token = security_manager.GenerateJWTToken(agent_id);
        
        if (!registerWithCloud(agent_id, token)) {
            std::cerr << "❌ Failed to register with cloud backend" << std::endl;
            return;
        }
        
        std::cout << "✅ Agent registered successfully: " << agent_id << std::endl;
        
        // Start monitoring thread
        std::thread monitor_thread(&LinuxAgent::monitorFileSystem, this);
        
        // Start process monitoring thread
        std::thread process_thread(&LinuxAgent::monitorProcesses, this);
        
        // Wait for threads to complete
        if (monitor_thread.joinable()) {
            monitor_thread.join();
        }
        if (process_thread.joinable()) {
            process_thread.join();
        }
    }
    
    void stop() {
        std::cout << "🛑 Stopping AegisAI Linux Agent..." << std::endl;
        running = false;
    }
    
private:
    bool registerWithCloud(const std::string& agent_id, const std::string& token) {
        // In a real implementation, this would communicate with the cloud backend
        // For now, we'll simulate a successful registration
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    }
    
    void monitorFileSystem() {
        char buffer[BUF_LEN];
        
        std::cout << "🔍 Starting file system monitoring..." << std::endl;
        
        while (running) {
            int length = read(inotify_fd, buffer, BUF_LEN);
            
            if (length < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    std::cerr << "Error reading inotify events: " << strerror(errno) << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            
            int i = 0;
            while (i < length) {
                struct inotify_event* event = (struct inotify_event*)&buffer[i];
                
                if (event->len) {
                    std::string filename(event->name);
                    std::string filepath = watch_path + "/" + filename;
                    
                    if (event->mask & IN_CREATE) {
                        std::cout << "📁 File created: " << filepath << std::endl;
                        scanFile(filepath);
                    }
                    else if (event->mask & IN_MODIFY) {
                        std::cout << "✏️  File modified: " << filepath << std::endl;
                        scanFile(filepath);
                    }
                    else if (event->mask & IN_DELETE) {
                        std::cout << "🗑️  File deleted: " << filepath << std::endl;
                    }
                }
                
                i += EVENT_SIZE + event->len;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    
    void monitorProcesses() {
        std::cout << "sPid monitoring started..." << std::endl;
        
        process_monitor.StartMonitoring();
        network_monitor.StartMonitoring();
        
        while (running) {
            // Monitor processes
            process_monitor.MonitorProcesses();
            
            // Monitor network
            network_monitor.MonitorNetworkConnections();
            
            // Sleep for a while
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        
        process_monitor.StopMonitoring();
        network_monitor.StopMonitoring();
    }
    
    void scanFile(const std::string& filepath) {
        // Check if file exists and is readable
        if (access(filepath.c_str(), R_OK) != 0) {
            return;
        }
        
        // Get file size
        struct stat st;
        if (stat(filepath.c_str(), &st) != 0) {
            return;
        }
        
        // Skip large files for now
        if (st.st_size > 100 * 1024 * 1024) { // 100MB
            std::cout << "⏭️  Skipping large file: " << filepath << std::endl;
            return;
        }
        
        // Calculate file hash
        std::string hash = calculateFileHash(filepath);
        if (!hash.empty()) {
            std::cout << "🔍 File hash: " << hash << std::endl;
        }
        
        // In a real implementation, this would send the file to the cloud backend for analysis
        // For now, we'll simulate the analysis
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // Simulate threat detection result
        bool isThreat = (filepath.find("malware") != std::string::npos || 
                        filepath.find("virus") != std::string::npos);
        
        if (isThreat) {
            std::cout << "🚨 Threat detected in file: " << filepath << std::endl;
            // In a real implementation, this would trigger remediation actions
        } else {
            std::cout << "✅ File scan completed: " << filepath << std::endl;
        }
    }
    
    std::string calculateFileHash(const std::string& filepath) {
        // Open file
        FILE* file = fopen(filepath.c_str(), "rb");
        if (!file) {
            return "";
        }
        
        // Calculate SHA256 hash
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        
        const int buffer_size = 32768;
        char buffer[buffer_size];
        
        int bytes_read;
        while ((bytes_read = fread(buffer, 1, buffer_size, file))) {
            SHA256_Update(&sha256, buffer, bytes_read);
        }
        
        SHA256_Final(hash, &sha256);
        fclose(file);
        
        // Convert hash to hex string
        char hash_string[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(&hash_string[i * 2], "%02x", hash[i]);
        }
        
        return std::string(hash_string);
    }
};

int main(int argc, char* argv[]) {
    try {
        std::string watch_path = "/tmp"; // Default watch path
        
        if (argc > 1) {
            watch_path = argv[1];
        }
        
        LinuxAgent agent(watch_path);
        agent.start();
        
        // Run for 60 seconds for demonstration
        std::this_thread::sleep_for(std::chrono::seconds(60));
        agent.stop();
        
        std::cout << "👋 AegisAI Linux Agent stopped" << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}