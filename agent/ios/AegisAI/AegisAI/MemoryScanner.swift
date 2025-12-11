//
//  MemoryScanner.swift
//  AegisAI
//
//  Created by AegisAI Team on 2025.
//  Copyright © 2025 AegisAI. All rights reserved.
//

import Foundation
import MachO

struct MemoryScanResult {
    let type: String
    let description: String
    let confidence: Double
    let details: String
    let timestamp: Date
    
    init(type: String, description: String, confidence: Double, details: String) {
        self.type = type
        self.description = description
        self.confidence = confidence
        self.details = details
        self.timestamp = Date()
    }
}

class MemoryScanner {
    private let suspiciousPatterns = [
        ".*exec.*sh.*",
        ".*chmod.*777.*",
        ".*wget.*http.*",
        ".*curl.*http.*",
        ".*su.*",
        ".*root.*",
        ".*hack.*",
        ".*malware.*",
        ".*payload.*",
        ".*reverse.*shell.*",
        ".*bind.*shell.*",
        ".*meterpreter.*",
        ".*empire.*",
        ".*cobalt.*strike.*"
    ]
    
    private let suspiciousProcesses = [
        "su",
        "shell",
        "hack",
        "malware",
        "payload",
        "reverse",
        "bind",
        "meterpreter",
        "empire",
        "cobalt"
    ]
    
    func scanForFilelessMalware() -> [MemoryScanResult] {
        var results: [MemoryScanResult] = []
        
        // Scan running processes
        scanProcesses(&results)
        
        // Scan system properties
        scanSystemProperties(&results)
        
        // Scan temporary directories
        scanTemporaryDirectories(&results)
        
        // Scan for suspicious network connections
        scanNetworkConnections(&results)
        
        return results
    }
    
    private func scanProcesses(_ results: inout [MemoryScanResult]) {
        // On iOS, we have limited access to process information
        // We'll use a simplified approach to check for suspicious activity
        
        // Check for jailbreak indicators
        checkJailbreakIndicators(&results)
        
        // Check for suspicious libraries
        checkLoadedLibraries(&results)
    }
    
    private func checkJailbreakIndicators(_ results: inout [MemoryScanResult]) {
        let jailbreakIndicators = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/"
        ]
        
        for indicator in jailbreakIndicators {
            if FileManager.default.fileExists(atPath: indicator) {
                results.append(MemoryScanResult(
                    type: "jailbreak_indicator",
                    description: "Jailbreak indicator found: \(indicator)",
                    confidence: 0.9,
                    details: indicator
                ))
            }
        }
        
        // Check write access to system directories
        let systemDirs = ["/private/", "/Applications/", "/System/"]
        for dir in systemDirs {
            if FileManager.default.isWritableFile(atPath: dir) {
                results.append(MemoryScanResult(
                    type: "jailbreak_indicator",
                    description: "System directory writable: \(dir)",
                    confidence: 0.8,
                    details: dir
                ))
            }
        }
    }
    
    private func checkLoadedLibraries(_ results: inout [MemoryScanResult]) {
        // Check for suspicious loaded libraries
        let imageCount = _dyld_image_count()
        
        for i in 0..<imageCount {
            if let imageName = _dyld_get_image_name(i) {
                let name = String(cString: imageName)
                
                // Check for suspicious library names
                for pattern in suspiciousProcesses {
                    if name.lowercased().contains(pattern) {
                        results.append(MemoryScanResult(
                            type: "suspicious_library",
                            description: "Suspicious library loaded: \(name)",
                            confidence: 0.8,
                            details: name
                        ))
                    }
                }
            }
        }
    }
    
    private func scanSystemProperties(_ results: inout [MemoryScanResult]) {
        // Check environment variables for suspicious values
        let suspiciousEnvVars = ["DYLD_INSERT_LIBRARIES", "MALLOC_INSERT_LIBRARIES"]
        
        for envVar in suspiciousEnvVars {
            if let value = ProcessInfo.processInfo.environment[envVar], !value.isEmpty {
                results.append(MemoryScanResult(
                    type: "suspicious_env_var",
                    description: "Suspicious environment variable: \(envVar)",
                    confidence: 0.7,
                    details: "\(envVar)=\(value)"
                ))
            }
        }
    }
    
    private func scanTemporaryDirectories(_ results: inout [MemoryScanResult]) {
        let tempDirs = [
            NSTemporaryDirectory(),
            "/tmp/",
            "/var/tmp/"
        ]
        
        for tempDir in tempDirs {
            let url = URL(fileURLWithPath: tempDir)
            scanDirectory(at: url, results: &results)
        }
    }
    
    private func scanDirectory(at url: URL, results: inout [MemoryScanResult]) {
        do {
            let contents = try FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)
            
            for fileURL in contents {
                // Check file name for suspicious patterns
                let fileName = fileURL.lastPathComponent.lowercased()
                
                for pattern in suspiciousPatterns {
                    if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
                        let range = NSRange(location: 0, length: fileName.count)
                        if regex.firstMatch(in: fileName, options: [], range: range) != nil {
                            results.append(MemoryScanResult(
                                type: "suspicious_file",
                                description: "Suspicious file found: \(fileName)",
                                confidence: 0.7,
                                details: fileURL.path
                            ))
                        }
                    }
                }
                
                // Check for suspicious file extensions
                let suspiciousExtensions = [".sh", ".pl", ".py", ".rb"]
                if let ext = fileURL.pathExtension.lowercased() as String?, suspiciousExtensions.contains(ext) {
                    results.append(MemoryScanResult(
                        type: "suspicious_script",
                        description: "Suspicious script file found: \(fileName)",
                        confidence: 0.6,
                        details: fileURL.path
                    ))
                }
            }
        } catch {
            // Directory might not exist or not be accessible
        }
    }
    
    private func scanNetworkConnections(_ results: inout [MemoryScanResult]) {
        // On iOS, network connection scanning is limited
        // We'll check for suspicious ports that might indicate C2 communication
        
        // This is a simplified check - in a real implementation, we would use
        // lower-level network APIs or system calls
        let suspiciousPorts = [8080, 10000, 4444, 5555]
        
        // We can't directly scan network connections on iOS without special entitlements
        // This is just a placeholder for where such functionality would go
        for port in suspiciousPorts {
            // In a real implementation, we would check actual connections
            // For now, we'll just add a placeholder result
            results.append(MemoryScanResult(
                type: "network_check",
                description: "Network connection scanning not available on iOS without special entitlements",
                confidence: 0.1,
                details: "Port \(port) check (placeholder)"
            ))
        }
    }
}