//
//  NetworkMonitor.swift
//  AegisAI
//
//  Created by AegisAI Team on 2025.
//  Copyright © 2025 AegisAI. All rights reserved.
//

import Foundation
import Network
import SystemConfiguration

class NetworkMonitor {
    private var monitor: NWPathMonitor?
    private var blockedDomains: Set<String> = []
    private var isMonitoring = false
    private var timer: Timer?
    
    // Suspicious C2 patterns
    private let suspiciousPatterns = [
        ".*\\.(tk|ml|ga|cf)$",  // Free domains often used by malware
        ".*[0-9]{5,}.*",        // Domains with long number sequences
        ".*[a-z]{20,}.*",       // Domains with very long random strings
        ".*rapid.*",            // Domains with "rapid" (often used by malware)
        ".*free.*",             // Domains with "free" (often used by malware)
    ]
    
    // Known C2 ports
    private let c2Ports: [UInt16] = [
        4444, 5555, 8080, 10000, 1337, 31337
    ]
    
    func startMonitoring() {
        guard !isMonitoring else { return }
        
        monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "NetworkMonitor")
        monitor?.pathUpdateHandler = { path in
            self.handlePathUpdate(path)
        }
        monitor?.start(queue: queue)
        
        isMonitoring = true
        
        // Update threat intelligence
        updateThreatIntelligence()
        
        // Start periodic DNS monitoring
        startDNSMonitoring()
    }
    
    func stopMonitoring() {
        guard isMonitoring else { return }
        
        monitor?.cancel()
        monitor = nil
        isMonitoring = false
        
        // Stop DNS monitoring
        timer?.invalidate()
        timer = nil
    }
    
    private func handlePathUpdate(_ path: NWPath) {
        if path.status == .satisfied {
            print("Network connected")
            // Check for any blocked connections
            checkForBlockedConnections()
        } else {
            print("Network disconnected")
        }
    }
    
    private func checkForBlockedConnections() {
        // In a real implementation, this would monitor active connections
        // and block any that match the blocked domains list
    }
    
    private func startDNSMonitoring() {
        // Monitor DNS queries periodically
        timer = Timer.scheduledTimer(withTimeInterval: 5.0, repeats: true) { _ in
            self.monitorDNSQueries()
        }
    }
    
    private func monitorDNSQueries() {
        // Monitor DNS queries for suspicious patterns
        // This is a simplified implementation
        // In a real implementation, we would use lower-level network APIs
        
        // Check system logs for DNS queries (simplified approach)
        // This is just a placeholder for where such functionality would go
        print("Monitoring DNS queries...")
    }
    
    private func updateThreatIntelligence() {
        // Update the list of blocked domains from the cloud
        let url = URL(string: "https://api.aegisai.com/threat-intel")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(getAuthToken())", forHTTPHeaderField: "Authorization")
        
        let payload: [String: Any] = [
            "device_id": getDeviceId(),
            "last_update": getLastThreatIntelUpdate()
        ]
        
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                print("Failed to update threat intelligence: \(error?.localizedDescription ?? "Unknown error")")
                return
            }
            
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let blockedDomains = json["blocked_domains"] as? [String] {
                    self.blockedDomains = Set(blockedDomains)
                    self.setLastThreatIntelUpdate(Date().timeIntervalSince1970)
                }
            } catch {
                print("Failed to parse threat intelligence: \(error.localizedDescription)")
            }
        }.resume()
    }
    
    func isDomainBlocked(_ domain: String) -> Bool {
        // Check if domain is in blocked list
        if blockedDomains.contains(domain) {
            return true
        }
        
        // Check for suspicious patterns
        for pattern in suspiciousPatterns {
            if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
                let range = NSRange(location: 0, length: domain.count)
                if regex.firstMatch(in: domain, options: [], range: range) != nil {
                    print("Suspicious domain pattern detected: \(domain)")
                    return true
                }
            }
        }
        
        return false
    }
    
    func isPortBlocked(_ port: UInt16) -> Bool {
        // Check if port is a known C2 port
        return c2Ports.contains(port)
    }
    
    private func getLastThreatIntelUpdate() -> TimeInterval {
        // In a real implementation, this would retrieve from UserDefaults or Keychain
        return UserDefaults.standard.double(forKey: "last_threat_intel_update")
    }
    
    private func setLastThreatIntelUpdate(_ timestamp: TimeInterval) {
        // In a real implementation, this would save to UserDefaults or Keychain
        UserDefaults.standard.set(timestamp, forKey: "last_threat_intel_update")
    }
    
    private func getDeviceId() -> String {
        // In a real implementation, this would return a unique device identifier
        return "device_" + (UIDevice.current.identifierForVendor?.uuidString ?? "unknown")
    }
    
    private func getAuthToken() -> String {
        // In a real implementation, this would return a valid auth token
        return "sample_auth_token"
    }
}