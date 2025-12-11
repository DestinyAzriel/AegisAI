//
//  ThreatScanner.swift
//  AegisAI
//
//  Created by AegisAI Team on 2025.
//  Copyright © 2025 AegisAI. All rights reserved.
//

import Foundation
import CommonCrypto

struct ThreatScanResult {
    let isThreat: Bool
    let threatType: String?
    let confidence: Double
    let message: String
}

class ThreatScanner {
    private let apiEndpoint = "https://api.aegisai.com/scan"
    private let threatIntelEndpoint = "https://api.aegisai.com/threat-intel"
    
    func performScan(completion: @escaping (ThreatScanResult) -> Void) {
        // Perform a full system scan
        let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        
        scanDirectory(at: documentsURL) { result in
            DispatchQueue.main.async {
                completion(result)
            }
        }
    }
    
    func performBackgroundScan(completion: @escaping (Bool) -> Void) {
        // Perform a lightweight background scan
        performScan { result in
            completion(true)
        }
    }
    
    func scanFile(at path: String, completion: @escaping (ThreatScanResult) -> Void) {
        let fileURL = URL(fileURLWithPath: path)
        
        // Calculate file hash
        calculateFileHash(for: fileURL) { hash in
            // Check local cache first
            if let cachedResult = self.getCachedResult(for: hash) {
                completion(cachedResult)
                return
            }
            
            // Send to cloud for analysis
            self.sendToCloud(for: fileURL, with: hash) { result in
                // Cache the result
                self.cacheResult(result, for: hash)
                completion(result)
            }
        }
    }
    
    private func scanDirectory(at url: URL, completion: @escaping (ThreatScanResult) -> Void) {
        let fileManager = FileManager.default
        
        guard let enumerator = fileManager.enumerator(at: url, includingPropertiesForKeys: nil) else {
            completion(ThreatScanResult(isThreat: false, threatType: nil, confidence: 0.0, message: "Failed to enumerate directory"))
            return
        }
        
        var threatCount = 0
        var scannedCount = 0
        
        for case let fileURL as URL in enumerator {
            scannedCount += 1
            
            scanFile(at: fileURL.path) { result in
                if result.isThreat {
                    threatCount += 1
                }
                
                // Check if we've scanned all files
                if scannedCount == enumerator.allObjects.count {
                    let message = "Scan complete. Found \(threatCount) threats."
                    completion(ThreatScanResult(isThreat: threatCount > 0, threatType: nil, confidence: 1.0, message: message))
                }
            }
        }
    }
    
    private func calculateFileHash(for url: URL, completion: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .background).async {
            do {
                let data = try Data(contentsOf: url)
                var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                data.withUnsafeBytes {
                    _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
                }
                
                let hashString = hash.map { String(format: "%02x", $0) }.joined()
                DispatchQueue.main.async {
                    completion(hashString)
                }
            } catch {
                DispatchQueue.main.async {
                    completion("")
                }
            }
        }
    }
    
    private func sendToCloud(for fileURL: URL, with fileHash: String, completion: @escaping (ThreatScanResult) -> Void) {
        // Prepare request
        var request = URLRequest(url: URL(string: apiEndpoint)!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(getAuthToken())", forHTTPHeaderField: "Authorization")
        
        // Prepare payload
        let payload: [String: Any] = [
            "file_hash": fileHash,
            "file_name": fileURL.lastPathComponent,
            "file_size": fileURL.fileSize(),
            "device_id": getDeviceId()
        ]
        
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        
        // Send request
        URLSession.shared.dataTask(with: request) { data, response, error in
            guard let data = data, error == nil else {
                completion(ThreatScanResult(isThreat: false, threatType: nil, confidence: 0.0, message: "Network error: \(error?.localizedDescription ?? "Unknown")"))
                return
            }
            
            do {
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    let isThreat = json["is_threat"] as? Bool ?? false
                    let threatType = json["threat_type"] as? String
                    let confidence = json["confidence"] as? Double ?? 0.0
                    let message = json["message"] as? String ?? ""
                    
                    completion(ThreatScanResult(isThreat: isThreat, threatType: threatType, confidence: confidence, message: message))
                }
            } catch {
                completion(ThreatScanResult(isThreat: false, threatType: nil, confidence: 0.0, message: "Parse error: \(error.localizedDescription)"))
            }
        }.resume()
    }
    
    private func getCachedResult(for fileHash: String) -> ThreatScanResult? {
        // In a real implementation, this would check a local cache
        return nil
    }
    
    private func cacheResult(_ result: ThreatScanResult, for fileHash: String) {
        // In a real implementation, this would cache the result
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

extension URL {
    func fileSize() -> Int64 {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            return attributes[.size] as? Int64 ?? 0
        } catch {
            return 0
        }
    }
}