//
//  FileMonitor.swift
//  AegisAI
//
//  Created by AegisAI Team on 2025.
//  Copyright © 2025 AegisAI. All rights reserved.
//

import Foundation
import CoreServices

class FileMonitor {
    private var stream: FSEventStream?
    private let threatScanner = ThreatScanner()
    var isMonitoring = false
    
    func startMonitoring() {
        guard !isMonitoring else { return }
        
        let pathsToWatch = [NSHomeDirectory()] as CFArray
        let latency: CFTimeInterval = 3.0
        let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagFileEvents)
        
        stream = FSEventStreamCreate(
            kCFAllocatorDefault,
            eventCallback,
            nil,
            pathsToWatch,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            latency,
            flags
        )
        
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
        FSEventStreamStart(stream!)
        
        isMonitoring = true
    }
    
    func stopMonitoring() {
        guard isMonitoring, let stream = stream else { return }
        
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        
        self.stream = nil
        isMonitoring = false
    }
    
    private let eventCallback: FSEventStreamCallback = { (stream, clientCallbackInfo, numEvents, eventPaths, eventFlags, eventIds) in
        let paths = unsafeBitCast(eventPaths, to: NSArray.self)
        
        for i in 0..<numEvents {
            let path = paths[Int(i)] as! String
            let flags = eventFlags[Int(i)]
            
            // Process only file events, not directory events
            if (flags & UInt32(kFSEventStreamEventFlagItemIsFile)) != 0 {
                // Handle file change
                let monitor = unsafeBitCast(clientCallbackInfo, to: FileMonitor.self)
                monitor.handleFileChange(at: path)
            }
        }
    }
    
    private func handleFileChange(at path: String) {
        // Check if this is a file we should scan
        if shouldScanFile(at: path) {
            threatScanner.scanFile(at: path) { result in
                if result.isThreat {
                    // Handle threat detection
                    self.handleThreatDetected(at: path, with: result)
                }
            }
        }
    }
    
    private func shouldScanFile(at path: String) -> Bool {
        // Get file extension
        let url = URL(fileURLWithPath: path)
        let extension = url.pathExtension.lowercased()
        
        // Check if it's a scannable extension
        let scannableExtensions = ["app", "ipa", "zip", "rar", "exe", "js", "sh"]
        return scannableExtensions.contains(extension)
    }
    
    private func handleThreatDetected(at path: String, with result: ThreatScanResult) {
        // Log threat detection
        print("Threat detected at: \(path)")
        
        // Send notification to user
        NotificationCenter.default.post(name: NSNotification.Name("ThreatDetected"), object: [
            "path": path,
            "result": result
        ])
    }
}