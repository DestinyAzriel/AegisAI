//
//  AppDelegate.swift
//  AegisAI
//
//  Created by AegisAI Team on 2025.
//  Copyright © 2025 AegisAI. All rights reserved.
//

import UIKit
import BackgroundTasks

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // Override point for customization after application launch.
        
        // Register background tasks
        BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.aegisai.background-scan", using: nil) { task in
            self.handleBackgroundScan(task: task as! BGProcessingTask)
        }
        
        return true
    }
    
    // MARK: UISceneSession Lifecycle
    
    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        // Called when a new scene session is being created.
        // Use this method to select a configuration to create the new scene with.
        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }
    
    func application(_ application: UIApplication, didDiscardSceneSessions sceneSessions: Set<UISceneSession>) {
        // Called when the user discards a scene session.
        // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
        // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
    }
    
    // MARK: Background Tasks
    
    func scheduleBackgroundScan() {
        let request = BGProcessingTaskRequest(identifier: "com.aegisai.background-scan")
        request.earliestBeginDate = Date(timeIntervalSinceNow: 30 * 60) // 30 minutes
        request.requiresNetworkConnectivity = true
        request.requiresExternalPower = false
        
        try? BGTaskScheduler.shared.submit(request)
    }
    
    func handleBackgroundScan(task: BGProcessingTask) {
        // Schedule the next background scan
        scheduleBackgroundScan()
        
        // Perform the background scan
        let scanner = ThreatScanner()
        scanner.performBackgroundScan { success in
            task.setTaskCompleted(success: success)
        }
        
        // Handle expiration
        task.expirationHandler = {
            // Clean up any resources
            task.setTaskCompleted(success: false)
        }
    }
}