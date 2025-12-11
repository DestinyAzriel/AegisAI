//
//  ViewController.swift
//  AegisAI
//
//  Created by AegisAI Team on 2025.
//  Copyright © 2025 AegisAI. All rights reserved.
//

import UIKit

class ViewController: UIViewController {
    
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var startButton: UIButton!
    @IBOutlet weak var scanButton: UIButton!
    
    let fileMonitor = FileMonitor()
    let threatScanner = ThreatScanner()
    let networkMonitor = NetworkMonitor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        updateUI()
    }
    
    @IBAction func startProtectionTapped(_ sender: UIButton) {
        // Start all monitoring services
        fileMonitor.startMonitoring()
        networkMonitor.startMonitoring()
        
        updateUI()
    }
    
    @IBAction func stopProtectionTapped(_ sender: UIButton) {
        // Stop all monitoring services
        fileMonitor.stopMonitoring()
        networkMonitor.stopMonitoring()
        
        updateUI()
    }
    
    @IBAction func scanNowTapped(_ sender: UIButton) {
        // Perform immediate scan
        threatScanner.performScan { results in
            DispatchQueue.main.async {
                let alert = UIAlertController(title: "Scan Complete", message: "Scan found \(results.threatCount) threats", preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "OK", style: .default))
                self.present(alert, animated: true)
            }
        }
    }
    
    func updateUI() {
        if fileMonitor.isMonitoring {
            statusLabel.text = "Protection Active"
            startButton.setTitle("Stop Protection", for: .normal)
        } else {
            statusLabel.text = "Protection Inactive"
            startButton.setTitle("Start Protection", for: .normal)
        }
    }
}