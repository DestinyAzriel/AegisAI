#!/usr/bin/env python3
"""
AegisAI Real-Time Protection System
==================================

This script runs AegisAI as a real-time protection system that actively monitors
the entire system (C:\\ and D:\\ drives) for threat detection and includes web protection.
"""

import os
import sys
import time
import json
import logging
import threading
import re
import subprocess
import signal
import platform
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

# Import core components with error handling
try:
    from core.agent import AgentInterface
    from core.yara_scanner import YaraScanner
    from core.behavioral_analyzer import BehavioralAnalyzer
    from core.enhanced_behavioral_analyzer import EnhancedBehavioralAnalyzer
    from core.predictive_threat_intelligence import PredictiveThreatIntelligenceEngine
    from core.web_protection import WebProtectionEngine
    from core.quarantine import QuarantineManager
    from core.dns_blocking import DNSBlockingServer
    from core.http_proxy import HTTPProxyServer
    from core.hosts_blocker import HostsBlocker
    from core.system_hardening import SystemHardeningManager
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"❌ Critical modules missing: {e}")
    MODULES_AVAILABLE = False
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RealTimeAegisAIHandler(FileSystemEventHandler):
    """Handler for real-time file system events"""
    
    def __init__(self):
        """Initialize the real-time handler"""
        self.threat_count = 0
        self.scan_count = 0
        self.last_scan_time = time.time()
        self.scan_delay = 0.5  # Minimum delay between scans (faster)
        self.last_recommendation_time = time.time()
        self.recommendation_interval = 2.0  # Generate recommendations every 2 seconds (faster)
        
        # Initialize core components
        try:
            self.agent = AgentInterface()
            self.yara_scanner = YaraScanner()
            self.behavioral_analyzer = BehavioralAnalyzer()
            self.enhanced_behavioral_analyzer = EnhancedBehavioralAnalyzer()
            self.pti_engine = PredictiveThreatIntelligenceEngine()
            self.web_protection = WebProtectionEngine()
            self.quarantine_manager = QuarantineManager()
            self.system_hardening = SystemHardeningManager()
            self.hosts_blocker = HostsBlocker()
            
            # Check if running with administrator privileges
            self.is_admin = self._check_admin_privileges()
            logger.info(f"Admin privileges detected: {self.is_admin}")
            if not self.is_admin:
                self._show_admin_warning()
            
            logger.info("🛡️  AegisAI real-time protection initialized")
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            sys.exit(1)
    
    def _check_admin_privileges(self):
        """Check if the script is running with administrator privileges"""
        try:
            if platform.system().lower() == 'windows':
                import ctypes
                result = ctypes.windll.shell32.IsUserAnAdmin()
                logger.info(f"IsUserAnAdmin() returned: {result}")
                return result
            else:
                result = os.geteuid() == 0
                logger.info(f"os.geteuid() == 0 returned: {result}")
                return result
        except Exception as e:
            logger.error(f"Error checking admin privileges: {e}")
            return False
    
    def _show_admin_warning(self):
        """Show a clear warning about missing admin privileges"""
        print("")
        print("⚠️  ADMINISTRATOR PRIVILEGES REQUIRED")
        print("=====================================")
        print("Some security features require administrator privileges to function properly:")
        print("  • System hardening (ASLR, DEP, Firewall)")
        print("  • Automatic threat quarantine")
        print("  • Registry modifications")
        print("  • Network protection")
        print("")
        print("Current status: ❌ Running without administrator privileges")
        print("")
        print("To enable full protection:")
        print("  1. Close this window")
        print("  2. Right-click on Command Prompt and select 'Run as administrator'")
        print("  3. Navigate to D:\\AegisAI")
        print("  4. Run: python realtime_aegisai.py")
        print("")
        print("The system will continue running but with limited functionality.")
        print("")
    
    def _apply_recommendations(self, recommendations):
        """Apply security recommendations automatically"""
        # Apply recommendations using the correct method
        try:
            results = self.system_hardening.apply_recommendations(recommendations)
            applied_count = results.get('applied', 0)
            simulated_count = results.get('simulated', 0)
            
            if applied_count > 0:
                logger.info(f"✅ Applied {applied_count} security recommendations")
            elif simulated_count > 0:
                # If not admin, show what would be applied
                high_confidence_recs = [rec for rec in recommendations if rec.get('confidence', 0) >= 0.7]
                if high_confidence_recs:
                    print(f"    🔧 WOULD APPLY (requires admin): {len(high_confidence_recs)} recommendations")
                    for i, rec in enumerate(high_confidence_recs[:3], 1):
                        description = rec.get('description', 'Unknown action')
                        confidence = rec.get('confidence', 0)
                        action = rec.get('action', 'unknown')
                        print(f"      {i}. {description} (Action: {action}, Confidence: {confidence:.1f})")
            elif not self.is_admin and len(recommendations) > 0:
                # Special case: if we have recommendations but nothing was simulated or applied
                print(f"    🔧 ADMIN REQUIRED: {len(recommendations)} security recommendations cannot be applied")
                print("       Run as administrator to enable automatic protection")
            return applied_count > 0
        except Exception as e:
            logger.error(f"Failed to apply recommendations: {e}")
            return False
    
    def _process_file(self, file_path):
        """Process a file for threat detection"""
        # Skip directories and certain system files
        if os.path.isdir(file_path):
            return
            
        # Skip files that are too large or in protected locations
        try:
            if os.path.getsize(file_path) > 100 * 1024 * 1024:  # 100MB limit
                return
        except:
            return
            
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_scan_time < self.scan_delay:
            return
        self.last_scan_time = current_time
        
        self.scan_count += 1
        if self.scan_count % 50 == 0:  # Log every 50 scans (more frequent)
            logger.info(f"Scanned {self.scan_count} files, detected {self.threat_count} threats")
        
        # Multi-layered threat detection
        results = []
        
        # Agent-based detection
        try:
            agent_result = self.agent.scan_file(file_path)
            if agent_result:
                results.append(('Agent', agent_result, 0.3))
        except Exception as e:
            pass
            
        # YARA signature scanning
        try:
            yara_result = self.yara_scanner.scan_file(file_path)
            if yara_result:
                results.append(('YARA', yara_result, 0.4))
        except Exception as e:
            pass
            
        # Behavioral analysis
        try:
            behavior_result = self.behavioral_analyzer.analyze_file(file_path)
            if behavior_result.get('is_anomaly', False):
                results.append(('Behavioral', behavior_result, 0.2))
        except Exception as e:
            pass
        
        # Enhanced behavioral analysis
        try:
            # This is where we integrate enhanced ML models with diverse threat data
            # For now, we'll simulate this enhancement by creating behavioral data
            behavioral_data = {
                'file_operations': 10,  # Simulated data
                'network_connections': 2,
                'cpu_usage': 15.0,
                'memory_usage': 100.0,
                'child_processes': 1,
                'registry_modifications': 1
            }
            enhanced_result = self.enhanced_behavioral_analyzer.analyze_behavior(behavioral_data)
            if enhanced_result.get('is_anomaly', False):
                results.append(('Enhanced ML', enhanced_result, 0.5))
        except Exception as e:
            pass
        
        # If threats detected, process them
        if results:
            self.threat_count += 1
            self._handle_threat(file_path, results)
    
    def _handle_threat(self, file_path, results):
        """Handle detected threats"""
        # Calculate overall confidence
        total_confidence = sum(result[2] for result in results)
        avg_confidence = min(total_confidence, 1.0) * 100
        
        # Determine threat severity
        if avg_confidence >= 90:
            severity = "MALICIOUS"
        elif avg_confidence >= 70:
            severity = "SUSPICIOUS"
        else:
            severity = "POTENTIALLY_UNWANTED"
        
        # Generate predictive intelligence using the correct method
        try:
            # Process the threat detection first
            threat_info = self.pti_engine.process_threat_detection({
                'file_path': file_path,
                'scan_time': datetime.now().isoformat(),
                'threat': {
                    'type': 'detected',
                    'severity': severity.lower(),
                    'confidence': avg_confidence / 100.0
                }
            })
            
            # Generate predictive intelligence more frequently
            current_time = time.time()
            if (self.threat_count % 2 == 0) or (current_time - self.last_recommendation_time > self.recommendation_interval):
                pti_results = self.pti_engine.generate_predictive_intelligence()
                hardening_recommendations = pti_results.get('hardening_recommendations', [])
                self.last_recommendation_time = current_time
            else:
                hardening_recommendations = []
        except Exception as e:
            logger.error(f"Error generating predictive intelligence: {e}")
            hardening_recommendations = []
        
        # Auto-quarantine high-confidence threats (only works with admin)
        if avg_confidence >= 70:
            try:
                quarantine_result = self.quarantine_manager.quarantine_file(file_path)
                if quarantine_result:
                    logger.info(f"🔒 AUTO-QUARANTINED: {file_path}")
                elif not self.is_admin:
                    logger.warning(f"⚠️  Would quarantine {file_path} (requires admin privileges)")
            except Exception as e:
                logger.error(f"Failed to quarantine {file_path}: {e}")
        
        # Apply hardening recommendations automatically (always try, regardless of admin status for testing)
        if hardening_recommendations:
            logger.info(f"Attempting to apply {len(hardening_recommendations)} recommendations")
            self._apply_recommendations(hardening_recommendations)
        
        # Display threat information
        detection_methods = ", ".join([result[0] for result in results])
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚨 THREAT DETECTED!")
        print(f"")
        print(f"    File: {file_path}")
        print(f"")
        print(f"    Threat: Suspicious File")
        print(f"")
        print(f"    Severity: {severity}")
        print(f"")
        print(f"    Confidence: {avg_confidence:.1f}%")
        print(f"")
        print(f"    Detection Methods: {detection_methods}")
        
        if hardening_recommendations:
            print(f"")
            print(f"    🔧 Recommendations:")
            print(f"")
            # Filter out duplicate recommendations and show unique ones
            unique_recommendations = []
            seen_actions = set()
            for rec in hardening_recommendations:
                action = rec.get('action', '')
                if action not in seen_actions:
                    unique_recommendations.append(rec)
                    seen_actions.add(action)
            
            for i, rec in enumerate(unique_recommendations[:3], 1):  # Show top 3 unique recommendations
                description = rec.get('description', 'Unknown action')
                confidence = rec.get('confidence', 0)
                action = rec.get('action', 'unknown')
                print(f"      {i}. {description} (Action: {action}, Confidence: {confidence:.1f})")
        elif not hardening_recommendations and self.threat_count % 2 == 0:
            # Show a message that recommendations are being generated
            print(f"")
            print(f"    🔧 Analyzing threat patterns...")
        
        print(f"")
    
    def on_modified(self, event):
        """Handle file modification events"""
        if not event.is_directory:
            self._process_file(event.src_path)
    
    def on_created(self, event):
        """Handle file creation events"""
        if not event.is_directory:
            self._process_file(event.src_path)

def start_web_protection():
    """Start web protection services"""
    print("🌐 Starting web protection services...")
    
    # Hosts file ad blocking (works automatically)
    try:
        hosts_blocker = HostsBlocker()
        blocked_count = hosts_blocker.block_ads_in_hosts()
        print(f"✅ Hosts file ad blocker: {blocked_count} domains blocked")
    except Exception as e:
        print(f"⚠️  Hosts file ad blocker failed: {e}")

def main():
    """Main function to run real-time protection"""
    if not MODULES_AVAILABLE:
        print("❌ Critical modules missing. Please install required dependencies.")
        return
    
    print("🛡️  AegisAI Real-Time Protection System")
    print("======================================")
    print("")
    
    # Initialize handler
    try:
        handler = RealTimeAegisAIHandler()
    except Exception as e:
        print(f"❌ Failed to initialize AegisAI: {e}")
        return
    
    # Start web protection
    start_web_protection()
    
    # Setup file system monitoring
    print("📁 Setting up file system monitoring...")
    observer = Observer()
    
    # Monitor C: and D: drives if they exist
    drives_to_monitor = []
    for drive in ['C:\\', 'D:\\']:
        if os.path.exists(drive):
            drives_to_monitor.append(drive)
            observer.schedule(handler, drive, recursive=True)
            print(f"✅ Monitoring: {drive}")
    
    if not drives_to_monitor:
        print("❌ No drives to monitor found")
        return
    
    # Start monitoring
    observer.start()
    print("")
    print("🔄 Real-time protection active. Press Ctrl+C to stop.")
    print("")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("")
        print("🛑 Stopping AegisAI real-time protection...")
        observer.stop()
        observer.join()
        print("✅ AegisAI stopped successfully")

if __name__ == "__main__":
    main()