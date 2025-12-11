#!/usr/bin/env python3
"""
AegisAI Real-time Behavioral Monitoring
=====================================

This module provides real-time behavioral monitoring capabilities for detecting
suspicious system activities as they happen.
"""

import os
import json
import logging
import time
import threading
from typing import Dict, List, Any, Callable
from datetime import datetime
import numpy as np

# Try to import required libraries
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = None
    logging.warning("Watchdog not available. File system monitoring disabled.")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    psutil = None
    logging.warning("Psutil not available. Process monitoring disabled.")

logger = logging.getLogger(__name__)

class RealTimeBehavioralMonitor:
    """Real-time behavioral monitoring for suspicious system activities"""
    
    def __init__(self):
        """Initialize the real-time behavioral monitor"""
        self.observer = None
        self.event_handler = None
        self.monitoring = False
        self.callbacks = []
        self.monitored_paths = []
        self.process_monitor_thread = None
        self.stop_process_monitor = False
        
        # Behavioral thresholds
        self.thresholds = {
            'file_operations_per_minute': 100,
            'process_creation_rate': 10,
            'network_connections_per_process': 20,
            'registry_modifications_per_minute': 50
        }
        
        # Statistics tracking
        self.stats = {
            'file_operations': 0,
            'process_creations': 0,
            'network_connections': 0,
            'registry_modifications': 0,
            'start_time': None
        }
        
        logger.info("Real-time behavioral monitor initialized")
    
    def add_callback(self, callback: Callable[[Dict], None]):
        """
        Add a callback function to be called when suspicious behavior is detected
        
        Args:
            callback: Function to call with behavioral data when anomalies are detected
        """
        self.callbacks.append(callback)
    
    def start_monitoring(self, paths: List[str] = None):
        """
        Start real-time behavioral monitoring
        
        Args:
            paths: List of paths to monitor (defaults to system directories)
        """
        if self.monitoring:
            logger.warning("Real-time monitoring already active")
            return False
        
        if not paths:
            # Default to monitoring common system directories
            paths = [
                "C:\\Windows\\System32",
                "C:\\Program Files",
                os.path.expanduser("~\\AppData\\Local\\Temp")
            ]
        
        self.monitored_paths = paths
        self.stats['start_time'] = datetime.now()
        
        # Start file system monitoring if available
        if WATCHDOG_AVAILABLE:
            self._start_filesystem_monitoring()
        
        # Start process monitoring if available
        if PSUTIL_AVAILABLE:
            self._start_process_monitoring()
        
        self.monitoring = True
        logger.info(f"Real-time behavioral monitoring started for paths: {paths}")
        return True
    
    def _start_filesystem_monitoring(self):
        """Start file system event monitoring"""
        try:
            self.event_handler = FileSystemEventHandler()
            self.event_handler.on_any_event = self._handle_filesystem_event
            
            self.observer = Observer()
            for path in self.monitored_paths:
                if os.path.exists(path):
                    self.observer.schedule(self.event_handler, path, recursive=True)
                    logger.debug(f"Scheduled monitoring for path: {path}")
            
            self.observer.start()
            logger.info("File system monitoring started")
        except Exception as e:
            logger.error(f"Failed to start file system monitoring: {e}")
    
    def _handle_filesystem_event(self, event):
        """Handle file system events"""
        # Update statistics
        self.stats['file_operations'] += 1
        
        # Check for suspicious activity
        self._check_suspicious_file_activity(event)
    
    def _check_suspicious_file_activity(self, event):
        """Check file system events for suspicious activity"""
        # Simple rate-based detection for now
        elapsed_time = (datetime.now() - self.stats['start_time']).total_seconds()
        if elapsed_time > 60:  # Check every minute
            ops_per_minute = self.stats['file_operations'] / (elapsed_time / 60)
            if ops_per_minute > self.thresholds['file_operations_per_minute']:
                behavioral_data = {
                    'timestamp': datetime.now().isoformat(),
                    'activity_type': 'file_operations',
                    'rate': ops_per_minute,
                    'threshold': self.thresholds['file_operations_per_minute'],
                    'suspicious': True,
                    'description': f"High file operation rate: {ops_per_minute:.2f}/min"
                }
                self._notify_callbacks(behavioral_data)
    
    def _start_process_monitoring(self):
        """Start process monitoring in a separate thread"""
        self.stop_process_monitor = False
        self.process_monitor_thread = threading.Thread(target=self._process_monitor_loop)
        self.process_monitor_thread.daemon = True
        self.process_monitor_thread.start()
        logger.info("Process monitoring started")
    
    def _process_monitor_loop(self):
        """Monitor process activities in a loop"""
        previous_processes = {}
        
        while not self.stop_process_monitor:
            try:
                # Get current processes
                current_processes = {}
                for proc in psutil.process_iter(['pid', 'name', 'create_time', 'connections']):
                    try:
                        current_processes[proc.info['pid']] = proc.info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                # Check for new processes
                new_processes = set(current_processes.keys()) - set(previous_processes.keys())
                self.stats['process_creations'] += len(new_processes)
                
                # Check for suspicious processes
                for pid in new_processes:
                    if pid in current_processes:
                        proc_info = current_processes[pid]
                        self._check_suspicious_process(proc_info)
                
                # Update previous processes
                previous_processes = current_processes
                
                # Check process creation rate
                self._check_process_creation_rate()
                
                time.sleep(1)  # Check every second
            except Exception as e:
                logger.error(f"Error in process monitoring loop: {e}")
                time.sleep(5)  # Wait longer on error
    
    def _check_suspicious_process(self, proc_info):
        """Check if a process is suspicious"""
        suspicious_names = ['powershell', 'cmd', 'wmic', 'netsh', 'mshta', 'regsvr32', 'rundll32']
        proc_name = proc_info.get('name', '').lower()
        
        if any(suspicious_name in proc_name for suspicious_name in suspicious_names):
            behavioral_data = {
                'timestamp': datetime.now().isoformat(),
                'activity_type': 'suspicious_process',
                'process_name': proc_name,
                'pid': proc_info.get('pid'),
                'suspicious': True,
                'description': f"Suspicious process detected: {proc_name}"
            }
            self._notify_callbacks(behavioral_data)
    
    def _check_process_creation_rate(self):
        """Check if process creation rate is suspicious"""
        elapsed_time = (datetime.now() - self.stats['start_time']).total_seconds()
        if elapsed_time > 60:  # Check every minute
            creations_per_minute = self.stats['process_creations'] / (elapsed_time / 60)
            if creations_per_minute > self.thresholds['process_creation_rate']:
                behavioral_data = {
                    'timestamp': datetime.now().isoformat(),
                    'activity_type': 'process_creation_rate',
                    'rate': creations_per_minute,
                    'threshold': self.thresholds['process_creation_rate'],
                    'suspicious': True,
                    'description': f"High process creation rate: {creations_per_minute:.2f}/min"
                }
                self._notify_callbacks(behavioral_data)
    
    def _notify_callbacks(self, behavioral_data: Dict):
        """Notify all registered callbacks of suspicious behavior"""
        for callback in self.callbacks:
            try:
                callback(behavioral_data)
            except Exception as e:
                logger.error(f"Error in behavioral monitoring callback: {e}")
    
    def stop_monitoring(self):
        """Stop real-time behavioral monitoring"""
        if not self.monitoring:
            return
        
        # Stop file system monitoring
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        
        # Stop process monitoring
        self.stop_process_monitor = True
        if self.process_monitor_thread:
            self.process_monitor_thread.join()
            self.process_monitor_thread = None
        
        self.monitoring = False
        logger.info("Real-time behavioral monitoring stopped")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get behavioral monitoring statistics
        
        Returns:
            Dictionary with monitoring statistics
        """
        elapsed_time = (datetime.now() - self.stats['start_time']).total_seconds() if self.stats['start_time'] else 0
        
        rates = {}
        if elapsed_time > 0:
            rates = {
                'file_operations_per_minute': (self.stats['file_operations'] / elapsed_time) * 60,
                'process_creations_per_minute': (self.stats['process_creations'] / elapsed_time) * 60
            }
        
        return {
            'monitoring_active': self.monitoring,
            'monitored_paths': self.monitored_paths,
            'statistics': self.stats,
            'rates': rates,
            'thresholds': self.thresholds
        }

def main():
    """Demo function to show real-time behavioral monitoring"""
    print("=" * 60)
    print("           AEGISAI REAL-TIME BEHAVIORAL MONITORING")
    print("=" * 60)
    
    # Initialize monitor
    monitor = RealTimeBehavioralMonitor()
    
    # Add callback for suspicious behavior
    def suspicious_behavior_callback(data):
        if data.get('suspicious', False):
            print(f"🚨 Suspicious behavior detected: {data.get('description', 'Unknown')}")
    
    monitor.add_callback(suspicious_behavior_callback)
    
    # Start monitoring
    print("Starting real-time behavioral monitoring...")
    success = monitor.start_monitoring()
    
    if success:
        print("✅ Real-time behavioral monitoring started")
        print("Monitoring for 30 seconds...")
        
        # Monitor for 30 seconds
        time.sleep(30)
        
        # Show statistics
        stats = monitor.get_statistics()
        print("\n📊 Monitoring Statistics:")
        print(f"  File operations: {stats['statistics']['file_operations']}")
        print(f"  Process creations: {stats['statistics']['process_creations']}")
        if stats['rates']:
            print(f"  File operations rate: {stats['rates']['file_operations_per_minute']:.2f}/min")
            print(f"  Process creation rate: {stats['rates']['process_creations_per_minute']:.2f}/min")
        
        # Stop monitoring
        monitor.stop_monitoring()
        print("\n⏹️  Real-time behavioral monitoring stopped")
    else:
        print("❌ Failed to start real-time behavioral monitoring")

if __name__ == "__main__":
    main()