"""
AegisAI Diagnostics and Troubleshooting Module
============================================

This module provides comprehensive system diagnostics and troubleshooting tools
for the AegisAI antivirus system.
"""

import os
import sys
import json
import logging
import platform
import subprocess
import threading
import time
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

# Import core components
try:
    from .config_manager import get_config_manager
    from .rust_agent_interface import RustAgentInterface
    from .license_manager import LicenseManager
except ImportError:
    # Fallback for when running as a script
    from config_manager import get_config_manager
    from rust_agent_interface import RustAgentInterface
    from license_manager import LicenseManager

logger = logging.getLogger(__name__)

class SystemDiagnostics:
    """Comprehensive system diagnostics for AegisAI"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the diagnostics module.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_manager = get_config_manager(config_path)
        self.rust_agent = None
        self.license_manager = LicenseManager()
        self.diagnostics_results = {}
        self.is_running_diagnostics = False
        
    def run_comprehensive_diagnostics(self) -> Dict:
        """
        Run comprehensive system diagnostics.
        
        Returns:
            Dictionary with diagnostics results
        """
        self.is_running_diagnostics = True
        logger.info("Starting comprehensive system diagnostics...")
        
        try:
            # Run all diagnostic checks
            self.diagnostics_results = {
                'timestamp': datetime.now().isoformat(),
                'system_info': self._check_system_info(),
                'component_status': self._check_component_status(),
                'resource_usage': self._check_resource_usage(),
                'network_connectivity': self._check_network_connectivity(),
                'file_system': self._check_file_system(),
                'license_status': self._check_license_status(),
                'configuration': self._check_configuration(),
                'performance_metrics': self._check_performance_metrics(),
                'security_status': self._check_security_status()
            }
            
            # Add overall health score
            self.diagnostics_results['health_score'] = self._calculate_health_score()
            self.diagnostics_results['recommendations'] = self._generate_recommendations()
            
            logger.info("Comprehensive diagnostics completed successfully")
            return self.diagnostics_results
            
        except Exception as e:
            logger.error(f"Error during diagnostics: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
        finally:
            self.is_running_diagnostics = False
    
    def _check_system_info(self) -> Dict:
        """Check system information."""
        try:
            return {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'machine': platform.machine(),
                'node': platform.node(),
                'python_version': sys.version,
                'python_implementation': platform.python_implementation(),
                'python_compiler': platform.python_compiler()
            }
        except Exception as e:
            return {'error': f"Failed to get system info: {e}"}
    
    def _check_component_status(self) -> Dict:
        """Check status of all system components."""
        try:
            status = {
                'core_engine': True,  # Always running in diagnostics context
                'rust_agent': False,
                'ml_engine': False,
                'realtime_protection': False,
                'network_protection': False,
                'quarantine_manager': False
            }
            
            # Check if Rust agent is available
            try:
                rust_config = self.config_manager.get_rust_config()
                agent_path = rust_config.get('executable_path')
                if agent_path and os.path.exists(agent_path):
                    status['rust_agent'] = True
            except:
                pass
            
            # Check ML engine availability
            try:
                # Try to import ML components
                import sklearn
                status['ml_engine'] = True
            except ImportError:
                pass
            
            # Check configuration for enabled features
            status['realtime_protection'] = self.config_manager.get('core.enable_realtime', False)
            status['network_protection'] = self.config_manager.get('core.enable_network_protection', False)
            status['quarantine_manager'] = self.config_manager.get('core.enable_quarantine', False)
            
            return status
        except Exception as e:
            return {'error': f"Failed to check component status: {e}"}
    
    def _check_resource_usage(self) -> Dict:
        """Check system resource usage."""
        try:
            import psutil
            
            # Get process info for current process
            process = psutil.Process(os.getpid())
            process_info = {
                'cpu_percent': process.cpu_percent(),
                'memory_info': dict(process.memory_info()._asdict()),
                'memory_percent': process.memory_percent(),
                'num_threads': process.num_threads(),
                'open_files': len(process.open_files()) if hasattr(process, 'open_files') else 0
            }
            
            # Get system-wide info
            system_info = {
                'cpu_count': psutil.cpu_count(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'virtual_memory': dict(psutil.virtual_memory()._asdict()),
                'swap_memory': dict(psutil.swap_memory()._asdict()),
                'disk_usage': dict(psutil.disk_usage('/')._asdict()) if os.name != 'nt' else dict(psutil.disk_usage('C:\\')._asdict()),
                'network_io': dict(psutil.net_io_counters()._asdict())
            }
            
            return {
                'process': process_info,
                'system': system_info
            }
        except ImportError:
            return {'error': 'psutil not available for resource monitoring'}
        except Exception as e:
            return {'error': f"Failed to check resource usage: {e}"}
    
    def _check_network_connectivity(self) -> Dict:
        """Check network connectivity and firewall status."""
        try:
            results = {
                'internet_access': False,
                'dns_resolution': False,
                'firewall_status': 'unknown'
            }
            
            # Check internet connectivity by pinging a known host
            try:
                # Use system ping command
                if os.name == 'nt':  # Windows
                    result = subprocess.run(['ping', '-n', '1', '8.8.8.8'], 
                                          capture_output=True, timeout=5)
                else:  # Unix/Linux/Mac
                    result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                                          capture_output=True, timeout=5)
                
                results['internet_access'] = result.returncode == 0
            except:
                pass
            
            # Check DNS resolution
            try:
                import socket
                socket.gethostbyname('google.com')
                results['dns_resolution'] = True
            except:
                pass
            
            # Check firewall status (Windows specific)
            if os.name == 'nt':
                try:
                    result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                          capture_output=True, text=True, timeout=5)
                    if 'State' in result.stdout:
                        results['firewall_status'] = 'active' if 'ON' in result.stdout else 'inactive'
                except:
                    pass
            
            return results
        except Exception as e:
            return {'error': f"Failed to check network connectivity: {e}"}
    
    def _check_file_system(self) -> Dict:
        """Check file system permissions and disk space."""
        try:
            results = {
                'disk_space': {},
                'permissions': {},
                'critical_paths': {}
            }
            
            # Check disk space on all drives
            if os.name == 'nt':  # Windows
                import string
                drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            else:  # Unix/Linux/Mac
                drives = ['/']
            
            for drive in drives:
                try:
                    stat = os.statvfs(drive) if hasattr(os, 'statvfs') else None
                    if stat:
                        total = stat.f_frsize * stat.f_blocks
                        free = stat.f_frsize * stat.f_bavail
                        used = total - free
                        results['disk_space'][drive] = {
                            'total': total,
                            'used': used,
                            'free': free,
                            'percent_used': (used / total) * 100 if total > 0 else 0
                        }
                except:
                    pass
            
            # Check permissions on critical directories
            critical_paths = [
                self.config_manager.get('system.quarantine_directory', './quarantine'),
                self.config_manager.get('system.log_directory', './logs'),
                self.config_manager.get('core.signature_db_path', './signatures')
            ]
            
            for path in critical_paths:
                try:
                    path_obj = Path(path)
                    results['critical_paths'][path] = {
                        'exists': path_obj.exists(),
                        'readable': os.access(path, os.R_OK),
                        'writable': os.access(path, os.W_OK),
                        'executable': os.access(path, os.X_OK) if os.name != 'nt' else True
                    }
                except Exception as e:
                    results['critical_paths'][path] = {'error': str(e)}
            
            return results
        except Exception as e:
            return {'error': f"Failed to check file system: {e}"}
    
    def _check_license_status(self) -> Dict:
        """Check license status and feature availability."""
        try:
            return self.license_manager.get_license_info()
        except Exception as e:
            return {'error': f"Failed to check license status: {e}"}
    
    def _check_configuration(self) -> Dict:
        """Check configuration file integrity and settings."""
        try:
            config_path = getattr(self.config_manager, 'config_path', 'config.json')
            return {
                'config_file': config_path,
                'exists': os.path.exists(config_path),
                'readable': os.access(config_path, os.R_OK),
                'writable': os.access(config_path, os.W_OK),
                'last_modified': datetime.fromtimestamp(os.path.getmtime(config_path)).isoformat() if os.path.exists(config_path) else None,
                'settings': {
                    'core': self.config_manager.get('core', {}),
                    'system': self.config_manager.get('system', {}),
                    'rust_agent': self.config_manager.get('rust_agent', {}),
                    'cloud': self.config_manager.get('cloud', {})
                }
            }
        except Exception as e:
            return {'error': f"Failed to check configuration: {e}"}
    
    def _check_performance_metrics(self) -> Dict:
        """Check performance metrics and bottlenecks."""
        try:
            metrics = {
                'startup_time': None,
                'scan_performance': None,
                'memory_growth': None,
                'cpu_spikes': None
            }
            
            # These would typically be collected during normal operation
            # For now, we'll return placeholder data
            return {
                'placeholder': True,
                'message': 'Performance metrics are collected during normal operation'
            }
        except Exception as e:
            return {'error': f"Failed to check performance metrics: {e}"}
    
    def _check_security_status(self) -> Dict:
        """Check security-related status."""
        try:
            return {
                'antivirus_detected': self._detect_other_antivirus(),
                'system_integrity': self._check_system_integrity(),
                'vulnerabilities': self._check_known_vulnerabilities()
            }
        except Exception as e:
            return {'error': f"Failed to check security status: {e}"}
    
    def _detect_other_antivirus(self) -> List[str]:
        """Detect other antivirus software that might conflict."""
        try:
            conflicts = []
            
            if os.name == 'nt':  # Windows
                # Check for common antivirus processes
                common_av_processes = [
                    'avp.exe', 'avg.exe', 'avast.exe', 'bitdefender.exe',
                    'eset.exe', 'f-secure.exe', 'kaspersky.exe', 'mcafee.exe',
                    'norton.exe', 'panda.exe', 'sophos.exe', 'trendmicro.exe'
                ]
                
                try:
                    result = subprocess.run(['tasklist'], capture_output=True, text=True, timeout=10)
                    for process in common_av_processes:
                        if process.lower() in result.stdout.lower():
                            conflicts.append(process)
                except:
                    pass
                
                # Check Windows Security Center status
                try:
                    import win32com.client
                    wmi = win32com.client.GetObject('winmgmts:')
                    col_items = wmi.ExecQuery("SELECT * FROM AntiVirusProduct")
                    for item in col_items:
                        conflicts.append(f"Windows Defender or other: {item.displayName}")
                except:
                    pass
            
            return conflicts
        except Exception as e:
            logger.warning(f"Failed to detect other antivirus software: {e}")
            return []
    
    def _check_system_integrity(self) -> Dict:
        """Check system integrity."""
        try:
            return {
                'system_files': 'unknown',
                'registry_integrity': 'unknown' if os.name == 'nt' else 'not_applicable',
                'kernel_modules': 'unknown'
            }
        except Exception as e:
            return {'error': f"Failed to check system integrity: {e}"}
    
    def _check_known_vulnerabilities(self) -> List[str]:
        """Check for known system vulnerabilities."""
        try:
            vulnerabilities = []
            
            # Check Python version for known vulnerabilities
            python_version = sys.version_info
            if python_version < (3, 8):
                vulnerabilities.append("Python version is outdated and may have security vulnerabilities")
            
            # Check for common vulnerable packages
            try:
                import importlib.metadata
                vulnerable_packages = {
                    'requests': '2.20.0',  # Example vulnerable version
                }
                
                for package, min_safe_version in vulnerable_packages.items():
                    try:
                        installed_version = importlib.metadata.version(package)
                        # In a real implementation, you would compare versions properly
                        # This is a simplified check
                        if installed_version < min_safe_version:
                            vulnerabilities.append(f"Package {package} version {installed_version} may be vulnerable")
                    except:
                        pass
            except:
                pass
            
            return vulnerabilities
        except Exception as e:
            logger.warning(f"Failed to check for vulnerabilities: {e}")
            return []
    
    def _calculate_health_score(self) -> int:
        """Calculate overall system health score (0-100)."""
        try:
            if not self.diagnostics_results:
                return 0
            
            score = 100
            
            # Component status checks
            component_status = self.diagnostics_results.get('component_status', {})
            if component_status.get('rust_agent') is False:
                score -= 10
            if component_status.get('ml_engine') is False:
                score -= 5
            
            # Resource usage checks
            resource_usage = self.diagnostics_results.get('resource_usage', {})
            if isinstance(resource_usage, dict) and 'system' in resource_usage:
                system = resource_usage['system']
                if isinstance(system, dict):
                    cpu_percent = system.get('cpu_percent', 0)
                    if cpu_percent > 90:
                        score -= 15
                    elif cpu_percent > 70:
                        score -= 10
                    
                    virtual_memory = system.get('virtual_memory', {})
                    if isinstance(virtual_memory, dict):
                        memory_percent = virtual_memory.get('percent', 0)
                        if memory_percent > 90:
                            score -= 15
                        elif memory_percent > 70:
                            score -= 10
            
            # Network connectivity
            network = self.diagnostics_results.get('network_connectivity', {})
            if network.get('internet_access') is False:
                score -= 20
            if network.get('dns_resolution') is False:
                score -= 15
            
            # File system checks
            file_system = self.diagnostics_results.get('file_system', {})
            critical_paths = file_system.get('critical_paths', {})
            for path_info in critical_paths.values():
                if isinstance(path_info, dict):
                    if path_info.get('exists') is False:
                        score -= 10
                    if path_info.get('writable') is False:
                        score -= 5
            
            # License status
            license_info = self.diagnostics_results.get('license_status', {})
            if license_info.get('licensed') is False:
                score -= 10
            
            # Security checks
            security_status = self.diagnostics_results.get('security_status', {})
            antivirus_conflicts = security_status.get('antivirus_detected', [])
            if antivirus_conflicts:
                score -= len(antivirus_conflicts) * 5
            
            # Ensure score is within bounds
            return max(0, min(100, score))
        except Exception as e:
            logger.warning(f"Failed to calculate health score: {e}")
            return 50  # Default middle score
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on diagnostics results."""
        try:
            recommendations = []
            
            if not self.diagnostics_results:
                return recommendations
            
            # Component recommendations
            component_status = self.diagnostics_results.get('component_status', {})
            if component_status.get('rust_agent') is False:
                recommendations.append("Install or rebuild the Rust agent for enhanced performance")
            if component_status.get('ml_engine') is False:
                recommendations.append("Install scikit-learn for machine learning-based threat detection")
            
            # Resource recommendations
            resource_usage = self.diagnostics_results.get('resource_usage', {})
            if isinstance(resource_usage, dict) and 'system' in resource_usage:
                system = resource_usage['system']
                if isinstance(system, dict):
                    cpu_percent = system.get('cpu_percent', 0)
                    if cpu_percent > 80:
                        recommendations.append("High CPU usage detected. Consider reducing scanning intensity or closing other applications")
                    
                    virtual_memory = system.get('virtual_memory', {})
                    if isinstance(virtual_memory, dict):
                        memory_percent = virtual_memory.get('percent', 0)
                        if memory_percent > 80:
                            recommendations.append("High memory usage detected. Consider restarting the application or closing other applications")
            
            # Network recommendations
            network = self.diagnostics_results.get('network_connectivity', {})
            if network.get('internet_access') is False:
                recommendations.append("No internet access detected. Check network connection and firewall settings")
            if network.get('dns_resolution') is False:
                recommendations.append("DNS resolution failed. Check DNS settings or try using a different DNS server")
            
            # File system recommendations
            file_system = self.diagnostics_results.get('file_system', {})
            critical_paths = file_system.get('critical_paths', {})
            for path, path_info in critical_paths.items():
                if isinstance(path_info, dict):
                    if path_info.get('exists') is False:
                        recommendations.append(f"Critical directory missing: {path}. Please create this directory")
                    if path_info.get('writable') is False:
                        recommendations.append(f"Insufficient permissions for directory: {path}. Please check directory permissions")
            
            # License recommendations
            license_info = self.diagnostics_results.get('license_status', {})
            if license_info.get('licensed') is False:
                recommendations.append("Using free tier. Consider upgrading for additional features and real-time protection")
            
            # Security recommendations
            security_status = self.diagnostics_results.get('security_status', {})
            antivirus_conflicts = security_status.get('antivirus_detected', [])
            if antivirus_conflicts:
                recommendations.append(f"Conflicting antivirus software detected: {', '.join(antivirus_conflicts)}. Consider disabling them to prevent conflicts")
            
            # Vulnerability recommendations
            vulnerabilities = security_status.get('vulnerabilities', [])
            for vulnerability in vulnerabilities:
                recommendations.append(f"Security vulnerability detected: {vulnerability}")
            
            return recommendations
        except Exception as e:
            logger.warning(f"Failed to generate recommendations: {e}")
            return ["Unable to generate specific recommendations due to diagnostic error"]
    
    def export_diagnostics_report(self, file_path: str) -> bool:
        """
        Export diagnostics report to a JSON file.
        
        Args:
            file_path: Path to export file
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            if not self.diagnostics_results:
                logger.warning("No diagnostics results to export")
                return False
            
            with open(file_path, 'w') as f:
                json.dump(self.diagnostics_results, f, indent=2, default=str)
            
            logger.info(f"Diagnostics report exported to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export diagnostics report: {e}")
            return False

class TroubleshootingAssistant:
    """Interactive troubleshooting assistant for common issues."""
    
    def __init__(self, diagnostics: SystemDiagnostics):
        """
        Initialize the troubleshooting assistant.
        
        Args:
            diagnostics: SystemDiagnostics instance
        """
        self.diagnostics = diagnostics
    
    def run_interactive_troubleshooting(self):
        """Run interactive troubleshooting session."""
        print("AegisAI Troubleshooting Assistant")
        print("=" * 40)
        
        # Run diagnostics if not already done
        if not self.diagnostics.diagnostics_results:
            print("Running system diagnostics...")
            self.diagnostics.run_comprehensive_diagnostics()
        
        # Display health score
        health_score = self.diagnostics.diagnostics_results.get('health_score', 50)
        print(f"\nSystem Health Score: {health_score}/100")
        
        # Display recommendations
        recommendations = self.diagnostics.diagnostics_results.get('recommendations', [])
        if recommendations:
            print("\nRecommendations:")
            for i, recommendation in enumerate(recommendations, 1):
                print(f"  {i}. {recommendation}")
        else:
            print("\nNo recommendations at this time. System appears healthy.")
        
        # Interactive menu
        while True:
            print("\nOptions:")
            print("1. View detailed diagnostics")
            print("2. Export diagnostics report")
            print("3. Run specific diagnostic check")
            print("4. Exit")
            
            try:
                choice = input("\nEnter your choice (1-4): ").strip()
                
                if choice == '1':
                    self._display_detailed_diagnostics()
                elif choice == '2':
                    self._export_diagnostics_report()
                elif choice == '3':
                    self._run_specific_check()
                elif choice == '4':
                    print("Exiting troubleshooting assistant.")
                    break
                else:
                    print("Invalid choice. Please try again.")
            except KeyboardInterrupt:
                print("\nExiting troubleshooting assistant.")
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def _display_detailed_diagnostics(self):
        """Display detailed diagnostics information."""
        results = self.diagnostics.diagnostics_results
        if not results:
            print("No diagnostics results available.")
            return
        
        print("\nDetailed Diagnostics Results:")
        print("-" * 30)
        
        # Display each section
        for section, data in results.items():
            if section in ['timestamp', 'health_score', 'recommendations']:
                continue
            
            print(f"\n{section.replace('_', ' ').title()}:")
            self._print_dict(data, indent=2)
    
    def _print_dict(self, data: Any, indent: int = 0):
        """Print dictionary data with proper indentation."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict):
                    print(" " * indent + f"{key}:")
                    self._print_dict(value, indent + 2)
                elif isinstance(value, list):
                    print(" " * indent + f"{key}:")
                    for item in value:
                        if isinstance(item, dict):
                            self._print_dict(item, indent + 4)
                        else:
                            print(" " * (indent + 4) + str(item))
                else:
                    print(" " * indent + f"{key}: {value}")
        else:
            print(" " * indent + str(data))
    
    def _export_diagnostics_report(self):
        """Export diagnostics report to file."""
        try:
            filename = input("Enter filename for export (default: diagnostics_report.json): ").strip()
            if not filename:
                filename = "diagnostics_report.json"
            
            if self.diagnostics.export_diagnostics_report(filename):
                print(f"Report exported successfully to {filename}")
            else:
                print("Failed to export report.")
        except Exception as e:
            print(f"Error exporting report: {e}")
    
    def _run_specific_check(self):
        """Run a specific diagnostic check."""
        print("\nAvailable diagnostic checks:")
        print("1. System Information")
        print("2. Component Status")
        print("3. Resource Usage")
        print("4. Network Connectivity")
        print("5. File System")
        print("6. License Status")
        print("7. Configuration")
        print("8. Security Status")
        
        try:
            choice = input("\nEnter check number (1-8): ").strip()
            
            check_functions = {
                '1': self.diagnostics._check_system_info,
                '2': self.diagnostics._check_component_status,
                '3': self.diagnostics._check_resource_usage,
                '4': self.diagnostics._check_network_connectivity,
                '5': self.diagnostics._check_file_system,
                '6': self.diagnostics._check_license_status,
                '7': self.diagnostics._check_configuration,
                '8': self.diagnostics._check_security_status
            }
            
            if choice in check_functions:
                print(f"\nRunning check {choice}...")
                result = check_functions[choice]()
                self._print_dict(result)
            else:
                print("Invalid choice.")
        except Exception as e:
            print(f"Error running check: {e}")

# Command line interface
def main():
    """Main entry point for command line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AegisAI Diagnostics and Troubleshooting Tool')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--export', help='Export diagnostics report to file')
    parser.add_argument('--interactive', action='store_true', help='Run interactive troubleshooting')
    parser.add_argument('--check', choices=['system', 'components', 'resources', 'network', 'filesystem', 'license', 'config', 'security'],
                       help='Run specific diagnostic check')
    
    args = parser.parse_args()
    
    # Initialize diagnostics
    diagnostics = SystemDiagnostics(config_path=args.config)
    
    if args.interactive:
        # Run interactive troubleshooting
        assistant = TroubleshootingAssistant(diagnostics)
        assistant.run_interactive_troubleshooting()
    elif args.check:
        # Run specific check
        check_functions = {
            'system': diagnostics._check_system_info,
            'components': diagnostics._check_component_status,
            'resources': diagnostics._check_resource_usage,
            'network': diagnostics._check_network_connectivity,
            'filesystem': diagnostics._check_file_system,
            'license': diagnostics._check_license_status,
            'config': diagnostics._check_configuration,
            'security': diagnostics._check_security_status
        }
        
        if args.check in check_functions:
            result = check_functions[args.check]()
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"Unknown check: {args.check}")
    elif args.export:
        # Run diagnostics and export
        diagnostics.run_comprehensive_diagnostics()
        if diagnostics.export_diagnostics_report(args.export):
            print(f"Diagnostics report exported to {args.export}")
        else:
            print("Failed to export diagnostics report")
    else:
        # Run comprehensive diagnostics and display results
        results = diagnostics.run_comprehensive_diagnostics()
        print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    main()