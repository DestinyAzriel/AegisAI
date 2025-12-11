#!/usr/bin/env python3
"""
AegisAI Antivirus - Command Line Interface
Main executable for antivirus scanning and real-time protection
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

def setup_logging(verbose=False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def scan_file(file_path):
    """Scan a single file"""
    try:
        from core.scanner import FileScanner
        from core.yara_scanner import YaraScanner
        
        # Initialize scanners
        file_scanner = FileScanner()
        yara_scanner = YaraScanner()
        
        print(f"🔍 Scanning file: {file_path}")
        
        # File scan
        file_result = file_scanner.scan_file(file_path)
        print(f"   File scan result: {file_result['status']}")
        
        # YARA scan
        yara_matches = yara_scanner.scan_file(file_path)
        print(f"   YARA matches: {len(yara_matches)}")
        
        # Detailed results
        if file_result['status'] == 'threat_detected':
            threat = file_result['threat']
            print(f"   🚨 THREAT: {threat['name']}")
            print(f"      Type: {threat['type']}")
            print(f"      Severity: {threat['severity']}")
        elif file_result['status'] == 'suspicious':
            analysis = file_result['analysis']
            print(f"   ⚠️  SUSPICIOUS: {analysis['name']}")
            print(f"      Confidence: {analysis['confidence']:.2f}")
        
        # YARA details
        for match in yara_matches:
            print(f"   🔍 YARA Rule: {match['rule']}")
            if 'meta' in match and 'description' in match['meta']:
                print(f"      Description: {match['meta']['description']}")
        
        return file_result['status'] != 'threat_detected'
        
    except Exception as e:
        print(f"❌ Error scanning file {file_path}: {e}")
        return False

def scan_directory(dir_path, recursive=True):
    """Scan all files in a directory"""
    try:
        print(f"📂 Scanning directory: {dir_path}")
        
        if not os.path.exists(dir_path):
            print(f"❌ Directory not found: {dir_path}")
            return False
        
        files_scanned = 0
        threats_found = 0
        suspicious_files = 0
        
        if recursive:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if scan_file(file_path):
                        files_scanned += 1
                    else:
                        threats_found += 1
                        files_scanned += 1
        else:
            for item in os.listdir(dir_path):
                item_path = os.path.join(dir_path, item)
                if os.path.isfile(item_path):
                    if scan_file(item_path):
                        files_scanned += 1
                    else:
                        threats_found += 1
                        files_scanned += 1
        
        print(f"\n📊 Scan Summary:")
        print(f"   Files scanned: {files_scanned}")
        print(f"   Threats detected: {threats_found}")
        print(f"   Suspicious files: {suspicious_files}")
        
        return threats_found == 0
        
    except Exception as e:
        print(f"❌ Error scanning directory {dir_path}: {e}")
        return False

def real_time_protection():
    """Start real-time protection"""
    try:
        print("🛡️  Starting real-time protection...")
        print("Press Ctrl+C to stop")
        
        from core.realtime import RealTimeProtection
        from core.scanner import FileScanner
        
        # Initialize components
        scanner = FileScanner()
        protection = RealTimeProtection(scanner)
        
        # Start monitoring
        protection.start_monitoring()
        
        # Keep running until interrupted
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping real-time protection...")
            return True
        
    except Exception as e:
        print(f"❌ Error starting real-time protection: {e}")
        return False

def update_signatures():
    """Update threat signatures"""
    try:
        print("🔄 Updating threat signatures...")
        
        from core.signature_updater import SignatureUpdater
        updater = SignatureUpdater("signatures.db")
        
        results = updater.update_all_feeds()
        
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)
        
        if success_count > 0:
            print(f"✅ Signature update completed successfully ({success_count}/{total_count} feeds updated)")
            return True
        elif total_count == 0:
            print("⚠️  No feeds configured for update")
            return True
        else:
            print(f"❌ Signature update failed ({success_count}/{total_count} feeds updated)")
            return False
            
    except Exception as e:
        print(f"❌ Error updating signatures: {e}")
        return False

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="AegisAI Antivirus - Advanced malware protection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aegisai.py --scan-file suspicious.exe        # Scan a single file
  aegisai.py --scan-dir /home/user/downloads   # Scan a directory
  aegisai.py --real-time                       # Start real-time protection
  aegisai.py --update                          # Update threat signatures
        """
    )
    
    parser.add_argument(
        '--scan-file',
        help='Scan a single file for threats',
        metavar='FILE'
    )
    
    parser.add_argument(
        '--scan-dir',
        help='Scan all files in a directory',
        metavar='DIRECTORY'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='Recursively scan subdirectories (used with --scan-dir)'
    )
    
    parser.add_argument(
        '--real-time',
        action='store_true',
        help='Start real-time protection'
    )
    
    parser.add_argument(
        '--update',
        action='store_true',
        help='Update threat signatures'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='AegisAI Antivirus 1.0'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Check if any action was specified
    if not any([args.scan_file, args.scan_dir, args.real_time, args.update]):
        parser.print_help()
        return 0
    
    # Execute requested actions
    success = True
    
    if args.update:
        success &= update_signatures()
    
    if args.scan_file:
        success &= scan_file(args.scan_file)
    
    if args.scan_dir:
        success &= scan_directory(args.scan_dir, args.recursive)
    
    if args.real_time:
        success &= real_time_protection()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())