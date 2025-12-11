#!/usr/bin/env python3
"""
AegisAI Hosts File Ad Blocker
============================

This module provides automatic ad blocking by modifying the system hosts file
to redirect ad domains to localhost. This approach works automatically
without requiring users to change DNS settings.
"""

import os
import sys
import logging
import platform
from datetime import datetime
import shutil

# Add core directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

# Try to import web protection module
try:
    from web_protection import WebProtectionEngine
    WEB_PROTECTION_AVAILABLE = True
except ImportError:
    WEB_PROTECTION_AVAILABLE = False
    WebProtectionEngine = None
    print("⚠️  Web protection module not available")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HostsBlocker:
    """Ad blocker that works by modifying the system hosts file"""
    
    def __init__(self):
        """Initialize the hosts file blocker"""
        if WEB_PROTECTION_AVAILABLE and WebProtectionEngine:
            self.web_protection = WebProtectionEngine()
        else:
            self.web_protection = None
        self.system = platform.system().lower()
        
        # Determine hosts file path based on OS
        if self.system == "windows":
            self.hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        else:
            self.hosts_path = "/etc/hosts"
            
        # Backup file path
        self.backup_path = self.hosts_path + ".aegisai.backup"
        
        logger.info(f"Hosts file path: {self.hosts_path}")
        
    def get_ad_domains(self):
        """
        Get list of ad domains to block from web protection engine
        
        Returns:
            List of ad domains to block
        """
        ad_domains = []
        
        # If web protection is available, get domains from it
        if self.web_protection:
            # Get blocked domains from web protection engine
            for rule in self.web_protection.filter_rules:
                if rule.category == "ads" and rule.action == "block":
                    ad_domains.append(rule.pattern)
        
        # Add some common ad domains that might not be in the rules
        common_ad_domains = [
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "googletagservices.com",
            "adservice.google.com",
            "facebook.com",  # For Facebook ads
            "ads.facebook.com",
            "creativecdn.com",
            "adnxs.com",
            "rubiconproject.com",
            "openx.net",
            "pubmatic.com",
            "taboola.com",
            "outbrain.com",
            "criteo.com",
            "ads.yahoo.com",
            "advertising.com",
            "quantserve.com",
            "scorecardresearch.com"
        ]
        
        # Combine and deduplicate
        all_domains = list(set(ad_domains + common_ad_domains))
        logger.info(f"Found {len(all_domains)} ad domains to block")
        return all_domains
    
    def backup_hosts_file(self):
        """Create a backup of the hosts file"""
        try:
            if os.path.exists(self.hosts_path):
                shutil.copy2(self.hosts_path, self.backup_path)
                logger.info(f"Backup created: {self.backup_path}")
                return True
            else:
                logger.warning(f"Hosts file not found: {self.hosts_path}")
                return False
        except Exception as e:
            logger.error(f"Failed to backup hosts file: {e}")
            return False
    
    def restore_hosts_file(self):
        """Restore the original hosts file from backup"""
        try:
            if os.path.exists(self.backup_path):
                shutil.copy2(self.backup_path, self.hosts_path)
                os.remove(self.backup_path)
                logger.info("Hosts file restored from backup")
                return True
            else:
                logger.warning("No backup found to restore")
                return False
        except Exception as e:
            logger.error(f"Failed to restore hosts file: {e}")
            return False
    
    def block_ads_in_hosts(self):
        """
        Block ad domains by adding them to the hosts file
        
        Returns:
            Number of domains blocked
        """
        try:
            # Get ad domains to block
            ad_domains = self.get_ad_domains()
            
            if not ad_domains:
                logger.warning("No ad domains found to block")
                return 0
                
            # Create backup if it doesn't exist
            if not os.path.exists(self.backup_path):
                self.backup_hosts_file()
            
            # Read current hosts file
            hosts_content = []
            if os.path.exists(self.hosts_path):
                with open(self.hosts_path, 'r', encoding='utf-8') as f:
                    hosts_content = f.readlines()
            
            # Check if our section already exists
            aegisai_section_start = "# AegisAI Ad Blocker - Start\n"
            aegisai_section_end = "# AegisAI Ad Blocker - End\n"
            
            # Remove existing AegisAI section if it exists
            new_content = []
            in_aegisai_section = False
            
            for line in hosts_content:
                if line == aegisai_section_start:
                    in_aegisai_section = True
                    continue
                elif line == aegisai_section_end:
                    in_aegisai_section = False
                    continue
                elif not in_aegisai_section:
                    new_content.append(line)
            
            # Add new AegisAI section with blocked domains
            new_content.append("\n" + aegisai_section_start)
            new_content.append(f"# Added by AegisAI on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            blocked_count = 0
            for domain in ad_domains:
                # Skip if domain is already blocked
                already_blocked = False
                for line in new_content:
                    if f"127.0.0.1 {domain}" in line or f"0.0.0.0 {domain}" in line:
                        already_blocked = True
                        break
                        
                if not already_blocked:
                    new_content.append(f"127.0.0.1 {domain}\n")
                    blocked_count += 1
                    
            new_content.append(aegisai_section_end)
            
            # Write updated hosts file
            with open(self.hosts_path, 'w', encoding='utf-8') as f:
                f.writelines(new_content)
            
            logger.info(f"Successfully blocked {blocked_count} ad domains")
            return blocked_count
            
        except Exception as e:
            logger.error(f"Failed to block ads in hosts file: {e}")
            return 0
    
    def unblock_ads_in_hosts(self):
        """
        Remove AegisAI ad blocking entries from hosts file
        
        Returns:
            Number of domains unblocked
        """
        try:
            # Read current hosts file
            if not os.path.exists(self.hosts_path):
                logger.warning("Hosts file not found")
                return 0
                
            with open(self.hosts_path, 'r', encoding='utf-8') as f:
                hosts_content = f.readlines()
            
            # Remove AegisAI section
            new_content = []
            in_aegisai_section = False
            unblocked_count = 0
            
            for line in hosts_content:
                if line.strip() == "# AegisAI Ad Blocker - Start":
                    in_aegisai_section = True
                    continue
                elif line.strip() == "# AegisAI Ad Blocker - End":
                    in_aegisai_section = False
                    unblocked_count += 1
                    continue
                elif not in_aegisai_section:
                    new_content.append(line)
            
            # Write updated hosts file
            with open(self.hosts_path, 'w', encoding='utf-8') as f:
                f.writelines(new_content)
            
            # Remove backup if it exists
            if os.path.exists(self.backup_path):
                os.remove(self.backup_path)
            
            logger.info(f"Successfully unblocked {unblocked_count} entries")
            return unblocked_count
            
        except Exception as e:
            logger.error(f"Failed to unblock ads in hosts file: {e}")
            return 0

def main():
    """Main function to demonstrate hosts file blocking"""
    print("🛡️  AegisAI Hosts File Ad Blocker")
    print("=" * 40)
    
    # Check if running on Windows
    if platform.system().lower() != "windows":
        print("❌ This tool is designed for Windows systems")
        return
    
    # Check if running as administrator
    try:
        with open(r"C:\Windows\System32\drivers\etc\hosts", 'a') as f:
            pass
    except PermissionError:
        print("❌ This tool requires administrator privileges to modify the hosts file")
        print("Please run as administrator")
        return
    except Exception:
        pass  # File might not exist, that's okay
    
    # Create blocker instance
    blocker = HostsBlocker()
    
    print("1. Block ads in hosts file")
    print("2. Unblock ads in hosts file")
    print("3. Restore original hosts file")
    
    choice = input("Enter your choice (1-3): ").strip()
    
    if choice == "1":
        count = blocker.block_ads_in_hosts()
        if count > 0:
            print(f"✅ Successfully blocked {count} ad domains")
            print("🔄 You may need to flush DNS cache for changes to take effect:")
            print("   Run 'ipconfig /flushdns' in Command Prompt")
        else:
            print("⚠️  No ad domains were blocked")
            
    elif choice == "2":
        count = blocker.unblock_ads_in_hosts()
        if count > 0:
            print(f"✅ Successfully unblocked {count} entries")
        else:
            print("⚠️  No entries were unblocked")
            
    elif choice == "3":
        if blocker.restore_hosts_file():
            print("✅ Hosts file restored from backup")
        else:
            print("⚠️  Failed to restore hosts file")
            
    else:
        print("❌ Invalid choice")

if __name__ == "__main__":
    main()