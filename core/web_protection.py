#!/usr/bin/env python3
"""
AegisAI Web Protection Module
============================

This module provides web protection features including:
- Ad blocking
- Malicious website blocking
- DNS filtering
- Content filtering
"""

import os
import json
import logging
import re
import ipaddress
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class WebFilterRule:
    """Represents a web filtering rule"""
    pattern: str
    rule_type: str  # domain, url, ip, content
    action: str  # block, allow, redirect
    category: str  # ads, malware, tracking, social, etc.
    priority: int = 0
    enabled: bool = True
    description: str = ""
    created_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class WebProtectionEngine:
    """Main web protection engine"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize web protection engine"""
        self.config = self._load_config(config_path)
        self.filter_rules = []
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.blocked_urls = set()
        self.allowed_domains = set()
        self.stats = {
            'blocked_requests': 0,
            'allowed_requests': 0,
            'blocked_ads': 0,
            'blocked_malware': 0,
            'blocked_tracking': 0,
            'blocked_social': 0
        }
        
        # Load default filter lists
        self._load_default_filters()
        
        logger.info("Web protection engine initialized")
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load configuration from file or use defaults"""
        default_config = {
            "web_protection": {
                "enabled": True,
                "ad_blocking": True,
                "malware_blocking": True,
                "tracking_protection": True,
                "social_media_blocking": False,
                "custom_rules_file": "web_protection_rules.json",
                "update_interval": 86400,  # 24 hours
                "blocked_page": "<html><body><h1>Access Blocked</h1><p>This site has been blocked by AegisAI Web Protection.</p></body></html>"
            }
        }
        
        if not config_path:
            config_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'web_protection_config.json')
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
            except Exception as e:
                logger.error(f"Error loading web protection config: {e}")
        
        return default_config
    
    def _load_default_filters(self):
        """Load default filter lists for ad blocking and malware protection"""
        # Add common ad domains
        ad_domains = [
            "doubleclick.net",
            "googleadservices.com",
            "googlesyndication.com",
            "googletagservices.com",
            "adservice.google.com",
            "facebook.com",  # For Facebook ads
            "facebook.net",
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
            "scorecardresearch.com",
            "zedo.com",
            "adtechus.com",
            "contextweb.com",
            "yieldmanager.com",
            "revsci.net",
            "demdex.net",
            "crwdcntrl.net",
            "adsrvr.org",
            "serving-sys.com",
            "mathtag.com",
            "bidswitch.net",
            "casalemedia.com",
            "adform.net",
            "smartadserver.com",
            "flashtalking.com",
            "sonobi.com",
            "tribalfusion.com",
            "atdmt.com",
            "fwmrm.net",
            "teads.tv",
            "spotxchange.com",
            "stickyadstv.com",
            "freewheel.tv",
            "adblade.com",
            "buysellads.com",
            "carbonads.com",
            "infolinks.com",
            "kontera.com",
            "chitika.com",
            "propellerads.com",
            "exoclick.com",
            "popads.net",
            "trafficjunky.net",
            "trafficfactory.biz",
            "clickadu.com",
            "juicyads.com",
            "adultfriendfinder.com",
            "cams.com",
            "livejasmin.com"
        ]
        
        # Add common tracking domains
        tracking_domains = [
            "google-analytics.com",
            "analytics.google.com",
            "facebook.com",  # For Facebook tracking
            "facebook.net",
            "connect.facebook.net",
            "pixel.facebook.com",
            "doubleclick.net",
            "googletagmanager.com",
            "hotjar.com",
            "newrelic.com",
            "mixpanel.com",
            "segment.com",
            "fullstory.com",
            "heap.io",
            "inspectlet.com",
            "crazyegg.com",
            "mouseflow.com",
            "clicky.com",
            "statcounter.com",
            "quantcast.com",
            "comscore.com",
            "nielsen.com",
            "adobedtm.com",
            "omtrdc.net",
            "2o7.net",
            "webtrends.com",
            "atinternet.com",
            "matomo.org",
            "piwik.org"
        ]
        
        # Add common malware domains
        malware_domains = [
            "malware-domain-list.com",
            "malwaredomains.com",
            "vxvault.net",
            "malware-traffic-analysis.net",
            "cybercrime-tracker.net",
            "feodotracker.abuse.ch",
            "zeustracker.abuse.ch",
            "ransomwaretracker.abuse.ch",
            "palevotracker.abuse.ch",
            "spyeyetracker.abuse.ch"
        ]
        
        # Add social media domains (optional blocking)
        social_domains = [
            "facebook.com",
            "fb.com",
            "instagram.com",
            "twitter.com",
            "x.com",
            "linkedin.com",
            "snapchat.com",
            "tiktok.com",
            "tiktokcdn.com",
            "reddit.com",
            "pinterest.com",
            "tumblr.com",
            "whatsapp.com",
            "telegram.org",
            "discord.com",
            "discordapp.com",
            "slack.com",
            "zoom.us",
            "skype.com",
            "teams.microsoft.com",
            "microsoft.com",  # Teams is part of Microsoft
            "google.com",     # For Google services including YouTube
            "youtube.com",
            "twitch.tv",
            "vimeo.com",
            "dailymotion.com"
        ]
        
        # Add rules for each category
        for domain in ad_domains:
            self.add_filter_rule(domain, "domain", "block", "ads", description=f"Block ad domain: {domain}")
        
        for domain in tracking_domains:
            self.add_filter_rule(domain, "domain", "block", "tracking", description=f"Block tracking domain: {domain}")
        
        for domain in malware_domains:
            self.add_filter_rule(domain, "domain", "block", "malware", description=f"Block malware domain: {domain}")
            
        for domain in social_domains:
            self.add_filter_rule(domain, "domain", "block", "social", description=f"Block social media domain: {domain}")
        
        logger.info(f"Loaded default filters: {len(ad_domains)} ads, {len(tracking_domains)} tracking, {len(malware_domains)} malware, {len(social_domains)} social")
    
    def add_filter_rule(self, pattern: str, rule_type: str, action: str, category: str, 
                       priority: int = 0, enabled: bool = True, description: str = ""):
        """
        Add a filter rule
        
        Args:
            pattern: Pattern to match (domain, URL, IP, or content pattern)
            rule_type: Type of rule (domain, url, ip, content)
            action: Action to take (block, allow, redirect)
            category: Category of rule (ads, malware, tracking, etc.)
            priority: Priority level (higher numbers = higher priority)
            enabled: Whether rule is enabled
            description: Description of the rule
        """
        rule = WebFilterRule(
            pattern=pattern,
            rule_type=rule_type,
            action=action,
            category=category,
            priority=priority,
            enabled=enabled,
            description=description
        )
        
        self.filter_rules.append(rule)
        
        # Add to appropriate sets for fast lookup
        if rule_type == "domain" and action == "block":
            if category == "ads":
                self.blocked_domains.add(pattern)
            elif category == "malware":
                self.blocked_domains.add(pattern)
            elif category == "tracking":
                self.blocked_domains.add(pattern)
            elif category == "social":
                self.blocked_domains.add(pattern)
        
        logger.info(f"Added filter rule: {pattern} ({category})")
    
    def remove_filter_rule(self, pattern: str, rule_type: str):
        """
        Remove a filter rule
        
        Args:
            pattern: Pattern to remove
            rule_type: Type of rule to remove
        """
        self.filter_rules = [rule for rule in self.filter_rules 
                           if not (rule.pattern == pattern and rule.rule_type == rule_type)]
        
        # Remove from sets
        if rule_type == "domain":
            self.blocked_domains.discard(pattern)
        
        logger.info(f"Removed filter rule: {pattern}")
    
    def check_domain(self, domain: str) -> Tuple[bool, str, Optional[WebFilterRule]]:
        """
        Check if a domain should be blocked
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (should_block, reason, rule)
        """
        if not self.config.get("web_protection", {}).get("enabled", True):
            return False, "Web protection disabled", None
        
        # Check if domain is explicitly allowed
        if domain in self.allowed_domains:
            self.stats['allowed_requests'] += 1
            return False, "Domain explicitly allowed", None
        
        # Check if domain is blocked
        if domain in self.blocked_domains:
            self.stats['blocked_requests'] += 1
            # Determine category for stats
            for rule in self.filter_rules:
                if rule.pattern == domain and rule.rule_type == "domain" and rule.action == "block":
                    if rule.category == "ads":
                        self.stats['blocked_ads'] += 1
                        return True, "Ad domain blocked", rule
                    elif rule.category == "malware":
                        self.stats['blocked_malware'] += 1
                        return True, "Malware domain blocked", rule
                    elif rule.category == "tracking":
                        self.stats['blocked_tracking'] += 1
                        return True, "Tracking domain blocked", rule
                    elif rule.category == "social":
                        self.stats['blocked_social'] += 1
                        return True, "Social media domain blocked", rule
            return True, "Domain blocked", None
        
        # Check for subdomain matches
        parts = domain.split('.')
        for i in range(len(parts)):
            subdomain = '.'.join(parts[i:])
            if subdomain in self.blocked_domains:
                self.stats['blocked_requests'] += 1
                # Determine category for stats
                for rule in self.filter_rules:
                    if rule.pattern == subdomain and rule.rule_type == "domain" and rule.action == "block":
                        if rule.category == "ads":
                            self.stats['blocked_ads'] += 1
                            return True, f"Ad subdomain blocked: {subdomain}", rule
                        elif rule.category == "malware":
                            self.stats['blocked_malware'] += 1
                            return True, f"Malware subdomain blocked: {subdomain}", rule
                        elif rule.category == "tracking":
                            self.stats['blocked_tracking'] += 1
                            return True, f"Tracking subdomain blocked: {subdomain}", rule
                        elif rule.category == "social":
                            self.stats['blocked_social'] += 1
                            return True, f"Social media subdomain blocked: {subdomain}", rule
                return True, f"Subdomain blocked: {subdomain}", None
        
        # Domain is not blocked
        self.stats['allowed_requests'] += 1
        return False, "Domain allowed", None
    
    def check_ip(self, ip_address: str) -> Tuple[bool, str, Optional[WebFilterRule]]:
        """
        Check if an IP address should be blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Tuple of (should_block, reason, rule)
        """
        if not self.config.get("web_protection", {}).get("enabled", True):
            return False, "Web protection disabled", None
        
        if ip_address in self.blocked_ips:
            self.stats['blocked_requests'] += 1
            self.stats['blocked_malware'] += 1
            return True, "IP blocked", None
        
        # Check if IP is in blocked ranges
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            for rule in self.filter_rules:
                if rule.rule_type == "ip" and rule.action == "block" and rule.enabled:
                    # Check if it's a CIDR block
                    if '/' in rule.pattern:
                        if ipaddress.ip_address(ip_address) in ipaddress.ip_network(rule.pattern, strict=False):
                            self.stats['blocked_requests'] += 1
                            self.stats['blocked_malware'] += 1
                            return True, f"IP in blocked range: {rule.pattern}", rule
                    # Check exact match
                    elif rule.pattern == ip_address:
                        self.stats['blocked_requests'] += 1
                        self.stats['blocked_malware'] += 1
                        return True, f"IP blocked: {ip_address}", rule
        except ValueError:
            pass  # Invalid IP address
        
        self.stats['allowed_requests'] += 1
        return False, "IP allowed", None
    
    def check_url(self, url: str) -> Tuple[bool, str, Optional[WebFilterRule]]:
        """
        Check if a URL should be blocked
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (should_block, reason, rule)
        """
        if not self.config.get("web_protection", {}).get("enabled", True):
            return False, "Web protection disabled", None
        
        # Check exact URL matches
        if url in self.blocked_urls:
            self.stats['blocked_requests'] += 1
            return True, "URL blocked", None
        
        # Check URL patterns
        for rule in self.filter_rules:
            if rule.rule_type == "url" and rule.action == "block" and rule.enabled:
                if rule.pattern in url:
                    self.stats['blocked_requests'] += 1
                    return True, f"URL pattern blocked: {rule.pattern}", rule
        
        self.stats['allowed_requests'] += 1
        return False, "URL allowed", None
    
    def check_content(self, content: str) -> Tuple[bool, str, Optional[WebFilterRule]]:
        """
        Check if content should be blocked (for ad injection detection)
        
        Args:
            content: Content to check
            
        Returns:
            Tuple of (should_block, reason, rule)
        """
        if not self.config.get("web_protection", {}).get("enabled", True):
            return False, "Web protection disabled", None
        
        # Check content patterns
        for rule in self.filter_rules:
            if rule.rule_type == "content" and rule.action == "block" and rule.enabled:
                if re.search(rule.pattern, content, re.IGNORECASE):
                    self.stats['blocked_requests'] += 1
                    if rule.category == "ads":
                        self.stats['blocked_ads'] += 1
                    elif rule.category == "malware":
                        self.stats['blocked_malware'] += 1
                    elif rule.category == "tracking":
                        self.stats['blocked_tracking'] += 1
                    elif rule.category == "social":
                        self.stats['blocked_social'] += 1
                    return True, f"Content pattern blocked: {rule.pattern}", rule
        
        return False, "Content allowed", None
    
    def get_blocked_page(self) -> str:
        """Get the HTML page to show when a request is blocked"""
        return self.config.get("web_protection", {}).get("blocked_page", 
            "<html><body><h1>Access Blocked</h1><p>This site has been blocked by AegisAI Web Protection.</p></body></html>")
    
    def get_statistics(self) -> Dict:
        """
        Get web protection statistics
        
        Returns:
            Dictionary with statistics
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "stats": self.stats.copy(),
            "total_rules": len(self.filter_rules),
            "blocked_domains_count": len(self.blocked_domains),
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_urls_count": len(self.blocked_urls)
        }
    
    def export_rules(self, format: str = "json") -> str:
        """
        Export filter rules in specified format
        
        Args:
            format: Export format (json, csv)
            
        Returns:
            Exported data as string
        """
        if format == "json":
            # Convert WebFilterRule objects to dictionaries
            export_data = []
            for rule in self.filter_rules:
                rule_dict = asdict(rule)
                # Convert datetime objects to strings
                if rule_dict["created_at"] is not None:
                    rule_dict["created_at"] = rule_dict["created_at"].isoformat()
                export_data.append(rule_dict)
            return json.dumps(export_data, indent=2)
        elif format == "csv":
            # Create CSV format
            csv_lines = ["pattern,rule_type,action,category,priority,enabled,description,created_at"]
            for rule in self.filter_rules:
                created_at_str = rule.created_at.isoformat() if rule.created_at else ""
                line = f"{rule.pattern},{rule.rule_type},{rule.action},{rule.category}," \
                       f"{rule.priority},{rule.enabled},\"{rule.description}\"," \
                       f"{created_at_str}"
                csv_lines.append(line)
            return "\n".join(csv_lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_rules(self, data: str, format: str = "json"):
        """
        Import filter rules from data
        
        Args:
            data: Data to import
            format: Data format (json, csv)
        """
        if format == "json":
            rules_data = json.loads(data)
            processed_rules = []
            for rule_data in rules_data:
                # Process the data before creating the rule
                processed_data = {
                    "pattern": rule_data["pattern"],
                    "rule_type": rule_data["rule_type"],
                    "action": rule_data["action"],
                    "category": rule_data["category"],
                    "priority": int(rule_data["priority"]),
                    "enabled": bool(rule_data["enabled"]),
                    "description": rule_data["description"]
                }
                # Convert string dates back to datetime objects
                if rule_data.get("created_at"):
                    processed_data["created_at"] = datetime.fromisoformat(rule_data["created_at"])
                processed_rules.append(WebFilterRule(**processed_data))
            
            # Add all rules
            for rule in processed_rules:
                self.filter_rules.append(rule)
                
                # Add to appropriate sets for fast lookup
                if rule.rule_type == "domain" and rule.action == "block":
                    self.blocked_domains.add(rule.pattern)
                elif rule.rule_type == "ip" and rule.action == "block":
                    self.blocked_ips.add(rule.pattern)
                elif rule.rule_type == "url" and rule.action == "block":
                    self.blocked_urls.add(rule.pattern)
        elif format == "csv":
            lines = data.strip().split('\n')
            headers = lines[0].split(',')
            processed_rules = []
            for line in lines[1:]:
                values = line.split(',')
                if len(values) == len(headers):
                    # Process the data before creating the rule
                    processed_data = {
                        "pattern": values[0],
                        "rule_type": values[1],
                        "action": values[2],
                        "category": values[3],
                        "priority": int(values[4]) if values[4].isdigit() else 0,
                        "enabled": values[5].lower() == "true" if values[5] else True,
                        "description": values[6]
                    }
                    # Convert date string to datetime object
                    if values[7]:
                        try:
                            processed_data["created_at"] = datetime.fromisoformat(values[7])
                        except ValueError:
                            processed_data["created_at"] = None
                    processed_rules.append(WebFilterRule(**processed_data))
            
            # Add all rules
            for rule in processed_rules:
                self.filter_rules.append(rule)
                
                # Add to appropriate sets for fast lookup
                if rule.rule_type == "domain" and rule.action == "block":
                    self.blocked_domains.add(rule.pattern)
                elif rule.rule_type == "ip" and rule.action == "block":
                    self.blocked_ips.add(rule.pattern)
                elif rule.rule_type == "url" and rule.action == "block":
                    self.blocked_urls.add(rule.pattern)
        else:
            raise ValueError(f"Unsupported import format: {format}")
        
        logger.info(f"Imported {len(self.filter_rules)} filter rules")

# Global web protection instance
web_protection_engine = WebProtectionEngine()

# Example usage
if __name__ == "__main__":
    # Test the web protection engine
    engine = WebProtectionEngine()
    
    # Test domain blocking
    should_block, reason, rule = engine.check_domain("doubleclick.net")
    print(f"Should block doubleclick.net: {should_block} ({reason})")
    
    # Test IP blocking
    should_block, reason, rule = engine.check_ip("192.168.1.100")
    print(f"Should block 192.168.1.100: {should_block} ({reason})")
    
    # Test URL blocking
    should_block, reason, rule = engine.check_url("http://example.com/malware.exe")
    print(f"Should block URL: {should_block} ({reason})")
    
    # Test content filtering
    should_block, reason, rule = engine.check_content("This is a test with some ad content")
    print(f"Should block content: {should_block} ({reason})")
    
    # Get statistics
    stats = engine.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    # Export rules
    exported = engine.export_rules("json")
    print(f"Exported rules: {exported[:200]}...")