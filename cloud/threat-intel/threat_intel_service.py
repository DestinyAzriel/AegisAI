#!/usr/bin/env python3
"""
AegisAI Enhanced Threat Intelligence Service
=========================================

Enhanced service for integrating with external threat intelligence feeds,
managing signature databases, and providing real-time threat intelligence
to endpoint agents.
"""

import requests
import json
import time
import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta
import asyncio
import aiohttp
from dataclasses import dataclass, asdict
import hashlib

# Enterprise ML imports for correlation engine
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
import numpy as np

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelEntry:
    """Represents a threat intelligence entry"""
    indicator: str
    indicator_type: str  # hash, domain, ip, url, email
    threat_name: str
    severity: str  # low, medium, high, critical
    source: str
    first_seen: datetime
    last_seen: datetime
    confidence: float  # 0.0 - 1.0
    tags: Optional[List[str]] = None
    description: str = ""
    related_indicators: Optional[List[str]] = None  # For correlation engine

class EnhancedThreatIntelService:
    """Enhanced service for managing threat intelligence from multiple sources"""
    
    def __init__(self, db_client=None):
        """
        Initialize the enhanced threat intelligence service
        
        Args:
            db_client: Database client for persistence (optional)
        """
        self.db_client = db_client
        self.threat_feeds = {}
        self.threat_database = {}  # In-memory cache
        self.last_update = {}
        self.feed_stats = {}
        
        # Initialize threat feeds
        self._initialize_threat_feeds()
        self._initialize_enterprise_feeds()
    
    def _initialize_threat_feeds(self):
        """Initialize known threat intelligence feeds"""
        self.threat_feeds = {
            "abuse_ch_malware": {
                "url": "https://bazaar.abuse.ch/export/json/recent/",
                "type": "hash",
                "format": "json",
                "update_interval": 3600,  # 1 hour
                "enabled": True,
                "tags": ["malware", "hash"]
            },
            "abuse_ch_urlhaus": {
                "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "type": "url",
                "format": "csv",
                "update_interval": 3600,  # 1 hour
                "enabled": True,
                "tags": ["url", "malware_distribution"]
            },
            "malware_bazaar": {
                "url": "https://mb-api.abuse.ch/api/v1/",
                "type": "hash",
                "format": "json",
                "update_interval": 1800,  # 30 minutes
                "enabled": True,
                "tags": ["malware", "hash"]
            },
            "virustotal_intelligence": {
                "url": "https://www.virustotal.com/api/v3/intelligence/hunting_notifications",
                "type": "hash",
                "format": "json",
                "update_interval": 7200,  # 2 hours
                "enabled": False,  # Requires API key
                "tags": ["malware", "vti"]
            },
            "alienvault_otx": {
                "url": "https://otx.alienvault.com/api/v1/indicators/export",
                "type": "mixed",
                "format": "json",
                "update_interval": 10800,  # 3 hours
                "enabled": False,  # Requires API key
                "tags": ["ioc", "threat_intel"]
            },
            "emerging_threats": {
                "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
                "type": "ip",
                "format": "text",
                "update_interval": 86400,  # 24 hours
                "enabled": True,
                "tags": ["ips", "compromised"]
            }
        }
    
    def _initialize_enterprise_feeds(self):
        """Initialize enterprise commercial threat intelligence feeds"""
        enterprise_feeds = {
            "recorded_future": {
                "url": "https://api.recordedfuture.com/v2/alerts",
                "type": "mixed",
                "format": "json",
                "update_interval": 300,  # 5 minutes (real-time)
                "enabled": False,  # Requires API key
                "tags": ["enterprise", "commercial", "real-time"],
                "risk_score_threshold": 60
            },
            "threat_connect": {
                "url": "https://app.threatconnect.com/api/v3/indicators",
                "type": "mixed",
                "format": "json",
                "update_interval": 900,  # 15 minutes
                "enabled": False,  # Requires API key
                "tags": ["enterprise", "commercial", "contextual"],
                "confidence_threshold": 0.7
            },
            "anomali": {
                "url": "https://api.threatstream.com/api/v2/intelligence",
                "type": "mixed",
                "format": "json",
                "update_interval": 1800,  # 30 minutes
                "enabled": False,  # Requires API key
                "tags": ["enterprise", "commercial", "comprehensive"],
                "severity_threshold": "medium"
            }
        }
        
        # Merge enterprise feeds with existing feeds
        self.threat_feeds.update(enterprise_feeds)
    
    async def update_threat_feeds(self, feed_names: Optional[List[str]] = None):
        """
        Update threat intelligence feeds
        
        Args:
            feed_names: List of specific feed names to update (None for all enabled feeds)
        """
        logger.info("Updating threat intelligence feeds...")
        
        # Determine which feeds to update
        feeds_to_update = []
        enterprise_feeds_to_update = []
        
        if feed_names:
            # Update only specified feeds
            for name, info in self.threat_feeds.items():
                if name in feed_names and info.get("enabled", True):
                    if name in ["recorded_future", "threat_connect", "anomali"]:
                        enterprise_feeds_to_update.append((name, info))
                    else:
                        feeds_to_update.append((name, info))
        else:
            # Update all enabled feeds
            for name, info in self.threat_feeds.items():
                if info.get("enabled", True):
                    if name in ["recorded_future", "threat_connect", "anomali"]:
                        enterprise_feeds_to_update.append((name, info))
                    else:
                        feeds_to_update.append((name, info))
        
        if not feeds_to_update and not enterprise_feeds_to_update:
            logger.info("No threat feeds to update")
            return
        
        async with aiohttp.ClientSession() as session:
            # Update standard feeds
            standard_tasks = []
            for feed_name, feed_info in feeds_to_update:
                # Check if it's time to update this feed
                last_update = self.last_update.get(feed_name, datetime.min)
                if datetime.now() - last_update > timedelta(seconds=feed_info["update_interval"]):
                    standard_tasks.append(self._update_feed(session, feed_name, feed_info))
            
            # Update enterprise feeds
            enterprise_tasks = []
            for feed_name, feed_info in enterprise_feeds_to_update:
                # Check if it's time to update this enterprise feed
                last_update = self.last_update.get(feed_name, datetime.min)
                if datetime.now() - last_update > timedelta(seconds=feed_info["update_interval"]):
                    enterprise_tasks.append(self._update_enterprise_feed(session, feed_name, feed_info))
            
            # Execute all tasks
            all_tasks = standard_tasks + enterprise_tasks
            if all_tasks:
                results = await asyncio.gather(*all_tasks, return_exceptions=True)
                successful_updates = sum(1 for result in results if not isinstance(result, Exception))
                failed_updates = len(all_tasks) - successful_updates
                
                logger.info(f"Updated {successful_updates}/{len(all_tasks)} threat feeds "
                           f"({failed_updates} failed)")
                
                # Update feed statistics
                self.feed_stats["last_update_run"] = datetime.now()
                self.feed_stats["feeds_updated"] = successful_updates
                self.feed_stats["feeds_failed"] = failed_updates
            else:
                logger.info("No threat feeds need updating")
    
    async def _update_feed(self, session: aiohttp.ClientSession, feed_name: str, feed_info: Dict):
        """
        Update a specific threat intelligence feed
        
        Args:
            session: aiohttp client session
            feed_name: Name of the feed
            feed_info: Feed configuration
        """
        try:
            logger.info(f"Updating threat feed: {feed_name}")
            
            start_time = time.time()
            
            if feed_name == "malware_bazaar":
                # Special handling for MalwareBazaar API
                payload = {"query": "get_recent", "selector": "time"}
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.post(feed_info["url"], data=payload, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        count = self._process_malware_bazaar_data(data, feed_name)
                    else:
                        raise Exception(f"HTTP {response.status}")
            elif feed_name == "virustotal_intelligence":
                # Handle VirusTotal API (would require API key in real implementation)
                logger.warning(f"VirusTotal feed requires API key: {feed_name}")
                return
            elif feed_name == "alienvault_otx":
                # Handle AlienVault OTX (would require API key in real implementation)
                logger.warning(f"AlienVault OTX feed requires API key: {feed_name}")
                return
            elif feed_name == "emerging_threats":
                # Handle text-based IP list
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.get(feed_info["url"], timeout=timeout) as response:
                    if response.status == 200:
                        text = await response.text()
                        count = self._process_text_data(text, feed_name, feed_info)
                    else:
                        raise Exception(f"HTTP {response.status}")
            else:
                # Standard GET request for JSON or CSV feeds
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.get(feed_info["url"], timeout=timeout) as response:
                    if response.status == 200:
                        if feed_info["format"] == "json":
                            data = await response.json()
                            count = self._process_json_data(data, feed_name, feed_info)
                        elif feed_info["format"] == "csv":
                            text = await response.text()
                            count = self._process_csv_data(text, feed_name, feed_info)
                        else:
                            raise Exception(f"Unsupported format: {feed_info['format']}")
                    else:
                        raise Exception(f"HTTP {response.status}")
            
            # Record update statistics
            update_time = time.time() - start_time
            self.last_update[feed_name] = datetime.now()
            
            logger.info(f"Successfully updated threat feed: {feed_name} "
                       f"({count} indicators, {update_time:.2f}s)")
            
            # Update feed stats
            if feed_name not in self.feed_stats:
                self.feed_stats[feed_name] = {
                    "total_updates": 0,
                    "total_indicators": 0,
                    "last_update_time": 0,
                    "average_update_time": 0
                }
            
            stats = self.feed_stats[feed_name]
            stats["total_updates"] += 1
            stats["total_indicators"] += count
            stats["last_update_time"] = update_time
            
            # Calculate running average
            if stats["total_updates"] > 1:
                total_time = stats["average_update_time"] * (stats["total_updates"] - 1) + update_time
                stats["average_update_time"] = total_time / stats["total_updates"]
            else:
                stats["average_update_time"] = update_time
            
        except Exception as e:
            logger.error(f"Failed to update threat feed {feed_name}: {e}")
            raise
    
    async def _update_enterprise_feed(self, session: aiohttp.ClientSession, feed_name: str, feed_info: Dict):
        """
        Update enterprise commercial threat intelligence feeds
        
        Args:
            session: aiohttp client session
            feed_name: Name of the enterprise feed
            feed_info: Enterprise feed configuration
        """
        try:
            logger.info(f"Updating enterprise threat feed: {feed_name}")
            
            start_time = time.time()
            count = 0
            
            # Handle enterprise feeds with API keys
            headers = {}
            if feed_name == "recorded_future":
                # Would require actual API key in real implementation
                headers["X-RFToken"] = "ENTERPRISE_API_KEY_PLACEHOLDER"
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.get(feed_info["url"], headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        count = self._process_recorded_future_data(data, feed_name, feed_info)
                    else:
                        raise Exception(f"HTTP {response.status}")
            elif feed_name == "threat_connect":
                # Would require actual API key in real implementation
                headers["Authorization"] = "Bearer ENTERPRISE_API_KEY_PLACEHOLDER"
                headers["Accept"] = "application/json"
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.get(feed_info["url"], headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        count = self._process_threat_connect_data(data, feed_name, feed_info)
                    else:
                        raise Exception(f"HTTP {response.status}")
            elif feed_name == "anomali":
                # Would require actual API key in real implementation
                headers["Authorization"] = "Basic ENTERPRISE_API_KEY_PLACEHOLDER"
                timeout = aiohttp.ClientTimeout(total=30)
                async with session.get(feed_info["url"], headers=headers, timeout=timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        count = self._process_anomali_data(data, feed_name, feed_info)
                    else:
                        raise Exception(f"HTTP {response.status}")
            else:
                logger.warning(f"Unknown enterprise feed: {feed_name}")
                return
            
            # Record update statistics
            update_time = time.time() - start_time
            self.last_update[feed_name] = datetime.now()
            
            logger.info(f"Successfully updated enterprise threat feed: {feed_name} "
                       f"({count} indicators, {update_time:.2f}s)")
            
            # Update feed stats
            if feed_name not in self.feed_stats:
                self.feed_stats[feed_name] = {
                    "total_updates": 0,
                    "total_indicators": 0,
                    "last_update_time": 0,
                    "average_update_time": 0
                }
            
            stats = self.feed_stats[feed_name]
            stats["total_updates"] += 1
            stats["total_indicators"] += count
            stats["last_update_time"] = update_time
            
            # Calculate running average
            if stats["total_updates"] > 1:
                total_time = stats["average_update_time"] * (stats["total_updates"] - 1) + update_time
                stats["average_update_time"] = total_time / stats["total_updates"]
            else:
                stats["average_update_time"] = update_time
                
        except Exception as e:
            logger.error(f"Failed to update enterprise threat feed {feed_name}: {e}")
            raise
    
    def _process_malware_bazaar_data(self, data: Dict, feed_name: str) -> int:
        """
        Process MalwareBazaar API response
        
        Args:
            data: JSON response from MalwareBazaar
            feed_name: Name of the feed
            
        Returns:
            Number of indicators processed
        """
        if data.get("query_status") != "ok":
            logger.warning(f"MalwareBazaar query failed: {data.get('query_status')}")
            return 0
        
        samples = data.get("data", [])
        count = 0
        
        for sample in samples:
            sha256_hash = sample.get("sha256_hash")
            if sha256_hash:
                threat_entry = ThreatIntelEntry(
                    indicator=sha256_hash,
                    indicator_type="hash",
                    threat_name=sample.get("signature", "Unknown Malware"),
                    severity="high",
                    source=feed_name,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    confidence=0.9,
                    tags=["malware", "hash"] + self.threat_feeds[feed_name].get("tags", []),
                    description=f"Malware sample with signature: {sample.get('signature', 'Unknown')}"
                )
                self.threat_database[sha256_hash] = threat_entry
                count += 1
        
        return count
    
    def _process_json_data(self, data: Dict, feed_name: str, feed_info: Dict) -> int:
        """
        Process JSON threat intelligence data
        
        Args:
            data: JSON data
            feed_name: Name of the feed
            feed_info: Feed configuration
            
        Returns:
            Number of indicators processed
        """
        # Generic JSON processor - would need customization for specific feeds
        count = 0
        logger.info(f"Processing JSON data from {feed_name}")
        
        # This is a placeholder - real implementation would depend on the specific feed format
        # For now, we'll just log that we received data
        if isinstance(data, list):
            count = len(data)
        elif isinstance(data, dict):
            # Try to find a list of indicators in common locations
            for key in ['indicators', 'data', 'entries', 'items']:
                if key in data and isinstance(data[key], list):
                    count = len(data[key])
                    break
        
        return count
    
    def _process_csv_data(self, text: str, feed_name: str, feed_info: Dict) -> int:
        """
        Process CSV threat intelligence data
        
        Args:
            text: CSV text data
            feed_name: Name of the feed
            feed_info: Feed configuration
            
        Returns:
            Number of indicators processed
        """
        lines = text.strip().split('\n')
        # Skip header lines that start with #
        data_lines = [line for line in lines if not line.startswith('#')]
        
        count = 0
        for line in data_lines[1:]:  # Skip header row
            if line.strip():
                try:
                    parts = line.split(',')
                    if len(parts) >= 3:
                        url = parts[2].strip()
                        if url and url != "url":
                            threat_entry = ThreatIntelEntry(
                                indicator=url,
                                indicator_type="url",
                                threat_name="Malicious URL",
                                severity="medium",
                                source=feed_name,
                                first_seen=datetime.now(),
                                last_seen=datetime.now(),
                                confidence=0.8,
                                tags=["url", "malware_distribution"] + self.threat_feeds[feed_name].get("tags", []),
                                description="Malicious URL from URLHaus"
                            )
                            # Store with a key that includes the type to avoid conflicts
                            key = f"url_{url}"
                            self.threat_database[key] = threat_entry
                            count += 1
                except Exception as e:
                    logger.warning(f"Failed to process CSV line from {feed_name}: {e}")
        
        return count
    
    def _process_text_data(self, text: str, feed_name: str, feed_info: Dict) -> int:
        """
        Process text-based threat intelligence data
        
        Args:
            text: Text data
            feed_name: Name of the feed
            feed_info: Feed configuration
            
        Returns:
            Number of indicators processed
        """
        lines = text.strip().split('\n')
        # Skip comment lines that start with #
        data_lines = [line for line in lines if not line.startswith('#') and line.strip()]
        
        count = 0
        for line in data_lines:
            line = line.strip()
            if line:
                try:
                    # Validate that it looks like an IP address
                    if self._is_valid_ip(line):
                        threat_entry = ThreatIntelEntry(
                            indicator=line,
                            indicator_type="ip",
                            threat_name="Compromised IP",
                            severity="medium",
                            source=feed_name,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            confidence=0.7,
                            tags=["ip", "compromised"] + self.threat_feeds[feed_name].get("tags", []),
                            description="Compromised IP address from Emerging Threats"
                        )
                        key = f"ip_{line}"
                        self.threat_database[key] = threat_entry
                        count += 1
                except Exception as e:
                    logger.warning(f"Failed to process text line from {feed_name}: {e}")
        
        return count
    
    def _process_recorded_future_data(self, data: Dict, feed_name: str, feed_info: Dict) -> int:
        """
        Process Recorded Future threat intelligence data
        
        Args:
            data: JSON data from Recorded Future API
            feed_name: Name of the feed
            feed_info: Feed configuration
            
        Returns:
            Number of indicators processed
        """
        count = 0
        try:
            # Process alerts from Recorded Future
            alerts = data.get("data", {}).get("results", [])
            risk_threshold = feed_info.get("risk_score_threshold", 60)
            
            for alert in alerts:
                # Extract risk score and filter by threshold
                risk_score = alert.get("risk", {}).get("score", 0)
                if risk_score < risk_threshold:
                    continue
                
                # Extract indicators from the alert
                indicators = alert.get("evidenceDetails", [])
                threat_name = alert.get("rule", "Recorded Future Alert")
                
                for indicator_data in indicators:
                    indicator_value = indicator_data.get("value")
                    indicator_type = indicator_data.get("type", "unknown").lower()
                    
                    if indicator_value and indicator_type in ["hash", "ip", "domain", "url"]:
                        # Map Recorded Future severity to our severity levels
                        if risk_score >= 90:
                            severity = "critical"
                            confidence = 0.95
                        elif risk_score >= 75:
                            severity = "high"
                            confidence = 0.85
                        elif risk_score >= 60:
                            severity = "medium"
                            confidence = 0.75
                        else:
                            severity = "low"
                            confidence = 0.6
                        
                        threat_entry = ThreatIntelEntry(
                            indicator=indicator_value,
                            indicator_type=indicator_type,
                            threat_name=threat_name,
                            severity=severity,
                            source=feed_name,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            confidence=confidence,
                            tags=["enterprise", "commercial", "recorded_future"] + feed_info.get("tags", []),
                            description=f"Recorded Future alert: {alert.get('title', 'Unknown threat')}"
                        )
                        
                        # Store in database with appropriate key
                        if indicator_type == "hash":
                            self.threat_database[indicator_value] = threat_entry
                        else:
                            key = f"{indicator_type}_{indicator_value}"
                            self.threat_database[key] = threat_entry
                        count += 1
                        
        except Exception as e:
            logger.error(f"Error processing Recorded Future data: {e}")
            
        return count
    
    def _process_threat_connect_data(self, data: Dict, feed_name: str, feed_info: Dict) -> int:
        """
        Process ThreatConnect threat intelligence data
        
        Args:
            data: JSON data from ThreatConnect API
            feed_name: Name of the feed
            feed_info: Feed configuration
            
        Returns:
            Number of indicators processed
        """
        count = 0
        try:
            # Process indicators from ThreatConnect
            indicators = data.get("data", [])
            confidence_threshold = feed_info.get("confidence_threshold", 0.7)
            
            for indicator in indicators:
                # Extract confidence and filter by threshold
                confidence = indicator.get("confidence", 0) / 100.0  # ThreatConnect uses 0-100 scale
                if confidence < confidence_threshold:
                    continue
                
                indicator_value = indicator.get("summary")
                indicator_type = indicator.get("type", "unknown").lower()
                
                if indicator_value and indicator_type in ["hash", "ip", "domain", "url", "emailaddress"]:
                    # Map ThreatConnect type to our types
                    type_mapping = {
                        "md5": "hash",
                        "sha1": "hash",
                        "sha256": "hash",
                        "address": "ip",
                        "emailaddress": "email"
                    }
                    mapped_type = type_mapping.get(indicator_type, indicator_type)
                    
                    # Map ThreatConnect rating to our severity levels
                    rating = indicator.get("rating", "None")
                    severity_mapping = {
                        "High": "high",
                        "Medium": "medium",
                        "Low": "low"
                    }
                    severity = severity_mapping.get(rating, "medium")
                    
                    threat_entry = ThreatIntelEntry(
                        indicator=indicator_value,
                        indicator_type=mapped_type,
                        threat_name=f"ThreatConnect Indicator - {rating}",
                        severity=severity,
                        source=feed_name,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        confidence=confidence,
                        tags=["enterprise", "commercial", "threat_connect"] + feed_info.get("tags", []),
                        description=f"ThreatConnect indicator with rating: {rating}"
                    )
                    
                    # Store in database with appropriate key
                    if mapped_type == "hash":
                        self.threat_database[indicator_value] = threat_entry
                    else:
                        key = f"{mapped_type}_{indicator_value}"
                        self.threat_database[key] = threat_entry
                    count += 1
                    
        except Exception as e:
            logger.error(f"Error processing ThreatConnect data: {e}")
            
        return count
    
    def _process_anomali_data(self, data: Dict, feed_name: str, feed_info: Dict) -> int:
        """
        Process Anomali threat intelligence data
        
        Args:
            data: JSON data from Anomali API
            feed_name: Name of the feed
            feed_info: Feed configuration
            
        Returns:
            Number of indicators processed
        """
        count = 0
        try:
            # Process intelligence from Anomali
            objects = data.get("objects", [])
            severity_threshold = feed_info.get("severity_threshold", "low")
            
            # Severity threshold mapping
            severity_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
            min_severity_level = severity_levels.get(severity_threshold, 1)
            
            for obj in objects:
                # Check if it's an indicator object
                if obj.get("type") == "indicator":
                    # Extract severity and filter by threshold
                    severity_label = obj.get("meta", {}).get("severity", "medium")
                    severity_level = severity_levels.get(severity_label, 2)
                    
                    if severity_level < min_severity_level:
                        continue
                    
                    indicator_value = obj.get("value")
                    indicator_type = obj.get("indicator_type", "unknown").lower()
                    
                    if indicator_value and indicator_type in ["hash", "ip", "domain", "url", "email"]:
                        # Map severity level to our severity levels
                        if severity_level >= 4:
                            severity = "critical"
                            confidence = 0.9
                        elif severity_level >= 3:
                            severity = "high"
                            confidence = 0.8
                        elif severity_level >= 2:
                            severity = "medium"
                            confidence = 0.7
                        else:
                            severity = "low"
                            confidence = 0.6
                        
                        threat_entry = ThreatIntelEntry(
                            indicator=indicator_value,
                            indicator_type=indicator_type,
                            threat_name=f"Anomali Threat - {severity_label.title()}",
                            severity=severity,
                            source=feed_name,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            confidence=confidence,
                            tags=["enterprise", "commercial", "anomali"] + feed_info.get("tags", []),
                            description=f"Anomali threat intelligence with severity: {severity_label}"
                        )
                        
                        # Store in database with appropriate key
                        if indicator_type == "hash":
                            self.threat_database[indicator_value] = threat_entry
                        else:
                            key = f"{indicator_type}_{indicator_value}"
                            self.threat_database[key] = threat_entry
                        count += 1
                        
        except Exception as e:
            logger.error(f"Error processing Anomali data: {e}")
            
        return count
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate if a string is a valid IP address
        
        Args:
            ip: String to validate
            
        Returns:
            True if valid IP, False otherwise
        """
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def check_indicator(self, indicator: str, indicator_type: str = "hash") -> Optional[ThreatIntelEntry]:
        """
        Check if an indicator is in the threat intelligence database
        
        Args:
            indicator: The indicator to check (hash, IP, domain, URL)
            indicator_type: Type of indicator
            
        Returns:
            ThreatIntelEntry if found, None otherwise
        """
        if indicator_type == "hash":
            return self.threat_database.get(indicator)
        else:
            # For other types, we need to search with prefix
            key = f"{indicator_type}_{indicator}"
            return self.threat_database.get(key)
    
    def search_indicators(self, query: str, indicator_types: Optional[List[str]] = None) -> List[ThreatIntelEntry]:
        """
        Search for indicators matching a query
        
        Args:
            query: Search query (substring match)
            indicator_types: List of indicator types to search (None for all)
            
        Returns:
            List of matching ThreatIntelEntry objects
        """
        results = []
        query_lower = query.lower()
        
        for entry in self.threat_database.values():
            # Filter by type if specified
            if indicator_types and entry.indicator_type not in indicator_types:
                continue
            
            # Match query against various fields
            if (query_lower in entry.indicator.lower() or
                query_lower in entry.threat_name.lower() or
                query_lower in entry.source.lower() or
                any(query_lower in tag.lower() for tag in (entry.tags or []))):
                results.append(entry)
        
        return results
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the threat intelligence database
        
        Returns:
            Dictionary with statistics
        """
        total_indicators = len(self.threat_database)
        type_counts = {}
        severity_counts = {}
        source_counts = {}
        
        for entry in self.threat_database.values():
            # Count by type
            type_counts[entry.indicator_type] = type_counts.get(entry.indicator_type, 0) + 1
            
            # Count by severity
            severity_counts[entry.severity] = severity_counts.get(entry.severity, 0) + 1
            
            # Count by source
            source_counts[entry.source] = source_counts.get(entry.source, 0) + 1
        
        return {
            "total_indicators": total_indicators,
            "indicators_by_type": type_counts,
            "indicators_by_severity": severity_counts,
            "indicators_by_source": source_counts,
            "last_updates": {name: dt.isoformat() if isinstance(dt, datetime) else str(dt) 
                           for name, dt in self.last_update.items()},
            "feed_statistics": self.feed_stats
        }
    
    def add_custom_indicator(self, indicator: str, indicator_type: str, threat_name: str, 
                           severity: str = "medium", confidence: float = 0.7,
                           tags: Optional[List[str]] = None, description: str = ""):
        """
        Add a custom threat indicator
        
        Args:
            indicator: The indicator value
            indicator_type: Type of indicator (hash, ip, domain, url, email)
            threat_name: Name of the threat
            severity: Severity level (low, medium, high, critical)
            confidence: Confidence level (0.0 - 1.0)
            tags: List of tags for categorization
            description: Description of the threat
        """
        threat_entry = ThreatIntelEntry(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_name=threat_name,
            severity=severity,
            source="custom",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            confidence=confidence,
            tags=tags or ["custom"],
            description=description
        )
        
        if indicator_type == "hash":
            self.threat_database[indicator] = threat_entry
        else:
            key = f"{indicator_type}_{indicator}"
            self.threat_database[key] = threat_entry
        
        logger.info(f"Added custom threat indicator: {indicator} ({indicator_type})")
    
    def bulk_add_indicators(self, indicators: List[Dict[str, Any]]):
        """
        Add multiple threat indicators at once
        
        Args:
            indicators: List of indicator dictionaries with required fields
        """
        for ind in indicators:
            try:
                self.add_custom_indicator(
                    indicator=ind["indicator"],
                    indicator_type=ind["indicator_type"],
                    threat_name=ind["threat_name"],
                    severity=ind.get("severity", "medium"),
                    confidence=ind.get("confidence", 0.7),
                    tags=ind.get("tags"),
                    description=ind.get("description", "")
                )
            except Exception as e:
                logger.error(f"Failed to add indicator {ind.get('indicator', 'unknown')}: {e}")
    
    def remove_indicator(self, indicator: str, indicator_type: str = "hash"):
        """
        Remove a threat indicator from the database
        
        Args:
            indicator: The indicator to remove
            indicator_type: Type of indicator
        """
        if indicator_type == "hash":
            if indicator in self.threat_database:
                del self.threat_database[indicator]
        else:
            key = f"{indicator_type}_{indicator}"
            if key in self.threat_database:
                del self.threat_database[key]
        
        logger.info(f"Removed threat indicator: {indicator} ({indicator_type})")
    
    def export_indicators(self, format: str = "json") -> str:
        """
        Export threat indicators in specified format
        
        Args:
            format: Export format (json, csv)
            
        Returns:
            Exported data as string
        """
        if format == "json":
            # Convert ThreatIntelEntry objects to dictionaries
            export_data = []
            for entry in self.threat_database.values():
                entry_dict = asdict(entry)
                # Convert datetime objects to strings
                entry_dict["first_seen"] = entry_dict["first_seen"].isoformat()
                entry_dict["last_seen"] = entry_dict["last_seen"].isoformat()
                export_data.append(entry_dict)
            return json.dumps(export_data, indent=2)
        elif format == "csv":
            # Create CSV format
            csv_lines = ["indicator,indicator_type,threat_name,severity,source,first_seen,last_seen,confidence,tags,description"]
            for entry in self.threat_database.values():
                tags_str = "|".join(entry.tags or [])
                line = f"{entry.indicator},{entry.indicator_type},{entry.threat_name},{entry.severity}," \
                       f"{entry.source},{entry.first_seen.isoformat()},{entry.last_seen.isoformat()}," \
                       f"{entry.confidence},\"{tags_str}\",\"{entry.description}\""
                csv_lines.append(line)
            return "\n".join(csv_lines)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def correlate_indicators(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """
        Correlate threat indicators to identify potential attack campaigns using ML clustering.
        
        Args:
            time_window_hours: Time window to consider for correlation (in hours)
            
        Returns:
            List of correlated threat campaigns
        """
        # Filter indicators within the time window
        cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
        recent_indicators = [
            entry for entry in self.threat_database.values()
            if entry.last_seen >= cutoff_time
        ]
        
        if len(recent_indicators) < 2:
            return []
        
        # Prepare data for correlation
        # Combine description, threat name, and tags for text analysis
        texts = []
        indicator_keys = []
        
        for entry in recent_indicators:
            # Create a rich text representation for correlation
            text_parts = [
                entry.threat_name,
                entry.description,
                " ".join(entry.tags or []),
                entry.indicator_type,
                entry.source
            ]
            combined_text = " ".join(text_parts)
            texts.append(combined_text)
            indicator_keys.append(
                entry.indicator if entry.indicator_type == "hash" 
                else f"{entry.indicator_type}_{entry.indicator}"
            )
        
        # Vectorize the text data using TF-IDF
        try:
            vectorizer = TfidfVectorizer(
                max_features=100,
                stop_words='english',
                ngram_range=(1, 2)
            )
            tfidf_matrix = vectorizer.fit_transform(texts)
            
            # Apply DBSCAN clustering
            # eps and min_samples are tuned for threat intelligence correlation
            clustering = DBSCAN(
                eps=0.5,
                min_samples=2,
                metric='cosine'
            )
            cluster_labels = clustering.fit_predict(tfidf_matrix)
            
            # Group indicators by cluster
            clusters = {}
            for i, label in enumerate(cluster_labels):
                if label != -1:  # Ignore noise points
                    if label not in clusters:
                        clusters[label] = []
                    clusters[label].append({
                        "indicator_key": indicator_keys[i],
                        "indicator_data": recent_indicators[i]
                    })
            
            # Create campaign reports
            campaigns = []
            for cluster_id, indicators in clusters.items():
                if len(indicators) >= 2:  # Only report clusters with multiple indicators
                    # Calculate cluster statistics
                    severities = [ind["indicator_data"].severity for ind in indicators]
                    sources = [ind["indicator_data"].source for ind in indicators]
                    types = [ind["indicator_data"].indicator_type for ind in indicators]
                    
                    # Determine predominant severity
                    severity_counts = {s: severities.count(s) for s in set(severities)}
                    predominant_severity = max(severity_counts, key=severity_counts.get)
                    
                    campaign = {
                        "campaign_id": f"campaign_{cluster_id}_{int(datetime.now().timestamp())}",
                        "indicators": [ind["indicator_key"] for ind in indicators],
                        "indicator_count": len(indicators),
                        "predominant_severity": predominant_severity,
                        "sources": list(set(sources)),
                        "indicator_types": list(set(types)),
                        "first_seen": min(ind["indicator_data"].first_seen for ind in indicators),
                        "last_seen": max(ind["indicator_data"].last_seen for ind in indicators),
                        "confidence": np.mean([ind["indicator_data"].confidence for ind in indicators])
                    }
                    campaigns.append(campaign)
            
            # Update related_indicators in the threat database
            for campaign in campaigns:
                for indicator_key in campaign["indicators"]:
                    if indicator_key in self.threat_database:
                        # Add other indicators in the same campaign as related
                        related = [key for key in campaign["indicators"] if key != indicator_key]
                        self.threat_database[indicator_key].related_indicators = related
            
            return campaigns
            
        except Exception as e:
            logger.error(f"Error during threat correlation: {e}")
            return []

# Example usage and testing
if __name__ == "__main__":
    # Initialize threat intelligence service
    intel_service = EnhancedThreatIntelService()
    
    # Add a custom indicator
    intel_service.add_custom_indicator(
        indicator="eicar_test_file_hash",
        indicator_type="hash",
        threat_name="EICAR Test File",
        severity="test",
        confidence=1.0,
        tags=["test", "antivirus"],
        description="Standard antivirus test file"
    )
    
    # Check an indicator
    result = intel_service.check_indicator("eicar_test_file_hash")
    if result:
        print(f"Threat found: {result.threat_name} ({result.severity})")
    else:
        print("No threat found")
    
    # Get statistics
    stats = intel_service.get_threat_statistics()
    print(f"Threat database statistics: {json.dumps(stats, indent=2, default=str)}")
    
    # Export data
    exported = intel_service.export_indicators("json")
    print(f"Exported data: {exported[:200]}...")  # Show first 200 chars