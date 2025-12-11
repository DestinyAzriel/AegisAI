"""
AegisAI Threat Intelligence Service
=================================

Service for integrating with external threat intelligence feeds and 
managing signature databases.
"""

import requests
import json
import hashlib
import time
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
import asyncio
import aiohttp
from dataclasses import dataclass

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelEntry:
    """Represents a threat intelligence entry"""
    indicator: str
    indicator_type: str  # hash, domain, ip, url
    threat_name: str
    severity: str
    source: str
    first_seen: datetime
    last_seen: datetime
    confidence: float

class ThreatIntelService:
    """Service for managing threat intelligence from multiple sources"""
    
    def __init__(self, db_path: str = "threat_intel.db"):
        """
        Initialize the threat intelligence service
        
        Args:
            db_path: Path to the threat intelligence database
        """
        self.db_path = db_path
        self.threat_feeds = {}
        self.threat_database = {}  # In-memory cache
        self.last_update = {}
        
        # Initialize threat feeds
        self._initialize_threat_feeds()
    
    def _initialize_threat_feeds(self):
        """Initialize known threat intelligence feeds"""
        self.threat_feeds = {
            "abuse_ch_malware": {
                "url": "https://bazaar.abuse.ch/export/json/recent/",
                "type": "hash",
                "format": "json",
                "update_interval": 3600  # 1 hour
            },
            "abuse_ch_urlhaus": {
                "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
                "type": "url",
                "format": "csv",
                "update_interval": 3600  # 1 hour
            },
            "malware_bazaar": {
                "url": "https://mb-api.abuse.ch/api/v1/",
                "type": "hash",
                "format": "json",
                "update_interval": 1800  # 30 minutes
            }
        }
    
    async def update_threat_feeds(self):
        """Update all threat intelligence feeds"""
        logger.info("Updating threat intelligence feeds...")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for feed_name, feed_info in self.threat_feeds.items():
                # Check if it's time to update this feed
                last_update = self.last_update.get(feed_name, datetime.min)
                if datetime.now() - last_update > timedelta(seconds=feed_info["update_interval"]):
                    tasks.append(self._update_feed(session, feed_name, feed_info))
            
            if tasks:
                await asyncio.gather(*tasks)
                logger.info(f"Updated {len(tasks)} threat feeds")
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
            
            if feed_name == "malware_bazaar":
                # Special handling for MalwareBazaar API
                payload = {"query": "get_recent", "selector": "time"}
                async with session.post(feed_info["url"], data=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._process_malware_bazaar_data(data, feed_name)
            else:
                # Standard GET request
                async with session.get(feed_info["url"]) as response:
                    if response.status == 200:
                        if feed_info["format"] == "json":
                            data = await response.json()
                            self._process_json_data(data, feed_name, feed_info)
                        elif feed_info["format"] == "csv":
                            text = await response.text()
                            self._process_csv_data(text, feed_name, feed_info)
            
            self.last_update[feed_name] = datetime.now()
            logger.info(f"Successfully updated threat feed: {feed_name}")
            
        except Exception as e:
            logger.error(f"Failed to update threat feed {feed_name}: {e}")
    
    def _process_malware_bazaar_data(self, data: Dict, feed_name: str):
        """
        Process MalwareBazaar API response
        
        Args:
            data: JSON response from MalwareBazaar
            feed_name: Name of the feed
        """
        if data.get("query_status") != "ok":
            logger.warning(f"MalwareBazaar query failed: {data.get('query_status')}")
            return
        
        samples = data.get("data", [])
        for sample in samples:
            sha256_hash = sample.get("sha256_hash")
            if sha256_hash:
                threat_entry = ThreatIntelEntry(
                    indicator=sha256_hash,
                    indicator_type="hash",
                    threat_name=sample.get("signature", "Unknown"),
                    severity="high",
                    source=feed_name,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    confidence=0.9
                )
                self.threat_database[sha256_hash] = threat_entry
    
    def _process_json_data(self, data: Dict, feed_name: str, feed_info: Dict):
        """
        Process JSON threat intelligence data
        
        Args:
            data: JSON data
            feed_name: Name of the feed
            feed_info: Feed configuration
        """
        # This is a generic processor - specific feeds may need custom handling
        logger.info(f"Processing JSON data from {feed_name}")
        # Implementation would depend on the specific feed format
    
    def _process_csv_data(self, text: str, feed_name: str, feed_info: Dict):
        """
        Process CSV threat intelligence data
        
        Args:
            text: CSV text data
            feed_name: Name of the feed
            feed_info: Feed configuration
        """
        lines = text.strip().split('\n')
        # Skip header lines that start with #
        data_lines = [line for line in lines if not line.startswith('#')]
        
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
                                confidence=0.8
                            )
                            # Store with a key that includes the type to avoid conflicts
                            key = f"url_{url}"
                            self.threat_database[key] = threat_entry
                except Exception as e:
                    logger.warning(f"Failed to process CSV line: {e}")
    
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
            # For other types, we need to search
            key = f"{indicator_type}_{indicator}"
            return self.threat_database.get(key)
    
    def get_threat_statistics(self) -> Dict:
        """
        Get statistics about the threat intelligence database
        
        Returns:
            Dictionary with statistics
        """
        total_indicators = len(self.threat_database)
        hash_indicators = sum(1 for entry in self.threat_database.values() if entry.indicator_type == "hash")
        url_indicators = sum(1 for entry in self.threat_database.values() if entry.indicator_type == "url")
        
        # Count by source
        source_counts = {}
        for entry in self.threat_database.values():
            source_counts[entry.source] = source_counts.get(entry.source, 0) + 1
        
        return {
            "total_indicators": total_indicators,
            "hash_indicators": hash_indicators,
            "url_indicators": url_indicators,
            "sources": source_counts,
            "last_updates": {name: dt.isoformat() if isinstance(dt, datetime) else str(dt) 
                           for name, dt in self.last_update.items()}
        }
    
    def add_custom_indicator(self, indicator: str, indicator_type: str, threat_name: str, 
                           severity: str = "medium", confidence: float = 0.7):
        """
        Add a custom threat indicator
        
        Args:
            indicator: The indicator value
            indicator_type: Type of indicator (hash, ip, domain, url)
            threat_name: Name of the threat
            severity: Severity level (low, medium, high)
            confidence: Confidence level (0.0 - 1.0)
        """
        threat_entry = ThreatIntelEntry(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_name=threat_name,
            severity=severity,
            source="custom",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            confidence=confidence
        )
        
        if indicator_type == "hash":
            self.threat_database[indicator] = threat_entry
        else:
            key = f"{indicator_type}_{indicator}"
            self.threat_database[key] = threat_entry
        
        logger.info(f"Added custom threat indicator: {indicator} ({indicator_type})")

# Example usage
if __name__ == "__main__":
    # Initialize threat intelligence service
    intel_service = ThreatIntelService()
    
    # Add a custom indicator
    intel_service.add_custom_indicator(
        indicator="eicar_test_file_hash",
        indicator_type="hash",
        threat_name="EICAR Test File",
        severity="test",
        confidence=1.0
    )
    
    # Check an indicator
    result = intel_service.check_indicator("eicar_test_file_hash")
    if result:
        print(f"Threat found: {result.threat_name} ({result.severity})")
    else:
        print("No threat found")
    
    # Get statistics
    stats = intel_service.get_threat_statistics()
    print(f"Threat database statistics: {stats}")