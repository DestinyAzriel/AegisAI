"""
AegisAI Static Analyzer
======================

This service performs static analysis on file samples, extracting features
and matching against YARA rules.
"""

import pefile
import yara
import hashlib
import json
from typing import Dict, List, Optional
import logging
import os
import sys

# Add the current directory to path to import threat_intel
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from threat_intel import ThreatIntelService
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    logging.warning("Threat intelligence service not available")
    THREAT_INTEL_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StaticAnalyzer:
    """Static analyzer for extracting file features"""
    
    def __init__(self, yara_rules_path: Optional[str] = None):
        """
        Initialize the static analyzer
        
        Args:
            yara_rules_path: Path to YARA rules file
        """
        self.yara_rules = None
        self.threat_intel_service = None
        
        if yara_rules_path:
            try:
                self.yara_rules = yara.compile(filepath=yara_rules_path)
                logger.info("YARA rules loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load YARA rules: {e}")
        
        # Initialize threat intelligence service
        if THREAT_INTEL_AVAILABLE:
            try:
                self.threat_intel_service = ThreatIntelService()
                logger.info("Threat intelligence service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize threat intelligence service: {e}")
    
    def calculate_hash(self, file_data: bytes) -> str:
        """
        Calculate SHA256 hash of file data
        
        Args:
            file_data: File content as bytes
            
        Returns:
            SHA256 hash as hex string
        """
        return hashlib.sha256(file_data).hexdigest()
    
    def extract_ember_features(self, file_data: bytes) -> Dict:
        """
        Extract EMBER-style features from file data
        This is a simplified implementation - a real implementation would
        extract many more features as defined in the EMBER paper.
        
        Args:
            file_data: File content as bytes
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # File size
        features['size'] = len(file_data)
        
        # Byte histogram (simplified)
        byte_hist = [0] * 256
        for byte in file_data[:10000]:  # Sample first 10KB
            byte_hist[byte] += 1
        features['byte_entropy'] = self._calculate_entropy(byte_hist)
        
        # Try to parse as PE file
        try:
            pe = pefile.PE(data=file_data)
            
            # Header information
            features['is_pe'] = True
            features['sections_count'] = len(pe.sections)
            
            # Section information
            sections_info = []
            for section in pe.sections:
                sections_info.append({
                    'name': section.Name.decode().strip('\x00'),
                    'virtual_size': section.Misc_VirtualSize,
                    'size_of_raw_data': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                })
            features['sections'] = sections_info
            
            # Import information
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                imports = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode() if entry.dll else ''
                    imports.append({
                        'dll': dll_name,
                        'functions': [imp.name.decode() if imp.name else '' 
                                    for imp in entry.imports]
                    })
                features['imports'] = imports
            
        except Exception as e:
            logger.debug(f"File is not a valid PE: {e}")
            features['is_pe'] = False
        
        return features
    
    def _calculate_entropy(self, histogram: List[int]) -> float:
        """
        Calculate entropy from byte histogram
        
        Args:
            histogram: Byte frequency histogram
            
        Returns:
            Entropy value
        """
        import math
        
        total = sum(histogram)
        if total == 0:
            return 0.0
            
        entropy = 0.0
        for count in histogram:
            if count > 0:
                probability = count / total
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def match_yara_rules(self, file_data: bytes) -> List[str]:
        """
        Match file data against YARA rules
        
        Args:
            file_data: File content as bytes
            
        Returns:
            List of matching rule names
        """
        if not self.yara_rules:
            return []
        
        try:
            matches = self.yara_rules.match(data=file_data)
            return [match.rule for match in matches]
        except Exception as e:
            logger.error(f"YARA matching failed: {e}")
            return []
    
    def analyze_file(self, file_data: bytes) -> Dict:
        """
        Perform complete static analysis on file
        
        Args:
            file_data: File content as bytes
            
        Returns:
            Dictionary containing all analysis results
        """
        file_hash = self.calculate_hash(file_data)
        
        results = {
            'file_hash': file_hash,
            'ember_features': self.extract_ember_features(file_data),
            'yara_matches': self.match_yara_rules(file_data),
            'threat_intel_matches': []
        }
        
        # Check threat intelligence
        if self.threat_intel_service:
            threat_entry = self.threat_intel_service.check_indicator(file_hash)
            if threat_entry:
                results['threat_intel_matches'].append({
                    'threat_name': threat_entry.threat_name,
                    'severity': threat_entry.severity,
                    'source': threat_entry.source,
                    'confidence': threat_entry.confidence
                })
        
        logger.info(f"Analysis complete for file {file_hash[:16]}...")
        logger.info(f"YARA matches: {results['yara_matches']}")
        logger.info(f"Threat intel matches: {len(results['threat_intel_matches'])}")
        
        return results

# Example usage
if __name__ == "__main__":
    # Initialize analyzer
    analyzer = StaticAnalyzer()
    
    # Example file analysis
    test_data = b"This is a test file for static analysis"
    results = analyzer.analyze_file(test_data)
    
    print("Static Analysis Results:")
    print(json.dumps(results, indent=2))