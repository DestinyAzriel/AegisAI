"""
YARA Rule Integration for AegisAI Core Engine
"""

import os
import logging
from typing import Dict, List, Optional

# Conditional import for YARA
YARA_AVAILABLE = False
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    yara = None
    logging.warning("YARA library not available. Install with: pip install yara-python")

logger = logging.getLogger(__name__)

class YaraScanner:
    """YARA rule-based scanning for AegisAI"""
    
    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA scanner.
        
        Args:
            rules_path: Path to YARA rules file or directory
        """
        self.rules = None
        self.rules_path = rules_path or "yara_rules"
        
        if YARA_AVAILABLE:
            self._load_rules()
        else:
            logger.warning("YARA scanning disabled - library not available")
    
    def _load_rules(self):
        """Load YARA rules from file or directory."""
        if not self.rules_path:
            logger.info("No YARA rules path specified")
            return
        
        # Check if YARA is available
        if not YARA_AVAILABLE:
            logger.warning("YARA not available, skipping rule loading")
            return
            
        try:
            if yara is not None:
                if os.path.isfile(self.rules_path):
                    self.rules = yara.compile(filepath=self.rules_path)
                    logger.info(f"Loaded YARA rules from {self.rules_path}")
                elif os.path.isdir(self.rules_path):
                    # Load all .yar and .yara files in directory
                    rules_dict = {}
                    for root, dirs, files in os.walk(self.rules_path):
                        for file in files:
                            if file.endswith(('.yar', '.yara')):
                                file_path = os.path.join(root, file)
                                rule_name = os.path.splitext(file)[0]
                                rules_dict[rule_name] = file_path
                    
                    if rules_dict:
                        self.rules = yara.compile(filepaths=rules_dict)
                        logger.info(f"Loaded {len(rules_dict)} YARA rule files from {self.rules_path}")
                    else:
                        logger.warning(f"No YARA rule files found in {self.rules_path}")
            else:
                logger.warning(f"YARA rules path does not exist: {self.rules_path}")
                
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.rules = None
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a file using YARA rules.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            List of matching rules
        """
        if not YARA_AVAILABLE or not self.rules or yara is None:
            return []
        
        try:
            matches = self.rules.match(file_path)
            results = []
            
            for match in matches:
                result = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags),
                    'meta': match.meta,
                    'strings': []
                }
                
                # Extract matching strings
                # Handle string matches (compatible with different YARA Python versions)
                matched_strings = []
                if hasattr(match, 'strings'):
                    for string in match.strings:
                        string_info = {
                            'identifier': getattr(string, 'identifier', ''),
                        }
                        # Safely access offset and data attributes
                        if hasattr(string, 'offset'):
                            string_info['offset'] = string.offset
                        if hasattr(string, 'data'):
                            string_info['data'] = string.data.decode('utf-8', errors='ignore')
                        matched_strings.append(string_info)
                result['strings'] = matched_strings
                
                results.append(result)
            
            if results:
                logger.info(f"YARA matches found in {file_path}: {[r['rule'] for r in results]}")
            
            return results
            
        except Exception as e:
            logger.error(f"YARA scan failed for {file_path}: {e}")
            return []
    
    def update_rules(self, new_rules_path: str) -> bool:
        """
        Update YARA rules.
        
        Args:
            new_rules_path: Path to new rules file or directory
            
        Returns:
            True if update successful, False otherwise
        """
        if not YARA_AVAILABLE:
            return False
        
        old_rules_path = self.rules_path
        self.rules_path = new_rules_path
        
        try:
            self._load_rules()
            logger.info("YARA rules updated successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to update YARA rules: {e}")
            # Revert to old rules
            self.rules_path = old_rules_path
            self._load_rules()
            return False