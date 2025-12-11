#!/usr/bin/env python3
"""
AegisAI ML Feature Extractor
==========================

This module provides machine learning-based feature extraction for file analysis.
"""

import os
import math
import hashlib
from typing import Dict, Any

class MLFeatureExtractor:
    """Extracts features from files for machine learning analysis"""
    
    def __init__(self):
        """Initialize the ML feature extractor"""
        pass
    
    def extract_features(self, filepath: str) -> Dict[str, Any]:
        """
        Extract features from a file for ML analysis
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            Dictionary with extracted features
        """
        if not os.path.exists(filepath):
            return {}
        
        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            
            # Calculate entropy
            entropy = self._calculate_entropy(filepath)
            
            # Get file extension
            _, ext = os.path.splitext(filepath)
            
            # Calculate hash
            file_hash = self._calculate_hash(filepath)
            
            return {
                'file_size': file_size,
                'entropy': entropy,
                'extension': ext.lower() if ext else '',
                'hash': file_hash,
                'features_extracted': True
            }
        except Exception as e:
            return {
                'error': str(e),
                'features_extracted': False
            }
    
    def _calculate_entropy(self, filepath: str) -> float:
        """
        Calculate file entropy
        
        Args:
            filepath: Path to the file
            
        Returns:
            Entropy value between 0 and 8
        """
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024)  # Read first 1KB for performance
                if not data:
                    return 0.0
                
                # Calculate frequency of each byte
                byte_counts = [0] * 256
                for byte in data:
                    byte_counts[byte] += 1
                
                # Calculate entropy using Shannon entropy formula
                entropy = 0.0
                data_len = len(data)
                for count in byte_counts:
                    if count > 0:
                        probability = count / data_len
                        entropy -= probability * math.log2(probability)
                
                return entropy
        except:
            return 0.0
    
    def _calculate_hash(self, filepath: str) -> str:
        """
        Calculate SHA256 hash of file
        
        Args:
            filepath: Path to the file
            
        Returns:
            SHA256 hash as hex string
        """
        try:
            with open(filepath, 'rb') as f:
                return hashlib.sha256(f.read(1024)).hexdigest()  # Hash first 1KB
        except:
            return ''

# Example usage
if __name__ == "__main__":
    extractor = MLFeatureExtractor()
    
    # Test with this script file
    features = extractor.extract_features(__file__)
    print("ML Feature Extraction Results:")
    for key, value in features.items():
        print(f"  {key}: {value}")