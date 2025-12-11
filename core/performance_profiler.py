vs"""
Performance Profiler for AegisAI Components
"""

import os
import sys
import time
import cProfile
import pstats
import io
from typing import Dict, List
import logging
from pathlib import Path

# Add the core directory to the path
sys.path.insert(0, str(Path(__file__).parent))

from ml_detector import MLFeatureExtractor
from robust_behavioral_analyzer import RobustBehavioralAnalyzer
from yara_scanner import YaraScanner
from scanner import FileScanner

logger = logging.getLogger(__name__)

class PerformanceProfiler:
    """Profile performance of AegisAI components to identify bottlenecks"""
    
    def __init__(self):
        """Initialize the performance profiler"""
        self.feature_extractor = MLFeatureExtractor()
        self.behavioral_analyzer = RobustBehavioralAnalyzer()
        self.yara_scanner = YaraScanner()
        self.file_scanner = FileScanner()
        
        # Collect baseline data for behavioral analyzer
        baseline_data = self.behavioral_analyzer.collect_baseline_data(1)  # 1 minute
        self.behavioral_analyzer.train_model(baseline_data)
    
    def profile_ml_feature_extraction(self, file_path: str) -> Dict:
        """
        Profile ML feature extraction performance
        
        Args:
            file_path: Path to test file
            
        Returns:
            Dictionary with profiling results
        """
        logger.info(f"Profiling ML feature extraction for {file_path}")
        
        # Profile the feature extraction
        pr = cProfile.Profile()
        pr.enable()
        
        # Extract features
        features = self.feature_extractor.extract_features(file_path)
        
        pr.disable()
        
        # Get profiling stats
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        return {
            'component': 'ml_feature_extraction',
            'file_path': file_path,
            'features_extracted': len(features),
            'profile_output': s.getvalue(),
            'total_features': features
        }
    
    def profile_behavioral_analysis(self, behavioral_data: Dict) -> Dict:
        """
        Profile behavioral analysis performance
        
        Args:
            behavioral_data: Behavioral data to analyze
            
        Returns:
            Dictionary with profiling results
        """
        logger.info("Profiling behavioral analysis")
        
        # Profile the behavioral analysis
        pr = cProfile.Profile()
        pr.enable()
        
        # Analyze behavior
        result = self.behavioral_analyzer.analyze_behavior(behavioral_data)
        
        pr.disable()
        
        # Get profiling stats
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        return {
            'component': 'behavioral_analysis',
            'analysis_result': result,
            'profile_output': s.getvalue()
        }
    
    def profile_yara_scanning(self, file_path: str) -> Dict:
        """
        Profile YARA scanning performance
        
        Args:
            file_path: Path to test file
            
        Returns:
            Dictionary with profiling results
        """
        logger.info(f"Profiling YARA scanning for {file_path}")
        
        # Profile the YARA scanning
        pr = cProfile.Profile()
        pr.enable()
        
        # Scan file with YARA
        matches = self.yara_scanner.scan_file(file_path)
        
        pr.disable()
        
        # Get profiling stats
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        return {
            'component': 'yara_scanning',
            'file_path': file_path,
            'matches_found': len(matches),
            'profile_output': s.getvalue()
        }
    
    def profile_file_scanning(self, file_path: str) -> Dict:
        """
        Profile complete file scanning performance
        
        Args:
            file_path: Path to test file
            
        Returns:
            Dictionary with profiling results
        """
        logger.info(f"Profiling complete file scanning for {file_path}")
        
        # Profile the complete file scanning
        pr = cProfile.Profile()
        pr.enable()
        
        # Scan file
        result = self.file_scanner.scan_file(file_path)
        
        pr.disable()
        
        # Get profiling stats
        s = io.StringIO()
        ps = pstats.Stats(pr, stream=s)
        ps.sort_stats('cumulative')
        ps.print_stats(10)  # Top 10 functions
        
        return {
            'component': 'file_scanning',
            'file_path': file_path,
            'scan_result': result,
            'profile_output': s.getvalue()
        }
    
    def run_comprehensive_profile(self, test_file: str) -> List[Dict]:
        """
        Run comprehensive profiling on all components
        
        Args:
            test_file: Path to test file
            
        Returns:
            List of profiling results
        """
        results = []
        
        # Test file must exist
        if not os.path.exists(test_file):
            logger.error(f"Test file not found: {test_file}")
            return results
        
        logger.info("Starting comprehensive performance profiling")
        
        # Profile ML feature extraction
        try:
            ml_result = self.profile_ml_feature_extraction(test_file)
            results.append(ml_result)
            logger.info("ML feature extraction profiling completed")
        except Exception as e:
            logger.error(f"ML feature extraction profiling failed: {e}")
        
        # Profile YARA scanning
        try:
            yara_result = self.profile_yara_scanning(test_file)
            results.append(yara_result)
            logger.info("YARA scanning profiling completed")
        except Exception as e:
            logger.error(f"YARA scanning profiling failed: {e}")
        
        # Profile complete file scanning
        try:
            file_scan_result = self.profile_file_scanning(test_file)
            results.append(file_scan_result)
            logger.info("Complete file scanning profiling completed")
        except Exception as e:
            logger.error(f"Complete file scanning profiling failed: {e}")
        
        # Profile behavioral analysis
        try:
            behavioral_data = {
                'file_operations': 25,
                'network_connections': 8,
                'cpu_usage': 35.0,
                'memory_usage': 180.0,
                'child_processes': 3,
                'registry_modifications': 2
            }
            behavioral_result = self.profile_behavioral_analysis(behavioral_data)
            results.append(behavioral_result)
            logger.info("Behavioral analysis profiling completed")
        except Exception as e:
            logger.error(f"Behavioral analysis profiling failed: {e}")
        
        return results

def main():
    """Main function to demonstrate performance profiling"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("           AEGISAI PERFORMANCE PROFILING")
    print("=" * 70)
    
    # Initialize profiler
    profiler = PerformanceProfiler()
    
    # Create a test file if it doesn't exist
    test_file = "performance_test.txt"
    if not os.path.exists(test_file):
        with open(test_file, "w") as f:
            f.write("This is a test file for performance profiling.\n" * 1000)
        print(f"Created test file: {test_file}")
    
    # Run comprehensive profiling
    results = profiler.run_comprehensive_profile(test_file)
    
    # Display results
    print("\n" + "=" * 70)
    print("PERFORMANCE PROFILING RESULTS")
    print("=" * 70)
    
    for result in results:
        print(f"\nComponent: {result['component']}")
        if 'file_path' in result:
            print(f"File: {result['file_path']}")
        if 'features_extracted' in result:
            print(f"Features Extracted: {result['features_extracted']}")
        if 'matches_found' in result:
            print(f"YARA Matches: {result['matches_found']}")
        if 'analysis_result' in result:
            print(f"Behavioral Analysis: {result['analysis_result']['is_anomaly']}")
        
        # Show top profiling results
        print("Top Performance Bottlenecks:")
        lines = result['profile_output'].split('\n')
        for i, line in enumerate(lines[:15]):  # Show top 15 lines
            if line.strip():
                print(f"  {line}")
    
    print("\n" + "=" * 70)
    print("PROFILING COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()