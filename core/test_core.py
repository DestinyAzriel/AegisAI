"""
Test suite for AegisAI Core Engine
"""

import unittest
import os
import tempfile
import shutil
import json
import time
import sys
from pathlib import Path

# Add the parent directory to the path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import FileScanner
from realtime import RealTimeProtection
from quarantine import QuarantineManager
from agent import AegisAICoreAgent

class TestFileScanner(unittest.TestCase):
    """Test cases for the FileScanner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = FileScanner()
        # Create a temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directory
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_calculate_file_hash(self):
        """Test file hash calculation"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Calculate hash
        file_hash = self.scanner.calculate_file_hash(test_file)
        
        # Verify hash is returned
        self.assertIsNotNone(file_hash)
        self.assertIsInstance(file_hash, str)
        if file_hash is not None:
            self.assertEqual(len(file_hash), 64)  # SHA-256 hash length
    
    def test_scan_clean_file(self):
        """Test scanning a clean file"""
        # Create a clean test file
        test_file = os.path.join(self.test_dir, "clean.txt")
        with open(test_file, "w") as f:
            f.write("This is a clean file")
        
        # Scan the file
        result = self.scanner.scan_file(test_file)
        
        # Verify result
        self.assertEqual(result['status'], 'clean')
        self.assertEqual(result['file_path'], test_file)
        self.assertIn('file_hash', result)
    
    def test_scan_nonexistent_file(self):
        """Test scanning a nonexistent file"""
        # Try to scan a file that doesn't exist
        result = self.scanner.scan_file("/nonexistent/file.txt")
        
        # Verify error result
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error'], 'File not found')
    
    def test_signature_scan(self):
        """Test signature-based scanning"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Calculate hash
        file_hash = self.scanner.calculate_file_hash(test_file)
        
        # Test signature scan (should not find anything in default DB)
        if file_hash is not None:
            result = self.scanner.signature_scan(test_file, file_hash)
            self.assertIsNone(result)
    
    def test_heuristic_scan_large_file(self):
        """Test heuristic scanning of large file"""
        # Create a large test file (101MB)
        test_file = os.path.join(self.test_dir, "large.txt")
        with open(test_file, "wb") as f:
            f.write(b"0" * (101 * 1024 * 1024))  # 101MB of zeros
        
        # Test heuristic scan
        result = self.scanner.heuristic_scan(test_file)
        
        # Verify result
        self.assertIsNotNone(result)
        if result is not None:
            self.assertEqual(result['type'], 'heuristic')
            self.assertEqual(result['severity'], 'suspicious')
    
    def test_heuristic_scan_executable(self):
        """Test heuristic scanning of executable file"""
        # Create a test executable file
        test_file = os.path.join(self.test_dir, "test.exe")
        with open(test_file, "wb") as f:
            f.write(b"MZ")  # Windows executable signature
            f.write(b"This is a test executable file with some content")
        
        # Test heuristic scan
        result = self.scanner.heuristic_scan(test_file)
        
        # Verify result
        self.assertIsNotNone(result)
        if result is not None:
            self.assertEqual(result['type'], 'heuristic')
            self.assertEqual(result['name'], 'Executable File')

class TestQuarantineManager(unittest.TestCase):
    """Test cases for the QuarantineManager class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directories for quarantine
        self.temp_dir = tempfile.mkdtemp()
        self.quarantine_path = os.path.join(self.temp_dir, "quarantine")
        self.quarantine_manager = QuarantineManager(self.quarantine_path)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directories
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_quarantine_file(self):
        """Test quarantining a file"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Quarantine the file
        result = self.quarantine_manager.quarantine_file(test_file)
        
        # Verify result
        self.assertTrue(result)
        self.assertFalse(os.path.exists(test_file))  # Original file should be gone
        
        # Check that quarantine directory exists
        self.assertTrue(os.path.exists(self.quarantine_path))
        
        # Check that database has entry
        db = self.quarantine_manager._load_database()
        self.assertEqual(len(db), 1)
    
    def test_restore_file(self):
        """Test restoring a quarantined file"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Get original hash
        original_hash = self.quarantine_manager._calculate_file_hash(test_file)
        
        # Quarantine the file
        self.quarantine_manager.quarantine_file(test_file)
        
        # Restore the file
        if original_hash is not None:
            result = self.quarantine_manager.restore_file(original_hash)
            
            # Verify result
            self.assertTrue(result)
            self.assertTrue(os.path.exists(test_file))  # File should be restored
            
            # Check that file content is preserved
            with open(test_file, "r") as f:
                content = f.read()
            self.assertEqual(content, "This is a test file")
    
    def test_delete_quarantined_file(self):
        """Test deleting a quarantined file"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Get original hash
        original_hash = self.quarantine_manager._calculate_file_hash(test_file)
        
        # Quarantine the file
        self.quarantine_manager.quarantine_file(test_file)
        
        # Delete the quarantined file
        if original_hash is not None:
            result = self.quarantine_manager.delete_quarantined_file(original_hash)
            
            # Verify result
            self.assertTrue(result)
            
            # Check that database is empty
            db = self.quarantine_manager._load_database()
            self.assertEqual(len(db), 0)
    
    def test_get_quarantine_statistics(self):
        """Test getting quarantine statistics"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Get original hash
        original_hash = self.quarantine_manager._calculate_file_hash(test_file)
        
        # Initially stats should be zero
        stats = self.quarantine_manager.get_quarantine_statistics()
        self.assertEqual(stats['total_quarantined'], 0)
        self.assertEqual(stats['active_quarantined'], 0)
        self.assertEqual(stats['restored_files'], 0)
        
        # Quarantine the file
        self.quarantine_manager.quarantine_file(test_file)
        
        # Stats should now show one quarantined file
        stats = self.quarantine_manager.get_quarantine_statistics()
        self.assertEqual(stats['total_quarantined'], 1)
        self.assertEqual(stats['active_quarantined'], 1)
        self.assertEqual(stats['restored_files'], 0)
        
        # Restore the file
        if original_hash is not None:
            self.quarantine_manager.restore_file(original_hash)
            
            # Stats should now show one restored file
            stats = self.quarantine_manager.get_quarantine_statistics()
            self.assertEqual(stats['total_quarantined'], 1)
            self.assertEqual(stats['active_quarantined'], 0)
            self.assertEqual(stats['restored_files'], 1)

class TestAegisAICoreAgent(unittest.TestCase):
    """Test cases for the AegisAICoreAgent class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create temporary directory for config
        self.temp_dir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.temp_dir, "config.json")
        
        # Create a simple config
        config = {
            "enable_realtime": False,  # Disable for testing
            "enable_quarantine": True
        }
        
        with open(self.config_file, "w") as f:
            json.dump(config, f)
        
        # Create agent instance
        self.agent = AegisAICoreAgent(self.config_file)
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures"""
        # Remove temporary directories
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_agent_initialization(self):
        """Test agent initialization"""
        # Verify components are initialized
        self.assertIsNotNone(self.agent.scanner)
        self.assertIsNone(self.agent.realtime_protection)  # Disabled in config
        self.assertIsNotNone(self.agent.quarantine_manager)
        
        # Verify agent is not running
        self.assertFalse(self.agent.running)
    
    def test_scan_file(self):
        """Test scanning a file through the agent"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Scan the file
        result = self.agent.scan_file(test_file)
        
        # Verify result
        self.assertEqual(result['status'], 'clean')
        self.assertEqual(result['file_path'], test_file)
        
        # Verify statistics
        self.assertEqual(self.agent.agent_stats['scans_performed'], 1)
    
    def test_get_agent_status(self):
        """Test getting agent status"""
        # Get status
        status = self.agent.get_agent_status()
        
        # Verify status structure
        self.assertIn('running', status)
        self.assertIn('agent_stats', status)
        self.assertIn('components', status)
        
        # Verify component status
        components = status['components']
        self.assertTrue(components['scanner'])
        self.assertFalse(components['realtime_protection'])  # Disabled
        self.assertTrue(components['quarantine_manager'])
    
    def test_quarantine_operations(self):
        """Test quarantine operations through the agent"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("This is a test file")
        
        # Get original hash
        with open(test_file, "rb") as f:
            import hashlib
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Initially no quarantined files
        quarantined = self.agent.get_quarantined_files()
        self.assertEqual(len(quarantined), 0)
        
        # Quarantine through agent's quarantine manager
        if self.agent.quarantine_manager is not None:
            success = self.agent.quarantine_manager.quarantine_file(test_file)
            self.assertTrue(success)
            
            # Should now have one quarantined file
            quarantined = self.agent.get_quarantined_files()
            self.assertEqual(len(quarantined), 1)
            
            # Delete through agent
            success = self.agent.delete_quarantined_file(file_hash)
            self.assertTrue(success)
            
            # Should now have no quarantined files
            quarantined = self.agent.get_quarantined_files()
            self.assertEqual(len(quarantined), 0)

def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestFileScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestQuarantineManager))
    suite.addTests(loader.loadTestsFromTestCase(TestAegisAICoreAgent))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)