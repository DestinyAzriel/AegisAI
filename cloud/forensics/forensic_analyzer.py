#!/usr/bin/env python3
"""
AegisAI Forensic Analysis Module

This module provides forensic capabilities for incident response and evidence collection.
"""

import os
import sys
import json
import hashlib
import base64
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import shutil
import tarfile
import tempfile
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ForensicAnalyzer:
    """Forensic analysis engine for incident response"""
    
    def __init__(self, evidence_dir: str = "/var/evidence"):
        """Initialize the forensic analyzer"""
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.case_number = None
        self.evidence_chain = []
        
        logger.info(f"Forensic analyzer initialized with evidence directory: {evidence_dir}")
    
    def start_investigation(self, case_number: str, description: str) -> str:
        """
        Start a new forensic investigation
        
        Args:
            case_number: Unique case identifier
            description: Case description
            
        Returns:
            str: Investigation ID
        """
        self.case_number = case_number
        investigation_id = f"{case_number}_{int(datetime.now().timestamp())}"
        
        # Create case directory
        case_dir = self.evidence_dir / case_number
        case_dir.mkdir(exist_ok=True)
        
        # Create investigation metadata
        metadata = {
            'investigation_id': investigation_id,
            'case_number': case_number,
            'description': description,
            'start_time': datetime.now().isoformat(),
            'status': 'active'
        }
        
        # Save metadata
        metadata_file = case_dir / 'metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.evidence_chain.append({
            'type': 'investigation_started',
            'timestamp': datetime.now().isoformat(),
            'data': metadata
        })
        
        logger.info(f"Investigation started: {investigation_id}")
        return investigation_id
    
    def collect_memory_dump(self, agent_id: str, memory_data: bytes) -> str:
        """
        Collect and preserve memory dump evidence
        
        Args:
            agent_id: Agent identifier
            memory_data: Raw memory data
            
        Returns:
            str: Evidence ID
        """
        if not self.case_number:
            raise ValueError("No active investigation")
        
        # Generate evidence ID
        evidence_id = f"mem_{agent_id}_{int(datetime.now().timestamp())}"
        
        # Create evidence directory
        evidence_dir = self.evidence_dir / self.case_number / 'memory'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Save memory dump
        dump_file = evidence_dir / f"{evidence_id}.dump"
        with open(dump_file, 'wb') as f:
            f.write(memory_data)
        
        # Calculate hash
        sha256_hash = hashlib.sha256(memory_data).hexdigest()
        
        # Create evidence record
        evidence_record = {
            'evidence_id': evidence_id,
            'type': 'memory_dump',
            'agent_id': agent_id,
            'file_path': str(dump_file),
            'size': len(memory_data),
            'sha256': sha256_hash,
            'timestamp': datetime.now().isoformat()
        }
        
        # Save evidence record
        record_file = evidence_dir / f"{evidence_id}.json"
        with open(record_file, 'w') as f:
            json.dump(evidence_record, f, indent=2)
        
        self.evidence_chain.append({
            'type': 'memory_collected',
            'timestamp': datetime.now().isoformat(),
            'data': evidence_record
        })
        
        logger.info(f"Memory dump collected: {evidence_id}")
        return evidence_id
    
    def collect_file_evidence(self, agent_id: str, file_path: str, 
                            original_location: str) -> str:
        """
        Collect and preserve file evidence
        
        Args:
            agent_id: Agent identifier
            file_path: Path to file to collect
            original_location: Original file location
            
        Returns:
            str: Evidence ID
        """
        if not self.case_number:
            raise ValueError("No active investigation")
        
        # Check if file exists
        if not os.path.exists(file_path):
            logger.warning(f"File not found: {file_path}")
            return None
        
        # Generate evidence ID
        evidence_id = f"file_{agent_id}_{int(datetime.now().timestamp())}"
        
        # Create evidence directory
        evidence_dir = self.evidence_dir / self.case_number / 'files'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy file to evidence directory
        filename = os.path.basename(file_path)
        evidence_file = evidence_dir / f"{evidence_id}_{filename}"
        shutil.copy2(file_path, evidence_file)
        
        # Calculate hashes
        with open(evidence_file, 'rb') as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Get file metadata
        stat = os.stat(evidence_file)
        
        # Create evidence record
        evidence_record = {
            'evidence_id': evidence_id,
            'type': 'file',
            'agent_id': agent_id,
            'original_location': original_location,
            'file_path': str(evidence_file),
            'filename': filename,
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash,
            'timestamp': datetime.now().isoformat()
        }
        
        # Save evidence record
        record_file = evidence_dir / f"{evidence_id}.json"
        with open(record_file, 'w') as f:
            json.dump(evidence_record, f, indent=2)
        
        self.evidence_chain.append({
            'type': 'file_collected',
            'timestamp': datetime.now().isoformat(),
            'data': evidence_record
        })
        
        logger.info(f"File evidence collected: {evidence_id}")
        return evidence_id
    
    def collect_process_evidence(self, agent_id: str, 
                               process_info: Dict[str, Any]) -> str:
        """
        Collect and preserve process evidence
        
        Args:
            agent_id: Agent identifier
            process_info: Process information
            
        Returns:
            str: Evidence ID
        """
        if not self.case_number:
            raise ValueError("No active investigation")
        
        # Generate evidence ID
        evidence_id = f"proc_{agent_id}_{int(datetime.now().timestamp())}"
        
        # Create evidence directory
        evidence_dir = self.evidence_dir / self.case_number / 'processes'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Save process information
        evidence_file = evidence_dir / f"{evidence_id}.json"
        with open(evidence_file, 'w') as f:
            json.dump(process_info, f, indent=2)
        
        # Create evidence record
        evidence_record = {
            'evidence_id': evidence_id,
            'type': 'process',
            'agent_id': agent_id,
            'file_path': str(evidence_file),
            'process_id': process_info.get('pid'),
            'process_name': process_info.get('name'),
            'timestamp': datetime.now().isoformat()
        }
        
        self.evidence_chain.append({
            'type': 'process_collected',
            'timestamp': datetime.now().isoformat(),
            'data': evidence_record
        })
        
        logger.info(f"Process evidence collected: {evidence_id}")
        return evidence_id
    
    def collect_network_evidence(self, agent_id: str, 
                               network_data: Dict[str, Any]) -> str:
        """
        Collect and preserve network evidence
        
        Args:
            agent_id: Agent identifier
            network_data: Network connection data
            
        Returns:
            str: Evidence ID
        """
        if not self.case_number:
            raise ValueError("No active investigation")
        
        # Generate evidence ID
        evidence_id = f"net_{agent_id}_{int(datetime.now().timestamp())}"
        
        # Create evidence directory
        evidence_dir = self.evidence_dir / self.case_number / 'network'
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Save network data
        evidence_file = evidence_dir / f"{evidence_id}.json"
        with open(evidence_file, 'w') as f:
            json.dump(network_data, f, indent=2)
        
        # Create evidence record
        evidence_record = {
            'evidence_id': evidence_id,
            'type': 'network',
            'agent_id': agent_id,
            'file_path': str(evidence_file),
            'connections': len(network_data.get('connections', [])),
            'timestamp': datetime.now().isoformat()
        }
        
        self.evidence_chain.append({
            'type': 'network_collected',
            'timestamp': datetime.now().isoformat(),
            'data': evidence_record
        })
        
        logger.info(f"Network evidence collected: {evidence_id}")
        return evidence_id
    
    def generate_evidence_package(self) -> str:
        """
        Generate a complete evidence package for the current investigation
        
        Returns:
            str: Path to evidence package
        """
        if not self.case_number:
            raise ValueError("No active investigation")
        
        # Create package filename
        package_name = f"aegisai_evidence_{self.case_number}_{int(datetime.now().timestamp())}.tar.gz"
        package_path = self.evidence_dir / package_name
        
        # Create tar.gz package
        with tarfile.open(package_path, "w:gz") as tar:
            case_dir = self.evidence_dir / self.case_number
            tar.add(case_dir, arcname=case_dir.name)
        
        # Update investigation metadata
        metadata_file = self.evidence_dir / self.case_number / 'metadata.json'
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            metadata['end_time'] = datetime.now().isoformat()
            metadata['status'] = 'completed'
            metadata['evidence_package'] = str(package_path)
            
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        logger.info(f"Evidence package generated: {package_path}")
        return str(package_path)
    
    def get_evidence_chain(self) -> List[Dict[str, Any]]:
        """
        Get the complete evidence chain
        
        Returns:
            List of evidence collection events
        """
        return self.evidence_chain.copy()
    
    def add_investigator_note(self, investigator: str, note: str) -> None:
        """
        Add an investigator note to the evidence chain
        
        Args:
            investigator: Investigator name
            note: Note content
        """
        note_entry = {
            'type': 'investigator_note',
            'investigator': investigator,
            'note': note,
            'timestamp': datetime.now().isoformat()
        }
        
        self.evidence_chain.append(note_entry)
        logger.info(f"Investigator note added by {investigator}")

class EvidencePreserver:
    """Evidence preservation and integrity verification"""
    
    def __init__(self):
        """Initialize the evidence preserver"""
        logger.info("Evidence preserver initialized")
    
    def verify_evidence_integrity(self, evidence_path: str) -> bool:
        """
        Verify the integrity of evidence files
        
        Args:
            evidence_path: Path to evidence file or directory
            
        Returns:
            bool: True if integrity verified
        """
        if not os.path.exists(evidence_path):
            logger.error(f"Evidence path not found: {evidence_path}")
            return False
        
        if os.path.isfile(evidence_path):
            # Single file verification
            return self._verify_file_integrity(evidence_path)
        elif os.path.isdir(evidence_path):
            # Directory verification
            return self._verify_directory_integrity(evidence_path)
        
        return False
    
    def _verify_file_integrity(self, file_path: str) -> bool:
        """
        Verify integrity of a single file
        
        Args:
            file_path: Path to file
            
        Returns:
            bool: True if integrity verified
        """
        # Check if hash file exists
        hash_file = file_path + '.sha256'
        if not os.path.exists(hash_file):
            logger.warning(f"Hash file not found: {hash_file}")
            return False
        
        # Read stored hash
        with open(hash_file, 'r') as f:
            stored_hash = f.read().strip()
        
        # Calculate current hash
        with open(file_path, 'rb') as f:
            current_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Compare hashes
        if stored_hash == current_hash:
            logger.info(f"File integrity verified: {file_path}")
            return True
        else:
            logger.error(f"File integrity compromised: {file_path}")
            return False
    
    def _verify_directory_integrity(self, dir_path: str) -> bool:
        """
        Verify integrity of a directory
        
        Args:
            dir_path: Path to directory
            
        Returns:
            bool: True if integrity verified
        """
        all_verified = True
        
        for root, dirs, files in os.walk(dir_path):
            for file in files:
                if not file.endswith('.sha256'):  # Skip hash files
                    file_path = os.path.join(root, file)
                    if not self._verify_file_integrity(file_path):
                        all_verified = False
        
        return all_verified
    
    def create_evidence_hash(self, file_path: str) -> str:
        """
        Create a hash file for evidence preservation
        
        Args:
            file_path: Path to evidence file
            
        Returns:
            str: Path to hash file
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        # Calculate hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Write hash file
        hash_file = file_path + '.sha256'
        with open(hash_file, 'w') as f:
            f.write(file_hash)
        
        logger.info(f"Hash file created: {hash_file}")
        return hash_file

# Example usage and testing
if __name__ == "__main__":
    # Create forensic analyzer
    analyzer = ForensicAnalyzer()
    
    # Start investigation
    investigation_id = analyzer.start_investigation(
        "CASE-2025-001", 
        "Suspicious process activity detected"
    )
    print(f"Started investigation: {investigation_id}")
    
    # Collect memory dump evidence
    memory_data = b"This is simulated memory data for forensic analysis"
    memory_evidence = analyzer.collect_memory_dump("agent-001", memory_data)
    print(f"Collected memory evidence: {memory_evidence}")
    
    # Collect file evidence (create a test file first)
    test_file = "/tmp/test_evidence.txt"
    with open(test_file, 'w') as f:
        f.write("This is test evidence content")
    
    file_evidence = analyzer.collect_file_evidence(
        "agent-001", 
        test_file, 
        "/usr/bin/suspicious_process"
    )
    print(f"Collected file evidence: {file_evidence}")
    
    # Collect process evidence
    process_info = {
        'pid': 12345,
        'name': 'suspicious_process',
        'cmdline': '/usr/bin/suspicious_process --malicious-flag',
        'parent_pid': 1,
        'user': 'root',
        'start_time': '2025-01-01T10:00:00Z'
    }
    
    process_evidence = analyzer.collect_process_evidence("agent-001", process_info)
    print(f"Collected process evidence: {process_evidence}")
    
    # Collect network evidence
    network_data = {
        'connections': [
            {
                'local_addr': '192.168.1.100:12345',
                'remote_addr': '10.0.0.1:80',
                'protocol': 'TCP',
                'state': 'ESTABLISHED'
            }
        ]
    }
    
    network_evidence = analyzer.collect_network_evidence("agent-001", network_data)
    print(f"Collected network evidence: {network_evidence}")
    
    # Add investigator note
    analyzer.add_investigator_note("Forensic Analyst", "Initial analysis complete. Suspicious network activity detected.")
    
    # Generate evidence package
    package_path = analyzer.generate_evidence_package()
    print(f"Generated evidence package: {package_path}")
    
    # Show evidence chain
    print("\nEvidence chain:")
    for entry in analyzer.get_evidence_chain():
        print(f"  {entry['timestamp']}: {entry['type']}")
    
    # Test evidence preservation
    preserver = EvidencePreserver()
    hash_file = preserver.create_evidence_hash(test_file)
    print(f"Created hash file: {hash_file}")
    
    # Verify integrity
    is_valid = preserver.verify_evidence_integrity(test_file)
    print(f"Evidence integrity verified: {is_valid}")