#!/usr/bin/env python3
"""
Predictive Threat Intelligence Engine for AegisAI
===============================================

This module implements a predictive threat intelligence system that goes beyond
traditional antivirus capabilities by analyzing threat patterns, predicting
future attacks, and providing proactive system hardening recommendations.
"""

import os
import json
import logging
import hashlib
import time
from typing import Dict, List, Set, Tuple, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import networkx as nx
import numpy as np

# Try to import required libraries
try:
    from sklearn.cluster import DBSCAN
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    DBSCAN = None
    TfidfVectorizer = None
    cosine_similarity = None
    logging.warning("ML libraries not available for predictive threat intelligence. Install with: pip install scikit-learn")

logger = logging.getLogger(__name__)

class ThreatPatternAnalyzer:
    """Analyzes threat patterns to identify emerging threats and attack vectors"""
    
    def __init__(self):
        """Initialize the threat pattern analyzer"""
        self.threat_graph = nx.DiGraph()  # Directed graph for threat evolution
        self.attack_patterns = {}  # Maps attack techniques to threat families
        self.threat_families = {}  # Groups related threats
        self.emerging_threats = set()  # Newly identified threats
        self.pattern_vectors = {}  # TF-IDF vectors for threat patterns
        # Initialize vectorizer only if ML is available
        self.vectorizer = None
        if ML_AVAILABLE and TfidfVectorizer is not None:
            self.vectorizer = TfidfVectorizer()
        
    def add_threat_sample(self, threat_info: Dict[str, Any]):
        """
        Add a threat sample to the analyzer for pattern analysis.
        
        Args:
            threat_info: Dictionary containing threat information
        """
        try:
            threat_id = threat_info.get('threat_id', hashlib.md5(str(threat_info).encode()).hexdigest())
            threat_type = threat_info.get('type', 'unknown')
            malware_family = threat_info.get('malware_family', 'unknown')
            attack_techniques = threat_info.get('attack_techniques', [])
            file_features = threat_info.get('file_features', {})
            behavioral_indicators = threat_info.get('behavioral_indicators', [])
            
            # Add threat to graph
            self.threat_graph.add_node(threat_id, 
                                     type=threat_type,
                                     family=malware_family,
                                     timestamp=datetime.now().isoformat())
            
            # Connect to related threats based on family
            for node, attrs in self.threat_graph.nodes(data=True):
                if (node != threat_id and 
                    attrs.get('family') == malware_family and
                    attrs.get('type') != threat_type):
                    # Add edge representing evolution
                    self.threat_graph.add_edge(node, threat_id, 
                                             relationship='evolves_to',
                                             timestamp=datetime.now().isoformat())
            
            # Track attack techniques
            for technique in attack_techniques:
                if technique not in self.attack_patterns:
                    self.attack_patterns[technique] = []
                self.attack_patterns[technique].append(threat_id)
            
            # Track threat families
            if malware_family not in self.threat_families:
                self.threat_families[malware_family] = []
            self.threat_families[malware_family].append(threat_id)
            
            # Create pattern vector for ML analysis
            if ML_AVAILABLE and self.vectorizer is not None:
                pattern_text = self._create_pattern_text(threat_info)
                self.pattern_vectors[threat_id] = pattern_text
                
        except Exception as e:
            logger.error(f"Error adding threat sample: {e}")
    
    def _create_pattern_text(self, threat_info: Dict[str, Any]) -> str:
        """
        Create text representation of threat patterns for vectorization.
        
        Args:
            threat_info: Dictionary containing threat information
            
        Returns:
            String representation of threat patterns
        """
        components = []
        
        # Add attack techniques
        techniques = threat_info.get('attack_techniques', [])
        components.extend(techniques)
        
        # Add file features
        features = threat_info.get('file_features', {})
        for key, value in features.items():
            components.append(f"{key}_{value}")
        
        # Add behavioral indicators
        behaviors = threat_info.get('behavioral_indicators', [])
        components.extend(behaviors)
        
        # Add threat type and family
        components.append(threat_info.get('type', ''))
        components.append(threat_info.get('malware_family', ''))
        
        return ' '.join(components)
    
    def identify_emerging_threats(self) -> List[Dict[str, Any]]:
        """
        Identify emerging threats based on recent activity patterns.
        
        Returns:
            List of emerging threat information
        """
        emerging = []
        
        # Look for threats that have appeared recently and are rapidly evolving
        recent_time = datetime.now() - timedelta(days=7)
        recent_threats = []
        
        for node, attrs in self.threat_graph.nodes(data=True):
            timestamp = attrs.get('timestamp', '')
            try:
                threat_time = datetime.fromisoformat(timestamp)
                if threat_time > recent_time:
                    recent_threats.append((node, attrs))
            except:
                pass
        
        # Count family occurrences in recent threats
        family_counts = Counter()
        for node, attrs in recent_threats:
            family = attrs.get('family', 'unknown')
            family_counts[family] += 1
        
        # Identify families with multiple recent threats
        for family, count in family_counts.items():
            if count > 2:  # At least 3 threats in the family recently
                emerging.append({
                    'type': 'emerging_family',
                    'family': family,
                    'count': count,
                    'confidence': min(count / 5.0, 1.0),  # Normalize to 0-1
                    'description': f'Emerging threat family with {count} recent samples'
                })
        
        # Use ML to find similar threats if available
        if ML_AVAILABLE and len(self.pattern_vectors) > 5:
            emerging.extend(self._ml_based_threat_detection())
        
        return emerging
    
    def _ml_based_threat_detection(self) -> List[Dict[str, Any]]:
        """
        Use ML to detect similar threat patterns and emerging threats.
        
        Returns:
            List of ML-identified emerging threats
        """
        emerging = []
        
        try:
            # Vectorize patterns
            threat_ids = list(self.pattern_vectors.keys())
            pattern_texts = list(self.pattern_vectors.values())
            
            if len(pattern_texts) < 2:
                return emerging
            
            # Create TF-IDF vectors
            if self.vectorizer is not None:
                tfidf_matrix = self.vectorizer.fit_transform(pattern_texts)
                
                # Calculate similarity matrix
                if cosine_similarity is not None:
                    similarity_matrix = cosine_similarity(tfidf_matrix)
                    
                    # Find clusters of similar threats
                    if DBSCAN is not None:
                        clustering = DBSCAN(eps=0.3, min_samples=2, metric='cosine')
                        cluster_labels = clustering.fit_predict(similarity_matrix)
                        
                        # Identify emerging clusters
                        unique_labels = set(cluster_labels)
                        for label in unique_labels:
                            if label == -1:  # Noise points
                                continue
                                
                            # Get threats in this cluster
                            cluster_indices = [i for i, l in enumerate(cluster_labels) if l == label]
                            cluster_threats = [threat_ids[i] for i in cluster_indices]
                            
                            if len(cluster_threats) >= 3:  # Significant cluster
                                # Get threat info for first threat in cluster
                                first_threat_attrs = self.threat_graph.nodes.get(cluster_threats[0], {})
                                family = first_threat_attrs.get('family', 'unknown')
                                
                                emerging.append({
                                    'type': 'clustered_threats',
                                    'family': family,
                                    'count': len(cluster_threats),
                                    'cluster_id': label,
                                    'confidence': min(len(cluster_threats) / 10.0, 1.0),
                                    'description': f'Cluster of {len(cluster_threats)} similar threats'
                                })
                    
        except Exception as e:
            logger.error(f"ML-based threat detection failed: {e}")
        
        return emerging
    
    def get_threat_evolution_graph(self) -> nx.DiGraph:
        """
        Get the threat evolution graph.
        
        Returns:
            NetworkX directed graph representing threat evolution
        """
        return self.threat_graph.copy()
    
    def get_attack_pattern_insights(self) -> Dict[str, Any]:
        """
        Get insights about attack patterns and techniques.
        
        Returns:
            Dictionary with attack pattern analysis
        """
        insights = {
            'total_techniques': len(self.attack_patterns),
            'technique_distribution': {},
            'most_common_techniques': [],
            'family_technique_mapping': {}
        }
        
        # Technique distribution
        technique_counts = {tech: len(threats) for tech, threats in self.attack_patterns.items()}
        insights['technique_distribution'] = technique_counts
        
        # Most common techniques
        sorted_techniques = sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)
        insights['most_common_techniques'] = sorted_techniques[:10]  # Top 10
        
        # Family to technique mapping
        for family, threats in self.threat_families.items():
            family_techniques = set()
            for threat_id in threats:
                # Find techniques associated with this threat
                for technique, threat_list in self.attack_patterns.items():
                    if threat_id in threat_list:
                        family_techniques.add(technique)
            insights['family_technique_mapping'][family] = list(family_techniques)
        
        return insights

class SystemHardeningAdvisor:
    """Provides system hardening recommendations based on threat intelligence"""
    
    def __init__(self):
        """Initialize the system hardening advisor"""
        self.vulnerability_database = self._load_vulnerability_database()
        self.hardening_recommendations = []
        self.threat_count = 0  # Track number of threats processed
        
    def _load_vulnerability_database(self) -> Dict[str, Any]:
        """
        Load vulnerability database (in a real implementation, this would connect to external sources).
        
        Returns:
            Dictionary with vulnerability information
        """
        # This is a simplified example - in reality, this would connect to vulnerability databases
        return {
            'CVE-2025-1234': {
                'description': 'Buffer overflow in network protocol handler',
                'severity': 'high',
                'affected_components': ['network_stack'],
                'recommendations': ['update_network_driver', 'enable_aslr']
            },
            'CVE-2025-5678': {
                'description': 'Privilege escalation through registry manipulation',
                'severity': 'critical',
                'affected_components': ['registry_access'],
                'recommendations': ['restrict_registry_access', 'enable_uac']
            }
        }
    
    def generate_hardening_recommendations(self, threat_intelligence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate system hardening recommendations based on threat intelligence.
        
        Args:
            threat_intelligence: Dictionary with threat intelligence data
            
        Returns:
            List of hardening recommendations
        """
        # Increment threat count for dynamic behavior
        self.threat_count += 1
        
        recommendations = []
        
        # Analyze attack techniques to generate recommendations
        attack_patterns = threat_intelligence.get('attack_patterns', {})
        for technique, count in attack_patterns.get('technique_distribution', {}).items():
            rec = self._generate_recommendation_for_technique(technique, count)
            if rec:
                recommendations.append(rec)
        
        # Analyze threat families
        family_mapping = attack_patterns.get('family_technique_mapping', {})
        for family, techniques in family_mapping.items():
            rec = self._generate_recommendation_for_family(family, techniques)
            if rec:
                recommendations.append(rec)
        
        # Add general security recommendations with dynamic confidence
        recommendations.extend(self._generate_general_recommendations())
        
        # Add dynamic recommendations based on threat patterns
        recommendations.extend(self._generate_dynamic_recommendations(threat_intelligence))
        
        # Add some variation based on threat count to make recommendations less static
        if self.threat_count % 3 == 0:
            recommendations.append({
                'action': 'review_security_policies',
                'description': 'Review and update security policies based on recent threat activity',
                'severity': 'medium',
                'confidence': 0.7,
                'type': 'periodic_review'
            })
        
        return recommendations
    
    def _generate_recommendation_for_technique(self, technique: str, count: int) -> Optional[Dict[str, Any]]:
        """
        Generate recommendation for a specific attack technique.
        
        Args:
            technique: Attack technique identifier
            count: Number of times this technique was observed
            
        Returns:
            Recommendation dictionary or None
        """
        # Map techniques to recommendations
        technique_recommendations = {
            'CreateProcess': {
                'action': 'restrict_process_creation',
                'description': 'Limit unauthorized process creation',
                'severity': 'high',
                'confidence': min(count / 10.0, 1.0)
            },
            'WriteProcessMemory': {
                'action': 'enable_memory_protection',
                'description': 'Enable memory protection mechanisms',
                'severity': 'critical',
                'confidence': min(count / 5.0, 1.0)
            },
            'RegSetValue': {
                'action': 'restrict_registry_writes',
                'description': 'Restrict unauthorized registry modifications',
                'severity': 'high',
                'confidence': min(count / 8.0, 1.0)
            },
            'WSAStartup': {
                'action': 'monitor_network_activity',
                'description': 'Monitor suspicious network connections',
                'severity': 'medium',
                'confidence': min(count / 15.0, 1.0)
            }
        }
        
        if technique in technique_recommendations:
            rec = technique_recommendations[technique].copy()
            rec['technique'] = technique
            rec['count'] = count
            return rec
        
        return None
    
    def _generate_recommendation_for_family(self, family: str, techniques: List[str]) -> Optional[Dict[str, Any]]:
        """
        Generate recommendation for a threat family.
        
        Args:
            family: Threat family name
            techniques: List of techniques used by this family
            
        Returns:
            Recommendation dictionary or None
        """
        # Map families to recommendations
        family_recommendations = {
            'ransomware': {
                'action': 'enable_file_encryption_monitoring',
                'description': 'Monitor for file encryption activities',
                'severity': 'critical',
                'confidence': 0.9
            },
            'trojan': {
                'action': 'restrict_persistence_mechanisms',
                'description': 'Restrict common persistence mechanisms',
                'severity': 'high',
                'confidence': 0.8
            },
            'worm': {
                'action': 'implement_network_segmentation',
                'description': 'Implement network segmentation to limit spread',
                'severity': 'high',
                'confidence': 0.85
            }
        }
        
        if family in family_recommendations:
            rec = family_recommendations[family].copy()
            rec['family'] = family
            rec['techniques'] = techniques
            return rec
        
        return None
    
    def _generate_general_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate general security recommendations with dynamic confidence.
        
        Returns:
            List of general recommendations
        """
        # Add some variation to confidence levels based on threat count
        variation = (self.threat_count % 5) * 0.02  # Small variation between 0-0.08
        
        return [
            {
                'action': 'enable_aslr',
                'description': 'Enable Address Space Layout Randomization',
                'severity': 'medium',
                'confidence': 0.9 + variation,  # Add variation
                'type': 'general'
            },
            {
                'action': 'enable_dep',
                'description': 'Enable Data Execution Prevention',
                'severity': 'high',
                'confidence': 0.95 - variation,  # Add variation
                'type': 'general'
            },
            {
                'action': 'restrict_admin_privileges',
                'description': 'Restrict administrative privileges',
                'severity': 'critical',
                'confidence': 0.9 + variation * 2,  # Add more variation
                'type': 'general'
            },
            {
                'action': 'enable_firewall',
                'description': 'Ensure firewall is enabled and properly configured',
                'severity': 'high',
                'confidence': 0.85 + variation,
                'type': 'general'
            }
        ]
    
    def _generate_dynamic_recommendations(self, threat_intelligence: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate dynamic recommendations based on current threat intelligence.
        
        Args:
            threat_intelligence: Dictionary with threat intelligence data
            
        Returns:
            List of dynamic recommendations
        """
        recommendations = []
        
        # Check for emerging threats
        emerging_threats = threat_intelligence.get('emerging_threats', [])
        if emerging_threats:
            # If we have emerging threats, recommend additional protections
            recommendations.append({
                'action': 'increase_monitoring',
                'description': 'Increase system monitoring due to emerging threats',
                'severity': 'medium',
                'confidence': 0.8,
                'type': 'dynamic'
            })
        
        # Check attack pattern insights
        attack_patterns = threat_intelligence.get('attack_patterns', {})
        technique_distribution = attack_patterns.get('technique_distribution', {})
        
        # If we see a lot of memory-related attacks, recommend ASLR more strongly
        memory_techniques = ['WriteProcessMemory', 'CreateRemoteThread', 'VirtualAllocEx']
        memory_attacks = sum(technique_distribution.get(tech, 0) for tech in memory_techniques)
        
        if memory_attacks > 5:
            recommendations.append({
                'action': 'enable_aslr',
                'description': 'Enable Address Space Layout Randomization to protect against memory exploits',
                'severity': 'high',
                'confidence': min(memory_attacks / 10.0, 1.0),
                'type': 'dynamic'
            })
        
        # If we see a lot of network-related attacks, recommend network protections
        network_techniques = ['WSAStartup', 'connect', 'send', 'recv']
        network_attacks = sum(technique_distribution.get(tech, 0) for tech in network_techniques)
        
        if network_attacks > 5:
            recommendations.append({
                'action': 'enhance_network_security',
                'description': 'Enhance network security measures due to increased network-based attacks',
                'severity': 'high',
                'confidence': min(network_attacks / 10.0, 1.0),
                'type': 'dynamic'
            })
        
        # If we see a lot of registry-related attacks, recommend registry protections
        registry_techniques = ['RegSetValue', 'RegCreateKey', 'RegDeleteKey']
        registry_attacks = sum(technique_distribution.get(tech, 0) for tech in registry_techniques)
        
        if registry_attacks > 3:
            recommendations.append({
                'action': 'restrict_registry_access',
                'description': 'Restrict registry access to prevent persistence mechanisms',
                'severity': 'medium',
                'confidence': min(registry_attacks / 5.0, 1.0),
                'type': 'dynamic'
            })
        
        return recommendations

class PredictiveThreatIntelligenceEngine:
    """Main predictive threat intelligence engine"""
    
    def __init__(self):
        """Initialize the predictive threat intelligence engine"""
        self.pattern_analyzer = ThreatPatternAnalyzer()
        self.hardening_advisor = SystemHardeningAdvisor()
        self.threat_database = {}  # Local threat intelligence database
        self.last_analysis_time = None
        
    def process_threat_detection(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a threat detection result and update threat intelligence.
        
        Args:
            detection_result: Dictionary with threat detection results
            
        Returns:
            Dictionary with processed threat intelligence
        """
        try:
            # Extract threat information
            threat_info = self._extract_threat_info(detection_result)
            
            # Add to pattern analyzer
            self.pattern_analyzer.add_threat_sample(threat_info)
            
            # Update local threat database
            threat_id = threat_info.get('threat_id')
            if threat_id:
                self.threat_database[threat_id] = threat_info
            
            # Update last analysis time
            self.last_analysis_time = datetime.now()
            
            return threat_info
            
        except Exception as e:
            logger.error(f"Error processing threat detection: {e}")
            return {}
    
    def _extract_threat_info(self, detection_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract threat information from detection result.
        
        Args:
            detection_result: Dictionary with threat detection results
            
        Returns:
            Dictionary with extracted threat information
        """
        threat_info = {
            'threat_id': hashlib.md5(str(detection_result).encode()).hexdigest(),
            'timestamp': datetime.now().isoformat(),
            'file_path': detection_result.get('file_path', ''),
            'detection_time': detection_result.get('scan_time', ''),
        }
        
        # Extract threat details
        threat = detection_result.get('threat', {})
        if threat:
            threat_info.update({
                'type': threat.get('type', 'unknown'),
                'name': threat.get('name', 'unknown'),
                'severity': threat.get('severity', 'unknown'),
                'confidence': threat.get('confidence', 0.0),
                'malware_family': threat.get('malware_type', 'unknown'),
                'description': threat.get('description', '')
            })
        
        # Extract file features (if available)
        threat_info['file_features'] = {
            'size': detection_result.get('file_size', 0),
            'entropy': detection_result.get('entropy', 0.0),
            'extension': detection_result.get('file_extension', 'unknown')
        }
        
        # Extract behavioral indicators (if available)
        analysis = detection_result.get('analysis', {})
        threat_info['behavioral_indicators'] = analysis.get('indicators', [])
        
        # Extract attack techniques based on threat type
        threat_info['attack_techniques'] = self._map_threat_to_techniques(threat_info)
        
        return threat_info
    
    def _map_threat_to_techniques(self, threat_info: Dict[str, Any]) -> List[str]:
        """
        Map threat information to attack techniques.
        
        Args:
            threat_info: Dictionary with threat information
            
        Returns:
            List of attack techniques
        """
        techniques = []
        threat_type = threat_info.get('type', '').lower()
        malware_family = threat_info.get('malware_family', '').lower()
        
        # Map based on threat type
        if 'trojan' in threat_type or 'trojan' in malware_family:
            techniques.extend(['CreateProcess', 'WriteProcessMemory', 'RegSetValue'])
        elif 'worm' in threat_type or 'worm' in malware_family:
            techniques.extend(['WSAStartup', 'connect', 'send'])
        elif 'ransomware' in threat_type or 'ransomware' in malware_family:
            techniques.extend(['WriteFile', 'CreateFile', 'encrypt'])
        elif 'keylogger' in threat_type or 'keylogger' in malware_family:
            techniques.extend(['GetAsyncKeyState', 'GetKeyboardState'])
        elif 'memory' in threat_type or 'exploit' in threat_type:
            techniques.extend(['WriteProcessMemory', 'VirtualAllocEx', 'CreateRemoteThread'])
        
        # Map based on behavioral indicators
        indicators = threat_info.get('behavioral_indicators', [])
        for indicator in indicators:
            if 'process' in indicator.lower():
                techniques.append('CreateProcess')
            elif 'memory' in indicator.lower():
                techniques.append('WriteProcessMemory')
            elif 'registry' in indicator.lower():
                techniques.append('RegSetValue')
            elif 'network' in indicator.lower():
                techniques.append('WSAStartup')
            elif 'file' in indicator.lower() and 'encrypt' in indicator.lower():
                techniques.append('encrypt')
        
        return list(set(techniques))  # Remove duplicates
    
    def generate_predictive_intelligence(self) -> Dict[str, Any]:
        """
        Generate predictive threat intelligence.
        
        Returns:
            Dictionary with predictive threat intelligence
        """
        intelligence = {
            'timestamp': datetime.now().isoformat(),
            'emerging_threats': [],
            'attack_patterns': {},
            'hardening_recommendations': [],
            'threat_statistics': {}
        }
        
        # Identify emerging threats
        intelligence['emerging_threats'] = self.pattern_analyzer.identify_emerging_threats()
        
        # Analyze attack patterns
        intelligence['attack_patterns'] = self.pattern_analyzer.get_attack_pattern_insights()
        
        # Generate hardening recommendations
        intelligence['hardening_recommendations'] = self.hardening_advisor.generate_hardening_recommendations(intelligence)
        
        # Generate threat statistics
        intelligence['threat_statistics'] = {
            'total_threats_analyzed': len(self.threat_database),
            'unique_families': len(self.pattern_analyzer.threat_families),
            'attack_techniques': len(self.pattern_analyzer.attack_patterns),
            'last_analysis': self.last_analysis_time.isoformat() if self.last_analysis_time else None
        }
        
        return intelligence
    
    def get_threat_evolution_report(self) -> Dict[str, Any]:
        """
        Generate a threat evolution report.
        
        Returns:
            Dictionary with threat evolution information
        """
        graph = self.pattern_analyzer.get_threat_evolution_graph()
        
        report = {
            'nodes': len(graph.nodes),
            'edges': len(graph.edges),
            'threat_families': {},
            'evolution_paths': []
        }
        
        # Family information
        for family, threats in self.pattern_analyzer.threat_families.items():
            report['threat_families'][family] = {
                'count': len(threats),
                'threats': threats
            }
        
        # Evolution paths
        for edge in graph.edges(data=True):
            source, target, attrs = edge
            report['evolution_paths'].append({
                'from': source,
                'to': target,
                'relationship': attrs.get('relationship', 'unknown'),
                'timestamp': attrs.get('timestamp', '')
            })
        
        return report

# Example usage and integration with AegisAI
def integrate_with_aegisai():
    """Example of how to integrate predictive threat intelligence with AegisAI"""
    # Create the engine
    pti_engine = PredictiveThreatIntelligenceEngine()
    
    # This would be called whenever a threat is detected
    def on_threat_detected(detection_result):
        # Process the threat detection
        threat_info = pti_engine.process_threat_detection(detection_result)
        
        # Generate predictive intelligence periodically
        if len(pti_engine.threat_database) % 10 == 0:  # Every 10 detections
            intelligence = pti_engine.generate_predictive_intelligence()
            print("Predictive Intelligence:", json.dumps(intelligence, indent=2))
            
            # Log emerging threats
            for threat in intelligence['emerging_threats']:
                logger.warning(f"Emerging threat detected: {threat}")
    
    return pti_engine, on_threat_detected

if __name__ == "__main__":
    # Demo the predictive threat intelligence engine
    print("🛡️  AEGISAI Predictive Threat Intelligence Engine Demo")
    print("=" * 55)
    
    # Create engine
    engine = PredictiveThreatIntelligenceEngine()
    
    # Simulate threat detections
    sample_detections = [
        {
            "file_path": "C:\\Users\\Test\\Downloads\\malware1.exe",
            "scan_time": "2025-10-15T10:30:00Z",
            "threat": {
                "type": "signature",
                "name": "Trojan.Generic.12345",
                "severity": "malicious",
                "confidence": 0.95,
                "malware_type": "trojan",
                "description": "Generic trojan detected"
            },
            "file_size": 1024000,
            "entropy": 7.2
        },
        {
            "file_path": "C:\\Users\\Test\\Documents\\ransomware.exe",
            "scan_time": "2025-10-15T11:15:00Z",
            "threat": {
                "type": "heuristic",
                "name": "Suspicious File Encryption",
                "severity": "malicious",
                "confidence": 0.85,
                "malware_type": "ransomware",
                "description": "File exhibits ransomware characteristics"
            },
            "file_size": 2048000,
            "entropy": 7.9
        },
        {
            "file_path": "C:\\Users\\Test\\AppData\\Local\\Temp\\worm.exe",
            "scan_time": "2025-10-15T12:00:00Z",
            "threat": {
                "type": "ml",
                "name": "AI Detected Worm",
                "severity": "malicious",
                "confidence": 0.92,
                "malware_type": "worm",
                "description": "Detected by machine learning model"
            },
            "file_size": 512000,
            "entropy": 6.8
        }
    ]
    
    # Process detections
    for i, detection in enumerate(sample_detections):
        print(f"\nProcessing detection {i+1}...")
        engine.process_threat_detection(detection)
    
    # Generate predictive intelligence
    print("\n" + "=" * 55)
    print("GENERATING PREDICTIVE THREAT INTELLIGENCE")
    print("=" * 55)
    
    intelligence = engine.generate_predictive_intelligence()
    
    # Display results
    print("\n📊 EMERGING THREATS:")
    for threat in intelligence['emerging_threats']:
        print(f"  • {threat['type']}: {threat['description']} (Confidence: {threat['confidence']:.2f})")
    
    print("\n🎯 ATTACK PATTERN INSIGHTS:")
    print(f"  Total Techniques: {intelligence['attack_patterns']['total_techniques']}")
    print("  Most Common Techniques:")
    for technique, count in intelligence['attack_patterns']['most_common_techniques'][:5]:
        print(f"    - {technique}: {count} occurrences")
    
    print("\n🔧 HARDENING RECOMMENDATIONS:")
    for rec in intelligence['hardening_recommendations'][:5]:
        severity = rec.get('severity', 'unknown').upper()
        print(f"  [{severity}] {rec['description']}")
        print(f"      Action: {rec.get('action', 'unknown')}")
        print(f"      Confidence: {rec.get('confidence', 0.0):.2f}")
    
    print("\n📈 THREAT STATISTICS:")
    stats = intelligence['threat_statistics']
    for key, value in stats.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    
    # Generate threat evolution report
    print("\n" + "=" * 55)
    print("THREAT EVOLUTION REPORT")
    print("=" * 55)
    
    evolution_report = engine.get_threat_evolution_report()
    print(f"Threat Families: {evolution_report['nodes']}")
    print(f"Evolution Relationships: {evolution_report['edges']}")
    print("\nFamily Distribution:")
    for family, info in evolution_report['threat_families'].items():
        print(f"  {family}: {info['count']} threats")