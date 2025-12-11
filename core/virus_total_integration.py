"""
VirusTotal API Integration for AegisAI
Provides additional threat intelligence by querying VirusTotal database
"""

import os
import sys
import json
import logging
import hashlib
import requests
import time
from typing import Dict, List, Optional
from pathlib import Path

# Add the core directory to the path
sys.path.insert(0, str(Path(__file__).parent))

logger = logging.getLogger(__name__)

class VirusTotalIntegration:
    """Integrate with VirusTotal API for enhanced threat intelligence"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal integration
        
        Args:
            api_key: VirusTotal API key (can also be set via VIRUSTOTAL_API_KEY environment variable)
        """
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({
                'x-apikey': self.api_key,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            })
            logger.info("VirusTotal integration initialized with API key")
        else:
            logger.warning("No VirusTotal API key provided. Integration will be limited.")
    
    def calculate_file_hash(self, file_path: str) -> Optional[str]:
        """
        Calculate SHA-256 hash of a file
        
        Args:
            file_path: Path to file
            
        Returns:
            SHA-256 hash of file or None if error
        """
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate file hash for {file_path}: {e}")
            return None
    
    def query_file_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Query VirusTotal for file hash information
        
        Args:
            file_hash: SHA-256 hash of file
            
        Returns:
            Dictionary with VirusTotal response or None if error/unavailable
        """
        if not self.api_key:
            logger.warning("No API key available for VirusTotal integration")
            return None
        
        if not file_hash:
            logger.error("No file hash provided")
            return None
        
        try:
            # Query VirusTotal for file hash
            url = f"{self.base_url}/files/{file_hash}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data
            elif response.status_code == 404:
                # File not found in VirusTotal database
                logger.info(f"File hash {file_hash} not found in VirusTotal database")
                return {
                    'not_found': True,
                    'hash': file_hash
                }
            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to query VirusTotal API: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse VirusTotal response: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal: {e}")
            return None
    
    def analyze_file_report(self, report: Dict) -> Dict:
        """
        Analyze VirusTotal file report to extract threat intelligence
        
        Args:
            report: VirusTotal file report
            
        Returns:
            Dictionary with analyzed threat intelligence
        """
        if not report:
            return {'status': 'error', 'error': 'No report provided'}
        
        if report.get('not_found'):
            return {
                'status': 'clean',
                'hash': report.get('hash'),
                'verdict': 'not_found',
                'threat_level': 0,
                'confidence': 0.0
            }
        
        try:
            # Extract data from report
            data = report.get('data', {})
            attributes = data.get('attributes', {})
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            last_analysis_results = attributes.get('last_analysis_results', {})
            reputation = attributes.get('reputation', 0)
            first_submission_date = attributes.get('first_submission_date', 0)
            
            # Calculate threat metrics
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            undetected_count = last_analysis_stats.get('undetected', 0)
            total_engines = malicious_count + suspicious_count + undetected_count + \
                           last_analysis_stats.get('harmless', 0) + \
                           last_analysis_stats.get('failure', 0)
            
            # Calculate threat level (0-10)
            if total_engines > 0:
                threat_ratio = (malicious_count + suspicious_count) / total_engines
                threat_level = min(10, int(threat_ratio * 10))
                confidence = min(1.0, (malicious_count + suspicious_count) / max(1, total_engines * 0.1))
            else:
                threat_level = 0
                confidence = 0.0
            
            # Determine verdict
            if malicious_count > 5:
                verdict = 'malicious'
            elif malicious_count > 0 or suspicious_count > 3:
                verdict = 'suspicious'
            else:
                verdict = 'clean'
            
            # Extract threat names from positive detections
            threat_names = []
            for engine, result in last_analysis_results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    threat_name = result.get('result')
                    if threat_name and threat_name not in threat_names:
                        threat_names.append(threat_name)
            
            # Create threat intelligence result
            threat_intel = {
                'status': 'success',
                'hash': data.get('id'),
                'verdict': verdict,
                'threat_level': threat_level,
                'confidence': confidence,
                'malicious_engines': malicious_count,
                'suspicious_engines': suspicious_count,
                'total_engines': total_engines,
                'reputation': reputation,
                'first_seen': first_submission_date,
                'threat_names': threat_names[:10],  # Limit to top 10 threat names
                'raw_report': report if logger.level <= logging.DEBUG else None
            }
            
            return threat_intel
            
        except Exception as e:
            logger.error(f"Failed to analyze VirusTotal report: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def scan_file_with_virustotal(self, file_path: str) -> Optional[Dict]:
        """
        Upload file to VirusTotal for scanning (if API key allows)
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Dictionary with scan results or None if error
        """
        if not self.api_key:
            logger.warning("No API key available for file upload")
            return None
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return None
        
        try:
            # Check file size (VirusTotal has limits)
            file_size = os.path.getsize(file_path)
            if file_size > 32 * 1024 * 1024:  # 32MB limit
                logger.warning(f"File too large for VirusTotal upload: {file_path} ({file_size} bytes)")
                return None
            
            # Calculate file hash first to check if already analyzed
            file_hash = self.calculate_file_hash(file_path)
            if file_hash:
                existing_report = self.query_file_hash(file_hash)
                if existing_report and not existing_report.get('not_found'):
                    logger.info(f"File already analyzed in VirusTotal: {file_hash}")
                    return self.analyze_file_report(existing_report)
            
            # Upload file for analysis
            url = f"{self.base_url}/files"
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = self.session.post(url, files=files, timeout=60)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                if analysis_id:
                    logger.info(f"File uploaded to VirusTotal, analysis ID: {analysis_id}")
                    # In a real implementation, we would poll for results
                    # For now, we'll return a pending status
                    return {
                        'status': 'pending',
                        'analysis_id': analysis_id,
                        'message': 'File uploaded for analysis. Check back later for results.'
                    }
                else:
                    logger.error("Failed to get analysis ID from VirusTotal response")
                    return None
            else:
                logger.error(f"VirusTotal file upload error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload file to VirusTotal: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error uploading file to VirusTotal: {e}")
            return None
    
    def get_ip_address_report(self, ip_address: str) -> Optional[Dict]:
        """
        Get VirusTotal report for an IP address
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Dictionary with IP report or None if error
        """
        if not self.api_key:
            logger.warning("No API key available for IP address lookup")
            return None
        
        try:
            url = f"{self.base_url}/ip_addresses/{ip_address}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"IP address {ip_address} not found in VirusTotal database")
                return None
            else:
                logger.error(f"VirusTotal IP API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to query VirusTotal IP API: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal IP API: {e}")
            return None
    
    def get_domain_report(self, domain: str) -> Optional[Dict]:
        """
        Get VirusTotal report for a domain
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dictionary with domain report or None if error
        """
        if not self.api_key:
            logger.warning("No API key available for domain lookup")
            return None
        
        try:
            url = f"{self.base_url}/domains/{domain}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                logger.info(f"Domain {domain} not found in VirusTotal database")
                return None
            else:
                logger.error(f"VirusTotal domain API error: {response.status_code} - {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to query VirusTotal domain API: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal domain API: {e}")
            return None
    
    def is_api_available(self) -> bool:
        """
        Check if VirusTotal API is available and properly configured
        
        Returns:
            True if API is available, False otherwise
        """
        return self.api_key is not None and len(self.api_key) > 0

def main():
    """Main function to demonstrate VirusTotal integration"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("           AEGISAI VIRUSTOTAL INTEGRATION DEMO")
    print("=" * 70)
    
    # Initialize VirusTotal integration
    vt = VirusTotalIntegration()
    
    if not vt.is_api_available():
        print("⚠️  VirusTotal API key not configured")
        print("   To use VirusTotal integration, set the VIRUSTOTAL_API_KEY environment variable")
        print("   or pass it to the VirusTotalIntegration constructor")
        return
    
    print("✅ VirusTotal integration initialized")
    
    # Example: Query a known test file hash (EICAR test file)
    print("\nTesting VirusTotal hash lookup...")
    eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    report = vt.query_file_hash(eicar_hash)
    
    if report:
        if report.get('not_found'):
            print("ℹ️  EICAR test file not found in VirusTotal (this is unexpected)")
        else:
            analysis = vt.analyze_file_report(report)
            print(f"🔍 EICAR test file analysis:")
            print(f"   Verdict: {analysis.get('verdict')}")
            print(f"   Threat Level: {analysis.get('threat_level')}/10")
            print(f"   Confidence: {analysis.get('confidence'):.2f}")
            print(f"   Malicious Engines: {analysis.get('malicious_engines')}")
            print(f"   Threat Names: {', '.join(analysis.get('threat_names', []))}")
    else:
        print("❌ Failed to query VirusTotal for EICAR test file")
    
    print("\n" + "=" * 70)
    print("VIRUSTOTAL INTEGRATION DEMO COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()