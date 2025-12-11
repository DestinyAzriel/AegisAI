"""
YARA Rule Optimizer for AegisAI
Optimizes YARA rules for faster signature matching
"""

import os
import re
import logging
from typing import Dict, List, Set
from pathlib import Path

# Add the core directory to the path
import sys
sys.path.insert(0, str(Path(__file__).parent))

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    logging.warning("YARA library not available. Install with: pip install yara-python")
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)

class YaraRuleOptimizer:
    """Optimize YARA rules for faster signature matching"""
    
    def __init__(self, rules_path: str = "yara_rules"):
        """
        Initialize YARA rule optimizer
        
        Args:
            rules_path: Path to YARA rules directory
        """
        self.rules_path = rules_path
        self.optimized_rules = {}
        self.rule_statistics = {}
    
    def analyze_rules(self) -> Dict:
        """
        Analyze YARA rules to identify optimization opportunities
        
        Returns:
            Dictionary with analysis results
        """
        if not YARA_AVAILABLE:
            logger.warning("YARA not available, skipping rule analysis")
            return {}
        
        logger.info("Analyzing YARA rules for optimization opportunities")
        
        analysis_results = {
            'total_rules': 0,
            'rules_by_type': {},
            'complexity_metrics': {},
            'optimization_opportunities': []
        }
        
        # Walk through rules directory
        if os.path.isdir(self.rules_path):
            for root, dirs, files in os.walk(self.rules_path):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                file_analysis = self._analyze_rule_file(content, file_path)
                                analysis_results['total_rules'] += file_analysis['rule_count']
                                
                                # Aggregate rule types
                                for rule_type, count in file_analysis['rule_types'].items():
                                    if rule_type in analysis_results['rules_by_type']:
                                        analysis_results['rules_by_type'][rule_type] += count
                                    else:
                                        analysis_results['rules_by_type'][rule_type] = count
                                
                                # Add optimization opportunities
                                analysis_results['optimization_opportunities'].extend(
                                    file_analysis['optimization_opportunities']
                                )
                        except Exception as e:
                            logger.error(f"Failed to analyze rule file {file_path}: {e}")
        
        return analysis_results
    
    def _analyze_rule_file(self, content: str, file_path: str) -> Dict:
        """
        Analyze a single YARA rule file
        
        Args:
            content: Content of the rule file
            file_path: Path to the rule file
            
        Returns:
            Dictionary with analysis results for this file
        """
        analysis = {
            'file_path': file_path,
            'rule_count': 0,
            'rule_types': {},
            'complexity_metrics': {},
            'optimization_opportunities': []
        }
        
        # Count rules
        rule_pattern = r'^\s*rule\s+(\w+)'
        rules = re.findall(rule_pattern, content, re.MULTILINE)
        analysis['rule_count'] = len(rules)
        
        # Identify rule types based on keywords
        rule_types = {
            'pe': r'\$.*pe\.',
            'elf': r'\$.*elf\.',
            'math': r'\$.*math\.',
            'hash': r'\$.*hash\.',
            'string': r'\$.*=\s*"',
            'hex': r'\$.*=\s*{',
            'regex': r'\$.*=\s*/'
        }
        
        for rule_type, pattern in rule_types.items():
            matches = re.findall(pattern, content, re.MULTILINE)
            analysis['rule_types'][rule_type] = len(matches)
        
        # Identify optimization opportunities
        optimization_checks = [
            {
                'name': 'Long hex strings',
                'pattern': r'\$.*=\s*{[^}]{100,}}',
                'description': 'Rules with very long hex strings can be slow to match'
            },
            {
                'name': 'Complex regex patterns',
                'pattern': r'\$.*=\s*/.*[.*+?{}]{3,}/',
                'description': 'Rules with complex regex patterns can be slow to match'
            },
            {
                'name': 'Too many strings per rule',
                'pattern': r'rule\s+\w+[^}]*strings:[^}]*\$[^}]*\$[^}]*\$[^}]*\$[^}]*\$[^}]*\$',
                'description': 'Rules with too many strings can be slow to match'
            },
            {
                'name': 'Unnecessary wildcards',
                'pattern': r'\$.*=\s*"[^"]*[*?][*?][*?][^"]*"',
                'description': 'Rules with multiple consecutive wildcards are inefficient'
            }
        ]
        
        for check in optimization_checks:
            matches = re.findall(check['pattern'], content, re.MULTILINE | re.DOTALL)
            if matches:
                analysis['optimization_opportunities'].append({
                    'file': file_path,
                    'check': check['name'],
                    'count': len(matches),
                    'description': check['description']
                })
        
        return analysis
    
    def optimize_rules(self) -> bool:
        """
        Optimize YARA rules for better performance
        
        Returns:
            True if optimization successful, False otherwise
        """
        if not YARA_AVAILABLE:
            logger.warning("YARA not available, skipping rule optimization")
            return False
        
        logger.info("Optimizing YARA rules for better performance")
        
        # Analyze rules first
        analysis = self.analyze_rules()
        
        # Apply optimizations
        optimizations_applied = 0
        
        # Walk through rules directory
        if os.path.isdir(self.rules_path):
            for root, dirs, files in os.walk(self.rules_path):
                for file in files:
                    if file.endswith(('.yar', '.yara')):
                        file_path = os.path.join(root, file)
                        try:
                            optimizations_applied += self._optimize_rule_file(file_path)
                        except Exception as e:
                            logger.error(f"Failed to optimize rule file {file_path}: {e}")
        
        logger.info(f"Applied {optimizations_applied} optimizations to YARA rules")
        return optimizations_applied > 0
    
    def _optimize_rule_file(self, file_path: str) -> int:
        """
        Optimize a single YARA rule file
        
        Args:
            file_path: Path to the rule file
            
        Returns:
            Number of optimizations applied
        """
        optimizations = 0
        
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            original_content = content
            
            # Optimization 1: Simplify hex strings by removing unnecessary wildcards
            # Replace multiple consecutive wildcards with single ones
            content = re.sub(r'\?{3,}', '??', content)
            content = re.sub(r'\*{2,}', '*', content)
            
            # Count optimizations
            if content != original_content:
                optimizations += 1
            
            # Optimization 2: Convert long hex strings to byte sequences where possible
            # This is a complex optimization that would require more sophisticated analysis
            # For now, we'll just log when we find long hex strings
            long_hex_pattern = r'(\{[^}]{200,}\})'
            long_hex_matches = re.findall(long_hex_pattern, content)
            if long_hex_matches:
                logger.info(f"Found {len(long_hex_matches)} long hex strings in {file_path}")
            
            # Write optimized content back to file if changes were made
            if content != original_content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"Optimized rule file: {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to optimize rule file {file_path}: {e}")
        
        return optimizations
    
    def compile_optimized_rules(self) -> bool:
        """
        Compile optimized YARA rules for faster matching
        
        Returns:
            True if compilation successful, False otherwise
        """
        logger.info("Compiling optimized YARA rules")
        
        # Check if YARA is available
        if not YARA_AVAILABLE:
            logger.warning("YARA not available, skipping rule compilation")
            return False
        
        try:
            # Load all .yar and .yara files in directory
            rules_dict = {}
            if os.path.isdir(self.rules_path):
                for root, dirs, files in os.walk(self.rules_path):
                    for file in files:
                        if file.endswith(('.yar', '.yara')):
                            file_path = os.path.join(root, file)
                            rule_name = os.path.splitext(file)[0]
                            rules_dict[rule_name] = file_path
            
            if rules_dict:
                # Compile rules
                compiled_rules = yara.compile(filepaths=rules_dict)
                
                # Save compiled rules to a file for faster loading
                compiled_file = os.path.join(self.rules_path, "compiled_rules.yarc")
                compiled_rules.save(compiled_file)
                logger.info(f"Compiled rules saved to {compiled_file}")
                
                return True
            else:
                logger.warning("No YARA rule files found to compile")
                return False
                
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            return False
    
    def get_rule_statistics(self) -> Dict:
        """
        Get statistics about YARA rules
        
        Returns:
            Dictionary with rule statistics
        """
        return self.rule_statistics

def main():
    """Main function to demonstrate YARA rule optimization"""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 70)
    print("           AEGISAI YARA RULE OPTIMIZER")
    print("=" * 70)
    
    # Initialize optimizer
    optimizer = YaraRuleOptimizer()
    
    # Analyze rules
    print("Analyzing YARA rules...")
    analysis = optimizer.analyze_rules()
    
    print(f"\nRule Analysis Results:")
    print(f"  Total Rules: {analysis.get('total_rules', 0)}")
    print(f"  Rule Types:")
    for rule_type, count in analysis.get('rules_by_type', {}).items():
        print(f"    {rule_type}: {count}")
    
    print(f"\nOptimization Opportunities:")
    for opportunity in analysis.get('optimization_opportunities', [])[:5]:
        print(f"  {opportunity['check']}: {opportunity['description']}")
    
    # Optimize rules
    print("\nOptimizing YARA rules...")
    success = optimizer.optimize_rules()
    if success:
        print("✅ YARA rules optimized successfully")
    else:
        print("⚠️  YARA rule optimization failed or no optimizations applied")
    
    # Compile optimized rules
    print("\nCompiling optimized rules...")
    compiled = optimizer.compile_optimized_rules()
    if compiled:
        print("✅ YARA rules compiled successfully")
    else:
        print("⚠️  YARA rule compilation failed")
    
    print("\n" + "=" * 70)
    print("YARA OPTIMIZATION COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()