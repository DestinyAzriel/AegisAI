"""
AegisAI Core Antivirus Engine
============================

This package contains the core components of the AegisAI antivirus engine,
including the scanning engine, real-time protection mechanisms, and endpoint agents.
"""

from .agent import AgentInterface
from .yara_scanner import YaraScanner
from .behavioral_analyzer import BehavioralAnalyzer
from .predictive_threat_intelligence import PredictiveThreatIntelligenceEngine

__all__ = [
    'AgentInterface',
    'YaraScanner',
    'BehavioralAnalyzer',
    'PredictiveThreatIntelligenceEngine'
]