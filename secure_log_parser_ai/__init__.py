"""
Secure-Log-Parser-AI: AI-powered anomaly detection for security logs

A Python-based expert system implementing rule-based detection with 
probabilistic reasoning for cybersecurity log analysis.

Core Components:
- Knowledge Base: Production rules, ontology, certainty factors
- Inference Engine: Forward chaining with conflict resolution
- Detection Layers: Signature, statistical, behavioral, meta-reasoning
- Parsers: JSON, XML, and syslog format support
"""

__version__ = '1.0.0'
__author__ = 'AI Security Research'

from .main import SecureLogParserAI, AnalysisResult

__all__ = [
    'SecureLogParserAI',
    'AnalysisResult'
]
