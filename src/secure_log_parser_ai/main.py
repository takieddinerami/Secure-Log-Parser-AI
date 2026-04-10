"""
Secure-Log-Parser-AI: Main system integration.
Orchestrates the complete log analysis pipeline.
"""
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json

try:
    from .models.log_event import LogEvent
    from .models.fact import Fact, WorkingMemory
    from .models.anomaly import Anomaly
    from .knowledge_base.rule_base import RuleBase
    from .knowledge_base.ontology import SecurityOntology, EventOntology
    from .knowledge_base.certainties import CertaintyFactorAlgebra
    from .inference_engine.forward_chainer import ForwardChainer, InferenceResult
    from .inference_engine.pattern_matcher import PatternMatcher
    from .inference_engine.explainer import Explainer
    from .parsers.json_parser import JSONLogParser, CloudTrailParser
    from .parsers.xml_parser import XMLLogParser, CEFParser
    from .parsers.normalizer import LogNormalizer
    from .detection.signature_based import SignatureDetector
    from .detection.statistical import StatisticalDetector
    from .detection.behavioral import BehavioralDetector
    from .detection.uncertainty import UncertaintyHandler
    from .utils.feature_engineering import FeatureExtractor
except ImportError:
    from models.log_event import LogEvent
    from models.fact import Fact, WorkingMemory
    from models.anomaly import Anomaly
    from knowledge_base.rule_base import RuleBase
    from knowledge_base.ontology import SecurityOntology, EventOntology
    from knowledge_base.certainties import CertaintyFactorAlgebra
    from inference_engine.forward_chainer import ForwardChainer, InferenceResult
    from inference_engine.pattern_matcher import PatternMatcher
    from inference_engine.explainer import Explainer
    from parsers.json_parser import JSONLogParser, CloudTrailParser
    from parsers.xml_parser import XMLLogParser, CEFParser
    from parsers.normalizer import LogNormalizer
    from detection.signature_based import SignatureDetector
    from detection.statistical import StatisticalDetector
    from detection.behavioral import BehavioralDetector
    from detection.uncertainty import UncertaintyHandler
    from utils.feature_engineering import FeatureExtractor


@dataclass
class AnalysisResult:
    """Complete result of log analysis"""
    anomalies: List[Anomaly] = field(default_factory=list)
    inference_result: Optional[InferenceResult] = None
    processed_events: int = 0
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'anomalies': [a.to_dict() for a in self.anomalies],
            'processed_events': self.processed_events,
            'execution_time_ms': self.execution_time_ms,
            'anomaly_count': len(self.anomalies),
            'metadata': self.metadata
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class SecureLogParserAI:
    """
    Main class for Secure-Log-Parser-AI system.
    
    Implements the complete pipeline:
    1. Parse: Convert raw logs to unified format
    2. Normalize: Schema unification
    3. Feature Extract: Extract temporal, frequency, behavioral features
    4. Detect: Multi-layer detection (signature, statistical, behavioral)
    5. Infer: Expert system inference
    6. Explain: Generate explanations
    
    Architecture:
    - Expert System shell pattern
    - Pipeline pattern for processing
    - Strategy pattern for detection algorithms
    """
    
    def __init__(self):
        # Knowledge base components
        self.rule_base = RuleBase()
        self.security_ontology = SecurityOntology()
        self.event_ontology = EventOntology()
        
        # Working memory
        self.working_memory = WorkingMemory()
        
        # Inference engine
        self.inference_engine = ForwardChainer(self.rule_base, self.working_memory)
        self.pattern_matcher = PatternMatcher(use_rete=True)
        self.explainer = Explainer()
        
        # Parsers
        self.json_parser = JSONLogParser()
        self.xml_parser = XMLLogParser()
        self.normalizer = LogNormalizer()
        
        # Detection layers
        self.signature_detector = SignatureDetector()
        self.statistical_detector = StatisticalDetector()
        self.behavioral_detector = BehavioralDetector()
        self.uncertainty_handler = UncertaintyHandler()
        
        # Feature extraction
        self.feature_extractor = FeatureExtractor()
        
        # Configuration
        self.detection_layers = {
            'signature': True,
            'statistical': True,
            'behavioral': True,
            'inference': True
        }
    
    def analyze_file(self, filepath: Union[str, Path], 
                     file_format: Optional[str] = None) -> AnalysisResult:
        """
        Analyze a log file.
        
        Args:
            filepath: Path to log file
            file_format: Optional format hint ('json', 'xml', 'cef')
        
        Returns:
            AnalysisResult with detected anomalies
        """
        import time
        start_time = time.time()
        
        # Parse file
        events = self._parse_file(filepath, file_format)
        
        # Analyze events
        result = self.analyze_events(events)
        
        result.execution_time_ms = (time.time() - start_time) * 1000
        return result
    
    def analyze_events(self, events: List[LogEvent]) -> AnalysisResult:
        """
        Analyze a list of log events.
        
        Args:
            events: List of LogEvent objects
        
        Returns:
            AnalysisResult with detected anomalies
        """
        import time
        start_time = time.time()
        
        result = AnalysisResult()
        result.processed_events = len(events)
        
        if not events:
            return result
        
        # Normalize events
        normalized_events = self.normalizer.normalize_batch(events)
        
        # Extract features
        for event in normalized_events:
            features = self.feature_extractor.extract_features(event)
            event.frequency_features = {
                k: v for k, v in features.items() 
                if k.startswith('freq_')
            }
            event.behavioral_features = {
                k: v for k, v in features.items()
                if k.startswith('behavior_')
            }
        
        # Layer 1: Signature-based detection
        if self.detection_layers['signature']:
            sig_anomalies = self.signature_detector.detect_batch(normalized_events)
            result.anomalies.extend(sig_anomalies)
        
        # Layer 2: Statistical detection
        if self.detection_layers['statistical']:
            stat_anomalies = self.statistical_detector.detect_batch(normalized_events)
            result.anomalies.extend(stat_anomalies)
        
        # Layer 3: Behavioral detection
        if self.detection_layers['behavioral']:
            beh_anomalies = self.behavioral_detector.detect_batch(normalized_events)
            result.anomalies.extend(beh_anomalies)
        
        # Convert events to facts and assert to working memory
        self._assert_events_as_facts(normalized_events)
        
        # Layer 4: Expert system inference
        if self.detection_layers['inference']:
            inference_result = self.inference_engine.infer()
            result.inference_result = inference_result
            result.anomalies.extend(inference_result.anomalies)
        
        # Meta-reasoning: Aggregate and resolve uncertainties
        result.anomalies = self._aggregate_anomalies(result.anomalies)
        
        # Apply uncertainty handling
        for anomaly in result.anomalies:
            # Calculate composite threat score
            anomaly.threat_score = self.uncertainty_handler.calculate_composite_threat_score(
                anomaly,
                {'indicator_count': len(anomaly.evidence)}
            )
            
            # Handle incomplete data
            missing = self._check_missing_data(anomaly)
            if missing:
                anomaly = self.uncertainty_handler.handle_incomplete_data(anomaly, missing)
        
        # Sort by threat score
        result.anomalies.sort(key=lambda a: a.threat_score, reverse=True)
        
        result.execution_time_ms = (time.time() - start_time) * 1000
        
        # Add metadata
        result.metadata = {
            'working_memory_facts': self.working_memory.size(),
            'rules_fired': len(result.inference_result.fired_rules) if result.inference_result else 0,
            'detection_layers': self.detection_layers
        }
        
        return result
    
    def _parse_file(self, filepath: Union[str, Path], 
                    file_format: Optional[str] = None) -> List[LogEvent]:
        """Parse log file based on format"""
        path = Path(filepath)
        
        # Detect format from extension if not specified
        if not file_format:
            ext = path.suffix.lower()
            if ext == '.json':
                file_format = 'json'
            elif ext in ['.xml', '.evtx']:
                file_format = 'xml'
            else:
                file_format = 'json'  # Default
        
        # Parse based on format
        if file_format == 'json':
            return self.json_parser.parse_file(path)
        elif file_format == 'xml':
            return self.xml_parser.parse_file(path)
        elif file_format == 'cloudtrail':
            parser = CloudTrailParser()
            return parser.parse_file(path)
        elif file_format == 'cef':
            # CEF is typically in text files, read and parse
            events = []
            with open(path, 'r') as f:
                for line in f:
                    parser = CEFParser()
                    event = parser.parse_cef_string(line.strip())
                    if event:
                        events.append(event)
            return events
        else:
            raise ValueError(f"Unsupported file format: {file_format}")
    
    def _assert_events_as_facts(self, events: List[LogEvent]) -> None:
        """Convert events to facts and assert to working memory"""
        for event in events:
            # Create facts from event attributes
            facts = self._event_to_facts(event)
            for fact in facts:
                self.working_memory.assert_fact(fact)
    
    def _event_to_facts(self, event: LogEvent) -> List[Fact]:
        """Convert a log event to a list of facts"""
        facts = []
        
        # Event type fact
        if event.frame and event.frame.event_type:
            facts.append(Fact.create(
                fact_type='event',
                subject=event.user_id or 'system',
                predicate='event_type',
                value=event.frame.event_type.value,
                source_event_id=event.event_id,
                timestamp=event.timestamp
            ))
        
        # Temporal facts
        if event.time_features:
            for key, value in event.time_features.items():
                facts.append(Fact.create(
                    fact_type='temporal',
                    subject=event.event_id,
                    predicate=key,
                    value=value,
                    source_event_id=event.event_id
                ))
        
        # Source IP fact
        if event.source_ip:
            facts.append(Fact.create(
                fact_type='network',
                subject=event.source_ip,
                predicate='source_of',
                value=event.event_id,
                source_event_id=event.event_id,
                metadata={'user_id': event.user_id}
            ))
        
        # User fact
        if event.user_id:
            facts.append(Fact.create(
                fact_type='user',
                subject=event.user_id,
                predicate='generated_event',
                value=event.event_id,
                source_event_id=event.event_id,
                metadata={'source_ip': event.source_ip}
            ))
        
        # Frequency facts
        if event.frequency_features:
            for key, value in event.frequency_features.items():
                facts.append(Fact.create(
                    fact_type='frequency',
                    subject=event.event_id,
                    predicate=key,
                    value=value,
                    source_event_id=event.event_id
                ))
        
        return facts
    
    def _aggregate_anomalies(self, anomalies: List[Anomaly]) -> List[Anomaly]:
        """Aggregate and deduplicate anomalies"""
        if not anomalies:
            return []
        
        # Group by anomaly type and affected entities
        groups: Dict[str, List[Anomaly]] = {}
        
        for anomaly in anomalies:
            # Create grouping key
            key_parts = [anomaly.anomaly_type.value]
            if anomaly.affected_users:
                key_parts.append(','.join(sorted(anomaly.affected_users)))
            if anomaly.source_ips:
                key_parts.append(','.join(sorted(anomaly.source_ips)))
            
            key = '|'.join(key_parts)
            
            if key not in groups:
                groups[key] = []
            groups[key].append(anomaly)
        
        # Aggregate each group
        aggregated = []
        for group_anomalies in groups.values():
            if len(group_anomalies) == 1:
                aggregated.append(group_anomalies[0])
            else:
                # Use uncertainty handler to aggregate
                combined = self.uncertainty_handler.aggregate_multi_source_evidence(
                    group_anomalies,
                    source_weights={
                        'signature': 1.0,
                        'statistical': 0.8,
                        'behavioral': 0.9,
                        'inference': 1.0
                    }
                )
                aggregated.append(combined)
        
        return aggregated
    
    def _check_missing_data(self, anomaly: Anomaly) -> List[str]:
        """Check for missing data in anomaly"""
        missing = []
        
        if not anomaly.affected_users:
            missing.append('user_id')
        if not anomaly.source_ips:
            missing.append('source_ip')
        
        return missing
    
    def get_explanation(self, anomaly_id: str) -> Optional[str]:
        """Get explanation for a specific anomaly"""
        # This would require storing anomalies or searching through results
        return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics"""
        return {
            'knowledge_base': {
                'total_rules': len(self.rule_base.get_all_rules()),
                'rule_statistics': self.rule_base.get_statistics()
            },
            'working_memory': self.working_memory.get_statistics(),
            'inference_engine': self.inference_engine.get_explanation(),
            'detectors': {
                'signatures': self.signature_detector.get_statistics(),
                'statistical': self.statistical_detector.get_baseline_statistics(),
                'behavioral': self.behavioral_detector.get_statistics()
            },
            'parsers': {
                'json': self.json_parser.get_statistics(),
                'xml': self.xml_parser.get_statistics()
            }
        }
    
    def reset(self) -> None:
        """Reset system state"""
        self.working_memory.clear()
        self.inference_engine.reset()
        self.statistical_detector = StatisticalDetector()
        self.behavioral_detector = BehavioralDetector()
    
    def configure_detection(self, **layers) -> None:
        """Configure which detection layers are enabled"""
        for layer, enabled in layers.items():
            if layer in self.detection_layers:
                self.detection_layers[layer] = enabled
