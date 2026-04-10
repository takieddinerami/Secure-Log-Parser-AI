"""
Anomaly detection results and threat classification.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
import uuid


class AnomalyType(Enum):
    """Types of security anomalies detectable by the system"""
    # Authentication anomalies
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    CREDENTIAL_STUFFING = "credential_stuffing"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    SUSPICIOUS_LOGIN_TIME = "suspicious_login_time"
    FAILED_LOGIN_ANOMALY = "failed_login_anomaly"
    
    # Privilege escalation
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUDO_ABUSE = "sudo_abuse"
    
    # Data exfiltration
    DATA_EXFILTRATION = "data_exfiltration"
    LARGE_DOWNLOAD = "large_download"
    UNUSUAL_DATA_ACCESS = "unusual_data_access"
    
    # Malware indicators
    MALWARE_BEHAVIOR = "malware_behavior"
    C2_COMMUNICATION = "c2_communication"
    SUSPICIOUS_PROCESS = "suspicious_process"
    
    # Insider threats
    INSIDER_THREAT = "insider_threat"
    OFF_HOURS_ACCESS = "off_hours_access"
    POLICY_VIOLATION = "policy_violation"
    
    # Network anomalies
    DDOS_ATTACK = "ddos_attack"
    PORT_SCAN = "port_scan"
    LATERAL_MOVEMENT = "lateral_movement"
    
    # Application attacks
    SQL_INJECTION = "sql_injection"
    XSS_ATTACK = "xss_attack"
    PATH_TRAVERSAL = "path_traversal"
    
    # Statistical anomalies
    STATISTICAL_OUTLIER = "statistical_outlier"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class Evidence:
    """
    Individual evidence contributing to anomaly detection.
    Used for explanation generation.
    """
    rule_id: str
    rule_name: str
    description: str
    certainty: float  # 0.0 - 1.0
    matched_facts: List[str] = field(default_factory=list)
    contributing_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'description': self.description,
            'certainty': round(self.certainty, 3),
            'matched_facts': self.matched_facts,
            'contributing_attributes': self.contributing_attributes
        }


@dataclass
class Anomaly:
    """
    Detected anomaly with full explanation and evidence.
    """
    # Identification
    anomaly_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    anomaly_type: AnomalyType = AnomalyType.UNKNOWN
    
    # Detection metadata
    detected_at: datetime = field(default_factory=datetime.now)
    detection_layer: str = ""  # 'signature', 'statistical', 'behavioral', 'meta'
    
    # Affected entities
    source_events: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    
    # Scoring
    threat_level: ThreatLevel = ThreatLevel.INFO
    threat_score: float = 0.0  # 0-100 scale
    certainty: float = 0.0  # Composite certainty factor
    
    # Evidence and explanation
    evidence: List[Evidence] = field(default_factory=list)
    explanation: str = ""
    recommendation: str = ""
    
    # Temporal context
    first_occurrence: Optional[datetime] = None
    last_occurrence: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # Rule information
    triggered_rules: List[str] = field(default_factory=list)
    
    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence and recalculate certainty"""
        self.evidence.append(evidence)
        self._update_certainty()
    
    def _update_certainty(self) -> None:
        """Update composite certainty using certainty factor algebra"""
        if not self.evidence:
            self.certainty = 0.0
            return
        
        # Combine certainties using the formula: CFcombined = CF1 + CF2 * (1 - CF1)
        combined_cf = self.evidence[0].certainty
        for ev in self.evidence[1:]:
            combined_cf = combined_cf + ev.certainty * (1 - combined_cf)
        
        self.certainty = min(1.0, combined_cf)
    
    def calculate_threat_score(self) -> float:
        """Calculate overall threat score (0-100)"""
        base_score = self.threat_level.value * 20  # 20, 40, 60, 80, 100
        
        # Adjust by certainty
        adjusted_score = base_score * self.certainty
        
        # Boost for multiple evidence sources
        evidence_boost = min(len(self.evidence) * 5, 20)
        
        self.threat_score = min(100, adjusted_score + evidence_boost)
        return self.threat_score
    
    def generate_explanation(self) -> str:
        """Generate natural language explanation of the anomaly"""
        parts = []
        
        # Header
        parts.append(f"ANOMALY DETECTED: {self.anomaly_type.value.replace('_', ' ').title()}")
        parts.append(f"Threat Level: {self.threat_level.name} (Score: {self.threat_score:.1f}/100)")
        parts.append(f"Certainty: {self.certainty*100:.1f}%")
        parts.append("")
        
        # Description
        parts.append(f"Detection Method: {self.detection_layer.replace('_', ' ').title()}")
        parts.append(f"Affected Users: {', '.join(self.affected_users) if self.affected_users else 'N/A'}")
        parts.append(f"Source IPs: {', '.join(self.source_ips) if self.source_ips else 'N/A'}")
        parts.append("")
        
        # Evidence breakdown
        parts.append("Evidence:")
        for i, ev in enumerate(self.evidence, 1):
            parts.append(f"  {i}. {ev.rule_name} (CF: {ev.certainty*100:.1f}%)")
            parts.append(f"     {ev.description}")
        
        # Recommendation
        if self.recommendation:
            parts.append("")
            parts.append(f"Recommendation: {self.recommendation}")
        
        self.explanation = "\n".join(parts)
        return self.explanation
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'anomaly_id': self.anomaly_id,
            'anomaly_type': self.anomaly_type.value,
            'detected_at': self.detected_at.isoformat(),
            'detection_layer': self.detection_layer,
            'threat_level': self.threat_level.name,
            'threat_score': round(self.threat_score, 2),
            'certainty': round(self.certainty, 3),
            'affected_users': self.affected_users,
            'source_ips': self.source_ips,
            'affected_systems': self.affected_systems,
            'evidence': [e.to_dict() for e in self.evidence],
            'explanation': self.explanation,
            'recommendation': self.recommendation,
            'triggered_rules': self.triggered_rules
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Anomaly':
        """Create Anomaly from dictionary"""
        anomaly = cls(
            anomaly_id=data.get('anomaly_id', str(uuid.uuid4())[:8]),
            anomaly_type=AnomalyType(data.get('anomaly_type', 'unknown')),
            detected_at=datetime.fromisoformat(data['detected_at']),
            detection_layer=data.get('detection_layer', ''),
            threat_level=ThreatLevel[data.get('threat_level', 'INFO')],
            threat_score=data.get('threat_score', 0.0),
            certainty=data.get('certainty', 0.0),
            affected_users=data.get('affected_users', []),
            source_ips=data.get('source_ips', []),
            affected_systems=data.get('affected_systems', []),
            explanation=data.get('explanation', ''),
            recommendation=data.get('recommendation', ''),
            triggered_rules=data.get('triggered_rules', [])
        )
        
        # Reconstruct evidence
        for ev_data in data.get('evidence', []):
            evidence = Evidence(
                rule_id=ev_data['rule_id'],
                rule_name=ev_data['rule_name'],
                description=ev_data['description'],
                certainty=ev_data['certainty'],
                matched_facts=ev_data.get('matched_facts', []),
                contributing_attributes=ev_data.get('contributing_attributes', {})
            )
            anomaly.evidence.append(evidence)
        
        return anomaly
