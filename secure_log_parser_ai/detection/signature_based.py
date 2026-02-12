"""
Signature-based detection layer.
Implements exact pattern matching and regular expression rules.
"""
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict

from ..models.log_event import LogEvent
from ..models.anomaly import Anomaly, AnomalyType, ThreatLevel, Evidence


@dataclass
class SignatureRule:
    """Signature detection rule"""
    rule_id: str
    name: str
    pattern: str  # Regex pattern
    anomaly_type: AnomalyType
    threat_level: ThreatLevel
    description: str
    certainty: float = 1.0
    enabled: bool = True


class SignatureDetector:
    """
    Signature-based detection using pattern matching.
    
    Layer 1 of the detection pipeline.
    - Exact pattern matching for known attack signatures
    - Regular expression rules for log message analysis
    - Fast detection of known threats
    
    Complexity: O(n × m) where n = events, m = signatures
    """
    
    def __init__(self):
        self.signatures: List[SignatureRule] = []
        self._compiled_patterns: Dict[str, re.Pattern] = {}
        self._build_signatures()
    
    def _build_signatures(self) -> None:
        """Build the signature database"""
        
        # Authentication attack signatures
        auth_signatures = [
            SignatureRule(
                rule_id='SIG-AUTH-001',
                name='SSH Brute Force Pattern',
                pattern=r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)',
                anomaly_type=AnomalyType.BRUTE_FORCE_ATTACK,
                threat_level=ThreatLevel.HIGH,
                description='Multiple SSH authentication failures indicating brute force',
                certainty=0.85
            ),
            SignatureRule(
                rule_id='SIG-AUTH-002',
                name='Credential Stuffing Pattern',
                pattern=r'(login|auth).*failed.*user.*password',
                anomaly_type=AnomalyType.CREDENTIAL_STUFFING,
                threat_level=ThreatLevel.HIGH,
                description='Rapid authentication attempts with different credentials',
                certainty=0.80
            ),
            SignatureRule(
                rule_id='SIG-AUTH-003',
                name='Default Credential Attempt',
                pattern=r'(admin|root|test|guest|user).*password.*(admin|123456|password)',
                anomaly_type=AnomalyType.BRUTE_FORCE_ATTACK,
                threat_level=ThreatLevel.MEDIUM,
                description='Attempt to login with default/weak credentials',
                certainty=0.75
            ),
        ]
        
        # Web attack signatures
        web_signatures = [
            SignatureRule(
                rule_id='SIG-WEB-001',
                name='SQL Injection Attempt',
                pattern=r'(union\s+select|insert\s+into|delete\s+from|drop\s+table|' +
                       r"'\s+or\s+'|';\s*--|\d+\s*=\s*\d+)",
                anomaly_type=AnomalyType.SQL_INJECTION,
                threat_level=ThreatLevel.CRITICAL,
                description='SQL injection pattern detected in request',
                certainty=0.90
            ),
            SignatureRule(
                rule_id='SIG-WEB-002',
                name='XSS Attempt',
                pattern=r'(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)',
                anomaly_type=AnomalyType.XSS_ATTACK,
                threat_level=ThreatLevel.HIGH,
                description='Cross-site scripting attempt detected',
                certainty=0.85
            ),
            SignatureRule(
                rule_id='SIG-WEB-003',
                name='Path Traversal Attempt',
                pattern=r'(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f)',
                anomaly_type=AnomalyType.PATH_TRAVERSAL,
                threat_level=ThreatLevel.HIGH,
                description='Directory traversal attack attempt',
                certainty=0.88
            ),
            SignatureRule(
                rule_id='SIG-WEB-004',
                name='Command Injection',
                pattern=r'(;\s*\||\|\s*|`.*`|\$\(.*\)|&&\s*|\|\s*bash|\|\s*sh)',
                anomaly_type=AnomalyType.MALWARE_BEHAVIOR,
                threat_level=ThreatLevel.CRITICAL,
                description='Command injection attempt detected',
                certainty=0.90
            ),
        ]
        
        # Malware signatures
        malware_signatures = [
            SignatureRule(
                rule_id='SIG-MAL-001',
                name='Mimikatz Usage',
                pattern=r'mimikatz|sekurlsa::|kerberos::|lsadump::',
                anomaly_type=AnomalyType.MALWARE_BEHAVIOR,
                threat_level=ThreatLevel.CRITICAL,
                description='Credential dumping tool detected',
                certainty=0.95
            ),
            SignatureRule(
                rule_id='SIG-MAL-002',
                name='PowerShell Obfuscation',
                pattern=r'(FromBase64String|EncodedCommand|bypass.*executionpolicy|noprofile.*windowstyle)',
                anomaly_type=AnomalyType.SUSPICIOUS_PROCESS,
                threat_level=ThreatLevel.HIGH,
                description='Obfuscated PowerShell command execution',
                certainty=0.85
            ),
            SignatureRule(
                rule_id='SIG-MAL-003',
                name='Reverse Shell Pattern',
                pattern=r'(bash\s+-i|/bin/sh\s+-i|nc\s+-e|netcat.*-e|python.*-c.*socket)',
                anomaly_type=AnomalyType.C2_COMMUNICATION,
                threat_level=ThreatLevel.CRITICAL,
                description='Reverse shell connection attempt',
                certainty=0.90
            ),
            SignatureRule(
                rule_id='SIG-MAL-004',
                name='Base64 Executable',
                pattern=r'TVqQAAMAAAAEAAAA|TVqQAAMAAAAEAAAA//8AALgAAAA',
                anomaly_type=AnomalyType.MALWARE_BEHAVIOR,
                threat_level=ThreatLevel.CRITICAL,
                description='Base64 encoded Windows executable detected',
                certainty=0.92
            ),
        ]
        
        # Privilege escalation signatures
        priv_esc_signatures = [
            SignatureRule(
                rule_id='SIG-PRIV-001',
                name='Sudo Privilege Escalation',
                pattern=r'sudo:.*user NOT in sudoers|sudo:.*incorrect password attempts',
                anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                threat_level=ThreatLevel.HIGH,
                description='Unauthorized sudo attempt detected',
                certainty=0.80
            ),
            SignatureRule(
                rule_id='SIG-PRIV-002',
                name='Setuid Binary Execution',
                pattern=r'setuid|setgid|chmod.*4755|chmod.*6755',
                anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                threat_level=ThreatLevel.MEDIUM,
                description='Setuid/setgid permission modification',
                certainty=0.70
            ),
        ]
        
        # Data exfiltration signatures
        data_exfil_signatures = [
            SignatureRule(
                rule_id='SIG-DATA-001',
                name='Large Data Transfer',
                pattern=r'(download|upload).*\d{3,}MB|transferred.*\d{3,}.*bytes',
                anomaly_type=AnomalyType.LARGE_DOWNLOAD,
                threat_level=ThreatLevel.MEDIUM,
                description='Large volume data transfer detected',
                certainty=0.65
            ),
            SignatureRule(
                rule_id='SIG-DATA-002',
                name='Database Dump',
                pattern=r'(mysqldump|pg_dump|\.sql\.gz|database.*backup.*\d{4,}MB)',
                anomaly_type=AnomalyType.DATA_EXFILTRATION,
                threat_level=ThreatLevel.HIGH,
                description='Database dump activity detected',
                certainty=0.80
            ),
        ]
        
        # Network attack signatures
        network_signatures = [
            SignatureRule(
                rule_id='SIG-NET-001',
                name='Port Scan Detection',
                pattern=r'(nmap|masscan|zmap).*-(sS|sT|sU|p)',
                anomaly_type=AnomalyType.PORT_SCAN,
                threat_level=ThreatLevel.MEDIUM,
                description='Port scanning tool usage detected',
                certainty=0.85
            ),
            SignatureRule(
                rule_id='SIG-NET-002',
                name='C2 Beacon Pattern',
                pattern=r'(GET|POST)\s+/[a-f0-9]{16,}|(GET|POST)\s+/[A-Za-z0-9+/]{20,}={0,2}',
                anomaly_type=AnomalyType.C2_COMMUNICATION,
                threat_level=ThreatLevel.CRITICAL,
                description='Potential command and control beacon',
                certainty=0.75
            ),
        ]
        
        # Combine all signatures
        all_signatures = (
            auth_signatures + web_signatures + malware_signatures +
            priv_esc_signatures + data_exfil_signatures + network_signatures
        )
        
        for sig in all_signatures:
            self.add_signature(sig)
    
    def add_signature(self, signature: SignatureRule) -> None:
        """Add a signature rule"""
        self.signatures.append(signature)
        try:
            self._compiled_patterns[signature.rule_id] = re.compile(
                signature.pattern, re.IGNORECASE
            )
        except re.error as e:
            print(f"Invalid regex pattern in {signature.rule_id}: {e}")
    
    def detect(self, event: LogEvent) -> List[Anomaly]:
        """
        Detect anomalies in a single event using signatures.
        
        Returns list of detected anomalies.
        """
        anomalies = []
        
        # Get text to analyze
        text = self._get_event_text(event)
        if not text:
            return anomalies
        
        # Check each signature
        for signature in self.signatures:
            if not signature.enabled:
                continue
            
            pattern = self._compiled_patterns.get(signature.rule_id)
            if not pattern:
                continue
            
            match = pattern.search(text)
            if match:
                anomaly = self._create_anomaly(event, signature, match)
                anomalies.append(anomaly)
        
        return anomalies
    
    def detect_batch(self, events: List[LogEvent]) -> List[Anomaly]:
        """Detect anomalies in a batch of events"""
        all_anomalies = []
        for event in events:
            anomalies = self.detect(event)
            all_anomalies.extend(anomalies)
        return all_anomalies
    
    def _get_event_text(self, event: LogEvent) -> str:
        """Extract searchable text from event"""
        parts = [event.raw_log]
        
        # Add message if available
        message = event.get_attribute('message')
        if message:
            parts.append(str(message))
        
        # Add command line if available
        command = event.get_attribute('command') or event.get_attribute('command_line')
        if command:
            parts.append(str(command))
        
        # Add URL if available
        url = event.get_attribute('url') or event.get_attribute('request_url')
        if url:
            parts.append(str(url))
        
        return ' '.join(parts)
    
    def _create_anomaly(self, event: LogEvent, signature: SignatureRule, 
                        match: re.Match) -> Anomaly:
        """Create anomaly from signature match"""
        evidence = Evidence(
            rule_id=signature.rule_id,
            rule_name=signature.name,
            description=signature.description,
            certainty=signature.certainty,
            matched_facts=[event.event_id],
            contributing_attributes={
                'matched_pattern': signature.pattern,
                'matched_text': match.group(0),
                'match_groups': match.groups()
            }
        )
        
        anomaly = Anomaly(
            anomaly_type=signature.anomaly_type,
            detection_layer="signature",
            source_events=[event.event_id],
            affected_users=[event.user_id] if event.user_id else [],
            source_ips=[event.source_ip] if event.source_ip else [],
            threat_level=signature.threat_level,
            triggered_rules=[signature.rule_id],
            recommendation=f"Review signature match: {signature.name}"
        )
        
        anomaly.add_evidence(evidence)
        anomaly.calculate_threat_score()
        anomaly.generate_explanation()
        
        return anomaly
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            'total_signatures': len(self.signatures),
            'enabled_signatures': sum(1 for s in self.signatures if s.enabled),
            'by_category': self._count_by_category()
        }
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count signatures by anomaly category"""
        counts = defaultdict(int)
        for sig in self.signatures:
            counts[sig.anomaly_type.value] += 1
        return dict(counts)
