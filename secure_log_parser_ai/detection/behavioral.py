"""
Behavioral analysis detection layer.
Implements User/Entity Behavior Analytics (UEBA) concepts.
"""
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta
import math

from ..models.log_event import LogEvent, EventType
from ..models.anomaly import Anomaly, AnomalyType, ThreatLevel, Evidence


@dataclass
class UserProfile:
    """Behavioral profile for a user"""
    user_id: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    
    # Temporal patterns
    typical_hours: List[int] = field(default_factory=list)
    typical_days: List[int] = field(default_factory=list)  # 0=Monday
    weekend_access_frequency: float = 0.0
    night_access_frequency: float = 0.0
    
    # Activity patterns
    common_services: List[str] = field(default_factory=list)
    common_source_ips: List[str] = field(default_factory=list)
    common_event_types: List[EventType] = field(default_factory=list)
    
    # Access patterns
    accessed_resources: Set[str] = field(default_factory=set)
    failed_login_rate: float = 0.0
    
    # Statistics
    total_events: int = 0
    session_count: int = 0
    
    def update(self, event: LogEvent) -> None:
        """Update profile with new event"""
        self.last_seen = event.timestamp
        self.total_events += 1
        
        # Update temporal patterns
        hour = event.timestamp.hour
        day = event.timestamp.weekday()
        
        if hour not in self.typical_hours:
            self.typical_hours.append(hour)
        if day not in self.typical_days:
            self.typical_days.append(day)
        
        # Update service patterns
        if event.service and event.service not in self.common_services:
            self.common_services.append(event.service)
        
        # Update IP patterns
        if event.source_ip and event.source_ip not in self.common_source_ips:
            self.common_source_ips.append(event.source_ip)
        
        # Update event type patterns
        if event.frame and event.frame.event_type not in self.common_event_types:
            self.common_event_types.append(event.frame.event_type)
    
    def calculate_deviation_score(self, event: LogEvent) -> float:
        """
        Calculate how much an event deviates from the profile.
        Returns score between 0 (normal) and 1 (highly anomalous).
        """
        if self.total_events < 10:
            return 0.0  # Not enough data
        
        deviations = []
        
        # Check temporal deviation
        hour = event.timestamp.hour
        if self.typical_hours and hour not in self.typical_hours:
            deviations.append(0.3)
        
        # Check service deviation
        if event.service and self.common_services:
            if event.service not in self.common_services:
                deviations.append(0.4)
        
        # Check source IP deviation
        if event.source_ip and self.common_source_ips:
            if event.source_ip not in self.common_source_ips:
                deviations.append(0.5)
        
        # Check event type deviation
        if event.frame and self.common_event_types:
            if event.frame.event_type not in self.common_event_types:
                deviations.append(0.3)
        
        # Combine deviations
        if not deviations:
            return 0.0
        
        return min(1.0, sum(deviations))


@dataclass
class SequencePattern:
    """Pattern for sequence-based detection"""
    name: str
    sequence: List[str]  # Ordered list of event types
    max_time_window: timedelta = field(default_factory=lambda: timedelta(minutes=10))
    certainty: float = 0.8


class BehavioralDetector:
    """
    Behavioral analysis detection layer.
    
    Layer 3 of the detection pipeline.
    - User/Entity Behavior Analytics (UEBA)
    - Sequence pattern matching
    - Peer group analysis
    - Deviation scoring
    
    Complexity: O(1) per event for profile update, O(n) for sequence matching
    """
    
    def __init__(self):
        # User profiles
        self.user_profiles: Dict[str, UserProfile] = {}
        
        # IP profiles (for entity behavior)
        self.ip_profiles: Dict[str, UserProfile] = {}
        
        # Recent events for sequence analysis
        self.recent_events: List[LogEvent] = []
        self.max_recent_events = 1000
        
        # Sequence patterns for attack chain detection
        self.sequence_patterns: List[SequencePattern] = []
        self._build_sequence_patterns()
        
        # Peer groups (users with similar roles)
        self.peer_groups: Dict[str, List[str]] = defaultdict(list)
    
    def _build_sequence_patterns(self) -> None:
        """Build attack sequence patterns"""
        patterns = [
            SequencePattern(
                name='Lateral Movement Chain',
                sequence=['authentication', 'network_connection', 'authentication', 'network_connection'],
                max_time_window=timedelta(minutes=30),
                certainty=0.75
            ),
            SequencePattern(
                name='Privilege Escalation Chain',
                sequence=['authentication', 'privilege_escalation', 'authorization'],
                max_time_window=timedelta(minutes=15),
                certainty=0.80
            ),
            SequencePattern(
                name='Data Exfiltration Chain',
                sequence=['authentication', 'data_access', 'data_access', 'network_connection'],
                max_time_window=timedelta(hours=1),
                certainty=0.70
            ),
        ]
        
        self.sequence_patterns = patterns
    
    def update_profile(self, event: LogEvent) -> None:
        """Update behavioral profile with new event"""
        # Update user profile
        if event.user_id:
            if event.user_id not in self.user_profiles:
                self.user_profiles[event.user_id] = UserProfile(user_id=event.user_id)
            self.user_profiles[event.user_id].update(event)
        
        # Update IP profile
        if event.source_ip:
            if event.source_ip not in self.ip_profiles:
                self.ip_profiles[event.source_ip] = UserProfile(user_id=event.source_ip)
            self.ip_profiles[event.source_ip].update(event)
        
        # Add to recent events
        self.recent_events.append(event)
        if len(self.recent_events) > self.max_recent_events:
            self.recent_events.pop(0)
    
    def detect(self, event: LogEvent) -> List[Anomaly]:
        """
        Detect behavioral anomalies.
        
        Returns list of detected anomalies.
        """
        anomalies = []
        
        # Update profiles first
        self.update_profile(event)
        
        # Check user behavior deviation
        if event.user_id:
            user_anomaly = self._check_user_deviation(event)
            if user_anomaly:
                anomalies.append(user_anomaly)
        
        # Check sequence patterns
        sequence_anomalies = self._check_sequence_patterns(event)
        anomalies.extend(sequence_anomalies)
        
        # Check peer group deviation
        if event.user_id:
            peer_anomaly = self._check_peer_deviation(event)
            if peer_anomaly:
                anomalies.append(peer_anomaly)
        
        return anomalies
    
    def detect_batch(self, events: List[LogEvent]) -> List[Anomaly]:
        """Detect anomalies in a batch of events"""
        anomalies = []
        
        # First pass: build profiles
        for event in events:
            self.update_profile(event)
        
        # Second pass: detect anomalies
        for event in events:
            event_anomalies = self.detect(event)
            anomalies.extend(event_anomalies)
        
        return anomalies
    
    def _check_user_deviation(self, event: LogEvent) -> Optional[Anomaly]:
        """Check if event deviates from user's normal behavior"""
        if not event.user_id:
            return None
        
        profile = self.user_profiles.get(event.user_id)
        if not profile or profile.total_events < 10:
            return None
        
        deviation_score = profile.calculate_deviation_score(event)
        
        if deviation_score > 0.5:  # Threshold for anomaly
            evidence = Evidence(
                rule_id='BEH-001',
                rule_name='User Behavior Deviation',
                description=f'Event deviates from user\'s typical behavior pattern',
                certainty=min(0.85, deviation_score),
                matched_facts=[event.event_id],
                contributing_attributes={
                    'deviation_score': deviation_score,
                    'typical_hours': profile.typical_hours,
                    'typical_services': profile.common_services,
                    'typical_source_ips': profile.common_source_ips,
                    'current_hour': event.timestamp.hour,
                    'current_service': event.service,
                    'current_source_ip': event.source_ip
                }
            )
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
                detection_layer="behavioral",
                source_events=[event.event_id],
                affected_users=[event.user_id],
                source_ips=[event.source_ip] if event.source_ip else [],
                threat_level=ThreatLevel.MEDIUM if deviation_score < 0.8 else ThreatLevel.HIGH,
                triggered_rules=['BEH-001'],
                recommendation="Review user's activity for potential account compromise"
            )
            
            anomaly.add_evidence(evidence)
            anomaly.calculate_threat_score()
            anomaly.generate_explanation()
            
            return anomaly
        
        return None
    
    def _check_sequence_patterns(self, event: LogEvent) -> List[Anomaly]:
        """Check for suspicious event sequences"""
        anomalies = []
        
        if not event.user_id:
            return anomalies
        
        # Get recent events for this user
        user_recent = [
            e for e in self.recent_events[-100:]  # Last 100 events
            if e.user_id == event.user_id
        ]
        
        if len(user_recent) < 2:
            return anomalies
        
        for pattern in self.sequence_patterns:
            if self._match_sequence(user_recent, pattern):
                evidence = Evidence(
                    rule_id='BEH-002',
                    rule_name=f'Sequence Pattern: {pattern.name}',
                    description=f'Detected suspicious event sequence: {pattern.name}',
                    certainty=pattern.certainty,
                    matched_facts=[e.event_id for e in user_recent[-len(pattern.sequence):]],
                    contributing_attributes={
                        'pattern_name': pattern.name,
                        'sequence': pattern.sequence,
                        'matched_events': len(pattern.sequence)
                    }
                )
                
                # Determine anomaly type based on pattern
                anomaly_type = AnomalyType.BEHAVIORAL_ANOMALY
                if 'Lateral' in pattern.name:
                    anomaly_type = AnomalyType.LATERAL_MOVEMENT
                elif 'Privilege' in pattern.name:
                    anomaly_type = AnomalyType.PRIVILEGE_ESCALATION
                elif 'Exfiltration' in pattern.name:
                    anomaly_type = AnomalyType.DATA_EXFILTRATION
                
                anomaly = Anomaly(
                    anomaly_type=anomaly_type,
                    detection_layer="behavioral",
                    source_events=[e.event_id for e in user_recent[-len(pattern.sequence):]],
                    affected_users=[event.user_id],
                    source_ips=[event.source_ip] if event.source_ip else [],
                    threat_level=ThreatLevel.HIGH,
                    triggered_rules=['BEH-002'],
                    recommendation=f"Investigate potential {pattern.name.lower()}"
                )
                
                anomaly.add_evidence(evidence)
                anomaly.calculate_threat_score()
                anomaly.generate_explanation()
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _match_sequence(self, events: List[LogEvent], pattern: SequencePattern) -> bool:
        """Check if events match a sequence pattern"""
        if len(events) < len(pattern.sequence):
            return False
        
        # Get the most recent events matching the pattern length
        recent = events[-len(pattern.sequence):]
        
        # Check time window
        time_span = recent[-1].timestamp - recent[0].timestamp
        if time_span > pattern.max_time_window:
            return False
        
        # Check sequence match
        for i, expected_type in enumerate(pattern.sequence):
            actual_type = recent[i].frame.event_type.value if recent[i].frame else None
            
            # Allow partial matching (e.g., 'authentication' matches 'login_success')
            if actual_type and expected_type not in actual_type:
                return False
        
        return True
    
    def _check_peer_deviation(self, event: LogEvent) -> Optional[Anomaly]:
        """Check if user deviates from peer group behavior"""
        if not event.user_id:
            return None
        
        # Find user's peer group
        peer_group = None
        for group_name, members in self.peer_groups.items():
            if event.user_id in members:
                peer_group = members
                break
        
        if not peer_group or len(peer_group) < 3:
            return None
        
        # Get peer profiles
        peer_profiles = [self.user_profiles.get(uid) for uid in peer_group 
                        if uid in self.user_profiles and uid != event.user_id]
        
        if len(peer_profiles) < 2:
            return None
        
        # Compare user's behavior to peers
        user_profile = self.user_profiles.get(event.user_id)
        if not user_profile:
            return None
        
        # Check if user's activity is unusual compared to peers
        peer_services = set()
        for profile in peer_profiles:
            peer_services.update(profile.common_services)
        
        if event.service and event.service not in peer_services:
            evidence = Evidence(
                rule_id='BEH-003',
                rule_name='Peer Group Deviation',
                description=f'User accessed service not typically used by peer group',
                certainty=0.65,
                matched_facts=[event.event_id],
                contributing_attributes={
                    'peer_group_size': len(peer_group),
                    'peer_common_services': list(peer_services)[:10],
                    'accessed_service': event.service
                }
            )
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.BEHAVIORAL_ANOMALY,
                detection_layer="behavioral",
                source_events=[event.event_id],
                affected_users=[event.user_id],
                threat_level=ThreatLevel.LOW,
                triggered_rules=['BEH-003'],
                recommendation="Review user's role and access requirements"
            )
            
            anomaly.add_evidence(evidence)
            anomaly.calculate_threat_score()
            anomaly.generate_explanation()
            
            return anomaly
        
        return None
    
    def assign_peer_group(self, user_id: str, group_name: str) -> None:
        """Assign a user to a peer group"""
        if user_id not in self.peer_groups[group_name]:
            self.peer_groups[group_name].append(user_id)
    
    def get_profile_summary(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get summary of user profile"""
        profile = self.user_profiles.get(user_id)
        if not profile:
            return None
        
        return {
            'user_id': profile.user_id,
            'first_seen': profile.first_seen.isoformat(),
            'last_seen': profile.last_seen.isoformat(),
            'total_events': profile.total_events,
            'typical_hours': profile.typical_hours,
            'typical_services': profile.common_services,
            'common_source_ips': profile.common_source_ips,
            'accessed_resources': list(profile.accessed_resources)
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            'user_profiles': len(self.user_profiles),
            'ip_profiles': len(self.ip_profiles),
            'sequence_patterns': len(self.sequence_patterns),
            'peer_groups': {k: len(v) for k, v in self.peer_groups.items()},
            'recent_events_buffer': len(self.recent_events)
        }
