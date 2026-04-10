"""
Frame-based representation for log events.
Implements frame-based knowledge representation with slots and facets.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum
import hashlib
import json


class EventType(Enum):
    """Semantic event types for security logs"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    DATA_EXFILTRATION = "data_exfiltration"
    NETWORK_CONNECTION = "network_connection"
    PROCESS_EXECUTION = "process_execution"
    FILE_ACCESS = "file_access"
    SYSTEM_EVENT = "system_event"
    SECURITY_ALERT = "security_alert"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Event severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1
    DEBUG = 0


@dataclass
class Slot:
    """
    Frame slot with facets for knowledge representation.
    Facets: value, type, default, constraints, inheritance
    """
    name: str
    value: Any = None
    slot_type: str = "string"
    default: Any = None
    constraints: List[callable] = field(default_factory=list)
    inherited_from: Optional[str] = None
    certainty: float = 1.0  # Certainty factor for this slot value
    
    def validate(self) -> bool:
        """Validate slot value against constraints"""
        if not self.constraints:
            return True
        return all(constraint(self.value) for constraint in self.constraints)
    
    def get_value(self) -> Any:
        """Get slot value with default fallback"""
        return self.value if self.value is not None else self.default


@dataclass
class Frame:
    """
    Frame-based knowledge representation for log events.
    Implements semantic networks through 'is-a' and 'instance-of' relationships.
    """
    name: str
    event_type: EventType
    slots: Dict[str, Slot] = field(default_factory=dict)
    parent_frames: List[str] = field(default_factory=list)
    children_frames: List[str] = field(default_factory=list)
    semantic_relations: Dict[str, List[str]] = field(default_factory=dict)
    
    def add_slot(self, name: str, value: Any, slot_type: str = "string", 
                 default: Any = None, certainty: float = 1.0) -> None:
        """Add a slot to the frame"""
        self.slots[name] = Slot(
            name=name,
            value=value,
            slot_type=slot_type,
            default=default,
            certainty=certainty
        )
    
    def get_slot(self, name: str) -> Optional[Slot]:
        """Get slot by name with inheritance resolution"""
        if name in self.slots:
            return self.slots[name]
        return None
    
    def get_slot_value(self, name: str, default: Any = None) -> Any:
        """Get slot value with inheritance and default handling"""
        slot = self.get_slot(name)
        if slot:
            return slot.get_value()
        return default
    
    def add_semantic_relation(self, relation_type: str, target: str) -> None:
        """Add semantic network relation (e.g., 'causes', 'precedes', 'related-to')"""
        if relation_type not in self.semantic_relations:
            self.semantic_relations[relation_type] = []
        self.semantic_relations[relation_type].append(target)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert frame to dictionary"""
        return {
            'name': self.name,
            'event_type': self.event_type.value,
            'slots': {k: {'value': v.value, 'certainty': v.certainty} 
                     for k, v in self.slots.items()},
            'parent_frames': self.parent_frames,
            'semantic_relations': self.semantic_relations
        }


@dataclass
class LogEvent:
    """
    Unified log event representation.
    Wraps frame-based representation with additional metadata.
    """
    # Core identification
    event_id: str
    timestamp: datetime
    raw_log: str
    source_format: str  # 'json', 'xml', 'syslog', etc.
    
    # Frame-based representation
    frame: Frame = field(default=None)
    
    # Parsed attributes (cached for quick access)
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    # Temporal context
    time_features: Dict[str, Any] = field(default_factory=dict)
    
    # Source information
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_id: Optional[str] = None
    service: Optional[str] = None
    
    # Computed features
    frequency_features: Dict[str, float] = field(default_factory=dict)
    behavioral_features: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize frame if not provided"""
        if self.frame is None:
            self.frame = Frame(
                name=f"event_{self.event_id}",
                event_type=EventType.UNKNOWN
            )
        
        # Generate event_id if not provided
        if not self.event_id:
            self.event_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique event ID from content hash"""
        content = f"{self.timestamp.isoformat()}{self.raw_log}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def set_event_type(self, event_type: EventType) -> None:
        """Set semantic event type"""
        self.frame.event_type = event_type
    
    def add_attribute(self, key: str, value: Any, certainty: float = 1.0) -> None:
        """Add parsed attribute with certainty factor"""
        self.attributes[key] = {'value': value, 'certainty': certainty}
        self.frame.add_slot(key, value, certainty=certainty)
    
    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get attribute value"""
        if key in self.attributes:
            return self.attributes[key]['value']
        return self.frame.get_slot_value(key, default)
    
    def extract_time_features(self) -> Dict[str, Any]:
        """Extract temporal features for analysis"""
        self.time_features = {
            'hour': self.timestamp.hour,
            'day_of_week': self.timestamp.weekday(),
            'is_weekend': self.timestamp.weekday() >= 5,
            'is_business_hours': 9 <= self.timestamp.hour < 17,
            'is_night': self.timestamp.hour < 6 or self.timestamp.hour >= 22,
            'minute': self.timestamp.minute,
            'month': self.timestamp.month
        }
        return self.time_features
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source_format': self.source_format,
            'event_type': self.frame.event_type.value if self.frame else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'user_id': self.user_id,
            'service': self.service,
            'attributes': self.attributes,
            'time_features': self.time_features,
            'frame': self.frame.to_dict() if self.frame else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LogEvent':
        """Create LogEvent from dictionary"""
        event = cls(
            event_id=data['event_id'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            raw_log=data.get('raw_log', ''),
            source_format=data['source_format'],
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            user_id=data.get('user_id'),
            service=data.get('service')
        )
        event.attributes = data.get('attributes', {})
        event.time_features = data.get('time_features', {})
        return event
