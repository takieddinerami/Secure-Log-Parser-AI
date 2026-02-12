"""
Log normalizer for schema unification across different log formats.
Converts various log formats to unified internal representation.
"""
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path

from ..models.log_event import LogEvent, EventType, Severity


class LogNormalizer:
    """
    Normalizes logs from various formats to unified schema.
    
    Unified schema fields:
    - event_id: Unique identifier
    - timestamp: Normalized datetime
    - event_type: Semantic event category
    - severity: Event severity level
    - source_ip: Origin IP address
    - destination_ip: Target IP address
    - user_id: Associated user
    - service: Service/application
    - message: Human-readable description
    - raw_log: Original log entry
    - attributes: Additional parsed fields
    """
    
    # Field mapping from various formats to unified schema
    FIELD_MAPPINGS = {
        'json': {
            'timestamp': ['timestamp', 'time', 'date', '@timestamp', 'eventTime', 'created'],
            'source_ip': ['source_ip', 'src_ip', 'client_ip', 'sourceIPAddress', 'remote_addr'],
            'destination_ip': ['destination_ip', 'dst_ip', 'dest_ip', 'target_ip'],
            'user_id': ['user_id', 'user', 'username', 'userName', 'user_identity', 'subject'],
            'service': ['service', 'eventSource', 'application', 'app', 'source'],
            'message': ['message', 'msg', 'text', 'description', 'eventName', 'activity'],
            'severity': ['severity', 'level', 'priority', 'syslog_severity'],
        },
        'xml': {
            'timestamp': ['timestamp', 'time', 'TimeCreated', 'created'],
            'source_ip': ['ipaddress', 'clientaddress', 'sourceip', 'ip'],
            'user_id': ['targetusername', 'subjectusername', 'username', 'user'],
            'service': ['service', 'application', 'provider'],
            'message': ['message', 'text', 'renderinginfo_message'],
            'severity': ['level', 'severity', 'priority'],
        },
        'syslog': {
            'timestamp': ['timestamp', 'time', 'received_at'],
            'source_ip': ['source_ip', 'remote_addr', 'fromhost'],
            'user_id': ['user', 'username', 'uid'],
            'service': ['programname', 'appname', 'tag', 'facility'],
            'message': ['message', 'msg', 'content'],
            'severity': ['severity', 'level', 'priority'],
        }
    }
    
    def __init__(self):
        self.normalized_count = 0
        self.error_count = 0
    
    def normalize(self, event: LogEvent, target_format: str = 'unified') -> LogEvent:
        """
        Normalize a log event to unified schema.
        
        Args:
            event: Input LogEvent
            target_format: Output format (currently only 'unified' supported)
        
        Returns:
            Normalized LogEvent
        """
        try:
            # Determine source format
            source_format = self._detect_source_format(event)
            
            # Apply field mappings
            mapping = self.FIELD_MAPPINGS.get(source_format, self.FIELD_MAPPINGS['json'])
            
            # Normalize fields
            normalized = self._apply_normalization(event, mapping)
            
            # Normalize severity
            normalized = self._normalize_severity(normalized)
            
            # Normalize event type
            normalized = self._normalize_event_type(normalized)
            
            self.normalized_count += 1
            return normalized
            
        except Exception as e:
            self.error_count += 1
            return event
    
    def normalize_batch(self, events: List[LogEvent]) -> List[LogEvent]:
        """Normalize a batch of events"""
        return [self.normalize(event) for event in events]
    
    def _detect_source_format(self, event: LogEvent) -> str:
        """Detect the source format of an event"""
        if event.source_format.startswith('json'):
            return 'json'
        elif event.source_format.startswith('xml'):
            return 'xml'
        elif 'syslog' in event.source_format:
            return 'syslog'
        return 'json'
    
    def _apply_normalization(self, event: LogEvent, mapping: Dict[str, List[str]]) -> LogEvent:
        """Apply field mappings to normalize event"""
        # Create new normalized event
        normalized = LogEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            raw_log=event.raw_log,
            source_format=f"normalized_{event.source_format}"
        )
        
        # Copy frame
        normalized.frame = event.frame
        
        # Apply field mappings
        for standard_field, source_fields in mapping.items():
            for source_field in source_fields:
                value = event.get_attribute(source_field)
                if value is not None:
                    normalized.add_attribute(standard_field, value)
                    
                    # Set direct properties
                    if standard_field == 'source_ip' and not normalized.source_ip:
                        normalized.source_ip = str(value)
                    elif standard_field == 'destination_ip' and not normalized.destination_ip:
                        normalized.destination_ip = str(value)
                    elif standard_field == 'user_id' and not normalized.user_id:
                        normalized.user_id = str(value)
                    elif standard_field == 'service' and not normalized.service:
                        normalized.service = str(value)
                    
                    break
        
        # Copy all other attributes
        for key, value_data in event.attributes.items():
            if key not in normalized.attributes:
                normalized.attributes[key] = value_data
        
        # Copy time features
        normalized.time_features = event.time_features
        
        return normalized
    
    def _normalize_severity(self, event: LogEvent) -> LogEvent:
        """Normalize severity to standard levels"""
        severity_value = event.get_attribute('severity')
        
        if severity_value is None:
            event.add_attribute('severity_normalized', 'unknown')
            return event
        
        # Convert various severity formats to standard
        severity_str = str(severity_value).lower()
        
        # Numeric severity (0-7 syslog style)
        if severity_str.isdigit():
            level = int(severity_str)
            if level <= 2:
                normalized = 'critical'
            elif level <= 3:
                normalized = 'high'
            elif level <= 4:
                normalized = 'medium'
            elif level <= 6:
                normalized = 'low'
            else:
                normalized = 'info'
        
        # String severity
        elif severity_str in ['critical', 'emergency', 'alert']:
            normalized = 'critical'
        elif severity_str in ['high', 'error', 'err']:
            normalized = 'high'
        elif severity_str in ['medium', 'warning', 'warn']:
            normalized = 'medium'
        elif severity_str in ['low', 'notice']:
            normalized = 'low'
        elif severity_str in ['info', 'information', 'informational', 'debug']:
            normalized = 'info'
        else:
            normalized = 'unknown'
        
        event.add_attribute('severity_normalized', normalized)
        
        # Map to Severity enum
        severity_map = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'medium': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        
        if normalized in severity_map:
            event.add_attribute('severity_enum', severity_map[normalized].name)
        
        return event
    
    def _normalize_event_type(self, event: LogEvent) -> LogEvent:
        """Normalize event type to standard categories"""
        event_type = event.frame.event_type if event.frame else EventType.UNKNOWN
        
        # Add normalized type string
        event.add_attribute('event_type_normalized', event_type.value)
        
        # Add category
        type_categories = {
            EventType.AUTHENTICATION: 'security',
            EventType.AUTHORIZATION: 'security',
            EventType.PRIVILEGE_ESCALATION: 'security',
            EventType.DATA_ACCESS: 'data',
            EventType.DATA_EXFILTRATION: 'security',
            EventType.NETWORK_CONNECTION: 'network',
            EventType.PROCESS_EXECUTION: 'system',
            EventType.FILE_ACCESS: 'data',
            EventType.SYSTEM_EVENT: 'system',
            EventType.SECURITY_ALERT: 'security',
            EventType.UNKNOWN: 'unknown'
        }
        
        event.add_attribute('event_category', type_categories.get(event_type, 'unknown'))
        
        return event
    
    def enrich_event(self, event: LogEvent, 
                     user_profiles: Optional[Dict] = None,
                     ip_reputation: Optional[Dict] = None) -> LogEvent:
        """
        Enrich event with additional context.
        
        Args:
            event: Input event
            user_profiles: Dictionary of user behavior profiles
            ip_reputation: Dictionary of IP reputation scores
        """
        # Add user context
        if event.user_id and user_profiles:
            profile = user_profiles.get(event.user_id)
            if profile:
                event.add_attribute('user_typical_hours', profile.get('typical_hours', 'unknown'))
                event.add_attribute('user_risk_score', profile.get('risk_score', 0))
        
        # Add IP context
        if event.source_ip and ip_reputation:
            reputation = ip_reputation.get(event.source_ip)
            if reputation:
                event.add_attribute('ip_reputation_score', reputation.get('score', 0))
                event.add_attribute('ip_threat_category', reputation.get('category', 'unknown'))
        
        # Add temporal context
        if event.time_features:
            event.add_attribute('is_off_hours', 
                not event.time_features.get('is_business_hours', True))
            event.add_attribute('is_weekend', 
                event.time_features.get('is_weekend', False))
        
        return event
    
    def create_unified_dict(self, event: LogEvent) -> Dict[str, Any]:
        """Create a unified dictionary representation"""
        return {
            'event_id': event.event_id,
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.get_attribute('event_type_normalized'),
            'event_category': event.get_attribute('event_category'),
            'severity': event.get_attribute('severity_normalized'),
            'source_ip': event.source_ip,
            'destination_ip': event.destination_ip,
            'user_id': event.user_id,
            'service': event.service,
            'message': event.get_attribute('message'),
            'is_off_hours': event.get_attribute('is_off_hours'),
            'is_weekend': event.get_attribute('is_weekend'),
            'attributes': {k: v['value'] if isinstance(v, dict) else v 
                          for k, v in event.attributes.items()},
            'time_features': event.time_features,
            'frame': event.frame.to_dict() if event.frame else None
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get normalizer statistics"""
        return {
            'normalized_count': self.normalized_count,
            'error_count': self.error_count,
            'success_rate': self.normalized_count / (self.normalized_count + self.error_count)
                          if (self.normalized_count + self.error_count) > 0 else 0
        }
