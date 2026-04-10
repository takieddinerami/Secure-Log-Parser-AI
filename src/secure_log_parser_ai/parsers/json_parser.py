"""
JSON log parser with schema handling and nested structure support.
"""
import json
import re
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path

from ..models.log_event import LogEvent, Frame, EventType, Severity


class JSONLogParser:
    """
    Parser for JSON-formatted log files.
    Handles nested structures, array flattening, and timestamp normalization.
    
    Supported formats:
    - Standard JSON logs (one object per line or array)
    - AWS CloudTrail
    - Windows Event Logs (JSON format)
    - Custom JSON schemas
    """
    
    # Common timestamp field names
    TIMESTAMP_FIELDS = [
        'timestamp', 'time', 'date', 'datetime', '@timestamp',
        'eventTime', 'event_time', 'created', 'generated',
        'ts', 't', 'eventTimestamp'
    ]
    
    # Common message field names
    MESSAGE_FIELDS = [
        'message', 'msg', 'text', 'description', 'details',
        'eventName', 'event_name', 'activity', 'action'
    ]
    
    def __init__(self, schema: Optional[Dict[str, Any]] = None):
        """
        Initialize parser with optional schema.
        
        schema: Dictionary mapping standard fields to JSON paths
        Example: {'timestamp': 'eventTime', 'user': 'userIdentity.userName'}
        """
        self.schema = schema or {}
        self.parsed_count = 0
        self.error_count = 0
    
    def parse_file(self, filepath: Union[str, Path]) -> List[LogEvent]:
        """Parse a JSON log file"""
        events = []
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Try to parse as JSON array first
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    event = self.parse_record(item)
                    if event:
                        events.append(event)
            elif isinstance(data, dict):
                event = self.parse_record(data)
                if event:
                    events.append(event)
        except json.JSONDecodeError:
            # Try line-delimited JSON (NDJSON)
            for line in content.strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    event = self.parse_record(record)
                    if event:
                        events.append(event)
                except json.JSONDecodeError as e:
                    self.error_count += 1
                    continue
        
        return events
    
    def parse_record(self, record: Dict[str, Any]) -> Optional[LogEvent]:
        """Parse a single JSON record into LogEvent"""
        try:
            # Extract timestamp
            timestamp = self._extract_timestamp(record)
            
            # Extract message
            message = self._extract_message(record)
            
            # Create LogEvent
            event = LogEvent(
                event_id=self._generate_event_id(record),
                timestamp=timestamp,
                raw_log=json.dumps(record),
                source_format='json'
            )
            
            # Extract and add attributes
            self._extract_attributes(event, record)
            
            # Extract time features
            event.extract_time_features()
            
            # Classify event type
            self._classify_event_type(event, message)
            
            self.parsed_count += 1
            return event
            
        except Exception as e:
            self.error_count += 1
            return None
    
    def _extract_timestamp(self, record: Dict[str, Any]) -> datetime:
        """Extract and normalize timestamp from record"""
        # Try schema-defined field first
        if 'timestamp' in self.schema:
            ts_value = self._get_nested_value(record, self.schema['timestamp'])
            if ts_value:
                return self._parse_timestamp(ts_value)
        
        # Try common timestamp fields
        for field in self.TIMESTAMP_FIELDS:
            if field in record:
                return self._parse_timestamp(record[field])
            # Try nested path
            if '.' in field:
                value = self._get_nested_value(record, field)
                if value:
                    return self._parse_timestamp(value)
        
        # Default to current time
        return datetime.now()
    
    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse various timestamp formats"""
        if isinstance(value, (int, float)):
            # Unix timestamp (seconds or milliseconds)
            if value > 1e12:  # Milliseconds
                value = value / 1000
            return datetime.fromtimestamp(value)
        
        if isinstance(value, str):
            # Try ISO 8601 format
            formats = [
                '%Y-%m-%dT%H:%M:%S.%fZ',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%f%z',
                '%Y-%m-%dT%H:%M:%S%z',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y/%m/%d %H:%M:%S',
                '%d/%b/%Y:%H:%M:%S',
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            
            # Try ISO format parser
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                pass
        
        return datetime.now()
    
    def _extract_message(self, record: Dict[str, Any]) -> str:
        """Extract message content from record"""
        # Try schema-defined field
        if 'message' in self.schema:
            msg = self._get_nested_value(record, self.schema['message'])
            if msg:
                return str(msg)
        
        # Try common message fields
        for field in self.MESSAGE_FIELDS:
            if field in record:
                return str(record[field])
            if '.' in field:
                value = self._get_nested_value(record, field)
                if value:
                    return str(value)
        
        # Return string representation of record
        return json.dumps(record)
    
    def _extract_attributes(self, event: LogEvent, record: Dict[str, Any]) -> None:
        """Extract attributes from record and add to event"""
        # Flatten nested structure
        flat = self._flatten_dict(record)
        
        for key, value in flat.items():
            # Skip timestamp fields (already extracted)
            if key in self.TIMESTAMP_FIELDS:
                continue
            
            # Extract specific security-relevant fields
            if key in ['source_ip', 'src_ip', 'client_ip', 'sourceIPAddress']:
                event.source_ip = str(value) if value else None
            elif key in ['destination_ip', 'dst_ip', 'dest_ip']:
                event.destination_ip = str(value) if value else None
            elif key in ['user_id', 'user', 'username', 'userName', 'user_identity']:
                event.user_id = str(value) if value else None
            elif key in ['service', 'eventSource', 'application']:
                event.service = str(value) if value else None
            
            # Add as attribute
            event.add_attribute(key, value)
            
            # Add to frame
            if event.frame:
                event.frame.add_slot(key, value)
    
    def _classify_event_type(self, event: LogEvent, message: str) -> None:
        """Classify event into semantic type"""
        message_lower = message.lower()
        
        # Authentication events
        if any(kw in message_lower for kw in ['login', 'logon', 'authentication', 'signin']):
            if any(kw in message_lower for kw in ['fail', 'denied', 'invalid', 'error']):
                event.set_event_type(EventType.AUTHENTICATION)
                if event.frame:
                    event.frame.add_slot('outcome', 'failure')
            elif any(kw in message_lower for kw in ['success', 'granted', 'authenticated']):
                event.set_event_type(EventType.AUTHENTICATION)
                if event.frame:
                    event.frame.add_slot('outcome', 'success')
        
        # Authorization events
        elif any(kw in message_lower for kw in ['access denied', 'unauthorized', 'forbidden']):
            event.set_event_type(EventType.AUTHORIZATION)
        
        # Privilege escalation
        elif any(kw in message_lower for kw in ['privilege', 'escalation', 'sudo', 'elevated']):
            event.set_event_type(EventType.PRIVILEGE_ESCALATION)
        
        # Data access
        elif any(kw in message_lower for kw in ['file', 'download', 'upload', 'data']):
            event.set_event_type(EventType.DATA_ACCESS)
        
        # Network events
        elif any(kw in message_lower for kw in ['connection', 'network', 'tcp', 'udp']):
            event.set_event_type(EventType.NETWORK_CONNECTION)
        
        # Process events
        elif any(kw in message_lower for kw in ['process', 'execution', 'command', 'shell']):
            event.set_event_type(EventType.PROCESS_EXECUTION)
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):
                # Flatten arrays with index
                for i, item in enumerate(v):
                    if isinstance(item, dict):
                        items.extend(self._flatten_dict(item, f"{new_key}[{i}]", sep).items())
                    else:
                        items.append((f"{new_key}[{i}]", item))
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _get_nested_value(self, d: Dict[str, Any], path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = path.split('.')
        value = d
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value
    
    def _generate_event_id(self, record: Dict[str, Any]) -> str:
        """Generate unique event ID from record content"""
        import hashlib
        content = json.dumps(record, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get parser statistics"""
        return {
            'parsed_count': self.parsed_count,
            'error_count': self.error_count,
            'success_rate': self.parsed_count / (self.parsed_count + self.error_count) 
                          if (self.parsed_count + self.error_count) > 0 else 0
        }


class CloudTrailParser(JSONLogParser):
    """Specialized parser for AWS CloudTrail logs"""
    
    def __init__(self):
        schema = {
            'timestamp': 'eventTime',
            'message': 'eventName',
            'user': 'userIdentity.userName',
            'source_ip': 'sourceIPAddress'
        }
        super().__init__(schema)
    
    def parse_record(self, record: Dict[str, Any]) -> Optional[LogEvent]:
        """Parse CloudTrail record"""
        # Handle CloudTrail format (Records array)
        if 'Records' in record:
            events = []
            for rec in record['Records']:
                event = super().parse_record(rec)
                if event:
                    events.append(event)
            return events if len(events) > 1 else (events[0] if events else None)
        
        return super().parse_record(record)


class WindowsEventParser(JSONLogParser):
    """Specialized parser for Windows Event Logs (JSON format)"""
    
    def __init__(self):
        schema = {
            'timestamp': 'TimeCreated',
            'message': 'Message',
            'event_id': 'Id',
            'level': 'Level'
        }
        super().__init__(schema)
    
    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse Windows event timestamp"""
        if isinstance(value, dict) and '@SystemTime' in value:
            return super()._parse_timestamp(value['@SystemTime'])
        return super()._parse_timestamp(value)
