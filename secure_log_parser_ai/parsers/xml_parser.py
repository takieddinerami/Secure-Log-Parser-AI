"""
XML log parser with namespace handling and XPath extraction.
"""
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from pathlib import Path
import re

from ..models.log_event import LogEvent, Frame, EventType


class XMLLogParser:
    """
    Parser for XML-formatted log files.
    Handles namespaces, XPath extraction, and various XML log formats.
    
    Supported formats:
    - Windows Event Log (EVTX XML export)
    - Syslog (RFC 5424)
    - Custom XML logs
    """
    
    # Common namespace mappings
    NAMESPACES = {
        'evt': 'http://schemas.microsoft.com/win/2004/08/events/event',
        'sys': 'http://www.w3.org/2003/05/soap-envelope',
        'ce': 'http://www.mitre.org/XMLSchema/ce',
    }
    
    def __init__(self, namespaces: Optional[Dict[str, str]] = None):
        """
        Initialize parser with namespace mappings.
        
        namespaces: Dictionary of prefix -> URI mappings
        """
        self.namespaces = namespaces or self.NAMESPACES.copy()
        self.parsed_count = 0
        self.error_count = 0
    
    def parse_file(self, filepath: Union[str, Path]) -> List[LogEvent]:
        """Parse an XML log file"""
        events = []
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            
            # Try to detect format and parse accordingly
            if self._is_windows_event_log(root):
                events = self._parse_windows_event_log(root)
            elif self._is_syslog(root):
                events = self._parse_syslog(root)
            else:
                # Generic XML parsing
                events = self._parse_generic_xml(root)
                
        except ET.ParseError as e:
            # Try to parse as line-delimited XML
            events = self._parse_line_delimited(path)
        
        return events
    
    def parse_string(self, xml_string: str) -> List[LogEvent]:
        """Parse XML from string"""
        try:
            root = ET.fromstring(xml_string)
            return self._parse_generic_xml(root)
        except ET.ParseError as e:
            self.error_count += 1
            return []
    
    def _is_windows_event_log(self, root: ET.Element) -> bool:
        """Check if XML is Windows Event Log format"""
        return root.tag.endswith('Event') or 'Events' in root.tag
    
    def _is_syslog(self, root: ET.Element) -> bool:
        """Check if XML is Syslog format"""
        return 'syslog' in root.tag.lower() or root.tag == '{http://www.w3.org/2003/05/soap-envelope}Envelope'
    
    def _parse_windows_event_log(self, root: ET.Element) -> List[LogEvent]:
        """Parse Windows Event Log XML format"""
        events = []
        
        # Handle single event or Events collection
        if root.tag.endswith('Events'):
            event_elements = root.findall('.//evt:Event', self.namespaces)
            if not event_elements:
                event_elements = root.findall('.//Event')
        else:
            event_elements = [root]
        
        for elem in event_elements:
            try:
                event = self._parse_windows_event_element(elem)
                if event:
                    events.append(event)
            except Exception as e:
                self.error_count += 1
                continue
        
        return events
    
    def _parse_windows_event_element(self, elem: ET.Element) -> Optional[LogEvent]:
        """Parse a single Windows Event element"""
        # Extract system data
        system = elem.find('evt:System', self.namespaces) or elem.find('System')
        
        if system is None:
            return None
        
        # Get event ID
        event_id_elem = system.find('evt:EventID', self.namespaces) or system.find('EventID')
        event_id = event_id_elem.text if event_id_elem is not None else '0'
        
        # Get timestamp
        time_elem = system.find('evt:TimeCreated', self.namespaces) or system.find('TimeCreated')
        timestamp = datetime.now()
        if time_elem is not None:
            time_str = time_elem.get('SystemTime') or time_elem.text
            if time_str:
                timestamp = self._parse_timestamp(time_str)
        
        # Get level/severity
        level_elem = system.find('evt:Level', self.namespaces) or system.find('Level')
        level = level_elem.text if level_elem is not None else '0'
        
        # Get computer name
        computer_elem = system.find('evt:Computer', self.namespaces) or system.find('Computer')
        computer = computer_elem.text if computer_elem is not None else 'unknown'
        
        # Get event data
        event_data = elem.find('evt:EventData', self.namespaces) or elem.find('EventData')
        data_dict = {}
        if event_data is not None:
            for data in event_data.findall('evt:Data', self.namespaces) or event_data.findall('Data'):
                name = data.get('Name')
                if name:
                    data_dict[name] = data.text
        
        # Get rendering info (message)
        rendering = elem.find('evt:RenderingInfo', self.namespaces) or elem.find('RenderingInfo')
        message = ''
        if rendering is not None:
            msg_elem = rendering.find('evt:Message', self.namespaces) or rendering.find('Message')
            if msg_elem is not None:
                message = msg_elem.text or ''
        
        # Create LogEvent
        event = LogEvent(
            event_id=f"win_{event_id}_{timestamp.timestamp()}",
            timestamp=timestamp,
            raw_log=ET.tostring(elem, encoding='unicode'),
            source_format='xml_windows_event'
        )
        
        # Add attributes
        event.add_attribute('event_id', event_id)
        event.add_attribute('level', level)
        event.add_attribute('computer', computer)
        event.add_attribute('message', message)
        
        for key, value in data_dict.items():
            event.add_attribute(key, value)
            
            # Extract specific fields
            if key.lower() in ['targetusername', 'subjectusername']:
                event.user_id = value
            elif key.lower() in ['ipaddress', 'clientaddress']:
                event.source_ip = value
        
        # Classify event type based on event ID
        self._classify_windows_event(event, int(event_id) if event_id.isdigit() else 0)
        
        event.extract_time_features()
        self.parsed_count += 1
        
        return event
    
    def _parse_syslog(self, root: ET.Element) -> List[LogEvent]:
        """Parse RFC 5424 Syslog XML format"""
        events = []
        
        # Find all syslog entries
        entries = root.findall('.//sys:Entry', self.namespaces)
        if not entries:
            entries = root.findall('.//Entry')
        
        for entry in entries:
            try:
                event = self._parse_syslog_entry(entry)
                if event:
                    events.append(event)
            except Exception as e:
                self.error_count += 1
                continue
        
        return events
    
    def _parse_syslog_entry(self, entry: ET.Element) -> Optional[LogEvent]:
        """Parse a single syslog entry"""
        # Extract timestamp
        timestamp_elem = entry.find('Timestamp') or entry.find('timestamp')
        timestamp = datetime.now()
        if timestamp_elem is not None:
            timestamp = self._parse_timestamp(timestamp_elem.text)
        
        # Extract message
        msg_elem = entry.find('Message') or entry.find('message') or entry.find('msg')
        message = msg_elem.text if msg_elem is not None else ''
        
        # Extract severity
        severity_elem = entry.find('Severity') or entry.find('severity') or entry.find('priority')
        severity = severity_elem.text if severity_elem is not None else '6'
        
        # Extract facility
        facility_elem = entry.find('Facility') or entry.find('facility')
        facility = facility_elem.text if facility_elem is not None else '0'
        
        # Extract hostname
        host_elem = entry.find('Hostname') or entry.find('hostname') or entry.find('host')
        hostname = host_elem.text if host_elem is not None else 'unknown'
        
        # Create LogEvent
        event = LogEvent(
            event_id=f"syslog_{timestamp.timestamp()}",
            timestamp=timestamp,
            raw_log=ET.tostring(entry, encoding='unicode'),
            source_format='xml_syslog'
        )
        
        event.add_attribute('message', message)
        event.add_attribute('severity', severity)
        event.add_attribute('facility', facility)
        event.add_attribute('hostname', hostname)
        
        event.extract_time_features()
        self.parsed_count += 1
        
        return event
    
    def _parse_generic_xml(self, root: ET.Element) -> List[LogEvent]:
        """Parse generic XML log format"""
        events = []
        
        # Try to find event-like elements
        event_tags = ['event', 'Event', 'log', 'Log', 'entry', 'Entry', 'record', 'Record']
        
        event_elements = []
        for tag in event_tags:
            event_elements = root.findall(f'.//{tag}')
            if event_elements:
                break
        
        # If no events found, treat root as single event
        if not event_elements:
            event_elements = [root]
        
        for elem in event_elements:
            try:
                event = self._parse_generic_event_element(elem)
                if event:
                    events.append(event)
            except Exception as e:
                self.error_count += 1
                continue
        
        return events
    
    def _parse_generic_event_element(self, elem: ET.Element) -> Optional[LogEvent]:
        """Parse a generic XML event element"""
        # Extract all text content
        text_content = ' '.join(elem.itertext()).strip()
        
        # Try to find timestamp
        timestamp = datetime.now()
        for ts_tag in ['timestamp', 'time', 'date', 'created', 'Time']:
            ts_elem = elem.find(f'.//{ts_tag}')
            if ts_elem is not None and ts_elem.text:
                try:
                    timestamp = self._parse_timestamp(ts_elem.text)
                    break
                except:
                    continue
        
        # Create LogEvent
        event = LogEvent(
            event_id=f"xml_{timestamp.timestamp()}",
            timestamp=timestamp,
            raw_log=ET.tostring(elem, encoding='unicode'),
            source_format='xml_generic'
        )
        
        # Extract all attributes and child elements
        self._extract_xml_data(elem, event)
        
        event.extract_time_features()
        self.parsed_count += 1
        
        return event
    
    def _extract_xml_data(self, elem: ET.Element, event: LogEvent, prefix: str = '') -> None:
        """Recursively extract data from XML element"""
        # Extract attributes
        for key, value in elem.attrib.items():
            attr_name = f"{prefix}{elem.tag}_{key}" if prefix else f"{elem.tag}_{key}"
            event.add_attribute(attr_name, value)
        
        # Extract child elements
        for child in elem:
            tag_name = child.tag.split('}')[-1] if '}' in child.tag else child.tag
            
            if len(child) == 0 and child.text:
                # Leaf element with text
                attr_name = f"{prefix}{tag_name}" if prefix else tag_name
                event.add_attribute(attr_name, child.text.strip())
                
                # Extract specific security fields
                if tag_name.lower() in ['username', 'user', 'userid']:
                    event.user_id = child.text
                elif tag_name.lower() in ['ip', 'ipaddress', 'sourceip', 'clientip']:
                    event.source_ip = child.text
                elif tag_name.lower() in ['service', 'application', 'app']:
                    event.service = child.text
            else:
                # Recurse into child elements
                new_prefix = f"{prefix}{tag_name}_" if prefix else f"{tag_name}_"
                self._extract_xml_data(child, event, new_prefix)
    
    def _parse_line_delimited(self, path: Path) -> List[LogEvent]:
        """Parse line-delimited XML (one event per line)"""
        events = []
        
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith('<'):
                    continue
                
                try:
                    root = ET.fromstring(line)
                    event = self._parse_generic_event_element(root)
                    if event:
                        events.append(event)
                except ET.ParseError:
                    self.error_count += 1
                    continue
        
        return events
    
    def _parse_timestamp(self, value: str) -> datetime:
        """Parse various timestamp formats"""
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue
        
        # Try ISO format
        try:
            return datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            pass
        
        return datetime.now()
    
    def _classify_windows_event(self, event: LogEvent, event_id: int) -> None:
        """Classify Windows event based on event ID"""
        # Security event IDs
        auth_events = [4624, 4625, 4634, 4647, 4648, 4778, 4779]  # Logon/Logoff
        account_mgmt = [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740]  # Account management
        privilege = [4672, 4673, 4674]  # Privilege use
        object_access = [4656, 4658, 4659, 4660, 4661, 4663, 4664]  # Object access
        policy_change = [4719, 4739, 612, 613]  # Policy change
        
        if event_id in auth_events:
            event.set_event_type(EventType.AUTHENTICATION)
        elif event_id in account_mgmt:
            event.set_event_type(EventType.AUTHORIZATION)
        elif event_id in privilege:
            event.set_event_type(EventType.PRIVILEGE_ESCALATION)
        elif event_id in object_access:
            event.set_event_type(EventType.FILE_ACCESS)
        elif event_id in policy_change:
            event.set_event_type(EventType.SYSTEM_EVENT)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get parser statistics"""
        return {
            'parsed_count': self.parsed_count,
            'error_count': self.error_count,
            'success_rate': self.parsed_count / (self.parsed_count + self.error_count)
                          if (self.parsed_count + self.error_count) > 0 else 0
        }


class CEFParser(XMLLogParser):
    """Parser for Common Event Format (CEF) logs in XML"""
    
    CEF_PATTERN = re.compile(
        r'CEF:(?P<version>\d+)\|'
        r'(?P<device_vendor>[^|]*)\|'
        r'(?P<device_product>[^|]*)\|'
        r'(?P<device_version>[^|]*)\|'
        r'(?P<signature_id>[^|]*)\|'
        r'(?P<name>[^|]*)\|'
        r'(?P<severity>[^|]*)\|'
        r'(?P<extensions>.*)'
    )
    
    def parse_cef_string(self, cef_string: str) -> Optional[LogEvent]:
        """Parse a CEF-formatted string"""
        match = self.CEF_PATTERN.match(cef_string)
        if not match:
            return None
        
        data = match.groupdict()
        
        # Parse extensions
        extensions = {}
        ext_string = data.get('extensions', '')
        for pair in ext_string.split(' '):
            if '=' in pair:
                key, value = pair.split('=', 1)
                extensions[key] = value
        
        # Create event
        timestamp = datetime.now()
        if 'rt' in extensions:
            timestamp = self._parse_timestamp(extensions['rt'])
        
        event = LogEvent(
            event_id=data.get('signature_id', '0'),
            timestamp=timestamp,
            raw_log=cef_string,
            source_format='cef'
        )
        
        event.add_attribute('device_vendor', data.get('device_vendor'))
        event.add_attribute('device_product', data.get('device_product'))
        event.add_attribute('signature_id', data.get('signature_id'))
        event.add_attribute('name', data.get('name'))
        event.add_attribute('severity', data.get('severity'))
        
        for key, value in extensions.items():
            event.add_attribute(key, value)
            
            if key == 'src':
                event.source_ip = value
            elif key == 'duser':
                event.user_id = value
        
        event.extract_time_features()
        self.parsed_count += 1
        
        return event
