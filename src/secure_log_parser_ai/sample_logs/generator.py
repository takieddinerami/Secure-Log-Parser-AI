"""
Sample log generators for testing the detection system.
Generates realistic security logs with various attack patterns.
"""
import json
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from xml.etree.ElementTree import Element, SubElement, tostring

from ..models.log_event import LogEvent, EventType, Severity


class SampleLogGenerator:
    """
    Generator for sample security logs.
    
    Generates logs for:
    - SSH brute force attempts
    - SQL injection patterns
    - Lateral movement
    - Privilege escalation
    - Data exfiltration
    - Normal baseline activity
    """
    
    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)
        
        self.base_time = datetime.now() - timedelta(days=1)
        
        # Sample data pools
        self.users = ['admin', 'john.doe', 'jane.smith', 'bob.wilson', 'alice.jones',
                     'guest', 'test', 'root', 'service_account', 'backup_user']
        self.ips = [f'192.168.1.{i}' for i in range(2, 254)] + \
                   [f'10.0.0.{i}' for i in range(2, 254)] + \
                   ['203.0.113.' + str(i) for i in range(1, 50)]  # External IPs
        self.services = ['ssh', 'web', 'database', 'file_server', 'ldap', 'vpn', 'api']
        self.countries = ['US', 'UK', 'DE', 'FR', 'JP', 'CN', 'RU', 'BR', 'IN', 'CA']
    
    def generate_attack_scenario(self, attack_type: str, count: int = 100) -> List[LogEvent]:
        """Generate logs for a specific attack scenario"""
        generators = {
            'brute_force': self._generate_brute_force,
            'sql_injection': self._generate_sql_injection,
            'lateral_movement': self._generate_lateral_movement,
            'privilege_escalation': self._generate_privilege_escalation,
            'data_exfiltration': self._generate_data_exfiltration
        }
        
        generator = generators.get(attack_type, self._generate_normal_activity)
        return generator(count)
    
    def generate_mixed_logs(self, count: int = 500) -> List[LogEvent]:
        """Generate mixed normal and attack logs"""
        events = []
        
        # 70% normal activity
        normal_count = int(count * 0.7)
        events.extend(self._generate_normal_activity(normal_count))
        
        # 30% various attacks
        attack_count = count - normal_count
        attack_types = ['brute_force', 'sql_injection', 'lateral_movement',
                       'privilege_escalation', 'data_exfiltration']
        
        for attack_type in attack_types:
            n = attack_count // len(attack_types)
            events.extend(self.generate_attack_scenario(attack_type, n))
        
        # Sort by timestamp
        events.sort(key=lambda e: e.timestamp)
        
        return events
    
    def _generate_brute_force(self, count: int) -> List[LogEvent]:
        """Generate SSH brute force attack logs"""
        events = []
        attacker_ip = random.choice([ip for ip in self.ips if ip.startswith('203.')])
        target_user = random.choice(['admin', 'root', 'administrator'])
        
        start_time = self.base_time + timedelta(hours=random.randint(0, 20))
        
        for i in range(count):
            # Rapid fire attempts (every few seconds)
            timestamp = start_time + timedelta(seconds=i * random.randint(1, 5))
            
            # 95% failure rate
            success = random.random() > 0.95
            
            log_data = {
                'timestamp': timestamp.isoformat(),
                'event_type': 'authentication',
                'source_ip': attacker_ip,
                'user_id': target_user if random.random() > 0.3 else random.choice(self.users),
                'service': 'ssh',
                'message': f'{"Accepted" if success else "Failed"} password for {target_user} from {attacker_ip}',
                'outcome': 'success' if success else 'failure',
                'auth_method': 'password'
            }
            
            event = self._create_event(log_data, timestamp)
            event.set_event_type(EventType.AUTHENTICATION)
            events.append(event)
        
        return events
    
    def _generate_sql_injection(self, count: int) -> List[LogEvent]:
        """Generate SQL injection attack logs"""
        events = []
        attacker_ip = random.choice(self.ips)
        
        # SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT * FROM users--",
            "1'; DROP TABLE users;--",
            "' OR 1=1--",
            "admin'--",
            "' OR '1'='1' /*",
            "1' AND 1=1--",
            "' UNION SELECT null, username, password FROM accounts--"
        ]
        
        start_time = self.base_time + timedelta(hours=random.randint(0, 20))
        
        for i in range(count):
            timestamp = start_time + timedelta(seconds=i * random.randint(10, 60))
            payload = random.choice(payloads)
            
            log_data = {
                'timestamp': timestamp.isoformat(),
                'event_type': 'web_access',
                'source_ip': attacker_ip,
                'service': 'web',
                'method': 'GET',
                'url': f'/api/users?id={payload}',
                'user_agent': 'sqlmap/1.0',
                'response_code': random.choice([200, 500, 403]),
                'message': f'SQL injection attempt detected: {payload[:50]}'
            }
            
            event = self._create_event(log_data, timestamp)
            event.set_event_type(EventType.DATA_ACCESS)
            events.append(event)
        
        return events
    
    def _generate_lateral_movement(self, count: int) -> List[LogEvent]:
        """Generate lateral movement attack logs"""
        events = []
        compromised_user = 'admin'
        source_ip = random.choice([ip for ip in self.ips if ip.startswith('192.168.')])
        
        # Sequence: authentication -> network connection -> authentication -> network connection
        target_machines = [f'192.168.1.{i}' for i in random.sample(range(10, 50), 5)]
        
        start_time = self.base_time + timedelta(hours=random.randint(0, 20))
        current_time = start_time
        
        for i, target in enumerate(target_machines):
            # Authentication to target
            current_time += timedelta(minutes=random.randint(5, 15))
            log_data = {
                'timestamp': current_time.isoformat(),
                'event_type': 'authentication',
                'source_ip': source_ip,
                'destination_ip': target,
                'user_id': compromised_user,
                'service': 'smb',
                'message': f'Successful login to {target}',
                'outcome': 'success'
            }
            event = self._create_event(log_data, current_time)
            event.set_event_type(EventType.AUTHENTICATION)
            events.append(event)
            
            # Network connection
            current_time += timedelta(seconds=random.randint(30, 120))
            log_data = {
                'timestamp': current_time.isoformat(),
                'event_type': 'network_connection',
                'source_ip': source_ip,
                'destination_ip': target,
                'destination_port': random.choice([445, 135, 3389]),
                'service': 'smb',
                'message': f'Network connection established to {target}'
            }
            event = self._create_event(log_data, current_time)
            event.set_event_type(EventType.NETWORK_CONNECTION)
            events.append(event)
            
            # Command execution
            current_time += timedelta(seconds=random.randint(10, 60))
            log_data = {
                'timestamp': current_time.isoformat(),
                'event_type': 'process_execution',
                'source_ip': target,
                'user_id': compromised_user,
                'command': random.choice(['whoami', 'net user', 'ipconfig', 'tasklist', 'systeminfo']),
                'service': 'winrm',
                'message': 'Process executed on remote system'
            }
            event = self._create_event(log_data, current_time)
            event.set_event_type(EventType.PROCESS_EXECUTION)
            events.append(event)
        
        return events[:count]
    
    def _generate_privilege_escalation(self, count: int) -> List[LogEvent]:
        """Generate privilege escalation logs"""
        events = []
        attacker_user = 'guest'
        source_ip = random.choice(self.ips)
        
        start_time = self.base_time + timedelta(hours=random.randint(0, 20))
        
        # Initial low-privilege login
        timestamp = start_time
        log_data = {
            'timestamp': timestamp.isoformat(),
            'event_type': 'authentication',
            'source_ip': source_ip,
            'user_id': attacker_user,
            'service': 'ssh',
            'message': f'Login as {attacker_user}',
            'outcome': 'success'
        }
        event = self._create_event(log_data, timestamp)
        event.set_event_type(EventType.AUTHENTICATION)
        events.append(event)
        
        # Sudo attempts
        for i in range(min(count - 1, 10)):
            timestamp += timedelta(seconds=random.randint(30, 120))
            log_data = {
                'timestamp': timestamp.isoformat(),
                'event_type': 'privilege_escalation',
                'source_ip': source_ip,
                'user_id': attacker_user,
                'service': 'sudo',
                'command': random.choice(['sudo su', 'sudo -i', 'sudo /bin/bash', 'sudo passwd root']),
                'message': f'User {attacker_user} attempted privilege escalation',
                'outcome': random.choice(['denied', 'denied', 'denied', 'success'])
            }
            event = self._create_event(log_data, timestamp)
            event.set_event_type(EventType.PRIVILEGE_ESCALATION)
            events.append(event)
        
        return events
    
    def _generate_data_exfiltration(self, count: int) -> List[LogEvent]:
        """Generate data exfiltration logs"""
        events = []
        malicious_user = random.choice(self.users)
        source_ip = random.choice(self.ips)
        
        start_time = self.base_time + timedelta(hours=random.randint(20, 23))  # Off hours
        
        # Database access
        timestamp = start_time
        for i in range(min(count // 3, 20)):
            timestamp += timedelta(minutes=random.randint(1, 5))
            log_data = {
                'timestamp': timestamp.isoformat(),
                'event_type': 'database_query',
                'source_ip': source_ip,
                'user_id': malicious_user,
                'service': 'database',
                'query': f'SELECT * FROM {random.choice(["customers", "orders", "users", "payments"])}',
                'rows_accessed': random.randint(1000, 50000),
                'message': 'Large database query executed'
            }
            event = self._create_event(log_data, timestamp)
            event.set_event_type(EventType.DATA_ACCESS)
            events.append(event)
        
        # Large file download
        for i in range(min(count // 3, 10)):
            timestamp += timedelta(minutes=random.randint(5, 15))
            log_data = {
                'timestamp': timestamp.isoformat(),
                'event_type': 'file_download',
                'source_ip': source_ip,
                'user_id': malicious_user,
                'service': 'file_server',
                'file_size_mb': random.randint(100, 1000),
                'destination': f'external_server_{i}.com',
                'message': f'Large file download: {random.randint(100, 1000)}MB'
            }
            event = self._create_event(log_data, timestamp)
            event.set_event_type(EventType.DATA_EXFILTRATION)
            events.append(event)
        
        # External connection
        for i in range(min(count // 3, 10)):
            timestamp += timedelta(minutes=random.randint(1, 10))
            log_data = {
                'timestamp': timestamp.isoformat(),
                'event_type': 'network_connection',
                'source_ip': source_ip,
                'destination_ip': f'203.0.113.{random.randint(1, 50)}',
                'destination_port': random.choice([443, 8080, 22]),
                'data_transferred_mb': random.randint(50, 500),
                'service': 'https',
                'message': 'External data transfer'
            }
            event = self._create_event(log_data, timestamp)
            event.set_event_type(EventType.NETWORK_CONNECTION)
            events.append(event)
        
        return events
    
    def _generate_normal_activity(self, count: int) -> List[LogEvent]:
        """Generate normal baseline activity logs"""
        events = []
        
        start_time = self.base_time
        
        for i in range(count):
            # Normal business hours
            hour = random.randint(9, 17)
            minute = random.randint(0, 59)
            timestamp = start_time + timedelta(
                days=random.randint(0, 1),
                hours=hour,
                minutes=minute
            )
            
            user = random.choice(self.users)
            service = random.choice(self.services)
            source_ip = random.choice([ip for ip in self.ips if ip.startswith('192.168.')])
            
            event_type = random.choice([
                'authentication', 'file_access', 'database_query', 'web_access'
            ])
            
            if event_type == 'authentication':
                log_data = {
                    'timestamp': timestamp.isoformat(),
                    'event_type': 'authentication',
                    'source_ip': source_ip,
                    'user_id': user,
                    'service': service,
                    'message': f'User {user} logged in successfully',
                    'outcome': 'success'
                }
                event = self._create_event(log_data, timestamp)
                event.set_event_type(EventType.AUTHENTICATION)
            
            elif event_type == 'file_access':
                log_data = {
                    'timestamp': timestamp.isoformat(),
                    'event_type': 'file_access',
                    'source_ip': source_ip,
                    'user_id': user,
                    'service': 'file_server',
                    'file': f'/home/{user}/document_{i}.pdf',
                    'action': random.choice(['read', 'write']),
                    'message': f'File accessed by {user}'
                }
                event = self._create_event(log_data, timestamp)
                event.set_event_type(EventType.FILE_ACCESS)
            
            elif event_type == 'database_query':
                log_data = {
                    'timestamp': timestamp.isoformat(),
                    'event_type': 'database_query',
                    'source_ip': source_ip,
                    'user_id': user,
                    'service': 'database',
                    'query': f'SELECT * FROM orders WHERE user_id = {i}',
                    'rows_accessed': random.randint(1, 100),
                    'message': 'Database query executed'
                }
                event = self._create_event(log_data, timestamp)
                event.set_event_type(EventType.DATA_ACCESS)
            
            else:  # web_access
                log_data = {
                    'timestamp': timestamp.isoformat(),
                    'event_type': 'web_access',
                    'source_ip': source_ip,
                    'user_id': user,
                    'service': 'web',
                    'method': random.choice(['GET', 'POST']),
                    'url': f'/api/data/{i}',
                    'response_code': 200,
                    'message': 'Web request processed'
                }
                event = self._create_event(log_data, timestamp)
                event.set_event_type(EventType.NETWORK_CONNECTION)
            
            events.append(event)
        
        return events
    
    def _create_event(self, data: Dict[str, Any], timestamp: datetime) -> LogEvent:
        """Create a LogEvent from log data"""
        event = LogEvent(
            event_id=f"evt_{timestamp.timestamp()}_{random.randint(1000, 9999)}",
            timestamp=timestamp,
            raw_log=json.dumps(data),
            source_format='json'
        )
        
        # Set standard fields
        event.source_ip = data.get('source_ip')
        event.destination_ip = data.get('destination_ip')
        event.user_id = data.get('user_id')
        event.service = data.get('service')
        
        # Add all data as attributes
        for key, value in data.items():
            event.add_attribute(key, value)
        
        event.extract_time_features()
        
        return event
    
    def to_json(self, events: List[LogEvent]) -> str:
        """Convert events to JSON string"""
        data = [event.to_dict() for event in events]
        return json.dumps(data, indent=2)
    
    def to_xml(self, events: List[LogEvent]) -> str:
        """Convert events to XML string"""
        root = Element('Logs')
        
        for event in events:
            log_elem = SubElement(root, 'Log')
            
            SubElement(log_elem, 'EventID').text = event.event_id
            SubElement(log_elem, 'Timestamp').text = event.timestamp.isoformat()
            SubElement(log_elem, 'SourceIP').text = event.source_ip or ''
            SubElement(log_elem, 'UserID').text = event.user_id or ''
            SubElement(log_elem, 'Service').text = event.service or ''
            
            if event.frame and event.frame.event_type:
                SubElement(log_elem, 'EventType').text = event.frame.event_type.value
            
            # Add attributes
            attrs_elem = SubElement(log_elem, 'Attributes')
            for key, value_data in event.attributes.items():
                value = value_data['value'] if isinstance(value_data, dict) else value_data
                attr_elem = SubElement(attrs_elem, 'Attribute')
                attr_elem.set('name', key)
                attr_elem.text = str(value)
        
        return tostring(root, encoding='unicode')
