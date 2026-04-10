"""
Ontology and semantic network for security event representation.
Implements frame-based knowledge organization and semantic relationships.
"""
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json


class SemanticRelation(Enum):
    """Types of semantic relationships in the security domain"""
    IS_A = "is_a"  # Hierarchical relationship
    INSTANCE_OF = "instance_of"  # Instance relationship
    CAUSES = "causes"  # Causal relationship
    PRECEDES = "precedes"  # Temporal precedence
    FOLLOWS = "follows"  # Temporal following
    RELATED_TO = "related_to"  # General association
    PART_OF = "part_of"  # Composition
    HAS_PART = "has_part"  # Decomposition
    INDICATES = "indicates"  # Symptom/indication
    MITIGATES = "mitigates"  # Countermeasure relationship


@dataclass
class OntologyNode:
    """Node in the semantic network"""
    name: str
    category: str
    description: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    relations: Dict[SemanticRelation, List[str]] = field(default_factory=dict)
    
    def add_relation(self, relation: SemanticRelation, target: str) -> None:
        """Add a semantic relation to another node"""
        if relation not in self.relations:
            self.relations[relation] = []
        if target not in self.relations[relation]:
            self.relations[relation].append(target)
    
    def get_related(self, relation: SemanticRelation) -> List[str]:
        """Get all nodes related by a specific relation type"""
        return self.relations.get(relation, [])
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'attributes': self.attributes,
            'relations': {k.value: v for k, v in self.relations.items()}
        }


class SecurityOntology:
    """
    Security domain ontology with semantic network.
    Models relationships between attack types, indicators, and countermeasures.
    """
    
    def __init__(self):
        self.nodes: Dict[str, OntologyNode] = {}
        self._build_core_ontology()
    
    def _build_core_ontology(self) -> None:
        """Build the core security ontology"""
        # Attack categories
        attack_categories = [
            ("authentication_attack", "attack_type", "Attacks targeting authentication mechanisms"),
            ("authorization_attack", "attack_type", "Attacks exploiting authorization flaws"),
            ("data_attack", "attack_type", "Attacks targeting data confidentiality/integrity"),
            ("network_attack", "attack_type", "Attacks on network infrastructure"),
            ("malware_attack", "attack_type", "Attacks using malicious software"),
            ("insider_threat", "attack_type", "Threats from internal actors"),
        ]
        
        for name, category, desc in attack_categories:
            self.add_node(name, category, desc)
        
        # Specific attack types with relationships
        attacks = [
            ("brute_force", "authentication_attack", "Repeated login attempts"),
            ("credential_stuffing", "authentication_attack", "Using leaked credentials"),
            ("impossible_travel", "authentication_attack", "Geographically impossible logins"),
            ("privilege_escalation", "authorization_attack", "Gaining higher privileges"),
            ("unauthorized_access", "authorization_attack", "Access without permission"),
            ("data_exfiltration", "data_attack", "Unauthorized data removal"),
            ("sql_injection", "data_attack", "Database injection attack"),
            ("ddos", "network_attack", "Distributed denial of service"),
            ("port_scan", "network_attack", "Network reconnaissance"),
            ("lateral_movement", "network_attack", "Moving through network"),
            ("c2_communication", "malware_attack", "Command and control traffic"),
            ("ransomware", "malware_attack", "Encryption-based extortion"),
            ("data_theft", "insider_threat", "Internal data stealing"),
            ("sabotage", "insider_threat", "Intentional system damage"),
        ]
        
        for name, parent, desc in attacks:
            self.add_node(name, "specific_attack", desc)
            self.add_relation(name, SemanticRelation.IS_A, parent)
            self.add_relation(parent, SemanticRelation.HAS_PART, name)
        
        # Indicators (symptoms/observables)
        indicators = [
            ("multiple_failed_logins", "indicator", "Repeated authentication failures"),
            ("rapid_fire_attempts", "indicator", "High-frequency login attempts"),
            ("off_hours_access", "indicator", "Activity outside business hours"),
            ("unusual_location", "indicator", "Login from new geography"),
            ("privilege_change", "indicator", "Modification of access rights"),
            ("large_data_transfer", "indicator", "Unusual data volume"),
            ("suspicious_process", "indicator", "Anomalous program execution"),
            ("external_communication", "indicator", "Traffic to external systems"),
        ]
        
        for name, category, desc in indicators:
            self.add_node(name, category, desc)
        
        # Link indicators to attacks (INDICATES relation)
        indicator_mappings = [
            ("multiple_failed_logins", "brute_force"),
            ("rapid_fire_attempts", "brute_force"),
            ("rapid_fire_attempts", "credential_stuffing"),
            ("unusual_location", "impossible_travel"),
            ("off_hours_access", "data_exfiltration"),
            ("off_hours_access", "insider_threat"),
            ("privilege_change", "privilege_escalation"),
            ("large_data_transfer", "data_exfiltration"),
            ("suspicious_process", "ransomware"),
            ("external_communication", "c2_communication"),
        ]
        
        for indicator, attack in indicator_mappings:
            self.add_relation(indicator, SemanticRelation.INDICATES, attack)
        
        # Temporal relationships (attack chains)
        temporal_chains = [
            ("port_scan", "lateral_movement"),
            ("brute_force", "privilege_escalation"),
            ("privilege_escalation", "data_exfiltration"),
            ("c2_communication", "ransomware"),
            ("lateral_movement", "data_exfiltration"),
        ]
        
        for source, target in temporal_chains:
            self.add_relation(source, SemanticRelation.PRECEDES, target)
            self.add_relation(target, SemanticRelation.FOLLOWS, source)
    
    def add_node(self, name: str, category: str, description: str = "",
                 attributes: Optional[Dict[str, Any]] = None) -> OntologyNode:
        """Add a node to the ontology"""
        if name not in self.nodes:
            self.nodes[name] = OntologyNode(
                name=name,
                category=category,
                description=description,
                attributes=attributes or {}
            )
        return self.nodes[name]
    
    def get_node(self, name: str) -> Optional[OntologyNode]:
        """Get a node by name"""
        return self.nodes.get(name)
    
    def add_relation(self, source: str, relation: SemanticRelation, target: str) -> None:
        """Add a semantic relation between nodes"""
        if source in self.nodes:
            self.nodes[source].add_relation(relation, target)
    
    def get_related_attacks(self, indicator: str) -> List[str]:
        """Get attacks indicated by a specific indicator"""
        node = self.nodes.get(indicator)
        if node:
            return node.get_related(SemanticRelation.INDICATES)
        return []
    
    def get_attack_chain(self, initial_attack: str, depth: int = 3) -> List[List[str]]:
        """
        Get possible attack chains starting from an initial attack.
        Returns list of paths (each path is a list of attack names).
        """
        chains = []
        
        def dfs(current: str, path: List[str], remaining_depth: int):
            path = path + [current]
            if remaining_depth == 0:
                chains.append(path)
                return
            
            node = self.nodes.get(current)
            if not node:
                chains.append(path)
                return
            
            next_attacks = node.get_related(SemanticRelation.PRECEDES)
            if not next_attacks:
                chains.append(path)
                return
            
            for next_attack in next_attacks:
                if next_attack not in path:  # Avoid cycles
                    dfs(next_attack, path, remaining_depth - 1)
        
        dfs(initial_attack, [], depth)
        return chains
    
    def find_common_indicators(self, attacks: List[str]) -> List[str]:
        """Find indicators common to multiple attacks"""
        if not attacks:
            return []
        
        common = None
        for attack in attacks:
            node = self.nodes.get(attack)
            if node:
                indicators = set(node.get_related(SemanticRelation.INDICATES))
                # Reverse lookup: find nodes that INDICATE this attack
                for name, node_obj in self.nodes.items():
                    if attack in node_obj.get_related(SemanticRelation.INDICATES):
                        indicators.add(name)
                
                if common is None:
                    common = indicators
                else:
                    common = common.intersection(indicators)
        
        return list(common) if common else []
    
    def to_dict(self) -> Dict[str, Any]:
        """Export ontology to dictionary"""
        return {
            'nodes': {k: v.to_dict() for k, v in self.nodes.items()}
        }
    
    def save_to_file(self, filepath: str) -> None:
        """Save ontology to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'SecurityOntology':
        """Load ontology from JSON file"""
        ontology = cls()
        with open(filepath, 'r') as f:
            data = json.load(f)
            # Reconstruct nodes and relations
            for name, node_data in data.get('nodes', {}).items():
                node = ontology.add_node(
                    name=name,
                    category=node_data['category'],
                    description=node_data.get('description', ''),
                    attributes=node_data.get('attributes', {})
                )
                for rel_str, targets in node_data.get('relations', {}).items():
                    relation = SemanticRelation(rel_str)
                    for target in targets:
                        node.add_relation(relation, target)
        return ontology


class EventOntology:
    """
    Ontology for log event types and their relationships.
    Maps raw log events to semantic categories.
    """
    
    def __init__(self):
        self.event_mappings: Dict[str, Dict[str, Any]] = {}
        self._build_event_mappings()
    
    def _build_event_mappings(self) -> None:
        """Build mappings from event patterns to semantic types"""
        mappings = {
            # Authentication events
            'login_success': {
                'patterns': ['login successful', 'authentication success', 'logged in'],
                'semantic_type': 'authentication',
                'outcome': 'success',
                'indicators': []
            },
            'login_failure': {
                'patterns': ['login failed', 'authentication failure', 'invalid credentials',
                           'wrong password', 'user not found'],
                'semantic_type': 'authentication',
                'outcome': 'failure',
                'indicators': ['multiple_failed_logins']
            },
            'logout': {
                'patterns': ['logout', 'session ended', 'user logged out'],
                'semantic_type': 'authentication',
                'outcome': 'logout',
                'indicators': []
            },
            
            # Authorization events
            'access_denied': {
                'patterns': ['access denied', 'permission denied', 'unauthorized',
                           'not authorized', 'access forbidden'],
                'semantic_type': 'authorization',
                'outcome': 'denied',
                'indicators': ['unauthorized_access']
            },
            'access_granted': {
                'patterns': ['access granted', 'permission granted', 'authorized'],
                'semantic_type': 'authorization',
                'outcome': 'granted',
                'indicators': []
            },
            'privilege_escalation': {
                'patterns': ['privilege escalation', 'sudo', 'elevated privileges',
                           'admin access granted', 'root access'],
                'semantic_type': 'privilege_escalation',
                'outcome': 'escalated',
                'indicators': ['privilege_change']
            },
            
            # Data events
            'file_access': {
                'patterns': ['file accessed', 'file opened', 'file read'],
                'semantic_type': 'data_access',
                'outcome': 'accessed',
                'indicators': []
            },
            'file_download': {
                'patterns': ['file downloaded', 'download complete', 'bulk download'],
                'semantic_type': 'data_exfiltration',
                'outcome': 'downloaded',
                'indicators': ['large_data_transfer']
            },
            'database_query': {
                'patterns': ['sql query', 'database access', 'select', 'insert', 'update'],
                'semantic_type': 'data_access',
                'outcome': 'queried',
                'indicators': []
            },
            
            # Network events
            'connection_established': {
                'patterns': ['connection established', 'connected to', 'tcp established'],
                'semantic_type': 'network_connection',
                'outcome': 'connected',
                'indicators': []
            },
            'connection_blocked': {
                'patterns': ['connection blocked', 'firewall drop', 'connection refused'],
                'semantic_type': 'network_connection',
                'outcome': 'blocked',
                'indicators': []
            },
            
            # Process events
            'process_started': {
                'patterns': ['process started', 'process created', 'execution started'],
                'semantic_type': 'process_execution',
                'outcome': 'started',
                'indicators': ['suspicious_process']
            },
            'process_terminated': {
                'patterns': ['process terminated', 'process ended', 'execution completed'],
                'semantic_type': 'process_execution',
                'outcome': 'terminated',
                'indicators': []
            },
        }
        
        self.event_mappings = mappings
    
    def classify_event(self, message: str) -> Optional[Dict[str, Any]]:
        """
        Classify a log message to its semantic type.
        Returns the matching event type or None.
        """
        message_lower = message.lower()
        
        for event_type, mapping in self.event_mappings.items():
            for pattern in mapping['patterns']:
                if pattern in message_lower:
                    return {
                        'event_type': event_type,
                        'semantic_type': mapping['semantic_type'],
                        'outcome': mapping['outcome'],
                        'indicators': mapping['indicators']
                    }
        
        return None
    
    def get_indicators_for_event(self, event_type: str) -> List[str]:
        """Get security indicators associated with an event type"""
        mapping = self.event_mappings.get(event_type)
        if mapping:
            return mapping.get('indicators', [])
        return []
