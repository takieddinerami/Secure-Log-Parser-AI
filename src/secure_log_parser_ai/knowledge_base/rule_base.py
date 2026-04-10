"""
Production rule base for the expert system.
Implements 20+ security detection rules with certainty factors.
"""
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import json
import re


class RuleCategory(Enum):
    """Categories of security detection rules"""
    AUTHENTICATION = "authentication"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    MALWARE = "malware"
    INSIDER_THREAT = "insider_threat"
    NETWORK_ANOMALY = "network_anomaly"
    STATISTICAL = "statistical"
    BEHAVIORAL = "behavioral"


class RulePriority(Enum):
    """Rule priority for conflict resolution"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class RuleCondition:
    """
    Condition for a production rule.
    Can be evaluated against working memory facts.
    """
    fact_type: Optional[str] = None
    subject: Optional[str] = None
    predicate: Optional[str] = None
    value: Any = None
    operator: str = "=="  # ==, !=, <, >, <=, >=, in, matches, exists
    custom_check: Optional[Callable] = None
    
    def evaluate(self, fact_value: Any) -> bool:
        """Evaluate condition against a fact value"""
        if self.custom_check:
            return self.custom_check(fact_value)
        
        if self.operator == "==":
            return fact_value == self.value
        elif self.operator == "!=":
            return fact_value != self.value
        elif self.operator == "<":
            return fact_value < self.value
        elif self.operator == ">":
            return fact_value > self.value
        elif self.operator == "<=":
            return fact_value <= self.value
        elif self.operator == ">=":
            return fact_value >= self.value
        elif self.operator == "in":
            return fact_value in self.value
        elif self.operator == "matches":
            return bool(re.search(self.value, str(fact_value)))
        elif self.operator == "exists":
            return fact_value is not None
        
        return False


@dataclass
class RuleAction:
    """
    Action to take when rule fires.
    """
    action_type: str  # 'assert_fact', 'create_anomaly', 'update_score', 'flag_event'
    parameters: Dict[str, Any] = field(default_factory=dict)
    anomaly_type: Optional[str] = None
    threat_level: Optional[str] = None
    recommendation: str = ""


@dataclass
class ProductionRule:
    """
    Production rule for the expert system.
    Format: IF <conditions> THEN <action> [CF <certainty_factor>]
    """
    rule_id: str
    name: str
    description: str
    category: RuleCategory
    priority: RulePriority
    certainty: float  # Rule certainty factor (0.0 - 1.0)
    
    # Conditions (AND logic - all must match)
    conditions: List[RuleCondition] = field(default_factory=list)
    
    # Actions to take when rule fires
    actions: List[RuleAction] = field(default_factory=list)
    
    # Metadata
    requires_aggregation: bool = False  # Requires aggregated facts
    time_window: Optional[int] = None  # Time window in seconds for temporal rules
    
    def __post_init__(self):
        # Clamp certainty to valid range
        self.certainty = max(0.0, min(1.0, self.certainty))
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'priority': self.priority.value,
            'certainty': self.certainty,
            'requires_aggregation': self.requires_aggregation,
            'time_window': self.time_window
        }


class RuleBase:
    """
    Production rule base containing all detection rules.
    Organized by category for efficient retrieval.
    """
    
    def __init__(self):
        self.rules: Dict[str, ProductionRule] = {}
        self._by_category: Dict[RuleCategory, List[str]] = {}
        self._by_priority: Dict[RulePriority, List[str]] = {}
        
        self._build_rule_base()
    
    def add_rule(self, rule: ProductionRule) -> None:
        """Add a rule to the rule base"""
        self.rules[rule.rule_id] = rule
        
        # Index by category
        if rule.category not in self._by_category:
            self._by_category[rule.category] = []
        self._by_category[rule.category].append(rule.rule_id)
        
        # Index by priority
        if rule.priority not in self._by_priority:
            self._by_priority[rule.priority] = []
        self._by_priority[rule.priority].append(rule.rule_id)
    
    def get_rule(self, rule_id: str) -> Optional[ProductionRule]:
        """Get rule by ID"""
        return self.rules.get(rule_id)
    
    def get_rules_by_category(self, category: RuleCategory) -> List[ProductionRule]:
        """Get all rules in a category"""
        rule_ids = self._by_category.get(category, [])
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]
    
    def get_rules_by_priority(self, priority: RulePriority) -> List[ProductionRule]:
        """Get all rules with a specific priority"""
        rule_ids = self._by_priority.get(priority, [])
        return [self.rules[rid] for rid in rule_ids if rid in self.rules]
    
    def get_all_rules(self) -> List[ProductionRule]:
        """Get all rules"""
        return list(self.rules.values())
    
    def _build_rule_base(self) -> None:
        """Build the complete rule base with 20+ security rules"""
        
        # ============================================================
        # AUTHENTICATION ANOMALIES (Rules 1-6)
        # ============================================================
        
        # Rule 1: Brute Force Attack Detection
        self.add_rule(ProductionRule(
            rule_id="AUTH-001",
            name="Brute Force Attack Detection",
            description="Detect multiple failed login attempts from same source",
            category=RuleCategory.AUTHENTICATION,
            priority=RulePriority.HIGH,
            certainty=0.85,
            conditions=[
                RuleCondition(fact_type="aggregated", predicate="failed_login_count", operator=">=", value=5),
                RuleCondition(fact_type="aggregated", predicate="time_window_seconds", operator="<=", value=300),
                RuleCondition(fact_type="aggregated", predicate="unique_usernames", operator=">=", value=1),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="brute_force_attack",
                    threat_level="HIGH",
                    recommendation="Block source IP and review authentication logs"
                )
            ],
            requires_aggregation=True,
            time_window=300
        ))
        
        # Rule 2: Credential Stuffing Detection
        self.add_rule(ProductionRule(
            rule_id="AUTH-002",
            name="Credential Stuffing Detection",
            description="Detect credential stuffing using multiple usernames from same source",
            category=RuleCategory.AUTHENTICATION,
            priority=RulePriority.HIGH,
            certainty=0.90,
            conditions=[
                RuleCondition(fact_type="aggregated", predicate="failed_login_count", operator=">=", value=10),
                RuleCondition(fact_type="aggregated", predicate="unique_usernames", operator=">=", value=5),
                RuleCondition(fact_type="aggregated", predicate="success_rate", operator="<=", value=0.1),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="credential_stuffing",
                    threat_level="CRITICAL",
                    recommendation="Implement CAPTCHA and rate limiting immediately"
                )
            ],
            requires_aggregation=True,
            time_window=600
        ))
        
        # Rule 3: Impossible Travel Detection
        self.add_rule(ProductionRule(
            rule_id="AUTH-003",
            name="Impossible Travel Detection",
            description="Detect logins from geographically distant locations in short time",
            category=RuleCategory.AUTHENTICATION,
            priority=RulePriority.CRITICAL,
            certainty=0.92,
            conditions=[
                RuleCondition(fact_type="temporal", predicate="same_user_different_country", operator="==", value=True),
                RuleCondition(fact_type="temporal", predicate="time_between_logins_minutes", operator="<=", value=60),
                RuleCondition(fact_type="temporal", predicate="distance_km", operator=">=", value=500),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="impossible_travel",
                    threat_level="CRITICAL",
                    recommendation="Force password reset and verify user identity"
                )
            ],
            requires_aggregation=True
        ))
        
        # Rule 4: Off-Hours Login Detection
        self.add_rule(ProductionRule(
            rule_id="AUTH-004",
            name="Off-Hours Login Detection",
            description="Detect login attempts outside normal business hours",
            category=RuleCategory.AUTHENTICATION,
            priority=RulePriority.MEDIUM,
            certainty=0.65,
            conditions=[
                RuleCondition(fact_type="event", predicate="is_business_hours", operator="==", value=False),
                RuleCondition(fact_type="event", predicate="is_night", operator="==", value=True),
                RuleCondition(fact_type="behavioral", predicate="user_typical_hours", operator="==", value="business_hours"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="suspicious_login_time",
                    threat_level="LOW",
                    recommendation="Review access patterns for this user"
                )
            ]
        ))
        
        # Rule 5: Weekend Access Anomaly
        self.add_rule(ProductionRule(
            rule_id="AUTH-005",
            name="Weekend Access Anomaly",
            description="Detect unusual weekend access by users who typically don't work weekends",
            category=RuleCategory.AUTHENTICATION,
            priority=RulePriority.MEDIUM,
            certainty=0.60,
            conditions=[
                RuleCondition(fact_type="event", predicate="is_weekend", operator="==", value=True),
                RuleCondition(fact_type="behavioral", predicate="user_weekend_access_frequency", operator="<=", value=0.1),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="off_hours_access",
                    threat_level="LOW",
                    recommendation="Verify business justification for weekend access"
                )
            ]
        ))
        
        # Rule 6: Rapid Authentication Failures
        self.add_rule(ProductionRule(
            rule_id="AUTH-006",
            name="Rapid Authentication Failures",
            description="Detect burst of authentication failures indicating automated attack",
            category=RuleCategory.AUTHENTICATION,
            priority=RulePriority.HIGH,
            certainty=0.80,
            conditions=[
                RuleCondition(fact_type="aggregated", predicate="failed_login_count", operator=">=", value=3),
                RuleCondition(fact_type="aggregated", predicate="time_window_seconds", operator="<=", value=60),
                RuleCondition(fact_type="aggregated", predicate="event_rate_per_second", operator=">=", value=1.0),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="failed_login_anomaly",
                    threat_level="MEDIUM",
                    recommendation="Monitor for potential brute force attack"
                )
            ],
            requires_aggregation=True,
            time_window=60
        ))
        
        # ============================================================
        # PRIVILEGE ESCALATION (Rules 7-9)
        # ============================================================
        
        # Rule 7: Unauthorized Privilege Escalation
        self.add_rule(ProductionRule(
            rule_id="PRIV-001",
            name="Unauthorized Privilege Escalation",
            description="Detect privilege escalation by non-admin users",
            category=RuleCategory.PRIVILEGE_ESCALATION,
            priority=RulePriority.CRITICAL,
            certainty=0.90,
            conditions=[
                RuleCondition(fact_type="event", predicate="event_type", operator="==", value="privilege_escalation"),
                RuleCondition(fact_type="event", predicate="user_role", operator="in", value=["guest", "user", "standard"]),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="privilege_escalation",
                    threat_level="CRITICAL",
                    recommendation="Immediately revoke elevated privileges and investigate"
                )
            ]
        ))
        
        # Rule 8: Sudo Abuse Detection
        self.add_rule(ProductionRule(
            rule_id="PRIV-002",
            name="Sudo Abuse Detection",
            description="Detect unusual sudo command usage patterns",
            category=RuleCategory.PRIVILEGE_ESCALATION,
            priority=RulePriority.HIGH,
            certainty=0.75,
            conditions=[
                RuleCondition(fact_type="event", predicate="event_type", operator="==", value="privilege_escalation"),
                RuleCondition(fact_type="aggregated", predicate="sudo_commands_count", operator=">=", value=10),
                RuleCondition(fact_type="behavioral", predicate="user_typical_sudo_frequency", operator="<=", value=2),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="sudo_abuse",
                    threat_level="HIGH",
                    recommendation="Review sudo commands executed and user activity"
                )
            ],
            requires_aggregation=True,
            time_window=3600
        ))
        
        # Rule 9: Access to Sensitive Resources
        self.add_rule(ProductionRule(
            rule_id="PRIV-003",
            name="Unauthorized Sensitive Resource Access",
            description="Detect access to sensitive resources by unauthorized users",
            category=RuleCategory.PRIVILEGE_ESCALATION,
            priority=RulePriority.HIGH,
            certainty=0.85,
            conditions=[
                RuleCondition(fact_type="event", predicate="resource_classification", operator="==", value="sensitive"),
                RuleCondition(fact_type="event", predicate="user_clearance_level", operator="<", value=3),
                RuleCondition(fact_type="event", predicate="access_granted", operator="==", value=True),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="unauthorized_access",
                    threat_level="HIGH",
                    recommendation="Review access controls and revoke unauthorized access"
                )
            ]
        ))
        
        # ============================================================
        # DATA EXFILTRATION (Rules 10-12)
        # ============================================================
        
        # Rule 10: Data Exfiltration Pattern
        self.add_rule(ProductionRule(
            rule_id="DATA-001",
            name="Data Exfiltration Pattern",
            description="Detect potential data exfiltration based on volume and timing",
            category=RuleCategory.DATA_EXFILTRATION,
            priority=RulePriority.CRITICAL,
            certainty=0.78,
            conditions=[
                RuleCondition(fact_type="event", predicate="data_volume_mb", operator=">=", value=100),
                RuleCondition(fact_type="event", predicate="is_business_hours", operator="==", value=False),
                RuleCondition(fact_type="event", predicate="direction", operator="==", value="egress"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="data_exfiltration",
                    threat_level="CRITICAL",
                    recommendation="Block data transfer and investigate data loss prevention"
                )
            ]
        ))
        
        # Rule 11: Large Download Anomaly
        self.add_rule(ProductionRule(
            rule_id="DATA-002",
            name="Large Download Anomaly",
            description="Detect unusually large data downloads",
            category=RuleCategory.DATA_EXFILTRATION,
            priority=RulePriority.HIGH,
            certainty=0.70,
            conditions=[
                RuleCondition(fact_type="event", predicate="data_volume_mb", operator=">=", value=500),
                RuleCondition(fact_type="statistical", predicate="z_score", operator=">=", value=3.0),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="large_download",
                    threat_level="MEDIUM",
                    recommendation="Verify legitimacy of large data transfer"
                )
            ]
        ))
        
        # Rule 12: Unusual Data Access Pattern
        self.add_rule(ProductionRule(
            rule_id="DATA-003",
            name="Unusual Data Access Pattern",
            description="Detect access to data not typically accessed by user",
            category=RuleCategory.DATA_EXFILTRATION,
            priority=RulePriority.MEDIUM,
            certainty=0.65,
            conditions=[
                RuleCondition(fact_type="event", predicate="database_tables_accessed", operator=">=", value=5),
                RuleCondition(fact_type="behavioral", predicate="user_typical_table_access", operator="<=", value=2),
                RuleCondition(fact_type="event", predicate="query_type", operator="==", value="SELECT"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="unusual_data_access",
                    threat_level="MEDIUM",
                    recommendation="Review database access logs for this user"
                )
            ]
        ))
        
        # ============================================================
        # MALWARE INDICATORS (Rules 13-15)
        # ============================================================
        
        # Rule 13: Suspicious Process Execution
        self.add_rule(ProductionRule(
            rule_id="MAL-001",
            name="Suspicious Process Execution",
            description="Detect execution of potentially malicious processes",
            category=RuleCategory.MALWARE,
            priority=RulePriority.CRITICAL,
            certainty=0.88,
            conditions=[
                RuleCondition(fact_type="event", predicate="process_name", operator="in", 
                            value=["mimikatz", "pwdump", "nc.exe", "nmap", "metasploit"]),
                RuleCondition(fact_type="event", predicate="event_type", operator="==", value="process_execution"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="malware_behavior",
                    threat_level="CRITICAL",
                    recommendation="Isolate system and perform malware scan immediately"
                )
            ]
        ))
        
        # Rule 14: C2 Communication Pattern
        self.add_rule(ProductionRule(
            rule_id="MAL-002",
            name="Command and Control Communication",
            description="Detect potential C2 communication patterns",
            category=RuleCategory.MALWARE,
            priority=RulePriority.CRITICAL,
            certainty=0.82,
            conditions=[
                RuleCondition(fact_type="event", predicate="connection_pattern", operator="==", value="beaconing"),
                RuleCondition(fact_type="aggregated", predicate="unique_external_ips", operator="==", value=1),
                RuleCondition(fact_type="aggregated", predicate="connection_interval_variance", operator="<=", value=5),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="c2_communication",
                    threat_level="CRITICAL",
                    recommendation="Block external IP and investigate for malware"
                )
            ],
            requires_aggregation=True,
            time_window=1800
        ))
        
        # Rule 15: PowerShell Obfuscation Detection
        self.add_rule(ProductionRule(
            rule_id="MAL-003",
            name="PowerShell Obfuscation Detection",
            description="Detect obfuscated PowerShell commands",
            category=RuleCategory.MALWARE,
            priority=RulePriority.HIGH,
            certainty=0.85,
            conditions=[
                RuleCondition(fact_type="event", predicate="process_name", operator="==", value="powershell.exe"),
                RuleCondition(fact_type="event", predicate="command_line", operator="matches", 
                            value=r"(FromBase64String|EncodedCommand|bypass|noprofile|windowstyle hidden)"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="suspicious_process",
                    threat_level="HIGH",
                    recommendation="Analyze PowerShell command and check for malware"
                )
            ]
        ))
        
        # ============================================================
        # INSIDER THREATS (Rules 16-17)
        # ============================================================
        
        # Rule 16: Insider Data Theft Pattern
        self.add_rule(ProductionRule(
            rule_id="INS-001",
            name="Insider Data Theft Pattern",
            description="Detect potential insider threat based on data access patterns",
            category=RuleCategory.INSIDER_THREAT,
            priority=RulePriority.HIGH,
            certainty=0.75,
            conditions=[
                RuleCondition(fact_type="event", predicate="data_classification", operator="==", value="confidential"),
                RuleCondition(fact_type="event", predicate="is_business_hours", operator="==", value=False),
                RuleCondition(fact_type="aggregated", predicate="files_accessed_count", operator=">=", value=50),
                RuleCondition(fact_type="behavioral", predicate="user_resignation_notice", operator="==", value=True),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="insider_threat",
                    threat_level="HIGH",
                    recommendation="Review user's data access and consider access revocation"
                )
            ],
            requires_aggregation=True
        ))
        
        # Rule 17: Policy Violation Detection
        self.add_rule(ProductionRule(
            rule_id="INS-002",
            name="Security Policy Violation",
            description="Detect violations of security policies",
            category=RuleCategory.INSIDER_THREAT,
            priority=RulePriority.MEDIUM,
            certainty=0.70,
            conditions=[
                RuleCondition(fact_type="event", predicate="usb_inserted", operator="==", value=True),
                RuleCondition(fact_type="event", predicate="data_copied_to_removable", operator="==", value=True),
                RuleCondition(fact_type="event", predicate="dlp_policy", operator="==", value="violated"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="policy_violation",
                    threat_level="MEDIUM",
                    recommendation="Review DLP logs and enforce removable media policy"
                )
            ]
        ))
        
        # ============================================================
        # NETWORK ANOMALIES (Rules 18-20)
        # ============================================================
        
        # Rule 18: DDoS Attack Detection
        self.add_rule(ProductionRule(
            rule_id="NET-001",
            name="DDoS Attack Detection",
            description="Detect potential DDoS attack patterns",
            category=RuleCategory.NETWORK_ANOMALY,
            priority=RulePriority.CRITICAL,
            certainty=0.85,
            conditions=[
                RuleCondition(fact_type="aggregated", predicate="connection_count", operator=">=", value=10000),
                RuleCondition(fact_type="aggregated", predicate="time_window_seconds", operator="<=", value=60),
                RuleCondition(fact_type="aggregated", predicate="unique_source_ips", operator=">=", value=100),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="ddos_attack",
                    threat_level="CRITICAL",
                    recommendation="Activate DDoS mitigation and contact ISP"
                )
            ],
            requires_aggregation=True,
            time_window=60
        ))
        
        # Rule 19: Port Scan Detection
        self.add_rule(ProductionRule(
            rule_id="NET-002",
            name="Port Scan Detection",
            description="Detect network port scanning activity",
            category=RuleCategory.NETWORK_ANOMALY,
            priority=RulePriority.HIGH,
            certainty=0.80,
            conditions=[
                RuleCondition(fact_type="aggregated", predicate="unique_destination_ports", operator=">=", value=20),
                RuleCondition(fact_type="aggregated", predicate="time_window_seconds", operator="<=", value=300),
                RuleCondition(fact_type="aggregated", predicate="source_ip", operator="==", value="single"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="port_scan",
                    threat_level="MEDIUM",
                    recommendation="Block scanning IP and review firewall rules"
                )
            ],
            requires_aggregation=True,
            time_window=300
        ))
        
        # Rule 20: Lateral Movement Detection
        self.add_rule(ProductionRule(
            rule_id="NET-003",
            name="Lateral Movement Detection",
            description="Detect potential lateral movement in network",
            category=RuleCategory.NETWORK_ANOMALY,
            priority=RulePriority.CRITICAL,
            certainty=0.78,
            conditions=[
                RuleCondition(fact_type="aggregated", predicate="unique_internal_targets", operator=">=", value=5),
                RuleCondition(fact_type="event", predicate="authentication_success", operator="==", value=True),
                RuleCondition(fact_type="aggregated", predicate="time_window_seconds", operator="<=", value=600),
                RuleCondition(fact_type="event", predicate="service", operator="in", value=["smb", "rdp", "ssh", "winrm"]),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="lateral_movement",
                    threat_level="CRITICAL",
                    recommendation="Isolate compromised account and scan affected systems"
                )
            ],
            requires_aggregation=True,
            time_window=600
        ))
        
        # ============================================================
        # STATISTICAL ANOMALIES (Rules 21-22)
        # ============================================================
        
        # Rule 21: Statistical Outlier Detection
        self.add_rule(ProductionRule(
            rule_id="STAT-001",
            name="Statistical Outlier Detection",
            description="Detect events that are statistical outliers",
            category=RuleCategory.STATISTICAL,
            priority=RulePriority.MEDIUM,
            certainty=0.70,
            conditions=[
                RuleCondition(fact_type="statistical", predicate="z_score", operator=">=", value=3.0),
                RuleCondition(fact_type="statistical", predicate="outlier_direction", operator="==", value="high"),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="statistical_outlier",
                    threat_level="MEDIUM",
                    recommendation="Review anomalous activity for potential security issue"
                )
            ]
        ))
        
        # Rule 22: Behavioral Baseline Deviation
        self.add_rule(ProductionRule(
            rule_id="BEH-001",
            name="Behavioral Baseline Deviation",
            description="Detect deviation from established behavioral baseline",
            category=RuleCategory.BEHAVIORAL,
            priority=RulePriority.MEDIUM,
            certainty=0.65,
            conditions=[
                RuleCondition(fact_type="behavioral", predicate="baseline_deviation_score", operator=">=", value=0.8),
                RuleCondition(fact_type="behavioral", predicate="confidence", operator=">=", value=0.7),
            ],
            actions=[
                RuleAction(
                    action_type="create_anomaly",
                    anomaly_type="behavioral_anomaly",
                    threat_level="MEDIUM",
                    recommendation="Review user's recent activity against historical baseline"
                )
            ]
        ))
    
    def save_to_file(self, filepath: str) -> None:
        """Save rule base to JSON file"""
        data = {
            'rules': [rule.to_dict() for rule in self.rules.values()],
            'statistics': {
                'total_rules': len(self.rules),
                'by_category': {k.value: len(v) for k, v in self._by_category.items()}
            }
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get rule base statistics"""
        return {
            'total_rules': len(self.rules),
            'by_category': {k.value: len(v) for k, v in self._by_category.items()},
            'by_priority': {k.name: len(v) for k, v in self._by_priority.items()}
        }
