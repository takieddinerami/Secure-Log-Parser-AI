"""
Forward-chaining inference engine for the expert system.
Implements conflict resolution and fact derivation.
"""
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
import heapq
import time

from ..models.fact import Fact, WorkingMemory
from ..models.anomaly import Anomaly, AnomalyType, ThreatLevel, Evidence
from ..knowledge_base.rule_base import RuleBase, ProductionRule, RuleCategory, RulePriority
from ..knowledge_base.certainties import CertaintyFactorAlgebra


@dataclass
class AgendaItem:
    """Item on the inference agenda (conflict set)"""
    rule: ProductionRule
    matching_facts: List[Fact]
    activation_time: datetime = field(default_factory=datetime.now)
    match_specificity: int = 0  # Number of conditions matched
    
    def __lt__(self, other: 'AgendaItem') -> bool:
        """Compare for priority queue ordering"""
        # Higher priority (lower enum value) comes first
        if self.rule.priority.value != other.rule.priority.value:
            return self.rule.priority.value < other.rule.priority.value
        
        # Higher specificity comes first
        if self.match_specificity != other.match_specificity:
            return self.match_specificity > other.match_specificity
        
        # More recent activation comes first
        return self.activation_time > other.activation_time


@dataclass
class FiredRule:
    """Record of a fired rule"""
    rule_id: str
    rule_name: str
    fired_at: datetime
    facts: List[str]
    derived_facts: List[str]
    certainty: float


@dataclass
class InferenceResult:
    """Result of inference cycle"""
    anomalies: List[Anomaly] = field(default_factory=list)
    fired_rules: List[FiredRule] = field(default_factory=list)
    facts_asserted: int = 0
    facts_retracted: int = 0
    cycles: int = 0
    execution_time_ms: float = 0.0
    
    def merge(self, other: 'InferenceResult') -> 'InferenceResult':
        """Merge another result into this one"""
        self.anomalies.extend(other.anomalies)
        self.fired_rules.extend(other.fired_rules)
        self.facts_asserted += other.facts_asserted
        self.facts_retracted += other.facts_retracted
        self.cycles += other.cycles
        self.execution_time_ms += other.execution_time_ms
        return self


class ForwardChainer:
    """
    Forward-chaining inference engine.
    
    Algorithm:
    1. Match phase: Find rules whose conditions match facts in working memory
    2. Conflict resolution: Select which rule to fire based on priority
    3. Action phase: Execute actions of selected rule
    4. Repeat until no more rules match or limit reached
    
    Conflict Resolution Strategies:
    - Priority ordering (CRITICAL > HIGH > MEDIUM > LOW)
    - Specificity (rules with more conditions fire first)
    - Recency (more recent matches fire first)
    - Certainty factor (higher CF rules preferred)
    """
    
    def __init__(self, rule_base: RuleBase, working_memory: WorkingMemory):
        self.rule_base = rule_base
        self.working_memory = working_memory
        
        # Agenda (conflict set)
        self.agenda: List[AgendaItem] = []
        
        # Fired rules history
        self.fired_rules: List[FiredRule] = []
        
        # Inference control
        self.max_iterations = 1000
        self.max_rules_per_cycle = 50
        
        # Performance tracking
        self.match_times: List[float] = []
        self.fire_times: List[float] = []
    
    def infer(self, context: Optional[Dict[str, Any]] = None) -> InferenceResult:
        """
        Run forward chaining inference.
        
        Returns InferenceResult containing all detected anomalies and fired rules.
        """
        start_time = time.time()
        result = InferenceResult()
        
        iteration = 0
        while iteration < self.max_iterations:
            # Match phase
            match_start = time.time()
            matches = self._match_rules()
            self.match_times.append(time.time() - match_start)
            
            if not matches:
                break
            
            # Build agenda
            self._build_agenda(matches)
            
            if not self.agenda:
                break
            
            # Fire rules from agenda
            rules_fired_this_cycle = 0
            while self.agenda and rules_fired_this_cycle < self.max_rules_per_cycle:
                item = heapq.heappop(self.agenda)
                
                fire_start = time.time()
                cycle_result = self._fire_rule(item, context)
                self.fire_times.append(time.time() - fire_start)
                
                result.merge(cycle_result)
                rules_fired_this_cycle += 1
                
                # Track fired rule
                self.fired_rules.append(FiredRule(
                    rule_id=item.rule.rule_id,
                    rule_name=item.rule.name,
                    fired_at=datetime.now(),
                    facts=[f.fact_id for f in item.matching_facts],
                    derived_facts=[f.fact_id for f in self.working_memory.get_recent_facts(10)],
                    certainty=item.rule.certainty
                ))
            
            result.cycles += 1
            iteration += 1
        
        result.execution_time_ms = (time.time() - start_time) * 1000
        return result
    
    def _match_rules(self) -> Dict[str, List[Fact]]:
        """
        Match phase: Find all rules whose conditions are satisfied.
        Returns dict of rule_id -> list of matching facts.
        """
        matches: Dict[str, List[Fact]] = {}
        
        for rule in self.rule_base.get_all_rules():
            matching_facts = self._match_rule_conditions(rule)
            if matching_facts:
                matches[rule.rule_id] = matching_facts
        
        return matches
    
    def _match_rule_conditions(self, rule: ProductionRule) -> List[Fact]:
        """Match a single rule's conditions against working memory"""
        all_facts = self.working_memory.get_all_facts()
        matching_facts = []
        
        for condition in rule.conditions:
            condition_matched = False
            
            for fact in all_facts:
                if self._evaluate_condition(condition, fact):
                    matching_facts.append(fact)
                    condition_matched = True
                    break
            
            if not condition_matched:
                # All conditions must match (AND logic)
                return []
        
        return matching_facts
    
    def _evaluate_condition(self, condition, fact: Fact) -> bool:
        """Evaluate a single condition against a fact"""
        # Check fact type
        if condition.fact_type and fact.fact_type != condition.fact_type:
            return False
        
        # Check subject
        if condition.subject and fact.subject != condition.subject:
            return False
        
        # Check predicate
        if condition.predicate and fact.predicate != condition.predicate:
            return False
        
        # Check value
        if condition.value is not None:
            return condition.evaluate(fact.value)
        
        return True
    
    def _build_agenda(self, matches: Dict[str, List[Fact]]) -> None:
        """Build priority queue of rule activations"""
        self.agenda = []
        
        for rule_id, facts in matches.items():
            rule = self.rule_base.get_rule(rule_id)
            if not rule:
                continue
            
            # Check if rule already fired with same facts
            if self._rule_already_fired(rule_id, facts):
                continue
            
            item = AgendaItem(
                rule=rule,
                matching_facts=facts,
                match_specificity=len(rule.conditions)
            )
            
            heapq.heappush(self.agenda, item)
    
    def _rule_already_fired(self, rule_id: str, facts: List[Fact]) -> bool:
        """Check if rule already fired with same facts"""
        fact_ids = frozenset(f.fact_id for f in facts)
        
        for fired in self.fired_rules:
            if fired.rule_id == rule_id:
                fired_fact_ids = frozenset(fired.facts)
                if fired_fact_ids == fact_ids:
                    return True
        
        return False
    
    def _fire_rule(self, item: AgendaItem, context: Optional[Dict[str, Any]]) -> InferenceResult:
        """Execute actions of a fired rule"""
        result = InferenceResult()
        rule = item.rule
        
        # Calculate effective certainty
        evidence_cfs = [f.certainty for f in item.matching_facts if f.certainty is not None]
        if evidence_cfs:
            combined_evidence_cf = CertaintyFactorAlgebra.combine_multiple(evidence_cfs)
            effective_cf = CertaintyFactorAlgebra.sequential_combination(
                rule.certainty, combined_evidence_cf
            )
        else:
            effective_cf = rule.certainty
        
        # Execute actions
        for action in rule.actions:
            if action.action_type == "create_anomaly":
                anomaly = self._create_anomaly_from_action(
                    action, rule, item.matching_facts, effective_cf
                )
                result.anomalies.append(anomaly)
            
            elif action.action_type == "assert_fact":
                new_fact = Fact.create(
                    fact_type=action.parameters.get('fact_type', 'inferred'),
                    subject=action.parameters.get('subject', 'system'),
                    predicate=action.parameters.get('predicate', 'derived'),
                    value=action.parameters.get('value'),
                    certainty=effective_cf,
                    derived_from=[f.fact_id for f in item.matching_facts]
                )
                self.working_memory.assert_fact(new_fact)
                result.facts_asserted += 1
            
            elif action.action_type == "update_score":
                # Update threat score in context
                if context is not None:
                    current_score = context.get('threat_score', 0)
                    delta = action.parameters.get('delta', 0)
                    context['threat_score'] = min(100, current_score + delta * effective_cf)
        
        result.fired_rules.append(FiredRule(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            fired_at=datetime.now(),
            facts=[f.fact_id for f in item.matching_facts],
            derived_facts=[],
            certainty=effective_cf
        ))
        
        return result
    
    def _create_anomaly_from_action(self, action, rule: ProductionRule,
                                    facts: List[Fact], certainty: float) -> Anomaly:
        """Create an anomaly from a rule action"""
        # Determine anomaly type
        anomaly_type = AnomalyType.UNKNOWN
        if action.anomaly_type:
            try:
                anomaly_type = AnomalyType(action.anomaly_type)
            except ValueError:
                pass
        
        # Determine threat level
        threat_level = ThreatLevel.INFO
        if action.threat_level:
            try:
                threat_level = ThreatLevel[action.threat_level]
            except KeyError:
                pass
        
        # Collect affected entities
        affected_users = []
        source_ips = []
        source_events = []
        
        for fact in facts:
            if fact.fact_type == "event":
                source_events.append(fact.source_event_id or fact.fact_id)
            
            # Extract user info from fact metadata
            if 'user_id' in fact.metadata:
                affected_users.append(fact.metadata['user_id'])
            if 'source_ip' in fact.metadata:
                source_ips.append(fact.metadata['source_ip'])
        
        # Create evidence
        evidence = Evidence(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            description=rule.description,
            certainty=certainty,
            matched_facts=[f.fact_id for f in facts],
            contributing_attributes={
                'fact_types': [f.fact_type for f in facts],
                'predicates': [f.predicate for f in facts],
                'subjects': [f.subject for f in facts]
            }
        )
        
        # Create anomaly
        anomaly = Anomaly(
            anomaly_type=anomaly_type,
            detection_layer="signature",
            affected_users=list(set(affected_users)),
            source_ips=list(set(source_ips)),
            source_events=list(set(source_events)),
            threat_level=threat_level,
            certainty=certainty,
            recommendation=action.recommendation,
            triggered_rules=[rule.rule_id]
        )
        
        anomaly.add_evidence(evidence)
        anomaly.calculate_threat_score()
        anomaly.generate_explanation()
        
        return anomaly
    
    def get_explanation(self) -> Dict[str, Any]:
        """Get explanation of inference process"""
        return {
            'fired_rules': [
                {
                    'rule_id': fr.rule_id,
                    'rule_name': fr.rule_name,
                    'fired_at': fr.fired_at.isoformat(),
                    'certainty': fr.certainty
                }
                for fr in self.fired_rules
            ],
            'performance': {
                'avg_match_time_ms': (sum(self.match_times) / len(self.match_times) * 1000) 
                                    if self.match_times else 0,
                'avg_fire_time_ms': (sum(self.fire_times) / len(self.fire_times) * 1000) 
                                   if self.fire_times else 0,
                'total_rules_fired': len(self.fired_rules)
            }
        }
    
    def reset(self) -> None:
        """Reset inference engine state"""
        self.agenda = []
        self.fired_rules = []
        self.match_times = []
        self.fire_times = []
