"""
Pattern matching engine implementing simplified Rete algorithm.
Efficiently matches facts against rule conditions.
"""
from typing import Dict, List, Set, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from collections import defaultdict
import time


@dataclass
class AlphaMemory:
    """
    Alpha memory stores facts that match a single condition.
    Part of the Rete network's alpha network.
    """
    condition_id: str
    facts: Set[str] = field(default_factory=set)  # Set of fact IDs
    
    def add_fact(self, fact_id: str) -> bool:
        """Add fact to alpha memory, return True if new"""
        if fact_id not in self.facts:
            self.facts.add(fact_id)
            return True
        return False
    
    def remove_fact(self, fact_id: str) -> bool:
        """Remove fact from alpha memory"""
        if fact_id in self.facts:
            self.facts.remove(fact_id)
            return True
        return False


@dataclass
class BetaMemory:
    """
    Beta memory stores partial matches (tokens) across multiple conditions.
    Part of the Rete network's beta network.
    """
    parent_node: Optional['BetaNode'] = None
    tokens: List[Dict[str, Any]] = field(default_factory=list)  # List of partial matches
    
    def add_token(self, token: Dict[str, Any]) -> None:
        """Add a partial match token"""
        self.tokens.append(token)
    
    def remove_tokens_with_fact(self, fact_id: str) -> None:
        """Remove all tokens containing a specific fact"""
        self.tokens = [t for t in self.tokens if fact_id not in t.get('fact_ids', [])]


@dataclass
class BetaNode:
    """
    Beta node performs joins between alpha and beta memories.
    """
    node_id: str
    alpha_memory: AlphaMemory
    beta_memory: BetaMemory
    join_tests: List[Callable] = field(default_factory=list)
    children: List['BetaNode'] = field(default_factory=list)
    
    def left_activation(self, fact_id: str, fact_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Activate from alpha memory (new fact)"""
        matches = []
        
        # Check against all tokens in beta memory
        for token in self.beta_memory.tokens:
            if self._perform_join_tests(fact_data, token):
                # Create new token combining fact and existing token
                new_token = {
                    'fact_ids': token.get('fact_ids', []) + [fact_id],
                    'bindings': {**token.get('bindings', {}), **fact_data}
                }
                matches.append(new_token)
                
                # Propagate to children
                for child in self.children:
                    child.left_activation(fact_id, fact_data)
        
        return matches
    
    def right_activation(self, token: Dict[str, Any]) -> None:
        """Activate from beta memory (new token)"""
        # Check against all facts in alpha memory
        for fact_id in self.alpha_memory.facts:
            # Fact data would be retrieved from working memory
            pass
    
    def _perform_join_tests(self, fact_data: Dict[str, Any], token: Dict[str, Any]) -> bool:
        """Perform join tests between fact and token"""
        for test in self.join_tests:
            if not test(fact_data, token):
                return False
        return True


@dataclass
class ProductionNode:
    """
    Production node represents a complete rule match.
    """
    rule_id: str
    rule_name: str
    matches: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_match(self, token: Dict[str, Any]) -> None:
        """Add a complete rule match"""
        self.matches.append(token)


class ReteNetwork:
    """
    Simplified Rete network for efficient pattern matching.
    Implements alpha and beta networks for rule condition matching.
    
    Complexity: O(1) for fact addition (amortized), O(rules × facts) worst case
    """
    
    def __init__(self):
        # Alpha network: condition -> AlphaMemory
        self.alpha_memories: Dict[str, AlphaMemory] = {}
        
        # Beta network
        self.beta_memories: Dict[str, BetaMemory] = {}
        self.beta_nodes: Dict[str, BetaNode] = {}
        
        # Production nodes (rule matches)
        self.production_nodes: Dict[str, ProductionNode] = {}
        
        # Root node
        self.root_beta = BetaMemory()
        self.root_beta.tokens = [{'fact_ids': [], 'bindings': {}}]  # Empty token
        
        # Statistics
        self.facts_processed = 0
        self.matches_found = 0
    
    def add_condition(self, condition_id: str, rule_id: str) -> AlphaMemory:
        """Add a condition to the alpha network"""
        if condition_id not in self.alpha_memories:
            self.alpha_memories[condition_id] = AlphaMemory(condition_id)
        return self.alpha_memories[condition_id]
    
    def add_production(self, rule_id: str, rule_name: str, 
                       condition_ids: List[str]) -> ProductionNode:
        """Add a production rule to the network"""
        # Create production node
        prod_node = ProductionNode(rule_id, rule_name)
        self.production_nodes[rule_id] = prod_node
        
        # Build beta network chain for this rule's conditions
        prev_beta = self.root_beta
        
        for i, cond_id in enumerate(condition_ids):
            alpha_mem = self.add_condition(cond_id, rule_id)
            
            # Create beta node for this join
            beta_node_id = f"{rule_id}_join_{i}"
            beta_mem = BetaMemory()
            self.beta_memories[beta_node_id] = beta_mem
            
            beta_node = BetaNode(
                node_id=beta_node_id,
                alpha_memory=alpha_mem,
                beta_memory=prev_beta
            )
            self.beta_nodes[beta_node_id] = beta_node
            
            # Link to previous node
            if prev_beta != self.root_beta:
                # Find parent beta node and add as child
                for bn in self.beta_nodes.values():
                    if bn.beta_memory == prev_beta:
                        bn.children.append(beta_node)
            
            prev_beta = beta_mem
        
        return prod_node
    
    def assert_fact(self, fact_id: str, fact_data: Dict[str, Any],
                    matching_conditions: List[str]) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Assert a fact into the network.
        Returns list of (rule_id, match_data) for triggered productions.
        """
        self.facts_processed += 1
        triggered = []
        
        # Add fact to matching alpha memories
        for cond_id in matching_conditions:
            if cond_id in self.alpha_memories:
                alpha_mem = self.alpha_memories[cond_id]
                is_new = alpha_mem.add_fact(fact_id)
                
                if is_new:
                    # Activate connected beta nodes
                    for beta_node in self.beta_nodes.values():
                        if beta_node.alpha_memory == alpha_mem:
                            matches = beta_node.left_activation(fact_id, fact_data)
                            
                            # Check if this completes a production
                            for match in matches:
                                # Find production node
                                for rule_id, prod_node in self.production_nodes.items():
                                    if any(cond_id in matching_conditions 
                                          for cond_id in self._get_rule_conditions(rule_id)):
                                        prod_node.add_match(match)
                                        triggered.append((rule_id, match))
                                        self.matches_found += 1
        
        return triggered
    
    def retract_fact(self, fact_id: str) -> None:
        """Retract a fact from the network"""
        # Remove from all alpha memories
        for alpha_mem in self.alpha_memories.values():
            alpha_mem.remove_fact(fact_id)
        
        # Remove from all beta memories
        for beta_mem in self.beta_memories.values():
            beta_mem.remove_tokens_with_fact(fact_id)
        
        # Remove from production nodes
        for prod_node in self.production_nodes.values():
            prod_node.matches = [m for m in prod_node.matches 
                               if fact_id not in m.get('fact_ids', [])]
    
    def _get_rule_conditions(self, rule_id: str) -> List[str]:
        """Get condition IDs for a rule (simplified)"""
        # This would be stored in a proper implementation
        return [f"{rule_id}_cond_{i}" for i in range(5)]  # Placeholder
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get network statistics"""
        return {
            'alpha_memories': len(self.alpha_memories),
            'beta_nodes': len(self.beta_nodes),
            'production_nodes': len(self.production_nodes),
            'facts_processed': self.facts_processed,
            'matches_found': self.matches_found
        }


class PatternMatcher:
    """
    High-level pattern matcher using Rete network or direct matching.
    Provides interface for matching facts against rule conditions.
    """
    
    def __init__(self, use_rete: bool = True):
        self.use_rete = use_rete
        self.rete = ReteNetwork() if use_rete else None
        
        # Direct matching fallback
        self.condition_cache: Dict[str, Callable] = {}
        
        # Performance tracking
        self.match_times: List[float] = []
    
    def register_rule(self, rule_id: str, rule_name: str, 
                      conditions: List[Dict[str, Any]]) -> None:
        """Register a rule with the pattern matcher"""
        if self.use_rete and self.rete:
            condition_ids = [f"{rule_id}_cond_{i}" for i in range(len(conditions))]
            self.rete.add_production(rule_id, rule_name, condition_ids)
            
            # Cache condition evaluators
            for i, cond in enumerate(conditions):
                cond_id = f"{rule_id}_cond_{i}"
                self.condition_cache[cond_id] = self._build_condition_evaluator(cond)
    
    def _build_condition_evaluator(self, condition: Dict[str, Any]) -> Callable:
        """Build a function to evaluate a condition against a fact"""
        def evaluator(fact: Dict[str, Any]) -> bool:
            for key, expected_value in condition.items():
                if key not in fact or fact[key] != expected_value:
                    return False
            return True
        return evaluator
    
    def match_fact(self, fact: Dict[str, Any], fact_id: str) -> List[Tuple[str, float]]:
        """
        Match a fact against registered rules.
        Returns list of (rule_id, match_confidence) tuples.
        """
        start_time = time.time()
        matches = []
        
        if self.use_rete and self.rete:
            # Find matching conditions
            matching_conditions = []
            for cond_id, evaluator in self.condition_cache.items():
                if evaluator(fact):
                    matching_conditions.append(cond_id)
            
            # Assert into Rete network
            triggered = self.rete.assert_fact(fact_id, fact, matching_conditions)
            matches = [(rule_id, 1.0) for rule_id, _ in triggered]
        else:
            # Direct matching
            matches = self._direct_match(fact)
        
        elapsed = time.time() - start_time
        self.match_times.append(elapsed)
        
        return matches
    
    def _direct_match(self, fact: Dict[str, Any]) -> List[Tuple[str, float]]:
        """Direct pattern matching without Rete"""
        matches = []
        
        for cond_id, evaluator in self.condition_cache.items():
            if evaluator(fact):
                # Extract rule ID from condition ID
                rule_id = cond_id.rsplit('_cond_', 1)[0]
                matches.append((rule_id, 1.0))
        
        return matches
    
    def match_batch(self, facts: List[Tuple[str, Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Match a batch of facts.
        Returns dict of rule_id -> list of matches.
        """
        all_matches: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        for fact_id, fact in facts:
            matches = self.match_fact(fact, fact_id)
            for rule_id, confidence in matches:
                all_matches[rule_id].append({
                    'fact_id': fact_id,
                    'fact': fact,
                    'confidence': confidence
                })
        
        return dict(all_matches)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pattern matcher statistics"""
        stats = {
            'registered_conditions': len(self.condition_cache),
            'avg_match_time_ms': (sum(self.match_times) / len(self.match_times) * 1000) 
                                if self.match_times else 0
        }
        
        if self.rete:
            stats['rete'] = self.rete.get_statistics()
        
        return stats
