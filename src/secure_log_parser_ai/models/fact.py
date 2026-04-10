"""
Working memory representation for the inference engine.
Implements fact storage and retrieval with hash-based indexing.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import hashlib


@dataclass
class Fact:
    """
    Represents a fact in the working memory.
    Facts are derived from log events or inferred by rules.
    """
    fact_id: str
    fact_type: str  # e.g., 'event_fact', 'inferred_fact', 'aggregated_fact'
    subject: str  # Entity the fact is about (user, IP, etc.)
    predicate: str  # Relationship or attribute
    value: Any  # The actual value
    certainty: float = 1.0  # Certainty factor (0.0 - 1.0)
    source_event_id: Optional[str] = None
    derived_from: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __hash__(self) -> int:
        """Hash based on fact content for indexing"""
        return hash((self.fact_type, self.subject, self.predicate, str(self.value)))
    
    def __eq__(self, other) -> bool:
        if not isinstance(other, Fact):
            return False
        return (self.fact_type == other.fact_type and 
                self.subject == other.subject and 
                self.predicate == other.predicate and 
                self.value == other.value)
    
    def to_tuple(self) -> tuple:
        """Convert to tuple representation for pattern matching"""
        return (self.fact_type, self.subject, self.predicate, self.value)
    
    @classmethod
    def create(cls, fact_type: str, subject: str, predicate: str, value: Any,
               certainty: float = 1.0, source_event_id: Optional[str] = None,
               **metadata) -> 'Fact':
        """Factory method to create a fact with auto-generated ID"""
        content = f"{fact_type}:{subject}:{predicate}:{str(value)}:{datetime.now().isoformat()}"
        fact_id = hashlib.md5(content.encode()).hexdigest()[:12]
        
        return cls(
            fact_id=fact_id,
            fact_type=fact_type,
            subject=subject,
            predicate=predicate,
            value=value,
            certainty=certainty,
            source_event_id=source_event_id,
            metadata=metadata
        )


class WorkingMemory:
    """
    Working memory for the inference engine.
    Provides O(1) fact lookup through multiple indices.
    """
    
    def __init__(self):
        # Primary storage: fact_id -> Fact
        self.facts: Dict[str, Fact] = {}
        
        # Indices for efficient querying
        self._by_type: Dict[str, Set[str]] = {}  # fact_type -> set of fact_ids
        self._by_subject: Dict[str, Set[str]] = {}  # subject -> set of fact_ids
        self._by_predicate: Dict[str, Set[str]] = {}  # predicate -> set of fact_ids
        self._by_event: Dict[str, Set[str]] = {}  # source_event_id -> set of fact_ids
        
        # Temporal index
        self._chronological: List[str] = []  # fact_ids in insertion order
        
        # Assertion history for truth maintenance
        self._assertion_history: List[tuple] = []  # (timestamp, fact_id, operation)
    
    def assert_fact(self, fact: Fact) -> bool:
        """
        Assert a fact into working memory.
        Returns True if fact was newly added, False if already existed.
        """
        if fact.fact_id in self.facts:
            # Fact already exists, update certainty if higher
            existing = self.facts[fact.fact_id]
            if fact.certainty > existing.certainty:
                existing.certainty = fact.certainty
            return False
        
        # Store fact
        self.facts[fact.fact_id] = fact
        self._chronological.append(fact.fact_id)
        
        # Update indices
        self._index_fact(fact)
        
        # Record assertion
        self._assertion_history.append((datetime.now(), fact.fact_id, 'ASSERT'))
        
        return True
    
    def retract_fact(self, fact_id: str) -> bool:
        """
        Retract a fact from working memory.
        Returns True if fact was removed, False if not found.
        """
        if fact_id not in self.facts:
            return False
        
        fact = self.facts[fact_id]
        
        # Remove from indices
        self._unindex_fact(fact)
        
        # Remove from primary storage
        del self.facts[fact_id]
        
        # Remove from chronological list
        if fact_id in self._chronological:
            self._chronological.remove(fact_id)
        
        # Record retraction
        self._assertion_history.append((datetime.now(), fact_id, 'RETRACT'))
        
        return True
    
    def _index_fact(self, fact: Fact) -> None:
        """Add fact to all indices"""
        # By type
        if fact.fact_type not in self._by_type:
            self._by_type[fact.fact_type] = set()
        self._by_type[fact.fact_type].add(fact.fact_id)
        
        # By subject
        if fact.subject not in self._by_subject:
            self._by_subject[fact.subject] = set()
        self._by_subject[fact.subject].add(fact.fact_id)
        
        # By predicate
        if fact.predicate not in self._by_predicate:
            self._by_predicate[fact.predicate] = set()
        self._by_predicate[fact.predicate].add(fact.fact_id)
        
        # By source event
        if fact.source_event_id:
            if fact.source_event_id not in self._by_event:
                self._by_event[fact.source_event_id] = set()
            self._by_event[fact.source_event_id].add(fact.fact_id)
    
    def _unindex_fact(self, fact: Fact) -> None:
        """Remove fact from all indices"""
        # By type
        if fact.fact_type in self._by_type:
            self._by_type[fact.fact_type].discard(fact.fact_id)
        
        # By subject
        if fact.subject in self._by_subject:
            self._by_subject[fact.subject].discard(fact.fact_id)
        
        # By predicate
        if fact.predicate in self._by_predicate:
            self._by_predicate[fact.predicate].discard(fact.fact_id)
        
        # By source event
        if fact.source_event_id and fact.source_event_id in self._by_event:
            self._by_event[fact.source_event_id].discard(fact.fact_id)
    
    def get_fact(self, fact_id: str) -> Optional[Fact]:
        """Get fact by ID"""
        return self.facts.get(fact_id)
    
    def get_facts_by_type(self, fact_type: str) -> List[Fact]:
        """Get all facts of a specific type"""
        fact_ids = self._by_type.get(fact_type, set())
        return [self.facts[fid] for fid in fact_ids if fid in self.facts]
    
    def get_facts_by_subject(self, subject: str) -> List[Fact]:
        """Get all facts about a specific subject"""
        fact_ids = self._by_subject.get(subject, set())
        return [self.facts[fid] for fid in fact_ids if fid in self.facts]
    
    def get_facts_by_predicate(self, predicate: str) -> List[Fact]:
        """Get all facts with a specific predicate"""
        fact_ids = self._by_predicate.get(predicate, set())
        return [self.facts[fid] for fid in fact_ids if fid in self.facts]
    
    def get_facts_by_event(self, event_id: str) -> List[Fact]:
        """Get all facts derived from a specific event"""
        fact_ids = self._by_event.get(event_id, set())
        return [self.facts[fid] for fid in fact_ids if fid in self.facts]
    
    def query(self, fact_type: Optional[str] = None,
              subject: Optional[str] = None,
              predicate: Optional[str] = None,
              value: Optional[Any] = None) -> List[Fact]:
        """
        Query facts with multiple constraints.
        Uses index intersection for efficiency.
        """
        # Start with all facts or use most selective index
        candidates = None
        
        if subject and subject in self._by_subject:
            candidates = self._by_subject[subject].copy()
        elif fact_type and fact_type in self._by_type:
            candidates = self._by_type[fact_type].copy()
        elif predicate and predicate in self._by_predicate:
            candidates = self._by_predicate[predicate].copy()
        else:
            candidates = set(self.facts.keys())
        
        # Apply remaining filters
        result = []
        for fact_id in candidates:
            if fact_id not in self.facts:
                continue
            fact = self.facts[fact_id]
            
            if fact_type and fact.fact_type != fact_type:
                continue
            if subject and fact.subject != subject:
                continue
            if predicate and fact.predicate != predicate:
                continue
            if value is not None and fact.value != value:
                continue
            
            result.append(fact)
        
        return result
    
    def get_recent_facts(self, count: int = 10) -> List[Fact]:
        """Get most recently asserted facts"""
        recent_ids = self._chronological[-count:]
        return [self.facts[fid] for fid in recent_ids if fid in self.facts]
    
    def get_all_facts(self) -> List[Fact]:
        """Get all facts in working memory"""
        return list(self.facts.values())
    
    def clear(self) -> None:
        """Clear all facts from working memory"""
        self.facts.clear()
        self._by_type.clear()
        self._by_subject.clear()
        self._by_predicate.clear()
        self._by_event.clear()
        self._chronological.clear()
        self._assertion_history.clear()
    
    def size(self) -> int:
        """Return number of facts in working memory"""
        return len(self.facts)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about working memory"""
        return {
            'total_facts': len(self.facts),
            'by_type': {k: len(v) for k, v in self._by_type.items()},
            'by_subject': len(self._by_subject),
            'by_predicate': len(self._by_predicate),
            'assertion_history_size': len(self._assertion_history)
        }
