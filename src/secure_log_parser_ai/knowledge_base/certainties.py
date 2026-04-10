"""
Certainty Factor algebra and Dempster-Shafer theory for uncertainty handling.
Implements probabilistic reasoning for incomplete and conflicting evidence.
"""
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from functools import reduce
import math


@dataclass
class CertaintyFactor:
    """
    Certainty Factor representation.
    CF values range from -1.0 (definitely false) to 1.0 (definitely true).
    """
    belief: float  # MB: measure of belief
    disbelief: float  # MD: measure of disbelief
    
    def __post_init__(self):
        # Clamp values to valid range
        self.belief = max(0.0, min(1.0, self.belief))
        self.disbelief = max(0.0, min(1.0, self.disbelief))
    
    @property
    def cf(self) -> float:
        """Calculate CF = MB - MD"""
        return self.belief - self.disbelief
    
    @classmethod
    def from_single_value(cls, value: float) -> 'CertaintyFactor':
        """Create CF from a single value (-1.0 to 1.0)"""
        if value >= 0:
            return cls(belief=value, disbelief=0.0)
        else:
            return cls(belief=0.0, disbelief=-value)
    
    def is_definite(self) -> bool:
        """Check if CF is close to definite (|CF| > 0.9)"""
        return abs(self.cf) > 0.9
    
    def is_unknown(self) -> bool:
        """Check if CF indicates unknown (|CF| < 0.1)"""
        return abs(self.cf) < 0.1


class CertaintyFactorAlgebra:
    """
    Certainty Factor algebra for combining evidence.
    Based on MYCIN expert system approach.
    """
    
    @staticmethod
    def combine(cf1: float, cf2: float) -> float:
        """
        Combine two certainty factors.
        Formula varies based on signs of CFs.
        """
        # Handle unknown values
        if cf1 is None:
            return cf2
        if cf2 is None:
            return cf1
        
        # Same sign combination
        if cf1 >= 0 and cf2 >= 0:
            return cf1 + cf2 * (1 - cf1)
        elif cf1 < 0 and cf2 < 0:
            return cf1 + cf2 * (1 + cf1)
        else:
            # Opposite signs
            denominator = 1 - min(abs(cf1), abs(cf2))
            if denominator == 0:
                return 0.0
            return (cf1 + cf2) / denominator
    
    @staticmethod
    def combine_multiple(cfs: List[float]) -> float:
        """Combine multiple certainty factors sequentially"""
        if not cfs:
            return 0.0
        if len(cfs) == 1:
            return cfs[0]
        
        return reduce(CertaintyFactorAlgebra.combine, cfs)
    
    @staticmethod
    def sequential_combination(rule_cf: float, evidence_cf: float) -> float:
        """
        Calculate CF for rule application.
        CF(H, E) = CF(rule) * CF(evidence)
        """
        return rule_cf * evidence_cf
    
    @staticmethod
    def weighted_combination(cfs: List[Tuple[float, float]]) -> float:
        """
        Weighted combination of certainty factors.
        Each tuple is (cf_value, weight).
        """
        if not cfs:
            return 0.0
        
        total_weight = sum(weight for _, weight in cfs)
        if total_weight == 0:
            return 0.0
        
        # Normalize weights
        normalized = [(cf, weight / total_weight) for cf, weight in cfs]
        
        # Weighted combination
        weighted_sum = sum(cf * weight for cf, weight in normalized)
        return max(-1.0, min(1.0, weighted_sum))
    
    @staticmethod
    def threshold_check(cf: float, threshold: float = 0.5) -> bool:
        """Check if CF meets threshold for firing"""
        return cf >= threshold
    
    @staticmethod
    def cf_to_probability(cf: float, prior: float = 0.5) -> float:
        """
        Convert certainty factor to probability.
        Uses the formula: P = (CF + 1) / 2 for uniform prior.
        """
        if prior == 0.5:
            return (cf + 1) / 2
        else:
            # More complex conversion with non-uniform prior
            odds = prior / (1 - prior)
            cf_odds = (1 + cf) / (1 - cf) if cf != 1 else float('inf')
            posterior_odds = odds * cf_odds
            return posterior_odds / (1 + posterior_odds)
    
    @staticmethod
    def probability_to_cf(probability: float, prior: float = 0.5) -> float:
        """Convert probability to certainty factor"""
        if probability == 1.0:
            return 1.0
        if probability == 0.0:
            return -1.0
        
        odds = probability / (1 - probability)
        prior_odds = prior / (1 - prior)
        cf_odds = odds / prior_odds
        return (cf_odds - 1) / (cf_odds + 1)


@dataclass
class MassFunction:
    """
    Mass function for Dempster-Shafer theory.
    Represents belief distribution over power set of hypotheses.
    """
    masses: Dict[frozenset, float]  # {hypothesis_set: mass_value}
    
    def __post_init__(self):
        # Normalize masses
        total = sum(self.masses.values())
        if total > 0 and total != 1.0:
            self.masses = {k: v/total for k, v in self.masses.items()}
    
    def belief(self, hypothesis: Set[str]) -> float:
        """
        Calculate Bel(A) = sum of masses for all subsets of A.
        """
        hyp_frozen = frozenset(hypothesis)
        return sum(mass for subset, mass in self.masses.items() 
                  if subset.issubset(hyp_frozen))
    
    def plausibility(self, hypothesis: Set[str]) -> float:
        """
        Calculate Pl(A) = 1 - Bel(not A).
        """
        all_elements = set().union(*self.masses.keys())
        complement = all_elements - hypothesis
        return 1 - self.belief(complement)
    
    def uncertainty(self, hypothesis: Set[str]) -> float:
        """Calculate uncertainty interval [Bel, Pl]"""
        bel = self.belief(hypothesis)
        pl = self.plausibility(hypothesis)
        return pl - bel


class DempsterShafer:
    """
    Dempster-Shafer theory implementation for evidence combination.
    Handles conflicting evidence and incomplete information.
    """
    
    @staticmethod
    def combine(m1: MassFunction, m2: MassFunction) -> MassFunction:
        """
        Combine two mass functions using Dempster's rule.
        m(A) = (1/K) * sum of m1(B) * m2(C) for all B ∩ C = A
        where K = 1 - sum of m1(B) * m2(C) for all B ∩ C = ∅
        """
        combined_masses: Dict[frozenset, float] = {}
        conflict = 0.0
        
        for set1, mass1 in m1.masses.items():
            for set2, mass2 in m2.masses.items():
                intersection = set1 & set2
                product = mass1 * mass2
                
                if len(intersection) == 0:
                    conflict += product
                else:
                    intersection_frozen = frozenset(intersection)
                    combined_masses[intersection_frozen] = \
                        combined_masses.get(intersection_frozen, 0) + product
        
        # Normalize by conflict factor
        normalization = 1 - conflict
        if normalization > 0:
            combined_masses = {k: v / normalization 
                             for k, v in combined_masses.items()}
        
        return MassFunction(combined_masses)
    
    @staticmethod
    def combine_multiple(mass_functions: List[MassFunction]) -> MassFunction:
        """Combine multiple mass functions"""
        if not mass_functions:
            return MassFunction({frozenset(): 1.0})
        if len(mass_functions) == 1:
            return mass_functions[0]
        
        result = mass_functions[0]
        for mf in mass_functions[1:]:
            result = DempsterShafer.combine(result, mf)
        return result
    
    @staticmethod
    def from_evidence(evidence: Dict[str, float], 
                      frame_of_discernment: Optional[Set[str]] = None) -> MassFunction:
        """
        Create mass function from evidence.
        evidence: {hypothesis: confidence}
        """
        masses = {}
        remaining_mass = 1.0
        
        for hypothesis, confidence in evidence.items():
            hyp_set = frozenset([hypothesis])
            masses[hyp_set] = confidence
            remaining_mass -= confidence
        
        # Assign remaining mass to ignorance (frame of discernment)
        if remaining_mass > 0 and frame_of_discernment:
            ignorance = frozenset(frame_of_discernment)
            masses[ignorance] = masses.get(ignorance, 0) + remaining_mass
        
        return MassFunction(masses)
    
    @staticmethod
    def calculate_threat_score(beliefs: Dict[str, float], 
                               weights: Optional[Dict[str, float]] = None) -> float:
        """
        Calculate composite threat score from beliefs.
        Returns score on 0-100 scale.
        """
        if not beliefs:
            return 0.0
        
        weights = weights or {}
        total_weight = sum(weights.get(k, 1.0) for k in beliefs.keys())
        
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(
            beliefs[k] * weights.get(k, 1.0) 
            for k in beliefs.keys()
        )
        
        # Normalize to 0-100 scale
        score = (weighted_sum / total_weight) * 100
        return min(100, max(0, score))


class FuzzyLogic:
    """
    Fuzzy logic operations for handling vague/imprecise log data.
    """
    
    @staticmethod
    def membership_grade(value: float, low: float, high: float, 
                         shape: str = 'trapezoid') -> float:
        """
        Calculate membership grade for fuzzy sets.
        
        shape: 'trapezoid', 'triangle', 'gaussian'
        """
        if shape == 'trapezoid':
            if value <= low:
                return 0.0
            elif value >= high:
                return 1.0
            else:
                return (value - low) / (high - low)
        
        elif shape == 'triangle':
            mid = (low + high) / 2
            if value <= low or value >= high:
                return 0.0
            elif value <= mid:
                return (value - low) / (mid - low)
            else:
                return (high - value) / (high - mid)
        
        elif shape == 'gaussian':
            mid = (low + high) / 2
            sigma = (high - low) / 4
            return math.exp(-0.5 * ((value - mid) / sigma) ** 2)
        
        return 0.0
    
    @staticmethod
    def fuzzy_and(memberships: List[float]) -> float:
        """Fuzzy AND (minimum)"""
        return min(memberships) if memberships else 0.0
    
    @staticmethod
    def fuzzy_or(memberships: List[float]) -> float:
        """Fuzzy OR (maximum)"""
        return max(memberships) if memberships else 0.0
    
    @staticmethod
    def fuzzy_not(membership: float) -> float:
        """Fuzzy NOT (complement)"""
        return 1.0 - membership
    
    @staticmethod
    def linguistic_variable(value: float, categories: Dict[str, Tuple[float, float]]) -> Dict[str, float]:
        """
        Map numeric value to linguistic categories.
        
        categories: {'low': (0, 30), 'medium': (20, 70), 'high': (60, 100)}
        Returns: {'low': 0.3, 'medium': 0.8, 'high': 0.1}
        """
        memberships = {}
        for category, (low, high) in categories.items():
            memberships[category] = FuzzyLogic.membership_grade(value, low, high)
        return memberships
