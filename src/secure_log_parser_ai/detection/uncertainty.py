"""
Uncertainty handling for the detection system.
Implements Dempster-Shafer theory and fuzzy logic for evidence combination.
"""
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict

from ..knowledge_base.certainties import (
    CertaintyFactorAlgebra, DempsterShafer, FuzzyLogic,
    MassFunction, CertaintyFactor
)
from ..models.anomaly import Anomaly, Evidence


@dataclass
class UncertainEvidence:
    """Evidence with uncertainty information"""
    source: str
    hypothesis: str
    belief: float  # Degree of belief (0-1)
    disbelief: float  # Degree of disbelief (0-1)
    context: Dict[str, Any]


class UncertaintyHandler:
    """
    Handles uncertainty in anomaly detection.
    
    Layer 4 (Meta-Reasoning) of the detection pipeline.
    - Combines evidence from multiple sources
    - Handles incomplete log entries
    - Resolves conflicting indicators
    - Calculates composite threat scores
    
    Uses:
    - Certainty Factor algebra for rule-based reasoning
    - Dempster-Shafer theory for evidence combination
    - Fuzzy logic for handling vague/imprecise data
    """
    
    def __init__(self):
        self.cf_algebra = CertaintyFactorAlgebra()
        self.ds_theory = DempsterShafer()
        self.fuzzy_logic = FuzzyLogic()
        
        # Evidence history for temporal reasoning
        self.evidence_history: List[UncertainEvidence] = []
        self.max_history_size = 1000
    
    def combine_certainties(self, certainties: List[float]) -> float:
        """
        Combine multiple certainty factors.
        
        Uses the formula: CFcombined = CF1 + CF2 * (1 - CF1)
        for same-direction certainties.
        """
        return self.cf_algebra.combine_multiple(certainties)
    
    def combine_evidence_ds(self, evidences: List[UncertainEvidence]) -> Dict[str, float]:
        """
        Combine evidence using Dempster-Shafer theory.
        
        Args:
            evidences: List of uncertain evidence
        
        Returns:
            Dictionary of hypothesis -> belief
        """
        if not evidences:
            return {}
        
        # Group by hypothesis
        by_hypothesis: Dict[str, List[UncertainEvidence]] = defaultdict(list)
        for ev in evidences:
            by_hypothesis[ev.hypothesis].append(ev)
        
        # Create mass functions for each hypothesis
        mass_functions = []
        frame_of_discernment = set(by_hypothesis.keys())
        
        for hypothesis, ev_list in by_hypothesis.items():
            # Combine beliefs for this hypothesis
            total_belief = sum(ev.belief for ev in ev_list) / len(ev_list)
            
            # Create mass function
            mass = MassFunction({
                frozenset([hypothesis]): total_belief,
                frozenset(frame_of_discernment): 1 - total_belief  # Remaining mass to ignorance
            })
            mass_functions.append(mass)
        
        # Combine all mass functions
        if len(mass_functions) == 1:
            combined = mass_functions[0]
        else:
            combined = self.ds_theory.combine_multiple(mass_functions)
        
        # Calculate beliefs for each hypothesis
        results = {}
        for hypothesis in frame_of_discernment:
            belief = combined.belief({hypothesis})
            plausibility = combined.plausibility({hypothesis})
            results[hypothesis] = {
                'belief': belief,
                'plausibility': plausibility,
                'uncertainty': plausibility - belief
            }
        
        return results
    
    def calculate_composite_threat_score(self, anomaly: Anomaly,
                                         additional_context: Optional[Dict] = None) -> float:
        """
        Calculate composite threat score using uncertainty handling.
        
        Returns score on 0-100 scale.
        """
        # Start with base score from anomaly
        base_score = anomaly.threat_score
        
        # Gather evidence certainties
        evidence_cfs = [e.certainty for e in anomaly.evidence]
        
        # Combine certainties
        if evidence_cfs:
            combined_cf = self.combine_certainties(evidence_cfs)
            
            # Adjust base score by combined certainty
            adjusted_score = base_score * (0.5 + 0.5 * combined_cf)
        else:
            adjusted_score = base_score
        
        # Apply context modifiers
        if additional_context:
            # Boost for multiple indicators
            indicator_count = additional_context.get('indicator_count', 0)
            if indicator_count > 2:
                adjusted_score *= (1 + 0.1 * min(indicator_count - 2, 3))
            
            # Reduce for conflicting evidence
            if additional_context.get('has_conflicting_evidence'):
                adjusted_score *= 0.8
            
            # Boost for high-value targets
            if additional_context.get('is_critical_asset'):
                adjusted_score *= 1.2
        
        return min(100, adjusted_score)
    
    def resolve_conflicts(self, evidences: List[Evidence]) -> Tuple[List[Evidence], List[Evidence]]:
        """
        Resolve conflicting evidence.
        
        Returns:
            Tuple of (supporting_evidence, conflicting_evidence)
        """
        if not evidences:
            return [], []
        
        # Group by general agreement/disagreement
        supporting = []
        conflicting = []
        
        # Simple approach: compare certainties
        avg_certainty = sum(e.certainty for e in evidences) / len(evidences)
        
        for ev in evidences:
            if ev.certainty >= avg_certainty:
                supporting.append(ev)
            else:
                conflicting.append(ev)
        
        return supporting, conflicting
    
    def handle_incomplete_data(self, anomaly: Anomaly, 
                               missing_fields: List[str]) -> Anomaly:
        """
        Adjust anomaly certainty for incomplete data.
        
        Reduces certainty based on importance of missing fields.
        """
        # Define field importance weights
        field_weights = {
            'user_id': 0.2,
            'source_ip': 0.15,
            'timestamp': 0.1,
            'event_type': 0.2,
            'message': 0.1,
            'severity': 0.15,
            'destination_ip': 0.1
        }
        
        # Calculate data completeness penalty
        penalty = sum(field_weights.get(field, 0.05) for field in missing_fields)
        penalty = min(0.5, penalty)  # Cap at 50% reduction
        
        # Adjust certainty
        original_certainty = anomaly.certainty
        adjusted_certainty = original_certainty * (1 - penalty)
        
        # Update anomaly
        anomaly.certainty = adjusted_certainty
        
        # Add note to explanation
        if missing_fields:
            anomaly.explanation += f"\n\nNote: Analysis based on incomplete data. "
            anomaly.explanation += f"Missing fields: {', '.join(missing_fields)}. "
            anomaly.explanation += f"Certainty adjusted from {original_certainty*100:.1f}% "
            anomaly.explanation += f"to {adjusted_certainty*100:.1f}%."
        
        return anomaly
    
    def fuzzy_classify_threat_level(self, threat_score: float) -> Dict[str, float]:
        """
        Classify threat level using fuzzy logic.
        
        Returns membership grades for each threat level.
        """
        categories = {
            'low': (0, 30),
            'medium': (20, 70),
            'high': (60, 90),
            'critical': (80, 100)
        }
        
        return self.fuzzy_logic.linguistic_variable(threat_score, categories)
    
    def temporal_reasoning(self, current_anomaly: Anomaly,
                          historical_anomalies: List[Anomaly]) -> Anomaly:
        """
        Apply temporal reasoning to adjust anomaly based on history.
        
        Considers:
        - Frequency of similar anomalies
        - Time since last similar anomaly
        - Trend analysis
        """
        if not historical_anomalies:
            return current_anomaly
        
        # Count similar anomalies
        similar_count = sum(
            1 for a in historical_anomalies
            if a.anomaly_type == current_anomaly.anomaly_type
        )
        
        # Adjust certainty based on frequency
        if similar_count >= 5:
            # Recurring pattern - increase certainty
            boost = min(0.15, similar_count * 0.02)
            current_anomaly.certainty = min(1.0, current_anomaly.certainty + boost)
            current_anomaly.explanation += f"\n\nTemporal Analysis: This is the {similar_count}th occurrence "
            current_anomaly.explanation += f"of this anomaly type, indicating a pattern."
        
        elif similar_count == 0:
            # First occurrence - slight uncertainty
            current_anomaly.explanation += "\n\nTemporal Analysis: First occurrence of this anomaly type."
        
        return current_anomaly
    
    def aggregate_multi_source_evidence(self, anomalies: List[Anomaly],
                                        source_weights: Optional[Dict[str, float]] = None) -> Anomaly:
        """
        Aggregate evidence from multiple detection sources.
        
        Combines anomalies from different detection layers.
        """
        if not anomalies:
            return None
        
        if len(anomalies) == 1:
            return anomalies[0]
        
        # Group by anomaly type
        by_type: Dict[str, List[Anomaly]] = defaultdict(list)
        for anomaly in anomalies:
            by_type[anomaly.anomaly_type.value].append(anomaly)
        
        # Find the most significant anomaly type
        primary_type = max(by_type.keys(), key=lambda t: len(by_type[t]))
        primary_anomalies = by_type[primary_type]
        
        # Create aggregated anomaly
        aggregated = Anomaly(
            anomaly_type=primary_anomalies[0].anomaly_type,
            detection_layer="meta",
            affected_users=list(set(
                user for a in primary_anomalies for user in a.affected_users
            )),
            source_ips=list(set(
                ip for a in primary_anomalies for ip in a.source_ips
            )),
            triggered_rules=list(set(
                rule for a in primary_anomalies for rule in a.triggered_rules
            ))
        )
        
        # Combine evidence
        all_evidence = []
        for anomaly in primary_anomalies:
            all_evidence.extend(anomaly.evidence)
        
        # Deduplicate evidence by rule_id
        seen_rules = set()
        for ev in all_evidence:
            if ev.rule_id not in seen_rules:
                aggregated.add_evidence(ev)
                seen_rules.add(ev.rule_id)
        
        # Calculate aggregated threat score
        threat_scores = [a.threat_score for a in primary_anomalies]
        certainties = [a.certainty for a in primary_anomalies]
        
        # Weight by source if provided
        if source_weights:
            weighted_scores = []
            for a in primary_anomalies:
                weight = source_weights.get(a.detection_layer, 1.0)
                weighted_scores.append(a.threat_score * weight)
            aggregated.threat_score = sum(weighted_scores) / sum(source_weights.values())
        else:
            aggregated.threat_score = max(threat_scores)
        
        # Combine certainties
        aggregated.certainty = self.combine_certainties(certainties)
        
        # Generate explanation
        aggregated.explanation = f"Aggregated Anomaly: {aggregated.anomaly_type.value}\n"
        aggregated.explanation += f"Sources: {len(primary_anomalies)} detection layers\n"
        aggregated.explanation += f"Combined Certainty: {aggregated.certainty*100:.1f}%\n"
        aggregated.explanation += f"Evidence Count: {len(aggregated.evidence)}"
        
        return aggregated
    
    def get_uncertainty_report(self, anomaly: Anomaly) -> Dict[str, Any]:
        """Generate uncertainty analysis report for an anomaly"""
        # Calculate fuzzy membership
        fuzzy_membership = self.fuzzy_classify_threat_level(anomaly.threat_score)
        
        # Analyze evidence distribution
        evidence_cfs = [e.certainty for e in anomaly.evidence]
        
        return {
            'anomaly_id': anomaly.anomaly_id,
            'certainty': anomaly.certainty,
            'fuzzy_classification': fuzzy_membership,
            'evidence_statistics': {
                'count': len(anomaly.evidence),
                'avg_certainty': sum(evidence_cfs) / len(evidence_cfs) if evidence_cfs else 0,
                'min_certainty': min(evidence_cfs) if evidence_cfs else 0,
                'max_certainty': max(evidence_cfs) if evidence_cfs else 0
            },
            'confidence_level': self._classify_confidence(anomaly.certainty)
        }
    
    def _classify_confidence(self, certainty: float) -> str:
        """Classify confidence level based on certainty"""
        if certainty >= 0.9:
            return 'very_high'
        elif certainty >= 0.75:
            return 'high'
        elif certainty >= 0.5:
            return 'medium'
        elif certainty >= 0.25:
            return 'low'
        else:
            return 'very_low'
