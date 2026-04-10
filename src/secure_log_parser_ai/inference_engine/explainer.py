"""
Explanation facility for the expert system.
Generates natural language justifications for anomaly detections.
Implements "Why" and "How" explanation capabilities.
"""
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime

from ..models.anomaly import Anomaly, Evidence
from ..models.fact import Fact


@dataclass
class ExplanationStep:
    """Single step in an explanation chain"""
    step_number: int
    description: str
    rule_id: Optional[str] = None
    facts: List[str] = field(default_factory=list)
    certainty: float = 0.0


@dataclass
class ExplanationTrace:
    """Complete trace of inference leading to a conclusion"""
    anomaly_id: str
    anomaly_type: str
    conclusion: str
    steps: List[ExplanationStep] = field(default_factory=list)
    final_certainty: float = 0.0
    
    def to_natural_language(self) -> str:
        """Convert trace to natural language explanation"""
        lines = [
            f"EXPLANATION FOR ANOMALY: {self.anomaly_type}",
            f"Conclusion: {self.conclusion}",
            f"Overall Certainty: {self.final_certainty*100:.1f}%",
            "",
            "Reasoning Chain:"
        ]
        
        for step in self.steps:
            lines.append(f"  Step {step.step_number}: {step.description}")
            if step.certainty > 0:
                lines.append(f"    Certainty: {step.certainty*100:.1f}%")
            if step.facts:
                lines.append(f"    Based on: {', '.join(step.facts)}")
        
        return "\n".join(lines)


class Explainer:
    """
    Explanation facility for generating justifications.
    
    Provides:
    - Why explanations: Why was this anomaly detected?
    - How explanations: How was this conclusion reached?
    - What-if analysis: What if certain facts were different?
    """
    
    def __init__(self):
        self.explanation_templates = self._load_templates()
    
    def _load_templates(self) -> Dict[str, str]:
        """Load natural language templates for different anomaly types"""
        return {
            'brute_force_attack': """
A brute force attack was detected because:
- {failed_count} failed login attempts were observed
- All attempts originated from the same source ({source_ip})
- The attempts occurred within a {time_window}-second window
- This pattern is characteristic of automated password guessing attacks.
""",
            'credential_stuffing': """
Credential stuffing was detected because:
- {failed_count} failed login attempts from {unique_users} different usernames
- Only {success_rate:.1%} of attempts were successful
- This pattern suggests use of leaked credential databases
- The attack is highly automated and distributed.
""",
            'impossible_travel': """
Impossible travel was detected because:
- User {user_id} logged in from {location1} and {location2}
- Time between logins: {time_diff} minutes
- Distance between locations: {distance} km
- Physical travel between these locations in this time is impossible.
""",
            'privilege_escalation': """
Unauthorized privilege escalation was detected because:
- User {user_id} with role '{user_role}' attempted elevation
- The action required privileges beyond their authorization level
- This may indicate account compromise or insider threat.
""",
            'data_exfiltration': """
Potential data exfiltration was detected because:
- {data_volume} MB of data was transferred
- Transfer occurred outside business hours ({timestamp})
- Direction: {direction}
- This pattern is consistent with data theft activity.
""",
            'default': """
Anomaly detected: {anomaly_type}
Certainty: {certainty:.1%}
Evidence: {evidence_count} supporting indicators
Recommendation: {recommendation}
"""
        }
    
    def explain_anomaly(self, anomaly: Anomaly, 
                        facts: Optional[List[Fact]] = None) -> ExplanationTrace:
        """
        Generate complete explanation for an anomaly.
        
        Implements "How" explanation - showing the reasoning chain.
        """
        trace = ExplanationTrace(
            anomaly_id=anomaly.anomaly_id,
            anomaly_type=anomaly.anomaly_type.value,
            conclusion=f"Detected {anomaly.threat_level.name} threat: {anomaly.anomaly_type.value}",
            final_certainty=anomaly.certainty
        )
        
        step_num = 1
        
        # Step 1: Initial observation
        trace.steps.append(ExplanationStep(
            step_number=step_num,
            description="Security events were observed and parsed from log sources.",
            certainty=1.0
        ))
        step_num += 1
        
        # Step 2: Fact extraction
        if facts:
            trace.steps.append(ExplanationStep(
                step_number=step_num,
                description=f"Extracted {len(facts)} relevant facts from events.",
                facts=[f.fact_id for f in facts[:5]],  # Show first 5
                certainty=0.95
            ))
            step_num += 1
        
        # Step 3: Rule matching
        for evidence in anomaly.evidence:
            trace.steps.append(ExplanationStep(
                step_number=step_num,
                description=f"Rule '{evidence.rule_name}' matched: {evidence.description}",
                rule_id=evidence.rule_id,
                facts=evidence.matched_facts,
                certainty=evidence.certainty
            ))
            step_num += 1
        
        # Step 4: Certainty combination
        trace.steps.append(ExplanationStep(
            step_number=step_num,
            description=f"Combined evidence using certainty factor algebra to reach final certainty of {anomaly.certainty*100:.1f}%.",
            certainty=anomaly.certainty
        ))
        
        return trace
    
    def explain_why(self, anomaly: Anomaly) -> str:
        """
        Generate "Why" explanation - why was this flagged?
        
        Focuses on the key indicators that triggered detection.
        """
        template = self.explanation_templates.get(
            anomaly.anomaly_type.value,
            self.explanation_templates['default']
        )
        
        # Extract data from evidence
        evidence_data = self._extract_evidence_data(anomaly)
        
        try:
            return template.format(**evidence_data)
        except KeyError:
            # Fallback to generic explanation
            return self._generate_generic_explanation(anomaly)
    
    def explain_how(self, anomaly: Anomaly) -> str:
        """
        Generate "How" explanation - how was this conclusion reached?
        
        Shows the inference chain and rule firings.
        """
        lines = [
            f"How was '{anomaly.anomaly_type.value}' detected?",
            "",
            "Inference Chain:"
        ]
        
        for i, evidence in enumerate(anomaly.evidence, 1):
            lines.append(f"\n{i}. Rule Applied: {evidence.rule_name}")
            lines.append(f"   Rule ID: {evidence.rule_id}")
            lines.append(f"   Description: {evidence.description}")
            lines.append(f"   Certainty Factor: {evidence.certainty*100:.1f}%")
            lines.append(f"   Matched Facts: {len(evidence.matched_facts)}")
            
            if evidence.contributing_attributes:
                lines.append("   Contributing Factors:")
                for attr, value in evidence.contributing_attributes.items():
                    lines.append(f"     - {attr}: {value}")
        
        # Certainty combination explanation
        lines.append("\nCertainty Combination:")
        if len(anomaly.evidence) == 1:
            lines.append(f"  Final certainty = Rule CF × Evidence CF = {anomaly.certainty*100:.1f}%")
        else:
            lines.append(f"  Multiple evidence sources combined using CF algebra:")
            cf_values = [e.certainty for e in anomaly.evidence]
            lines.append(f"  Input CFs: {[f'{cf*100:.1f}%' for cf in cf_values]}")
            lines.append(f"  Combined CF: {anomaly.certainty*100:.1f}%")
        
        return "\n".join(lines)
    
    def explain_contradiction(self, anomaly: Anomaly, 
                              conflicting_evidence: List[Evidence]) -> str:
        """
        Explain how contradictory evidence was resolved.
        
        Important for transparency in AI systems.
        """
        lines = [
            "Contradiction Resolution:",
            f"Anomaly: {anomaly.anomaly_type.value}",
            "",
            "Supporting Evidence:"
        ]
        
        supporting = [e for e in anomaly.evidence if e.certainty > 0.5]
        contradicting = [e for e in conflicting_evidence if e.certainty > 0.5]
        
        for ev in supporting:
            lines.append(f"  + {ev.rule_name}: {ev.certainty*100:.1f}% confidence")
        
        lines.append("\nContradicting Evidence:")
        for ev in contradicting:
            lines.append(f"  - {ev.rule_name}: {ev.certainty*100:.1f}% confidence")
        
        lines.append(f"\nResolution: Final certainty of {anomaly.certainty*100:.1f}% reflects")
        lines.append("the net belief after weighing all evidence.")
        
        return "\n".join(lines)
    
    def generate_summary(self, anomalies: List[Anomaly]) -> str:
        """Generate summary explanation for multiple anomalies"""
        if not anomalies:
            return "No anomalies detected."
        
        # Group by type
        by_type: Dict[str, List[Anomaly]] = {}
        for anomaly in anomalies:
            t = anomaly.anomaly_type.value
            if t not in by_type:
                by_type[t] = []
            by_type[t].append(anomaly)
        
        lines = [
            "SECURITY ANALYSIS SUMMARY",
            f"Total Anomalies Detected: {len(anomalies)}",
            f"Unique Threat Types: {len(by_type)}",
            "",
            "Breakdown by Type:"
        ]
        
        for threat_type, threats in sorted(by_type.items(), 
                                           key=lambda x: len(x[1]), 
                                           reverse=True):
            avg_certainty = sum(t.certainty for t in threats) / len(threats)
            high_severity = sum(1 for t in threats if t.threat_level.value >= 4)
            
            lines.append(f"\n  {threat_type.replace('_', ' ').title()}:")
            lines.append(f"    Count: {len(threats)}")
            lines.append(f"    Average Certainty: {avg_certainty*100:.1f}%")
            lines.append(f"    High Severity: {high_severity}")
        
        # Overall risk assessment
        max_threat = max(anomalies, key=lambda a: a.threat_score)
        lines.append(f"\nHighest Risk: {max_threat.anomaly_type.value}")
        lines.append(f"Threat Score: {max_threat.threat_score:.1f}/100")
        
        return "\n".join(lines)
    
    def _extract_evidence_data(self, anomaly: Anomaly) -> Dict[str, Any]:
        """Extract data from evidence for template formatting"""
        data = {
            'anomaly_type': anomaly.anomaly_type.value,
            'certainty': anomaly.certainty,
            'evidence_count': len(anomaly.evidence),
            'recommendation': anomaly.recommendation,
            'failed_count': 0,
            'source_ip': 'unknown',
            'time_window': 0,
            'unique_users': 0,
            'success_rate': 0.0,
            'user_id': 'unknown',
            'user_role': 'unknown',
            'data_volume': 0,
            'timestamp': 'unknown',
            'direction': 'unknown'
        }
        
        # Extract from evidence attributes
        for evidence in anomaly.evidence:
            attrs = evidence.contributing_attributes
            
            if 'failed_count' in attrs:
                data['failed_count'] = attrs['failed_count']
            if 'source_ip' in attrs:
                data['source_ip'] = attrs['source_ip']
            if 'time_window' in attrs:
                data['time_window'] = attrs['time_window']
            if 'unique_users' in attrs:
                data['unique_users'] = attrs['unique_users']
            if 'success_rate' in attrs:
                data['success_rate'] = attrs['success_rate']
            if 'user_id' in attrs:
                data['user_id'] = attrs['user_id']
            if 'user_role' in attrs:
                data['user_role'] = attrs['user_role']
            if 'data_volume' in attrs:
                data['data_volume'] = attrs['data_volume']
        
        return data
    
    def _generate_generic_explanation(self, anomaly: Anomaly) -> str:
        """Generate generic explanation when specific template unavailable"""
        lines = [
            f"ANOMALY: {anomaly.anomaly_type.value.replace('_', ' ').title()}",
            f"Threat Level: {anomaly.threat_level.name}",
            f"Certainty: {anomaly.certainty*100:.1f}%",
            f"Threat Score: {anomaly.threat_score:.1f}/100",
            "",
            "Evidence:"
        ]
        
        for i, evidence in enumerate(anomaly.evidence, 1):
            lines.append(f"  {i}. {evidence.rule_name}")
            lines.append(f"     {evidence.description}")
        
        if anomaly.recommendation:
            lines.append(f"\nRecommendation: {anomaly.recommendation}")
        
        return "\n".join(lines)
    
    def get_explanation_trace(self, anomaly_id: str, 
                              fired_rules: List[Dict[str, Any]],
                              facts: List[Fact]) -> ExplanationTrace:
        """Reconstruct explanation trace from inference history"""
        trace = ExplanationTrace(
            anomaly_id=anomaly_id,
            anomaly_type="unknown",
            conclusion="Inference trace reconstructed from history",
            final_certainty=0.0
        )
        
        for i, rule_info in enumerate(fired_rules, 1):
            trace.steps.append(ExplanationStep(
                step_number=i,
                description=f"Fired rule: {rule_info.get('rule_name', 'unknown')}",
                rule_id=rule_info.get('rule_id'),
                facts=rule_info.get('facts', []),
                certainty=rule_info.get('certainty', 0.0)
            ))
        
        return trace
