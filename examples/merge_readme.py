import os

readme1_path = r'c:\Users\MSUI\OneDrive\Desktop\S\Secure-Log-Parser-AI\README.md'
readme2_path = r'c:\Users\MSUI\OneDrive\Desktop\S\Secure-Log-Parser-AI\README_Taki_Eddine_Rami.md'

with open(readme1_path, 'r', encoding='utf-8') as f:
    r1 = f.read()

with open(readme2_path, 'r', encoding='utf-8') as f:
    r2 = f.read()

merged_content = """# Secure-Log-Parser-AI

## A Journey into AI-Powered Cybersecurity

---

*"In a world where cyber threats evolve faster than ever, we need systems that don't just process data—they need to understand it, reason about it, and explain their decisions. This project is my attempt to bridge the gap between classical AI and modern cybersecurity."*

Hello, and welcome to my project. 

My name is **Taki Eddine Rami**, and I'm thrilled to share with you something that has been both a challenging and deeply rewarding journey over the past months. What you're looking at isn't just another log analysis tool, it's an intelligent system that thinks, reasons, and explains itself like a human security analyst would.

This work was completed under the invaluable supervision and guidance of four exceptional professors who shaped my understanding of both the theoretical and practical aspects of this field:

- **Pr. Tag Samir** - Professor of Cybersecurity, who constantly pushed me to think like an attacker and understand the real-world implications of every detection
- **Pr. Menassel Yahia** - Professor of AI, whose deep knowledge of expert systems, knowledge representation, and reasoning under uncertainty formed the theoretical foundation of this entire project
- **Pr. Zebdi Abdel Moumen** - Professor of Compilation, who taught me the importance of systematic parsing and the beauty of well-structured language processing
- **Pr. Chergui Othaila** - Professor of Semi-Structured Data, whose insights on handling messy, real-world data formats were crucial to this project's success  
To all four of you, thank you for your patience, your challenging questions, and your unwavering support.

---

## Overview

A Python-based **Expert System** implementing rule-based anomaly detection with probabilistic reasoning for cybersecurity log analysis.

This project demonstrates practical application of AI concepts including:
- **Expert Systems** with forward-chaining inference
- **Knowledge Representation** using frames and semantic networks
- **Uncertainty Handling** via Certainty Factor algebra and Dempster-Shafer theory
- **Multi-layer Detection** combining signature, statistical, and behavioral analysis

**Secure-Log-Parser-AI** is a rule-based Expert System for detecting security anomalies in semi-structured logs (JSON, XML, syslog). It combines classical AI techniques with modern cybersecurity needs to create a system that is:

- **Interpretable**: Every detection comes with a natural language explanation
- **Uncertainty-aware**: It knows when it's confident and when it's not
- **Multi-layered**: It looks at your data from four different perspectives before making a decision
- **Fast**: No deep learning training cycles—just intelligent reasoning

### The Core Idea

Imagine a seasoned security analyst who has seen every attack in the book. They don't just look for signatures—they understand patterns, they notice when something "feels off," and they can articulate exactly why they're concerned. That's what I tried to encode into this system.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    SECURE-LOG-PARSER-AI                         │
├─────────────────────────────────────────────────────────────────┤
│  PARSING LAYER                                                  │
│  ├── JSON Parser (CloudTrail, Windows Events, Custom)          │
│  ├── XML Parser (Windows EVTX, Syslog, CEF)                    │
│  └── Normalizer (Schema Unification)                           │
├─────────────────────────────────────────────────────────────────┤
│  DETECTION LAYERS                                               │
│  ├── Layer 1: Signature-Based (Regex patterns)                 │
│  ├── Layer 2: Statistical (Z-score, baselines)                 │
│  ├── Layer 3: Behavioral (UEBA, sequence patterns)             │
│  └── Layer 4: Meta-Reasoning (Evidence combination)            │
├─────────────────────────────────────────────────────────────────┤
│  EXPERT SYSTEM CORE                                             │
│  ├── Knowledge Base (20+ production rules)                     │
│  │   ├── Authentication Anomalies                              │
│  │   ├── Privilege Escalation                                  │
│  │   ├── Data Exfiltration                                     │
│  │   ├── Malware Indicators                                    │
│  │   ├── Insider Threats                                       │
│  │   └── Network Anomalies                                     │
│  ├── Inference Engine (Forward Chaining)                       │
│  │   ├── Pattern Matcher (Rete Network)                       │
│  │   └── Conflict Resolution                                   │
│  └── Working Memory (Fact Storage)                             │
├─────────────────────────────────────────────────────────────────┤
│  EXPLANATION FACILITY                                           │
│  ├── Natural Language Justifications                           │
│  ├── Certainty Factor Propagation                              │
│  └── Contradiction Resolution                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Why I Chose This Approach

You might be wondering: *"Why not just use machine learning like everyone else?"*

Fair question. Here's my thinking:

1. **Explainability**: When a SOC analyst gets woken up at 3 AM by an alert, they need to know *why* immediately. My system tells them in plain English.
2. **No Training Data Required**: ML systems need thousands of labeled examples. My system works out of the box with expert-encoded knowledge.
3. **Predictable Behavior**: Neural networks can surprise you. Expert systems do exactly what their rules specify—no more, no less.
4. **Handling Uncertainty**: Real security data is messy, incomplete, and contradictory. Certainty Factors and Dempster-Shafer theory give me rigorous mathematical tools to handle this.
5. **Academic Value**: This project demonstrates classical AI concepts that remain relevant regardless of the latest ML trends.

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd secure_log_parser_ai

# Install in development mode
pip install -e .

# Or install dependencies directly (Python 3.9+)
pip install -r requirements.txt
```

### Dependencies

```
# Core (standard library only for AI components)
# Optional for enhanced features
pandas>=1.3.0
numpy>=1.21.0
networkx>=2.6.0
```

## Quick Start

### Command Line Interface

```bash
# Analyze a log file
python -m secure_log_parser_ai analyze logs.json

# Analyze with specific format
python -m secure_log_parser_ai analyze logs.xml --format xml

# Generate sample logs for testing
python -m secure_log_parser_ai generate --attack-type brute_force --count 100

# Show system status
python -m secure_log_parser_ai status
```

### Python API

```python
from secure_log_parser_ai import SecureLogParserAI

# Initialize system
system = SecureLogParserAI()

# Analyze a log file
result = system.analyze_file('security_logs.json')

# Process results
print(f"Detected {len(result.anomalies)} anomalies")
for anomaly in result.anomalies:
    print(f"- {anomaly.anomaly_type.value}: {anomaly.threat_score}/100")
    print(f"  Certainty: {anomaly.certainty*100:.1f}%")
    print(f"  Explanation: {anomaly.explanation}")
```

---

## Knowledge Base

### Production Rules (22 Rules)

The system includes 22 production rules across 6 categories:

#### Authentication Anomalies (6 rules)
| Rule ID | Name | CF | Description |
|---------|------|-----|-------------|
| AUTH-001 | Brute Force Detection | 0.85 | 5+ failed logins within 5 minutes from same IP |
| AUTH-002 | Credential Stuffing | 0.90 | 10+ attempts with different usernames, <10% success |
| AUTH-003 | Impossible Travel | 0.92 | Logins from distant locations within impossible timeframe |
| AUTH-004 | Off-Hours Login | 0.65 | Login outside typical business hours |
| AUTH-005 | Weekend Access | 0.60 | Unusual weekend access pattern |
| AUTH-006 | Rapid Failures | 0.80 | Burst of 3+ failures within 60 seconds |

#### Privilege Escalation (3 rules)
| Rule ID | Name | CF | Description |
|---------|------|-----|-------------|
| PRIV-001 | Unauthorized Escalation | 0.90 | Non-admin user attempting privilege escalation |
| PRIV-002 | Sudo Abuse | 0.75 | Unusual sudo command patterns |
| PRIV-003 | Sensitive Access | 0.85 | Access to sensitive resources by unauthorized user |

#### Data Exfiltration (3 rules)
| Rule ID | Name | CF | Description |
|---------|------|-----|-------------|
| DATA-001 | Exfiltration Pattern | 0.78 | Large data transfer during off-hours |
| DATA-002 | Large Download | 0.70 | Statistical outlier in download size |
| DATA-003 | Unusual Data Access | 0.65 | Access to data outside normal pattern |

#### Malware Indicators (3 rules)
| Rule ID | Name | CF | Description |
|---------|------|-----|-------------|
| MAL-001 | Mimikatz Usage | 0.95 | Credential dumping tool detected |
| MAL-002 | PowerShell Obfuscation | 0.85 | Obfuscated PowerShell execution |
| MAL-003 | Reverse Shell | 0.90 | Reverse shell connection pattern |

#### Insider Threats (2 rules)
| Rule ID | Name | CF | Description |
|---------|------|-----|-------------|
| INS-001 | Data Theft Pattern | 0.75 | Resigning employee accessing confidential data |
| INS-002 | Policy Violation | 0.70 | DLP policy violation with removable media |

#### Network Anomalies (3 rules)
| Rule ID | Name | CF | Description |
|---------|------|-----|-------------|
| NET-001 | DDoS Attack | 0.85 | High volume of connections from many sources |
| NET-002 | Port Scan | 0.80 | Sequential connection attempts to multiple ports |
| NET-003 | Lateral Movement | 0.78 | Authentication to multiple internal targets |

### Rule Format

```python
ProductionRule(
    rule_id="AUTH-001",
    name="Brute Force Attack Detection",
    description="Detect multiple failed login attempts from same source",
    category=RuleCategory.AUTHENTICATION,
    priority=RulePriority.HIGH,
    certainty=0.85,
    conditions=[
        RuleCondition(fact_type="aggregated", predicate="failed_login_count", operator=">=", value=5),
        RuleCondition(fact_type="aggregated", predicate="time_window_seconds", operator="<=", value=300),
    ],
    actions=[
        RuleAction(
            action_type="create_anomaly",
            anomaly_type="brute_force_attack",
            threat_level="HIGH",
            recommendation="Block source IP and review authentication logs"
        )
    ]
)
```

---

## Certainty Factor Algebra

The system uses MYCIN-style Certainty Factor algebra for handling uncertainty:

### Combining Certainties

```
For same direction:
CFcombined = CF1 + CF2 * (1 - CF1)

For opposite direction:
CFcombined = (CF1 + CF2) / (1 - min(|CF1|, |CF2|))
```

### Sequential Combination

```
CF(H, E) = CF(rule) × CF(evidence)
```

### Example

```
Rule CF: 0.85
Evidence 1 CF: 0.90
Evidence 2 CF: 0.70

Combined Evidence: 0.90 + 0.70 × (1 - 0.90) = 0.97
Final CF: 0.85 × 0.97 = 0.82 (82% certainty)
```

---

## Detection Layers

The system analyzes logs through four distinct lenses:

| Layer | Technology | What It Does |
|-------|-----------|--------------|
| **Signature-Based (Layer 1)** | Regex patterns + Heuristics | Known attack signatures (SQLi, XSS, Mimikatz, etc.). 20+ signatures covering common attacks. Fast O(n) processing. |
| **Statistical (Layer 2)** | Z-score + Moving averages | Detects outliers in event rates, payload sizes. Baseline profiling using moving averages. Time-series pattern analysis. |
| **Behavioral (Layer 3)** | UEBA + Sequence patterns | User profiling, peer group analysis, attack chains. Sequence pattern matching for attack chains. |
| **Meta-Reasoning (Layer 4)** | CF algebra + Dempster-Shafer | Combines evidence, resolves conflicts. Composite threat scoring (0-100 scale). |

---

## Supported Log Formats

### JSON
- Standard JSON logs
- AWS CloudTrail
- Windows Event Logs (JSON format)
- Custom JSON schemas

### XML
- Windows Event Log (EVTX export)
- Syslog (RFC 5424)
- Common Event Format (CEF)

### Features
- Nested structure flattening
- Timestamp normalization (ISO 8601)
- Schema unification
- Namespace handling

---

## Sample Log Generation

Generate test data for development and testing:

```python
from secure_log_parser_ai.sample_logs import SampleLogGenerator

generator = SampleLogGenerator()

# Generate specific attack scenarios
events = generator.generate_attack_scenario('brute_force', count=100)
events = generator.generate_attack_scenario('sql_injection', count=50)
events = generator.generate_attack_scenario('lateral_movement', count=30)

# Generate mixed logs (70% normal, 30% attacks)
events = generator.generate_mixed_logs(count=500)

# Export to JSON
json_data = generator.to_json(events)

# Export to XML
xml_data = generator.to_xml(events)
```

---

## Performance

### Complexity Analysis

| Component | Time Complexity | Space Complexity |
|-----------|-----------------|------------------|
| JSON Parsing | O(n) | O(n) |
| XML Parsing | O(n) | O(n) |
| Signature Detection | O(n × m) | O(1) |
| Statistical Detection | O(n) | O(k) |
| Rule Matching | O(rules × facts) | O(facts) |
| Inference | O(iterations × rules) | O(facts) |

Where:
- n = number of events
- m = number of signatures
- k = number of baseline metrics

### Benchmarks

Typical performance on standard hardware:
- Parsing: ~10,000 events/second
- Signature Detection: ~5,000 events/second
- Full Analysis: ~1,000 events/second

---

## Testing

```bash
# Run all tests
python -m pytest tests/

# Run specific test category
python -m pytest tests/test_inference_engine.py
python -m pytest tests/test_detection.py

# Generate coverage report
python -m pytest --cov=secure_log_parser_ai tests/
```

---

## Project Structure

```
secure_log_parser_ai/
├── knowledge_base/          # Expert System knowledge base
│   ├── ontology.py         # Frame-based representation, semantic networks
│   ├── certainties.py      # CF algebra, Dempster-Shafer theory
│   └── rule_base.py        # 22 production rules
├── inference_engine/        # Inference engine components
│   ├── forward_chainer.py  # Forward chaining with conflict resolution
│   ├── pattern_matcher.py  # Rete network implementation
│   └── explainer.py        # Natural language justification
├── parsers/                 # Log parsing modules
│   ├── json_parser.py      # JSON log parser
│   ├── xml_parser.py       # XML log parser
│   └── normalizer.py       # Schema unification
├── detection/               # Detection layers
│   ├── signature_based.py  # Pattern matching
│   ├── statistical.py      # Statistical analysis
│   ├── behavioral.py       # UEBA
│   └── uncertainty.py      # Meta-reasoning
├── models/                  # Data models
│   ├── log_event.py        # Frame-based event representation
│   ├── anomaly.py          # Anomaly detection results
│   └── fact.py             # Working memory facts
├── utils/                   # Utilities
│   └── feature_engineering.py
├── sample_logs/             # Sample log generators
│   └── generator.py
├── main.py                  # System integration
├── cli.py                   # Command-line interface
└── README.md
```

---

## Academic Context

This project demonstrates:

### AI Concepts
- **Expert Systems**: Rule-based reasoning with forward chaining
- **Knowledge Representation**: Frames, semantic networks, production rules
- **Uncertainty Handling**: Certainty factors, Dempster-Shafer theory
- **Inference Engines**: Pattern matching, conflict resolution
- **Explanation Facilities**: Natural language justification

### Security Domain Knowledge
- Attack pattern recognition
- Behavioral analysis
- Threat intelligence integration
- Anomaly detection techniques

### Software Engineering
- Modular architecture
- Pipeline pattern
- Strategy pattern
- Separation of concerns

---

## What I Learned

This project taught me more than just technical skills:

- **The value of classical AI**: In our rush toward deep learning, we shouldn't forget the elegant solutions developed over decades of AI research.
- **Domain expertise matters**: You can't build a good security system without understanding how attackers actually think and operate.
- **Uncertainty is everywhere**: Real data is never clean. Learning to quantify and propagate uncertainty is crucial.
- **Explanation is essential**: An AI system that can't explain itself is a liability, not an asset.

---

## Future Work

If I had more time (and sleep), here's what I'd add:

- **Backward chaining**: For hypothesis testing ("Is this a brute force attack?")
- **Truth Maintenance System**: Handle non-monotonic reasoning when new evidence arrives
- **Case-based reasoning**: Learn from historical anomalies
- **More log formats**: Splunk, Elasticsearch, custom enterprise formats
- **Visualization**: Show certainty factor propagation graphs

---

## References

1. Buchanan, B. G., & Shortliffe, E. H. (1984). *Rule-Based Expert Systems: The MYCIN Experiments*
2. Duda, R. O., et al. (1976). "Development of the PROSPECTOR Consultation System"
3. Shafer, G. (1976). *A Mathematical Theory of Evidence*
4. Forgy, C. L. (1982). "Rete: A Fast Algorithm for the Many Pattern/Many Object Pattern Match Problem"

---

## Closing Thoughts

This project represents countless hours of coding, debugging, reading research papers, and asking my professors "but why does it work this way?" 

Is it perfect? No. Could a deep learning system achieve higher accuracy on some benchmarks? Probably. But can those systems tell you *why* they made a decision, or handle incomplete data gracefully, or work without thousands of training examples? 

That's the gap I tried to fill.

I hope this system, or at least the ideas behind it, proves useful to someone out there fighting the good fight against cyber threats.

Stay curious, stay skeptical, and keep learning.

— **Taki Eddine Rami**

---

*"The real problem is not whether machines think but whether men do."* — B.F. Skinner

---

## Acknowledgments

Once again, my deepest gratitude to:
- **Pr. Zebdi** for teaching me that parsing is more than just reading data—it's understanding structure
- **Pr. Chergui** for showing me how to tame semi-structured data without losing my mind
- **Pr. Tag** for reminding me that in cybersecurity, the attacker only needs to be right once—we need to be right every time
- **Pr. Menassel Yahia** for introducing me to the elegant world of expert systems and for insisting that I truly understand certainty factors before implementing them (you were right, the math matters!)

And to my family and friends who tolerated my absent-mindedness during the final weeks of this project—thank you for your patience.

---

**License**: MIT License  
**Version**: 1.0.0  
**Last Updated**: February 2026
"""

with open(readme1_path, 'w', encoding='utf-8') as f:
    f.write(merged_content)

print("Merge completed successfully!")
