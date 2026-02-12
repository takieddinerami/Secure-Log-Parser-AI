# Secure-Log-Parser-AI

## A Journey into AI-Powered Cybersecurity

---

*"In a world where cyber threats evolve faster than ever, we need systems that don't just process data—they need to understand it, reason about it, and explain their decisions. This project is my attempt to bridge the gap between classical AI and modern cybersecurity."*

---

Hello, and welcome to my project. 

My name is **Taki Eddine Rami**, and I'm thrilled to share with you something that has been both a challenging and deeply rewarding journey over the past months. What you're looking at isn't just another log analysis tool, it's an intelligent system that thinks, reasons, and explains itself like a human security analyst would.

This work was completed under the invaluable supervision and guidance of four exceptional professors who shaped my understanding of both the theoretical and practical aspects of this field:

- **Pr. Tag Samir** - Professor of Cybersecurity, who constantly pushed me to think like an attacker and understand the real-world implications of every detection
- **Pr. Menassel Yahia** - Professor of AI, whose deep knowledge of expert systems, knowledge representation, and reasoning under uncertainty formed the theoretical foundation of this entire project
- **Pr. Zebdi Abdel Moumen** - Professor of Compilation, who taught me the importance of systematic parsing and the beauty of well-structured language processing
- **Pr. Chergui Othaila** - Professor of Semi-Structured Data, whose insights on handling messy, real-world data formats were crucial to this project's success  
To all four of you, thank you for your patience, your challenging questions, and your unwavering support.

---

## What Is This Project About?

Let me be honest with you—when I first started this project, I was overwhelmed. The cybersecurity landscape is flooded with "black box" machine learning solutions that detect anomalies but can't tell you *why* they flagged something. I wanted to build something different. Something transparent. Something that could explain its reasoning to a junior analyst or a C-suite executive with equal clarity.

**Secure-Log-Parser-AI** is a rule-based Expert System for detecting security anomalies in semi-structured logs (JSON, XML, syslog). It combines classical AI techniques with modern cybersecurity needs to create a system that is:

- **Interpretable**: Every detection comes with a natural language explanation
- **Uncertainty-aware**: It knows when it's confident and when it's not
- **Multi-layered**: It looks at your data from four different perspectives before making a decision
- **Fast**: No deep learning training cycles—just intelligent reasoning

### The Core Idea

Imagine a seasoned security analyst who has seen every attack in the book. They don't just look for signatures—they understand patterns, they notice when something "feels off," and they can articulate exactly why they're concerned. That's what I tried to encode into this system.

---

## What Technologies Did I Use?

I believe in using the right tool for the job, not the trendiest one. Here's what powers this system:

### Core AI Technologies

**1. Expert Systems & Forward Chaining**
- I implemented a full forward-chaining inference engine with conflict resolution
- 22 hand-crafted production rules that capture real security expertise
- Working memory with hash-based indexing for O(1) fact lookup

**2. Knowledge Representation**
- Frame-based representation for log events (inspired by Minsky's frames)
- Semantic networks to model relationships between attack types
- Production rules with Certainty Factors for uncertainty handling

**3. Uncertainty Handling**
- Certainty Factor algebra (the same approach used in the famous MYCIN system)
- Dempster-Shafer theory for combining evidence from multiple sources
- Fuzzy logic for handling vague temporal patterns ("off-hours," "high volume")

**4. Pattern Matching**
- A simplified Rete network implementation for efficient rule firing
- Multi-condition rule matching with proper join semantics

### Detection Layers

The system analyzes logs through four distinct lenses:

| Layer | Technology | What It Does |
|-------|-----------|--------------|
| **Signature** | Regex patterns + Heuristics | Known attack signatures (SQLi, XSS, Mimikatz, etc.) |
| **Statistical** | Z-score + Moving averages | Detects outliers in event rates, payload sizes |
| **Behavioral** | UEBA + Sequence patterns | User profiling, peer group analysis, attack chains |
| **Meta-Reasoning** | CF algebra + Dempster-Shafer | Combines evidence, resolves conflicts |

### Parsing & Data Handling

- **JSON Parser**: Handles nested structures, CloudTrail, Windows Events
- **XML Parser**: DOM/SAX hybrid approach, namespace handling
- **Normalizer**: Unifies schemas across different log formats
- **Feature Engineering**: Temporal, frequency, and behavioral feature extraction

### Programming & Architecture

- **Python 3.9+**: Clean, readable, maintainable code
- **Pure Python for core AI**: No heavy dependencies for the reasoning engine
- **Modular architecture**: Knowledge base, inference engine, and working memory are cleanly separated
- **Pipeline pattern**: Parse → Normalize → Feature Extract → Detect → Explain

---

## The 22 Rules: A Peek Into the Knowledge Base

I spent considerable time researching real attack patterns and consulting with security professionals to craft these rules. Here are a few examples:

```
Rule AUTH-001: Brute Force Attack Detection
IF failed_login_count >= 5 AND time_window < 300s AND source_ip = same
THEN flag_brute_force_attack (CF: 0.85)

Rule AUTH-003: Impossible Travel
IF same_user_different_country AND time_between_logins < 60min AND distance > 500km
THEN flag_impossible_travel (CF: 0.92)

Rule MAL-001: Mimikatz Detection
IF process_name matches 'mimikatz|sekurlsa|lsadump'
THEN flag_credential_dumping (CF: 0.95)
```

Each rule has:
- A priority level (CRITICAL, HIGH, MEDIUM, LOW)
- A certainty factor (0.0 to 1.0)
- A natural language explanation template
- A recommended response action

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

## How to Use It

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd secure_log_parser_ai

# Install in development mode
pip install -e .
```

### Command Line Interface

```bash
# Analyze a log file
python -m secure_log_parser_ai analyze security_logs.json

# Generate sample attack logs for testing
python -m secure_log_parser_ai generate --attack-type brute_force --count 100

# Check system status
python -m secure_log_parser_ai status
```

### Python API

```python
from secure_log_parser_ai import SecureLogParserAI

# Initialize the system
system = SecureLogParserAI()

# Analyze your logs
result = system.analyze_file('logs.json')

# Review findings
for anomaly in result.anomalies:
    print(f"Detected: {anomaly.anomaly_type.value}")
    print(f"Certainty: {anomaly.certainty*100:.1f}%")
    print(f"Explanation: {anomaly.explanation}")
```

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
