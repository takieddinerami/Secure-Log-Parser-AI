#!/usr/bin/env python3
"""
Test script for Secure-Log-Parser-AI
"""
from secure_log_parser_ai.main import SecureLogParserAI
from secure_log_parser_ai.sample_logs.generator import SampleLogGenerator

def main():
    print("=" * 60)
    print("Secure-Log-Parser-AI System Test")
    print("=" * 60)
    print()
    
    # Initialize system
    print("Initializing system...")
    system = SecureLogParserAI()
    print(f"[OK] System initialized with {len(system.rule_base.get_all_rules())} production rules")
    print()
    
    # Test 1: Generate and analyze brute force logs
    print("Test 1: Brute Force Attack Detection")
    print("-" * 40)
    generator = SampleLogGenerator(seed=42)
    events = generator.generate_attack_scenario('brute_force', count=50)
    print(f"Generated {len(events)} sample events")
    
    result = system.analyze_events(events)
    print(f"Processed {result.processed_events} events")
    print(f"Detected {len(result.anomalies)} anomalies")
    
    if result.anomalies:
        print("\nTop Anomalies:")
        for i, anomaly in enumerate(result.anomalies[:3], 1):
            print(f"  {i}. {anomaly.anomaly_type.value}")
            print(f"     Threat Score: {anomaly.threat_score:.1f}/100")
            print(f"     Certainty: {anomaly.certainty*100:.1f}%")
            print(f"     Layer: {anomaly.detection_layer}")
    
    print()
    system.reset()
    
    # Test 2: SQL Injection Detection
    print("Test 2: SQL Injection Detection")
    print("-" * 40)
    events = generator.generate_attack_scenario('sql_injection', count=30)
    result = system.analyze_events(events)
    print(f"Processed {result.processed_events} events")
    
    sql_anomalies = [a for a in result.anomalies if 'sql' in a.anomaly_type.value.lower()]
    print(f"Detected {len(sql_anomalies)} SQL injection related anomalies")
    print()
    system.reset()
    
    # Test 3: Mixed logs
    print("Test 3: Mixed Normal and Attack Logs")
    print("-" * 40)
    events = generator.generate_mixed_logs(count=200)
    result = system.analyze_events(events)
    print(f"Processed {result.processed_events} events")
    print(f"Detected {len(result.anomalies)} total anomalies")
    
    # Show anomaly type breakdown
    from collections import Counter
    type_counts = Counter(a.anomaly_type.value for a in result.anomalies)
    print("\nBreakdown by type:")
    for atype, count in type_counts.most_common():
        print(f"  - {atype}: {count}")
    
    print()
    
    # Test 4: System status
    print("Test 4: System Status")
    print("-" * 40)
    status = system.get_system_status()
    print(f"Knowledge Base Rules: {status['knowledge_base']['rule_statistics']['total_rules']}")
    print(f"Working Memory Facts: {status['working_memory']['total_facts']}")
    print(f"Signature Rules: {status['detectors']['signatures']['total_signatures']}")
    print()
    
    # Test 5: Explanation generation
    print("Test 5: Explanation Generation")
    print("-" * 40)
    if result.anomalies:
        anomaly = result.anomalies[0]
        print(f"Anomaly: {anomaly.anomaly_type.value}")
        print(f"Explanation preview:")
        lines = anomaly.explanation.split('\n')[:5]
        for line in lines:
            print(f"  {line}")
        print("  ...")
    
    print()
    print("=" * 60)
    print("All tests completed successfully!")
    print("=" * 60)

if __name__ == '__main__':
    main()
