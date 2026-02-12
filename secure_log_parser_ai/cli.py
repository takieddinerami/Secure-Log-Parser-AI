"""
Command-line interface for Secure-Log-Parser-AI.
Minimal CLI focused on demonstrating the AI detection engine.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .main import SecureLogParserAI, AnalysisResult
from .sample_logs.generator import SampleLogGenerator


def create_parser() -> argparse.ArgumentParser:
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog='secure-log-parser-ai',
        description='AI-powered anomaly detection for security logs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyze a log file
  python -m secure_log_parser_ai analyze logs.json
  
  # Analyze with specific format
  python -m secure_log_parser_ai analyze logs.xml --format xml
  
  # Generate sample logs for testing
  python -m secure_log_parser_ai generate --attack-type brute_force --count 100
  
  # Run system diagnostics
  python -m secure_log_parser_ai status
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze log files for security anomalies'
    )
    analyze_parser.add_argument(
        'filepath',
        type=str,
        help='Path to log file to analyze'
    )
    analyze_parser.add_argument(
        '-f', '--format',
        choices=['json', 'xml', 'cloudtrail', 'cef', 'auto'],
        default='auto',
        help='Log file format (default: auto-detect)'
    )
    analyze_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file for results (JSON format)'
    )
    analyze_parser.add_argument(
        '--layers',
        type=str,
        default='all',
        help='Detection layers to enable: all, signature, statistical, behavioral, inference'
    )
    analyze_parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Generate command
    generate_parser = subparsers.add_parser(
        'generate',
        help='Generate sample log files for testing'
    )
    generate_parser.add_argument(
        '-t', '--attack-type',
        choices=['brute_force', 'sql_injection', 'lateral_movement', 
                'privilege_escalation', 'data_exfiltration', 'mixed'],
        default='mixed',
        help='Type of attack to simulate'
    )
    generate_parser.add_argument(
        '-c', '--count',
        type=int,
        default=100,
        help='Number of log entries to generate'
    )
    generate_parser.add_argument(
        '-o', '--output',
        type=str,
        default='sample_logs.json',
        help='Output file path'
    )
    generate_parser.add_argument(
        '--format',
        choices=['json', 'xml'],
        default='json',
        help='Output format'
    )
    
    # Status command
    status_parser = subparsers.add_parser(
        'status',
        help='Show system status and statistics'
    )
    
    # Explain command
    explain_parser = subparsers.add_parser(
        'explain',
        help='Explain an anomaly detection result'
    )
    explain_parser.add_argument(
        'result_file',
        type=str,
        help='Path to analysis result JSON file'
    )
    explain_parser.add_argument(
        '-a', '--anomaly-id',
        type=str,
        help='Specific anomaly ID to explain'
    )
    
    return parser


def cmd_analyze(args) -> int:
    """Execute analyze command"""
    print("Secure-Log-Parser-AI Analysis")
    print(f"   File: {args.filepath}")
    print(f"   Format: {args.format}")
    print()
    
    # Initialize system
    system = SecureLogParserAI()
    
    # Configure detection layers
    if args.layers != 'all':
        layers = {layer: False for layer in system.detection_layers}
        for layer in args.layers.split(','):
            layer = layer.strip()
            if layer in layers:
                layers[layer] = True
        system.configure_detection(**layers)
    
    # Analyze file
    try:
        file_format = None if args.format == 'auto' else args.format
        result = system.analyze_file(args.filepath, file_format)
        
        # Display results
        print("[OK] Analysis Complete")
        print(f"   Processed Events: {result.processed_events}")
        print(f"   Execution Time: {result.execution_time_ms:.2f}ms")
        print(f"   Anomalies Detected: {len(result.anomalies)}")
        print()
        
        if result.anomalies:
            print("Detected Anomalies:")
            print("-" * 60)
            
            for i, anomaly in enumerate(result.anomalies[:10], 1):
                print(f"\n{i}. {anomaly.anomaly_type.value.replace('_', ' ').title()}")
                print(f"   Threat Level: {anomaly.threat_level.name}")
                print(f"   Threat Score: {anomaly.threat_score:.1f}/100")
                print(f"   Certainty: {anomaly.certainty*100:.1f}%")
                print(f"   Detection Layer: {anomaly.detection_layer}")
                
                if anomaly.affected_users:
                    print(f"   Affected Users: {', '.join(anomaly.affected_users)}")
                if anomaly.source_ips:
                    print(f"   Source IPs: {', '.join(anomaly.source_ips)}")
                
                if args.verbose:
                    print(f"\n   Explanation:")
                    for line in anomaly.explanation.split('\n'):
                        print(f"      {line}")
                    
                    if anomaly.recommendation:
                        print(f"\n   Recommendation: {anomaly.recommendation}")
                
                print(f"   Evidence Sources: {len(anomaly.evidence)}")
                for ev in anomaly.evidence:
                    print(f"      - {ev.rule_name} (CF: {ev.certainty*100:.1f}%)")
            
            if len(result.anomalies) > 10:
                print(f"\n   ... and {len(result.anomalies) - 10} more anomalies")
        else:
            print("✨ No anomalies detected")
        
        # Save results if output specified
        if args.output:
            with open(args.output, 'w') as f:
                f.write(result.to_json())
            print(f"\n💾 Results saved to: {args.output}")
        
        return 0
        
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.filepath}")
        return 1
    except Exception as e:
        print(f"[ERROR] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_generate(args) -> int:
    """Execute generate command"""
    print("Generating Sample Logs")
    print(f"   Attack Type: {args.attack_type}")
    print(f"   Count: {args.count}")
    print(f"   Format: {args.format}")
    print()
    
    generator = SampleLogGenerator()
    
    try:
        if args.attack_type == 'mixed':
            events = generator.generate_mixed_logs(args.count)
        else:
            events = generator.generate_attack_scenario(args.attack_type, args.count)
        
        # Save to file
        output_path = Path(args.output)
        
        if args.format == 'json':
            data = [event.to_dict() for event in events]
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
        else:
            # XML format
            xml_content = generator.to_xml(events)
            with open(output_path, 'w') as f:
                f.write(xml_content)
        
        print(f"[OK] Generated {len(events)} log entries")
        print(f"Saved to: {output_path.absolute()}")
        
        return 0
        
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1


def cmd_status(args) -> int:
    """Execute status command"""
    print("Secure-Log-Parser-AI System Status")
    print("=" * 50)
    
    system = SecureLogParserAI()
    status = system.get_system_status()
    
    # Knowledge Base
    print("\nKnowledge Base:")
    kb_stats = status['knowledge_base']['rule_statistics']
    print(f"   Total Rules: {kb_stats['total_rules']}")
    print(f"   By Category:")
    for category, count in kb_stats['by_category'].items():
        print(f"      - {category}: {count}")
    
    # Working Memory
    print("\nWorking Memory:")
    wm_stats = status['working_memory']
    print(f"   Total Facts: {wm_stats['total_facts']}")
    print(f"   Unique Subjects: {wm_stats['by_subject']}")
    print(f"   Unique Predicates: {wm_stats['by_predicate']}")
    
    # Detection Layers
    print("\nDetection Layers:")
    detectors = status['detectors']
    print(f"   Signatures: {detectors['signatures']['total_signatures']} rules")
    print(f"   Statistical Baselines: {len(detectors['statistical']['global_baselines'])} metrics")
    print(f"   Behavioral Profiles: {detectors['behavioral']['user_profiles']} users")
    
    # Inference Engine
    print("\nInference Engine:")
    ie_stats = status['inference_engine']['performance']
    print(f"   Rules Fired (last run): {ie_stats['total_rules_fired']}")
    print(f"   Avg Match Time: {ie_stats['avg_match_time_ms']:.3f}ms")
    print(f"   Avg Fire Time: {ie_stats['avg_fire_time_ms']:.3f}ms")
    
    return 0


def cmd_explain(args) -> int:
    """Execute explain command"""
    print("Explaining Analysis Results")
    print(f"   File: {args.result_file}")
    print()
    
    try:
        with open(args.result_file, 'r') as f:
            data = json.load(f)
        
        anomalies = data.get('anomalies', [])
        
        if not anomalies:
            print("No anomalies found in results file")
            return 0
        
        if args.anomaly_id:
            # Find specific anomaly
            anomaly = next(
                (a for a in anomalies if a['anomaly_id'] == args.anomaly_id),
                None
            )
            if anomaly:
                print_explanation(anomaly)
            else:
                print(f"[ERROR] Anomaly {args.anomaly_id} not found")
                return 1
        else:
            # Explain all anomalies
            for i, anomaly in enumerate(anomalies, 1):
                print(f"\n{'='*60}")
                print(f"Anomaly {i}/{len(anomalies)}")
                print(f"{'='*60}")
                print_explanation(anomaly)
        
        return 0
        
    except FileNotFoundError:
        print(f"❌ Error: File not found: {args.result_file}")
        return 1
    except json.JSONDecodeError:
        print("[ERROR] Invalid JSON file")
        return 1


def print_explanation(anomaly: dict) -> None:
    """Print formatted anomaly explanation"""
    print(f"\n🚨 {anomaly['anomaly_type'].replace('_', ' ').title()}")
    print(f"   ID: {anomaly['anomaly_id']}")
    print(f"   Threat Level: {anomaly['threat_level']}")
    print(f"   Threat Score: {anomaly['threat_score']}/100")
    print(f"   Certainty: {anomaly['certainty']*100:.1f}%")
    print(f"   Detection Layer: {anomaly['detection_layer']}")
    
    if anomaly.get('affected_users'):
        print(f"   Affected Users: {', '.join(anomaly['affected_users'])}")
    if anomaly.get('source_ips'):
        print(f"   Source IPs: {', '.join(anomaly['source_ips'])}")
    
    print(f"\n   Explanation:")
    for line in anomaly.get('explanation', 'No explanation available').split('\n'):
        print(f"      {line}")
    
    if anomaly.get('recommendation'):
        print(f"\n   Recommendation: {anomaly['recommendation']}")
    
    print(f"\n   Evidence ({len(anomaly.get('evidence', []))} sources):")
    for ev in anomaly.get('evidence', []):
        print(f"      • {ev['rule_name']}")
        print(f"        {ev['description']}")
        print(f"        Certainty: {ev['certainty']*100:.1f}%")


def main(args: Optional[list] = None) -> int:
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args(args)
    
    if not args.command:
        parser.print_help()
        return 1
    
    commands = {
        'analyze': cmd_analyze,
        'generate': cmd_generate,
        'status': cmd_status,
        'explain': cmd_explain
    }
    
    command_func = commands.get(args.command)
    if command_func:
        return command_func(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
