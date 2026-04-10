"""
Integration tests for the complete system.
"""
import unittest
from datetime import datetime

from secure_log_parser_ai.main import SecureLogParserAI, AnalysisResult
from secure_log_parser_ai.sample_logs.generator import SampleLogGenerator
from secure_log_parser_ai.models.log_event import LogEvent


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.system = SecureLogParserAI()
        self.generator = SampleLogGenerator(seed=42)
    
    def test_system_initialization(self):
        """Test system initializes correctly"""
        self.assertIsNotNone(self.system.rule_base)
        self.assertIsNotNone(self.system.working_memory)
        self.assertIsNotNone(self.system.inference_engine)
        self.assertEqual(len(self.system.rule_base.get_all_rules()), 22)
    
    def test_analyze_brute_force_logs(self):
        """Test detection of brute force attack logs"""
        events = self.generator.generate_attack_scenario('brute_force', count=50)
        
        result = self.system.analyze_events(events)
        
        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(result.processed_events, 50)
        
        # Should detect brute force anomalies
        brute_force_anomalies = [
            a for a in result.anomalies 
            if 'brute' in a.anomaly_type.value.lower()
        ]
        self.assertGreater(len(brute_force_anomalies), 0)
    
    def test_analyze_sql_injection_logs(self):
        """Test detection of SQL injection logs"""
        events = self.generator.generate_attack_scenario('sql_injection', count=30)
        
        result = self.system.analyze_events(events)
        
        # Should detect SQL injection
        sql_anomalies = [
            a for a in result.anomalies
            if 'sql' in a.anomaly_type.value.lower()
        ]
        self.assertGreater(len(sql_anomalies), 0)
    
    def test_analyze_mixed_logs(self):
        """Test analysis of mixed normal and attack logs"""
        events = self.generator.generate_mixed_logs(count=200)
        
        result = self.system.analyze_events(events)
        
        self.assertEqual(result.processed_events, 200)
        self.assertIsNotNone(result.anomalies)
        
        # Should have various types of anomalies
        anomaly_types = set(a.anomaly_type.value for a in result.anomalies)
        self.assertGreater(len(anomaly_types), 0)
    
    def test_explanation_generation(self):
        """Test that explanations are generated"""
        events = self.generator.generate_attack_scenario('brute_force', count=20)
        
        result = self.system.analyze_events(events)
        
        for anomaly in result.anomalies:
            self.assertIsNotNone(anomaly.explanation)
            self.assertGreater(len(anomaly.explanation), 0)
            self.assertIn(anomaly.anomaly_type.value.replace('_', ' '), 
                         anomaly.explanation.lower())
    
    def test_threat_scoring(self):
        """Test threat score calculation"""
        events = self.generator.generate_attack_scenario('brute_force', count=30)
        
        result = self.system.analyze_events(events)
        
        for anomaly in result.anomalies:
            self.assertGreaterEqual(anomaly.threat_score, 0)
            self.assertLessEqual(anomaly.threat_score, 100)
            self.assertGreaterEqual(anomaly.certainty, 0)
            self.assertLessEqual(anomaly.certainty, 1)
    
    def test_system_status(self):
        """Test system status report"""
        status = self.system.get_system_status()
        
        self.assertIn('knowledge_base', status)
        self.assertIn('working_memory', status)
        self.assertIn('detectors', status)
        
        self.assertEqual(status['knowledge_base']['rule_statistics']['total_rules'], 22)
    
    def test_detection_layer_configuration(self):
        """Test configuring detection layers"""
        # Disable all layers except signature
        self.system.configure_detection(
            signature=True,
            statistical=False,
            behavioral=False,
            inference=False
        )
        
        events = self.generator.generate_mixed_logs(count=100)
        result = self.system.analyze_events(events)
        
        # Should still work with limited layers
        self.assertEqual(result.processed_events, 100)
        
        # Reset to default
        self.system.configure_detection(
            signature=True,
            statistical=True,
            behavioral=True,
            inference=True
        )


class TestCertaintyFactors(unittest.TestCase):
    """Test certainty factor calculations"""
    
    def test_cf_combination(self):
        """Test certainty factor combination"""
        from secure_log_parser_ai.knowledge_base.certainties import CertaintyFactorAlgebra
        
        # Test same direction combination
        cf1 = 0.6
        cf2 = 0.7
        combined = CertaintyFactorAlgebra.combine(cf1, cf2)
        expected = 0.6 + 0.7 * (1 - 0.6)  # = 0.88
        self.assertAlmostEqual(combined, expected, places=5)
        
        # Test multiple combination
        cfs = [0.5, 0.6, 0.7]
        combined = CertaintyFactorAlgebra.combine_multiple(cfs)
        self.assertGreater(combined, 0.5)
        self.assertLessEqual(combined, 1.0)


class TestKnowledgeBase(unittest.TestCase):
    """Test knowledge base components"""
    
    def test_security_ontology(self):
        """Test security ontology"""
        from secure_log_parser_ai.knowledge_base.ontology import SecurityOntology
        
        ontology = SecurityOntology()
        
        # Test node retrieval
        node = ontology.get_node('brute_force')
        self.assertIsNotNone(node)
        
        # Test relation lookup
        indicators = ontology.get_related_attacks('multiple_failed_logins')
        self.assertIn('brute_force', indicators)
    
    def test_rule_base(self):
        """Test rule base"""
        from secure_log_parser_ai.knowledge_base.rule_base import RuleBase
        
        rb = RuleBase()
        
        # Should have 22 rules
        self.assertEqual(len(rb.get_all_rules()), 22)
        
        # Test category filtering
        auth_rules = rb.get_rules_by_category(
            rb.get_all_rules()[0].category
        )
        self.assertGreater(len(auth_rules), 0)


if __name__ == '__main__':
    unittest.main()
