"""
Statistical anomaly detection layer.
Implements baseline profiling, z-score calculation, and time-series analysis.
"""
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timedelta
import statistics
import math

from ..models.log_event import LogEvent
from ..models.anomaly import Anomaly, AnomalyType, ThreatLevel, Evidence


@dataclass
class BaselineProfile:
    """Statistical baseline profile for a metric"""
    metric_name: str
    mean: float = 0.0
    std_dev: float = 0.0
    min_value: float = 0.0
    max_value: float = 0.0
    sample_count: int = 0
    last_updated: datetime = field(default_factory=datetime.now)
    
    def update(self, value: float) -> None:
        """Update profile with new value using Welford's algorithm"""
        self.sample_count += 1
        delta = value - self.mean
        self.mean += delta / self.sample_count
        delta2 = value - self.mean
        
        if self.sample_count > 1:
            # Update variance
            variance = (self.std_dev ** 2) * (self.sample_count - 2)
            variance += delta * delta2
            self.std_dev = math.sqrt(variance / (self.sample_count - 1))
        
        self.min_value = min(self.min_value, value) if self.min_value else value
        self.max_value = max(self.max_value, value)
        self.last_updated = datetime.now()
    
    def calculate_z_score(self, value: float) -> float:
        """Calculate z-score for a value"""
        if self.std_dev == 0:
            return 0.0
        return (value - self.mean) / self.std_dev
    
    def is_anomaly(self, value: float, threshold: float = 3.0) -> bool:
        """Check if value is anomalous based on z-score"""
        z_score = abs(self.calculate_z_score(value))
        return z_score > threshold


@dataclass
class TimeWindow:
    """Time window for aggregating events"""
    start: datetime
    end: datetime
    events: List[LogEvent] = field(default_factory=list)
    
    def add_event(self, event: LogEvent) -> None:
        if self.start <= event.timestamp <= self.end:
            self.events.append(event)
    
    @property
    def count(self) -> int:
        return len(self.events)
    
    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()


class StatisticalDetector:
    """
    Statistical anomaly detection layer.
    
    Layer 2 of the detection pipeline.
    - Baseline profiling using moving averages
    - Z-score calculation for numerical features
    - Time-series pattern analysis
    - Rate-based anomaly detection
    
    Complexity: O(n) for single pass, O(1) for incremental updates
    """
    
    def __init__(self):
        # Baseline profiles for different metrics
        self.baselines: Dict[str, BaselineProfile] = {}
        
        # User behavior baselines
        self.user_baselines: Dict[str, Dict[str, BaselineProfile]] = defaultdict(dict)
        
        # IP behavior baselines
        self.ip_baselines: Dict[str, Dict[str, BaselineProfile]] = defaultdict(dict)
        
        # Time window history for rate analysis
        self.window_history: List[TimeWindow] = []
        self.window_size = timedelta(minutes=5)
        
        # Detection thresholds
        self.z_score_threshold = 3.0
        self.min_samples_for_baseline = 10
    
    def update_baseline(self, metric_name: str, value: float, 
                        user_id: Optional[str] = None,
                        ip_address: Optional[str] = None) -> None:
        """
        Update baseline profile with new observation.
        
        Args:
            metric_name: Name of the metric (e.g., 'event_rate', 'payload_size')
            value: Observed value
            user_id: Optional user context for user-specific baseline
            ip_address: Optional IP context for IP-specific baseline
        """
        # Global baseline
        if metric_name not in self.baselines:
            self.baselines[metric_name] = BaselineProfile(metric_name)
        self.baselines[metric_name].update(value)
        
        # User-specific baseline
        if user_id:
            if metric_name not in self.user_baselines[user_id]:
                self.user_baselines[user_id][metric_name] = BaselineProfile(f"{user_id}:{metric_name}")
            self.user_baselines[user_id][metric_name].update(value)
        
        # IP-specific baseline
        if ip_address:
            if metric_name not in self.ip_baselines[ip_address]:
                self.ip_baselines[ip_address][metric_name] = BaselineProfile(f"{ip_address}:{metric_name}")
            self.ip_baselines[ip_address][metric_name].update(value)
    
    def detect(self, event: LogEvent, context: Optional[Dict] = None) -> List[Anomaly]:
        """
        Detect statistical anomalies in a single event.
        
        Returns list of detected anomalies.
        """
        anomalies = []
        
        # Check event rate anomalies
        rate_anomaly = self._check_event_rate(event, context)
        if rate_anomaly:
            anomalies.append(rate_anomaly)
        
        # Check payload size anomalies
        size_anomaly = self._check_payload_size(event)
        if size_anomaly:
            anomalies.append(size_anomaly)
        
        # Check temporal pattern anomalies
        temporal_anomaly = self._check_temporal_pattern(event)
        if temporal_anomaly:
            anomalies.append(temporal_anomaly)
        
        # Check user behavior anomalies
        if event.user_id:
            user_anomaly = self._check_user_behavior(event)
            if user_anomaly:
                anomalies.append(user_anomaly)
        
        return anomalies
    
    def detect_batch(self, events: List[LogEvent]) -> List[Anomaly]:
        """
        Detect anomalies in a batch of events.
        First builds baselines, then detects anomalies.
        """
        if not events:
            return []
        
        # First pass: build baselines
        self._build_baselines_from_events(events)
        
        # Second pass: detect anomalies
        anomalies = []
        for event in events:
            event_anomalies = self.detect(event)
            anomalies.extend(event_anomalies)
        
        return anomalies
    
    def _build_baselines_from_events(self, events: List[LogEvent]) -> None:
        """Build baseline profiles from event batch"""
        # Group events by time windows
        if not events:
            return
        
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        
        # Calculate event rates per user and IP
        user_event_counts: Dict[str, List[int]] = defaultdict(list)
        ip_event_counts: Dict[str, List[int]] = defaultdict(list)
        payload_sizes: List[float] = []
        
        # Sliding window analysis
        window_size = timedelta(minutes=5)
        current_window_start = events_sorted[0].timestamp
        window_user_counts: Dict[str, int] = defaultdict(int)
        window_ip_counts: Dict[str, int] = defaultdict(int)
        
        for event in events_sorted:
            # Check if we need to start a new window
            if event.timestamp - current_window_start > window_size:
                # Record window counts
                for user, count in window_user_counts.items():
                    user_event_counts[user].append(count)
                for ip, count in window_ip_counts.items():
                    ip_event_counts[ip].append(count)
                
                # Reset window
                current_window_start = event.timestamp
                window_user_counts.clear()
                window_ip_counts.clear()
            
            # Count in current window
            if event.user_id:
                window_user_counts[event.user_id] += 1
            if event.source_ip:
                window_ip_counts[event.source_ip] += 1
            
            # Collect payload sizes
            payload_size = event.get_attribute('payload_size') or event.get_attribute('bytes_sent')
            if payload_size:
                try:
                    payload_sizes.append(float(payload_size))
                except (ValueError, TypeError):
                    pass
        
        # Update baselines
        for user, counts in user_event_counts.items():
            for count in counts:
                self.update_baseline('event_rate', count, user_id=user)
        
        for ip, counts in ip_event_counts.items():
            for count in counts:
                self.update_baseline('event_rate', count, ip_address=ip)
        
        for size in payload_sizes:
            self.update_baseline('payload_size', size)
    
    def _check_event_rate(self, event: LogEvent, context: Optional[Dict]) -> Optional[Anomaly]:
        """Check for anomalous event rates"""
        if not context or 'recent_event_count' not in context:
            return None
        
        recent_count = context.get('recent_event_count', 0)
        time_window = context.get('time_window_seconds', 60)
        rate = recent_count / time_window if time_window > 0 else 0
        
        # Check against baseline
        baseline = self.baselines.get('event_rate')
        if baseline and baseline.sample_count >= self.min_samples_for_baseline:
            z_score = baseline.calculate_z_score(rate)
            
            if abs(z_score) > self.z_score_threshold:
                evidence = Evidence(
                    rule_id='STAT-001',
                    rule_name='Statistical Event Rate Anomaly',
                    description=f'Event rate {rate:.2f}/s is {abs(z_score):.2f} std devs from mean',
                    certainty=min(0.9, abs(z_score) / 5),
                    matched_facts=[event.event_id],
                    contributing_attributes={
                        'observed_rate': rate,
                        'baseline_mean': baseline.mean,
                        'baseline_std': baseline.std_dev,
                        'z_score': z_score
                    }
                )
                
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.STATISTICAL_OUTLIER,
                    detection_layer="statistical",
                    source_events=[event.event_id],
                    affected_users=[event.user_id] if event.user_id else [],
                    source_ips=[event.source_ip] if event.source_ip else [],
                    threat_level=ThreatLevel.MEDIUM if abs(z_score) < 5 else ThreatLevel.HIGH,
                    triggered_rules=['STAT-001'],
                    recommendation="Review event rate patterns and investigate source"
                )
                
                anomaly.add_evidence(evidence)
                anomaly.calculate_threat_score()
                anomaly.generate_explanation()
                
                return anomaly
        
        return None
    
    def _check_payload_size(self, event: LogEvent) -> Optional[Anomaly]:
        """Check for anomalous payload sizes"""
        payload_size = event.get_attribute('payload_size') or event.get_attribute('bytes_sent')
        if not payload_size:
            return None
        
        try:
            size = float(payload_size)
        except (ValueError, TypeError):
            return None
        
        baseline = self.baselines.get('payload_size')
        if baseline and baseline.sample_count >= self.min_samples_for_baseline:
            z_score = baseline.calculate_z_score(size)
            
            if z_score > self.z_score_threshold:  # Only check for large values
                evidence = Evidence(
                    rule_id='STAT-002',
                    rule_name='Statistical Payload Size Anomaly',
                    description=f'Payload size {size} is {z_score:.2f} std devs above mean',
                    certainty=min(0.85, z_score / 5),
                    matched_facts=[event.event_id],
                    contributing_attributes={
                        'observed_size': size,
                        'baseline_mean': baseline.mean,
                        'baseline_std': baseline.std_dev,
                        'z_score': z_score
                    }
                )
                
                anomaly = Anomaly(
                    anomaly_type=AnomalyType.LARGE_DOWNLOAD,
                    detection_layer="statistical",
                    source_events=[event.event_id],
                    affected_users=[event.user_id] if event.user_id else [],
                    source_ips=[event.source_ip] if event.source_ip else [],
                    threat_level=ThreatLevel.MEDIUM,
                    triggered_rules=['STAT-002'],
                    recommendation="Review large data transfer for potential exfiltration"
                )
                
                anomaly.add_evidence(evidence)
                anomaly.calculate_threat_score()
                anomaly.generate_explanation()
                
                return anomaly
        
        return None
    
    def _check_temporal_pattern(self, event: LogEvent) -> Optional[Anomaly]:
        """Check for anomalous temporal patterns"""
        # Check if event occurs at unusual time
        if not event.time_features:
            return None
        
        is_night = event.time_features.get('is_night', False)
        is_weekend = event.time_features.get('is_weekend', False)
        
        # Simple check: flag activity during night on weekends
        if is_night and is_weekend:
            evidence = Evidence(
                rule_id='STAT-003',
                rule_name='Off-Hours Activity',
                description='Activity detected during night time on weekend',
                certainty=0.60,
                matched_facts=[event.event_id],
                contributing_attributes={
                    'hour': event.time_features.get('hour'),
                    'day_of_week': event.time_features.get('day_of_week'),
                    'is_night': is_night,
                    'is_weekend': is_weekend
                }
            )
            
            anomaly = Anomaly(
                anomaly_type=AnomalyType.OFF_HOURS_ACCESS,
                detection_layer="statistical",
                source_events=[event.event_id],
                affected_users=[event.user_id] if event.user_id else [],
                source_ips=[event.source_ip] if event.source_ip else [],
                threat_level=ThreatLevel.LOW,
                triggered_rules=['STAT-003'],
                recommendation="Verify business justification for off-hours access"
            )
            
            anomaly.add_evidence(evidence)
            anomaly.calculate_threat_score()
            anomaly.generate_explanation()
            
            return anomaly
        
        return None
    
    def _check_user_behavior(self, event: LogEvent) -> Optional[Anomaly]:
        """Check for anomalous user behavior"""
        if not event.user_id:
            return None
        
        user_baseline = self.user_baselines.get(event.user_id, {})
        event_rate_baseline = user_baseline.get('event_rate')
        
        if event_rate_baseline and event_rate_baseline.sample_count >= self.min_samples_for_baseline:
            # Check current activity level
            # This would need recent context to calculate properly
            pass
        
        return None
    
    def get_baseline_statistics(self) -> Dict[str, Any]:
        """Get baseline statistics"""
        return {
            'global_baselines': {
                name: {
                    'mean': profile.mean,
                    'std_dev': profile.std_dev,
                    'samples': profile.sample_count
                }
                for name, profile in self.baselines.items()
            },
            'user_baselines_count': len(self.user_baselines),
            'ip_baselines_count': len(self.ip_baselines)
        }
