"""
Feature engineering for log analysis.
Extracts temporal, frequency, and behavioral features.
"""
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime, timedelta
import statistics
import math

from ..models.log_event import LogEvent


@dataclass
class TemporalFeatures:
    """Temporal features extracted from events"""
    hour: int
    day_of_week: int
    is_weekend: bool
    is_business_hours: bool
    is_night: bool
    session_duration: Optional[float] = None
    time_since_last_event: Optional[float] = None


@dataclass
class FrequencyFeatures:
    """Frequency-based features"""
    event_count: int
    events_per_minute: float
    unique_users: int
    unique_ips: int
    unique_services: int


@dataclass
class BehavioralFeatures:
    """Behavioral features"""
    user_diversity: float  # Entropy of user distribution
    ip_diversity: float
    service_diversity: float
    pattern_consistency: float


class FeatureExtractor:
    """
    Feature extraction for log analysis.
    
    Extracts:
    - Temporal features: time patterns, session duration
    - Frequency features: event rates, unique counts
    - Behavioral features: entropy measures, consistency
    - Graph features: interaction patterns
    """
    
    def __init__(self):
        self.event_history: List[LogEvent] = []
        self.max_history = 10000
        
        # Sliding window for rate calculations
        self.window_size = timedelta(minutes=5)
    
    def extract_features(self, event: LogEvent, 
                        context_events: Optional[List[LogEvent]] = None) -> Dict[str, Any]:
        """
        Extract all features for an event.
        
        Returns dictionary of feature names to values.
        """
        features = {}
        
        # Temporal features
        temporal = self.extract_temporal_features(event)
        features.update(self._temporal_to_dict(temporal))
        
        # Frequency features
        context = context_events or self._get_recent_events(event.timestamp)
        frequency = self.extract_frequency_features(context)
        features.update(self._frequency_to_dict(frequency))
        
        # Behavioral features
        behavioral = self.extract_behavioral_features(context)
        features.update(self._behavioral_to_dict(behavioral))
        
        # Add to history
        self.event_history.append(event)
        if len(self.event_history) > self.max_history:
            self.event_history.pop(0)
        
        return features
    
    def extract_temporal_features(self, event: LogEvent) -> TemporalFeatures:
        """Extract temporal features from an event"""
        timestamp = event.timestamp
        
        # Basic temporal features
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        is_weekend = day_of_week >= 5
        is_business_hours = 9 <= hour < 17 and not is_weekend
        is_night = hour < 6 or hour >= 22
        
        # Calculate time since last event from same user/IP
        time_since_last = None
        session_duration = None
        
        if self.event_history:
            # Find last event from same user
            if event.user_id:
                user_events = [
                    e for e in reversed(self.event_history)
                    if e.user_id == event.user_id
                ]
                if user_events:
                    last_event = user_events[0]
                    time_since_last = (event.timestamp - last_event.timestamp).total_seconds()
                    
                    # Estimate session duration (events within 30 min)
                    if time_since_last < 1800:  # 30 minutes
                        session_events = [
                            e for e in user_events
                            if (event.timestamp - e.timestamp).total_seconds() < 1800
                        ]
                        if len(session_events) > 1:
                            session_duration = (
                                session_events[0].timestamp - session_events[-1].timestamp
                            ).total_seconds()
        
        return TemporalFeatures(
            hour=hour,
            day_of_week=day_of_week,
            is_weekend=is_weekend,
            is_business_hours=is_business_hours,
            is_night=is_night,
            session_duration=session_duration,
            time_since_last_event=time_since_last
        )
    
    def extract_frequency_features(self, events: List[LogEvent]) -> FrequencyFeatures:
        """Extract frequency features from a set of events"""
        if not events:
            return FrequencyFeatures(
                event_count=0,
                events_per_minute=0.0,
                unique_users=0,
                unique_ips=0,
                unique_services=0
            )
        
        # Basic counts
        event_count = len(events)
        
        # Calculate rate
        if len(events) > 1:
            time_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
            events_per_minute = (event_count / time_span * 60) if time_span > 0 else 0
        else:
            events_per_minute = 0
        
        # Unique counts
        unique_users = len(set(e.user_id for e in events if e.user_id))
        unique_ips = len(set(e.source_ip for e in events if e.source_ip))
        unique_services = len(set(e.service for e in events if e.service))
        
        return FrequencyFeatures(
            event_count=event_count,
            events_per_minute=events_per_minute,
            unique_users=unique_users,
            unique_ips=unique_ips,
            unique_services=unique_services
        )
    
    def extract_behavioral_features(self, events: List[LogEvent]) -> BehavioralFeatures:
        """Extract behavioral features using entropy measures"""
        if not events:
            return BehavioralFeatures(
                user_diversity=0.0,
                ip_diversity=0.0,
                service_diversity=0.0,
                pattern_consistency=0.0
            )
        
        # Calculate user diversity (entropy)
        user_counts = defaultdict(int)
        ip_counts = defaultdict(int)
        service_counts = defaultdict(int)
        
        for event in events:
            if event.user_id:
                user_counts[event.user_id] += 1
            if event.source_ip:
                ip_counts[event.source_ip] += 1
            if event.service:
                service_counts[event.service] += 1
        
        total = len(events)
        
        user_diversity = self._calculate_entropy(user_counts, total)
        ip_diversity = self._calculate_entropy(ip_counts, total)
        service_diversity = self._calculate_entropy(service_counts, total)
        
        # Pattern consistency (how regular are the events)
        if len(events) > 1:
            intervals = []
            for i in range(1, len(events)):
                interval = (events[i].timestamp - events[i-1].timestamp).total_seconds()
                intervals.append(interval)
            
            if intervals:
                mean_interval = statistics.mean(intervals)
                std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
                # Consistency: low std/mean ratio = high consistency
                pattern_consistency = 1.0 / (1 + std_interval / mean_interval) if mean_interval > 0 else 0
            else:
                pattern_consistency = 0.0
        else:
            pattern_consistency = 0.0
        
        return BehavioralFeatures(
            user_diversity=user_diversity,
            ip_diversity=ip_diversity,
            service_diversity=service_diversity,
            pattern_consistency=pattern_consistency
        )
    
    def extract_aggregation_features(self, events: List[LogEvent],
                                     group_by: str = 'user_id') -> Dict[str, Any]:
        """
        Extract aggregated features grouped by a field.
        
        Args:
            events: List of events to aggregate
            group_by: Field to group by ('user_id', 'source_ip', 'service')
        
        Returns:
            Dictionary of group values to feature dictionaries
        """
        # Group events
        groups = defaultdict(list)
        for event in events:
            key = getattr(event, group_by, None) or event.get_attribute(group_by)
            if key:
                groups[key].append(event)
        
        # Extract features for each group
        features = {}
        for key, group_events in groups.items():
            features[key] = {
                'event_count': len(group_events),
                'frequency': self.extract_frequency_features(group_events),
                'behavioral': self.extract_behavioral_features(group_events),
                'time_range': {
                    'start': min(e.timestamp for e in group_events).isoformat(),
                    'end': max(e.timestamp for e in group_events).isoformat()
                }
            }
        
        return features
    
    def _calculate_entropy(self, counts: Dict[str, int], total: int) -> float:
        """Calculate Shannon entropy from counts"""
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        
        # Normalize to 0-1 range (max entropy is log2(n))
        max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0
    
    def _get_recent_events(self, before: datetime, 
                          window: Optional[timedelta] = None) -> List[LogEvent]:
        """Get recent events within time window"""
        window = window or self.window_size
        cutoff = before - window
        
        return [
            e for e in self.event_history
            if cutoff <= e.timestamp <= before
        ]
    
    def _temporal_to_dict(self, features: TemporalFeatures) -> Dict[str, Any]:
        """Convert temporal features to dictionary"""
        return {
            'temporal_hour': features.hour,
            'temporal_day_of_week': features.day_of_week,
            'temporal_is_weekend': features.is_weekend,
            'temporal_is_business_hours': features.is_business_hours,
            'temporal_is_night': features.is_night,
            'temporal_session_duration': features.session_duration,
            'temporal_time_since_last': features.time_since_last_event
        }
    
    def _frequency_to_dict(self, features: FrequencyFeatures) -> Dict[str, Any]:
        """Convert frequency features to dictionary"""
        return {
            'freq_event_count': features.event_count,
            'freq_events_per_minute': features.events_per_minute,
            'freq_unique_users': features.unique_users,
            'freq_unique_ips': features.unique_ips,
            'freq_unique_services': features.unique_services
        }
    
    def _behavioral_to_dict(self, features: BehavioralFeatures) -> Dict[str, Any]:
        """Convert behavioral features to dictionary"""
        return {
            'behavior_user_diversity': features.user_diversity,
            'behavior_ip_diversity': features.ip_diversity,
            'behavior_service_diversity': features.service_diversity,
            'behavior_pattern_consistency': features.pattern_consistency
        }
    
    def get_feature_vector(self, event: LogEvent) -> List[float]:
        """Get numerical feature vector for an event"""
        features = self.extract_features(event)
        
        # Select numerical features
        numerical = [
            features.get('temporal_hour', 0),
            features.get('temporal_day_of_week', 0),
            float(features.get('temporal_is_weekend', False)),
            float(features.get('temporal_is_business_hours', False)),
            float(features.get('temporal_is_night', False)),
            features.get('temporal_session_duration', 0) or 0,
            features.get('temporal_time_since_last', 0) or 0,
            features.get('freq_event_count', 0),
            features.get('freq_events_per_minute', 0),
            features.get('freq_unique_users', 0),
            features.get('freq_unique_ips', 0),
            features.get('freq_unique_services', 0),
            features.get('behavior_user_diversity', 0),
            features.get('behavior_ip_diversity', 0),
            features.get('behavior_service_diversity', 0),
            features.get('behavior_pattern_consistency', 0)
        ]
        
        return numerical
