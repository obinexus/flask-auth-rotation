# src/services/quota_service.py
"""Quota management service for API access control"""
from datetime import datetime, timedelta
from src.models.api_access_log import APIAccessLog
from src.extensions import db
from collections import defaultdict

class QuotaService:
    """Manages API quota enforcement per Confio Zero-Trust specifications"""
    
    # Tier limits as defined in OBINexus specifications
    TIER_LIMITS = {
        'tier1': {'requests_per_hour': 100, 'data_limit_mb': 10},
        'tier2': {'requests_per_hour': 1000, 'data_limit_mb': 100},
        'tier3': {'requests_per_hour': 10000, 'data_limit_mb': 1000}
    }
    
    def check_quota(self, user_id: int, tier: str) -> bool:
        """
        Check if user has remaining quota for API access
        
        Args:
            user_id: User identifier
            tier: User's API tier (tier1, tier2, tier3)
            
        Returns:
            bool: True if quota available, False if exceeded
        """
        limits = self.TIER_LIMITS.get(tier, self.TIER_LIMITS['tier1'])
        metrics = self.get_user_metrics(user_id)
        
        # Check both request count and data usage
        if metrics['requests_count'] >= limits['requests_per_hour']:
            return False
        
        if metrics['data_consumed_mb'] >= limits['data_limit_mb']:
            return False
            
        return True
    
    def get_user_metrics(self, user_id: int) -> dict:
        """
        Calculate current hour's usage metrics for a user
        
        Args:
            user_id: User identifier
            
        Returns:
            dict: Contains requests_count and data_consumed_mb
        """
        # Get current hour window
        current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        
        # Query logs for current hour
        logs = APIAccessLog.query.filter(
            APIAccessLog.user_id == user_id,
            APIAccessLog.timestamp >= current_hour
        ).all()
        
        # Calculate metrics
        requests_count = len(logs)
        data_consumed_mb = sum(log.data_size_mb for log in logs)
        
        return {
            'requests_count': requests_count,
            'data_consumed_mb': data_consumed_mb,
            'window_start': current_hour,
            'window_end': current_hour + timedelta(hours=1)
        }
    
    def reset_quota(self, user_id: int):
        """
        Force reset quota for a user (admin function)
        Note: This doesn't delete logs, just allows immediate access
        """
        # In a production system, this might set a flag or exception
        # For now, logs naturally expire out of the current hour window
        pass
    
    def get_usage_report(self, user_id: int, days: int = 7) -> dict:
        """
        Generate usage report for specified number of days
        
        Args:
            user_id: User identifier
            days: Number of days to include in report
            
        Returns:
            dict: Daily usage statistics
        """
        start_date = datetime.utcnow() - timedelta(days=days)
        
        logs = APIAccessLog.query.filter(
            APIAccessLog.user_id == user_id,
            APIAccessLog.timestamp >= start_date
        ).all()
        
        # Group by day
        daily_stats = defaultdict(lambda: {'requests': 0, 'data_mb': 0.0})
        
        for log in logs:
            day_key = log.timestamp.date().isoformat()
            daily_stats[day_key]['requests'] += 1
            daily_stats[day_key]['data_mb'] += log.data_size_mb
        
        return dict(daily_stats)
