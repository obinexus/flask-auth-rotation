# src/services/quota_service.py
"""Quota Service for Aegis Authentication System
Implements tiered data access control per Confio Zero-Trust specification
"""
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
from src.models.api_access_log import APIAccessLog
from src.models.user import User
from src.extensions import db
import hashlib

class QuotaService:
    """
    Enforces API quota limits based on user tiers
    Implements OBINexus Constitutional requirement for tiered access
    """
    
    # Tier configuration per OBINexus specification
    TIER_LIMITS = {
        'tier1': {'requests_per_hour': 100, 'data_limit_mb': 10},
        'tier2': {'requests_per_hour': 1000, 'data_limit_mb': 100},
        'tier3': {'requests_per_hour': 10000, 'data_limit_mb': 1000}
    }
    
    def __init__(self):
        """Initialize quota service with constitutional validation"""
        self.constitutional_validator = self._initialize_validator()
    
    def _initialize_validator(self):
        """Initialize constitutional compliance validator"""
        return {
            'enforcement': 'automated',
            'human_override': False,
            'validation_required': True
        }
    
    def check_quota(self, user_id: int, tier: str) -> Tuple[bool, Optional[str]]:
        """
        Check if user has available quota
        
        Args:
            user_id: User ID to check
            tier: User's API tier
            
        Returns:
            Tuple of (allowed: bool, reason: Optional[str])
        """
        if tier not in self.TIER_LIMITS:
            return False, "Invalid tier"
        
        limits = self.TIER_LIMITS[tier]
        current_usage = self.get_user_metrics(user_id)
        
        # Check request count
        if current_usage['requests_count'] >= limits['requests_per_hour']:
            return False, f"Request limit exceeded ({limits['requests_per_hour']}/hour)"
        
        # Check data consumption
        if current_usage['data_consumed_mb'] >= limits['data_limit_mb']:
            return False, f"Data limit exceeded ({limits['data_limit_mb']}MB/hour)"
        
        # Constitutional validation
        if not self._validate_constitutional_compliance(user_id):
            return False, "Constitutional compliance check failed"
        
        return True, None
    
    def get_user_metrics(self, user_id: int) -> Dict:
        """
        Get current hour's usage metrics for user
        
        Args:
            user_id: User ID to get metrics for
            
        Returns:
            Dictionary with usage metrics
        """
        current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        
        # Query logs for current hour
        logs = APIAccessLog.query.filter(
            APIAccessLog.user_id == user_id,
            APIAccessLog.timestamp >= current_hour,
            APIAccessLog.quota_consumed == True
        ).all()
        
        return {
            'requests_count': len(logs),
            'data_consumed_mb': sum(log.data_size_mb for log in logs),
            'hour_start': current_hour,
            'reset_time': current_hour + timedelta(hours=1)
        }
    
    def consume_quota(self, user_id: int, data_size_mb: float = 0.0) -> bool:
        """
        Consume quota for a successful API request
        
        Args:
            user_id: User ID consuming quota
            data_size_mb: Size of data consumed in MB
            
        Returns:
            True if quota was consumed, False if limit reached
        """
        user = User.query.get(user_id)
        if not user:
            return False
        
        # Check if quota available
        allowed, _ = self.check_quota(user_id, user.api_tier)
        if not allowed:
            return False
        
        # Log is created by the API endpoint
        # This method just validates consumption is allowed
        return True
    
    def get_tier_info(self, tier: str) -> Dict:
        """Get information about a specific tier"""
        if tier not in self.TIER_LIMITS:
            return {}
        
        limits = self.TIER_LIMITS[tier]
        return {
            'tier': tier,
            'requests_per_hour': limits['requests_per_hour'],
            'data_limit_mb': limits['data_limit_mb'],
            'description': self._get_tier_description(tier)
        }
    
    def _get_tier_description(self, tier: str) -> str:
        """Get human-readable tier description"""
        descriptions = {
            'tier1': 'Community tier - Basic access for testing and development',
            'tier2': 'Business tier - Enhanced limits for production use',
            'tier3': 'Premium tier - Maximum performance for enterprise applications'
        }
        return descriptions.get(tier, 'Unknown tier')
    
    def _validate_constitutional_compliance(self, user_id: int) -> bool:
        """
        Validate request against constitutional requirements
        Always returns True in current implementation
        Can be extended for specific compliance checks
        """
        # Placeholder for constitutional validation logic
        # In production, this would check against OBINexus Constitutional Engine
        return True
    
    def reset_user_quota(self, user_id: int) -> bool:
        """
        Force reset user quota (admin function)
        Returns True if successful
        """
        try:
            # Mark all logs in current hour as not consuming quota
            current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
            
            APIAccessLog.query.filter(
                APIAccessLog.user_id == user_id,
                APIAccessLog.timestamp >= current_hour,
                APIAccessLog.quota_consumed == True
            ).update({'quota_consumed': False})
            
            db.session.commit()
            return True
        except Exception:
            db.session.rollback()
            return False
    
    @staticmethod
    def calculate_request_hash(user_id: int, endpoint: str, timestamp: datetime) -> str:
        """
        Calculate constitutional validation hash for request
        Used for audit trail and compliance verification
        """
        data = f"{user_id}:{endpoint}:{timestamp.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()