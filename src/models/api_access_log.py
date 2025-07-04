# src/models/api_access_log.py
"""API Access Log model for Aegis Authentication System
Tracks API usage for quota enforcement per Confio Zero-Trust specification
"""
from datetime import datetime
from src.extensions import db
from time import timedelta

class APIAccessLog(db.Model):
    """
    API access tracking for tiered quota enforcement
    Per OBINexus Constitutional requirement for zero-trust validation
    """
    __tablename__ = 'api_access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Request details
    endpoint = db.Column(db.String(256), nullable=False)
    method = db.Column(db.String(10), nullable=False)  # GET, POST, etc.
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 support
    user_agent = db.Column(db.String(256))
    
    # Response details
    status_code = db.Column(db.Integer, nullable=False)
    response_time_ms = db.Column(db.Integer)  # Response time in milliseconds
    data_size_mb = db.Column(db.Float, nullable=False, default=0.0)
    
    # Quota tracking
    tier_at_request = db.Column(db.String(20))  # Snapshot of user tier
    quota_consumed = db.Column(db.Boolean, default=False)  # Was quota applied
    
    # Temporal tracking
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    # Constitutional compliance
    validation_hash = db.Column(db.String(128))  # Hash of request for audit
    constitutional_check = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<APIAccessLog user_id={self.user_id} endpoint={self.endpoint} timestamp={self.timestamp}>'
    
    @classmethod
    def get_hourly_usage(cls, user_id, tier):
        """Get usage statistics for the current hour"""
        from datetime import timedelta
        current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        
        logs = cls.query.filter(
            cls.user_id == user_id,
            cls.timestamp >= current_hour,
            cls.quota_consumed == True
        ).all()
        
        return {
            'requests_count': len(logs),
            'data_consumed_mb': sum(log.data_size_mb for log in logs),
            'hour_start': current_hour,
            'tier': tier
        }
    
    @classmethod
    def cleanup_old_logs(cls, days_to_keep=30):
        """Remove logs older than specified days for privacy compliance"""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        deleted = cls.query.filter(cls.timestamp < cutoff_date).delete()
        db.session.commit()
        return deleted