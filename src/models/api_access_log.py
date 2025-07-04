# src/models/api_access_log.py
"""API Access Log model for tracking API usage and quota enforcement"""
from datetime import datetime
from src.extensions import db

class APIAccessLog(db.Model):
    """Tracks API access for quota management and audit compliance"""
    __tablename__ = 'api_access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    endpoint = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # Supports IPv6
    status_code = db.Column(db.Integer)
    data_size_mb = db.Column(db.Float, default=0.0)
    
    # Constitutional compliance tracking
    compliance_hash = db.Column(db.String(64))  # SHA-256 hash for audit
    
    def __repr__(self):
        return f'<APIAccessLog {self.user_id}:{self.endpoint} at {self.timestamp}>'
