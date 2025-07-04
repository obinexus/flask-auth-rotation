# src/models/password_history.py
"""Password History model for Aegis Authentication System
Tracks historical passwords to enforce non-reuse policy per Confio specification
"""
from datetime import datetime
from src.extensions import db

class PasswordHistory(db.Model):
    """
    Password history tracking for enforcing 5-year non-reuse policy
    Per OBINexus Constitutional requirement 5.3
    """
    __tablename__ = 'password_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Stored password components (never plaintext)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)
    
    # Temporal tracking
    used_from = db.Column(db.DateTime, nullable=False)
    used_until = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Audit metadata
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PasswordHistory user_id={self.user_id} used_from={self.used_from}>'
    
    def age_in_days(self):
        """Calculate age of this password entry in days"""
        return (datetime.utcnow() - self.used_until).days
    
    def is_within_history_window(self, days=1825):  # 5 years = 1825 days
        """Check if password is within the history enforcement window"""
        return self.age_in_days() < days
