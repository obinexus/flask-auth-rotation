# src/models/password_history.py
"""Password History model for enforcing rotation policy"""
from datetime import datetime
from src.extensions import db

class PasswordHistory(db.Model):
    """Tracks password history to prevent reuse per CRUD specifications"""
    __tablename__ = 'password_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Track which iteration this was (for audit)
    iteration = db.Column(db.Integer, default=1)
    
    def __repr__(self):
        return f'<PasswordHistory user={self.user_id} iteration={self.iteration}>'
