"""User model for Aegis Authentication System"""
import secrets
from datetime import datetime, timedelta
from src.extensions import db

class User(db.Model):
    """User model implementing secure credential storage with API access tiers"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)
    password_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    password_expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # API Access Tier Management
    api_tier = db.Column(db.String(20), default='tier1')
    api_key = db.Column(db.String(256), unique=True, nullable=True)
    api_key_created = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    password_history = db.relationship('PasswordHistory', backref='user', 
                                     lazy=True, cascade='all, delete-orphan')
    api_access_logs = db.relationship('APIAccessLog', backref='user', 
                                    lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def is_password_expired(self):
        """Check if password has exceeded annual rotation period"""
        return datetime.utcnow() > self.password_expires
    
    def days_until_expiry(self):
        """Calculate days until password expiration"""
        delta = self.password_expires - datetime.utcnow()
        return delta.days if delta.days > 0 else 0
    
    def generate_api_key(self):
        """Generate new API key for user"""
        self.api_key = secrets.token_urlsafe(32)
        self.api_key_created = datetime.utcnow()
        return self.api_key