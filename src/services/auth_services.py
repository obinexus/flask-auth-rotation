"""Authentication service for Aegis System"""
import secrets
import bcrypt
from datetime import datetime, timedelta
from sqlalchemy import desc
from src.extensions import db
from src.models.user import User
from src.models.password_history import PasswordHistory
from src.config import Config

class AuthService:
    """Handles authentication operations"""
    
    @staticmethod
    def generate_salt():
        """Generate cryptographically secure random salt"""
        return secrets.token_hex(32)
    
    @staticmethod
    def hash_password(password, salt=None):
        """Hash password using bcrypt with explicit salt handling"""
        if salt is None:
            salt = AuthService.generate_salt()
        
        combined = f"{password}{salt}".encode('utf-8')
        hashed = bcrypt.hashpw(combined, bcrypt.gensalt(rounds=12))
        
        return hashed.decode('utf-8'), salt
    
    @staticmethod
    def verify_password(password, stored_hash, salt):
        """Verify password against stored hash using constant-time comparison"""
        combined = f"{password}{salt}".encode('utf-8')
        return bcrypt.checkpw(combined, stored_hash.encode('utf-8'))
    
    @staticmethod
    def is_password_in_history(user, new_password):
        """Check if password exists in user's password history"""
        # Check current password
        if AuthService.verify_password(new_password, user.password_hash, user.salt):
            return True
        
        # Check password history
        for hist in user.password_history:
            if AuthService.verify_password(new_password, hist.password_hash, hist.salt):
                return True
        
        return False
    
    @staticmethod
    def record_password_history(user):
        """Record current password in history before updating"""
        from src.models.password_history import PasswordHistory
        
        # Add current password to history
        history_entry = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash,
            salt=user.salt
        )
        db.session.add(history_entry)
        
        # Maintain only PASSWORD_HISTORY_COUNT entries
        old_entries = PasswordHistory.query.filter_by(user_id=user.id)\
                                         .order_by(desc(PasswordHistory.created_at))\
                                         .offset(Config.PASSWORD_HISTORY_COUNT - 1)\
                                         .all()
        
        for entry in old_entries:
            db.session.delete(entry)
