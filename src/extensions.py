# src/extensions.py
"""Flask extensions initialization"""
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy
db = SQLAlchemy()

# Additional extensions can be added here as needed
# e.g., flask_migrate, flask_limiter for rate limiting, etc.


# src/config.py
"""Configuration for Aegis Authentication System
Implements secure defaults per OBINexus Constitutional requirements
"""
import os
from datetime import timedelta

class Config:
    """Base configuration with secure defaults"""
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32).hex()
    
    # Session configuration
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True  # No JS access
    SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # 30-minute timeout
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///aegis_auth.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False
    
    # Password policy per Confio specification
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_EXPIRY_DAYS = 365
    PASSWORD_HISTORY_COUNT = 5
    PBKDF2_ITERATIONS = 600000
    
    # Rate limiting (to be implemented with flask-limiter)
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'
    LOGIN_ATTEMPTS_LIMIT = 5
    LOGIN_ATTEMPTS_WINDOW = 300  # 5 minutes
    
    # API Tier limits per OBINexus specification
    API_TIER_LIMITS = {
        'tier1': {'requests_per_hour': 100, 'data_limit_mb': 10},
        'tier2': {'requests_per_hour': 1000, 'data_limit_mb': 100},
        'tier3': {'requests_per_hour': 10000, 'data_limit_mb': 1000}
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    # Less secure settings for development only
    SESSION_COOKIE_SECURE = False  # Allow HTTP in dev
    
class ProductionConfig(Config):
    """Production configuration with enhanced security"""
    DEBUG = False
    TESTING = False
    
    # Enhanced security for production
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # CSRF tokens don't expire
    
    # Require secure environment variables in production
    SECRET_KEY = os.environ['SECRET_KEY']  # Will raise if not set
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']
    
    # Optional pepper for additional security
    PASSWORD_PEPPER = os.environ.get('PASSWORD_PEPPER')

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory database for tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Faster hashing for tests
    PBKDF2_ITERATIONS = 1000

# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}