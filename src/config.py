"""Configuration management for Aegis Authentication System"""
import os
import secrets
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    
    # Password policy
    PASSWORD_EXPIRY_DAYS = 365
    PASSWORD_HISTORY_COUNT = 5
    MIN_PASSWORD_LENGTH = 8
    
    # PBKDF2 configuration
    PBKDF2_ITERATIONS = 600000
    
    # API Rate limits
    API_RATE_LIMITS = {
        'tier1': {'requests_per_hour': 100, 'data_limit_mb': 10},
        'tier2': {'requests_per_hour': 1000, 'data_limit_mb': 100},
        'tier3': {'requests_per_hour': 10000, 'data_limit_mb': 1000}
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///aegis_auth.db'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}