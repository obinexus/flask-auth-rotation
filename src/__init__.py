# src/__init__.py
"""Aegis Authentication System - Core Package"""
__version__ = "1.0.0"
__author__ = "Nnamdi Michael Okpala"
__framework__ = "OBINexus Constitutional Legal Framework"

# src/models/__init__.py
"""Database models for Aegis Authentication System"""
from .user import User
from .password_history import PasswordHistory
from .api_access_log import APIAccessLog

__all__ = ['User', 'PasswordHistory', 'APIAccessLog']

# src/controllers/__init__.py
"""Controllers implementing CRUD lifecycle management"""
from .auth_controller import auth_bp
from .dashboard_controller import dashboard_bp
from .api_controller import api_bp

__all__ = ['auth_bp', 'dashboard_bp', 'api_bp']

# src/services/__init__.py
"""Service layer for business logic"""
from .quota_service import QuotaService

__all__ = ['QuotaService']

# src/utils/__init__.py
"""Utility functions and decorators"""
from .security import hash_password, verify_password
from .decorators import login_required, api_key_required

__all__ = ['hash_password', 'verify_password', 'login_required', 'api_key_required']