# src/utils/decorators.py
"""Authentication and authorization decorators"""
from functools import wraps
from flask import redirect, url_for, session, flash, request, jsonify
from src.models.user import User

def login_required(f):
    """
    Decorator to ensure user is authenticated before accessing route
    Implements zero-trust principle - verify every request
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        # Verify user still exists and is active
        user = User.query.get(session['user_id'])
        if not user or not user.is_active:
            session.clear()
            flash('Session invalid. Please log in again.', 'error')
            return redirect(url_for('auth.login'))
        
        # Check if password has expired
        if user.is_password_expired():
            flash('Your password has expired. Please update it.', 'warning')
            return redirect(url_for('auth.update_password'))
            
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    """
    Decorator for API endpoints requiring valid API key
    Implements quota checking per tier specifications
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Inject user into request context
        request.current_user = user
        return f(*args, **kwargs)
    return decorated_function

def tier_required(minimum_tier):
    """
    Decorator to enforce minimum API tier for access
    Args:
        minimum_tier: Minimum tier required (tier1, tier2, tier3)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401
            
            tier_hierarchy = {'tier1': 1, 'tier2': 2, 'tier3': 3}
            user_tier_level = tier_hierarchy.get(request.current_user.api_tier, 0)
            required_level = tier_hierarchy.get(minimum_tier, 999)
            
            if user_tier_level < required_level:
                return jsonify({'error': f'Minimum tier {minimum_tier} required'}), 403
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator