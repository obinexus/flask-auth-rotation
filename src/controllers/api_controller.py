# src/controllers/api_controller.py
"""API Access Controller for Aegis Authentication System
Implements tiered data access with quota enforcement per Confio Zero-Trust specifications
"""
from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, flash
from datetime import datetime, timedelta
from src.models.user import User
from src.models.api_access_log import APIAccessLog
from src.extensions import db
from src.utils.decorators import login_required
from src.services.quota_service import QuotaService
import secrets

api_bp = Blueprint('api', __name__)

# Tier configuration per OBINexus specifications
TIER_LIMITS = {
    'tier1': {'requests_per_hour': 100, 'data_limit_mb': 10},
    'tier2': {'requests_per_hour': 1000, 'data_limit_mb': 100},
    'tier3': {'requests_per_hour': 10000, 'data_limit_mb': 1000}
}

@api_bp.route('/dashboard')
@login_required
def api_dashboard():
    """Display API access management dashboard"""
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for('auth.login'))
    
    # Get recent API usage logs
    recent_logs = APIAccessLog.query.filter_by(
        user_id=user.id
    ).order_by(APIAccessLog.timestamp.desc()).limit(10).all()
    
    return render_template('partials/api_dashboard.html',
                         user=user,
                         tier_limits=TIER_LIMITS,
                         recent_logs=recent_logs)

@api_bp.route('/generate-key', methods=['POST'])
@login_required
def generate_api_key():
    """Generate new API key for authenticated user"""
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for('auth.login'))
    
    # Generate new API key using cryptographically secure method
    new_key = user.generate_api_key()
    db.session.commit()
    
    flash(f'New API key generated: {new_key}', 'success')
    return redirect(url_for('api.api_dashboard'))

@api_bp.route('/quota-status')
@login_required
def quota_status():
    """Get current quota usage for partial page updates"""
    user = User.query.get(session.get('user_id'))
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401
    
    quota_service = QuotaService()
    metrics = quota_service.get_user_metrics(user.id)
    
    # Calculate reset time
    current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    next_hour = current_hour + timedelta(hours=1)
    reset_time = next_hour.strftime('%H:%M UTC')
    
    return render_template('partials/quota_partial.html',
                         metrics=metrics,
                         reset_time=reset_time)

@api_bp.route('/api/v1/data', methods=['GET'])
def api_data_endpoint():
    """Protected API endpoint with quota enforcement"""
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({'error': 'API key required'}), 401
    
    # Validate API key
    user = User.query.filter_by(api_key=api_key).first()
    if not user:
        return jsonify({'error': 'Invalid API key'}), 401
    
    # Check quota
    quota_service = QuotaService()
    if not quota_service.check_quota(user.id, user.api_tier):
        return jsonify({'error': 'Quota exceeded'}), 429
    
    # Log API access
    log_entry = APIAccessLog(
        user_id=user.id,
        endpoint='/api/v1/data',
        method='GET',
        ip_address=request.remote_addr,
        status_code=200,
        data_size_mb=0.1  # Example size
    )
    db.session.add(log_entry)
    db.session.commit()
    
    # Return mock data (replace with actual implementation)
    return jsonify({
        'status': 'success',
        'data': {
            'timestamp': datetime.utcnow().isoformat(),
            'tier': user.api_tier,
            'message': 'Confio Zero-Trust Authentication Active'
        }
    })

@api_bp.route('/revoke-key', methods=['POST'])
@login_required
def revoke_api_key():
    """Revoke current API key"""
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect(url_for('auth.login'))
    
    user.api_key = None
    user.api_key_created = None
    db.session.commit()
    
    flash('API key revoked successfully', 'warning')
    return redirect(url_for('api.api_dashboard'))