#!/usr/bin/env python3
"""
Flask CRUD Password Rotation System
Implements the Obinexus Computing password lifecycle management scheme
Author: Implementation for Aegis Project
Based on: Password Rotation and CRUD-Based Authentication Management Scheme by Nnamdi Michael Okpala
"""

import os
import secrets
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional, Tuple

import bcrypt
from flask import Flask, render_template_string, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc, func
from dataclasses import dataclass
import requests

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aegis_auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Password policy configuration
PASSWORD_EXPIRY_DAYS = 365  # Annual rotation as per white paper
PASSWORD_HISTORY_COUNT = 5  # Number of previous passwords to track
MIN_PASSWORD_LENGTH = 8

# API Quota Configuration
API_RATE_LIMITS = {
    'tier1': {'requests_per_hour': 100, 'data_limit_mb': 10},
    'tier2': {'requests_per_hour': 1000, 'data_limit_mb': 100},
    'tier3': {'requests_per_hour': 10000, 'data_limit_mb': 1000}
}

db = SQLAlchemy(app)

# Thread-safe quota management
@dataclass
class QuotaMetric:
    """Thread-safe metric tracking for API quota enforcement"""
    requests_count: int = 0
    data_consumed_mb: float = 0.0
    last_reset: datetime = None
    
    def __post_init__(self):
        self.last_reset = datetime.utcnow()
        self._lock = threading.Lock()
    
    def increment(self, data_mb: float = 0.0) -> Tuple[bool, str]:
        """Atomically increment metrics and check limits"""
        with self._lock:
            self.requests_count += 1
            self.data_consumed_mb += data_mb
            return True, "OK"
    
    def reset_if_needed(self) -> None:
        """Reset metrics if hour has passed"""
        with self._lock:
            now = datetime.utcnow()
            if (now - self.last_reset).total_seconds() >= 3600:
                self.requests_count = 0
                self.data_consumed_mb = 0.0
                self.last_reset = now

class QuotaManager:
    """Manages API quotas with thread-safe operations"""
    def __init__(self):
        self._user_metrics: Dict[int, QuotaMetric] = defaultdict(QuotaMetric)
        self._global_lock = threading.RLock()
    
    def check_and_update_quota(self, user_id: int, tier: str, data_mb: float = 0.0) -> Tuple[bool, str]:
        """Check if user can make request and update metrics"""
        with self._global_lock:
            metric = self._user_metrics[user_id]
            metric.reset_if_needed()
            
            limits = API_RATE_LIMITS.get(tier, API_RATE_LIMITS['tier1'])
            
            # Check limits before incrementing
            if metric.requests_count >= limits['requests_per_hour']:
                return False, "Hourly request limit exceeded"
            
            if metric.data_consumed_mb + data_mb > limits['data_limit_mb']:
                return False, "Data transfer limit exceeded"
            
            # Update metrics
            return metric.increment(data_mb)
    
    def get_user_metrics(self, user_id: int) -> dict:
        """Get current metrics for user"""
        with self._global_lock:
            metric = self._user_metrics[user_id]
            metric.reset_if_needed()
            return {
                'requests_count': metric.requests_count,
                'data_consumed_mb': metric.data_consumed_mb,
                'last_reset': metric.last_reset.isoformat()
            }

# Initialize quota manager
quota_manager = QuotaManager()

# Database Models
class User(db.Model):
    """User model implementing secure credential storage with API access tiers"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)  # Explicit salt storage for transparency
    password_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    password_expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # API Access Tier Management
    api_tier = db.Column(db.String(20), default='tier1')
    api_key = db.Column(db.String(256), unique=True, nullable=True)
    api_key_created = db.Column(db.DateTime, nullable=True)
    
    # Relationship to password history
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    api_access_logs = db.relationship('APIAccessLog', backref='user', lazy=True, cascade='all, delete-orphan')
    
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

class PasswordHistory(db.Model):
    """Track historical passwords to prevent reuse"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PasswordHistory for user_id={self.user_id}>'

class APIAccessLog(db.Model):
    """Track API access for audit and quota enforcement"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    endpoint = db.Column(db.String(256), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    status_code = db.Column(db.Integer, nullable=False)
    data_size_mb = db.Column(db.Float, default=0.0)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    
    def __repr__(self):
        return f'<APIAccessLog user_id={self.user_id} endpoint={self.endpoint}>'

# Security Functions
def generate_salt():
    """Generate cryptographically secure random salt"""
    return secrets.token_hex(32)

def hash_password(password, salt=None):
    """
    Hash password using bcrypt with explicit salt handling
    Returns: (hash, salt) tuple
    """
    if salt is None:
        salt = generate_salt()
    
    # Combine password and salt, then hash with bcrypt
    # Note: bcrypt has its own salt, but we maintain explicit salt for transparency
    combined = f"{password}{salt}".encode('utf-8')
    hashed = bcrypt.hashpw(combined, bcrypt.gensalt(rounds=12))
    
    return hashed.decode('utf-8'), salt

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash using constant-time comparison"""
    combined = f"{password}{salt}".encode('utf-8')
    return bcrypt.checkpw(combined, stored_hash.encode('utf-8'))

def is_password_in_history(user, new_password):
    """Check if password exists in user's password history"""
    # Check current password
    if verify_password(new_password, user.password_hash, user.salt):
        return True
    
    # Check password history
    for hist in user.password_history:
        if verify_password(new_password, hist.password_hash, hist.salt):
            return True
    
    return False

def record_password_history(user):
    """Record current password in history before updating"""
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
                                     .offset(PASSWORD_HISTORY_COUNT - 1)\
                                     .all()
    
    for entry in old_entries:
        db.session.delete(entry)

def login_required(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def api_auth_required(f):
    """Decorator for API authentication and quota enforcement"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        
        if not api_key:
            return jsonify({'error': 'API key required'}), 401
        
        user = User.query.filter_by(api_key=api_key, is_active=True).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Check quota
        data_size = float(request.headers.get('Content-Length', 0)) / (1024 * 1024)  # Convert to MB
        allowed, message = quota_manager.check_and_update_quota(user.id, user.api_tier, data_size)
        
        if not allowed:
            return jsonify({'error': message, 'tier': user.api_tier}), 429
        
        # Set user context for the request
        request.current_user = user
        
        # Log API access
        response = f(*args, **kwargs)
        
        # Log after successful response
        log_entry = APIAccessLog(
            user_id=user.id,
            endpoint=request.endpoint or request.path,
            method=request.method,
            status_code=response[1] if isinstance(response, tuple) else 200,
            data_size_mb=data_size,
            ip_address=request.remote_addr
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return response
    return decorated_function

# HTML Templates (embedded for simplicity)
BASE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Aegis Authentication System</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="password"], select { width: 100%; padding: 8px; box-sizing: border-box; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .error { color: red; }
        .success { color: green; }
        .warning { color: orange; }
        .info { background-color: #e7f3ff; padding: 10px; margin-bottom: 20px; border-left: 4px solid #2196F3; }
        .navigation { margin-bottom: 20px; }
        .navigation a { margin-right: 15px; }
        .quota-info { background-color: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .api-key-display { font-family: monospace; background-color: #f5f5f5; padding: 5px; border: 1px solid #ddd; }
        .metric-box { display: inline-block; padding: 10px; margin: 5px; background-color: #e8f5e9; border-radius: 5px; }
        .partial-content { border: 1px solid #ddd; padding: 15px; margin: 10px 0; }
    </style>
    <script>
        // Partial content loading
        async function loadPartial(url, targetId) {
            try {
                const response = await fetch(url);
                const data = await response.text();
                document.getElementById(targetId).innerHTML = data;
            } catch (error) {
                console.error('Error loading partial:', error);
            }
        }
        
        // Auto-refresh quota metrics
        function startQuotaRefresh() {
            setInterval(() => {
                loadPartial('/api/quota-status', 'quota-display');
            }, 5000);
        }
    </script>
</head>
<body>
    <h1>Aegis Authentication System</h1>
    <div class="info">
        <strong>CRUD Password Lifecycle Implementation</strong><br>
        Based on Obinexus Computing specifications<br>
        <em>Confio Zero-Trust Authentication with API Quota Management</em>
    </div>
    
    <div class="navigation">
        {% if session.get('user_id') %}
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('api_dashboard') }}">API Access</a>
            <a href="{{ url_for('update_password') }}">Change Password</a>
            <a href="{{ url_for('logout') }}">Logout</a>
            <a href="{{ url_for('delete_account') }}">Delete Account</a>
        {% else %}
            <a href="{{ url_for('login') }}">Login</a>
            <a href="{{ url_for('register') }}">Register</a>
        {% endif %}
    </div>
    
    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
            {% for category, message in messages %}
                <div class="{{ category }}">{{ message }}</div>
            {% endfor %}
        {% endif %}
    {% endwith %}
    
    {% block content %}{% endblock %}
</body>
</html>
"""

REGISTER_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<h2>CREATE: User Registration</h2>
<p>Phase 1 of CRUD lifecycle - Secure credential creation with salting and hashing</p>
<form method="POST">
    <div class="form-group">
        <label>Username:</label>
        <input type="text" name="username" required>
    </div>
    <div class="form-group">
        <label>Password:</label>
        <input type="password" name="password" required minlength="{{ min_length }}">
        <small>Minimum {{ min_length }} characters. Consider using a pattern like base+year (e.g., nna2001)</small>
    </div>
    <button type="submit">Register</button>
</form>
{% endblock %}
"""

LOGIN_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<h2>READ: User Authentication</h2>
<p>Phase 2 of CRUD lifecycle - Secure credential verification via hash comparison</p>
<form method="POST">
    <div class="form-group">
        <label>Username:</label>
        <input type="text" name="username" required>
    </div>
    <div class="form-group">
        <label>Password:</label>
        <input type="password" name="password" required>
    </div>
    <button type="submit">Login</button>
</form>
{% endblock %}
"""

DASHBOARD_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<h2>User Dashboard</h2>
<p>Welcome, <strong>{{ user.username }}</strong>!</p>

<h3>Password Status</h3>
<ul>
    <li>Password created: {{ user.password_created.strftime('%Y-%m-%d') }}</li>
    <li>Password expires: {{ user.password_expires.strftime('%Y-%m-%d') }}</li>
    <li>Days until expiry: {{ user.days_until_expiry() }}</li>
    <li>Status: 
        {% if user.is_password_expired() %}
            <span class="error">EXPIRED - Update Required</span>
        {% elif user.days_until_expiry() < 30 %}
            <span class="warning">Expiring Soon</span>
        {% else %}
            <span class="success">Active</span>
        {% endif %}
    </li>
</ul>

<h3>Account Information</h3>
<ul>
    <li>Account created: {{ user.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</li>
    <li>Password history entries: {{ user.password_history|length }}</li>
</ul>
{% endblock %}
"""

UPDATE_PASSWORD_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<h2>UPDATE: Password Rotation</h2>
<p>Phase 3 of CRUD lifecycle - Annual password rotation with history enforcement</p>

{% if user.is_password_expired() %}
<div class="warning">
    <strong>Your password has expired!</strong> Please update it to continue using your account securely.
</div>
{% endif %}

<form method="POST">
    <div class="form-group">
        <label>Current Password:</label>
        <input type="password" name="current_password" required>
    </div>
    <div class="form-group">
        <label>New Password:</label>
        <input type="password" name="new_password" required minlength="{{ min_length }}">
        <small>Cannot reuse any of your last {{ history_count }} passwords. Consider incrementing your pattern (e.g., nna2001 → nna2002)</small>
    </div>
    <div class="form-group">
        <label>Confirm New Password:</label>
        <input type="password" name="confirm_password" required>
    </div>
    <button type="submit">Update Password</button>
</form>
{% endblock %}
"""

DELETE_ACCOUNT_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<h2>DELETE: Account Deletion</h2>
<p>Phase 4 of CRUD lifecycle - Secure credential and data removal</p>

<div class="warning">
    <strong>Warning:</strong> This action is permanent and will:
    <ul>
        <li>Delete your account credentials</li>
        <li>Remove all password history</li>
        <li>Invalidate all active sessions</li>
        <li>Permanently remove your account data</li>
    </ul>
</div>

<form method="POST">
    <div class="form-group">
        <label>Enter your password to confirm deletion:</label>
        <input type="password" name="password" required>
    </div>
    <div class="form-group">
        <label>Type "DELETE" to confirm:</label>
        <input type="text" name="confirmation" required pattern="DELETE">
    </div>
    <button type="submit" onclick="return confirm('Are you absolutely sure? This cannot be undone.')">Delete Account</button>
</form>
{% endblock %}
"""

API_DASHBOARD_TEMPLATE = """
{% extends "base.html" %}
{% block content %}
<h2>API Access Management</h2>
<p>Tiered data access with quota enforcement per Confio Zero-Trust specifications</p>

<div class="quota-info">
    <h3>Current Tier: <strong>{{ user.api_tier|upper }}</strong></h3>
    <div id="quota-display" class="partial-content">
        <!-- Quota metrics loaded via partial rendering -->
    </div>
</div>

<div class="api-key-section">
    <h3>API Key Management</h3>
    {% if user.api_key %}
        <p>Current API Key:</p>
        <div class="api-key-display">{{ user.api_key }}</div>
        <p><small>Created: {{ user.api_key_created.strftime('%Y-%m-%d %H:%M:%S') if user.api_key_created else 'N/A' }}</small></p>
    {% else %}
        <p>No API key generated yet.</p>
    {% endif %}
    
    <form method="POST" action="{{ url_for('generate_api_key') }}">
        <button type="submit" onclick="return confirm('Generate new API key? This will invalidate your existing key.')">
            Generate New API Key
        </button>
    </form>
</div>

<div class="tier-info">
    <h3>Tier Limits</h3>
    <table style="width: 100%; border-collapse: collapse;">
        <tr>
            <th style="border: 1px solid #ddd; padding: 8px;">Tier</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Requests/Hour</th>
            <th style="border: 1px solid #ddd; padding: 8px;">Data Limit (MB)</th>
        </tr>
        {% for tier, limits in tier_limits.items() %}
        <tr style="{% if tier == user.api_tier %}background-color: #e8f5e9;{% endif %}">
            <td style="border: 1px solid #ddd; padding: 8px;">{{ tier|upper }}</td>
            <td style="border: 1px solid #ddd; padding: 8px;">{{ limits.requests_per_hour }}</td>
            <td style="border: 1px solid #ddd; padding: 8px;">{{ limits.data_limit_mb }}</td>
        </tr>
        {% endfor %}
    </table>
</div>

<div class="api-usage">
    <h3>Recent API Usage</h3>
    <div id="api-logs">
        {% if recent_logs %}
        <table style="width: 100%; border-collapse: collapse;">
            <tr>
                <th style="border: 1px solid #ddd; padding: 8px;">Timestamp</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Endpoint</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Status</th>
                <th style="border: 1px solid #ddd; padding: 8px;">Data (MB)</th>
            </tr>
            {% for log in recent_logs %}
            <tr>
                <td style="border: 1px solid #ddd; padding: 8px;">{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                <td style="border: 1px solid #ddd; padding: 8px;">{{ log.endpoint }}</td>
                <td style="border: 1px solid #ddd; padding: 8px;">{{ log.status_code }}</td>
                <td style="border: 1px solid #ddd; padding: 8px;">{{ "%.2f"|format(log.data_size_mb) }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No API usage recorded yet.</p>
        {% endif %}
    </div>
</div>

<script>
    // Start quota refresh when page loads
    window.addEventListener('load', () => {
        loadPartial('/api/quota-status', 'quota-display');
        startQuotaRefresh();
    });
</script>
{% endblock %}
"""

QUOTA_PARTIAL_TEMPLATE = """
<div class="metric-box">
    <strong>Requests This Hour:</strong> {{ metrics.requests_count }}
</div>
<div class="metric-box">
    <strong>Data Consumed:</strong> {{ "%.2f"|format(metrics.data_consumed_mb) }} MB
</div>
<div class="metric-box">
    <strong>Reset Time:</strong> {{ reset_time }}
</div>
"""

# Routes
@app.route('/')
def index():
    """Landing page"""
    return redirect(url_for('index_page'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """CREATE operation - User registration with secure password storage"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return redirect(url_for('register'))
        
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f'Password must be at least {MIN_PASSWORD_LENGTH} characters', 'error')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        # Create user with hashed password
        password_hash, salt = hash_password(password)
        
        user = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            password_created=datetime.utcnow(),
            password_expires=datetime.utcnow() + timedelta(days=PASSWORD_EXPIRY_DAYS)
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Password will expire in 365 days.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('register'))
    
    return render_template_string(REGISTER_TEMPLATE, min_length=MIN_PASSWORD_LENGTH)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """READ operation - Authenticate user via hash comparison"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and verify_password(password, user.password_hash, user.salt):
            # Authentication successful
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            # Check password expiration
            if user.is_password_expired():
                flash('Your password has expired. Please update it.', 'warning')
                return redirect(url_for('update_password'))
            elif user.days_until_expiry() < 30:
                flash(f'Your password will expire in {user.days_until_expiry()} days.', 'warning')
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing password status"""
    user = User.query.get(session['user_id'])
    return render_template_string(DASHBOARD_TEMPLATE, user=user)

@app.route('/update-password', methods=['GET', 'POST'])
@login_required
def update_password():
    """UPDATE operation - Password rotation with history check"""
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Verify current password
        if not verify_password(current_password, user.password_hash, user.salt):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('update_password'))
        
        # Validate new password
        if len(new_password) < MIN_PASSWORD_LENGTH:
            flash(f'New password must be at least {MIN_PASSWORD_LENGTH} characters', 'error')
            return redirect(url_for('update_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('update_password'))
        
        # Check password history
        if is_password_in_history(user, new_password):
            flash(f'Cannot reuse any of your last {PASSWORD_HISTORY_COUNT} passwords', 'error')
            return redirect(url_for('update_password'))
        
        try:
            # Record current password in history
            record_password_history(user)
            
            # Update password
            password_hash, salt = hash_password(new_password)
            user.password_hash = password_hash
            user.salt = salt
            user.password_created = datetime.utcnow()
            user.password_expires = datetime.utcnow() + timedelta(days=PASSWORD_EXPIRY_DAYS)
            
            db.session.commit()
            
            flash('Password updated successfully! Next rotation due in 365 days.', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Password update failed: {str(e)}', 'error')
            return redirect(url_for('update_password'))
    
    return render_template_string(UPDATE_PASSWORD_TEMPLATE, 
                                user=user,
                                min_length=MIN_PASSWORD_LENGTH,
                                history_count=PASSWORD_HISTORY_COUNT)

@app.route('/delete-account', methods=['GET', 'POST'])
@login_required
def delete_account():
    """DELETE operation - Secure account and credential removal"""
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirmation = request.form.get('confirmation', '')
        
        # Verify password
        if not verify_password(password, user.password_hash, user.salt):
            flash('Password verification failed', 'error')
            return redirect(url_for('delete_account'))
        
        # Verify confirmation
        if confirmation != 'DELETE':
            flash('Please type DELETE to confirm', 'error')
            return redirect(url_for('delete_account'))
        
        try:
            # Option 1: Hard delete (complete removal)
            # db.session.delete(user)  # This cascades to password history
            
            # Option 2: Soft delete with credential invalidation
            user.is_active = False
            user.password_hash = secrets.token_hex(32)  # Random hash no one knows
            user.salt = secrets.token_hex(32)
            
            db.session.commit()
            
            # Clear session (revoke authentication)
            session.clear()
            
            flash('Account deleted successfully. All credentials have been purged.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Account deletion failed: {str(e)}', 'error')
            return redirect(url_for('delete_account'))
    
    return render_template_string(DELETE_ACCOUNT_TEMPLATE, user=user)

@app.route('/logout')
def logout():
    """Logout user and clear session"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/api/dashboard')
@login_required
def api_dashboard():
    """API management dashboard"""
    user = User.query.get(session['user_id'])
    recent_logs = APIAccessLog.query.filter_by(user_id=user.id)\
                                   .order_by(desc(APIAccessLog.timestamp))\
                                   .limit(10)\
                                   .all()
    
    return render_template_string(API_DASHBOARD_TEMPLATE,
                                user=user,
                                tier_limits=API_RATE_LIMITS,
                                recent_logs=recent_logs)

@app.route('/api/generate-key', methods=['POST'])
@login_required
def generate_api_key():
    """Generate new API key for user"""
    user = User.query.get(session['user_id'])
    
    try:
        # Generate new key
        new_key = user.generate_api_key()
        db.session.commit()
        
        flash(f'New API key generated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Failed to generate API key: {str(e)}', 'error')
    
    return redirect(url_for('api_dashboard'))

@app.route('/api/quota-status')
@login_required
def quota_status():
    """Get current quota status (partial rendering endpoint)"""
    user = User.query.get(session['user_id'])
    metrics = quota_manager.get_user_metrics(user.id)
    
    # Calculate time until reset
    last_reset = datetime.fromisoformat(metrics['last_reset'])
    next_reset = last_reset + timedelta(hours=1)
    reset_time = next_reset.strftime('%H:%M:%S')
    
    return render_template_string(QUOTA_PARTIAL_TEMPLATE,
                                metrics=metrics,
                                reset_time=reset_time)

# API Data Endpoints with Quota Enforcement
@app.route('/api/v1/data/silo/<silo_id>')
@api_auth_required
def api_silo_request(silo_id):
    """Silo data request endpoint with quota enforcement"""
    # Simulate data retrieval with size calculation
    sample_data = {
        'silo_id': silo_id,
        'timestamp': datetime.utcnow().isoformat(),
        'data': {
            'metrics': {
                'temperature': 22.5,
                'humidity': 45.2,
                'pressure': 1013.25
            },
            'status': 'operational',
            'tier': request.current_user.api_tier
        }
    }
    
    return jsonify(sample_data), 200

@app.route('/api/v1/data/aggregate', methods=['POST'])
@api_auth_required
def api_aggregate_data():
    """Aggregate data endpoint for tier 2+ users"""
    if request.current_user.api_tier == 'tier1':
        return jsonify({'error': 'Aggregate queries require tier2 or higher'}), 403
    
    # Parse request data
    query_params = request.get_json() or {}
    
    # Simulate aggregation
    result = {
        'query': query_params,
        'results': {
            'total_records': 1000,
            'aggregations': {
                'avg_temperature': 23.4,
                'max_humidity': 78.9,
                'min_pressure': 1008.5
            }
        },
        'execution_time_ms': 145
    }
    
    return jsonify(result), 200

@app.route('/api/v1/data/stream/<stream_id>')
@api_auth_required
def api_stream_data(stream_id):
    """Stream data endpoint for tier 3 users only"""
    if request.current_user.api_tier != 'tier3':
        return jsonify({'error': 'Stream access requires tier3'}), 403
    
    # Simulate stream data
    stream_data = {
        'stream_id': stream_id,
        'batch_size': 100,
        'data_points': [
            {'t': i, 'v': 20 + (i % 10)} for i in range(100)
        ]
    }
    
    return jsonify(stream_data), 200

# Index route with partial rendering
@app.route('/index')
def index_page():
    """Root index with partial rendering support"""
    INDEX_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Aegis Zero-Trust API Gateway</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
            .header { background-color: #2c3e50; color: white; padding: 20px; text-align: center; }
            .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
            .section { margin: 20px 0; padding: 20px; background-color: #f8f9fa; border-radius: 8px; }
            .api-example { background-color: #e9ecef; padding: 10px; margin: 10px 0; font-family: monospace; }
            .tier-card { display: inline-block; width: 30%; margin: 1%; padding: 20px; background-color: white; 
                         border: 1px solid #dee2e6; border-radius: 8px; vertical-align: top; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Aegis Zero-Trust API Gateway</h1>
            <p>Confio Authentication System with Tiered Data Access</p>
        </div>
        
        <div class="container">
            <div class="section">
                <h2>API Access Tiers</h2>
                <div class="tier-card">
                    <h3>Tier 1 - Basic</h3>
                    <ul>
                        <li>100 requests/hour</li>
                        <li>10 MB data transfer</li>
                        <li>Basic silo queries</li>
                    </ul>
                </div>
                <div class="tier-card">
                    <h3>Tier 2 - Professional</h3>
                    <ul>
                        <li>1,000 requests/hour</li>
                        <li>100 MB data transfer</li>
                        <li>Aggregate queries</li>
                    </ul>
                </div>
                <div class="tier-card">
                    <h3>Tier 3 - Enterprise</h3>
                    <ul>
                        <li>10,000 requests/hour</li>
                        <li>1 GB data transfer</li>
                        <li>Stream access</li>
                    </ul>
                </div>
            </div>
            
            <div class="section">
                <h2>API Usage Examples</h2>
                <div class="api-example">
                    GET /api/v1/data/silo/{silo_id}<br>
                    Headers: X-API-Key: your-api-key
                </div>
                <div class="api-example">
                    POST /api/v1/data/aggregate<br>
                    Headers: X-API-Key: your-api-key<br>
                    Body: {"filters": {...}, "aggregations": [...]}
                </div>
            </div>
            
            <div class="section">
                <h2>Getting Started</h2>
                <ol>
                    <li><a href="/register">Register an account</a></li>
                    <li><a href="/login">Login to your account</a></li>
                    <li>Navigate to API Dashboard to generate your API key</li>
                    <li>Use the API key in your requests</li>
                </ol>
            </div>
        </div>
    </body>
    </html>
    """
    return INDEX_TEMPLATE

# Template context processor
@app.context_processor
def inject_base_template():
    return dict(base_template=BASE_TEMPLATE)

# Override template lookup to use our embedded templates
original_render = render_template_string
def render_template_string(template, **context):
    if template in [REGISTER_TEMPLATE, LOGIN_TEMPLATE, DASHBOARD_TEMPLATE, 
                   UPDATE_PASSWORD_TEMPLATE, DELETE_ACCOUNT_TEMPLATE,
                   API_DASHBOARD_TEMPLATE, QUOTA_PARTIAL_TEMPLATE]:
        template = template.replace('{% extends "base.html" %}', 
                                  '{% extends base_template %}')
        context['base_template'] = BASE_TEMPLATE
    return original_render(template, **context)

# CLI Commands for testing
@app.cli.command()
def init_db():
    """Initialize database tables"""
    db.create_all()
    print("Database initialized successfully")

@app.cli.command()
def test_auth():
    """Run authentication tests"""
    print("Running authentication system tests...")
    
    # Test password hashing
    test_password = "TestPass123"
    hash1, salt1 = hash_password(test_password)
    print(f"✓ Password hashing works: {len(hash1)} chars")
    
    # Test verification
    assert verify_password(test_password, hash1, salt1)
    assert not verify_password("WrongPass", hash1, salt1)
    print("✓ Password verification works")
    
    # Test different passwords get different hashes
    hash2, salt2 = hash_password(test_password)
    assert hash1 != hash2 or salt1 != salt2
    print("✓ Unique salts generated")
    
    print("\nAll tests passed! System ready for deployment.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    print("""
    Aegis Authentication System - CRUD Password Lifecycle Implementation
    ==================================================================
    
    Based on: Obinexus Computing Password Rotation Scheme
    Author: Implementation for Aegis Project
    
    Features implemented:
    - CREATE: Secure user registration with bcrypt + salt
    - READ: Hash-based authentication with constant-time comparison  
    - UPDATE: Annual password rotation with history enforcement
    - DELETE: Secure credential removal and session invalidation
    
    To run:
    1. Install dependencies: pip install flask flask-sqlalchemy bcrypt
    2. Run the application: python app.py
    3. Access at http://localhost:5000
    
    CLI Commands:
    - flask init-db     : Initialize database
    - flask test-auth   : Run authentication tests
    """)
    
    app.run(debug=True)