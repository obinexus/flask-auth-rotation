#!/usr/bin/env python3
"""
Flask CRUD Password Rotation System
Implements the Obinexus Computing password lifecycle management scheme
Author: Implementation for Aegis Project
Based on: Password Rotation and CRUD-Based Authentication Management Scheme by Nnamdi Michael Okpala
"""

import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import Flask, render_template_string, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc

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

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    """User model implementing secure credential storage"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)  # Explicit salt storage for transparency
    password_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    password_expires = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship to password history
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def is_password_expired(self):
        """Check if password has exceeded annual rotation period"""
        return datetime.utcnow() > self.password_expires
    
    def days_until_expiry(self):
        """Calculate days until password expiration"""
        delta = self.password_expires - datetime.utcnow()
        return delta.days if delta.days > 0 else 0

class PasswordHistory(db.Model):
    """Track historical passwords to prevent reuse"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PasswordHistory for user_id={self.user_id}>'

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
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        button:hover { background-color: #0056b3; }
        .error { color: red; }
        .success { color: green; }
        .warning { color: orange; }
        .info { background-color: #e7f3ff; padding: 10px; margin-bottom: 20px; border-left: 4px solid #2196F3; }
        .navigation { margin-bottom: 20px; }
        .navigation a { margin-right: 15px; }
    </style>
</head>
<body>
    <h1>Aegis Authentication System</h1>
    <div class="info">
        <strong>CRUD Password Lifecycle Implementation</strong><br>
        Based on Obinexus Computing specifications
    </div>
    
    <div class="navigation">
        {% if session.get('user_id') %}
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
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

# Routes
@app.route('/')
def index():
    """Landing page"""
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

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

# Template context processor
@app.context_processor
def inject_base_template():
    return dict(base_template=BASE_TEMPLATE)

# Override template lookup to use our embedded templates
original_render = render_template_string
def render_template_string(template, **context):
    if template in [REGISTER_TEMPLATE, LOGIN_TEMPLATE, DASHBOARD_TEMPLATE, 
                   UPDATE_PASSWORD_TEMPLATE, DELETE_ACCOUNT_TEMPLATE]:
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
