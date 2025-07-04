# src/controllers/auth_controller.py
"""Authentication Controller for Aegis Authentication System
Implements CRUD-based password lifecycle management per OBINexus specifications
Enforces Confio Zero-Trust principles with annual rotation requirement
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta
from src.models.user import User
from src.models.password_history import PasswordHistory
from src.extensions import db
from src.utils.security import hash_password, verify_password
import secrets
import re

auth_bp = Blueprint('auth', __name__)

# Configuration per OBINexus Constitutional requirements
MIN_PASSWORD_LENGTH = 8
PASSWORD_EXPIRY_DAYS = 365  # Annual rotation requirement
PASSWORD_HISTORY_COUNT = 5  # 5-year history per specification
SESSION_TIMEOUT_MINUTES = 30

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """CREATE: User Registration - Phase 1 of CRUD lifecycle"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate inputs
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('register.html', min_length=MIN_PASSWORD_LENGTH)
        
        if len(password) < MIN_PASSWORD_LENGTH:
            flash(f'Password must be at least {MIN_PASSWORD_LENGTH} characters', 'error')
            return render_template('register.html', min_length=MIN_PASSWORD_LENGTH)
        
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html', min_length=MIN_PASSWORD_LENGTH)
        
        # Create user with secure password storage
        salt = secrets.token_hex(32)
        password_hash = hash_password(password, salt)
        
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
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html', min_length=MIN_PASSWORD_LENGTH)
    
    return render_template('register.html', min_length=MIN_PASSWORD_LENGTH)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """READ: User Authentication - Phase 2 of CRUD lifecycle"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid credentials', 'error')
            return render_template('login.html')
        
        # Verify password using constant-time comparison
        if not verify_password(password, user.salt, user.password_hash):
            flash('Invalid credentials', 'error')
            return render_template('login.html')
        
        # Check if account is active
        if not user.is_active:
            flash('Account is inactive', 'error')
            return render_template('login.html')
        
        # Set session
        session['user_id'] = user.id
        session['username'] = user.username
        session['login_time'] = datetime.utcnow().isoformat()
        
        # Check password expiration
        if user.is_password_expired():
            flash('Your password has expired. Please update it.', 'warning')
            return redirect(url_for('auth.update_password'))
        elif user.days_until_expiry() < 30:
            flash(f'Your password expires in {user.days_until_expiry()} days', 'warning')
        
        return redirect(url_for('dashboard.dashboard'))
    
    return render_template('login.html')

@auth_bp.route('/update-password', methods=['GET', 'POST'])
def update_password():
    """UPDATE: Password Rotation - Phase 3 of CRUD lifecycle"""
    if 'user_id' not in session:
        flash('Please log in to update your password', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validate current password
        if not verify_password(current_password, user.salt, user.password_hash):
            flash('Current password is incorrect', 'error')
            return render_template('update_password.html', 
                                 min_length=MIN_PASSWORD_LENGTH,
                                 history_count=PASSWORD_HISTORY_COUNT)
        
        # Validate new password
        if len(new_password) < MIN_PASSWORD_LENGTH:
            flash(f'Password must be at least {MIN_PASSWORD_LENGTH} characters', 'error')
            return render_template('update_password.html',
                                 min_length=MIN_PASSWORD_LENGTH,
                                 history_count=PASSWORD_HISTORY_COUNT)
        
        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('update_password.html',
                                 min_length=MIN_PASSWORD_LENGTH,
                                 history_count=PASSWORD_HISTORY_COUNT)
        
        # Check password history
        new_salt = secrets.token_hex(32)
        new_hash = hash_password(new_password, new_salt)
        
        # Check against current password
        if verify_password(new_password, user.salt, user.password_hash):
            flash('New password cannot be the same as current password', 'error')
            return render_template('update_password.html',
                                 min_length=MIN_PASSWORD_LENGTH,
                                 history_count=PASSWORD_HISTORY_COUNT)
        
        # Check against password history
        for history in user.password_history:
            if verify_password(new_password, history.salt, history.password_hash):
                flash(f'Password was used previously. Cannot reuse last {PASSWORD_HISTORY_COUNT} passwords', 'error')
                return render_template('update_password.html',
                                     min_length=MIN_PASSWORD_LENGTH,
                                     history_count=PASSWORD_HISTORY_COUNT)
        
        # Save current password to history
        history_entry = PasswordHistory(
            user_id=user.id,
            password_hash=user.password_hash,
            salt=user.salt,
            used_from=user.password_created,
            used_until=datetime.utcnow()
        )
        db.session.add(history_entry)
        
        # Update user password
        user.password_hash = new_hash
        user.salt = new_salt
        user.password_created = datetime.utcnow()
        user.password_expires = datetime.utcnow() + timedelta(days=PASSWORD_EXPIRY_DAYS)
        
        # Clean old history entries (keep only last N)
        old_history = PasswordHistory.query.filter_by(user_id=user.id)\
            .order_by(PasswordHistory.used_until.desc())\
            .offset(PASSWORD_HISTORY_COUNT - 1).all()
        
        for old in old_history:
            db.session.delete(old)
        
        try:
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('dashboard.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to update password. Please try again.', 'error')
    
    return render_template('update_password.html',
                         min_length=MIN_PASSWORD_LENGTH,
                         history_count=PASSWORD_HISTORY_COUNT)

@auth_bp.route('/delete-account', methods=['GET', 'POST'])
def delete_account():
    """DELETE: Account Deletion - Phase 4 of CRUD lifecycle"""
    if 'user_id' not in session:
        flash('Please log in to delete your account', 'warning')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirmation = request.form.get('confirmation', '')
        
        # Verify password
        if not verify_password(password, user.salt, user.password_hash):
            flash('Incorrect password', 'error')
            return render_template('delete_account.html')
        
        # Verify confirmation
        if confirmation != 'DELETE':
            flash('Please type DELETE to confirm', 'error')
            return render_template('delete_account.html')
        
        try:
            # Delete all related data (cascading delete handles history and logs)
            db.session.delete(user)
            db.session.commit()
            
            # Clear session
            session.clear()
            
            flash('Account deleted successfully', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash('Failed to delete account. Please try again.', 'error')
    
    return render_template('delete_account.html')

@auth_bp.route('/logout')
def logout():
    """Session termination with zero-trust principle"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.before_app_request
def check_session_timeout():
    """Enforce session timeout per zero-trust requirements"""
    if 'user_id' in session and 'login_time' in session:
        login_time = datetime.fromisoformat(session['login_time'])
        if datetime.utcnow() - login_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
            session.clear()
            flash('Session expired. Please log in again.', 'warning')