"""Authentication controller handling auth routes"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from datetime import datetime, timedelta
from src.extensions import db
from src.models.user import User
from src.services.auth_service import AuthService
from src.config import Config

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """CREATE operation - User registration with secure password storage"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return redirect(url_for('auth.register'))
        
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            flash(f'Password must be at least {Config.MIN_PASSWORD_LENGTH} characters', 'error')
            return redirect(url_for('auth.register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('auth.register'))
        
        # Create user with hashed password
        password_hash, salt = AuthService.hash_password(password)
        
        user = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            password_created=datetime.utcnow(),
            password_expires=datetime.utcnow() + timedelta(days=Config.PASSWORD_EXPIRY_DAYS)
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Password will expire in 365 days.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('auth.register'))
    
    return render_template('partials/register.html', min_length=Config.MIN_PASSWORD_LENGTH)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """READ operation - Authenticate user via hash comparison"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and AuthService.verify_password(password, user.password_hash, user.salt):
            # Authentication successful
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            
            # Check password expiration
            if user.is_password_expired():
                flash('Your password has expired. Please update it.', 'warning')
                return redirect(url_for('auth.update_password'))
            elif user.days_until_expiry() < 30:
                flash(f'Your password will expire in {user.days_until_expiry()} days.', 'warning')
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard.index'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('auth.login'))
    
    return render_template('partials/login.html')
