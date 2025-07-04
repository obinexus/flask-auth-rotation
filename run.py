"""Application entry point for Aegis Authentication System"""
from flask import Flask, redirect, url_for, session, render_template
from src.extensions import db
from src.config import config

def create_app(config_name='default'):
    """Create and configure Flask application"""
    app = Flask(__name__, 
                template_folder='templates',
                static_folder='static')
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    
    # Register blueprints
    from src.controllers.auth_controller import auth_bp
    from src.controllers.dashboard_controller import dashboard_bp
    from src.controllers.api_controller import api_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Define root route handler
    @app.route('/')
    def index():
        """
        Root route implementing zero-trust redirect logic
        Conforms to Confio authentication flow specification
        """
        # Implement zero-trust verification per constitutional requirements
        if 'user_id' in session:
            # Verify session validity against User model
            from src.models.user import User
            user = User.query.get(session['user_id'])
            
            if user and user.is_active and not user.is_password_expired():
                return redirect(url_for('dashboard.dashboard'))
            elif user and user.is_password_expired():
                # Force password rotation per CRUD lifecycle
                return redirect(url_for('auth.update_password'))
        
        # Check if index.html exists, otherwise redirect to login
        try:
            return render_template('index.html')
        except:
            # Fallback to login if landing page doesn't exist
            return redirect(url_for('auth.login'))
    
    # Register error handlers
    register_error_handlers(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app

def register_error_handlers(app):
    """Register error handlers"""
    @app.errorhandler(404)
    def not_found(error):
        return "Page not found", 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return "Internal server error", 500

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)