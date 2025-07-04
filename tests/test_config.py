"""Test configuration loading"""
import pytest
from src.app import create_app

def test_development_config():
    """Verify development configuration loads correctly"""
    app = create_app('development')
    assert app.config['DEBUG'] is True
    assert app.config['PBKDF2_ITERATIONS'] == 600000
    assert 'SECRET_KEY' in app.config
