# src/utils/security.py
"""Security utilities for Aegis Authentication System
Implements PBKDF2-HMAC-SHA512 with 600,000 iterations per Confio specification
"""
import hashlib
import hmac
import secrets
from typing import Tuple

# Constants per OBINexus Constitutional requirements
PBKDF2_ITERATIONS = 600000  # Per Confio specification
HASH_ALGORITHM = 'sha512'
KEY_LENGTH = 64  # 512 bits

def hash_password(password: str, salt: str) -> str:
    """
    Hash password using PBKDF2-HMAC-SHA512
    
    Args:
        password: Plain text password
        salt: Hex-encoded salt string
        
    Returns:
        Hex-encoded password hash
    """
    # Convert salt from hex string to bytes
    salt_bytes = bytes.fromhex(salt)
    
    # Derive key using PBKDF2
    dk = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password.encode('utf-8'),
        salt_bytes,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH
    )
    
    return dk.hex()

def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verify password against stored hash using constant-time comparison
    
    Args:
        password: Plain text password to verify
        salt: Hex-encoded salt string
        stored_hash: Hex-encoded stored password hash
        
    Returns:
        True if password matches, False otherwise
    """
    # Hash the provided password
    computed_hash = hash_password(password, salt)
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, stored_hash)

def generate_secure_token(length: int = 32) -> str:
    """
    Generate cryptographically secure random token
    
    Args:
        length: Number of bytes (will be hex-encoded, so output is 2x length)
        
    Returns:
        Hex-encoded secure random token
    """
    return secrets.token_hex(length)

def hash_with_pepper(data: str, pepper: str) -> str:
    """
    Apply pepper to hashed data using HMAC
    Optional additional security layer per Confio specification
    
    Args:
        data: Data to pepper (typically a password hash)
        pepper: Application-wide secret pepper
        
    Returns:
        Hex-encoded peppered hash
    """
    return hmac.new(
        pepper.encode('utf-8'),
        data.encode('utf-8'),
        hashlib.sha512
    ).hexdigest()