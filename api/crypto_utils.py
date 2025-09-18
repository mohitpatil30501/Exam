"""
Cryptography utilities for secure data handling
"""

import base64
import os
import secrets
from typing import Union, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token
    
    Args:
        length: Length of the token in bytes (default: 32)
    
    Returns:
        A URL-safe base64-encoded token string
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode()


def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt
    
    Args:
        length: Length of the salt in bytes (default: 16)
    
    Returns:
        A random salt as bytes
    """
    return os.urandom(length)


def create_key_from_password(
    password: str, 
    salt: Optional[bytes] = None,
    iterations: int = 480000,  # OWASP recommended minimum as of 2023
    length: int = 32
) -> tuple[bytes, bytes]:
    """
    Create a secure key from a password using PBKDF2
    
    Args:
        password: The password or secret to derive a key from
        salt: Optional salt, will generate one if not provided
        iterations: Number of iterations (default: 480000, OWASP recommended)
        length: Desired key length in bytes (default: 32)
    
    Returns:
        Tuple of (key, salt)
    """
    if salt is None:
        salt = generate_salt()
        
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


class SecureFernetEncryption:
    """
    Secure encryption using Fernet (AES-128 in CBC mode) with proper key derivation
    """
    
    def __init__(self, username: str):
        """
        Initialize with a username to create a user-specific encryption key
        
        Args:
            username: Username to create a personalized encryption key
        """
        # Get the master key and add username as personalization
        master_password = f"{settings.SECRET_KEY}{username[::-1]}"
        
        # Store a user-specific salt in the database or use a consistent one
        # Here we're using a configuration-based salt combined with username
        salt_source = getattr(settings, 'ENCRYPTION_SALT', 'default-salt-please-change-in-settings')
        salt = hashes.SHA256(f"{salt_source}-{username}".encode()).digest()
        
        # Create a key with high iteration count
        key, _ = create_key_from_password(
            password=master_password,
            salt=salt,
            iterations=getattr(settings, 'ENCRYPTION_ITERATIONS', 480000)
        )
        
        self.fernet = Fernet(key)
    
    def encrypt(self, data: Union[str, bytes]) -> str:
        """
        Encrypt data
        
        Args:
            data: String or bytes to encrypt
            
        Returns:
            Encrypted data as base64 string
        """
        if isinstance(data, str):
            data = data.encode()
            
        return self.fernet.encrypt(data).decode()
    
    def decrypt(self, token: Union[str, bytes]) -> bytes:
        """
        Decrypt data
        
        Args:
            token: Encrypted token as string or bytes
            
        Returns:
            Decrypted data as bytes
        """
        if isinstance(token, str):
            token = token.encode()
            
        return self.fernet.decrypt(token)
    
    def decrypt_to_string(self, token: Union[str, bytes]) -> str:
        """
        Decrypt data and return as string
        
        Args:
            token: Encrypted token
            
        Returns:
            Decrypted data as string
        """
        return self.decrypt(token).decode()


# For backward compatibility with existing code
def key_maker(username):
    """
    Legacy key maker function for backward compatibility
    This is deprecated and should be replaced with SecureFernetEncryption
    """
    return SecureFernetEncryption(username).fernet