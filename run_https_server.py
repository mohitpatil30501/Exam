"""
Utility script to run Django development server with HTTPS support

This script uses Django's runserver_plus command from django-extensions
to run a development server with HTTPS support. This allows testing
security features like SECURE_SSL_REDIRECT in development.

Usage:
    python run_https_server.py

Requirements:
    django-extensions
    werkzeug
    pyOpenSSL
"""

import os
import sys
import django
from django.core.management import call_command

if __name__ == "__main__":
    # Add the project directory to the Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    # Set the Django settings module
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Exam.settings')
    
    # Configure Django
    django.setup()
    
    # Set DEBUG to True for development
    from django.conf import settings
    
    # Install django-extensions if not already installed
    try:
        import django_extensions
    except ImportError:
        print("django-extensions not found. Installing...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "django-extensions", "werkzeug", "pyOpenSSL"])
        print("Installation complete. Please restart this script.")
        sys.exit(1)
    
    # Check if django-extensions is in INSTALLED_APPS
    if 'django_extensions' not in settings.INSTALLED_APPS:
        print("Please add 'django_extensions' to INSTALLED_APPS in settings.py")
        sys.exit(1)
    
    # Run the development server with HTTPS
    try:
        print("Starting development server with HTTPS support...")
        print("Visit https://localhost:8000/ to access your application")
        print("Note: You'll see security warnings in the browser since this is a self-signed certificate.")
        print("Press Ctrl+C to stop the server.")
        call_command('runserver_plus', '--cert-file=cert.crt', '--key-file=cert.key')
    except ImportError:
        print("Error: Could not import runserver_plus. Make sure django-extensions is installed.")
        sys.exit(1)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)