#!/usr/bin/env python3
"""
Generate self-signed certificates for local development HTTPS

This script generates self-signed certificates that can be used with Django's
runserver_plus command to enable HTTPS in development.

Usage:
    python generate_cert.py
"""

import os
import subprocess

def generate_self_signed_cert():
    """Generate a self-signed certificate for development use"""
    print("Generating self-signed certificate for development...")
    
    # Check if certificates already exist
    if os.path.exists('cert.crt') and os.path.exists('cert.key'):
        overwrite = input("Certificate files already exist. Overwrite? (y/n): ")
        if overwrite.lower() != 'y':
            print("Aborted. Using existing certificates.")
            return
    
    # Generate a self-signed certificate valid for 365 days
    command = [
        'openssl', 'req', '-x509', '-nodes', '-days', '365', '-newkey', 'rsa:2048',
        '-keyout', 'cert.key', '-out', 'cert.crt',
        '-subj', '/CN=localhost'
    ]
    
    try:
        subprocess.run(command, check=True)
        print("Certificate generated successfully!")
        print("Files created: cert.key, cert.crt")
        print("\nNOTE: These are self-signed certificates for development only.")
        print("      Your browser will show security warnings when using them.")
    except subprocess.CalledProcessError:
        print("Error: Failed to generate certificates.")
        print("Make sure OpenSSL is installed and in your PATH.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    generate_self_signed_cert()