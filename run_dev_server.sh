#!/bin/bash
# Run the Django development server with HTTP support only
# This script ensures that all HTTPS-related settings are disabled

# Set environment variables to disable HTTPS enforcement
export PYTHONHTTPSVERIFY=0
export OAUTHLIB_INSECURE_TRANSPORT=1
export DEBUG=True

echo "Starting development server in HTTP-only mode..."
python3 manage.py runserver --insecure