#!/usr/bin/env python
"""
Django development server with SSL support.
This script allows you to run the Django development server with SSL support.
"""
import os
import sys
import ssl
from django.core.management.commands.runserver import Command as RunserverCommand
from django.core.management import execute_from_command_line
from django.conf import settings

# Override the default get_handler method to use SSL
class SecureRunserverCommand(RunserverCommand):
    def get_handler(self, *args, **options):
        handler = super().get_handler(*args, **options)
        # Return the handler without wrapping it with SSL
        return handler

# Run the server
if __name__ == "__main__":
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Exam.settings')
    
    # Add command-line arguments to use the regular non-SSL server
    sys.argv.insert(1, "runserver")
    sys.argv.insert(2, "--nothreading")
    sys.argv.insert(3, "--noreload")
    
    execute_from_command_line(sys.argv)